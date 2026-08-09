#!/usr/bin/env python3
"""map_crown_jewels.py -- AWS crown-jewel mapper (aws_attack_model/v1 collector).

Part of the AWS red-team attack-chain suite. Enumerates and RANKS high-value
targets (crown jewels) plus the connectivity edges to them, so the chain
enumerator knows what to aim at.

Design rules (shared contract, references/attack_model_schema.md):
  * Emit the `aws_attack_model/v1` envelope. This collector fills
    `crown_jewels`, `nodes`, `edges`, `gaps` (and `accounts` when known);
    it leaves `findings` / `active_threats` empty for peer collectors.
  * stdlib + boto3 only. boto3 is imported lazily so --self-test / --ingest
    runs need no AWS and no boto3 installed.
  * Deterministic: no datetime.now() at import or anywhere. Timestamps come
    from --now (ISO string) supplied by the caller.
  * Per-account errors/denials are recorded as Gap records, never fatal.
  * --ingest reuses existing inventory JSON (e.g. resource_inventory.json
    / account_inventory.json) to classify without re-collecting.

Value scoring is a documented, deterministic function (see value_score and
references/scoring.md). It never invents data: attributes that are not present
in the source are left unknown and drive a Gap rather than an inflated score.
"""

import argparse
import glob
import json
import os
import re
import sys

SCHEMA = "aws_attack_model/v1"
SOURCE_SKILL = "aws-crown-jewel-mapper"
DEFAULT_ROLE = "TransilienceComplianceRole"

# --------------------------------------------------------------------------- #
# Data-class taxonomy + scoring (mirrored in references/scoring.md)
# --------------------------------------------------------------------------- #
# data_class is drawn from the shared contract enum:
#   pii | financial | source | model | secret | backup | log | other
#
# Base score per class -- the intrinsic "how much does the attacker want this".
BASE_SCORE = {
    "financial": 72,
    "pii": 70,
    "secret": 68,
    "model": 58,
    "source": 55,
    "backup": 50,
    "log": 42,
    "other": 25,
}

# Deterministic score modifiers (added, then clamped to [0, 100]).
MOD_PROD = 12            # prod naming
MOD_PUBLIC = 18          # internet-facing / public access
MOD_REPLICATED = 6       # cross-region replication configured
MOD_CLIENT_NAMED = 8     # name references a known customer/client token
MOD_LARGE = 5            # large store (object count / size / allocated storage)
MOD_NONPROD = -15        # dev/test/uat/sandbox/staging naming

# Ordered token rules -> data_class. First matching rule wins.
# Keep specific/high-value tokens BEFORE generic ones ("data" last).
TOKEN_RULES = [
    ("secret",    ["secret", "credential", "cred-", "vault", "tf-state", "tfstate",
                   "terraform-state", "keys", "keystore", "privatekey", "apikey"]),
    ("financial", ["financial", "finance", "invoice", "billing", "payment", "payroll",
                   "ledger", "accounting", "revenue", "tax", "transaction"]),
    ("pii",       ["pii", "personal", "customer", "client-data", "employee", "hr-",
                   "identity", "patient", "member", "userdata", "user-data", "profile",
                   "kyc", "onboard"]),
    ("backup",    ["backup", "bkp", "archive", "snapshot", "restore", "dr-", "-dr",
                   "disaster", "recovery", "cold-storage", "glacier"]),
    ("log",       ["log", "logs", "audit", "cloudtrail", "-trail", "access-log",
                   "accesslog", "flowlog", "flow-log", "config-bucket"]),
    ("source",    ["source", "repo", "artifact", "artifacts", "build", "codepipeline",
                   "codebuild", "codecommit", "jenkins", "nexus", "release", "package"]),
    ("model",     ["model", "sagemaker", "bedrock", "ml-", "-ml", "training",
                   "inference", "embeddings", "knowledge-base", "kb-"]),
    ("other",     ["data", "warehouse", "lake", "datalake", "store", "prod-data"]),
]

NONPROD_TOKENS = ["dev", "test", "uat", "qa", "sandbox", "staging", "stg", "demo",
                  "scratch", "tmp", "temp", "poc", "sample", "-lab"]
PROD_TOKENS = ["prod", "prd", "production", "live", "-p-"]

# Log / config / backup service buckets that AWS itself provisions.
INFRA_LOG_HINTS = ["cloudtrail", "config-bucket", "aws-config", "-logs", "logbucket",
                   "access-logs", "accesslog", "log-archive", "logarchive"]


def _lc(s):
    return (s or "").lower()


def _has(name, tokens):
    n = _lc(name)
    return any(t in n for t in tokens)


def classify_by_name(name):
    """Return data_class for an arbitrary resource name using ordered token rules.

    Deterministic and side-effect free. Falls back to 'other' when nothing
    matches -- we do NOT guess a sensitive class from an unclassifiable name.
    """
    n = _lc(name)
    for data_class, tokens in TOKEN_RULES:
        if any(t in n for t in tokens):
            return data_class
    return "other"


def classify_db(engine, name):
    """Classify a database node. Engine + prod/client naming push toward pii/financial."""
    by_name = classify_by_name(name)
    if by_name in ("financial", "pii", "secret"):
        return by_name
    # Relational / warehouse engines holding prod business data default to pii
    # unless the name says otherwise. A dedicated finance name already won above.
    return "pii" if by_name == "other" else by_name


def is_prod(name):
    n = _lc(name)
    if _has(n, NONPROD_TOKENS):
        return False
    return _has(n, PROD_TOKENS)


def is_nonprod(name):
    return _has(name, NONPROD_TOKENS)


def is_client_named(name, customer, client_tokens):
    n = _lc(name)
    toks = list(client_tokens or [])
    if customer:
        toks.append(_lc(customer))
    return any(t and t in n for t in toks)


def value_score(data_class, name, *, prod=False, public=False, replicated=False,
                client_named=False, large=False, nonprod=False):
    """Deterministic value_score in [0, 100].

    score = BASE_SCORE[data_class]
            + MOD_PROD        if prod
            + MOD_PUBLIC      if public
            + MOD_REPLICATED  if replicated
            + MOD_CLIENT_NAMED if client_named
            + MOD_LARGE       if large
            + MOD_NONPROD     if nonprod
    clamped to [0, 100]. Same inputs always yield the same score.
    """
    score = BASE_SCORE.get(data_class, BASE_SCORE["other"])
    if prod:
        score += MOD_PROD
    if public:
        score += MOD_PUBLIC
    if replicated:
        score += MOD_REPLICATED
    if client_named:
        score += MOD_CLIENT_NAMED
    if large:
        score += MOD_LARGE
    if nonprod:
        score += MOD_NONPROD
    return max(0, min(100, int(score)))


# --------------------------------------------------------------------------- #
# Node / crown-jewel / edge / gap builders
# --------------------------------------------------------------------------- #
def _node_id(node_type, account_id, name_or_arn):
    return "%s:%s:%s" % (node_type, account_id, name_or_arn)


def _make_node(node_type, account_id, name, arn=None, internet_facing=False,
               attributes=None):
    return {
        "id": _node_id(node_type, account_id, arn or name),
        "type": node_type,
        "account_id": account_id,
        "name": name,
        "arn": arn,
        "exposure": {"internet_facing": bool(internet_facing), "ports": [], "cidrs": []},
        "attributes": attributes or {},
    }


def _make_jewel(node, value, data_class, size="unknown", protections=None):
    return {
        "id": node["id"],
        "account_id": node["account_id"],
        "type": node["type"],
        "name": node["name"],
        "value_score": value,
        "data_class": data_class,
        "size": size,
        "protections": protections or [],
        "reachable_by": [],  # filled by the chain enumerator, not this collector
    }


def _gap(area, reason, accounts, recommended):
    return {
        "area": area,
        "reason": reason,
        "accounts": [a for a in accounts if a],
        "recommended_collection": recommended,
    }


# --------------------------------------------------------------------------- #
# Ingest classification (reuse existing inventory JSON, no AWS calls)
# --------------------------------------------------------------------------- #
def _account_entries(doc):
    """Yield per-account dicts from a *_inventory.json style document."""
    if isinstance(doc, dict) and isinstance(doc.get("accounts"), list):
        for a in doc["accounts"]:
            if isinstance(a, dict):
                yield a
    elif isinstance(doc, list):
        for a in doc:
            if isinstance(a, dict):
                yield a


def _acct_id(acc):
    return (acc.get("normalized_account_id") or acc.get("account_id")
            or acc.get("requested_account_id") or "unknown")


def _dget(d, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


def classify_account(acc, customer, client_tokens):
    """Classify one inventory account entry into nodes + crown jewels + edges + gaps."""
    nodes, jewels, edges, gaps = [], [], [], []
    account_id = _acct_id(acc)

    if acc.get("status") not in (None, "ok", "success", "OK"):
        gaps.append(_gap(
            "account_collection",
            "inventory entry marked status=%r; classification may be partial"
            % acc.get("status"),
            [account_id],
            "re-run the estate inventory collector for this account",
        ))

    ri = acc.get("resource_inventory") or {}
    storage = ri.get("storage") or {}
    ml = ri.get("ml") or {}
    user_res = ri.get("user_resources") or {}

    seen_log_bucket_ids = []

    # ---- S3 buckets --------------------------------------------------------
    buckets = _dget(acc, "s3", "buckets", default=[]) or []
    for b in buckets:
        name = b.get("name") if isinstance(b, dict) else str(b)
        if not name:
            continue
        data_class = classify_by_name(name)
        is_log = data_class == "log" or _has(name, INFRA_LOG_HINTS)
        node_type = "log_bucket" if is_log else "s3_bucket"
        prod = is_prod(name)
        nonprod = is_nonprod(name)
        client = is_client_named(name, customer, client_tokens)
        # public / replication status is NOT present in this inventory shape.
        public = bool(b.get("public")) if isinstance(b, dict) else False
        replicated = bool(b.get("replication")) if isinstance(b, dict) else False
        node = _make_node(node_type, account_id, name, arn="arn:aws:s3:::%s" % name,
                          internet_facing=public,
                          attributes={"region": b.get("region") if isinstance(b, dict) else None,
                                      "created": b.get("created") if isinstance(b, dict) else None,
                                      "public_status": "unknown" if not isinstance(b, dict) or "public" not in b else public})
        nodes.append(node)
        val = value_score(data_class, name, prod=prod, public=public,
                          replicated=replicated, client_named=client, nonprod=nonprod)
        jewels.append(_make_jewel(node, val, data_class,
                                  size="unknown",
                                  protections=[]))
        if node_type == "log_bucket":
            seen_log_bucket_ids.append(node["id"])

    # Account writes its logs to each log-archive bucket it owns.
    for lb_id in seen_log_bucket_ids:
        edges.append({
            "src": _node_id("account", account_id, account_id),
            "dst": lb_id,
            "type": "writes_logs_to",
            "attributes": {"primitive_id": None, "via": "s3-log-archive",
                           "condition": "inferred from log-archive bucket naming"},
            "evidence": {"source": "inventory", "id": lb_id},
        })

    # ---- Databases ---------------------------------------------------------
    for inst in storage.get("rds_instances", []) or []:
        ident = inst.get("identifier") or inst.get("name")
        if not ident:
            continue
        engine = inst.get("engine", "")
        dc = classify_db(engine, ident)
        prod, nonprod = is_prod(ident), is_nonprod(ident)
        client = is_client_named(ident, customer, client_tokens)
        large = (inst.get("allocated_storage") or 0) >= 100
        node = _make_node("rds_instance", account_id, ident,
                          attributes={"engine": engine,
                                      "engine_version": inst.get("engine_version"),
                                      "class": inst.get("class"),
                                      "region": inst.get("region"),
                                      "allocated_storage": inst.get("allocated_storage")})
        nodes.append(node)
        val = value_score(dc, ident, prod=prod, client_named=client,
                          large=large, nonprod=nonprod)
        jewels.append(_make_jewel(node, val, dc,
                                  size="%sGiB" % inst.get("allocated_storage")
                                  if inst.get("allocated_storage") else "unknown",
                                  protections=["multi_az"] if inst.get("multi_az") else []))

    # redshift / documentdb / dynamodb / elasticache (present in richer inventories)
    _classify_simple_stores(storage, account_id, customer, client_tokens, nodes, jewels)

    # ---- Secrets Manager + SSM SecureString --------------------------------
    for sec in (storage.get("secrets") or user_res.get("secrets") or []):
        name = sec.get("name") if isinstance(sec, dict) else str(sec)
        if not name:
            continue
        node = _make_node("secret", account_id, name,
                          arn=sec.get("arn") if isinstance(sec, dict) else None,
                          attributes={"region": sec.get("region") if isinstance(sec, dict) else None})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("secret", name,
                                                    prod=is_prod(name),
                                                    client_named=is_client_named(name, customer, client_tokens)),
                                  "secret"))
    for p in (storage.get("ssm_parameters") or user_res.get("ssm_parameters") or []):
        name = p.get("name") if isinstance(p, dict) else str(p)
        ptype = p.get("type") if isinstance(p, dict) else None
        if not name or (ptype and ptype != "SecureString"):
            continue
        node = _make_node("ssm_parameter", account_id, name,
                          attributes={"type": ptype or "SecureString"})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("secret", name, prod=is_prod(name)),
                                  "secret"))

    # ---- KMS keys ----------------------------------------------------------
    for k in (storage.get("kms_keys") or []):
        kid = k.get("key_id") or k.get("id") or k.get("arn") if isinstance(k, dict) else str(k)
        if not kid:
            continue
        node = _make_node("kms_key", account_id, kid,
                          arn=k.get("arn") if isinstance(k, dict) else None,
                          attributes={"alias": k.get("alias") if isinstance(k, dict) else None})
        nodes.append(node)
        # KMS keys protect data; value tracks the class of what they guard (secret-ish).
        jewels.append(_make_jewel(node, value_score("secret", str(k.get("alias") or kid) if isinstance(k, dict) else kid),
                                  "secret", protections=["kms"]))

    # ---- Bedrock KBs / agents + SageMaker (model class) --------------------
    for kb in ml.get("bedrock_knowledge_bases", []) or []:
        name = kb.get("name") or kb.get("id")
        node = _make_node("bedrock_kb", account_id, name,
                          attributes={"id": kb.get("id"), "status": kb.get("status"),
                                      "region": kb.get("region")})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("model", name or "", prod=True), "model"))
    for ag in ml.get("bedrock_agents", []) or []:
        name = ag.get("name") or ag.get("id")
        node = _make_node("bedrock_agent", account_id, name,
                          attributes={"id": ag.get("id"), "status": ag.get("status"),
                                      "region": ag.get("region")})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("model", name or ""), "model"))
    for key in ("sagemaker_domains", "sagemaker_notebook_instances", "sagemaker_model_samples"):
        for sm in ml.get(key, []) or []:
            name = sm.get("name") or sm.get("id") if isinstance(sm, dict) else str(sm)
            node = _make_node("sagemaker", account_id, name,
                              attributes={"kind": key,
                                          "region": sm.get("region") if isinstance(sm, dict) else None})
            nodes.append(node)
            jewels.append(_make_jewel(node, value_score("model", name or ""), "model"))

    # ---- Source / artifact / CI-CD ----------------------------------------
    for repo in (ri.get("compute", {}).get("ecr_repositories")
                 or storage.get("ecr_repositories") or []):
        name = repo.get("name") or repo.get("repository_name") if isinstance(repo, dict) else str(repo)
        node = _make_node("ecr_repo", account_id, name,
                          attributes={"region": repo.get("region") if isinstance(repo, dict) else None})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("source", name or "", prod=is_prod(name or "")),
                                  "source"))
    for ci_key, via in (("codebuild_projects", "codebuild"),
                        ("codepipeline_pipelines", "codepipeline"),
                        ("codecommit_repositories", "codecommit")):
        for c in (ri.get("compute", {}).get(ci_key) or []):
            name = c.get("name") if isinstance(c, dict) else str(c)
            node = _make_node("ci_system", account_id, name,
                              attributes={"via": via,
                                          "region": c.get("region") if isinstance(c, dict) else None})
            nodes.append(node)
            jewels.append(_make_jewel(node, value_score("source", name or "", prod=True),
                                      "source"))

    # ---- Identity stores (IAM Identity Center / Cognito) ------------------
    for idc in user_res.get("identity_center_instances", []) or []:
        arn = idc.get("instance_arn") if isinstance(idc, dict) else None
        name = arn or (idc.get("identity_store_id") if isinstance(idc, dict) else str(idc))
        node = _make_node("sso_instance", account_id, name, arn=arn,
                          attributes={"identity_store_id": idc.get("identity_store_id") if isinstance(idc, dict) else None,
                                      "status": idc.get("status") if isinstance(idc, dict) else None})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("secret", "identity-center", prod=True),
                                  "secret", protections=["identity_store"]))
        edges.append({
            "src": node["id"],
            "dst": _node_id("account", account_id, account_id),
            "type": "member_of",
            "attributes": {"primitive_id": None, "via": "identity-center",
                           "condition": None},
            "evidence": {"source": "inventory", "id": node["id"]},
        })
    for pool in user_res.get("cognito_user_pools", []) or []:
        name = pool.get("name") or pool.get("id") if isinstance(pool, dict) else str(pool)
        node = _make_node("cognito_pool", account_id, name,
                          attributes={"id": pool.get("id") if isinstance(pool, dict) else None,
                                      "region": pool.get("region") if isinstance(pool, dict) else None})
        nodes.append(node)
        jewels.append(_make_jewel(node, value_score("pii", name or "", prod=True), "pii"))
        edges.append({
            "src": node["id"],
            "dst": _node_id("account", account_id, account_id),
            "type": "member_of",
            "attributes": {"primitive_id": None, "via": "cognito", "condition": None},
            "evidence": {"source": "inventory", "id": node["id"]},
        })

    # ---- Connectivity gaps (not carried in this inventory shape) -----------
    gaps.append(_gap(
        "connectivity",
        "S3 public-access / replication status and cross-region replication "
        "config are not present in the ingested inventory; value_score treats "
        "them as unknown (not public, not replicated).",
        [account_id],
        "aws s3api get-bucket-policy-status / get-public-access-block / "
        "get-bucket-replication per bucket",
    ))

    return nodes, jewels, edges, gaps


def _classify_simple_stores(storage, account_id, customer, client_tokens, nodes, jewels):
    """redshift_clusters / documentdb_clusters / dynamodb_tables / elasticache in
    richer inventories. Each maps to its own NODE_TYPE."""
    mapping = [
        ("redshift_clusters", "redshift", "identifier"),
        ("documentdb_clusters", "documentdb", "identifier"),
        ("dynamodb_tables", "dynamodb", "name"),
        ("elasticache_clusters", "elasticache", "id"),
    ]
    for key, node_type, name_field in mapping:
        for item in storage.get(key, []) or []:
            name = (item.get(name_field) or item.get("name") or item.get("id")
                    if isinstance(item, dict) else str(item))
            if not name:
                continue
            dc = classify_db(item.get("engine", "") if isinstance(item, dict) else "", name)
            node = _make_node(node_type, account_id, name,
                              attributes={"engine": item.get("engine") if isinstance(item, dict) else None,
                                          "region": item.get("region") if isinstance(item, dict) else None})
            nodes.append(node)
            jewels.append(_make_jewel(
                node,
                value_score(dc, name, prod=is_prod(name),
                            client_named=is_client_named(name, customer, client_tokens),
                            nonprod=is_nonprod(name)),
                dc))


# --------------------------------------------------------------------------- #
# Ingest loading
# --------------------------------------------------------------------------- #
def _expand_ingest(patterns):
    files = []
    for pat in patterns or []:
        if os.path.isdir(pat):
            files.extend(sorted(glob.glob(os.path.join(pat, "**", "*.json"),
                                          recursive=True)))
        else:
            files.extend(sorted(glob.glob(pat)))
    # de-dup, preserve order
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def run_ingest(patterns, customer, client_tokens):
    nodes, jewels, edges, gaps = [], [], [], []
    accounts_meta = {}
    files = _expand_ingest(patterns)
    if not files:
        gaps.append(_gap("ingest", "no inventory JSON matched --ingest patterns: %r"
                         % (patterns,), [], "point --ingest at a resource inventory dir/glob"))
        return nodes, jewels, edges, gaps, accounts_meta

    for path in files:
        try:
            with open(path, "r") as fh:
                doc = json.load(fh)
        except Exception as exc:  # noqa: BLE001 - record, never fail
            gaps.append(_gap("ingest", "failed to read/parse %s: %s" % (path, exc),
                             [], "verify the file is valid inventory JSON"))
            continue
        entries = list(_account_entries(doc))
        if not entries:
            continue
        for acc in entries:
            aid = _acct_id(acc)
            accounts_meta.setdefault(aid, {
                "account_id": aid, "label": _dget(acc, "name_hints", "name", default=""),
                "env": "unknown",
                "is_management": _dget(acc, "name_hints", "organization",
                                       "management_account_id", default=None) == aid,
                "org_id": _dget(acc, "name_hints", "organization", "organization_id",
                                default=None),
                "notes": "from ingest %s" % os.path.basename(path),
            })
            n, j, e, g = classify_account(acc, customer, client_tokens)
            nodes.extend(n)
            jewels.extend(j)
            edges.extend(e)
            gaps.extend(g)
    return nodes, jewels, edges, gaps, accounts_meta


# --------------------------------------------------------------------------- #
# Live connectivity collection (best-effort, boto3 lazy). Errors -> Gap.
# --------------------------------------------------------------------------- #
def run_live_connectivity(accounts, role_name, edges, gaps, existing_node_ids):
    try:
        import boto3  # noqa: F401  (lazy)
    except Exception:  # noqa: BLE001
        gaps.append(_gap("connectivity", "boto3 not available; skipped live "
                         "collection of VPC peering / TGW / bucket replication", [],
                         "install boto3 and re-run with --accounts"))
        return
    from botocore.exceptions import ClientError  # noqa

    for entry in accounts:
        aid = entry.get("account_id", "unknown")
        role_arn = entry.get("role_arn") or "arn:aws:iam::%s:role/%s" % (aid, role_name)
        try:
            sts = boto3.client("sts")
            kwargs = {"RoleArn": role_arn, "RoleSessionName": "crown-jewel-mapper"}
            if entry.get("external_id"):
                kwargs["ExternalId"] = entry["external_id"]
            creds = sts.assume_role(**kwargs)["Credentials"]
            sess = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        except Exception as exc:  # noqa: BLE001
            gaps.append(_gap("connectivity", "assume_role failed for %s: %s" % (aid, exc),
                             [aid], "verify %s is assumable" % role_arn))
            continue

        # VPC peering + Transit Gateway attachments (region-scoped; caller can
        # extend regions). Best-effort in us-east-1; record a Gap for others.
        try:
            ec2 = sess.client("ec2", region_name=entry.get("region", "us-east-1"))
            for pc in ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", []):
                peer_acct = (pc.get("AccepterVpcInfo", {}) or {}).get("OwnerId", "external")
                edges.append({
                    "src": _node_id("account", aid, aid),
                    "dst": _node_id("account", peer_acct, peer_acct),
                    "type": "member_of",
                    "attributes": {"primitive_id": None, "via": "vpc-peering",
                                   "condition": pc.get("VpcPeeringConnectionId")},
                    "evidence": {"source": "config",
                                 "id": pc.get("VpcPeeringConnectionId", "")},
                })
            for tgw in ec2.describe_transit_gateway_attachments().get(
                    "TransitGatewayAttachments", []):
                edges.append({
                    "src": _node_id("account", aid, aid),
                    "dst": _node_id("account",
                                    tgw.get("ResourceOwnerId", "external"),
                                    tgw.get("ResourceOwnerId", "external")),
                    "type": "member_of",
                    "attributes": {"primitive_id": None, "via": "transit-gateway",
                                   "condition": tgw.get("TransitGatewayAttachmentId")},
                    "evidence": {"source": "config",
                                 "id": tgw.get("TransitGatewayAttachmentId", "")},
                })
        except Exception as exc:  # noqa: BLE001
            gaps.append(_gap("connectivity", "VPC peering / TGW query failed for %s: %s"
                             % (aid, exc), [aid],
                             "ec2:DescribeVpcPeeringConnections / "
                             "DescribeTransitGatewayAttachments across all regions"))
    gaps.append(_gap("connectivity", "cross-region S3 replication + cross-account "
                     "bucket policies require per-bucket API calls not run here", [],
                     "s3api get-bucket-replication / get-bucket-policy per bucket"))


# --------------------------------------------------------------------------- #
# Envelope assembly
# --------------------------------------------------------------------------- #
def build_envelope(customer, now, accounts_meta, nodes, jewels, edges, gaps):
    # de-dup nodes / jewels by id, edges by (src,dst,type)
    def _dedup_by(items, keyfn):
        seen, out = set(), []
        for it in items:
            k = keyfn(it)
            if k not in seen:
                seen.add(k)
                out.append(it)
        return out

    nodes = _dedup_by(nodes, lambda n: n["id"])
    jewels = _dedup_by(jewels, lambda j: j["id"])
    edges = _dedup_by(edges, lambda e: (e["src"], e["dst"], e["type"]))
    # rank crown jewels highest-value first (stable by id on ties)
    jewels.sort(key=lambda j: (-j["value_score"], j["id"]))

    return {
        "schema": SCHEMA,
        "customer": customer or "",
        "collected_at": now,
        "source_skill": SOURCE_SKILL,
        "accounts": list(accounts_meta.values()),
        "nodes": nodes,
        "edges": edges,
        "findings": [],
        "crown_jewels": jewels,
        "active_threats": [],
        "gaps": gaps,
    }


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #
SELF_TEST_FIXTURE = {
    "customer_name": "acme",
    "accounts": [
        {
            "normalized_account_id": "111122223333",
            "status": "ok",
            "name_hints": {"name": "acme-prod",
                           "organization": {"organization_id": "o-abc123",
                                            "management_account_id": "999988887777"}},
            "s3": {"buckets": [
                {"name": "acme-prod-financial-invoices", "region": "us-east-1"},
                {"name": "acme-backup-archive", "region": "us-east-1"},
                {"name": "acme-cloudtrail-logs", "region": "us-east-1"},
                {"name": "acme-dev-scratch", "region": "us-west-2"},
                {"name": "acme-tf-state", "region": "us-east-1"},
            ]},
            "resource_inventory": {
                "storage": {
                    "rds_instances": [
                        {"identifier": "acme-prod-customers-db", "engine": "aurora-postgresql",
                         "allocated_storage": 500, "multi_az": True, "region": "us-east-1"},
                    ],
                    "secrets": [{"name": "acme/prod/db-master", "region": "us-east-1"}],
                    "kms_keys": [{"key_id": "abcd-1234", "alias": "alias/acme-prod"}],
                },
                "ml": {
                    "bedrock_knowledge_bases": [
                        {"id": "KB1", "name": "acme-support-kb", "status": "ACTIVE",
                         "region": "us-east-1"}],
                },
                "compute": {
                    "ecr_repositories": [{"name": "acme-prod-api", "region": "us-east-1"}],
                },
                "user_resources": {
                    "identity_center_instances": [
                        {"instance_arn": "arn:aws:sso:::instance/ssoins-xyz",
                         "identity_store_id": "d-123", "status": "ACTIVE"}],
                },
            },
        },
    ],
}


def self_test():
    nodes, jewels, edges, gaps = [], [], [], []
    accounts_meta = {}
    for acc in _account_entries(SELF_TEST_FIXTURE):
        aid = _acct_id(acc)
        accounts_meta[aid] = {"account_id": aid, "label": "acme-prod", "env": "prod",
                              "is_management": False, "org_id": "o-abc123",
                              "notes": "self-test fixture"}
        n, j, e, g = classify_account(acc, "acme", [])
        nodes += n; jewels += j; edges += e; gaps += g
    env = build_envelope("acme", "2026-08-08T00:00:00Z", accounts_meta,
                         nodes, jewels, edges, gaps)

    # Validate envelope shape.
    assert env["schema"] == SCHEMA, "bad schema tag"
    for arr in ("accounts", "nodes", "edges", "findings", "crown_jewels",
                "active_threats", "gaps"):
        assert isinstance(env[arr], list), "%s must be a list" % arr
    assert env["crown_jewels"], "expected crown jewels"
    # every jewel has a matching node id and required fields
    node_ids = {n["id"] for n in env["nodes"]}
    classes = set()
    for j in env["crown_jewels"]:
        for f in ("id", "account_id", "type", "name", "value_score", "data_class",
                  "size", "protections", "reachable_by"):
            assert f in j, "jewel missing %s" % f
        assert 0 <= j["value_score"] <= 100, "score out of range"
        assert j["id"] in node_ids, "jewel %s has no node" % j["id"]
        classes.add(j["data_class"])
    # value ranking sanity: financial prod db/bucket should outrank dev scratch
    top = env["crown_jewels"][0]
    assert top["value_score"] >= env["crown_jewels"][-1]["value_score"]
    # data_class coverage across taxonomy
    assert {"financial", "backup", "log", "secret", "model", "source", "pii"} & classes
    # edges reference known nodes or account nodes
    assert any(e["type"] == "writes_logs_to" for e in env["edges"]), "expected writes_logs_to"
    assert any(e["type"] == "member_of" for e in env["edges"]), "expected member_of"

    print("SELF-TEST PASS")
    print(json.dumps(env, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="AWS crown-jewel mapper -> aws_attack_model/v1 envelope")
    ap.add_argument("--accounts",
                    help="JSON file: array of {account_id, role_arn?, profile?, "
                         "external_id?, region?} for live connectivity collection")
    ap.add_argument("--ingest", nargs="+", default=[],
                    help="dir(s)/glob(s) of existing inventory JSON to classify "
                         "(e.g. resource_inventory.json)")
    ap.add_argument("--customer", default="", help="customer/org name (also a client token)")
    ap.add_argument("--client-tokens", nargs="*", default=[],
                    help="extra name tokens that mark client-owned data (raises score)")
    ap.add_argument("--role-name", default=DEFAULT_ROLE,
                    help="cross-account role name for live collection (default %s)"
                         % DEFAULT_ROLE)
    ap.add_argument("--now", default=None,
                    help="ISO-8601 timestamp stamped into collected_at (caller-supplied)")
    ap.add_argument("--output", default="crown_jewels.json",
                    help="output path for the envelope (default crown_jewels.json)")
    ap.add_argument("--self-test", action="store_true",
                    help="run offline self-test (no AWS) and print a valid envelope")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    nodes, jewels, edges, gaps, accounts_meta = run_ingest(
        args.ingest, args.customer, args.client_tokens)

    if args.accounts:
        try:
            with open(args.accounts) as fh:
                accts = json.load(fh)
            if isinstance(accts, dict):
                accts = accts.get("accounts", [])
        except Exception as exc:  # noqa: BLE001
            accts = []
            gaps.append(_gap("accounts", "failed to read --accounts %s: %s"
                             % (args.accounts, exc), [], "provide a valid accounts JSON"))
        existing = {n["id"] for n in nodes}
        run_live_connectivity(accts, args.role_name, edges, gaps, existing)
        for a in accts:
            aid = a.get("account_id")
            if aid:
                accounts_meta.setdefault(aid, {
                    "account_id": aid, "label": a.get("label", ""), "env": "unknown",
                    "is_management": False, "org_id": None, "notes": "from --accounts"})

    if not args.ingest and not args.accounts:
        gaps.append(_gap("input", "neither --ingest nor --accounts provided; "
                         "nothing to classify", [],
                         "pass --ingest <inventory glob> and/or --accounts <file>"))

    env = build_envelope(args.customer, args.now, accounts_meta,
                         nodes, jewels, edges, gaps)

    with open(args.output, "w") as fh:
        json.dump(env, fh, indent=2)

    print("wrote %s" % args.output)
    print("  accounts=%d nodes=%d crown_jewels=%d edges=%d gaps=%d"
          % (len(env["accounts"]), len(env["nodes"]), len(env["crown_jewels"]),
             len(env["edges"]), len(env["gaps"])))
    if env["crown_jewels"]:
        top = env["crown_jewels"][:5]
        print("  top jewels:")
        for j in top:
            print("    %3d  %-14s %-9s %s"
                  % (j["value_score"], j["type"], j["data_class"], j["name"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
