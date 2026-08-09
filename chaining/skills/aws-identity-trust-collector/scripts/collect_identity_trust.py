#!/usr/bin/env python3
"""Deep AWS IAM / identity / trust collector for the red-team attack-chain suite.

Emits an ``aws_attack_model/v1`` envelope (see references/attack_model_schema.md).
This collector fills ``accounts``, ``nodes``, ``edges``, ``findings`` and ``gaps``;
it leaves ``crown_jewels`` and ``active_threats`` empty for other collectors.

Design rules (per the shared contract):
  * stdlib + boto3 only; boto3 is imported lazily so ``--self-test`` and
    ``py_compile`` work with no AWS and no boto3 installed.
  * never call time/date at import — the caller supplies ``--now`` (ISO-8601).
  * per-account AccessDenied / errors become ``Gap`` records, never a hard fail.
  * node ids are stable: ``iam_user:<acct>:<name>``, ``iam_role:<acct>:<name>``,
    ``iam_group:<acct>:<name>``, ``access_key:<acct>:<user>:<keyid>``,
    ``account:<acct>``, ``external_account:<acct-or-*>``, ``pe_admin:<acct>``.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "aws_attack_model/v1"
SOURCE_SKILL = "aws-identity-trust-collector"
DEFAULT_ROLE_NAME = "TransilienceComplianceRole"

# Well-known AWS managed policy ARNs -> semantic tags.
MANAGED_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
MANAGED_IAM_FULL = "arn:aws:iam::aws:policy/IAMFullAccess"
MANAGED_EC2_FULL = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
MANAGED_SSM_FULL = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"

CI_ROBOT_RE = re.compile(r"(jenkins|teamcity|cloudagent|pipeline|bitbucket|gitlab|circleci|githubactions|robot|ci[-_])", re.I)


# --------------------------------------------------------------------------- #
# time helpers
# --------------------------------------------------------------------------- #
def parse_iso(value):
    """Parse an ISO-8601 string into an aware UTC datetime (or None)."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def age_days(now_dt, then):
    then_dt = parse_iso(then)
    if then_dt is None or now_dt is None:
        return None
    return (now_dt - then_dt).days


# --------------------------------------------------------------------------- #
# policy-document analysis (pure functions over IAM policy statements)
# --------------------------------------------------------------------------- #
def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def iter_statements(doc):
    """Yield statement dicts from a policy document (which may be a JSON string)."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return
    if not isinstance(doc, dict):
        return
    for stmt in as_list(doc.get("Statement")):
        if isinstance(stmt, dict):
            yield stmt


def action_matches(action, needle):
    """Case-insensitive IAM action glob match. ``iam:*`` matches ``iam:passrole``."""
    action = str(action).lower()
    needle = str(needle).lower()
    if action in ("*", needle):
        return True
    if action.endswith("*") and needle.startswith(action[:-1]):
        return True
    return False


def allow_statements(statements):
    return [s for s in statements if str(s.get("Effect", "Allow")).lower() == "allow"]


def allows(statements, needle):
    """True if any Allow statement permits an action matching ``needle``."""
    for stmt in allow_statements(statements):
        # NotAction with Allow is effectively an allow-all-except; treat as broad.
        if stmt.get("NotAction") is not None:
            return True
        for action in as_list(stmt.get("Action")):
            if action_matches(action, needle):
                return True
    return False


def has_star_star(statements):
    """Action:* on Resource:* (or NotAction Allow) — full administrator."""
    for stmt in allow_statements(statements):
        resources = [str(r) for r in as_list(stmt.get("Resource"))]
        star_resource = "*" in resources or stmt.get("NotResource") is not None or not resources
        if stmt.get("NotAction") is not None and star_resource:
            return True
        for action in as_list(stmt.get("Action")):
            if str(action) == "*" and star_resource:
                return True
    return False


def has_wildcard_inline(statements):
    """A statement granting action ``*`` (or ``svc:*``) on resource ``*``."""
    for stmt in allow_statements(statements):
        resources = [str(r) for r in as_list(stmt.get("Resource"))]
        if "*" not in resources:
            continue
        for action in as_list(stmt.get("Action")):
            a = str(action)
            if a == "*" or a.endswith(":*"):
                return True
    return False


def passrole_resources(statements):
    """Resource strings from statements that allow iam:PassRole."""
    resources = []
    for stmt in allow_statements(statements):
        if any(action_matches(a, "iam:passrole") for a in as_list(stmt.get("Action"))):
            resources.extend(str(r) for r in as_list(stmt.get("Resource")))
    return resources


def analyze_principal(statements, attached_arns):
    """Return the set of capability flags for a principal from its effective policy."""
    attached = {str(a) for a in attached_arns}
    admin_managed = MANAGED_ADMIN in attached
    caps = {
        "admin_like": admin_managed or has_star_star(statements),
        "admin_managed": admin_managed,
        "iam_full": MANAGED_IAM_FULL in attached or admin_managed or allows(statements, "iam:*"),
        "wildcard_inline": has_wildcard_inline(statements),
        "ec2_full": MANAGED_EC2_FULL in attached or allows(statements, "ec2:*") or allows(statements, "ec2:runinstances"),
        "ssm_full": (
            MANAGED_SSM_FULL in attached
            or allows(statements, "ssm:*")
            or allows(statements, "ssm:sendcommand")
            or allows(statements, "ssm:startsession")
        ),
        "can_passrole": allows(statements, "iam:passrole"),
        "passrole_resources": passrole_resources(statements),
        "passrole_via": [],
    }
    if caps["can_passrole"]:
        if allows(statements, "lambda:createfunction"):
            caps["passrole_via"].append(("lambda", "IAM_PASSROLE_LAMBDA", "pe_passrole_lambda"))
        if allows(statements, "glue:createjob") or allows(statements, "glue:*"):
            caps["passrole_via"].append(("glue", "IAM_PASSROLE_GLUE", "pe_passrole_glue_sagemaker"))
        if allows(statements, "sagemaker:createnotebookinstance") or allows(statements, "sagemaker:createtrainingjob"):
            caps["passrole_via"].append(("sagemaker", "IAM_PASSROLE_SAGEMAKER", "pe_passrole_glue_sagemaker"))
        if allows(statements, "cloudformation:createstack"):
            caps["passrole_via"].append(("cloudformation", "IAM_PASSROLE_CFN", "pe_passrole_cloudformation"))
        if allows(statements, "ec2:runinstances"):
            caps["passrole_via"].append(("ec2", "IAM_EC2_FULL", "pe_ec2_run_as_role"))
    return caps


# --------------------------------------------------------------------------- #
# trust-policy analysis
# --------------------------------------------------------------------------- #
def account_of_arn(arn):
    """Extract the 12-digit account id from an ARN, or return None."""
    m = re.search(r"arn:aws[-a-z]*:[^:]*:[^:]*:(\d{12}):", str(arn))
    if m:
        return m.group(1)
    if re.fullmatch(r"\d{12}", str(arn)):
        return str(arn)
    return None


def principal_kind(arn):
    """Classify an AWS principal ARN string."""
    s = str(arn)
    if s == "*":
        return "any"
    if s.endswith(":root") or re.fullmatch(r"\d{12}", s):
        return "account"
    if ":user/" in s:
        return "user"
    if ":role/" in s or ":assumed-role/" in s:
        return "role"
    return "other"


def trust_condition_has_externalid(stmt):
    """True if the statement pins sts:ExternalId or aws:SourceArn (confused-deputy guard)."""
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return False
    for keys in cond.values():
        if not isinstance(keys, dict):
            continue
        for k in keys:
            kl = str(k).lower()
            if kl in ("sts:externalid", "aws:sourcearn", "aws:sourceaccount"):
                return True
    return False


def analyze_trust(trust_doc):
    """Return structured trust facts for a role's AssumeRolePolicyDocument."""
    facts = {"wildcard_principal": False, "aws_principals": [], "service_principals": [], "federated": []}
    for stmt in allow_statements(list(iter_statements(trust_doc))):
        actions = [str(a).lower() for a in as_list(stmt.get("Action"))]
        if not any(a.startswith("sts:assumerole") or a == "sts:*" or a == "*" for a in actions):
            continue
        principal = stmt.get("Principal")
        has_extid = trust_condition_has_externalid(stmt)
        if principal == "*":
            facts["wildcard_principal"] = True
            continue
        if not isinstance(principal, dict):
            continue
        for arn in as_list(principal.get("AWS")):
            if str(arn) == "*":
                facts["wildcard_principal"] = True
            else:
                facts["aws_principals"].append({"arn": str(arn), "external_id": has_extid})
        for svc in as_list(principal.get("Service")):
            facts["service_principals"].append(str(svc))
        for fed in as_list(principal.get("Federated")):
            facts["federated"].append(str(fed))
    return facts


# --------------------------------------------------------------------------- #
# model builder (pure: operates on collected per-account data)
# --------------------------------------------------------------------------- #
class ModelBuilder:
    def __init__(self, customer, now_iso):
        self.customer = customer
        self.now_iso = now_iso
        self.now_dt = parse_iso(now_iso)
        self.accounts = []
        self.nodes = {}
        self.edges = {}
        self.findings = []
        self.gaps = []
        self._fid = 0

    # -- primitives ------------------------------------------------------- #
    def add_node(self, node):
        self.nodes.setdefault(node["id"], node)
        return node["id"]

    def node(self, nid, ntype, account_id, name, arn=None, exposure=None, attributes=None):
        return self.add_node({
            "id": nid, "type": ntype, "account_id": account_id, "name": name, "arn": arn,
            "exposure": exposure or {"internet_facing": False, "ports": [], "cidrs": []},
            "attributes": attributes or {},
        })

    def edge(self, src, dst, etype, primitive_id=None, via=None, condition=None,
             source="iam", evidence_id=None):
        key = (src, dst, etype, via, primitive_id)
        self.edges.setdefault(key, {
            "src": src, "dst": dst, "type": etype,
            "attributes": {"primitive_id": primitive_id, "via": via, "condition": condition},
            "evidence": {"source": source, "id": evidence_id or src},
        })

    def finding(self, account_id, control, severity, resource, primitive_ids,
                mitre=None, internet_facing=False, raw_source="iam:api"):
        self._fid += 1
        self.findings.append({
            "id": f"F-{self._fid:04d}", "account_id": account_id, "control": control,
            "severity": severity, "resource": resource, "internet_facing": internet_facing,
            "primitive_ids": primitive_ids, "mitre": mitre or [], "raw_source": raw_source,
        })

    def gap(self, area, reason, accounts, recommended):
        self.gaps.append({
            "area": area, "reason": reason, "accounts": accounts,
            "recommended_collection": recommended,
        })

    def external_account(self, acct):
        acct = acct or "*"
        nid = f"external_account:{acct}"
        self.node(nid, "external_account", "external", "any-principal" if acct == "*" else acct,
                  attributes={"account_id": acct})
        return nid

    # -- per-account ingestion ------------------------------------------- #
    def add_account(self, data):
        acct = data["account_id"]
        collected = set(data.get("_collected_accounts") or [acct])
        self.accounts.append({
            "account_id": acct, "label": data.get("label") or acct,
            "env": data.get("env", "unknown"), "is_management": data.get("is_management", False),
            "org_id": data.get("org_id"), "notes": data.get("notes", ""),
        })
        acct_node = f"account:{acct}"
        self.node(acct_node, "account", acct, data.get("label") or acct,
                  attributes={
                      "password_policy": data.get("password_policy"),
                      "account_summary": data.get("account_summary"),
                  })
        admin_node = f"pe_admin:{acct}"
        self.node(admin_node, "account", acct, "account-administrator",
                  attributes={"pseudo": True, "represents": "account administrator state"})

        for err in data.get("errors", []):
            self.gap(err.get("area", "iam"), err.get("reason", "collection error"),
                     [acct], err.get("recommended", "Re-run with a role granting iam:Get*/iam:List* and organizations:*"))

        self._add_users(acct, acct_node, admin_node, data.get("users", []))
        self._add_groups(acct, data.get("groups", []))
        self._add_roles(acct, acct_node, admin_node, collected, data.get("roles", []))
        self._add_root(acct, data)
        self._add_org(acct, data.get("organizations"))

    def _add_users(self, acct, acct_node, admin_node, users):
        for u in users:
            name = u["name"]
            uid = f"iam_user:{acct}:{name}"
            caps = analyze_principal(u.get("statements", []), u.get("attached_arns", []))
            keys = u.get("access_keys", [])
            active_keys = [k for k in keys if str(k.get("status", "")).lower() == "active"]
            mfa = bool(u.get("mfa_devices"))
            console = bool(u.get("login_profile"))
            self.node(uid, "iam_user", acct, name, arn=u.get("arn"), attributes={
                "path": u.get("path"), "console_login": console, "mfa": mfa,
                "permission_boundary": u.get("boundary"), "groups": u.get("groups", []),
                "admin_like": caps["admin_like"], "iam_full": caps["iam_full"],
                "active_key_count": len(active_keys),
            })
            self.edge(uid, acct_node, "member_of", source="iam")

            for k in keys:
                kid = k.get("id") or "unknown"
                knode = f"access_key:{acct}:{name}:{kid}"
                a_days = age_days(self.now_dt, k.get("create_date"))
                last_days = age_days(self.now_dt, k.get("last_used_date"))
                status = str(k.get("status", "")).lower()
                self.node(knode, "access_key", acct, kid, attributes={
                    "status": status, "age_days": a_days, "last_used_days": last_days,
                    "last_used_service": k.get("last_used_service"),
                    "multiple_active": len(active_keys) > 1,
                })
                self.edge(uid, knode, "has_credential", primitive_id="ca_static_key_theft",
                          source="iam", evidence_id=knode)
                if status == "active":
                    self.finding(acct, "IAM_ACTIVE_ACCESS_KEY", "medium", knode,
                                 ["ca_static_key_theft"], mitre=["T1552.001"])
                    stale = (
                        (a_days is not None and a_days > 180)
                        or (last_days is not None and last_days > 90)
                        or (last_days is None and a_days is not None and a_days > 90)
                    )
                    if stale:
                        self.finding(acct, "IAM_STALE_ACCESS_KEY", "high", knode,
                                     ["ca_static_key_theft", "ps_long_lived_key"], mitre=["T1552.001"])

            if console and not mfa:
                self.finding(acct, "IAM_USER_NO_MFA", "high" if caps["admin_like"] else "medium",
                             uid, ["ca_no_mfa_phish", "pe_no_mfa_admin_console"], mitre=["T1078.004", "T1621"])

            self._principal_privesc(acct, uid, admin_node, name, caps, u.get("boundary"), kind="user")

    def _add_groups(self, acct, groups):
        for g in groups:
            gid = f"iam_group:{acct}:{g['name']}"
            self.node(gid, "iam_group", acct, g["name"], arn=g.get("arn"),
                      attributes={"members": g.get("members", [])})
            for member in g.get("members", []):
                self.edge(f"iam_user:{acct}:{member}", gid, "member_of", source="iam")

    def _add_roles(self, acct, acct_node, admin_node, collected, roles):
        for r in roles:
            name = r["name"]
            rid = f"iam_role:{acct}:{name}"
            caps = analyze_principal(r.get("statements", []), r.get("attached_arns", []))
            self.node(rid, "iam_role", acct, name, arn=r.get("arn"), attributes={
                "path": r.get("path"), "permission_boundary": r.get("boundary"),
                "admin_like": caps["admin_like"], "iam_full": caps["iam_full"],
                "trust_policy": r.get("trust_policy"),
            })
            self._principal_privesc(acct, rid, admin_node, name, caps, r.get("boundary"), kind="role")
            self._role_trust(acct, rid, acct_node, admin_node, collected, name, caps, r.get("trust_policy"))

    def _principal_privesc(self, acct, pid, admin_node, name, caps, boundary, kind):
        prims = []
        if caps["admin_managed"]:
            self.finding(acct, "IAM_ADMIN_MANAGED_POLICY", "critical", pid, ["pe_admin", "pe_no_mfa_admin_console"], mitre=["T1078"])
        if caps["iam_full"]:
            self.finding(acct, "IAM_FULL_ACCESS", "critical", pid, ["pe_iam_fullaccess"], mitre=["T1098"])
            prims.append("pe_iam_fullaccess")
        if caps["wildcard_inline"]:
            self.finding(acct, "IAM_WILDCARD_INLINE_POLICY", "high", pid, ["pe_wildcard_policy"], mitre=["T1098"])
            prims.append("pe_wildcard_policy")
        if caps["ec2_full"]:
            self.finding(acct, "IAM_EC2_FULL", "high", pid, ["pe_ec2_run_as_role"], mitre=["T1078"])
        if caps["ssm_full"]:
            self.finding(acct, "IAM_SSM_FULL", "high", pid, ["pe_ssm_sendcommand", "lm_ssm_lateral"], mitre=["T1651", "T1021"])

        # can_escalate -> account administrator when holding admin / IAMFullAccess / wildcard *:*
        if caps["admin_like"] or caps["iam_full"]:
            self.edge(pid, admin_node, "can_escalate", primitive_id="pe_admin", source="iam")

        # PassRole edges to the roles the principal can pass, tagged by consuming service.
        if caps["passrole_via"]:
            targets = self._passrole_targets(acct, caps["passrole_resources"])
            for via, control, primitive in caps["passrole_via"]:
                self.finding(acct, control, "high", pid, [primitive], mitre=["T1548"])
                for role_id in targets:
                    self.edge(pid, role_id, "can_passrole", primitive_id=primitive, via=via, source="iam")

        # CI/CD robot with admin.
        if CI_ROBOT_RE.search(name) and caps["admin_like"]:
            self.finding(acct, "CI_ROBOT_ADMIN", "critical", pid, ["lm_ci_robot_pivot"], mitre=["T1078"])

        # Missing permission boundary on a provisioning / admin identity.
        provisioning = caps["admin_like"] or caps["iam_full"] or bool(caps["passrole_via"])
        if provisioning and not boundary:
            self.finding(acct, "NO_PERMISSION_BOUNDARY", "high", pid, ["pe_no_permission_boundary"], mitre=["T1098"])

    def _passrole_targets(self, acct, resources):
        role_ids = [nid for nid, n in self.nodes.items()
                    if n["type"] == "iam_role" and n["account_id"] == acct]
        if not resources or any(str(r) == "*" for r in resources):
            admin = [rid for rid in role_ids if self.nodes[rid]["attributes"].get("admin_like")]
            return admin or role_ids
        matched = []
        for rid in role_ids:
            arn = self.nodes[rid].get("arn") or ""
            name = self.nodes[rid]["name"]
            for res in resources:
                if fnmatch.fnmatch(arn, str(res)) or str(res).endswith("/" + name):
                    matched.append(rid)
                    break
        return matched

    def _role_trust(self, acct, rid, acct_node, admin_node, collected, name, caps, trust_doc):
        # Name-based special roles.
        if name == "OrganizationAccountAccessRole":
            self.finding(acct, "ORG_ACCOUNT_ACCESS_ROLE", "critical", rid,
                         ["lm_org_account_access_role"], mitre=["T1078", "T1550"])
            self.edge(rid, admin_node, "can_escalate", primitive_id="pe_admin", source="iam")
        if name == "AWSControlTowerExecution":
            self.finding(acct, "AWS_CONTROL_TOWER_EXECUTION", "critical", rid,
                         ["lm_org_account_access_role"], mitre=["T1078"])
        if name.startswith("AWSReservedSSO_") and caps["admin_like"]:
            self.finding(acct, "SSO_ADMIN_ROLE", "high", rid, ["lm_sso_role_fanout"], mitre=["T1078.004"])

        if trust_doc is None:
            return
        facts = analyze_trust(trust_doc)
        if facts["wildcard_principal"]:
            ext = self.external_account("*")
            self.finding(acct, "IAM_RISKY_TRUST_POLICY", "critical", rid,
                         ["lm_confused_deputy_no_externalid"], mitre=["T1199", "T1078"])
            self.edge(rid, ext, "trusts", primitive_id="lm_confused_deputy_no_externalid",
                      condition="principal wildcard", source="iam")
            self.edge(ext, rid, "can_assume", condition="principal wildcard", source="iam")

        for p in facts["aws_principals"]:
            arn = p["arn"]
            p_acct = account_of_arn(arn)
            kind = principal_kind(arn)
            external = p_acct is not None and p_acct not in collected
            extid = p["external_id"]

            if kind == "account" or p_acct is None:
                # account-level (root) trust
                if external:
                    src = self.external_account(p_acct)
                else:
                    src = f"account:{p_acct}" if p_acct else acct_node
                    self.node(src, "account", p_acct or acct, p_acct or acct)
            elif kind == "user" and not external:
                src = f"iam_user:{p_acct}:{arn.split('/')[-1]}"
                self.node(src, "iam_user", p_acct, arn.split("/")[-1], arn=arn)
            elif kind == "role" and not external:
                src = f"iam_role:{p_acct}:{arn.split('/')[-1]}"
                self.node(src, "iam_role", p_acct, arn.split("/")[-1], arn=arn)
            else:
                src = self.external_account(p_acct)

            condition = "external_id present" if extid else "external_id absent"
            self.edge(src, rid, "can_assume", condition=condition, source="iam", evidence_id=rid)
            self.edge(rid, src, "trusts", condition=condition, source="iam", evidence_id=rid)

            if external and not extid:
                self.finding(acct, "IAM_RISKY_TRUST_POLICY", "high", rid,
                             ["lm_confused_deputy_no_externalid"], mitre=["T1199", "T1078"])

    def _add_root(self, acct, data):
        summary = data.get("account_summary") or {}
        root_keys = summary.get("AccountAccessKeysPresent")
        root_mfa = summary.get("AccountMFAEnabled")
        root_events = data.get("root_events") or []
        if root_keys:
            self.finding(acct, "ROOT_ACTIVITY", "critical", f"account:{acct}:root-access-key",
                         ["pe_root_mfa_manipulation"], mitre=["T1098"], raw_source="iam:GetAccountSummary")
        if root_events:
            self.finding(acct, "ROOT_ACTIVITY", "critical", f"account:{acct}:root-usage",
                         ["pe_root_mfa_manipulation"], mitre=["T1098", "T1531"], raw_source="cloudtrail:ingest")
        if root_mfa == 0:
            self.finding(acct, "ROOT_MFA_DISABLED", "critical", f"account:{acct}:root-mfa",
                         ["pe_root_mfa_manipulation", "ps_deactivate_mfa"], mitre=["T1531"],
                         raw_source="iam:GetAccountSummary")

    def _add_org(self, acct, org):
        if not org:
            return
        acct_node = f"account:{acct}"
        for member in org.get("accounts", []):
            mid = f"account:{member['account_id']}"
            self.node(mid, "account", member["account_id"], member.get("name") or member["account_id"],
                      attributes={"org_member": True})
        if not org.get("scps"):
            self.finding(acct, "NO_PERMISSION_BOUNDARY", "high", f"organization:{org.get('org_id', 'unknown')}",
                         ["pe_no_permission_boundary"], mitre=["T1098"], raw_source="organizations:ListPolicies")

    # -- output ----------------------------------------------------------- #
    def envelope(self):
        return {
            "schema": SCHEMA, "customer": self.customer, "collected_at": self.now_iso,
            "source_skill": SOURCE_SKILL,
            "accounts": self.accounts,
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges.values()),
            "findings": self.findings,
            "crown_jewels": [],
            "active_threats": [],
            "gaps": self.gaps,
        }


# --------------------------------------------------------------------------- #
# ingest — reuse existing IAM key-risk JSON/CSV and CloudTrail (root usage)
# --------------------------------------------------------------------------- #
def iter_ingest_files(patterns):
    for pattern in patterns:
        p = Path(pattern)
        if p.is_dir():
            for child in sorted(p.rglob("*.json")) + sorted(p.rglob("*.jsonl")) + sorted(p.rglob("*.csv")):
                yield child
        elif p.exists():
            yield p
        else:
            for match in sorted(Path().glob(pattern)):
                yield match


def load_ingest(patterns):
    """Return {'root_events': {acct:[...]}, 'access_keys': {acct:[...]}} from prior outputs."""
    root_events = {}
    access_keys = {}
    for path in iter_ingest_files(patterns or []):
        try:
            if path.suffix.lower() == ".csv":
                rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8", errors="replace"))))
            elif path.suffix.lower() == ".jsonl":
                rows = [json.loads(ln) for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
            else:
                doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                rows = doc if isinstance(doc, list) else doc.get("records") or doc.get("rows") or doc.get("Events") or [doc]
        except (OSError, ValueError):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            _ingest_row(row, root_events, access_keys)
    return {"root_events": root_events, "access_keys": access_keys}


def _ingest_row(row, root_events, access_keys):
    # CloudTrail root usage
    ident = row.get("userIdentity") or row.get("UserIdentity") or {}
    ct = row.get("CloudTrailEvent")
    if isinstance(ct, str):
        try:
            inner = json.loads(ct)
            ident = inner.get("userIdentity", ident)
            row = inner
        except json.JSONDecodeError:
            pass
    if isinstance(ident, dict) and str(ident.get("type", "")).lower() == "root":
        acct = ident.get("accountId") or row.get("recipientAccountId") or "unknown"
        root_events.setdefault(str(acct), []).append({
            "event": row.get("eventName"), "time": row.get("eventTime"),
        })
        return
    # IAM access-key risk record
    kid = row.get("access_key_id") or row.get("AccessKeyId") or row.get("accessKeyId")
    if kid:
        acct = row.get("account_id") or row.get("AccountId") or row.get("account") or "unknown"
        access_keys.setdefault(str(acct), []).append({
            "id": kid, "user": row.get("user_name") or row.get("UserName") or row.get("user"),
            "status": row.get("status") or row.get("Status") or "Active",
            "create_date": row.get("create_date") or row.get("CreateDate"),
            "last_used_date": row.get("last_used_date") or row.get("AccessKeyLastUsedDate"),
        })


# --------------------------------------------------------------------------- #
# live collection (boto3; imported lazily; all failures -> Gap)
# --------------------------------------------------------------------------- #
def collect_account(entry, ingest, errors):
    """Collect IAM/identity/trust facts for one account. Returns account_data dict."""
    import boto3  # lazy — keeps py_compile / self-test boto3-free
    from botocore.exceptions import ClientError, BotoCoreError

    acct = entry["account_id"]
    data = {"account_id": acct, "label": entry.get("label"), "env": entry.get("env", "unknown"),
            "is_management": entry.get("is_management", False), "errors": [],
            "users": [], "roles": [], "groups": [], "root_events": ingest["root_events"].get(acct, [])}

    try:
        session = _session_for_account(boto3, entry)
        iam = session.client("iam")
    except (ClientError, BotoCoreError, Exception) as exc:  # noqa: BLE001 - assume-role failure
        data["errors"].append({"area": "assume_role", "reason": f"{type(exc).__name__}: {exc}",
                               "recommended": f"Grant sts:AssumeRole into arn:aws:iam::{acct}:role/{DEFAULT_ROLE_NAME}"})
        return data

    _safe(data, "users", lambda: _collect_users(iam), errors=data["errors"], acct=acct,
          area="iam_users", rec="Grant iam:ListUsers/ListAccessKeys/ListMFADevices/GetLoginProfile/ListAttachedUserPolicies")
    _safe(data, "roles", lambda: _collect_roles(iam), errors=data["errors"], acct=acct,
          area="iam_roles", rec="Grant iam:ListRoles/ListAttachedRolePolicies/ListRolePolicies/GetRolePolicy")
    _safe(data, "groups", lambda: _collect_groups(iam), errors=data["errors"], acct=acct,
          area="iam_groups", rec="Grant iam:ListGroups/GetGroup/ListAttachedGroupPolicies")
    _safe(data, "account_summary", lambda: iam.get_account_summary().get("SummaryMap"),
          errors=data["errors"], acct=acct, area="account_summary", rec="Grant iam:GetAccountSummary")
    _safe(data, "password_policy", lambda: _password_policy(iam), errors=data["errors"], acct=acct,
          area="password_policy", rec="Grant iam:GetAccountPasswordPolicy")
    _safe(data, "organizations", lambda: _collect_org(session), errors=data["errors"], acct=acct,
          area="organizations", rec="Grant organizations:List*/Describe* (management/delegated-admin only)")

    # supplement keys from ingest when live user collection was denied
    if not data["users"] and ingest["access_keys"].get(acct):
        by_user = {}
        for k in ingest["access_keys"][acct]:
            by_user.setdefault(k.get("user") or "unknown", []).append(k)
        data["users"] = [{"name": u, "access_keys": ks, "statements": [], "attached_arns": []}
                         for u, ks in by_user.items()]
    return data


def _session_for_account(boto3, entry):
    if entry.get("profile"):
        return boto3.Session(profile_name=entry["profile"])
    acct = entry["account_id"]
    role_arn = entry.get("role_arn") or f"arn:aws:iam::{acct}:role/{DEFAULT_ROLE_NAME}"
    params = {"RoleArn": role_arn, "RoleSessionName": "aws-identity-trust-collector"}
    if entry.get("external_id"):
        params["ExternalId"] = entry["external_id"]
    creds = boto3.client("sts").assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _safe(data, key, fn, errors, acct, area, rec):
    from botocore.exceptions import ClientError, BotoCoreError
    try:
        data[key] = fn()
    except (ClientError, BotoCoreError) as exc:
        errors.append({"area": area, "reason": f"{type(exc).__name__}: {exc}", "recommended": rec})
    except Exception as exc:  # noqa: BLE001 - never hard-fail one account
        errors.append({"area": area, "reason": f"{type(exc).__name__}: {exc}", "recommended": rec})


def _policy_doc(iam, arn):
    ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    return iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]


def _statements_for(iam, attached, inline_docs):
    stmts = []
    arns = []
    for pol in attached:
        arns.append(pol["PolicyArn"])
        try:
            stmts.extend(iter_statements(_policy_doc(iam, pol["PolicyArn"])))
        except Exception:  # noqa: BLE001 - fall back to name heuristics via arns
            pass
    for doc in inline_docs:
        stmts.extend(iter_statements(doc))
    return stmts, arns


def _collect_users(iam):
    out = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
            inline_names = iam.list_user_policies(UserName=name).get("PolicyNames", [])
            inline_docs = [iam.get_user_policy(UserName=name, PolicyName=p)["PolicyDocument"] for p in inline_names]
            groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=name).get("Groups", [])]
            # fold group policies into effective statements
            for gname in groups:
                g_attached = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
                g_inline = iam.list_group_policies(GroupName=gname).get("PolicyNames", [])
                g_docs = [iam.get_group_policy(GroupName=gname, PolicyName=p)["PolicyDocument"] for p in g_inline]
                gs, ga = _statements_for(iam, g_attached, g_docs)
                inline_docs = inline_docs + g_docs
                attached = attached + g_attached
            stmts, arns = _statements_for(iam, attached, inline_docs)
            keys = []
            for k in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
                lu = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {})
                keys.append({
                    "id": k["AccessKeyId"], "status": k.get("Status"),
                    "create_date": _iso(k.get("CreateDate")),
                    "last_used_date": _iso(lu.get("LastUsedDate")),
                    "last_used_service": lu.get("ServiceName"),
                })
            mfa = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
            try:
                iam.get_login_profile(UserName=name)
                login = True
            except Exception:  # noqa: BLE001 - NoSuchEntity => no console login
                login = False
            out.append({
                "name": name, "arn": u.get("Arn"), "path": u.get("Path"),
                "boundary": (u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                "groups": groups, "attached_arns": arns, "statements": stmts,
                "access_keys": keys, "mfa_devices": mfa, "login_profile": login,
            })
    return out


def _collect_roles(iam):
    out = []
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            name = r["RoleName"]
            if r.get("Path", "").startswith("/aws-service-role/"):
                continue
            attached = iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
            inline_names = iam.list_role_policies(RoleName=name).get("PolicyNames", [])
            inline_docs = [iam.get_role_policy(RoleName=name, PolicyName=p)["PolicyDocument"] for p in inline_names]
            stmts, arns = _statements_for(iam, attached, inline_docs)
            out.append({
                "name": name, "arn": r.get("Arn"), "path": r.get("Path"),
                "boundary": (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                "trust_policy": r.get("AssumeRolePolicyDocument"),
                "attached_arns": arns, "statements": stmts,
            })
    return out


def _collect_groups(iam):
    out = []
    for page in iam.get_paginator("list_groups").paginate():
        for g in page["Groups"]:
            name = g["GroupName"]
            members = [m["UserName"] for m in iam.get_group(GroupName=name).get("Users", [])]
            out.append({"name": name, "arn": g.get("Arn"), "members": members})
    return out


def _password_policy(iam):
    try:
        return iam.get_account_password_policy().get("PasswordPolicy")
    except Exception:  # noqa: BLE001 - NoSuchEntity => no policy set
        return None


def _collect_org(session):
    org = session.client("organizations")
    root = org.list_roots()["Roots"][0]
    accounts = [{"account_id": a["Id"], "name": a.get("Name")}
                for page in org.get_paginator("list_accounts").paginate() for a in page["Accounts"]]
    scps = [p["Id"] for page in org.get_paginator("list_policies").paginate(Filter="SERVICE_CONTROL_POLICY")
            for p in page["Policies"]]
    return {"org_id": root.get("Arn", "").split("/")[-2] if "/" in root.get("Arn", "") else None,
            "accounts": accounts, "scps": scps}


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


# --------------------------------------------------------------------------- #
# self-test — emit a valid envelope from a tiny inline fixture (no AWS)
# --------------------------------------------------------------------------- #
def self_test_fixture():
    return [{
        "account_id": "111111111111", "label": "prod", "env": "prod",
        "account_summary": {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 0},
        "password_policy": None,
        "users": [{
            "name": "ci-deployer", "arn": "arn:aws:iam::111111111111:user/ci-deployer",
            "boundary": None, "groups": ["deployers"],
            "attached_arns": [MANAGED_IAM_FULL],
            "statements": [
                {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
                {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"},
            ],
            "access_keys": [
                {"id": "AKIAOLD", "status": "Active", "create_date": "2023-01-01T00:00:00Z", "last_used_date": None},
                {"id": "AKIANEW", "status": "Active", "create_date": "2025-12-01T00:00:00Z", "last_used_date": "2026-01-01T00:00:00Z"},
            ],
            "mfa_devices": [], "login_profile": True,
        }],
        "groups": [{"name": "deployers", "arn": "arn:aws:iam::111111111111:group/deployers", "members": ["ci-deployer"]}],
        "roles": [
            {"name": "OrganizationAccountAccessRole", "arn": "arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
             "boundary": None, "attached_arns": [MANAGED_ADMIN],
             "statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
             "trust_policy": {"Version": "2012-10-17", "Statement": [
                 {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}]}},
            {"name": "vendor-audit", "arn": "arn:aws:iam::111111111111:role/vendor-audit",
             "boundary": None, "attached_arns": [], "statements": [],
             "trust_policy": {"Version": "2012-10-17", "Statement": [
                 {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::888888888888:root"}, "Action": "sts:AssumeRole"}]}},
        ],
        "root_events": [{"event": "ConsoleLogin", "time": "2026-01-01T00:00:00Z"}],
    }]


def validate_envelope(env):
    errors = []
    if env.get("schema") != SCHEMA:
        errors.append("bad schema")
    for key in ("accounts", "nodes", "edges", "findings", "crown_jewels", "active_threats", "gaps"):
        if not isinstance(env.get(key), list):
            errors.append(f"missing/invalid array: {key}")
    ids = [n["id"] for n in env["nodes"]]
    if len(ids) != len(set(ids)):
        errors.append("duplicate node ids")
    node_ids = set(ids)
    for e in env["edges"]:
        for end in ("src", "dst"):
            if e[end] not in node_ids:
                errors.append(f"edge {end} references missing node: {e[end]}")
    return errors


def run_self_test(customer, now_iso, output):
    builder = ModelBuilder(customer or "self-test", now_iso or "2026-01-01T00:00:00Z")
    for acct in self_test_fixture():
        builder.add_account(acct)
    env = builder.envelope()
    errors = validate_envelope(env)
    controls = sorted({f["control"] for f in env["findings"]})
    edge_types = sorted({e["type"] for e in env["edges"]})
    if output:
        Path(output).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "self_test": "PASS" if not errors else "FAIL",
        "errors": errors,
        "nodes": len(env["nodes"]), "edges": len(env["edges"]), "findings": len(env["findings"]),
        "controls": controls, "edge_types": edge_types,
    }, indent=2))
    return 0 if not errors else 1


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(description="Deep AWS IAM/identity/trust collector -> aws_attack_model/v1 envelope")
    ap.add_argument("--accounts", help="accounts.json: [{account_id, role_arn?, profile?, external_id?, label?, env?}]")
    ap.add_argument("--ingest", nargs="*", default=[], help="dirs/globs of prior IAM key-risk JSON/CSV + CloudTrail to reuse")
    ap.add_argument("--customer", default="unknown", help="customer name stamped in the envelope")
    ap.add_argument("--now", help="ISO-8601 timestamp for reproducible age math (no datetime.now)")
    ap.add_argument("--output", default="identity_trust.json", help="output envelope path")
    ap.add_argument("--self-test", action="store_true", help="emit a valid envelope from an inline fixture (no AWS)")
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test(args.customer, args.now, args.output if args.output != "identity_trust.json" else None)

    if not args.now:
        ap.error("--now ISO-8601 is required for live collection (no datetime.now at runtime)")
    if not args.accounts:
        ap.error("--accounts accounts.json is required for live collection")

    accounts = json.loads(Path(args.accounts).read_text(encoding="utf-8"))
    if isinstance(accounts, dict):
        accounts = accounts.get("accounts", [])
    ingest = load_ingest(args.ingest)

    builder = ModelBuilder(args.customer, args.now)
    collected_ids = [a["account_id"] for a in accounts]
    for entry in accounts:
        errors = []
        data = collect_account(entry, ingest, errors)
        data["_collected_accounts"] = collected_ids
        builder.add_account(data)

    env = builder.envelope()
    Path(args.output).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": args.output, "accounts": len(env["accounts"]),
        "nodes": len(env["nodes"]), "edges": len(env["edges"]),
        "findings": len(env["findings"]), "gaps": len(env["gaps"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
