#!/usr/bin/env python3
"""
aws-attack-surface-collector :: collect_attack_surface.py

Collect the INTERNET-EXPOSURE that standard CSPM commonly misses, and emit it as an
`aws_attack_model/v1` envelope (see references/attack_model_schema.md) so the downstream
attack-graph-builder / enumerator / report-packager can traverse it.

This collector OWNS: nodes, edges (only the `exposes` edges from the singleton `internet`
node), findings, and gaps. All other envelope arrays (accounts is populated from the input,
crown_jewels / active_threats stay empty) are left for other collectors to fill.

Coverage (things CSPM baselines routinely skip):
  - Public EBS snapshots        (describe-snapshots OwnerIds=self + createVolumePermission=all)
  - Public AMIs                 (describe-images  Owners=self  + launchPermission=all)
  - Public/shared RDS snapshots (describe-db-snapshots + describe-db-snapshot-attributes 'restore')
  - Public ECR repos            (get-repository-policy with anonymous/* principal)
  - Public Lambda function URLs (get-function-url-config AuthType=NONE + get-policy)
  - Open API Gateway            (routes/methods AuthorizationType == NONE)
  - Redshift/DocumentDB/ElastiCache PubliclyAccessible
  - WAF association gaps        (internet-facing ALBs / CloudFront distributions with no WebACL)
  - VPC flow-log presence       (VPCs with no flow log = detection gap)
  - Public security-group map   (0.0.0.0/0 ingress + ports)
  - IMDSv1 state                (instances with HttpTokens == optional)

Design rules (per the shared contract):
  * stdlib + boto3 only. boto3 is imported lazily so --self-test runs without it.
  * Does NOT call datetime.now at import. `collected_at` comes from --now (with a runtime
    fallback only inside main(), never at import).
  * Per-account / per-service AccessDenied or API errors are recorded as Gap records and
    NEVER fail the whole run.
  * Never invents AWS data. Everything emitted comes from an API response or --ingest input.
"""

import argparse
import glob
import json
import os
import sys

SCHEMA = "aws_attack_model/v1"
SOURCE_SKILL = "aws-attack-surface-collector"
DEFAULT_ROLE_NAME = "TransilienceComplianceRole"
INTERNET_ID = "internet"

# Commercial regions (default sweep). Kept as a static list for determinism.
COMMERCIAL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ap-northeast-2", "ap-northeast-3", "ap-east-1",
    "sa-east-1", "me-south-1", "af-south-1",
]

# control -> primitive_id / severity / MITRE, sourced from aws-attack-primitive-kb.
# Keeping this map in sync with attack_primitives.json is what lets the graph builder tag
# our findings/nodes to the right kill-chain primitives.
CONTROL_MAP = {
    "EBS_SNAPSHOT_PUBLIC":      {"primitive": "ia_public_snapshot",  "severity": "high",     "mitre": ["T1580", "T1078"]},
    "AMI_PUBLIC":               {"primitive": "ia_public_snapshot",  "severity": "high",     "mitre": ["T1580", "T1078"]},
    "RDS_SNAPSHOT_PUBLIC":      {"primitive": "ia_public_snapshot",  "severity": "high",     "mitre": ["T1580", "T1078"]},
    "ECR_PUBLIC_REPO":          {"primitive": "ia_public_ecr",       "severity": "medium",   "mitre": ["T1190", "T1525"]},
    "LAMBDA_PUBLIC_URL":        {"primitive": "ia_public_lambda_url","severity": "medium",   "mitre": ["T1190"]},
    "APIGW_NO_AUTH":            {"primitive": "ia_public_api_gw",    "severity": "medium",   "mitre": ["T1190"]},
    "REDSHIFT_PUBLIC":          {"primitive": "ia_public_db",        "severity": "critical", "mitre": ["T1190"]},
    "DOCDB_PUBLIC":             {"primitive": "ia_public_db",        "severity": "critical", "mitre": ["T1190"]},
    "ELASTICACHE_PUBLIC":       {"primitive": "ia_public_db",        "severity": "critical", "mitre": ["T1190"]},
    "EC2_IMDSV2_NOT_ENFORCED":  {"primitive": "ca_imds_theft",       "severity": "high",     "mitre": ["T1552.005"]},
    "EC2_PUBLIC_ADMIN_PORT":    {"primitive": "ia_admin_port_open",  "severity": "high",     "mitre": ["T1190", "T1110"]},
    "EC2_PUBLIC_ALL_TRAFFIC":   {"primitive": "ia_all_traffic_sg",   "severity": "high",     "mitre": ["T1190"]},
    "ALB_INTERNET_FACING":      {"primitive": "ia_public_web_alb",   "severity": "high",     "mitre": ["T1190"]},
    "ALB_NO_WAF":               {"primitive": "ia_public_web_alb",   "severity": "medium",   "mitre": ["T1190"]},
    "CLOUDFRONT_NO_WAF":        {"primitive": "ia_public_web_alb",   "severity": "medium",   "mitre": ["T1190"]},
    "VPC_FLOW_LOGS_DISABLED":   {"primitive": "de_dns_tunneling",    "severity": "medium",   "mitre": ["T1071.004"]},
}

ADMIN_PORTS = {22, 3389}


# --------------------------------------------------------------------------------------
# Envelope model + helpers
# --------------------------------------------------------------------------------------
class Model:
    """Accumulator for the aws_attack_model/v1 envelope arrays this collector owns."""

    def __init__(self):
        self.accounts = []
        self.nodes = {}      # id -> node (de-dup by id)
        self.edges = []
        self.findings = {}   # id -> finding (de-dup by id)
        self.gaps = []

    # -- nodes ----------------------------------------------------------------
    def add_node(self, node_id, node_type, account_id, name, arn=None,
                 internet_facing=False, ports=None, cidrs=None, attributes=None):
        existing = self.nodes.get(node_id)
        if existing:
            # merge exposure (union ports/cidrs, OR internet_facing) + attributes
            exp = existing["exposure"]
            exp["internet_facing"] = exp["internet_facing"] or internet_facing
            exp["ports"] = sorted(set(exp["ports"]) | set(ports or []))
            exp["cidrs"] = sorted(set(exp["cidrs"]) | set(cidrs or []))
            if attributes:
                existing["attributes"].update(attributes)
            return node_id
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "account_id": account_id,
            "name": name,
            "arn": arn,
            "exposure": {
                "internet_facing": bool(internet_facing),
                "ports": sorted(set(ports or [])),
                "cidrs": sorted(set(cidrs or [])),
            },
            "attributes": attributes or {},
        }
        return node_id

    # -- edges ----------------------------------------------------------------
    def add_exposes_edge(self, dst_id, primitive_id, via, evidence_id, evidence_source="config"):
        self.edges.append({
            "src": INTERNET_ID,
            "dst": dst_id,
            "type": "exposes",
            "attributes": {"primitive_id": primitive_id, "via": via, "condition": None},
            "evidence": {"source": evidence_source, "id": evidence_id},
        })

    # -- findings -------------------------------------------------------------
    def add_finding(self, control, account_id, resource, internet_facing,
                    raw_source, severity=None, extra_id=""):
        cm = CONTROL_MAP.get(control, {})
        prim = cm.get("primitive")
        fid = ":".join([control, account_id, extra_id or resource])
        if fid in self.findings:
            return fid
        self.findings[fid] = {
            "id": fid,
            "account_id": account_id,
            "control": control,
            "severity": severity or cm.get("severity", "medium"),
            "resource": resource,
            "internet_facing": bool(internet_facing),
            "primitive_ids": [prim] if prim else [],
            "mitre": cm.get("mitre", []),
            "raw_source": raw_source,
        }
        return fid

    # -- gaps -----------------------------------------------------------------
    def add_gap(self, area, reason, accounts, recommended_collection):
        self.gaps.append({
            "area": area,
            "reason": reason,
            "accounts": accounts if isinstance(accounts, list) else [accounts],
            "recommended_collection": recommended_collection,
        })

    # -- convenience: record one internet-exposed resource end to end ---------
    def record_exposure(self, node_type, account_id, name, control, *, arn=None,
                        region="global", ports=None, cidrs=None, attributes=None,
                        internet_facing=True, add_edge=True, raw_source="api"):
        node_id = "{}:{}:{}".format(node_type, account_id, name)
        self.add_node(node_id, node_type, account_id, name, arn=arn,
                      internet_facing=internet_facing, ports=ports, cidrs=cidrs,
                      attributes=attributes)
        cm = CONTROL_MAP.get(control, {})
        if add_edge:
            self.add_exposes_edge(node_id, cm.get("primitive"), region, node_id)
        self.add_finding(control, account_id, arn or name, internet_facing,
                         raw_source, extra_id=name)
        return node_id

    # -- serialize ------------------------------------------------------------
    def envelope(self, customer, collected_at):
        return {
            "schema": SCHEMA,
            "customer": customer,
            "collected_at": collected_at,
            "source_skill": SOURCE_SKILL,
            "accounts": self.accounts,
            "nodes": [{"id": INTERNET_ID, "type": "internet", "account_id": "internet",
                       "name": "internet", "arn": None,
                       "exposure": {"internet_facing": True, "ports": [], "cidrs": ["0.0.0.0/0"]},
                       "attributes": {}}] + list(self.nodes.values()),
            "edges": self.edges,
            "findings": list(self.findings.values()),
            "crown_jewels": [],
            "active_threats": [],
            "gaps": self.gaps,
        }


# --------------------------------------------------------------------------------------
# boto3 session (lazy import so --self-test needs no boto3 / creds)
# --------------------------------------------------------------------------------------
def assume_session(acct, model):
    """Return a boto3.Session for an account, or None (recording a Gap) on failure."""
    try:
        import boto3  # lazy
    except Exception as exc:  # noqa: BLE001
        model.add_gap("boto3", "boto3 not importable: {}".format(exc),
                      [acct.get("account_id", "unknown")],
                      "pip install boto3 and re-run")
        return None

    acct_id = acct.get("account_id", "unknown")
    try:
        if acct.get("profile"):
            return boto3.Session(profile_name=acct["profile"])
        role_arn = acct.get("role_arn") or "arn:aws:iam::{}:role/{}".format(acct_id, DEFAULT_ROLE_NAME)
        sts = boto3.client("sts")
        kwargs = {"RoleArn": role_arn, "RoleSessionName": "aws-attack-surface-collector"}
        if acct.get("external_id"):
            kwargs["ExternalId"] = acct["external_id"]
        creds = sts.assume_role(**kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except Exception as exc:  # noqa: BLE001
        model.add_gap("assume_role",
                      "could not assume role for account: {}".format(exc),
                      [acct_id],
                      "verify {} exists and is assumable (sts:AssumeRole)".format(
                          acct.get("role_arn") or DEFAULT_ROLE_NAME))
        return None


def _gap_on_error(model, area, acct_id, region, exc, recommended):
    model.add_gap(area,
                  "{} collection failed in {}: {}".format(area, region or "global", exc),
                  [acct_id], recommended)


def _parse_policy_public(policy_doc):
    """True if an IAM/resource policy JSON string grants access to anonymous/* principals."""
    try:
        doc = json.loads(policy_doc) if isinstance(policy_doc, str) else policy_doc
    except Exception:  # noqa: BLE001
        return False
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        p = s.get("Principal")
        if p == "*":
            return True
        if isinstance(p, dict):
            for v in p.values():
                if v == "*" or (isinstance(v, list) and "*" in v):
                    return True
    return False


# --------------------------------------------------------------------------------------
# Per-service collectors (each fully wrapped; failures become Gaps, never exceptions)
# --------------------------------------------------------------------------------------
def collect_security_groups(session, region, acct_id, model):
    """Return {sg_id: {'ports': set(int), 'all_traffic': bool}} for SGs open to 0.0.0.0/0."""
    public = {}
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                ports, all_traffic = set(), False
                for perm in sg.get("IpPermissions", []):
                    open_cidr = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                    open_cidr = open_cidr or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                    if not open_cidr:
                        continue
                    if perm.get("IpProtocol") == "-1":
                        all_traffic = True
                        ports.add(-1)
                    else:
                        fp = perm.get("FromPort")
                        tp = perm.get("ToPort")
                        if fp is not None:
                            ports.add(int(fp))
                        if tp is not None and tp != fp:
                            ports.add(int(tp))
                if ports or all_traffic:
                    sg_id = sg.get("GroupId")
                    public[sg_id] = {"ports": ports, "all_traffic": all_traffic}
                    if all_traffic:
                        model.add_finding("EC2_PUBLIC_ALL_TRAFFIC", acct_id, sg_id, True,
                                          "ec2:describe_security_groups", extra_id="{}:{}".format(region, sg_id))
                    if ports & ADMIN_PORTS:
                        model.add_finding("EC2_PUBLIC_ADMIN_PORT", acct_id, sg_id, True,
                                          "ec2:describe_security_groups", extra_id="{}:{}".format(region, sg_id))
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "security_groups", acct_id, region, exc,
                      "aws ec2 describe-security-groups --region {}".format(region))
    return public


def collect_ec2_instances(session, region, acct_id, model, public_sgs):
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    iid = inst.get("InstanceId")
                    public_ip = inst.get("PublicIpAddress")
                    http_tokens = (inst.get("MetadataOptions") or {}).get("HttpTokens")
                    imds_optional = http_tokens == "optional"
                    # ports open to internet via this instance's SGs
                    ports = set()
                    for sg in inst.get("SecurityGroups", []):
                        info = public_sgs.get(sg.get("GroupId"))
                        if info:
                            ports |= info["ports"]
                    internet_facing = bool(public_ip)
                    if not (imds_optional or internet_facing):
                        continue  # not interesting for exposure/IMDS purposes
                    node_id = "ec2_instance:{}:{}".format(acct_id, iid)
                    model.add_node(node_id, "ec2_instance", acct_id, iid,
                                   arn=None, internet_facing=internet_facing,
                                   ports=sorted(p for p in ports if p != -1),
                                   cidrs=["0.0.0.0/0"] if (internet_facing and ports) else [],
                                   attributes={"public_ip": public_ip,
                                               "http_tokens": http_tokens,
                                               "region": region})
                    if internet_facing and ports:
                        model.add_exposes_edge(node_id, "ia_admin_port_open" if (ports & ADMIN_PORTS) else "ia_public_web_alb",
                                               region, node_id)
                    if imds_optional:
                        model.add_finding("EC2_IMDSV2_NOT_ENFORCED", acct_id, iid, internet_facing,
                                          "ec2:describe_instances", extra_id="{}:{}".format(region, iid))
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "ec2_instances", acct_id, region, exc,
                      "aws ec2 describe-instances --region {}".format(region))


def collect_ebs_snapshots(session, region, acct_id, model):
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                sid = snap.get("SnapshotId")
                try:
                    attr = ec2.describe_snapshot_attribute(SnapshotId=sid, Attribute="createVolumePermission")
                except Exception as exc:  # noqa: BLE001
                    _gap_on_error(model, "ebs_snapshot_attribute", acct_id, region, exc,
                                  "aws ec2 describe-snapshot-attribute --snapshot-id {} --attribute createVolumePermission".format(sid))
                    continue
                perms = attr.get("CreateVolumePermissions", [])
                public = any(p.get("Group") == "all" for p in perms)
                shared = [p.get("UserId") for p in perms if p.get("UserId")]
                if public:
                    model.record_exposure("ebs_snapshot", acct_id, sid, "EBS_SNAPSHOT_PUBLIC",
                                          region=region, attributes={"shared_public": True, "region": region,
                                          "encrypted": snap.get("Encrypted")},
                                          raw_source="ec2:describe_snapshot_attribute")
                elif shared:
                    model.record_exposure("ebs_snapshot", acct_id, sid, "EBS_SNAPSHOT_PUBLIC",
                                          region=region, internet_facing=False, add_edge=False,
                                          attributes={"shared_public": False, "shared_accounts": shared,
                                                      "region": region},
                                          raw_source="ec2:describe_snapshot_attribute")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "ebs_snapshots", acct_id, region, exc,
                      "aws ec2 describe-snapshots --owner-ids self --region {}".format(region))


def collect_amis(session, region, acct_id, model):
    try:
        ec2 = session.client("ec2", region_name=region)
        images = ec2.describe_images(Owners=["self"]).get("Images", [])
        for img in images:
            aid = img.get("ImageId")
            if img.get("Public"):
                model.record_exposure("ami", acct_id, aid, "AMI_PUBLIC", region=region,
                                      attributes={"shared_public": True, "region": region,
                                                  "name": img.get("Name")},
                                      raw_source="ec2:describe_images")
                continue
            try:
                attr = ec2.describe_image_attribute(ImageId=aid, Attribute="launchPermission")
            except Exception as exc:  # noqa: BLE001
                _gap_on_error(model, "ami_attribute", acct_id, region, exc,
                              "aws ec2 describe-image-attribute --image-id {} --attribute launchPermission".format(aid))
                continue
            perms = attr.get("LaunchPermissions", [])
            if any(p.get("Group") == "all" for p in perms):
                model.record_exposure("ami", acct_id, aid, "AMI_PUBLIC", region=region,
                                      attributes={"shared_public": True, "region": region},
                                      raw_source="ec2:describe_image_attribute")
            else:
                shared = [p.get("UserId") for p in perms if p.get("UserId")]
                if shared:
                    model.record_exposure("ami", acct_id, aid, "AMI_PUBLIC", region=region,
                                          internet_facing=False, add_edge=False,
                                          attributes={"shared_public": False, "shared_accounts": shared,
                                                      "region": region},
                                          raw_source="ec2:describe_image_attribute")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "amis", acct_id, region, exc,
                      "aws ec2 describe-images --owners self --region {}".format(region))


def collect_rds_snapshots(session, region, acct_id, model):
    try:
        rds = session.client("rds", region_name=region)
        # instance snapshots
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate():
            for snap in page.get("DBSnapshots", []):
                sid = snap.get("DBSnapshotIdentifier")
                _rds_snapshot_attr(rds, sid, acct_id, region, model,
                                   attr_fn="describe_db_snapshot_attributes",
                                   key="DBSnapshotAttributesResult", arn=snap.get("DBSnapshotArn"))
        # cluster snapshots (Aurora)
        cpag = rds.get_paginator("describe_db_cluster_snapshots")
        for page in cpag.paginate():
            for snap in page.get("DBClusterSnapshots", []):
                sid = snap.get("DBClusterSnapshotIdentifier")
                _rds_snapshot_attr(rds, sid, acct_id, region, model,
                                   attr_fn="describe_db_cluster_snapshot_attributes",
                                   key="DBClusterSnapshotAttributesResult",
                                   arn=snap.get("DBClusterSnapshotArn"), cluster=True)
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "rds_snapshots", acct_id, region, exc,
                      "aws rds describe-db-snapshots --region {}".format(region))


def _rds_snapshot_attr(rds, sid, acct_id, region, model, attr_fn, key, arn=None, cluster=False):
    try:
        if cluster:
            res = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=sid)
        else:
            res = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "rds_snapshot_attribute", acct_id, region, exc,
                      "aws rds {} --identifier {}".format(attr_fn.replace('_', '-'), sid))
        return
    attrs = (res.get(key, {}) or {}).get("DBClusterSnapshotAttributes" if cluster
                                         else "DBSnapshotAttributes", [])
    values = []
    for a in attrs:
        if a.get("AttributeName") == "restore":
            values = a.get("AttributeValues", [])
    if "all" in values:
        model.record_exposure("rds_snapshot", acct_id, sid, "RDS_SNAPSHOT_PUBLIC", region=region,
                              arn=arn, attributes={"shared_public": True, "region": region,
                                                   "cluster": cluster},
                              raw_source=attr_fn)
    elif values:
        model.record_exposure("rds_snapshot", acct_id, sid, "RDS_SNAPSHOT_PUBLIC", region=region,
                              arn=arn, internet_facing=False, add_edge=False,
                              attributes={"shared_public": False, "shared_accounts": values,
                                          "region": region, "cluster": cluster},
                              raw_source=attr_fn)


def collect_ecr(session, region, acct_id, model):
    try:
        ecr = session.client("ecr", region_name=region)
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo.get("repositoryName")
                try:
                    pol = ecr.get_repository_policy(repositoryName=name)
                except Exception:  # noqa: BLE001 -- RepositoryPolicyNotFoundException is normal
                    continue
                if _parse_policy_public(pol.get("policyText", "{}")):
                    model.record_exposure("ecr_repo", acct_id, name, "ECR_PUBLIC_REPO", region=region,
                                          arn=repo.get("repositoryArn"),
                                          attributes={"region": region},
                                          raw_source="ecr:get_repository_policy")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "ecr", acct_id, region, exc,
                      "aws ecr describe-repositories --region {}".format(region))


def collect_lambda(session, region, acct_id, model):
    try:
        lam = session.client("lambda", region_name=region)
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn.get("FunctionName")
                try:
                    cfg = lam.get_function_url_config(FunctionName=name)
                except Exception:  # noqa: BLE001 -- ResourceNotFound means no URL, normal
                    continue
                if cfg.get("AuthType") == "NONE":
                    model.record_exposure("lambda_function", acct_id, name, "LAMBDA_PUBLIC_URL",
                                          region=region, arn=fn.get("FunctionArn"),
                                          attributes={"url_auth": "NONE", "function_url": cfg.get("FunctionUrl"),
                                                      "region": region},
                                          raw_source="lambda:get_function_url_config")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "lambda", acct_id, region, exc,
                      "aws lambda list-functions --region {}".format(region))


def collect_apigw(session, region, acct_id, model):
    # HTTP/WebSocket APIs (v2)
    try:
        apiv2 = session.client("apigatewayv2", region_name=region)
        apis = apiv2.get_apis().get("Items", [])
        for api in apis:
            api_id = api.get("ApiId")
            try:
                routes = apiv2.get_routes(ApiId=api_id).get("Items", [])
            except Exception as exc:  # noqa: BLE001
                _gap_on_error(model, "apigwv2_routes", acct_id, region, exc,
                              "aws apigatewayv2 get-routes --api-id {}".format(api_id))
                continue
            open_routes = [r.get("RouteKey") for r in routes
                           if (r.get("AuthorizationType") in (None, "NONE"))]
            if open_routes:
                model.record_exposure("api_gateway", acct_id, api_id, "APIGW_NO_AUTH", region=region,
                                      attributes={"authorization": "NONE", "protocol": api.get("ProtocolType"),
                                                  "endpoint": api.get("ApiEndpoint"),
                                                  "open_routes": open_routes, "region": region},
                                      raw_source="apigatewayv2:get_routes")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "apigatewayv2", acct_id, region, exc,
                      "aws apigatewayv2 get-apis --region {}".format(region))
    # REST APIs (v1) -- best-effort method scan
    try:
        api = session.client("apigateway", region_name=region)
        for rest in api.get_rest_apis().get("items", []):
            rid = rest.get("id")
            try:
                resources = api.get_resources(restApiId=rid, limit=500).get("items", [])
            except Exception:  # noqa: BLE001
                continue
            no_auth = False
            for r in resources:
                for method, m in (r.get("resourceMethods") or {}).items():
                    try:
                        detail = api.get_method(restApiId=rid, resourceId=r.get("id"), httpMethod=method)
                    except Exception:  # noqa: BLE001
                        continue
                    if detail.get("authorizationType", "NONE") == "NONE" and not detail.get("apiKeyRequired"):
                        no_auth = True
            if no_auth:
                model.record_exposure("api_gateway", acct_id, rid, "APIGW_NO_AUTH", region=region,
                                      attributes={"authorization": "NONE", "protocol": "REST",
                                                  "name": rest.get("name"), "region": region},
                                      raw_source="apigateway:get_method")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "apigateway", acct_id, region, exc,
                      "aws apigateway get-rest-apis --region {}".format(region))


def collect_redshift(session, region, acct_id, model):
    try:
        rs = session.client("redshift", region_name=region)
        paginator = rs.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                if c.get("PubliclyAccessible"):
                    cid = c.get("ClusterIdentifier")
                    ep = c.get("Endpoint") or {}
                    model.record_exposure("redshift", acct_id, cid, "REDSHIFT_PUBLIC", region=region,
                                          ports=[ep.get("Port")] if ep.get("Port") else [],
                                          cidrs=["0.0.0.0/0"],
                                          attributes={"publicly_accessible": True, "endpoint": ep.get("Address"),
                                                      "region": region},
                                          raw_source="redshift:describe_clusters")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "redshift", acct_id, region, exc,
                      "aws redshift describe-clusters --region {}".format(region))


def collect_docdb(session, region, acct_id, model):
    try:
        docdb = session.client("docdb", region_name=region)
        paginator = docdb.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for inst in page.get("DBInstances", []):
                if inst.get("PubliclyAccessible"):
                    iid = inst.get("DBInstanceIdentifier")
                    ep = inst.get("Endpoint") or {}
                    model.record_exposure("documentdb", acct_id, iid, "DOCDB_PUBLIC", region=region,
                                          arn=inst.get("DBInstanceArn"),
                                          ports=[ep.get("Port")] if ep.get("Port") else [],
                                          cidrs=["0.0.0.0/0"],
                                          attributes={"publicly_accessible": True, "endpoint": ep.get("Address"),
                                                      "region": region},
                                          raw_source="docdb:describe_db_instances")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "docdb", acct_id, region, exc,
                      "aws docdb describe-db-instances --region {}".format(region))


def collect_elasticache(session, region, acct_id, model, public_sgs):
    """ElastiCache has no PubliclyAccessible flag; flag clusters whose SGs are open to 0.0.0.0/0."""
    try:
        ec = session.client("elasticache", region_name=region)
        paginator = ec.get_paginator("describe_cache_clusters")
        for page in paginator.paginate():
            for c in page.get("CacheClusters", []):
                sg_ids = [s.get("SecurityGroupId") for s in c.get("SecurityGroups", [])]
                open_sgs = [s for s in sg_ids if s in public_sgs]
                if open_sgs:
                    cid = c.get("CacheClusterId")
                    model.record_exposure("elasticache", acct_id, cid, "ELASTICACHE_PUBLIC", region=region,
                                          cidrs=["0.0.0.0/0"],
                                          attributes={"publicly_accessible": True, "open_security_groups": open_sgs,
                                                      "engine": c.get("Engine"), "region": region},
                                          raw_source="elasticache:describe_cache_clusters")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "elasticache", acct_id, region, exc,
                      "aws elasticache describe-cache-clusters --region {}".format(region))


def collect_alb_waf(session, region, acct_id, model):
    """Internet-facing ALBs with no associated WAFv2 WebACL."""
    try:
        elbv2 = session.client("elbv2", region_name=region)
        wafv2 = session.client("wafv2", region_name=region)
        # build set of ALB ARNs that DO have WAF association
        protected = set()
        try:
            acls = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
            for acl in acls:
                res = wafv2.list_resources_for_web_acl(WebACLArn=acl.get("ARN"),
                                                       ResourceType="APPLICATION_LOAD_BALANCER")
                for arn in res.get("ResourceArns", []):
                    protected.add(arn)
        except Exception as exc:  # noqa: BLE001
            _gap_on_error(model, "wafv2_regional", acct_id, region, exc,
                          "aws wafv2 list-web-acls --scope REGIONAL --region {}".format(region))
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("Type") != "application" or lb.get("Scheme") != "internet-facing":
                    continue
                arn = lb.get("LoadBalancerArn")
                name = lb.get("LoadBalancerName")
                has_waf = arn in protected
                control = "ALB_INTERNET_FACING" if has_waf else "ALB_NO_WAF"
                model.record_exposure("alb", acct_id, name, control, region=region, arn=arn,
                                      attributes={"scheme": "internet-facing", "waf_associated": has_waf,
                                                  "dns_name": lb.get("DNSName"), "region": region},
                                      raw_source="elbv2:describe_load_balancers")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "alb_waf", acct_id, region, exc,
                      "aws elbv2 describe-load-balancers --region {}".format(region))


def collect_cloudfront_waf(session, acct_id, model):
    """CloudFront distributions (global) with no WebACL attached."""
    try:
        cf = session.client("cloudfront")
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            dl = page.get("DistributionList", {}) or {}
            for d in dl.get("Items", []) or []:
                if not d.get("WebACLId"):
                    did = d.get("Id")
                    model.record_exposure("alb", acct_id, "cloudfront/{}".format(did), "CLOUDFRONT_NO_WAF",
                                          region="global", arn=d.get("ARN"),
                                          attributes={"domain": d.get("DomainName"), "waf_associated": False,
                                                      "kind": "cloudfront"},
                                          raw_source="cloudfront:list_distributions")
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "cloudfront_waf", acct_id, "global", exc,
                      "aws cloudfront list-distributions")


def collect_vpc_flow_logs(session, region, acct_id, model):
    """VPCs with no flow log = a detection blind spot (finding + gap)."""
    try:
        ec2 = session.client("ec2", region_name=region)
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        if not vpcs:
            return
        try:
            fls = ec2.describe_flow_logs().get("FlowLogs", [])
        except Exception as exc:  # noqa: BLE001
            _gap_on_error(model, "vpc_flow_logs", acct_id, region, exc,
                          "aws ec2 describe-flow-logs --region {}".format(region))
            return
        vpcs_with_fl = {fl.get("ResourceId") for fl in fls}
        for vpc in vpcs:
            vid = vpc.get("VpcId")
            if vid not in vpcs_with_fl:
                model.add_finding("VPC_FLOW_LOGS_DISABLED", acct_id, vid, False,
                                  "ec2:describe_flow_logs", extra_id="{}:{}".format(region, vid))
    except Exception as exc:  # noqa: BLE001
        _gap_on_error(model, "vpcs", acct_id, region, exc,
                      "aws ec2 describe-vpcs --region {}".format(region))


# --------------------------------------------------------------------------------------
# --ingest : reuse existing CSPM / inventory JSON instead of re-collecting
# --------------------------------------------------------------------------------------
def ingest_existing(patterns, model):
    """Merge exposure findings/nodes from prior CSPM JSON (e.g. cspm.json).

    Understands two shapes:
      1. A full aws_attack_model/v1 envelope  -> merge nodes/edges/findings/gaps.
      2. A loose list (or {"findings":[...]}) -> promote any row whose control/check id
         maps to a known exposure control.
    """
    files = []
    for pat in patterns:
        if os.path.isdir(pat):
            files.extend(glob.glob(os.path.join(pat, "**", "*.json"), recursive=True))
        else:
            files.extend(glob.glob(pat, recursive=True))
    for path in sorted(set(files)):
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            model.add_gap("ingest", "could not parse {}: {}".format(path, exc), [],
                          "verify the JSON is well-formed")
            continue
        _ingest_obj(data, path, model)


def _ingest_obj(data, path, model):
    if isinstance(data, dict) and data.get("schema") == SCHEMA:
        for n in data.get("nodes", []):
            if n.get("id") and n["id"] != INTERNET_ID:
                model.nodes.setdefault(n["id"], n)
        for e in data.get("edges", []):
            if e.get("type") == "exposes":
                model.edges.append(e)
        for f in data.get("findings", []):
            if f.get("id"):
                model.findings.setdefault(f["id"], f)
        for g in data.get("gaps", []):
            model.gaps.append(g)
        return
    # loose findings list
    rows = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        control = row.get("control") or row.get("check_id") or row.get("check")
        if control in CONTROL_MAP:
            acct = str(row.get("account_id") or row.get("account") or "unknown")
            resource = str(row.get("resource") or row.get("resource_id") or row.get("arn") or "unknown")
            model.add_finding(control, acct, resource,
                              bool(row.get("internet_facing", True)),
                              "ingest:{}".format(os.path.basename(path)),
                              extra_id=resource)


# --------------------------------------------------------------------------------------
# Self-test : prove envelope shape without AWS/boto3
# --------------------------------------------------------------------------------------
def build_self_test_model():
    """Populate one of each exposure type from inline synthetic data (no AWS calls)."""
    model = Model()
    a = "123456789012"
    model.accounts.append({"account_id": a, "label": "self-test", "env": "sandbox",
                           "is_management": False, "org_id": None, "notes": "synthetic"})
    model.record_exposure("ebs_snapshot", a, "snap-0abc", "EBS_SNAPSHOT_PUBLIC", region="us-east-1",
                          attributes={"shared_public": True}, raw_source="self-test")
    model.record_exposure("ami", a, "ami-0def", "AMI_PUBLIC", region="us-east-1",
                          attributes={"shared_public": True}, raw_source="self-test")
    model.record_exposure("rds_snapshot", a, "rds-snap-0", "RDS_SNAPSHOT_PUBLIC", region="us-west-2",
                          attributes={"shared_public": True}, raw_source="self-test")
    model.record_exposure("ecr_repo", a, "payments-api", "ECR_PUBLIC_REPO", region="us-east-1",
                          raw_source="self-test")
    model.record_exposure("lambda_function", a, "public-fn", "LAMBDA_PUBLIC_URL", region="eu-west-1",
                          attributes={"url_auth": "NONE"}, raw_source="self-test")
    model.record_exposure("api_gateway", a, "abc123api", "APIGW_NO_AUTH", region="eu-west-1",
                          attributes={"authorization": "NONE"}, raw_source="self-test")
    model.record_exposure("redshift", a, "analytics", "REDSHIFT_PUBLIC", region="us-east-1",
                          ports=[5439], cidrs=["0.0.0.0/0"],
                          attributes={"publicly_accessible": True}, raw_source="self-test")
    model.record_exposure("documentdb", a, "docdb-1", "DOCDB_PUBLIC", region="us-east-1",
                          ports=[27017], cidrs=["0.0.0.0/0"],
                          attributes={"publicly_accessible": True}, raw_source="self-test")
    model.record_exposure("elasticache", a, "cache-1", "ELASTICACHE_PUBLIC", region="us-east-1",
                          cidrs=["0.0.0.0/0"], attributes={"publicly_accessible": True},
                          raw_source="self-test")
    model.record_exposure("alb", a, "web-alb", "ALB_NO_WAF", region="us-east-1",
                          attributes={"scheme": "internet-facing", "waf_associated": False},
                          raw_source="self-test")
    # EC2 with public IP + open admin port + IMDSv1
    nid = model.add_node("ec2_instance:{}:i-0self".format(a), "ec2_instance", a, "i-0self",
                         internet_facing=True, ports=[22], cidrs=["0.0.0.0/0"],
                         attributes={"http_tokens": "optional", "public_ip": "203.0.113.5"})
    model.add_exposes_edge(nid, "ia_admin_port_open", "us-east-1", nid)
    model.add_finding("EC2_IMDSV2_NOT_ENFORCED", a, "i-0self", True, "self-test", extra_id="i-0self")
    model.add_finding("EC2_PUBLIC_ADMIN_PORT", a, "sg-0self", True, "self-test", extra_id="sg-0self")
    model.add_finding("VPC_FLOW_LOGS_DISABLED", a, "vpc-0self", False, "self-test", extra_id="vpc-0self")
    model.add_gap("self-test", "synthetic gap to prove Gap shape", [a],
                  "n/a -- this is a --self-test run")
    return model


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------
def resolve_regions(regions_arg):
    if not regions_arg or regions_arg == "all":
        return list(COMMERCIAL_REGIONS)
    return [r.strip() for r in regions_arg.split(",") if r.strip()]


def collect_account(acct, regions, model):
    acct_id = acct.get("account_id", "unknown")
    model.accounts.append({
        "account_id": acct_id,
        "label": acct.get("label", acct_id),
        "env": acct.get("env", "unknown"),
        "is_management": bool(acct.get("is_management", False)),
        "org_id": acct.get("org_id"),
        "notes": acct.get("notes", ""),
    })
    session = assume_session(acct, model)
    if session is None:
        return  # gap already recorded

    # global (once per account)
    collect_cloudfront_waf(session, acct_id, model)

    for region in regions:
        public_sgs = collect_security_groups(session, region, acct_id, model)
        collect_ec2_instances(session, region, acct_id, model, public_sgs)
        collect_ebs_snapshots(session, region, acct_id, model)
        collect_amis(session, region, acct_id, model)
        collect_rds_snapshots(session, region, acct_id, model)
        collect_ecr(session, region, acct_id, model)
        collect_lambda(session, region, acct_id, model)
        collect_apigw(session, region, acct_id, model)
        collect_redshift(session, region, acct_id, model)
        collect_docdb(session, region, acct_id, model)
        collect_elasticache(session, region, acct_id, model, public_sgs)
        collect_alb_waf(session, region, acct_id, model)
        collect_vpc_flow_logs(session, region, acct_id, model)


def load_accounts(path):
    with open(path, "r") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "accounts" in data:
        data = data["accounts"]
    if not isinstance(data, list):
        raise ValueError("accounts file must be a JSON array of {account_id, role_arn?, profile?, external_id?}")
    return data


def resolve_now(now_arg):
    if now_arg:
        return now_arg
    # runtime fallback ONLY (never at import) so re-runs are still reproducible when --now is given
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="collect_attack_surface.py",
        description="Collect internet-exposure CSPM misses and emit an aws_attack_model/v1 envelope.")
    p.add_argument("--accounts", help="Path to accounts.json (array of {account_id, role_arn?, profile?, external_id?}).")
    p.add_argument("--regions", default="all",
                   help="Comma-separated regions, or 'all' for all commercial regions (default).")
    p.add_argument("--ingest", action="append", default=[],
                   help="Dir or glob of existing CSPM/model JSON to merge (repeatable).")
    p.add_argument("--customer", default="generic", help="Customer label stamped into the envelope.")
    p.add_argument("--now", help="ISO-8601 timestamp for collected_at (recommended; keeps runs reproducible).")
    p.add_argument("--output", default="attack_surface.json", help="Output path (default attack_surface.json).")
    p.add_argument("--self-test", "--dry-run", dest="self_test", action="store_true",
                   help="Emit a synthetic-but-valid envelope with no AWS/boto3 calls.")
    args = p.parse_args(argv)

    collected_at = resolve_now(args.now)

    if args.self_test:
        model = build_self_test_model()
    else:
        model = Model()
        if args.ingest:
            ingest_existing(args.ingest, model)
        if args.accounts:
            try:
                accounts = load_accounts(args.accounts)
            except Exception as exc:  # noqa: BLE001
                p.error("could not load --accounts {}: {}".format(args.accounts, exc))
            regions = resolve_regions(args.regions)
            for acct in accounts:
                collect_account(acct, regions, model)
        elif not args.ingest:
            # Nothing to do -> still emit a valid empty envelope (shape proof).
            model.add_gap("input", "no --accounts and no --ingest provided; emitted empty envelope",
                          [], "re-run with --accounts accounts.json or --ingest <glob> (or --self-test)")

    envelope = model.envelope(args.customer, collected_at)

    with open(args.output, "w") as fh:
        json.dump(envelope, fh, indent=2)

    counts = {
        "nodes": len(envelope["nodes"]),
        "edges": len(envelope["edges"]),
        "findings": len(envelope["findings"]),
        "gaps": len(envelope["gaps"]),
        "accounts": len(envelope["accounts"]),
    }
    sys.stderr.write("wrote {} :: {}\n".format(args.output, json.dumps(counts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
