#!/usr/bin/env python3
"""Promote an existing CSPM findings export into an `aws_attack_model/v1` envelope.

This is the "reuse existing evidence" fast path for the AWS red-team attack-chain
suite. Instead of live-collecting, point this at a CSPM export (e.g. a customer
`cspm.json` with a `findings[]` list of `control_id` rows) and it emits a
schema-conformant model that the graph builder / enumerator consume directly.

It is KB-driven: every finding whose control matches a primitive in
aws-attack-primitive-kb is tagged (primitive_id + MITRE + tactic) and turned into
the appropriate nodes/edges:

  * initial-access / exposure controls -> resource node + `exposes` edge from the
    singleton `internet` node; public *data* resources are ALSO emitted as
    crown jewels so initial-access kill chains always have a target.
  * admin / wildcard IAM controls      -> iam principal node + `can_escalate` edge to a
    synthetic `pe_admin:<account>` node.
  * active/stale access-key controls    -> access_key node + `has_credential` edge.
  * risky trust-policy controls         -> iam_role node + `trusts` edge (external unknown).

Stdlib only. Deterministic. No datetime.now (pass --now).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path

SCHEMA = "aws_attack_model/v1"
INTERNET_ID = "internet:global:internet"
DEFAULT_KB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "aws-attack-primitive-kb", "references", "attack_primitives.json",
)

# control_id -> node type for resource-bearing controls
RESOURCE_NODE_TYPE = {
    "S3_PUBLIC_BUCKET_ACCESS": "s3_bucket", "S3_PUBLIC_POLICY": "s3_bucket", "S3_PUBLIC_ACL": "s3_bucket",
    "S3_BLOCK_PUBLIC_ACCESS_DISABLED": "s3_bucket",
    "RDS_PUBLIC_ACCESS": "rds_instance", "RDS_UNENCRYPTED": "rds_instance", "RDS_CLUSTER_UNENCRYPTED": "rds_instance",
    "REDSHIFT_PUBLIC": "redshift", "DOCDB_PUBLIC": "documentdb", "ELASTICACHE_PUBLIC": "elasticache",
    "EKS_PUBLIC_API": "eks_cluster",
    "EC2_PUBLIC_ADMIN_PORT": "ec2_instance", "EC2_PUBLIC_ALL_TRAFFIC": "ec2_instance",
    "EC2_PUBLIC_PLAINTEXT_PORT": "ec2_instance", "EC2_IMDSV2_NOT_ENFORCED": "ec2_instance",
    "LB_HTTP_LISTENER": "alb", "ALB_INTERNET_FACING": "alb", "ALB_NO_WAF": "alb",
    "CLOUDFRONT_ALLOW_HTTP": "s3_bucket", "CLOUDFRONT_WEAK_TLS": "s3_bucket", "CLOUDFRONT_NO_WAF": "s3_bucket",
    "LAMBDA_PUBLIC_URL": "lambda_function", "APIGW_NO_AUTH": "api_gateway", "ECR_PUBLIC_REPO": "ecr_repo",
    "EBS_SNAPSHOT_PUBLIC": "ebs_snapshot", "AMI_PUBLIC": "ami", "RDS_SNAPSHOT_PUBLIC": "rds_snapshot",
    "EBS_UNENCRYPTED": "ec2_instance", "EFS_UNENCRYPTED": "s3_bucket", "FSX_UNENCRYPTED": "s3_bucket",
}
# controls whose exposed resource is a valuable target in its own right
DATA_CROWN = {"s3_bucket", "rds_instance", "redshift", "documentdb", "elasticache"}
IDENTITY_ESCALATE = {"IAM_ADMIN_MANAGED_POLICY", "IAM_WILDCARD_INLINE_POLICY", "IAM_FULL_ACCESS",
                     "IAM_WILDCARD_MANAGED_POLICY"}
KEY_CONTROLS = {"IAM_ACTIVE_ACCESS_KEY", "IAM_STALE_ACCESS_KEY"}
TRUST_CONTROLS = {"IAM_RISKY_TRUST_POLICY", "ORG_ACCOUNT_ACCESS_ROLE", "AWS_CONTROL_TOWER_EXECUTION"}


def load_kb(path):
    kb = json.loads(Path(path).read_text(encoding="utf-8"))
    idx = {}
    for p in kb.get("primitives", []):
        for ctrl in p.get("signature", {}).get("controls", []):
            idx.setdefault(ctrl.upper(), []).append(p)
    return idx


def kb_tags(control, kb_idx):
    prims = kb_idx.get((control or "").upper(), [])
    primitive_ids = sorted({p["id"] for p in prims})
    mitre = sorted({m for p in prims for m in p.get("mitre", [])})
    tactics = sorted({p.get("tactic", "") for p in prims})
    return primitive_ids, mitre, tactics


def iter_cspm_findings(data):
    if isinstance(data, dict) and data.get("schema") == SCHEMA:
        return None  # already a model; caller handles pass-through
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings") or data.get("records") or data.get("rows") or []
    return []


def promote(paths, kb_idx, customer, now):
    nodes = {INTERNET_ID: {"id": INTERNET_ID, "type": "internet", "account_id": "internet",
                           "name": "internet", "arn": None,
                           "exposure": {"internet_facing": True, "ports": [], "cidrs": []}, "attributes": {}}}
    edges, findings, crown, gaps, accounts = [], {}, {}, [], {}
    fid = 0
    files = []
    for pat in paths:
        if os.path.isdir(pat):
            files.extend(glob.glob(os.path.join(pat, "**", "*.json"), recursive=True))
        else:
            files.extend(glob.glob(pat, recursive=True) or [pat])
    for path in sorted(set(files)):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            gaps.append({"area": "ingest", "reason": f"could not parse {path}: {exc}",
                        "accounts": [], "recommended_collection": "verify JSON is well-formed"})
            continue
        for acc in (data.get("accounts", []) if isinstance(data, dict) else []):
            aid = str(acc.get("account_id") or acc.get("id") or "")
            if aid:
                accounts[aid] = {"account_id": aid, "label": acc.get("label") or acc.get("account_label") or aid,
                                 "env": acc.get("env") or acc.get("account_env") or "unknown",
                                 "is_management": bool(acc.get("is_management")),
                                 "org_id": acc.get("org_id"), "notes": acc.get("account_purpose") or ""}
        rows = iter_cspm_findings(data)
        if rows is None:
            gaps.append({"area": "ingest", "reason": f"{path} is already a model envelope; feed it to build_attack_graph --inputs instead",
                        "accounts": [], "recommended_collection": ""})
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            control = row.get("control_id") or row.get("control") or row.get("check_id") or row.get("check")
            if not control:
                continue
            control = str(control).upper()
            acct = str(row.get("account_id") or row.get("account") or "unknown")
            label = row.get("account_label") or acct
            accounts.setdefault(acct, {"account_id": acct, "label": label,
                                       "env": row.get("account_env") or "unknown",
                                       "is_management": False, "org_id": None,
                                       "notes": row.get("account_purpose") or ""})
            resource = str(row.get("resource_id") or row.get("resource") or row.get("arn") or row.get("resource_type") or "unknown")
            severity = str(row.get("severity") or "medium").lower()
            primitive_ids, mitre, tactics = kb_tags(control, kb_idx)
            internet_facing = any(t == "initial-access" for t in tactics)
            fid += 1
            fkey = f"F-{fid:05d}"
            findings[fkey] = {"id": fkey, "account_id": acct, "control": control, "severity": severity,
                              "resource": resource, "internet_facing": internet_facing,
                              "primitive_ids": primitive_ids, "mitre": mitre,
                              "raw_source": f"cspm:{os.path.basename(path)}"}
            ntype = RESOURCE_NODE_TYPE.get(control)
            # exposure nodes + edges
            if ntype and internet_facing:
                nid = f"{ntype}:{acct}:{resource}"
                nodes.setdefault(nid, {"id": nid, "type": ntype, "account_id": acct, "name": resource,
                                       "arn": None, "exposure": {"internet_facing": True, "ports": [], "cidrs": ["0.0.0.0/0"]},
                                       "attributes": {"account_label": label}})
                edges.append({"src": INTERNET_ID, "dst": nid, "type": "exposes",
                              "attributes": {"primitive_id": primitive_ids[0] if primitive_ids else None, "via": control},
                              "evidence": {"source": "config", "id": fkey}})
                if ntype in DATA_CROWN:
                    crown.setdefault(nid, {"id": nid, "account_id": acct, "type": ntype, "name": resource,
                                           "value_score": 70 if severity in ("critical", "high") else 50,
                                           "data_class": "financial" if any(k in resource.lower() for k in ("bank", "financial", "finance", "payment", "ledger", "trading", "billing")) else "other",
                                           "size": "", "protections": [], "reachable_by": [INTERNET_ID]})
            # identity escalation
            if control in IDENTITY_ESCALATE:
                uid = f"iam_user:{acct}:{resource}"
                admin = f"pe_admin:{acct}"
                nodes.setdefault(uid, {"id": uid, "type": "iam_user", "account_id": acct, "name": resource,
                                       "arn": None, "exposure": {"internet_facing": False, "ports": [], "cidrs": []},
                                       "attributes": {"admin_like": True, "account_label": label}})
                nodes.setdefault(admin, {"id": admin, "type": "iam_role", "account_id": acct, "name": "account-administrator",
                                         "arn": None, "exposure": {"internet_facing": False, "ports": [], "cidrs": []},
                                         "attributes": {"synthetic": True}})
                edges.append({"src": uid, "dst": admin, "type": "can_escalate",
                              "attributes": {"primitive_id": primitive_ids[0] if primitive_ids else None, "via": control},
                              "evidence": {"source": "iam", "id": fkey}})
            if control in KEY_CONTROLS:
                kid = f"access_key:{acct}:{resource}"
                uid = f"iam_user:{acct}:{resource}"
                nodes.setdefault(uid, {"id": uid, "type": "iam_user", "account_id": acct, "name": resource,
                                       "arn": None, "exposure": {"internet_facing": False, "ports": [], "cidrs": []}, "attributes": {"account_label": label}})
                nodes.setdefault(kid, {"id": kid, "type": "access_key", "account_id": acct, "name": resource,
                                       "arn": None, "exposure": {"internet_facing": False, "ports": [], "cidrs": []},
                                       "attributes": {"stale": control == "IAM_STALE_ACCESS_KEY"}})
                edges.append({"src": uid, "dst": kid, "type": "has_credential",
                              "attributes": {"primitive_id": primitive_ids[0] if primitive_ids else None, "via": control},
                              "evidence": {"source": "iam", "id": fkey}})
            if control in TRUST_CONTROLS:
                rid = f"iam_role:{acct}:{resource}"
                nodes.setdefault(rid, {"id": rid, "type": "iam_role", "account_id": acct, "name": resource,
                                       "arn": None, "exposure": {"internet_facing": False, "ports": [], "cidrs": []}, "attributes": {"account_label": label}})
                ext = f"external_account:external:{control.lower()}"
                nodes.setdefault(ext, {"id": ext, "type": "external_account", "account_id": "external",
                                       "name": "untrusted-or-external principal", "arn": None,
                                       "exposure": {"internet_facing": False, "ports": [], "cidrs": []}, "attributes": {}})
                edges.append({"src": ext, "dst": rid, "type": "can_assume",
                              "attributes": {"primitive_id": primitive_ids[0] if primitive_ids else None, "via": control, "condition": "external_id absent"},
                              "evidence": {"source": "iam", "id": fkey}})
    return {"schema": SCHEMA, "customer": customer, "collected_at": now,
            "source_skill": "aws-attack-graph-builder/cspm_to_model",
            "accounts": sorted(accounts.values(), key=lambda a: a["account_id"]),
            "nodes": list(nodes.values()), "edges": edges,
            "findings": list(findings.values()), "crown_jewels": list(crown.values()),
            "active_threats": [], "gaps": gaps}


def main():
    ap = argparse.ArgumentParser(description="Promote a CSPM findings export into aws_attack_model/v1.")
    ap.add_argument("--cspm", nargs="+", required=True, help="CSPM export JSON file(s)/dir(s)/glob(s).")
    ap.add_argument("--kb", default=DEFAULT_KB, help="attack_primitives.json (default: bundled KB).")
    ap.add_argument("--customer", default="")
    ap.add_argument("--now", default="", help="ISO-8601 timestamp (no datetime.now).")
    ap.add_argument("--output", default="cspm_model.json")
    args = ap.parse_args()
    kb_idx = load_kb(args.kb)
    model = promote(args.cspm, kb_idx, args.customer, args.now)
    Path(args.output).write_text(json.dumps(model, indent=2), encoding="utf-8")
    counts = {k: len(model.get(k, [])) for k in ("accounts", "nodes", "edges", "findings", "crown_jewels", "gaps")}
    print(f"wrote {args.output} :: {json.dumps(counts)}")


if __name__ == "__main__":
    main()
