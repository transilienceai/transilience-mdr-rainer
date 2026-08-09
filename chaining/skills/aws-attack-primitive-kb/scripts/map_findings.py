#!/usr/bin/env python3
"""Map an aws_attack_model/v1 model against the attack-primitive KB.

For each finding, match finding.control against each primitive.signature.controls
(case-insensitive) and attach primitive_ids + the union of MITRE techniques. Also
best-effort tag nodes/edges whose type is referenced by a primitive.signature
condition string.

stdlib only. Deterministic: no clock reads, stable ordering everywhere.
"""

import argparse
import json
import os
import sys

DEFAULT_KB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references",
    "attack_primitives.json",
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_control_index(primitives):
    """control (lowercased) -> sorted list of primitive ids that list it."""
    index = {}
    for prim in primitives:
        pid = prim.get("id")
        sig = prim.get("signature") or {}
        for control in sig.get("controls") or []:
            if not isinstance(control, str):
                continue
            key = control.strip().lower()
            if not key:
                continue
            index.setdefault(key, set()).add(pid)
    return {k: sorted(v) for k, v in index.items()}


def primitive_by_id(primitives):
    return {p.get("id"): p for p in primitives}


def condition_node_types(primitives):
    """Map a NODE_TYPE / EDGE_TYPE token -> sorted primitive ids whose condition
    strings mention it. Best-effort substring tagging only."""
    node_types = [
        "internet", "external_account", "account", "iam_user", "iam_role",
        "iam_group", "access_key", "instance_profile", "ec2_instance",
        "eks_cluster", "lambda_function", "alb", "api_gateway", "s3_bucket",
        "rds_instance", "redshift", "documentdb", "elasticache", "dynamodb",
        "ebs_snapshot", "ami", "rds_snapshot", "ecr_repo", "secret",
        "ssm_parameter", "kms_key", "bedrock_kb", "bedrock_agent", "sagemaker",
        "sso_instance", "cognito_pool", "log_bucket", "ci_system",
    ]
    edge_types = [
        "exposes", "has_credential", "can_assume", "can_passrole",
        "can_escalate", "trusts", "can_reach", "runs_as", "replicates_to",
        "writes_logs_to", "member_of", "stores_credential_for",
    ]
    index = {}
    for prim in primitives:
        pid = prim.get("id")
        sig = prim.get("signature") or {}
        blob = " ".join(str(c).lower() for c in (sig.get("conditions") or []))
        for token in node_types + edge_types:
            if token in blob:
                index.setdefault(token, set()).add(pid)
    return {k: sorted(v) for k, v in index.items()}


def map_model(model, kb):
    primitives = kb.get("primitives") or []
    control_index = build_control_index(primitives)
    by_id = primitive_by_id(primitives)
    type_index = condition_node_types(primitives)

    findings = model.get("findings") or []
    tagged_findings = 0
    hit_primitives = set()
    tactic_counts = {}

    for finding in findings:
        control = finding.get("control")
        pids = []
        if isinstance(control, str):
            pids = control_index.get(control.strip().lower(), [])
        if pids:
            finding["primitive_ids"] = pids
            mitre = []
            for pid in pids:
                for t in (by_id.get(pid, {}).get("mitre") or []):
                    if t not in mitre:
                        mitre.append(t)
            finding["mitre"] = mitre
            tagged_findings += 1
            for pid in pids:
                hit_primitives.add(pid)
                tactic = by_id.get(pid, {}).get("tactic", "unknown")
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        else:
            finding.setdefault("primitive_ids", [])
            finding.setdefault("mitre", [])

    # Best-effort node/edge annotation by type.
    for node in model.get("nodes") or []:
        ntype = node.get("type")
        pids = type_index.get(ntype, [])
        if pids:
            attrs = node.setdefault("attributes", {})
            attrs["primitive_hints"] = pids
    for edge in model.get("edges") or []:
        etype = edge.get("type")
        pids = type_index.get(etype, [])
        if pids:
            attrs = edge.setdefault("attributes", {})
            attrs["primitive_hints"] = pids

    summary = {
        "findings_total": len(findings),
        "findings_tagged": tagged_findings,
        "distinct_primitives_hit": len(hit_primitives),
        "coverage_by_tactic": dict(sorted(tactic_counts.items())),
        "primitives_hit": sorted(hit_primitives),
    }
    return model, summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="aws_attack_model/v1 envelope JSON")
    ap.add_argument("--kb", default=DEFAULT_KB, help="attack_primitives.json (default: bundled KB)")
    ap.add_argument("--output", required=True, help="output tagged model JSON path")
    args = ap.parse_args(argv)

    model = load_json(args.model)
    kb = load_json(args.kb)

    if model.get("schema") != "aws_attack_model/v1":
        sys.stderr.write(
            "WARN: model schema is %r, expected 'aws_attack_model/v1'\n"
            % model.get("schema")
        )

    tagged, summary = map_model(model, kb)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(tagged, fh, indent=2, sort_keys=False)
        fh.write("\n")

    print("attack-primitive mapping summary")
    print("  findings total       : %d" % summary["findings_total"])
    print("  findings tagged      : %d" % summary["findings_tagged"])
    print("  distinct primitives  : %d" % summary["distinct_primitives_hit"])
    print("  coverage by tactic   :")
    if summary["coverage_by_tactic"]:
        for tactic, count in summary["coverage_by_tactic"].items():
            print("    %-22s %d" % (tactic, count))
    else:
        print("    (none)")
    print("  wrote                : %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
