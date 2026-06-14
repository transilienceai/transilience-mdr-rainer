#!/usr/bin/env python3
"""Build a business-as-usual CloudTrail baseline from normalized observations."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FAMILY_LABELS = {
    "ci_cd_deployment": "CI/CD and deployment automation",
    "application_service_communication": "Application and AWS service-to-service communication",
    "user_access": "Human, SSO, and console access",
    "identity_privilege_management": "Identity and privilege management",
    "data_access_storage": "Storage, data, and KMS operations",
    "network_security_changes": "Network and perimeter security changes",
    "governance_security_visibility": "Security governance and visibility",
    "database_operations": "Database operations",
    "operations_maintenance": "Operations and maintenance",
    "other_control_plane": "Other control-plane activity",
}

CRITICAL_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteConfigurationRecorder",
    "StopConfigurationRecorder",
    "DeleteConfigRule",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "CreateRole",
    "DeleteRole",
    "DeleteBucket",
    "DeleteBucketPolicy",
    "PutBucketPolicy",
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "DeleteDBInstance",
    "DisableKey",
    "ScheduleKeyDeletion",
}


def load_json(path: Path) -> Any:
    if not path or not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_observations(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def top(counter: Counter, limit: int = 12) -> list[dict[str, Any]]:
    return [{"value": str(value), "count": count} for value, count in counter.most_common(limit) if value not in {"", None}]


def pct(part: int, total: int) -> str:
    return "0.0%" if not total else f"{part * 100 / total:.1f}%"


def family_for(obs: dict[str, Any]) -> str:
    event = str(obs.get("event_name") or "")
    source = str(obs.get("event_source") or "")
    actor = str(obs.get("actor") or "").lower()
    pattern = str(obs.get("pattern_category") or "")
    e = event.lower()
    if event in {"ConsoleLogin", "AssumeRole"} or source == "signin.amazonaws.com" or "awsreservedsso_" in actor:
        return "user_access"
    if source == "rds.amazonaws.com" or "dbinstance" in e or "dbcluster" in e:
        return "database_operations"
    if source == "s3.amazonaws.com" or "bucket" in e or event in {"CreateGrant", "CreateKey", "DisableKey", "ScheduleKeyDeletion"}:
        return "data_access_storage"
    if any(t in e for t in ["securitygroup", "networkacl", "route", "internetgateway", "vpc", "vpcpeering"]):
        return "network_security_changes"
    if source in {"cloudtrail.amazonaws.com", "config.amazonaws.com"} or event in {"DeleteConfigRule", "StopConfigurationRecorder", "DeleteConfigurationRecorder", "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}:
        return "governance_security_visibility"
    if source == "iam.amazonaws.com" and any(t in e for t in ["role", "policy", "user", "accesskey", "signinprofile", "password"]):
        if any(t in actor for t in ["cloudformation", "codebuild", "codepipeline", "deploy", "cdk", "terraform", "jenkins"]):
            return "ci_cd_deployment"
        return "identity_privilege_management"
    if event in {"RunInstances", "TerminateInstances", "CreateLaunchTemplate", "RegisterTaskDefinition", "UpdateService", "CreateFunction", "UpdateFunctionCode"}:
        return "ci_cd_deployment"
    if event in {"StartInstances", "StopInstances", "RebootInstances"} or any(t in actor for t in ["quicksetup", "ssm", "backup"]):
        return "operations_maintenance"
    if pattern == "deployment" or any(t in actor for t in ["autoscaling", "cloudformation", "stacksets", "eks-nodegroup", "elasticloadbalancing"]):
        return "application_service_communication"
    return "other_control_plane"


def summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "observation_count": len(items),
        "first_seen": min((str(i.get("event_time") or "") for i in items if i.get("event_time")), default=""),
        "last_seen": max((str(i.get("event_time") or "") for i in items if i.get("event_time")), default=""),
        "top_events": top(Counter(i.get("event_name") for i in items), 15),
        "top_event_sources": top(Counter(i.get("event_source") for i in items), 10),
        "top_actors": top(Counter(i.get("actor") for i in items), 15),
        "top_actor_types": top(Counter(i.get("actor_type") for i in items), 10),
        "top_source_ips": top(Counter(i.get("source_ip") for i in items), 15),
        "top_regions": top(Counter(i.get("region") for i in items), 10),
        "risk_levels": top(Counter(i.get("risk") for i in items), 8),
        "business_risks": top(Counter(i.get("business_risk_category") for i in items), 10),
    }


def abnormal_conditions(family: str) -> list[str]:
    defaults = {
        "ci_cd_deployment": ["deployment actions from named users", "new deployment role/event/source-IP tuple", "critical IAM/storage/network changes outside pipeline roles"],
        "application_service_communication": ["new AWS service principal for sensitive event", "service-to-service action touching identity, audit, or data boundary"],
        "user_access": ["root login", "new country/IP/device for privileged user", "console access without expected MFA evidence"],
        "identity_privilege_management": ["CreateAccessKey outside rotation role", "role/policy writes from unmanaged egress", "new privilege-bearing IAM actor"],
        "data_access_storage": ["DeleteBucket burst", "audit/log bucket deletion", "KMS grant/key changes by unusual actor"],
        "network_security_changes": ["public ingress or route change", "named-user security group changes", "new internet gateway or peering change"],
        "governance_security_visibility": ["CloudTrail/Config/FlowLogs tamper", "delete or stop visibility controls", "first-seen visibility change actor"],
        "database_operations": ["DeleteDBInstance", "database changes from named user", "new source IP for DB control-plane action"],
        "operations_maintenance": ["maintenance action outside known automation", "rare account/actor/event/source-IP tuple"],
        "other_control_plane": ["critical override event", "rare tuple involving high-risk API"],
    }
    return defaults.get(family, defaults["other_control_plane"])


def build_baseline(observations: list[dict[str, Any]], customer: str, source: Path) -> dict[str, Any]:
    for obs in observations:
        obs["business_family"] = family_for(obs)
    total = len(observations)
    grouped_accounts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tuple_counts = Counter()
    for obs in observations:
        grouped_accounts[str(obs.get("account_id") or "unknown")].append(obs)
        grouped_families[obs["business_family"]].append(obs)
        tuple_counts[(obs.get("account_id"), obs.get("actor"), obs.get("event_name"), obs.get("source_ip"))] += 1

    actor_event_baseline = [
        {"account_id": a, "actor": actor, "event_name": event, "source_ip": ip, "count": count}
        for (a, actor, event, ip), count in sorted(tuple_counts.items(), key=lambda kv: (-kv[1], str(kv[0])))
    ]

    candidates = []
    for obs in observations:
        tuple_key = (obs.get("account_id"), obs.get("actor"), obs.get("event_name"), obs.get("source_ip"))
        reasons = []
        if obs.get("actor_type") == "root":
            reasons.append("root actor is always alertable")
        if obs.get("event_name") in CRITICAL_EVENTS or obs.get("risk") == "critical":
            reasons.append("critical CloudTrail event remains alertable")
        if tuple_counts[tuple_key] < 2:
            reasons.append("rare account/actor/event/source-IP tuple")
        if obs.get("actor_type") in {"iam_user", "assumed_role", "unknown"} and obs.get("risk") in {"critical", "high"}:
            reasons.append("human or non-standard actor performed high-impact action")
        if reasons:
            candidates.append({**obs, "reasons": reasons})

    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "customer": customer,
            "source_observations": str(source),
            "observation_count": total,
            "account_count": len(grouped_accounts),
            "business_family_count": len(grouped_families),
            "alert_candidate_count": len(candidates),
            "caveats": [
                "CloudTrail LookupEvents is management-event oriented and query-limited.",
                "Observed normal does not mean approved safe.",
                "Critical identity, logging, destructive, exposure, root, and audit-integrity events remain alertable.",
            ],
        },
        "overall": {**summarize(observations), "business_family_mix": top(Counter(o["business_family"] for o in observations), 12)},
        "accounts": {account: {**summarize(items), "business_family_mix": top(Counter(i["business_family"] for i in items), 12)} for account, items in grouped_accounts.items()},
        "business_families": {
            family: {
                "label": FAMILY_LABELS.get(family, family),
                "observation_pct": pct(len(items), total),
                "normal_interpretation": f"Observed recurring {FAMILY_LABELS.get(family, family).lower()} activity across CloudTrail management events.",
                "abnormal_conditions": abnormal_conditions(family),
                **summarize(items),
            }
            for family, items in grouped_families.items()
        },
        "actor_event_baseline": actor_event_baseline,
        "alert_candidates": candidates,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--customer", default="AWS customer")
    parser.add_argument("--account-inventory", type=Path)
    parser.add_argument("--resource-inventory", type=Path)
    args = parser.parse_args()
    observations = load_observations(args.observations)
    baseline = build_baseline(observations, args.customer, args.observations)
    if args.account_inventory:
        baseline["metadata"]["account_inventory"] = str(args.account_inventory)
    if args.resource_inventory:
        baseline["metadata"]["resource_inventory"] = str(args.resource_inventory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "observations": len(observations), "alert_candidates": len(baseline["alert_candidates"])}, indent=2))


if __name__ == "__main__":
    main()
