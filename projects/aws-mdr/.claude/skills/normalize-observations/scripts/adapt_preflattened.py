#!/usr/bin/env python3
"""Adapt pre-flattened CloudTrail exports to the MDR observation schema.

Use when CloudTrail data has already been exported and flattened by a SIEM,
a third-party collector, or an ETL pipeline and the raw CloudTrail event
structure (eventVersion / userIdentity / CloudTrailEvent) is no longer present.

See use-cases/02-preflattened-exports/README.md for full context.

Input record shape (flat):
    event_time, event_name, event_source, username, user_type,
    source_ip, aws_region, recipient_account_id, error_code, resources

Output record shape (MDR observation schema):
    event_id, event_time, account_id, recipient_account_id, region,
    event_name, event_source, actor, actor_type, source_ip, user_agent,
    resources, error_code, risk, business_risk_category, pattern_category,
    collection_call_id, raw_source
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

EVENT_RISK: dict[str, str] = {
    "StopLogging": "critical", "DeleteTrail": "critical", "UpdateTrail": "critical",
    "PutEventSelectors": "critical", "DeleteConfigurationRecorder": "critical",
    "StopConfigurationRecorder": "critical", "DeleteConfigRule": "critical",
    "CreateAccessKey": "critical", "ScheduleKeyDeletion": "critical", "DisableKey": "critical",
    "DeleteBucket": "high", "DeleteBucketPolicy": "high", "PutBucketPolicy": "high",
    "AttachRolePolicy": "high", "AttachUserPolicy": "high", "PutRolePolicy": "high",
    "PutUserPolicy": "high", "CreateRole": "high", "DeleteRole": "high",
    "CreateUser": "high", "DeleteUser": "high", "UpdateAccountPasswordPolicy": "high",
    "CreateGrant": "high", "CreateKey": "high",
    "AuthorizeSecurityGroupIngress": "high", "AuthorizeSecurityGroupEgress": "high",
    "CreateNetworkAclEntry": "high", "DeleteNetworkAclEntry": "high",
    "ReplaceNetworkAclEntry": "high", "CreateRoute": "high", "DeleteRoute": "high",
    "ReplaceRoute": "high", "AttachInternetGateway": "high", "DetachInternetGateway": "high",
    "CreateDBInstance": "high", "DeleteDBInstance": "high",
}

DEPLOYMENT_RE = re.compile(
    r"(cloudformation|codebuild|codepipeline|codedeploy|terraform|cdk|jenkins|deploy|pipeline|stacksets)",
    re.I,
)

USER_TYPE_MAP: dict[str, str] = {
    "IAMUser": "iam_user",
    "AssumedRole": "assumed_role",
    "Root": "root",
    "AWSService": "aws_service",
    "AWSAccount": "aws_account",
    "FederatedUser": "federated_user",
}


def _actor_type(user_type: str, actor: str) -> str:
    if actor == "root":
        return "root"
    return USER_TYPE_MAP.get(user_type, "unknown")


def _pattern_category(event_name: str, event_source: str, actor: str) -> str:
    text = f"{event_name} {event_source} {actor}".lower()
    if DEPLOYMENT_RE.search(text) or event_name in {
        "RunInstances", "CreateFunction", "UpdateFunctionCode", "RegisterTaskDefinition",
    }:
        return "ci_cd_deployment"
    if event_name.startswith((
        "Create", "Delete", "Update", "Put", "Attach", "Detach",
        "Authorize", "Revoke", "Modify", "Replace",
    )):
        return "identity_privilege_management"
    return "other_control_plane"


def _business_risk(event_name: str, actor: str) -> str:
    if actor == "root":
        return "critical"
    e = event_name.lower()
    if any(w in e for w in ("delete", "stop", "disable", "revoke")):
        return "high"
    if any(w in e for w in ("create", "attach", "authorize", "put")):
        return "medium"
    return "low"


def adapt(record: dict, source_file: str) -> dict | None:
    event_name = str(record.get("event_name") or "")
    if not event_name:
        return None
    actor = str(record.get("username") or "unknown").lower()
    event_source = str(record.get("event_source") or "")
    user_type = str(record.get("user_type") or "")
    account_id = str(record.get("recipient_account_id") or record.get("account_id") or "")
    risk = "critical" if actor == "root" else EVENT_RISK.get(event_name, "medium")
    return {
        "event_id": str(record.get("event_id") or ""),
        "event_time": str(record.get("event_time") or ""),
        "account_id": account_id,
        "recipient_account_id": account_id,
        "region": str(record.get("aws_region") or record.get("region") or ""),
        "event_name": event_name,
        "event_source": event_source,
        "actor": actor,
        "actor_type": _actor_type(user_type, actor),
        "source_ip": str(record.get("source_ip") or ""),
        "user_agent": str(record.get("user_agent") or ""),
        "resources": record.get("resources") or [],
        "error_code": str(record.get("error_code") or ""),
        "risk": risk,
        "business_risk_category": _business_risk(event_name, actor),
        "pattern_category": _pattern_category(event_name, event_source, actor),
        "collection_call_id": "",
        "raw_source": source_file,
    }


def iter_records(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        for line in text.splitlines():
            line = line.strip()
            if line:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
        return
    data = json.loads(text or "[]")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
    elif isinstance(data, dict):
        for key in ("events", "Events", "records", "Records"):
            if isinstance(data.get(key), list):
                yield from (r for r in data[key] if isinstance(r, dict))
                return
        yield data


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Adapt pre-flattened CloudTrail exports to MDR observation JSONL."
    )
    parser.add_argument(
        "--input", nargs="+", type=Path, required=True,
        help="One or more flat CloudTrail export files (JSON array or JSONL).",
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Output JSONL path for normalized observations.",
    )
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    total_in = total_out = 0

    with args.output.open("w", encoding="utf-8") as fout:
        for path in args.input:
            for record in iter_records(path):
                total_in += 1
                obs = adapt(record, path.name)
                if obs:
                    fout.write(json.dumps(obs) + "\n")
                    total_out += 1

    print(json.dumps({
        "input_records": total_in,
        "observations": total_out,
        "output": str(args.output),
    }))


if __name__ == "__main__":
    main()
