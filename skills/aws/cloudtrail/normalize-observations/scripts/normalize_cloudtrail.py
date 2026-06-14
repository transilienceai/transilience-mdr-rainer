#!/usr/bin/env python3
"""Normalize CloudTrail-shaped records into business-analysis observations."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


EVENT_RISK = {
    "StopLogging": "critical",
    "DeleteTrail": "critical",
    "UpdateTrail": "critical",
    "PutEventSelectors": "critical",
    "DeleteConfigurationRecorder": "critical",
    "StopConfigurationRecorder": "critical",
    "DeleteConfigRule": "critical",
    "CreateAccessKey": "critical",
    "ScheduleKeyDeletion": "critical",
    "DisableKey": "critical",
    "DeleteBucket": "high",
    "DeleteBucketPolicy": "high",
    "PutBucketPolicy": "high",
    "AttachRolePolicy": "high",
    "AttachUserPolicy": "high",
    "PutRolePolicy": "high",
    "PutUserPolicy": "high",
    "CreateRole": "high",
    "DeleteRole": "high",
    "CreateUser": "high",
    "DeleteUser": "high",
    "UpdateAccountPasswordPolicy": "high",
    "CreateGrant": "high",
    "CreateKey": "high",
    "AuthorizeSecurityGroupIngress": "high",
    "AuthorizeSecurityGroupEgress": "high",
    "CreateNetworkAclEntry": "high",
    "DeleteNetworkAclEntry": "high",
    "ReplaceNetworkAclEntry": "high",
    "CreateRoute": "high",
    "DeleteRoute": "high",
    "ReplaceRoute": "high",
    "AttachInternetGateway": "high",
    "DetachInternetGateway": "high",
    "CreateDBInstance": "high",
    "DeleteDBInstance": "high",
}

DEPLOYMENT_RE = re.compile(r"(cloudformation|codebuild|codepipeline|codedeploy|terraform|cdk|jenkins|deploy|pipeline|stacksets)", re.I)


def iter_paths(paths: list[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix.lower() in {".json", ".jsonl", ".ndjson"})
        else:
            yield path


def iter_json_records(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        for line in text.splitlines():
            if line.strip():
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
        events = data.get("Events") or data.get("events")
        if isinstance(events, list):
            for item in events:
                if isinstance(item, dict):
                    yield item
        else:
            yield data


def cloudtrail_detail(record: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(record.get("cloudtrail_event"), dict):
        return dict(record["cloudtrail_event"])
    if isinstance(record.get("decoded_payload"), dict):
        return dict(record["decoded_payload"])
    if "CloudTrailEvent" in record:
        try:
            return json.loads(record["CloudTrailEvent"])
        except json.JSONDecodeError:
            return None
    if "eventVersion" in record and "eventName" in record:
        return dict(record)
    return None


def actor_from(detail: dict[str, Any], wrapper: dict[str, Any]) -> str:
    identity = detail.get("userIdentity") or {}
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    arn = str(identity.get("arn") or "")
    if issuer.get("userName"):
        return str(issuer["userName"])
    if identity.get("userName"):
        return str(identity["userName"])
    if wrapper.get("Username"):
        return str(wrapper["Username"])
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[-1].split("/", 1)[0]
    if identity.get("type") == "Root":
        return "root"
    return arn or "unknown"


def actor_type(actor: str, detail: dict[str, Any]) -> str:
    identity = detail.get("userIdentity") or {}
    arn = str(identity.get("arn") or "")
    lowered = f"{actor} {arn}".lower()
    if actor == "root" or identity.get("type") == "Root":
        return "root"
    if "awsreservedsso_" in lowered:
        return "sso_role"
    if identity.get("type") == "IAMUser":
        return "iam_user"
    if identity.get("type") == "AWSService" or lowered.endswith(".amazonaws.com"):
        return "service_principal"
    if "awsservicerolefor" in lowered:
        return "aws_service_role"
    if identity.get("type") == "AssumedRole" or ":assumed-role/" in arn:
        return "assumed_role"
    return "unknown" if actor == "unknown" else "assumed_role"


def resources_from(record: dict[str, Any], detail: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for resource in record.get("Resources") or []:
        if isinstance(resource, dict) and resource.get("ResourceName"):
            out.append(str(resource["ResourceName"]))
    for resource in detail.get("resources") or []:
        if isinstance(resource, dict):
            value = resource.get("ARN") or resource.get("accountId") or resource.get("resourceName")
            if value:
                out.append(str(value))
    return sorted(set(out))


def pattern_category(event_name: str, event_source: str, actor: str) -> str:
    text = f"{event_name} {event_source} {actor}".lower()
    if "consolelogin" in text or "assumerole" in text or "accesskey" in text:
        return "access"
    if DEPLOYMENT_RE.search(text) or event_name in {"RunInstances", "CreateFunction", "UpdateFunctionCode", "RegisterTaskDefinition"}:
        return "deployment"
    if any(token in text for token in ["startinstances", "stopinstances", "rebootinstances", "backup", "ssm"]):
        return "maintenance"
    if event_name.startswith(("Create", "Delete", "Update", "Put", "Attach", "Detach", "Authorize", "Revoke", "Modify", "Replace")):
        return "change"
    return "other"


def business_risk(event_name: str, actor: str) -> str:
    e = event_name.lower()
    if actor == "root" or any(t in e for t in ["accesskey", "policy", "user", "role", "group", "certificate", "password", "grant", "key"]):
        return "credential_or_privilege_risk"
    if any(t in e for t in ["logging", "trail", "flowlogs", "configurationrecorder", "configrule", "eventselectors"]):
        return "defense_evasion"
    if "bucketpolicy" in e or "bucketpublicaccess" in e:
        return "data_exposure"
    if any(t in e for t in ["deletebucket", "deletedb", "terminateinstances", "deletevpc"]):
        return "data_loss_or_outage"
    if any(t in e for t in ["securitygroup", "networkacl", "route", "internetgateway", "vpcpeering"]):
        return "internet_exposure"
    if "runinstances" in e:
        return "unauthorized_infrastructure"
    return "operational_change_risk"


def normalize(record: dict[str, Any], raw_source: str) -> dict[str, Any] | None:
    detail = cloudtrail_detail(record)
    if not detail or not detail.get("eventName"):
        return None
    identity = detail.get("userIdentity") or {}
    actor = actor_from(detail, record)
    event_name = str(detail.get("eventName") or record.get("EventName") or "")
    account_id = str(identity.get("accountId") or detail.get("recipientAccountId") or record.get("lookup_account_id") or "")
    region = str(detail.get("awsRegion") or record.get("lookup_region") or "")
    risk = "critical" if actor == "root" else EVENT_RISK.get(event_name, "medium")
    return {
        "event_id": str(detail.get("eventID") or record.get("EventId") or ""),
        "event_time": str(detail.get("eventTime") or record.get("EventTime") or record.get("event_time") or ""),
        "account_id": account_id,
        "recipient_account_id": str(detail.get("recipientAccountId") or ""),
        "region": region,
        "event_name": event_name,
        "event_source": str(detail.get("eventSource") or ""),
        "actor": actor,
        "actor_type": actor_type(actor, detail),
        "source_ip": str(detail.get("sourceIPAddress") or ""),
        "user_agent": str(detail.get("userAgent") or ""),
        "resources": resources_from(record, detail),
        "error_code": str(detail.get("errorCode") or ""),
        "risk": risk,
        "business_risk_category": business_risk(event_name, actor),
        "pattern_category": pattern_category(event_name, str(detail.get("eventSource") or ""), actor),
        "collection_call_id": str(record.get("collection_call_id") or ""),
        "raw_source": raw_source,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", nargs="+", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    written = 0
    with args.output.open("w", encoding="utf-8") as handle:
        for path in iter_paths(args.input):
            for record in iter_json_records(path):
                total += 1
                obs = normalize(record, str(path))
                if obs:
                    written += 1
                    handle.write(json.dumps(obs, sort_keys=True) + "\n")
    print(json.dumps({"input_records": total, "normalized_observations": written, "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
