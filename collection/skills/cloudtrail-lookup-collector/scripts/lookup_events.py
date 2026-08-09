#!/usr/bin/env python3
"""Collect CloudTrail LookupEvents output with reproducibility metadata."""

from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


AWS_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=30)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_event_names(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]


def account_id_from_role(role_arn: str) -> str:
    match = re.match(r"arn:aws:iam::(\d{12}):role/.+", role_arn)
    return match.group(1) if match else ""


def session_for(account: dict[str, Any]) -> boto3.Session:
    base = boto3.Session(profile_name=account.get("profile")) if account.get("profile") else boto3.Session()
    role_arn = account.get("role_arn")
    if not role_arn:
        return base
    sts = base.client("sts", config=AWS_CONFIG)
    kwargs: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "cloudtrail-lookup-collector"}
    if account.get("external_id"):
        kwargs["ExternalId"] = account["external_id"]
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def cli_equivalent(region: str, event_name: str, start: datetime, end: datetime) -> str:
    return (
        f"aws cloudtrail lookup-events --region {region} "
        f"--lookup-attributes AttributeKey=EventName,AttributeValue={event_name} "
        f"--start-time {start.isoformat()} --end-time {end.isoformat()} --max-results 50"
    )


def collect_one(client, account: dict[str, Any], account_id: str, region: str, event_name: str, start: datetime, end: datetime, max_pages: int, call_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    call = {
        "call_id": call_id,
        "method": "boto3.client('cloudtrail').lookup_events",
        "account_id": account_id,
        "role_arn": account.get("role_arn", ""),
        "region": region,
        "parameters": {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": event_name}], "StartTime": start.isoformat(), "EndTime": end.isoformat(), "MaxResults": 50},
        "aws_cli_equivalent": cli_equivalent(region, event_name, start, end),
        "status": "started",
        "returned_events": 0,
        "pages": 0,
        "capped": False,
    }
    out: list[dict[str, Any]] = []
    token = None
    try:
        while True:
            kwargs: dict[str, Any] = {
                "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": event_name}],
                "StartTime": start,
                "EndTime": end,
                "MaxResults": 50,
            }
            if token:
                kwargs["NextToken"] = token
            response = client.lookup_events(**kwargs)
            events = response.get("Events", [])
            call["returned_events"] += len(events)
            call["pages"] += 1
            for event in events:
                wrapper = dict(event)
                wrapper["collection_call_id"] = call_id
                wrapper["lookup_account_id"] = account_id
                wrapper["lookup_region"] = region
                wrapper["reproduction"] = {
                    "call_id": call_id,
                    "method": call["method"],
                    "account_id": account_id,
                    "role_arn": account.get("role_arn", ""),
                    "region": region,
                    "parameters": call["parameters"],
                    "aws_cli_equivalent": call["aws_cli_equivalent"],
                }
                out.append(wrapper)
            token = response.get("NextToken")
            if not token:
                break
            if call["pages"] >= max_pages:
                call["capped"] = True
                break
            time.sleep(0.05)
        call["status"] = "ok"
    except ClientError as exc:
        call["status"] = "error"
        call["error"] = f"{exc.response.get('Error', {}).get('Code')}: {exc.response.get('Error', {}).get('Message')}"
    except Exception as exc:  # noqa: BLE001
        call["status"] = "error"
        call["error"] = f"{type(exc).__name__}: {exc}"
    return out, call


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accounts", type=Path, required=True)
    parser.add_argument("--event-names", type=Path, required=True)
    parser.add_argument("--regions", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-pages-per-event", type=int, default=4)
    args = parser.parse_args()

    accounts = json.loads(args.accounts.read_text(encoding="utf-8"))
    event_names = load_event_names(args.event_names)
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    start = parse_time(args.start)
    end = parse_time(args.end)
    args.output.mkdir(parents=True, exist_ok=True)

    calls = []
    raw_lookup = []
    call_num = 0
    for account in accounts:
        account_id = account.get("account_id") or account_id_from_role(account.get("role_arn", "")) or "current"
        session = session_for(account)
        for region in regions:
            client = session.client("cloudtrail", region_name=region, config=AWS_CONFIG)
            for event_name in event_names:
                call_num += 1
                events, call = collect_one(client, account, account_id, region, event_name, start, end, args.max_pages_per_event, f"AWS-{call_num:04d}")
                raw_lookup.extend(events)
                calls.append(call)

    (args.output / "raw_lookup_events.json").write_text(json.dumps(raw_lookup, indent=2, sort_keys=True, default=str), encoding="utf-8")
    raw_cloudtrail = []
    for event in raw_lookup:
        if event.get("CloudTrailEvent"):
            try:
                raw_cloudtrail.append(json.loads(event["CloudTrailEvent"]))
            except json.JSONDecodeError:
                pass
    (args.output / "raw_cloudtrail_events.json").write_text(json.dumps(raw_cloudtrail, indent=2, sort_keys=True, default=str), encoding="utf-8")
    (args.output / "lookup_calls.json").write_text(json.dumps(calls, indent=2, sort_keys=True, default=str), encoding="utf-8")
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "accounts": len(accounts),
        "regions": regions,
        "event_names": event_names,
        "call_count": len(calls),
        "returned_events": len(raw_lookup),
        "raw_lookup_events": str(args.output / "raw_lookup_events.json"),
        "raw_cloudtrail_events": str(args.output / "raw_cloudtrail_events.json"),
        "lookup_calls": str(args.output / "lookup_calls.json"),
        "errors": [c for c in calls if c.get("status") == "error"],
        "capped_queries": [c for c in calls if c.get("capped")],
    }
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
