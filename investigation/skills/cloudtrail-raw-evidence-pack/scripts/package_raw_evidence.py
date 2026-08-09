#!/usr/bin/env python3
"""Package raw CloudTrail records with reproduction metadata."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def iter_paths(paths: list[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix.lower() in {".json", ".jsonl", ".ndjson"})
        else:
            yield path


def iter_records(path: Path) -> Iterable[dict[str, Any]]:
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


def detail_from(record: dict[str, Any]) -> dict[str, Any] | None:
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


def actor_from(detail: dict[str, Any]) -> str:
    identity = detail.get("userIdentity") or {}
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    arn = str(identity.get("arn") or "")
    if issuer.get("userName"):
        return str(issuer["userName"])
    if identity.get("userName"):
        return str(identity["userName"])
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[-1].split("/", 1)[0]
    if identity.get("type") == "Root":
        return "root"
    return arn or "unknown"


def summary(detail: dict[str, Any]) -> dict[str, Any]:
    identity = detail.get("userIdentity") or {}
    return {
        "event_id": detail.get("eventID"),
        "event_time": detail.get("eventTime"),
        "event_name": detail.get("eventName"),
        "event_source": detail.get("eventSource"),
        "aws_region": detail.get("awsRegion"),
        "source_ip": detail.get("sourceIPAddress"),
        "user_agent": detail.get("userAgent"),
        "actor": actor_from(detail),
        "account_id": identity.get("accountId") or detail.get("recipientAccountId"),
    }


def reproduction(record: dict[str, Any], path: Path, call_id: str) -> dict[str, Any]:
    existing = record.get("reproduction")
    if isinstance(existing, dict) and existing:
        return existing
    if record.get("aws_cli_equivalent"):
        return {"call_id": call_id, "method": "aws_cloudtrail_lookup_events", "aws_cli_equivalent": record["aws_cli_equivalent"]}
    return {
        "call_id": call_id,
        "method": "local_json_cloudtrail_extraction",
        "file": str(path),
        "command_equivalent": f"jq '.. | objects | select(has(\"eventVersion\") and has(\"eventName\"))' {path}",
    }


def load_cases(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        return [{"id": "all_events", "title": "All CloudTrail events", "match": {}}]
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("cases") or [{"id": "all_events", "title": "All CloudTrail events", "match": {}}]


def value_for_key(detail: dict[str, Any], key: str) -> str:
    if key == "actor":
        return actor_from(detail)
    if key == "accountId":
        identity = detail.get("userIdentity") or {}
        return str(identity.get("accountId") or detail.get("recipientAccountId") or "")
    return str(detail.get(key) or "")


def matches(case: dict[str, Any], detail: dict[str, Any]) -> bool:
    match = case.get("match") or {}
    for key, expected in match.items():
        values = expected if isinstance(expected, list) else [expected]
        if value_for_key(detail, key) not in {str(v) for v in values}:
            return False
    return True


def write_case(out_dir: Path, case: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    case_id = case["id"]
    json_path = out_dir / f"{case_id}_raw_cloudtrail_events.json"
    jsonl_path = out_dir / f"{case_id}_raw_cloudtrail_events.jsonl"
    records_path = out_dir / f"{case_id}_cloudtrail_event_records_only.json"
    json_path.write_text(json.dumps(events, indent=2, sort_keys=True), encoding="utf-8")
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    records_path.write_text(json.dumps([e["cloudtrail_event"] for e in events], indent=2, sort_keys=True), encoding="utf-8")
    return {
        "title": case.get("title", case_id),
        "exported_raw_cloudtrail_events": len(events),
        "json": str(json_path),
        "jsonl": str(jsonl_path),
        "cloudtrail_records_only_json": str(records_path),
        "event_names": dict(Counter(e["summary"].get("event_name") for e in events)),
        "actors": dict(Counter(e["summary"].get("actor") for e in events)),
        "source_ips": dict(Counter(e["summary"].get("source_ip") for e in events)),
        "accounts": dict(Counter(e["summary"].get("account_id") for e in events)),
    }


def write_indexes(out_dir: Path, by_case: dict[str, list[dict[str, Any]]], calls: list[dict[str, Any]]) -> None:
    lines = ["# CloudTrail Event Reproduction Index", ""]
    for case_id, events in by_case.items():
        lines.extend([f"## {case_id}", "", "| Time | Event | Actor | Source IP | Account | Event ID | Call | Command |", "| --- | --- | --- | --- | --- | --- | --- | --- |"])
        for event in events:
            s = event["summary"]
            r = event["reproduction"]
            command = r.get("aws_cli_equivalent") or r.get("command_equivalent") or ""
            lines.append(f"| {s.get('event_time') or ''} | {s.get('event_name') or ''} | {s.get('actor') or ''} | {s.get('source_ip') or ''} | {s.get('account_id') or ''} | `{s.get('event_id') or ''}` | `{r.get('call_id')}` | `{command}` |")
        lines.append("")
    (out_dir / "event_reproduction_index.md").write_text("\n".join(lines), encoding="utf-8")

    report = ["# CloudTrail Raw Evidence Reproduction Report", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", "", "## Calls and Extractions", ""]
    for call in calls:
        report.extend([f"### {call['call_id']}", "", f"- Method: `{call.get('method')}`", f"- Source: `{call.get('source')}`", f"- Returned/decoded: `{call.get('returned_events', 0)}`", f"- Matched/exported: `{call.get('matched_events', 0)}`"])
        if call.get("command_equivalent"):
            report.append(f"- Command: `{call['command_equivalent']}`")
        report.append("")
    (out_dir / "reproduction_report.md").write_text("\n".join(report), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", nargs="+", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-config", type=Path)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    cases = load_cases(args.case_config)
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    calls: list[dict[str, Any]] = []
    call_num = 0

    for path in iter_paths(args.input):
        call_num += 1
        call_id = f"FILE-{call_num:04d}"
        returned = 0
        matched = 0
        for record in iter_records(path):
            detail = detail_from(record)
            if not detail:
                continue
            returned += 1
            wrapper = {
                "collection_source": "file_extraction",
                "collection_call_id": call_id,
                "summary": summary(detail),
                "reproduction": reproduction(record, path, call_id),
                "cloudtrail_event": detail,
            }
            for case in cases:
                if matches(case, detail):
                    by_case[case["id"]].append(wrapper)
                    matched += 1
        calls.append({"call_id": call_id, "method": "local_json_cloudtrail_extraction", "source": str(path), "returned_events": returned, "matched_events": matched, "command_equivalent": f"jq '.. | objects | select(has(\"eventVersion\") and has(\"eventName\"))' {path}"})

    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "output_dir": str(args.output), "case_counts": {}, "call_count": len(calls)}
    combined: list[dict[str, Any]] = []
    for case in cases:
        events = by_case.get(case["id"], [])
        combined.extend(events)
        manifest["case_counts"][case["id"]] = write_case(args.output, case, events)
    (args.output / "all_cases_raw_cloudtrail_events.json").write_text(json.dumps(combined, indent=2, sort_keys=True), encoding="utf-8")
    (args.output / "all_cases_cloudtrail_event_records_only.json").write_text(json.dumps([e["cloudtrail_event"] for e in combined], indent=2, sort_keys=True), encoding="utf-8")
    (args.output / "lookup_and_extraction_calls.json").write_text(json.dumps(calls, indent=2, sort_keys=True), encoding="utf-8")
    manifest["combined_exported_raw_cloudtrail_events"] = len(combined)
    manifest["combined_json"] = str(args.output / "all_cases_raw_cloudtrail_events.json")
    manifest["combined_cloudtrail_records_only_json"] = str(args.output / "all_cases_cloudtrail_event_records_only.json")
    manifest["calls_json"] = str(args.output / "lookup_and_extraction_calls.json")
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    write_indexes(args.output, by_case, calls)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
