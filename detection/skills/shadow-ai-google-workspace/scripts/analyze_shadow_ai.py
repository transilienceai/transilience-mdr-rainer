#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

AI_RE = re.compile(r"openai|chatgpt|claude|anthropic|gemini|google ai|ai studio|test kitchen|read ai|otter|fireflies|granola|fathom|perplexity|notion|figma|canva|github|copilot|cursor|replit|codeium|tabnine|zapier|make|n8n|workspace studio|email pulse|automation|\bagent\b", re.I)
BROAD_SCOPE_RE = re.compile(r"mail\.google\.com|/gmail|/drive|/documents|/spreadsheets|/presentations|/calendar|admin\.directory|admin\.reports|script\.external_request|script\.scriptapp|cloud-platform", re.I)
ADMIN_OAUTH_EVENTS = {"ADD_TO_TRUSTED_OAUTH2_APPS", "REMOVE_FROM_TRUSTED_OAUTH2_APPS", "ADD_TO_LIMITED_OAUTH2_APPS", "REMOVE_FROM_LIMITED_OAUTH2_APPS", "ADD_TO_BLOCKED_OAUTH2_APPS", "REMOVE_FROM_BLOCKED_OAUTH2_APPS", "ADD_TO_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS", "REMOVE_FROM_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS", "ADD_TO_CAA_EXEMPT_OAUTH2_APPS", "REMOVE_FROM_CAA_EXEMPT_OAUTH2_APPS"}


def iter_json_objects(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


def parameter_map(item: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for event in item.get("events", []) or []:
        for param in event.get("parameters", []) or []:
            name = param.get("name")
            if not name:
                continue
            for key in ("value", "intValue", "boolValue", "multiValue", "multiIntValue"):
                if key in param:
                    result[name] = param[key]
                    break
    return result


def normalize_event(item: dict[str, Any]) -> dict[str, Any]:
    event = (item.get("events") or [{}])[0]
    actor = item.get("actor") or {}
    event_id = item.get("id") or {}
    return {"time": event_id.get("time") or item.get("time") or "", "actor": actor.get("email") or actor.get("profileId") or item.get("actor") or "", "ip": item.get("ipAddress") or item.get("ip") or "", "name": event.get("name") or item.get("name") or "", "type": event.get("type") or item.get("type") or "", "params": parameter_map(item) if "events" in item else item.get("params", {})}


def iter_events(path: Path) -> Iterable[dict[str, Any]]:
    for payload in iter_json_objects(path):
        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield normalize_event(item)
        else:
            yield normalize_event(payload)


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def first_value(params: dict[str, Any], names: list[str]) -> str:
    for name in names:
        value = params.get(name)
        if value not in (None, ""):
            return ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
    return ""


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def analyze(input_dir: Path, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    shadow_rows: list[dict[str, Any]] = []
    broad_rows: list[dict[str, Any]] = []
    gemini_rows: list[dict[str, Any]] = []
    admin_rows: list[dict[str, Any]] = []
    app_counter: Counter[str] = Counter()
    user_counter: Counter[str] = Counter()
    confidence_counter: Counter[str] = Counter()

    for feed in ("token", "access_evaluation"):
        for row in iter_events(input_dir / f"{feed}.ndjson"):
            params = row["params"]
            app_name = first_value(params, ["app_name", "application_name", "display_name", "client_name"])
            client_id = first_value(params, ["client_id", "oauth_client_id", "app_id"])
            scopes = as_list(params.get("scope") or params.get("scopes") or params.get("scopes_requested"))
            scope_text = ", ".join(scopes)
            haystack = " ".join([app_name, client_id, scope_text, row["name"]])
            ai_match = bool(AI_RE.search(haystack))
            broad_match = bool(BROAD_SCOPE_RE.search(scope_text)) or len(scopes) >= 5
            confidence = "confirmed_oauth_grant" if feed == "token" and ai_match else "access_evaluation_context" if ai_match else ""
            record = {"source_feed": feed, "time": row["time"], "actor": row["actor"], "event_name": row["name"], "app_name": app_name, "client_id": client_id, "confidence": confidence, "scope_count": len(scopes), "scopes": scope_text[:1600], "ip": row["ip"]}
            if ai_match:
                shadow_rows.append(record)
                app_counter[app_name or client_id or "unknown"] += 1
                user_counter[row["actor"] or "unknown"] += 1
                confidence_counter[confidence] += 1
            if broad_match:
                broad_record = dict(record)
                broad_record["confidence"] = confidence or "broad_scope_non_ai_or_unknown"
                broad_rows.append(broad_record)

    for row in iter_events(input_dir / "gemini_in_workspace_apps.ndjson"):
        record = {"source_feed": "gemini_in_workspace_apps", "time": row["time"], "actor": row["actor"], "event_name": row["name"], "confidence": "workspace_gemini_usage", "ip": row["ip"], "params_excerpt": json.dumps(row["params"], sort_keys=True, default=str)[:1200]}
        gemini_rows.append(record)
        user_counter[row["actor"] or "unknown"] += 1
        confidence_counter["workspace_gemini_usage"] += 1

    for row in iter_events(input_dir / "admin.ndjson"):
        if row["name"] in ADMIN_OAUTH_EVENTS or "OAUTH" in row["name"]:
            record = {"source_feed": "admin", "time": row["time"], "actor": row["actor"], "event_name": row["name"], "confidence": "admin_oauth_control", "ip": row["ip"], "params_excerpt": json.dumps(row["params"], sort_keys=True, default=str)[:1200]}
            admin_rows.append(record)
            confidence_counter["admin_oauth_control"] += 1

    oauth_fields = ["source_feed", "time", "actor", "event_name", "app_name", "client_id", "confidence", "scope_count", "scopes", "ip"]
    write_csv(output_dir / "shadow_ai_oauth_events.csv", shadow_rows, oauth_fields)
    write_csv(output_dir / "broad_oauth_events.csv", broad_rows, oauth_fields)
    write_csv(output_dir / "gemini_workspace_events.csv", gemini_rows, ["source_feed", "time", "actor", "event_name", "confidence", "ip", "params_excerpt"])
    write_csv(output_dir / "oauth_admin_control_events.csv", admin_rows, ["source_feed", "time", "actor", "event_name", "confidence", "ip", "params_excerpt"])
    summary = {"shadow_ai_oauth_events": len(shadow_rows), "broad_oauth_events": len(broad_rows), "gemini_workspace_events": len(gemini_rows), "oauth_admin_control_events": len(admin_rows), "top_shadow_ai_apps": app_counter.most_common(25), "top_users": user_counter.most_common(25), "confidence_counts": confidence_counter.most_common()}
    (output_dir / "shadow_ai_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Google Workspace audit evidence for shadow AI usage.")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--internal-domain", default="", help="Optional tenant domain for reviewer notes; not required for OAuth analysis.")
    args = parser.parse_args()
    print(json.dumps(analyze(args.input_dir, args.output_dir), indent=2))


if __name__ == "__main__":
    main()
