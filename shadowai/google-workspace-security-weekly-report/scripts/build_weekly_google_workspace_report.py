#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

AI_RE = re.compile(r"openai|chatgpt|claude|anthropic|gemini|google ai|ai studio|read ai|otter|fireflies|perplexity|notion|figma|github|copilot|cursor|workspace studio|email pulse|automation|\bagent\b", re.I)
BROAD_SCOPE_RE = re.compile(r"mail\.google\.com|/gmail|/drive|/documents|/spreadsheets|/presentations|/calendar|admin\.directory|admin\.reports|script\.external_request|script\.scriptapp", re.I)
CONFIG_HINT_RE = re.compile(r"ROLE|PRIVILEGE|PASSWORD|2SV|VERIFICATION|SAML|SSO|OAUTH|TRUSTED|BLOCKED|LIMITED|CAA|RULE|GROUP|ORG|USER|MOBILE|DEVICE|TOKEN|API|DOMAIN|DRIVE|SHARING|DWD|DELEGATION", re.I)
HIGH_RISK_ADMIN = {"ASSIGN_ROLE", "CREATE_USER", "SUSPEND_USER", "ARCHIVE_USER", "DELETE_USER", "CHANGE_PASSWORD", "RESET_SIGNIN_COOKIES", "CHANGE_PASSWORD_ON_NEXT_LOGIN"}
CONFIG_KEYS = ["accounts:num_users", "accounts:num_suspended_users", "accounts:num_archived_users", "accounts:num_disabled_accounts", "accounts:num_users_2sv_enrolled", "accounts:num_users_2sv_enforced", "accounts:num_users_2sv_protected", "accounts:num_security_keys", "accounts:num_passkeys_enrolled", "accounts:num_users_with_passkeys_enrolled", "accounts:num_authorized_apps", "accounts:num_users_less_secure_apps_access_allowed", "drive:num_owned_items_with_visibility_shared_externally_added", "drive:num_owned_items_with_visibility_shared_externally_removed", "gmail:num_7day_imap_users", "gmail:num_7day_pop_users", "meet:num_meetings_with_external_users", "meet:num_calls_by_external_users"]


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


def parameters(item: dict[str, Any]) -> dict[str, Any]:
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


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    event = (item.get("events") or [{}])[0]
    actor = item.get("actor") or {}
    event_id = item.get("id") or {}
    return {"time": event_id.get("time") or item.get("time") or "", "actor": actor.get("email") or actor.get("profileId") or item.get("actor") or "", "ip": item.get("ipAddress") or item.get("ip") or "", "name": event.get("name") or item.get("name") or "", "type": event.get("type") or item.get("type") or "", "params": parameters(item) if "events" in item else item.get("params", {})}


def events(path: Path) -> Iterable[dict[str, Any]]:
    for payload in iter_json_objects(path):
        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield normalize(item)
        else:
            yield normalize(payload)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def value(params: dict[str, Any], names: list[str]) -> str:
    for name in names:
        raw = params.get(name)
        if raw not in (None, ""):
            return ", ".join(str(v) for v in raw) if isinstance(raw, list) else str(raw)
    return ""


def is_external_actor(actor: str, internal_domain: str) -> bool:
    return bool(actor and "@" in actor and internal_domain and not actor.lower().endswith("@" + internal_domain.lower()))


def extract_domains(params: dict[str, Any], internal_domain: str) -> list[str]:
    domains: list[str] = []
    for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", json.dumps(params, default=str)):
        domain = email.rsplit("@", 1)[1].lower()
        if internal_domain and domain == internal_domain.lower():
            continue
        if domain not in domains:
            domains.append(domain)
    return domains


def load_usage(input_dir: Path) -> dict[str, Any]:
    candidates = sorted(input_dir.glob("customerUsageReports-*.json")) + sorted(input_dir.glob("customerUsageReports.json"))
    if not candidates:
        return {}
    try:
        return json.loads(candidates[-1].read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def usage_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    reports = payload.get("usageReports") or []
    params = reports[0].get("parameters", []) if reports else []
    result: dict[str, Any] = {}
    for item in params:
        name = item.get("name")
        if name:
            result[name] = item.get("intValue", item.get("stringValue", item.get("boolValue", item.get("datetimeValue"))))
    return result


def build(input_dir: Path, output_dir: Path, internal_domain: str, week_label: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    admin_rows: list[dict[str, Any]] = []
    high_admin: list[dict[str, Any]] = []
    admin_counter: Counter[str] = Counter()
    for row in events(input_dir / "admin.ndjson"):
        admin_counter[row["name"]] += 1
        record = {"time": row["time"], "actor": row["actor"], "event_name": row["name"], "event_type": row["type"], "ip": row["ip"], "params_excerpt": json.dumps(row["params"], sort_keys=True, default=str)[:1200]}
        if CONFIG_HINT_RE.search(row["name"]) or CONFIG_HINT_RE.search(record["params_excerpt"]):
            admin_rows.append(record)
        if row["name"] in HIGH_RISK_ADMIN or "ROLE" in row["name"] or "OAUTH" in row["name"] or "SAML" in row["name"]:
            high_admin.append(record)
    write_csv(output_dir / "weekly_admin_configuration_events.csv", admin_rows, ["time", "actor", "event_name", "event_type", "ip", "params_excerpt"])
    write_csv(output_dir / "weekly_high_risk_admin_events.csv", high_admin, ["time", "actor", "event_name", "event_type", "ip", "params_excerpt"])

    drive_groups = {"external_grants": [], "external_downloads": [], "access_requests": [], "public_like_changes": [], "shared_transfer_exposed": []}
    for row in events(input_dir / "drive.ndjson"):
        params = row["params"]
        domains = extract_domains(params, internal_domain)
        params_text = json.dumps(params, sort_keys=True, default=str)
        record = {"time": row["time"], "actor": row["actor"], "event_name": row["name"], "external_domains": ", ".join(domains), "ip": row["ip"], "params_excerpt": params_text[:1200]}
        if row["name"] == "change_user_access" and domains:
            drive_groups["external_grants"].append(record)
        if row["name"] == "download" and is_external_actor(row["actor"], internal_domain):
            drive_groups["external_downloads"].append(record)
        if row["name"] == "request_access":
            drive_groups["access_requests"].append(record)
        if row["name"] in {"change_document_visibility", "change_document_access_scope"} and any(v in params_text.lower() for v in ["people_with_link", "shared_externally", "public"]):
            drive_groups["public_like_changes"].append(record)
        if row["name"] == "change_owner" and any(v in params_text.lower() for v in ["people_with_link", "shared_externally", "public"]):
            drive_groups["shared_transfer_exposed"].append(record)
    for key, rows in drive_groups.items():
        write_csv(output_dir / f"weekly_drive_{key}.csv", rows, ["time", "actor", "event_name", "external_domains", "ip", "params_excerpt"])

    risky_login: list[dict[str, Any]] = []
    password_2sv: list[dict[str, Any]] = []
    login_failures_by_user: Counter[str] = Counter()
    login_failures_by_ip: Counter[str] = Counter()
    for row in events(input_dir / "login.ndjson"):
        record = {"time": row["time"], "actor": row["actor"], "event_name": row["name"], "ip": row["ip"], "params_excerpt": json.dumps(row["params"], sort_keys=True, default=str)[:1200]}
        if row["name"] == "login_failure":
            login_failures_by_user[row["actor"] or "unknown"] += 1
            login_failures_by_ip[row["ip"] or "unknown"] += 1
        if row["name"] in {"risky_sensitive_action_allowed", "risky_sensitive_action_blocked"}:
            risky_login.append(record)
        if row["name"] in {"password_edit", "2sv_enroll", "2sv_disable", "2sv_unenroll"}:
            password_2sv.append(record)
    write_csv(output_dir / "weekly_login_risky_events.csv", risky_login, ["time", "actor", "event_name", "ip", "params_excerpt"])
    write_csv(output_dir / "weekly_login_password_2sv_events.csv", password_2sv, ["time", "actor", "event_name", "ip", "params_excerpt"])

    shadow_ai: list[dict[str, Any]] = []
    broad_oauth: list[dict[str, Any]] = []
    for feed in ("token", "access_evaluation"):
        for row in events(input_dir / f"{feed}.ndjson"):
            params = row["params"]
            app_name = value(params, ["app_name", "application_name", "display_name", "client_name"])
            client_id = value(params, ["client_id", "oauth_client_id", "app_id"])
            scopes = listify(params.get("scope") or params.get("scopes") or params.get("scopes_requested"))
            scope_text = ", ".join(scopes)
            record = {"source_feed": feed, "time": row["time"], "actor": row["actor"], "event_name": row["name"], "app_name": app_name, "client_id": client_id, "scope_count": len(scopes), "scopes": scope_text[:1600], "ip": row["ip"]}
            if AI_RE.search(" ".join([app_name, client_id, scope_text, row["name"]])):
                shadow_ai.append(record)
            if BROAD_SCOPE_RE.search(scope_text) or len(scopes) >= 5:
                broad_oauth.append(record)
    write_csv(output_dir / "weekly_shadow_ai_oauth_events.csv", shadow_ai, ["source_feed", "time", "actor", "event_name", "app_name", "client_id", "scope_count", "scopes", "ip"])
    write_csv(output_dir / "weekly_broad_oauth_events.csv", broad_oauth, ["source_feed", "time", "actor", "event_name", "app_name", "client_id", "scope_count", "scopes", "ip"])

    gemini_rows: list[dict[str, Any]] = []
    gemini_counter: Counter[str] = Counter()
    for row in events(input_dir / "gemini_in_workspace_apps.ndjson"):
        gemini_counter[row["name"]] += 1
        gemini_rows.append({"time": row["time"], "actor": row["actor"], "event_name": row["name"], "ip": row["ip"], "params_excerpt": json.dumps(row["params"], sort_keys=True, default=str)[:1200]})
    write_csv(output_dir / "weekly_gemini_workspace_events.csv", gemini_rows, ["time", "actor", "event_name", "ip", "params_excerpt"])

    metrics = usage_metrics(load_usage(input_dir))
    config_rows = [{"metric": key, "value": metrics.get(key, "not_available")} for key in CONFIG_KEYS]
    write_csv(output_dir / "weekly_configuration_snapshot.csv", config_rows, ["metric", "value"])
    summary = {"week_label": week_label, "admin_configuration_events": len(admin_rows), "high_risk_admin_events": len(high_admin), "drive_external_grants": len(drive_groups["external_grants"]), "drive_external_downloads": len(drive_groups["external_downloads"]), "drive_access_requests": len(drive_groups["access_requests"]), "drive_public_like_changes": len(drive_groups["public_like_changes"]), "drive_shared_transfer_exposed": len(drive_groups["shared_transfer_exposed"]), "risky_login_events": len(risky_login), "password_2sv_events": len(password_2sv), "login_failures_by_user": login_failures_by_user.most_common(15), "login_failures_by_ip": login_failures_by_ip.most_common(15), "shadow_ai_oauth_events": len(shadow_ai), "broad_oauth_events": len(broad_oauth), "gemini_workspace_events": len(gemini_rows), "gemini_event_counts": gemini_counter.most_common(15), "admin_event_counts": admin_counter.most_common(15)}
    (output_dir / "weekly_analysis_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_report(output_dir / "weekly_google_workspace_security_report.md", summary, config_rows)
    return summary


def write_report(path: Path, summary: dict[str, Any], config_rows: list[dict[str, Any]]) -> None:
    lines = [f"# Weekly Google Workspace Security Report - {summary['week_label']}", "", "## Executive Summary", "", f"- Shadow AI OAuth events: {summary['shadow_ai_oauth_events']}", f"- Broad OAuth events: {summary['broad_oauth_events']}", f"- Gemini Workspace events: {summary['gemini_workspace_events']}", f"- Drive external grants: {summary['drive_external_grants']}", f"- External downloads: {summary['drive_external_downloads']}", f"- Risky login events: {summary['risky_login_events']}", f"- High-risk admin events: {summary['high_risk_admin_events']}", "", "## Priority Review Queue", "", "1. Review `weekly_shadow_ai_oauth_events.csv` and validate current app status in Admin Console.", "2. Review `weekly_broad_oauth_events.csv` for high-risk Gmail, Drive, Admin, Calendar, and Apps Script scopes.", "3. Review Drive external exposure CSVs for owner validation and remediation.", "4. Review risky login and high-risk admin event CSVs for expected business activity.", "", "## Configuration Snapshot", "", "| Metric | Value |", "| --- | --- |"]
    for row in config_rows:
        lines.append(f"| `{row['metric']}` | {row['value']} |")
    lines.extend(["", "## Evidence Files", "", "- `weekly_analysis_summary.json`", "- `weekly_configuration_snapshot.csv`", "- `weekly_shadow_ai_oauth_events.csv`", "- `weekly_broad_oauth_events.csv`", "- `weekly_gemini_workspace_events.csv`", "- `weekly_drive_external_grants.csv`", "- `weekly_drive_external_downloads.csv`", "- `weekly_drive_access_requests.csv`", "- `weekly_drive_public_like_changes.csv`", "- `weekly_drive_shared_transfer_exposed.csv`", "- `weekly_login_risky_events.csv`", "- `weekly_login_password_2sv_events.csv`", "- `weekly_admin_configuration_events.csv`", "- `weekly_high_risk_admin_events.csv`", "", "Do not claim current allow/block/trust state unless Admin Console state was validated after log analysis."])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a weekly Google Workspace security report from audit evidence.")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--internal-domain", required=True)
    parser.add_argument("--week-label", default="current-week")
    args = parser.parse_args()
    print(json.dumps(build(args.input_dir, args.output_dir, args.internal_domain, args.week_label), indent=2))


if __name__ == "__main__":
    main()
