#!/usr/bin/env python3
"""Create business-context triage findings from CloudTrail evidence and specs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path | None, default: Any) -> Any:
    if not path or not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_evidence_pack(path: Path) -> dict[str, Any]:
    manifest = load_json(path / "manifest.json", {})
    cases = {}
    for case_id, meta in (manifest.get("case_counts") or {}).items():
        case_path = Path(meta.get("json", ""))
        if case_path.exists():
            cases[case_id] = {"meta": meta, "events": load_json(case_path, [])}
    if not cases and (path / "all_cases_raw_cloudtrail_events.json").exists():
        cases["all_events"] = {"meta": {"title": "All events"}, "events": load_json(path / "all_cases_raw_cloudtrail_events.json", [])}
    return {"manifest": manifest, "cases": cases}


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    summaries = [e.get("summary") or {} for e in events]
    return {
        "count": len(events),
        "events": Counter(s.get("event_name") for s in summaries).most_common(8),
        "actors": Counter(s.get("actor") for s in summaries).most_common(8),
        "accounts": Counter(s.get("account_id") for s in summaries).most_common(8),
        "source_ips": Counter(s.get("source_ip") for s in summaries).most_common(8),
        "first_seen": min((s.get("event_time") for s in summaries if s.get("event_time")), default=""),
        "last_seen": max((s.get("event_time") for s in summaries if s.get("event_time")), default=""),
    }


def fmt_counts(items: list[tuple[Any, int]]) -> str:
    return ", ".join(f"`{k}` ({v})" for k, v in items if k) or "not observed"


def infer_assessment(case_id: str, summary: dict[str, Any]) -> tuple[str, str, list[str]]:
    events = {str(k) for k, _ in summary["events"]}
    actors = {str(k).lower() for k, _ in summary["actors"]}
    if "ConsoleLogin" in events and "root" in actors:
        return (
            "Root break-glass verification required",
            "Root usage may be legitimate if MFA and approval exist, but it is never routine business-as-usual without a ticket.",
            ["Confirm break-glass ticket", "Pull root activity for the following hours", "Validate MFA device and source IP"],
        )
    if "CreateAccessKey" in events:
        return (
            "Static credential governance risk",
            "Access-key creation may be scheduled rotation or user self-service, but it leaves residual credential theft risk.",
            ["Confirm owner and purpose", "Check for approved rotation role or ticket", "Plan OIDC/federation replacement"],
        )
    if "UpdateAccountPasswordPolicy" in events:
        return (
            "Likely control hardening with change-management gap",
            "Batch password-policy changes are often compliance hardening, but should be pipeline-owned and ticketed.",
            ["Confirm change record", "Compare parameters to standard", "Move recurring setting to IaC"],
        )
    if "DeleteBucket" in events:
        return (
            "Destructive storage cleanup requiring retention review",
            "Bucket deletion can be normal decommissioning, but audit/log buckets require explicit retention approval.",
            ["Check bucket names for audit/log patterns", "Confirm decommission ticket", "Validate retention/legal hold"],
        )
    if any(e in events for e in ["CreateRole", "AttachRolePolicy", "PutRolePolicy"]):
        return (
            "Privilege-bearing IAM change",
            "IAM role and policy writes can be legitimate deployment work but are privilege-escalation primitives if credentials are stolen.",
            ["Verify identity owner", "Review created policies", "Check source network and credential type"],
        )
    return (
        "Business context required",
        "The event cluster needs owner verification before it can be treated as approved baseline activity.",
        ["Confirm owner", "Validate change record", "Compare to baseline"],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-pack", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--detection-specs", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    evidence = load_evidence_pack(args.evidence_pack)
    baseline = load_json(args.baseline, {})
    specs = load_json(args.detection_specs, {})
    lines = [
        "# CloudTrail Business Triage Findings",
        "",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Evidence pack: `{args.evidence_pack}`",
        f"- Baseline: `{args.baseline or 'not supplied'}`",
        f"- Detection specs: `{args.detection_specs or 'not supplied'}`",
        "",
    ]
    if baseline:
        lines.append(f"- Baseline observations: `{baseline.get('metadata', {}).get('observation_count', 'unknown')}`")
    if specs:
        lines.append(f"- Detection specs: `{specs.get('metadata', {}).get('spec_count', len(specs.get('detections', [])))}`")
    lines.append("")

    for case_id, bundle in evidence["cases"].items():
        events = bundle["events"]
        s = summarize_events(events)
        assessment, why, checks = infer_assessment(case_id, s)
        lines.extend(
            [
                f"## {case_id} - {bundle['meta'].get('title', case_id)}",
                "",
                f"### What happened",
                f"{s['count']} raw CloudTrail events from `{s['first_seen']}` to `{s['last_seen']}`. Event mix: {fmt_counts(s['events'])}. Actors: {fmt_counts(s['actors'])}. Accounts: {fmt_counts(s['accounts'])}. Source IPs: {fmt_counts(s['source_ips'])}.",
                "",
                "### Why it likely happened",
                why,
                "",
                "### Business-as-usual assessment",
                assessment,
                "",
                "### Residual risk",
                "Authorized activity can still create residual risk when it uses root, static credentials, unmanaged egress, broad IAM write permissions, audit-log deletion, or manual cross-account changes.",
                "",
                "### Verification",
            ]
        )
        lines.extend(f"- {item}" for item in checks)
        lines.extend(["", "### Remediation", "- Prefer federation, IaC, approved automation roles, protected log archives, and explicit exception ownership over ad hoc privileged activity.", "", "### Alerting implication", "- Alert on recurrence outside approved actors, source networks, change windows, and reproduction-backed exception records.", ""])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
