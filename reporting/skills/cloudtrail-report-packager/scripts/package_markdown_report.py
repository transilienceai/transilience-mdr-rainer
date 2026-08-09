#!/usr/bin/env python3
"""Package CloudTrail analysis artifacts into a customer-facing Markdown report."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path | None, default: Any) -> Any:
    if not path or not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_text(path: Path | None) -> str:
    if not path or not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def count_list(items: list[dict[str, Any]], limit: int = 8) -> str:
    return ", ".join(f"`{item.get('value')}` ({item.get('count')})" for item in items[:limit]) or "not observed"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--customer", required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--evidence-pack", type=Path)
    parser.add_argument("--triage", type=Path)
    parser.add_argument("--detection-specs", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    baseline = load_json(args.baseline, {})
    detections = load_json(args.detection_specs, {})
    triage = load_text(args.triage)
    evidence_manifest = load_json(args.evidence_pack / "manifest.json" if args.evidence_pack else None, {})

    lines = [
        f"# {args.customer} CloudTrail Business Operations and Alerting Report",
        "",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        "- Classification: Confidential",
        "",
        "## Executive Summary",
        "",
    ]
    if baseline:
        meta = baseline.get("metadata", {})
        lines.extend(
            [
                f"The baseline contains `{meta.get('observation_count', 'unknown')}` normalized CloudTrail observations across `{meta.get('account_count', 'unknown')}` accounts.",
                f"It produced `{meta.get('alert_candidate_count', 'unknown')}` candidate deviations or critical override items.",
                "",
            ]
        )
    if evidence_manifest:
        lines.extend([f"The evidence package contains `{evidence_manifest.get('combined_exported_raw_cloudtrail_events', 'unknown')}` raw CloudTrail events with reproduction metadata.", ""])
    if detections:
        lines.extend([f"The detection package contains `{detections.get('metadata', {}).get('spec_count', len(detections.get('detections', [])))}` portable CloudTrail detection specs.", ""])

    if triage:
        lines.extend(["## Investigation Findings", "", triage, ""])

    if baseline:
        lines.extend(["## Business Baseline", ""])
        overall = baseline.get("overall", {})
        lines.append(f"- Top events: {count_list(overall.get('top_events', []))}")
        lines.append(f"- Top actors: {count_list(overall.get('top_actors', []))}")
        lines.append(f"- Business families: {count_list(overall.get('business_family_mix', []))}")
        lines.append("")

    if detections:
        lines.extend(["## Detection Recommendations", ""])
        for spec in detections.get("detections", []):
            lines.extend([f"### {spec.get('title')}", "", f"- Severity: `{spec.get('severity')}`", f"- Family: `{spec.get('business_family')}`", f"- Description: {spec.get('description')}", f"- Required evidence: {', '.join(spec.get('required_evidence', []))}", ""])

    lines.extend(["## Evidence Appendix", ""])
    if args.evidence_pack:
        lines.extend(
            [
                f"- Evidence pack: `{args.evidence_pack}`",
                f"- Manifest: `{args.evidence_pack / 'manifest.json'}`",
                f"- Event reproduction index: `{args.evidence_pack / 'event_reproduction_index.md'}`",
                f"- Reproduction report: `{args.evidence_pack / 'reproduction_report.md'}`",
                "",
            ]
        )
    if args.baseline:
        lines.append(f"- Baseline JSON: `{args.baseline}`")
    if args.detection_specs:
        lines.append(f"- Detection specs JSON: `{args.detection_specs}`")
    lines.append("")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
