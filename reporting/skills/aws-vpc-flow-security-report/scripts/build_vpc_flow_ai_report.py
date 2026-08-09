#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

HIGH_CATEGORIES = {"foundation_model_provider", "model_broker", "vector_database", "llm_observability", "llm_observability_or_gateway", "eval_observability"}
MEDIUM_CATEGORIES = {"internal_vector_or_database", "internal_inference_service", "package_or_model_artifact_source", "model_provider_or_registry", "embedding_reranking_provider"}


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def severity(row: dict[str, str]) -> str:
    confidence = row.get("confidence", "")
    category = row.get("dst_category", "")
    bytes_value = int(float(row.get("bytes") or 0))
    if confidence == "high":
        return "critical"
    if category in HIGH_CATEGORIES and bytes_value >= 100_000_000:
        return "critical"
    if category in HIGH_CATEGORIES:
        return "high"
    if category in MEDIUM_CATEGORIES:
        return "medium"
    if confidence == "low":
        return "medium"
    return "low"


def markdown_table(rows: list[dict[str, str]], fields: list[str]) -> str:
    if not rows:
        return "_No rows._"
    header = "| " + " | ".join(fields) + " |"
    separator = "| " + " | ".join("---" for _ in fields) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(str(row.get(field, "")).replace("|", "\\|")[:180] for field in fields) + " |")
    return "\n".join([header, separator, *body])


def top_rows(rows: list[dict[str, str]], limit: int = 15) -> list[dict[str, str]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(rows, key=lambda row: (order.get(row.get("severity", "low"), 4), -int(float(row.get("bytes") or 0))))[:limit]


def build(input_dir: Path, output_dir: Path, week_label: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates = read_csv(input_dir / "ai-candidate-flows.csv")
    workloads = read_csv(input_dir / "workload-ai-summary.csv")
    manifest = load_json(input_dir / "raw-query-manifest.json")
    bedrock = load_json(input_dir / "bedrock-cloudtrail-events.json")
    if not isinstance(bedrock, list):
        bedrock = []
    for row in candidates:
        row["severity"] = severity(row)
    fields = ["severity", "workload", "dst_category", "provider", "confidence", "match_basis", "dstaddr", "dstport", "flows", "bytes", "avg_packet_size", "avg_duration_seconds"]
    write_csv(output_dir / "vpc_flow_ai_priority_findings.csv", [row for row in candidates if row["severity"] in {"critical", "high"}], fields)
    write_csv(output_dir / "vpc_flow_ai_provider_findings.csv", [row for row in candidates if row["dst_category"] in HIGH_CATEGORIES], fields)
    write_csv(output_dir / "vpc_flow_ai_rag_agent_findings.csv", [row for row in candidates if row["dst_category"] in {"vector_database", "internal_vector_or_database", "internal_inference_service"}], fields)
    write_csv(output_dir / "vpc_flow_ai_security_findings.csv", candidates, fields)
    limitation_rows = [{"limitation": item} for item in manifest.get("limitations", [])] if isinstance(manifest, dict) else []
    write_csv(output_dir / "vpc_flow_ai_limitations.csv", limitation_rows, ["limitation"])

    severity_counts = Counter(row["severity"] for row in candidates)
    category_counts = Counter(row["dst_category"] for row in candidates)
    confidence_counts = Counter(row["confidence"] or "none" for row in candidates)
    provider_counts = Counter(row["provider"] or row["dst_category"] for row in candidates)
    bedrock_count = len([event for event in bedrock if isinstance(event, dict) and "error" not in event])
    report = [
        f"# VPC Flow AI Security Report - {week_label}",
        "",
        "## Executive Summary",
        "",
        f"- Candidate flow rows: {len(candidates)}",
        f"- Candidate workloads: {len(workloads)}",
        f"- Priority findings: {severity_counts.get('critical', 0) + severity_counts.get('high', 0)}",
        f"- Bedrock CloudTrail events: {bedrock_count}",
        f"- Collection method: {manifest.get('collection_method', 'unknown') if isinstance(manifest, dict) else 'unknown'}",
        "",
        "## Counts",
        "",
        f"- Severity: {dict(severity_counts)}",
        f"- Confidence: {dict(confidence_counts)}",
        f"- Category: {dict(category_counts)}",
        f"- Provider: {dict(provider_counts.most_common(15))}",
        "",
        "## Top Workloads",
        "",
        markdown_table(workloads[:15], ["workload", "score", "providers", "categories", "flows", "bytes", "unique_destinations"]),
        "",
        "## Priority Findings",
        "",
        markdown_table(top_rows([row for row in candidates if row["severity"] in {"critical", "high"}]), ["severity", "workload", "dst_category", "provider", "confidence", "dstaddr", "dstport", "bytes"]),
        "",
        "## Provider And Model-Path Evidence",
        "",
        markdown_table(top_rows([row for row in candidates if row["dst_category"] in HIGH_CATEGORIES]), ["severity", "workload", "dst_category", "provider", "confidence", "match_basis", "dstaddr", "bytes"]),
        "",
        "## RAG, Vector, And Internal Inference Candidates",
        "",
        markdown_table(top_rows([row for row in candidates if row["dst_category"] in {"vector_database", "internal_vector_or_database", "internal_inference_service"}]), ["severity", "workload", "dst_category", "provider", "confidence", "dstaddr", "dstport", "bytes"]),
        "",
        "## Bedrock Attribution",
        "",
    ]
    if bedrock and isinstance(bedrock[0], dict) and "error" in bedrock[0]:
        report.append(f"- CloudTrail lookup error: {bedrock[0].get('error')} {bedrock[0].get('message', '')}")
    elif bedrock_count:
        for event in bedrock[:25]:
            report.append(f"- {event.get('event_time')} {event.get('event_name')} model=`{event.get('model_id') or '-'}` user=`{event.get('username') or '-'}` source_ip=`{event.get('source_ip') or '-'}`")
    else:
        report.append("- No Bedrock CloudTrail invocation events were present in the analysis artifacts.")
    report.extend(["", "## Limitations"])
    for item in manifest.get("limitations", []) if isinstance(manifest, dict) else []:
        report.append(f"- {item}")
    report.extend([
        "",
        "## Evidence Files Generated",
        "",
        "- `vpc_flow_ai_security_findings.csv`",
        "- `vpc_flow_ai_priority_findings.csv`",
        "- `vpc_flow_ai_provider_findings.csv`",
        "- `vpc_flow_ai_rag_agent_findings.csv`",
        "- `vpc_flow_ai_limitations.csv`",
        "- `vpc_flow_ai_security_report_summary.json`",
    ])
    (output_dir / "vpc_flow_ai_security_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    summary = {
        "candidate_flows": len(candidates),
        "candidate_workloads": len(workloads),
        "bedrock_events": bedrock_count,
        "severity_counts": severity_counts.most_common(),
        "confidence_counts": confidence_counts.most_common(),
        "category_counts": category_counts.most_common(),
    }
    (output_dir / "vpc_flow_ai_security_report_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a VPC Flow Log AI security report.")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--week-label", default="current window")
    args = parser.parse_args()
    print(json.dumps(build(args.input_dir, args.output_dir, args.week_label), indent=2))


if __name__ == "__main__":
    main()
