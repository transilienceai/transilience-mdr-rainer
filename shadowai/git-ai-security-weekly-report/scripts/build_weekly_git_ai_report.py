#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITY_BY_CONFIDENCE = {
    "confirmed_code_usage": "high",
    "ci_cd_signal": "high",
    "prompt_or_data_signal": "medium",
    "dependency_signal": "medium",
    "keyword_only": "low",
}

HIGH_RISK_CATEGORIES = {"mcp_tooling", "secret_configuration", "ci_cd_ai_usage"}


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


def severity(row: dict[str, str]) -> str:
    if row.get("category") in HIGH_RISK_CATEGORIES and row.get("confidence") in {"confirmed_code_usage", "ci_cd_signal"}:
        return "critical"
    return SEVERITY_BY_CONFIDENCE.get(row.get("confidence", ""), "low")


def load_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def top_rows(rows: list[dict[str, str]], limit: int = 15) -> list[dict[str, str]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(rows, key=lambda row: (order.get(row.get("severity", "low"), 4), row.get("repo", ""), row.get("file_path", "")))[:limit]


def markdown_table(rows: list[dict[str, str]], fields: list[str]) -> str:
    if not rows:
        return "_No rows._"
    header = "| " + " | ".join(fields) + " |"
    separator = "| " + " | ".join("---" for _ in fields) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(str(row.get(field, "")).replace("|", "\\|")[:180] for field in fields) + " |")
    return "\n".join([header, separator, *body])


def build(input_dir: Path, output_dir: Path, week_label: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = read_csv(input_dir / "git_shadow_ai_findings.csv")
    for row in rows:
        row["severity"] = severity(row)

    fields = ["severity", "repo", "category", "component", "confidence", "file_path", "line_number", "reason"]
    write_csv(output_dir / "git_ai_security_findings.csv", rows, fields)
    write_csv(output_dir / "git_ai_priority_findings.csv", [row for row in rows if row["severity"] in {"critical", "high"}], fields)
    write_csv(output_dir / "git_ai_mcp_and_agent_findings.csv", [row for row in rows if row["category"] in {"mcp_tooling", "agent_framework"}], fields)
    write_csv(output_dir / "git_ai_prompt_rag_training_findings.csv", [row for row in rows if row["category"] in {"prompt_surface", "rag_vector_store", "training_eval_data"}], fields)
    write_csv(output_dir / "git_ai_supply_chain_findings.csv", [row for row in rows if row["category"] in {"ai_supply_chain", "ci_cd_ai_usage", "secret_configuration"}], fields)

    summary = load_summary(input_dir / "git_shadow_ai_summary.json")
    severity_counts = Counter(row["severity"] for row in rows)
    category_counts = Counter(row["category"] for row in rows)
    confidence_counts = Counter(row["confidence"] for row in rows)
    repos_with_findings = sorted({row["repo"] for row in rows if row.get("repo")})

    report = [
        f"# Git AI Security Report - {week_label}",
        "",
        "## Executive Summary",
        "",
        f"- Repositories scanned: {summary.get('repos_scanned', len(repos_with_findings))}",
        f"- Files scanned: {summary.get('files_scanned', 'unknown')}",
        f"- Total findings: {len(rows)}",
        f"- Repositories with findings: {len(repos_with_findings)}",
        f"- Priority findings: {severity_counts.get('critical', 0) + severity_counts.get('high', 0)}",
        "",
        "## Counts",
        "",
        f"- Severity: {dict(severity_counts)}",
        f"- Confidence: {dict(confidence_counts)}",
        f"- Category: {dict(category_counts)}",
        "",
        "## Priority Findings",
        "",
        markdown_table(top_rows([row for row in rows if row["severity"] in {"critical", "high"}]), ["severity", "repo", "category", "component", "confidence", "file_path", "line_number"]),
        "",
        "## Model Providers, Agents, and MCP",
        "",
        markdown_table(top_rows([row for row in rows if row["category"] in {"model_provider_usage", "agent_framework", "mcp_tooling"}]), ["severity", "repo", "category", "component", "confidence", "file_path", "line_number"]),
        "",
        "## Prompts, RAG, Training, and Eval",
        "",
        markdown_table(top_rows([row for row in rows if row["category"] in {"prompt_surface", "rag_vector_store", "training_eval_data"}]), ["severity", "repo", "category", "component", "confidence", "file_path", "line_number"]),
        "",
        "## Supply Chain and CI/CD",
        "",
        markdown_table(top_rows([row for row in rows if row["category"] in {"ai_supply_chain", "ci_cd_ai_usage", "secret_configuration"}]), ["severity", "repo", "category", "component", "confidence", "file_path", "line_number"]),
        "",
        "## Reviewer Notes",
        "",
        "- Validate keyword-only findings before treating them as active AI usage.",
        "- Confirm business owner, approval status, data touched, and runtime telemetry for confirmed code usage.",
        "- Review MCP servers and CI/CD AI usage first because they can expose tools, source code, credentials, and build artifacts.",
        "",
        "## Evidence Files Generated",
        "",
        "- `git_ai_security_findings.csv`",
        "- `git_ai_priority_findings.csv`",
        "- `git_ai_mcp_and_agent_findings.csv`",
        "- `git_ai_prompt_rag_training_findings.csv`",
        "- `git_ai_supply_chain_findings.csv`",
    ]
    (output_dir / "git_ai_security_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    output_summary = {
        "findings": len(rows),
        "repositories_with_findings": len(repos_with_findings),
        "severity_counts": severity_counts.most_common(),
        "confidence_counts": confidence_counts.most_common(),
        "category_counts": category_counts.most_common(),
    }
    (output_dir / "git_ai_security_report_summary.json").write_text(json.dumps(output_summary, indent=2), encoding="utf-8")
    return output_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a Git AI security report from shadow AI findings.")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--week-label", default="current window")
    args = parser.parse_args()
    print(json.dumps(build(args.input_dir, args.output_dir, args.week_label), indent=2))


if __name__ == "__main__":
    main()
