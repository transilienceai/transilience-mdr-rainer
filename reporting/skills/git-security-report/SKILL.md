---
name: git-security-report
description: Build concise Git shadow-AI security reports from shadow-ai-git outputs, including models and providers, agent frameworks, MCP tooling, prompts, RAG/vector usage, training or eval artifacts, AI supply-chain dependencies, CI/CD usage, confidence levels, and prioritized remediation. Use when Codex needs to consolidate Git AI findings into Markdown, CSV, and JSON reporting artifacts for MDR or security review.
---

# Git AI Security Weekly Report

Use this skill to convert Git shadow-AI analysis outputs into a security report.

## Workflow

1. Confirm the analysis directory contains `git_shadow_ai_findings.csv` and `git_shadow_ai_summary.json`.
2. Run `scripts/build_weekly_git_ai_report.py --input-dir <analysis> --output-dir <report-dir> --week-label <label>`.
3. Review generated category CSVs and the Markdown narrative.
4. Validate `keyword_only` findings manually before including them as security issues.
5. Keep customer repositories, raw evidence, and final customer reports out of public repositories.

## Report Sections

The script generates a Markdown report with:

- Executive summary.
- Models and provider usage.
- Agent frameworks and MCP tooling.
- Prompts, RAG, vector stores, training, and eval signals.
- AI supply-chain and CI/CD usage.
- Confidence levels and evidence reasons.
- Security findings and remediation priorities.
- Evidence files generated.

Use `references/finding-rules.md` for severity mapping, `references/configuration-metrics.md` for summary metrics, and `references/report-template.md` when manually extending the generated report.
