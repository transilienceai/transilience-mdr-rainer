---
name: aws-vpc-flow-security-report
description: Build concise VPC Flow Log AI security reports from shadow-ai-aws-vpc-flow outputs, including model-provider egress, RAG/vector candidates, agent-like fanout, Bedrock events, internal inference indicators, confidence levels, limitations, and remediation priorities. Use when Codex needs to consolidate VPC Flow Log AI findings into Markdown, CSV, and JSON reporting artifacts for MDR or security review.
---

# AWS VPC Flow AI Security Report

Use this skill to convert VPC Flow Log AI analysis outputs into a security report.

## Workflow

1. Confirm the analysis directory contains `ai-candidate-flows.csv`, `workload-ai-summary.csv`, and `raw-query-manifest.json`.
2. Run `scripts/build_vpc_flow_ai_report.py --input-dir <analysis> --output-dir <report-dir> --week-label <label>`.
3. Review generated category CSVs and the Markdown narrative.
4. Validate low-confidence internal-port findings against service inventory before treating them as AI systems.
5. Keep customer raw logs and final customer reports out of public repositories.

## Report Sections

The script generates a Markdown report with:

- Executive summary.
- Provider and model-path evidence.
- RAG/vector-store candidates.
- Agent-like fanout and timing candidates.
- Bedrock runtime attribution.
- Internal inference and model-download candidates.
- Confidence levels and reasons.
- Limitations and required follow-up telemetry.
- Evidence files generated.

Use `references/finding-rules.md` for severity mapping, `references/confidence-levels.md` for confidence language, and `references/report-template.md` when manually extending the generated report.
