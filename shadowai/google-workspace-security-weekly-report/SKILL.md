---
name: google-workspace-security-weekly-report
description: Build concise weekly Google Workspace security reports from exported Admin Reports and customer usage evidence, including shadow AI OAuth activity, Gemini Workspace usage, Drive external exposure, login risk, admin configuration changes, and configuration snapshot metrics. Use when Codex needs to consolidate Google Workspace audit logs into Markdown, CSV, and JSON weekly reporting artifacts for MDR or executive review.
---

# Google Workspace Security Weekly Report

Use this skill to convert exported Google Workspace evidence into a weekly security report.

## Workflow

1. Confirm the evidence directory contains exported Google Workspace `*.ndjson` files and optional `customerUsageReports-YYYY-MM-DD.json`.
2. Run `scripts/build_weekly_google_workspace_report.py --input-dir <evidence> --output-dir <report-dir> --internal-domain <domain> --week-label <label>`.
3. Review generated CSVs for Drive, login, admin, OAuth, Gemini, and configuration evidence.
4. Edit the Markdown executive narrative only after validating the source CSV/JSON counts.
5. Keep customer raw evidence and final customer reports out of public repositories.

## Report Sections

The script generates a Markdown report with:

- Executive summary.
- Shadow AI and OAuth risk.
- Gemini Workspace usage.
- Drive external exposure.
- Login and authentication risk.
- Admin and configuration changes.
- Configuration snapshot from customer usage reports.
- Evidence files generated.

Use `references/finding-rules.md` for signal definitions. Use `references/report-template.md` when manually extending the generated report.
