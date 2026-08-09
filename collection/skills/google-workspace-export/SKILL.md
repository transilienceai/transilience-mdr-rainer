---
name: google-workspace-export
description: Export Google Workspace Admin Reports and customer usage evidence with the gws CLI for security reviews, shadow AI detection, OAuth investigation, Drive sharing analysis, login risk review, Gemini Workspace usage review, and weekly Google Workspace audit reporting. Use when Codex needs to authenticate read-only, collect scoped Google Workspace audit feeds, preserve raw evidence, or prepare inputs for downstream Google Workspace security analysis.
---

# Google Workspace GWS Export

Use this skill to collect read-only Google Workspace audit evidence for security analysis.

## Workflow

1. Confirm the tenant, audit window, and output directory.
2. Verify `gws` is authenticated with read-only Admin Reports and Usage Reports scopes.
3. Run `scripts/export_workspace_reports.sh` with explicit `--start`, `--end`, and `--output-dir` values.
4. Preserve the raw `*.ndjson`, `*.err`, manifest, and customer usage report files unchanged.
5. Hand the output directory to shadow AI, OAuth, Drive, login, Gemini, or weekly-report analysis skills.

## Required Scopes

Use read-only scopes only:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`
- `https://www.googleapis.com/auth/admin.reports.usage.readonly`

Do not request Gmail, Drive content, Admin SDK write, or secret-reading scopes for this evidence collection workflow.

## High-Signal Feeds

Default feeds are optimized for security and AI detection:

- `admin` for policy, OAuth app-control, role, user, and security configuration changes.
- `drive` for external grants, downloads, access requests, public-like visibility, and shared drive ownership changes.
- `login` for failed login, risky sensitive action, password, and 2SV events.
- `token` for OAuth grants and scope evidence.
- `access_evaluation` for contextual app access and OAuth access evaluation evidence.
- `gemini_in_workspace_apps` for Gemini feature utilization events.
- `user_accounts` for account lifecycle signals.

Read `references/google-admin-report-feeds.md` when selecting additional feeds. Read `references/export-layout.md` when packaging evidence for another skill.

## Operational Rules

- Keep exports tenant-local and read-only.
- Do not normalize or deduplicate raw evidence during collection.
- Record exact start and end timestamps in UTC.
- Treat empty feed files with non-empty `.err` files as collection issues to investigate, not as proof of no activity.
- Keep customer data out of public repositories; use synthetic fixtures for reusable tests.
