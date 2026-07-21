# Export Layout

Use a single evidence directory per audit window.

Required files produced by `scripts/export_workspace_reports.sh`:

- `export_manifest.json` records the UTC window, exported feeds, byte counts, and customer usage date.
- `<application>.ndjson` stores one raw Admin Reports API JSON response per line.
- `<application>.err` stores collection errors for that application.
- `customerUsageReports-YYYY-MM-DD.json` stores the customer usage report nearest the window end.
- `customerUsageReports-YYYY-MM-DD.err` stores usage-report collection errors.

Recommended downstream artifacts should be written beside, not over, raw evidence:

- `shadow_ai_summary.json`
- `shadow_ai_oauth_events.csv`
- `broad_oauth_events.csv`
- `weekly_analysis_summary.json`
- `weekly_google_workspace_security_report.md`

Do not edit raw `*.ndjson` files after collection.
