---
name: aws-cloudtrail-raw-evidence-pack
description: Package actual raw AWS CloudTrail events into reproducible evidence bundles. Use when extracting CloudTrail records from LookupEvents output, CloudTrail JSON/JSONL, QRadar or SIEM decoded_payload fields, or investigation case filters, and when the report must include exact calls, file extraction commands, event-to-call indexes, records-only JSON, manifests, and reproduction metadata.
---

# AWS CloudTrail Raw Evidence Pack

Use this skill when the customer needs the actual CloudTrail events behind a finding, not normalized alert rows.

## Quick Start

```bash
python3 ../../skills/aws/cloudtrail/raw-evidence-pack/scripts/package_raw_evidence.py \
  --input lookup_output.json qradar_events_dir \
  --output evidence_pack \
  --case-config cases.json
```

`--case-config` is optional. Without it, the packager exports all CloudTrail-shaped records into a single `all_events` case.

## Evidence Rules

- Preserve raw CloudTrail event objects under `cloudtrail_event`.
- Write a records-only JSON file for customers who want only raw CloudTrail records.
- Keep wrappers separate from raw records.
- Include `reproduction` metadata whenever available:
  - AWS CLI equivalent or file extraction command
  - account, role, region, lookup parameters
  - source file and decoded payload path
- Never represent QRadar alert rows, CSV rows, or normalized observations as raw CloudTrail evidence.

## Outputs

The evidence pack writes:

- `<case>_raw_cloudtrail_events.json`
- `<case>_raw_cloudtrail_events.jsonl`
- `<case>_cloudtrail_event_records_only.json`
- `all_cases_raw_cloudtrail_events.json`
- `all_cases_cloudtrail_event_records_only.json`
- `manifest.json`
- `event_reproduction_index.md`
- `reproduction_report.md`

Read `references/case_config.md` before writing a non-trivial `--case-config`.
