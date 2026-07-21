# Use Case 02 — Pre-flattened CloudTrail Exports

Use this path when CloudTrail data has already been exported and flattened by a SIEM, a third-party collector, a cost/compliance tool, or a homegrown ETL. The raw CloudTrail event structure (`eventVersion`, `userIdentity`, `CloudTrailEvent`) is gone; you have flat rows with fields like `event_name`, `username`, `source_ip`, `aws_region`.

## Why this path exists

`normalize-observations` and `raw-evidence-pack` both expect **raw CloudTrail format**. When data is pre-flattened, `normalize_cloudtrail.py` produces zero observations because it cannot find `eventName` in the expected nesting. The adapter in this use case reconstructs the schema those scripts need without calling AWS.

## Recognising pre-flattened data

Your input is pre-flattened if the top-level keys look like:

```json
{
  "event_time": "2026-06-01T12:00:00Z",
  "event_name": "AssumeRole",
  "event_source": "sts.amazonaws.com",
  "username": "build-user",
  "user_type": "AssumedRole",
  "source_ip": "203.0.113.10",
  "aws_region": "us-east-1",
  "recipient_account_id": "111111111111"
}
```

If the top-level keys are `eventVersion`, `userIdentity`, `eventName` — use [use case 01](../01-live-lookup-full-pipeline/README.md) instead.

## Step 1 — Adapt pre-flattened exports to observation format

The bundled adapter converts flat rows into the stable observation schema that `business-baseline`, `detection-specs`, `business-triage`, and `report-packager` consume.

```bash
python3 .claude/skills/normalize-observations/scripts/adapt_preflattened.py \
  --input path/to/export_account_a.json \
          path/to/export_account_b.json \
  --output outputs/normalized_observations.jsonl
```

The adapter:
- Maps `username` → `actor`, `user_type` → `actor_type`, `recipient_account_id` → `account_id`.
- Derives `risk`, `business_risk_category`, and `pattern_category` using the same logic as the normalizer.
- Accepts JSON arrays or JSONL; handles multiple files in one pass.
- Reports `input_records` and `observations` counts on stdout as JSON.

### Field mapping reference

| Flat field | Observation field | Notes |
|---|---|---|
| `event_name` | `event_name` | direct |
| `event_source` | `event_source` | direct |
| `event_time` | `event_time` | direct |
| `username` | `actor` | lowercased |
| `user_type` | `actor_type` | mapped: `IAMUser`→`iam_user`, `AssumedRole`→`assumed_role`, `Root`→`root`, `AWSService`→`aws_service` |
| `recipient_account_id` | `account_id` | direct |
| `source_ip` | `source_ip` | direct |
| `aws_region` | `region` | direct |
| `error_code` | `error_code` | direct |
| `resources` | `resources` | direct (list) |
| *(derived)* | `risk` | `critical` if root; else EVENT_RISK table; default `medium` |
| *(derived)* | `business_risk_category` | delete/stop/disable→high; create/attach/put→medium; else low |
| *(derived)* | `pattern_category` | deployment regex → `ci_cd_deployment`; write verbs → `identity_privilege_management`; else `other_control_plane` |

## Step 2 — Build the business baseline

```bash
python3 .claude/skills/business-baseline/scripts/build_business_baseline.py \
  --observations outputs/normalized_observations.jsonl \
  --customer "Acme Corp" \
  --output outputs/baseline.json
```

## Step 3 — Generate detection specs

```bash
python3 .claude/skills/detection-specs/scripts/generate_detection_specs.py \
  --baseline outputs/baseline.json \
  --output outputs/detection_specs.json
```

## Step 4 — Triage (using adapted observations as evidence)

`business-triage` normally takes a `raw-evidence-pack` directory. With pre-flattened data, pass the adapted JSONL directly:

```bash
python3 .claude/skills/business-triage/scripts/triage_cloudtrail_findings.py \
  --evidence-pack outputs/normalized_observations.jsonl \
  --baseline outputs/baseline.json \
  --detection-specs outputs/detection_specs.json \
  --output outputs/triage.json
```

## Step 5 — Package the report

```bash
python3 .claude/skills/report-packager/scripts/package_markdown_report.py \
  --customer "Acme Corp" \
  --baseline outputs/baseline.json \
  --triage outputs/triage.json \
  --detection-specs outputs/detection_specs.json \
  --output outputs/cloudtrail_report.md
```

Note: `--evidence-pack` is omitted because we do not have raw CloudTrail records. The report still includes baseline findings, detection specs, and triage; the evidence appendix will note the limitation.

## Limitations vs. the live pipeline

| Capability | Live (use case 01) | Pre-flattened (this use case) |
|---|---|---|
| Raw CloudTrail records in report | Yes | No — flattening discards them |
| Reproduction commands in evidence pack | Yes | No |
| `raw-evidence-pack` outputs | Yes | Skipped |
| Baseline, detection specs, triage, report | Yes | Yes |
| `actor_type` accuracy | High (parsed from `userIdentity`) | Depends on exporter mapping `user_type` |

## Common input formats

### JSON array (most exporters)

```json
[
  {"event_time": "2026-06-01T12:00:00Z", "event_name": "AssumeRole", ...},
  {"event_time": "2026-06-01T12:01:00Z", "event_name": "Decrypt", ...}
]
```

### JSONL / NDJSON

```
{"event_time": "2026-06-01T12:00:00Z", "event_name": "AssumeRole", ...}
{"event_time": "2026-06-01T12:01:00Z", "event_name": "Decrypt", ...}
```

Both formats are accepted by the adapter.
