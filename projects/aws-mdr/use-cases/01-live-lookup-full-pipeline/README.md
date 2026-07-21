# Use Case 01 — Live LookupEvents: Full Pipeline

Run all seven skills end-to-end when you have live AWS credentials. This is the canonical path: collect → normalize → evidence pack → baseline → detection specs → triage → report.

## Prerequisites

- AWS credentials configured (profile, environment variables, or EC2/ECS instance role).
- One or more roles with `cloudtrail:LookupEvents` in the target accounts.
- Python 3.10+ and `pip install -r requirements.txt` from the repo root.

## Step 1 — Create an accounts config

`accounts.json` lists every account and role to collect from. Use `examples/accounts.example.json` as a template.

```json
[
  {
    "account_id": "111111111111",
    "role_arn": "arn:aws:iam::111111111111:role/SecurityReadOnly"
  },
  {
    "account_id": "222222222222",
    "role_arn": "arn:aws:iam::222222222222:role/SecurityReadOnly",
    "profile": "mgmt-account"
  }
]
```

## Step 2 — Collect live CloudTrail events

```bash
python3 .claude/skills/lookup-collector/scripts/lookup_events.py \
  --accounts accounts.json \
  --event-names examples/event_names.txt \
  --regions us-east-1 us-west-2 \
  --start 2026-06-01T00:00:00Z \
  --end   2026-06-08T00:00:00Z \
  --output outputs/collection
```

Outputs: `outputs/collection/raw_lookup_events.json`, `lookup_calls.json`, `normalized_observations.jsonl`, `manifest.json`.

## Step 3 — Normalize observations

Use the normalized JSONL already written by the collector, or re-normalize the raw events:

```bash
python3 .claude/skills/normalize-observations/scripts/normalize_cloudtrail.py \
  --input outputs/collection/raw_lookup_events.json \
  --output outputs/normalized_observations.jsonl
```

## Step 4 — Package raw evidence

```bash
python3 .claude/skills/raw-evidence-pack/scripts/package_raw_evidence.py \
  --input outputs/collection/raw_lookup_events.json \
  --output outputs/evidence_pack \
  --case-config examples/cases.example.json
```

## Step 5 — Build the business baseline

```bash
python3 .claude/skills/business-baseline/scripts/build_business_baseline.py \
  --observations outputs/normalized_observations.jsonl \
  --customer "Acme Corp" \
  --output outputs/baseline.json
```

## Step 6 — Generate detection specs

```bash
python3 .claude/skills/detection-specs/scripts/generate_detection_specs.py \
  --baseline outputs/baseline.json \
  --output outputs/detection_specs.json
```

## Step 7 — Triage findings

```bash
python3 .claude/skills/business-triage/scripts/triage_cloudtrail_findings.py \
  --evidence-pack outputs/evidence_pack \
  --baseline outputs/baseline.json \
  --detection-specs outputs/detection_specs.json \
  --output outputs/triage.json
```

## Step 8 — Package the report

```bash
python3 .claude/skills/report-packager/scripts/package_markdown_report.py \
  --customer "Acme Corp" \
  --baseline outputs/baseline.json \
  --evidence-pack outputs/evidence_pack \
  --triage outputs/triage.json \
  --detection-specs outputs/detection_specs.json \
  --output outputs/cloudtrail_report.md
```

## What to expect

For a mid-size AWS environment over 7 days (management events only):

| Metric | Typical range |
|---|---|
| Raw events collected | 10 000 – 200 000 |
| Normalized observations | same as raw (1:1) |
| Alert candidates in baseline | 5 – 20% of observations |
| Detection specs generated | 8 – 12 |
| Report length | 4 – 8 KB Markdown |

## Smoke test

The repo's built-in smoke test exercises steps 2–8 with synthetic data:

```bash
cd projects/aws-mdr
bash examples/run_smoke.sh
```
