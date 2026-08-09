---
name: aws-cloudtrail-detection-specs
description: Generate portable AWS CloudTrail detection specifications from a CloudTrail business baseline, normalized observations, or evidence pack. Use for alert logic covering root activity, access-key creation, IAM role/policy writes, unmanaged egress, password-policy changes, S3 bucket deletion, audit-log tamper, network exposure changes, destructive database actions, KMS grant/key changes, and baseline drift without binding to a specific SIEM.
---

# AWS CloudTrail Detection Specs

Use this skill to produce backend-neutral detection specs. The output is intended to be reviewed, then implemented in QRadar, Athena, ClickHouse, Sigma-like systems, or a custom detection engine.

## Quick Start

```bash
python3 ../../skills/aws/cloudtrail/detection-specs/scripts/generate_detection_specs.py \
  --baseline baseline.json \
  --output cloudtrail_detection_specs.json
```

## Detection Policy

Generate detections as portable specs with:

- stable `id`
- severity and business family
- event/actor/source conditions
- evidence fields to collect
- suppression and exception criteria
- analyst response guidance

Do not generate SIEM-specific query syntax unless the user asks for an adapter. Keep the portable spec as the source of truth.

## Default Detection Families

- Root `ConsoleLogin` or root API use
- `CreateAccessKey` outside approved rotation roles
- IAM role/policy writes from unmanaged egress
- `UpdateAccountPasswordPolicy` outside approved pipeline/change role
- S3 `DeleteBucket` bursts and audit/log bucket deletion
- CloudTrail, Config, or FlowLogs tamper
- Network exposure changes from named users
- Destructive database operations
- KMS key/grant changes by unusual actors
- Baseline tuple drift for account/actor/event/source-IP combinations

## Output

Use `references/detection_spec_schema.md` for exact fields. Every spec must include `required_evidence`; otherwise the customer cannot reproduce or defend the alert.
