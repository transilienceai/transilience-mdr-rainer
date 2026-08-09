---
name: aws-cloudtrail-normalize-observations
description: Normalize AWS CloudTrail records into a stable business-analysis observation schema. Use when working with CloudTrail LookupEvents output, raw CloudTrail JSON, CloudTrail JSONL, QRadar decoded_payload records, evidence-pack wrappers, actor/source-IP/event baselining, or when another AWS CloudTrail skill needs normalized observations before baseline, detection, triage, or reporting.
---

# AWS CloudTrail Normalize Observations

Use this skill to convert raw CloudTrail-shaped records into one normalized JSONL stream that downstream baseline, alerting, and reporting skills can consume.

## Quick Start

Run the bundled normalizer when the input is file-based:

```bash
python3 ../../skills/aws/cloudtrail/normalize-observations/scripts/normalize_cloudtrail.py \
  --input path/to/cloudtrail.json path/to/events.jsonl \
  --output normalized_observations.jsonl
```

The script accepts:

- CloudTrail `LookupEvents` responses with `CloudTrailEvent`
- raw CloudTrail event objects with `eventVersion`
- JSON arrays or JSONL streams
- evidence-pack wrappers with `cloudtrail_event`
- SIEM wrappers with `decoded_payload`

## Workflow

1. Preserve the raw evidence separately; normalization is an analysis view, not the legal evidence record.
2. Normalize all events before building baselines or detection specs.
3. Use `references/observation_schema.md` when a downstream task needs exact field names.
4. Treat `actor`, `actor_type`, `business_risk_category`, and `pattern_category` as explainability fields; do not use them as the only source of truth for enforcement.

## Rules

- Extract actor in this order: SSO/session issuer role name, IAM user name, CloudTrail `Username`, assumed-role ARN role name, root, full ARN, `unknown`.
- Classify root as critical regardless of event name.
- Mark static IAM users and named users separately from service roles and SSO/admin roles.
- Keep `source_ip` exactly as CloudTrail reports it; classify AWS service sources separately rather than rewriting them.
- Include `resources` from CloudTrail `Resources`, request parameters, or event resources when available.
- Do not discard malformed records silently when running manually; report invalid counts in the manifest or console output.

## Output

The script writes one JSON object per line with the stable observation schema. Downstream skills expect these fields:

`event_id`, `event_time`, `account_id`, `region`, `event_name`, `event_source`, `actor`, `actor_type`, `source_ip`, `user_agent`, `resources`, `error_code`, `risk`, `business_risk_category`, `pattern_category`.
