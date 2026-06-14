---
name: aws-cloudtrail-lookup-collector
description: Collect reproducible AWS CloudTrail management events through CloudTrail LookupEvents. Use when making live AWS CloudTrail calls across accounts, roles, regions, event names, and time windows, especially when the output must include exact boto3 parameters, AWS CLI equivalents, call ledgers, capped-query markers, raw CloudTrailEvent payloads, and normalized observation JSONL for later baseline or alert analysis.
---

# AWS CloudTrail Lookup Collector

Use this skill for live CloudTrail management-event collection. It is customer-agnostic and requires explicit account/role/session configuration.

## Quick Start

```bash
python3 ../../skills/aws/cloudtrail/lookup-collector/scripts/lookup_events.py \
  --accounts accounts.json \
  --event-names events.txt \
  --regions us-east-1,us-west-2 \
  --start 2026-04-01T00:00:00Z \
  --end 2026-06-12T00:00:00Z \
  --output cloudtrail_lookup_out
```

## Account Config

`accounts.json` is an array:

```json
[
  {"account_id": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/ReadOnlySecurityRole", "profile": "optional-source-profile"}
]
```

If `role_arn` is omitted, the script uses the current boto3 session credentials. If `profile` is present, it uses that profile before assuming the role.

## Rules

- Record every lookup call in `lookup_calls.json`.
- Include an AWS CLI equivalent for every call.
- Capture errors and capped queries; do not hide partial collection.
- Keep raw lookup responses separately from normalized observations.
- Prefer narrow event-name lookups for high-signal management events; CloudTrail LookupEvents is query-limited and not a full data-event lake.

## Outputs

- `raw_lookup_events.json`
- `raw_cloudtrail_events.json`
- `lookup_calls.json`
- `normalized_observations.jsonl`
- `manifest.json`

Use this skill with `aws-cloudtrail-normalize-observations` when normalizing pre-existing CloudTrail files rather than making live AWS calls.
