---
name: aws-cloudtrail-business-baseline
description: Build business-as-usual baselines from normalized AWS CloudTrail observations. Use when analyzing AWS control-plane activity to understand normal business operations, actor/event/source-IP tuples, account behavior, application communication patterns, CI/CD deployment patterns, user access, identity changes, storage/KMS, network changes, database operations, or alertable deviations from prior CloudTrail activity.
---

# AWS CloudTrail Business Baseline

Use this skill after `aws-cloudtrail-normalize-observations` to turn normalized CloudTrail observations into a business operating model.

## Quick Start

```bash
python3 ../../skills/aws/cloudtrail/business-baseline/scripts/build_business_baseline.py \
  --observations normalized_observations.jsonl \
  --output baseline.json
```

Optional inputs:

- `--account-inventory accounts.json`
- `--resource-inventory resources.json`
- `--customer "Customer Name"`

## Workflow

1. Normalize CloudTrail first.
2. Build account, actor/event/source-IP, and business-family aggregates.
3. Review the caveats in the baseline metadata before using it for suppression.
4. Use baseline recurrence as context, not approval. Critical visibility, identity, destructive, and exposure events stay alertable.

## Business Families

Use the bundled script’s family mapping unless the customer has a better taxonomy:

- CI/CD and deployment automation
- Application and AWS service-to-service communication
- Human, SSO, and console access
- Identity and privilege management
- Storage, data, and KMS operations
- Network and perimeter security changes
- Security governance and visibility
- Database operations
- Operations and maintenance
- Other control-plane activity

## Output

The baseline JSON contains:

- `metadata`
- `overall`
- `accounts`
- `business_families`
- `actor_event_baseline`
- `alert_candidates`

Use `references/baseline_schema.md` for the exact interface.
