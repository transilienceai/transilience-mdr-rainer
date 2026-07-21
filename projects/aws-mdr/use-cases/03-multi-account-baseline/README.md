# Use Case 03 — Multi-account Business Baseline

Build a business-as-usual (BAU) baseline that covers an entire AWS organization or a defined account portfolio. The baseline is the foundation for alert tuning, deviation detection, and monthly security reporting.

## When to use this

- You manage 4+ AWS accounts and need a unified view of normal activity.
- You want to distinguish human access from CI/CD from AWS-service-to-service traffic.
- You are setting up first-time alert tuning and need to know what the noise floor looks like before writing detection rules.

## Collection strategy

Collect from all accounts in one pass so the normalizer and baseline see the full actor/event/account population together:

```bash
# accounts.json lists every account and cross-account role
python3 .claude/skills/lookup-collector/scripts/lookup_events.py \
  --accounts accounts.json \
  --event-names examples/event_names.txt \
  --regions us-east-1 us-east-2 us-west-2 eu-west-1 \
  --start 2026-05-16T00:00:00Z \
  --end   2026-06-16T00:00:00Z \
  --output outputs/collection
```

A 30-day window gives the baseline enough data to distinguish one-time events from recurring operational patterns.

## Normalize all accounts together

```bash
python3 .claude/skills/normalize-observations/scripts/normalize_cloudtrail.py \
  --input outputs/collection/raw_lookup_events.json \
  --output outputs/normalized_observations.jsonl
```

Passing all account files at once is important: the baseline groups by `account_id` internally, so per-account files and a single merged file produce identical baselines.

## Build the baseline

```bash
python3 .claude/skills/business-baseline/scripts/build_business_baseline.py \
  --observations outputs/normalized_observations.jsonl \
  --customer "Acme Corp" \
  --output outputs/baseline.json
```

### What the baseline captures

The baseline groups activity by five dimensions and flags deviations:

| Dimension | What it tracks |
|---|---|
| Business family | 10 families: CI/CD, user access, identity/privilege, data/storage, network, governance, database, operations, application-service comms, other |
| Account | Per-account event volumes and top actors |
| Critical events | Any event in the CRITICAL_EVENTS set, regardless of frequency |
| Actor × event tuples | Unique `(account_id, actor, event_name, source_ip)` combinations |
| Root activity | Any root API or console use |

### Alert candidate threshold

`alert_candidates` in the baseline summary counts observations that match any of:

- `actor_type == "root"`
- `event_name` in `CRITICAL_EVENTS`
- `actor_type` is a named human (`iam_user`, `assumed_role`, `unknown`) and `risk` is `critical` or `high`

A ratio of alert candidates / total observations > 5% usually means the account set has unusual activity or the event-name list is too broad.

## Per-account breakdown

Read the `accounts` key in `baseline.json` for per-account summaries:

```python
import json
b = json.load(open("outputs/baseline.json"))
for acct_id, summary in b["accounts"].items():
    print(acct_id, summary["event_count"], "events,", summary["actor_count"], "actors")
```

## Using the baseline for recurring runs

Re-run the full pipeline weekly or monthly. Store each `baseline.json` under a date-stamped path:

```
outputs/baselines/2026-05-16_to_2026-06-16/baseline.json
outputs/baselines/2026-06-01_to_2026-06-30/baseline.json
```

Feed the previous baseline into `business-triage --baseline` when triaging the current period's events. Triage will flag account/actor/event/IP tuples not seen in the prior baseline.

## Scaling notes

| Accounts | Events (7d) | Baseline build time |
|---|---|---|
| 1–5 | < 100k | seconds |
| 5–20 | 100k – 1M | < 2 min |
| 20+ | > 1M | 5–15 min; consider narrowing event-name list |

Narrow the `--event-names` list to management events only (IAM, CloudTrail, S3 control, EC2 security groups, KMS, RDS) to keep collection fast and baseline signal high.
