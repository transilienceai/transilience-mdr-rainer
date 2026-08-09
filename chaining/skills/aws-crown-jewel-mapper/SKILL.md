---
name: aws-crown-jewel-mapper
description: >-
  Enumerate and RANK the high-value AWS targets (crown jewels) an attacker would
  aim at, plus the connectivity edges that reach them, and emit them in the
  shared aws_attack_model/v1 contract. Classifies S3 buckets, databases
  (RDS/Redshift/DocumentDB/DynamoDB), Secrets Manager secrets, SSM SecureString
  parameters, KMS keys, Bedrock knowledge bases/agents, SageMaker
  models/notebooks/domains, backup/DR and log-archive stores, source/artifact
  and CI/CD systems, and identity stores (IAM Identity Center, Cognito) into a
  data_class taxonomy with a deterministic value_score. Collects connectivity
  edges (VPC peering, Transit Gateway, cross-region replication, shared
  log-bucket writers) where available and records blind spots as Gaps.
  Use when you need a ranked crown-jewel target list for the AWS red-team
  attack-chain suite -- so the chain enumerator knows what to aim at -- or to
  turn an existing AWS resource inventory into ranked CrownJewel/Node/Edge/Gap
  records without re-collecting.
---

# AWS Crown Jewel Mapper

A collector in the AWS red-team attack-chain suite. It answers one question:
**what are the highest-value targets in this AWS estate, how valuable is each,
and what connects an attacker to them?** Its output feeds the graph builder and
the chain enumerator, which traverse toward the ranked jewels.

## Purpose

- Enumerate high-value resources across accounts and classify each into a
  `data_class` (`pii | financial | source | model | secret | backup | log |
  other`).
- Assign every jewel a deterministic `value_score` (0-100) so the enumerator
  can prioritize.
- Emit the connectivity edges that reach jewels (`replicates_to`,
  `writes_logs_to`, `member_of`) when the source data is available.
- Record every collection blind spot as a `Gap` so the next run collects more.
- Emit the `aws_attack_model/v1` envelope, filling `crown_jewels`, `nodes`,
  `edges`, and `gaps` (leaving `findings` / `active_threats` for peer
  collectors). Contract: `references/attack_model_schema.md`.

## Scoring

`value_score = clamp(BASE_SCORE[data_class] + modifiers, 0, 100)`, computed by
the documented, deterministic `value_score()` function. Same inputs always yield
the same score -- see `references/scoring.md` for the full rubric, base scores,
modifiers, and the data_class taxonomy and token heuristics.

Highlights:
- Base score ranks intent: financial/pii highest, then secret, model, source,
  backup, log, other.
- Modifiers: prod naming `+12`, public/internet-facing `+18`, cross-region
  replication `+6`, client-named `+8`, large store `+5`, dev/test/uat `-15`.
- Attributes not present in the source (e.g. S3 public-access status when
  ingesting an inventory that lacks it) are treated as unknown -- they do **not**
  inflate the score, and a Gap is recorded instead. The tool never invents data.

## Inputs

- `--ingest <dir/glob>` (preferred): reuse existing inventory JSON such as
  `resource_inventory.json` / `account_inventory.json` to
  classify without re-collecting. Accepts multiple dirs/globs; dirs are searched
  recursively for `*.json`.
- `--accounts <file>`: JSON array of `{account_id, role_arn?, profile?,
  external_id?, region?}` for best-effort **live** connectivity collection (VPC
  peering, Transit Gateway attachments). Per-account errors become Gaps.
- `--customer` / `--client-tokens`: names/tokens that mark client-owned data and
  raise its score.
- `--now <ISO-8601>`: caller-supplied timestamp stamped into `collected_at`
  (the script never calls `datetime.now()`).
- `--role-name`: cross-account role for live collection (default
  `TransilienceComplianceRole`).

## CLI

```bash
# Classify from an existing inventory (no AWS calls)
python scripts/map_crown_jewels.py \
  --ingest ./inventory/resource_inventory.json \
  --customer acme --now 2026-08-08T00:00:00Z \
  --output crown_jewels.json

# Ingest a whole directory of inventories + live connectivity edges
python scripts/map_crown_jewels.py \
  --ingest ./inventory/ \
  --accounts accounts.json --customer acme \
  --now 2026-08-08T00:00:00Z --output crown_jewels.json

# Offline self-test: emit a valid envelope from an inline fixture (no AWS)
python scripts/map_crown_jewels.py --self-test
```

Requirements: stdlib + boto3 only. boto3 is imported lazily, so `--ingest` and
`--self-test` need no AWS credentials and no boto3 installed.

## Outputs

An `aws_attack_model/v1` envelope written to `--output`:
- `crown_jewels[]`: `{id, account_id, type, name, value_score, data_class, size,
  protections, reachable_by}`, ranked highest value first. `reachable_by` is
  left empty here and filled by the chain enumerator.
- `nodes[]`: one Node per jewel, id `"<type>:<account_id>:<name-or-arn>"`, with
  `exposure` and type-specific `attributes`.
- `edges[]`: `writes_logs_to` (account -> log_bucket), `member_of` (identity
  store / peered account -> account), `replicates_to` (live replication config).
- `gaps[]`: connectivity and attribute blind spots with the exact CLI/API to run
  next time.

## Connectivity

Edges emitted when the source is available:
- `writes_logs_to`: an account -> its log-archive bucket (inferred from
  log-bucket naming during ingest).
- `member_of`: identity-store (IAM Identity Center / Cognito) -> account; and,
  under `--accounts` live mode, peered/attached accounts via VPC peering and
  Transit Gateway.
- `replicates_to`: cross-region S3 replication from live `get-bucket-replication`
  when reachable.

Sources not present in a plain inventory (S3 public-access/replication status,
cross-account bucket policies, cross-region replication) are emitted as Gaps with
the precise API to collect them, rather than guessed.

## Examples

- Ranked target list for the enumerator: `--ingest <inventory> --customer <name>`
  produces `crown_jewels.json` sorted by `value_score`; hand it to the graph
  builder / chain enumerator.
- Client-data emphasis: add `--client-tokens toppanbg authormate` so buckets/DBs
  named after those clients score higher.

## Gaps

Every run appends Gap records for: S3 public-access/replication status absent
from ingest; cross-region replication and cross-account bucket policies needing
per-bucket API calls; missing boto3 or un-assumable roles in live mode; and any
inventory file that failed to parse. Each Gap names the accounts affected and the
exact `recommended_collection` command.
