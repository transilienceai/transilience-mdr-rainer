# Crown-jewel scoring rubric & data_class taxonomy

This is the authoritative rubric for `value_score()` in
`scripts/map_crown_jewels.py`. It is deterministic: identical inputs always
produce the identical integer score. The mapper never invents data -- an
attribute that is absent from the source is treated as unknown (not present) and
drives a Gap, not a higher score.

## data_class taxonomy

`data_class` is drawn verbatim from the shared contract enum:

| data_class | Meaning | Typical resources |
|---|---|---|
| `financial` | Money/accounting data | invoice/billing/payment/payroll/ledger buckets & DBs |
| `pii` | Personal / customer / employee data | customer/user/employee/patient/KYC stores, Cognito pools |
| `secret` | Credentials & key material | Secrets Manager, SSM SecureString, KMS keys, tf-state, IAM Identity Center |
| `model` | AI/ML assets | Bedrock KBs/agents, SageMaker models/notebooks/domains |
| `source` | Source & build artifacts | ECR, CodeCommit/CodeBuild/CodePipeline, artifact buckets |
| `backup` | Backup / DR / archive | backup/archive/snapshot/DR buckets & stores |
| `log` | Audit / log archive (tamper targets) | CloudTrail/Config/access-log buckets |
| `other` | Unclassified / generic data | generic `data`/`warehouse`/`lake` buckets |

### Name-token heuristics (ordered; first match wins)

Classification uses `classify_by_name()` with ordered token rules so specific,
high-value tokens win over generic ones. Order: **secret -> financial -> pii ->
backup -> log -> source -> model -> other**. Representative tokens:

- **secret**: secret, credential, vault, tf-state, tfstate, terraform-state,
  keys, keystore, privatekey, apikey
- **financial**: financial, finance, invoice, billing, payment, payroll, ledger,
  accounting, revenue, tax, transaction
- **pii**: pii, personal, customer, client-data, employee, hr-, identity,
  patient, member, userdata, profile, kyc, onboard
- **backup**: backup, bkp, archive, snapshot, restore, dr-, -dr, disaster,
  recovery, cold-storage, glacier
- **log**: log, logs, audit, cloudtrail, -trail, access-log, flowlog,
  config-bucket
- **source**: source, repo, artifact, build, codepipeline, codebuild,
  codecommit, jenkins, nexus, release, package
- **model**: model, sagemaker, bedrock, ml-, training, inference, embeddings,
  knowledge-base, kb-
- **other**: data, warehouse, lake, datalake, store, prod-data

Buckets whose name matches log/config/access-log hints are typed as `log_bucket`
Nodes (tamper targets); everything else S3 is an `s3_bucket` Node.

Databases (`classify_db`): a finance/pii/secret name wins; otherwise a prod
relational/warehouse store defaults to `pii` (it holds business records).

## Scoring formula

```
value_score = clamp( BASE_SCORE[data_class] + sum(modifiers), 0, 100 )
```

### Base scores (intent -- how much the attacker wants this class)

| data_class | base |
|---|---|
| financial | 72 |
| pii | 70 |
| secret | 68 |
| model | 58 |
| source | 55 |
| backup | 50 |
| log | 42 |
| other | 25 |

### Modifiers (added once each, then clamped)

| Modifier | Delta | When |
|---|---|---|
| prod naming | +12 | name has prod/prd/production/live tokens (and no non-prod token) |
| public / internet-facing | +18 | resource is public / internet-facing (only when the source states it) |
| cross-region replication | +6 | replication configured (only when the source states it) |
| client-named | +8 | name contains `--customer` or a `--client-tokens` value |
| large store | +5 | large object count / size / `allocated_storage >= 100 GiB` |
| dev/test/uat/sandbox | -15 | non-prod naming |

`clamp` bounds the result to `[0, 100]`.

### Worked examples

| Resource | class | modifiers | score |
|---|---|---|---|
| `acme-prod-financial-invoices` (S3) | financial 72 | prod +12, client +8 | 92 |
| `acme-prod-customers-db` (RDS, 500 GiB) | pii 70 | prod +12, client +8, large +5 | 95 |
| `acme/prod/db-master` (secret) | secret 68 | prod +12 | 80 |
| `acme-backup-archive` (S3) | backup 50 | client +8 | 58 |
| `acme-cloudtrail-logs` (log_bucket) | log 42 | client +8 | 50 |
| `acme-dev-scratch` (S3) | other 25 | client +8, nonprod -15 | 18 |

## What is deliberately NOT scored

- **S3 public-access & replication status** are absent from plain resource
  inventories. When ingesting such a source, both are treated as unknown
  (`public=False`, `replicated=False`) and a Gap is emitted recommending
  `get-bucket-policy-status` / `get-public-access-block` /
  `get-bucket-replication`.
- **reachable_by** is intentionally empty in this collector; the chain
  enumerator computes reachability over the merged attack graph.
