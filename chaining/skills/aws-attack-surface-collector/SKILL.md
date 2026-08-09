---
name: aws-attack-surface-collector
description: Collects the internet-facing AWS exposure that standard CSPM baselines routinely miss and emits it as an aws_attack_model/v1 envelope for the red-team attack-chain suite. Use when you need to enumerate public EBS snapshots, public AMIs, public or cross-account-shared RDS snapshots, public ECR repositories, unauthenticated Lambda function URLs, open API Gateway routes, publicly-accessible Redshift/DocumentDB/ElastiCache, WAF association gaps on internet-facing ALBs and CloudFront, VPC flow-log blind spots, security groups open to 0.0.0.0/0, and EC2 instances still allowing IMDSv1 — across one or many AWS accounts via cross-account role assumption — so the attack-graph builder and enumerator can find more initial-access footholds next run.
---

# AWS Attack Surface Collector

Part of the AWS red-team attack-chain suite. It is generic (not customer-specific) and
customer-agnostic: all account/role/region context is supplied at runtime.

## Purpose

Standard CSPM baselines reliably flag public S3 buckets and obvious open ports, but they
routinely **miss** the quieter internet-exposure paths attackers actually use for initial
access. This collector closes those blind spots and emits everything as the shared
`aws_attack_model/v1` envelope (see `references/attack_model_schema.md`) so the downstream
`aws-attack-graph-builder` can merge it, the enumerator can traverse it, and the report
packager can render kill chains from it.

It owns the `nodes`, `exposes` `edges` (from the singleton `internet` node), `findings`,
and `gaps` arrays. `crown_jewels` and `active_threats` are left empty for other collectors.

## Inputs

- `--accounts accounts.json` — array of `{account_id, role_arn?, profile?, external_id?}`.
  Assumes `role_arn` per account (default role name `TransilienceComplianceRole`). See
  `references/account_config.md`.
- `--regions r1,r2` — comma-separated regions, or `all` (default) for all commercial regions.
- `--ingest <dir-or-glob>` — reuse existing CSPM/inventory/model JSON (e.g. `cspm.json`)
  and merge its exposure findings/nodes **without re-collecting**. Repeatable. Understands both
  a full `aws_attack_model/v1` envelope and a loose findings list keyed by `control`/`check_id`.
- `--customer NAME` — label stamped into the envelope (default `generic`).
- `--now ISO8601` — timestamp for `collected_at`. Recommended for reproducibility; the script
  never calls the clock at import (only a runtime fallback inside `main()` if omitted).
- `--output attack_surface.json` — output path.
- `--self-test` / `--dry-run` — emit a synthetic-but-valid envelope with **no AWS/boto3 calls**.

Dependencies: Python 3 stdlib + `boto3` only. `boto3` is imported lazily, so `--self-test`
runs with neither `boto3` nor credentials installed.

## CLI

```bash
# Full sweep across the estate
python3 scripts/collect_attack_surface.py \
  --accounts accounts.json \
  --regions us-east-1,us-west-2,eu-west-1 \
  --customer acme \
  --now 2026-08-08T00:00:00Z \
  --output attack_surface.json

# Reuse existing CSPM output instead of re-collecting
python3 scripts/collect_attack_surface.py \
  --ingest ./outputs/**/cspm.json \
  --now 2026-08-08T00:00:00Z --customer acme --output attack_surface.json

# Prove the envelope shape offline (no AWS)
python3 scripts/collect_attack_surface.py --self-test --now 2026-08-08T00:00:00Z --output /tmp/as.json
```

## Outputs (the envelope)

A single `aws_attack_model/v1` JSON file:

```json
{
  "schema": "aws_attack_model/v1",
  "customer": "acme",
  "collected_at": "2026-08-08T00:00:00Z",
  "source_skill": "aws-attack-surface-collector",
  "accounts":  [ Account ],
  "nodes":     [ {"id":"internet",...}, <exposed resource nodes> ],
  "edges":     [ <exposes edges from internet> ],
  "findings":  [ Finding ],
  "crown_jewels":   [],
  "active_threats": [],
  "gaps":      [ Gap ]
}
```

The first node is always the singleton `internet` node; every exposed resource gets an
`exposes` edge `internet -> resource`.

## Node / Edge / Finding / Gap mapping

Coverage → node type → control (from `aws-attack-primitive-kb`) → primitive:

| Exposure collected | Node `type` | Finding `control` | primitive_id |
|---|---|---|---|
| Public EBS snapshot (`createVolumePermission=all`) | `ebs_snapshot` | `EBS_SNAPSHOT_PUBLIC` | `ia_public_snapshot` |
| Public AMI (`launchPermission=all`) | `ami` | `AMI_PUBLIC` | `ia_public_snapshot` |
| Public/shared RDS snapshot (`restore`=all/accts) | `rds_snapshot` | `RDS_SNAPSHOT_PUBLIC` | `ia_public_snapshot` |
| Public ECR repo (anonymous/`*` policy) | `ecr_repo` | `ECR_PUBLIC_REPO` | `ia_public_ecr` |
| Lambda function URL `AuthType=NONE` | `lambda_function` | `LAMBDA_PUBLIC_URL` | `ia_public_lambda_url` |
| API Gateway route/method `authType=NONE` | `api_gateway` | `APIGW_NO_AUTH` | `ia_public_api_gw` |
| Redshift `PubliclyAccessible` | `redshift` | `REDSHIFT_PUBLIC` | `ia_public_db` |
| DocumentDB `PubliclyAccessible` | `documentdb` | `DOCDB_PUBLIC` | `ia_public_db` |
| ElastiCache reachable via open SG | `elasticache` | `ELASTICACHE_PUBLIC` | `ia_public_db` |
| Internet-facing ALB w/ WAF | `alb` | `ALB_INTERNET_FACING` | `ia_public_web_alb` |
| Internet-facing ALB w/o WAF | `alb` | `ALB_NO_WAF` | `ia_public_web_alb` |
| CloudFront distribution w/o WebACL | `alb` | `CLOUDFRONT_NO_WAF` | `ia_public_web_alb` |
| SG 0.0.0.0/0 on 22/3389 | (finding on SG; on `ec2_instance` if attached) | `EC2_PUBLIC_ADMIN_PORT` | `ia_admin_port_open` |
| SG 0.0.0.0/0 all-protocol | (finding on SG) | `EC2_PUBLIC_ALL_TRAFFIC` | `ia_all_traffic_sg` |
| EC2 `HttpTokens=optional` | `ec2_instance` | `EC2_IMDSV2_NOT_ENFORCED` | `ca_imds_theft` |
| VPC with no flow log | (finding on VPC) | `VPC_FLOW_LOGS_DISABLED` | `de_dns_tunneling` |

- **Node** — `id` is `"<type>:<account_id>:<name>"`; carries `exposure{internet_facing,ports,cidrs}`
  and type-specific `attributes` (e.g. `shared_public`, `url_auth`, `publicly_accessible`,
  `http_tokens`, `waf_associated`). Nodes with the same id are merged (exposure unioned).
- **Edge** — only `exposes` from `internet`, tagged with the mapped `primitive_id` in
  `attributes.primitive_id` and the region in `attributes.via`. Shared-but-not-public snapshots
  get a node + finding but **no** `exposes` edge (internet_facing=false).
- **Finding** — atomic misconfiguration with `control`, `severity`, `primitive_ids`, `mitre`
  (severity/MITRE pulled from the KB), and `raw_source` = the API/CLI it came from.
- **Gap** — every per-account/per-service denial or error becomes a `Gap{area,reason,accounts,
  recommended_collection}` with the exact CLI to re-run; the sweep never aborts.

## Examples

```bash
python3 -m py_compile scripts/collect_attack_surface.py     # must pass
python3 scripts/collect_attack_surface.py --self-test --now 2026-08-08T00:00:00Z --output /tmp/as.json
```

Chain into the graph builder:

```bash
# collect exposure ...
python3 scripts/collect_attack_surface.py --accounts accounts.json --now "$NOW" --output surface.json
# ... then merge with other collectors' envelopes in aws-attack-graph-builder
```

## Data gaps it closes

These are the CSPM-invisible footholds this collector adds to the model so future runs find
more/deeper chains:

- Snapshots and AMIs shared publicly or cross-account (mountable/launchable by attackers).
- RDS/Aurora snapshots restorable by `all` or by foreign accounts.
- Public container images (ECR anonymous pull → supply-chain reuse).
- Unauthenticated Lambda function URLs and open API Gateway routes.
- Managed data stores reachable from the internet (Redshift/DocumentDB/ElastiCache).
- Internet-facing web front doors with no WAF in front of them.
- VPCs with no flow logs (defender blind spots that also enable DNS tunneling exfiltration).
- Security groups open to the world on admin/all ports.
- EC2 instances still permitting IMDSv1 (SSRF → instance-credential theft).

Anything it could not read (denied/paginated/API error) is recorded as a `Gap` with the
re-run command, so the next collection is scoped to exactly what is still missing.
