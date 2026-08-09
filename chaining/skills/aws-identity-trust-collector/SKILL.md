---
name: aws-identity-trust-collector
description: Deep AWS IAM, identity, and trust-relationship collector that goes further than a user-centric access-key report so future runs automatically surface privilege escalation and cross-account pivots. Collects per account IAM users, roles, groups with attached and inline policy documents, access keys (age, last-used, active, multi-key), MFA devices and console login profiles, role trust policies as JSON, permission boundaries, account password policy, root access-key and root-usage posture, and the Organizations tree with SCPs, then computes has_credential, can_assume, can_passrole, trusts, and can_escalate edges into an aws_attack_model/v1 graph. Use when building the identity layer of an AWS attack graph, hunting IAM privilege-escalation and PassRole paths, mapping cross-account and confused-deputy trust, auditing stale or MFA-less credentials, or enriching a red-team attack-chain model with identity and trust primitives.
---

# AWS Identity & Trust Collector

Part of the AWS red-team attack-chain suite. Emits the shared `aws_attack_model/v1` envelope
(contract: `references/attack_model_schema.md`) that the attack-graph builder merges, the
enumerator traverses, and the report packager renders. Generic AWS — no customer-specific
assumptions.

## Purpose

Produce the **identity and trust layer** of the attack graph, deeper than a user-centric
access-key report, so downstream runs find privilege escalation and cross-account pivots
automatically. This collector fills `accounts`, `nodes`, `edges`, `findings`, and `gaps`
and leaves `crown_jewels` and `active_threats` for other collectors.

It captures, per account:

- IAM **users, roles, groups** with attached managed + inline policy documents (group
  policies folded into each user's effective permissions).
- **Access keys**: age, last-used date/service, active/inactive status, and multi-key users.
- **MFA devices** and **console login profiles** (which users can log into the console).
- **Role trust policies as JSON**, detecting `Principal:"*"`, external-account trust, and the
  presence/absence of `ExternalId` / `aws:SourceArn` conditions (confused deputy).
- **Permission boundaries** on users and roles.
- **Account password policy** and **root** posture (root access-key presence, root MFA, and
  root usage from ingested CloudTrail when available).
- **Organizations** tree and **SCPs** when org / delegated-admin access is available.

## Inputs

- `--accounts accounts.json` — array of `{account_id, role_arn?, profile?, external_id?, label?, env?}`.
  The collector assumes `role_arn` per account (default role `TransilienceComplianceRole`) or
  uses a named `profile`. Mirrors the shared cross-account convention.
- `--ingest <dir/glob> ...` — reuse existing IAM access-key-risk JSON/CSV (avoid re-collecting
  keys) and prior CloudTrail (root-usage detection). Ingested keys seed users when live IAM
  collection is denied.
- `--customer <name>` — stamped into the envelope.
- `--now <ISO-8601>` — required for live runs; all age math uses it (no `datetime.now`).
- `--output <path>` — output envelope (default `identity_trust.json`).
- `--self-test` — emit and validate an envelope from an inline fixture (no AWS, no boto3).

Dependencies: Python stdlib + `boto3` (imported lazily; not needed for `--self-test`).

## CLI

```bash
# live collection across accounts, reusing prior IAM key-risk + CloudTrail outputs
python3 scripts/collect_identity_trust.py \
  --accounts accounts.json \
  --ingest ./outputs/iam_key_risk/ ./outputs/cloudtrail/ \
  --customer acme --now 2026-08-08T00:00:00Z \
  --output identity_trust.json

# offline validation (no AWS): emits a valid envelope from a built-in fixture
python3 scripts/collect_identity_trust.py --self-test
```

Per-account `AccessDenied` or any collection error is recorded as a `Gap`; the run never
hard-fails on one account.

## Outputs

A single `aws_attack_model/v1` JSON envelope:

- **nodes**: `account`, `iam_user`, `iam_role`, `iam_group`, `access_key`, `external_account`,
  plus a synthetic per-account administrator node `pe_admin:<acct>` (typed `account`) used as
  the escalation target. Node ids are stable: `iam_user:<acct>:<name>`, `iam_role:<acct>:<name>`,
  `iam_group:<acct>:<name>`, `access_key:<acct>:<user>:<keyid>`, `account:<acct>`,
  `external_account:<acct-or-*>`, `pe_admin:<acct>`.
- **edges**: `has_credential`, `can_assume`, `can_passrole` (`via = lambda|glue|sagemaker|cloudformation|ec2`),
  `trusts` (`condition = external_id present|absent`), `can_escalate` (→ `pe_admin`), `member_of`.
- **findings**: tagged with KB control names (see below).
- **gaps**: one per denied/failed collection area with the exact IAM/Org permission to add.

## Edge computation

| Edge | Source → Dest | When |
|------|---------------|------|
| `has_credential` | `iam_user` → `access_key` | user owns an access key |
| `can_assume` | `iam_user`/`iam_role`/`external_account` → `iam_role` | role trust policy allows that principal to `sts:AssumeRole` |
| `can_passrole` | principal → `iam_role` (`via` = service) | principal holds `iam:PassRole` **and** a compute-create action (`lambda:CreateFunction`, `glue:*`, `sagemaker:Create*`, `cloudformation:CreateStack`, `ec2:RunInstances`) |
| `trusts` | `iam_role` → `account`/`external_account`/principal | trust-policy principal; `condition` = ExternalId/SourceArn present or absent |
| `can_escalate` | principal → `pe_admin:<acct>` | principal holds `IAMFullAccess` / wildcard `*:*` / `AdministratorAccess` |
| `member_of` | `iam_user` → `iam_group`/`account` | group membership / account ownership |

Effective permissions are assembled from attached managed policy documents + inline policies +
(for users) inherited group policies. Full mapping of signatures → controls → KB primitives is
in `references/passrole_primitives.md`.

### Control tags (matched to the attack-primitive KB)

`IAM_ACTIVE_ACCESS_KEY`, `IAM_STALE_ACCESS_KEY`, `IAM_USER_NO_MFA`,
`IAM_ADMIN_MANAGED_POLICY`, `IAM_WILDCARD_INLINE_POLICY`, `IAM_FULL_ACCESS`,
`IAM_PASSROLE_LAMBDA` / `IAM_PASSROLE_GLUE` / `IAM_PASSROLE_SAGEMAKER` / `IAM_PASSROLE_CFN`,
`IAM_EC2_FULL`, `IAM_SSM_FULL`, `IAM_RISKY_TRUST_POLICY`, `ORG_ACCOUNT_ACCESS_ROLE`,
`AWS_CONTROL_TOWER_EXECUTION`, `SSO_ADMIN_ROLE`, `CI_ROBOT_ADMIN`, `NO_PERMISSION_BOUNDARY`,
`ROOT_ACTIVITY`, `ROOT_MFA_DISABLED`.

## Examples

- **PassRole privesc**: a CI user with `iam:PassRole` + `lambda:CreateFunction` yields
  `IAM_PASSROLE_LAMBDA` findings and `can_passrole` edges (via=lambda) to every passable role,
  so the enumerator can chain the user into a higher-privileged Lambda execution role.
- **Cross-account confused deputy**: a `vendor-audit` role trusting an external account with no
  `ExternalId` yields `IAM_RISKY_TRUST_POLICY` and a `trusts`/`can_assume` edge pair with
  `condition: external_id absent`.
- **Org pivot**: `OrganizationAccountAccessRole` trusting the management account yields
  `ORG_ACCOUNT_ACCESS_ROLE` and a `can_escalate` edge to that account's administrator node.

## Gaps

Every denied or failed collection (assume-role, `iam:List*`, `GetAccountSummary`,
`GetAccountPasswordPolicy`, `organizations:*`) becomes a `Gap` naming the affected account and
the exact permission or API to add next run. Absence of a signal (e.g., no org access) is
reported as a gap, never as a clean result. The collector does not invent data — fields it
could not read are left null and surfaced as gaps.
