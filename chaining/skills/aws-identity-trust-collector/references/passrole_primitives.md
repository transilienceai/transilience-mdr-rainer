# PassRole & privilege-escalation primitives detected

This collector computes IAM privilege-escalation and cross-account pivot primitives from
effective policy statements (attached managed + inline + group-inherited) and role trust
policies. It tags findings with KB control names (see
`../../aws-attack-primitive-kb/references/attack_primitives.json`) and emits the matching
edges into the `aws_attack_model/v1` graph.

## How a principal's effective policy is assembled

For every IAM user and role, the collector gathers statements from:
- attached **managed** policies (default version document fetched via `GetPolicyVersion`);
- **inline** policies;
- for users, the inline + attached policies of every **group** the user belongs to.

Well-known AWS-managed policy ARNs are also matched by name as a fallback when the policy
document cannot be read: `AdministratorAccess`, `IAMFullAccess`, `AmazonEC2FullAccess`,
`AmazonSSMFullAccess`.

Action matching is a case-insensitive IAM glob: `*` matches everything, `iam:*` matches
`iam:PassRole`, etc.

## PassRole primitives (principal → iam_role edge, `attributes.via`)

`can_passrole` requires `iam:PassRole` **plus** a compute-create action. The edge `via`
records the consuming service; the target roles are those matched by the PassRole
`Resource` (all roles, or admin-like roles when the resource is `*`).

| via | Trigger actions | Control | KB primitive |
|-----|-----------------|---------|--------------|
| `lambda` | `iam:PassRole` + `lambda:CreateFunction` | `IAM_PASSROLE_LAMBDA` | `pe_passrole_lambda` |
| `glue` | `iam:PassRole` + (`glue:CreateJob` \| `glue:*`) | `IAM_PASSROLE_GLUE` | `pe_passrole_glue_sagemaker` |
| `sagemaker` | `iam:PassRole` + (`sagemaker:CreateNotebookInstance` \| `sagemaker:CreateTrainingJob`) | `IAM_PASSROLE_SAGEMAKER` | `pe_passrole_glue_sagemaker` |
| `cloudformation` | `iam:PassRole` + `cloudformation:CreateStack` | `IAM_PASSROLE_CFN` | `pe_passrole_cloudformation` |
| `ec2` | `iam:PassRole` + `ec2:RunInstances` | `IAM_EC2_FULL` | `pe_ec2_run_as_role` |

## Direct escalation primitives (principal → `pe_admin:<acct>` via `can_escalate`)

| Condition | Control | KB primitive |
|-----------|---------|--------------|
| `AdministratorAccess` attached | `IAM_ADMIN_MANAGED_POLICY` | `pe_admin` |
| `iam:*` / `IAMFullAccess` | `IAM_FULL_ACCESS` | `pe_iam_fullaccess` |
| inline `*` / `svc:*` on `*` | `IAM_WILDCARD_INLINE_POLICY` | `pe_wildcard_policy` |
| `ec2:*` / EC2FullAccess | `IAM_EC2_FULL` | `pe_ec2_run_as_role` |
| `ssm:*` / SSMFullAccess / `ssm:SendCommand` / `ssm:StartSession` | `IAM_SSM_FULL` | `pe_ssm_sendcommand`, `lm_ssm_lateral` |

A `can_escalate` edge to the synthetic per-account administrator node `pe_admin:<acct>` is
emitted whenever a principal is admin-like (`Action:* Resource:*` or `AdministratorAccess`)
or holds `IAMFullAccess` / `iam:*`.

## Trust-policy primitives (role trust `AssumeRolePolicyDocument`)

For each `sts:AssumeRole*` Allow statement the trust `Principal` is classified and edges are
emitted both ways: `can_assume` (principal → role) and `trusts` (role → principal), with
`attributes.condition` set to `external_id present` or `external_id absent` (from
`sts:ExternalId` / `aws:SourceArn` / `aws:SourceAccount` conditions).

| Signature | Control | KB primitive |
|-----------|---------|--------------|
| `Principal: "*"` (or `{"AWS":"*"}`) | `IAM_RISKY_TRUST_POLICY` | `lm_confused_deputy_no_externalid` |
| trusts an **external** account with no ExternalId/SourceArn (confused deputy) | `IAM_RISKY_TRUST_POLICY` | `lm_confused_deputy_no_externalid` |
| role named `OrganizationAccountAccessRole` | `ORG_ACCOUNT_ACCESS_ROLE` | `lm_org_account_access_role` |
| role named `AWSControlTowerExecution` | `AWS_CONTROL_TOWER_EXECUTION` | `lm_org_account_access_role` |
| admin `AWSReservedSSO_*` role | `SSO_ADMIN_ROLE` | `lm_sso_role_fanout` |
| CI/robot-named principal (jenkins/pipeline/ci/…) that is admin-like | `CI_ROBOT_ADMIN` | `lm_ci_robot_pivot` |

## Credential, MFA, boundary & root primitives

| Signature | Control | KB primitive |
|-----------|---------|--------------|
| access key `Active` | `IAM_ACTIVE_ACCESS_KEY` | `ca_static_key_theft` |
| active key age > 180d, unused > 90d, or unused & age > 90d | `IAM_STALE_ACCESS_KEY` | `ca_static_key_theft`, `ps_long_lived_key` |
| console login profile present + no MFA device | `IAM_USER_NO_MFA` | `ca_no_mfa_phish`, `pe_no_mfa_admin_console` |
| admin/passrole/provisioning identity with no permissions boundary | `NO_PERMISSION_BOUNDARY` | `pe_no_permission_boundary` |
| root access key present, or root activity in ingested CloudTrail | `ROOT_ACTIVITY` | `pe_root_mfa_manipulation` |
| account root MFA disabled (`AccountMFAEnabled == 0`) | `ROOT_MFA_DISABLED` | `pe_root_mfa_manipulation`, `ps_deactivate_mfa` |

`has_credential` edges connect each `iam_user` to its `access_key` nodes, carrying age,
last-used, and multiple-active-key attributes for downstream stale-key reasoning.
