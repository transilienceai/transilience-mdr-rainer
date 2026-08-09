# `accounts.json` format

`--accounts` points at a JSON file describing the AWS accounts to sweep. It is either a
JSON **array** of account objects, or an object with an `"accounts"` key holding that array.

```json
[
  {
    "account_id": "123456789012",
    "label": "prod-payments",
    "env": "prod",
    "role_arn": "arn:aws:iam::123456789012:role/TransilienceComplianceRole",
    "external_id": "optional-shared-secret",
    "is_management": false,
    "org_id": "o-abcd1234",
    "notes": "free-form"
  },
  {
    "account_id": "210987654321",
    "profile": "sandbox"
  }
]
```

## Fields

| field | required | meaning |
|---|---|---|
| `account_id` | yes | 12-digit AWS account id. |
| `role_arn` | no | Role to `sts:AssumeRole` into. Defaults to `arn:aws:iam::<account_id>:role/TransilienceComplianceRole`. |
| `profile` | no | Local named AWS profile. If set, used instead of AssumeRole (no `role_arn` needed). |
| `external_id` | no | Passed as `ExternalId` to `AssumeRole` (confused-deputy protection). |
| `label`, `env`, `is_management`, `org_id`, `notes` | no | Copied into the envelope's `accounts[]` entry for context. `env` ∈ `prod|non-prod|shared|sandbox|unknown`. |

## Auth model

- Default: the caller's ambient credentials (env vars / instance role / SSO) must be able to
  `sts:AssumeRole` into each account's `role_arn`. This mirrors a typical cross-account
  `TransilienceComplianceRole` estate model.
- If `profile` is given, that local profile is used directly (handy for single-account runs).
- If an account cannot be assumed, the run does **not** fail — a `Gap` record is emitted for
  that account and the sweep continues.

## Required read permissions on the assumed role

`ec2:Describe*`, `rds:Describe*`, `ecr:Describe*`/`GetRepositoryPolicy`,
`lambda:ListFunctions`/`GetFunctionUrlConfig`/`GetPolicy`,
`apigateway:GET`/`apigatewayv2:Get*`, `redshift:DescribeClusters`,
`docdb:DescribeDBInstances`, `elasticache:DescribeCacheClusters`,
`elasticloadbalancing:DescribeLoadBalancers`, `wafv2:List*`, `cloudfront:ListDistributions`.
Any denial is captured as a `Gap` (with the exact CLI to re-run), never a crash.
