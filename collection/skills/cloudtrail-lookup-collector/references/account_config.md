# Lookup Collector Account Config

`accounts.json` is an array:

```json
[
  {
    "account_id": "123456789012",
    "role_arn": "arn:aws:iam::123456789012:role/SecurityReadOnly",
    "profile": "source-profile"
  }
]
```

Fields:

- `account_id`: required for reporting. If omitted, the collector uses the account ID parsed from `role_arn` when possible.
- `role_arn`: optional. If present, the collector assumes it before calling CloudTrail.
- `profile`: optional local AWS profile to use before assuming the role.
- `external_id`: optional STS external ID.

If `role_arn` is omitted, the current boto3 session is used directly.
