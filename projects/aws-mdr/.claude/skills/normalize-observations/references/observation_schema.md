# Normalized CloudTrail Observation Schema

Each line is a JSON object.

Required fields:

- `event_id`: CloudTrail event ID when present.
- `event_time`: UTC ISO timestamp string.
- `account_id`: 12-digit AWS account ID when known.
- `region`: CloudTrail lookup or event region.
- `event_name`: AWS API/event name.
- `event_source`: AWS service source, for example `iam.amazonaws.com`.
- `actor`: human-readable principal, role, user, or `root`.
- `actor_type`: one of `root`, `iam_user`, `assumed_role`, `sso_role`, `aws_service_role`, `service_principal`, `unknown`.
- `source_ip`: CloudTrail `sourceIPAddress`.
- `user_agent`: CloudTrail user agent string.
- `resources`: list of resource names/ARNs.
- `error_code`: CloudTrail error code or empty string.
- `risk`: `critical`, `high`, `medium`, or `low`.
- `business_risk_category`: one of `credential_or_privilege_risk`, `defense_evasion`, `data_exposure`, `data_loss_or_outage`, `internet_exposure`, `unauthorized_infrastructure`, `operational_change_risk`.
- `pattern_category`: `deployment`, `access`, `change`, `maintenance`, or `other`.

Optional fields:

- `raw_source`: input path or collection source.
- `collection_call_id`: lookup/file call ID from an evidence pack.
- `recipient_account_id`: CloudTrail recipient account when different from `account_id`.
