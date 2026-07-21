# Use Case 04 — Detection Spec Export for SIEM Import

Turn a CloudTrail business baseline into portable, SIEM-agnostic detection specifications that a security engineer can translate into QRadar AQL, Splunk SPL, Sigma rules, or any other query language.

## When to use this

- You have a baseline and want to generate the initial detection rule set without manually authoring every alert.
- You are onboarding a new AWS environment and need a first-draft detection library before the first alert fires.
- You want a vendor-neutral detection spec to review with a client before committing to a specific SIEM syntax.

## Prerequisites

A `baseline.json` produced by `business-baseline`. You do not need live AWS access for this step.

## Step 1 — Generate detection specs from the baseline

```bash
python3 .claude/skills/detection-specs/scripts/generate_detection_specs.py \
  --baseline outputs/baseline.json \
  --output outputs/detection_specs.json
```

## What is generated

`generate_detection_specs.py` reads the baseline's alert candidates, critical-event list, and actor/account tuple set and emits one spec per detection category. A 30-day baseline over a typical AWS environment produces 8–12 specs covering:

| Spec | Severity | Family |
|---|---|---|
| Root console or API activity | critical | user_access |
| CreateAccessKey outside designated rotation | critical | identity_privilege_management |
| IAM role or policy writes from unmanaged egress | critical | identity_privilege_management |
| Account password policy change outside pipeline | high | identity_privilege_management |
| S3 DeleteBucket burst or audit bucket deletion | critical | data_access_storage |
| CloudTrail / FlowLogs / Config tamper | critical | governance_security_visibility |
| Network exposure change by named or unusual actor | high | network_security_changes |
| Destructive database control-plane action | critical | database_operations |
| KMS key or grant change by unusual actor | high | data_access_storage |
| Account/actor/event/IP tuple drift | medium | other_control_plane |

## Spec schema

Each spec in `detection_specs.json` follows this structure:

```json
{
  "spec_id": "cloudtrail-root-activity",
  "title": "Root Console or API Activity",
  "severity": "critical",
  "family": "user_access",
  "description": "Detect any root console login or root API use.",
  "logic": {
    "event_names": ["ConsoleLogin"],
    "actor_types": ["root"],
    "conditions": ["actor == 'root'"]
  },
  "required_evidence": [
    "raw CloudTrail event",
    "break-glass ticket",
    "MFA device type",
    "post-login root activity"
  ],
  "baseline_context": {
    "observed_count": 0,
    "last_seen": null
  }
}
```

`baseline_context` is populated from the baseline when the spec is generated from a real baseline. It is empty when generated from a stub baseline.

## Translating specs to SIEM queries

### QRadar AQL example (root activity)

```sql
SELECT
  devicetime, username, sourceip, qid, category
FROM events
WHERE
  LOGSOURCETYPENAME(logsourceid) = 'Amazon AWS CloudTrail'
  AND username = 'root'
LAST 24 HOURS
```

### Splunk SPL example (CreateAccessKey)

```spl
index=cloudtrail eventName=CreateAccessKey
| where NOT match(userIdentity.arn, "rotation-role")
| table _time, userIdentity.arn, requestParameters.userName, sourceIPAddress
```

### Sigma example (IAM write from unmanaged egress)

```yaml
title: IAM Write from Unmanaged Egress IP
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|startswith:
      - 'Attach'
      - 'Put'
      - 'Create'
    eventSource: iam.amazonaws.com
  filter_known_cidrs:
    sourceIPAddress|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: selection and not filter_known_cidrs
falsepositives:
  - Approved IaC pipeline running from cloud build agent with dynamic IP
level: high
```

## Feeding specs into triage

The detection specs are also consumed by `business-triage` to score findings against the detection library:

```bash
python3 .claude/skills/business-triage/scripts/triage_cloudtrail_findings.py \
  --evidence-pack outputs/evidence_pack \
  --baseline outputs/baseline.json \
  --detection-specs outputs/detection_specs.json \
  --output outputs/triage.json
```

## Updating specs over time

Re-generate specs each time you rebuild the baseline. `baseline_context.observed_count` will update to reflect whether a previously-zero alert class now has baseline hits (normal: suppress or tune) or a previously-active class has dropped to zero (anomaly: investigate).

Store versioned spec files alongside versioned baselines:

```
outputs/detection-specs/2026-06-16/detection_specs.json
outputs/detection-specs/2026-07-01/detection_specs.json
```

Diff them to track detection library drift across the environment's lifecycle.
