---
name: aws-cloudtrail-business-triage
description: Convert AWS CloudTrail event clusters, baselines, detection candidates, or evidence packs into business-context triage findings. Use when explaining what happened, why it likely happened, whether it looks like business-as-usual, what residual risk remains, what to verify, and what controls to remediate for CloudTrail investigations.
---

# AWS CloudTrail Business Triage

Use this skill when the raw events are known but the customer needs the operational interpretation.

## Quick Start

```bash
python3 ../../skills/aws/cloudtrail/business-triage/scripts/triage_cloudtrail_findings.py \
  --evidence-pack evidence_pack \
  --baseline baseline.json \
  --detection-specs cloudtrail_detection_specs.json \
  --output triage_findings.md
```

## Triage Structure

For each finding, produce:

- what happened
- why it likely happened
- evidence summary
- business-as-usual assessment
- residual risk
- verification steps
- remediation actions
- alerting implication

## Rules

- Separate probable legitimate activity from residual control risk.
- Do not call activity benign solely because it repeats.
- Treat root, audit-log deletion, IAM privilege creation, access-key creation, and destructive resource changes as requiring verification even when likely authorized.
- Prefer named business patterns: CI/CD rotation, break-glass root use, contractor Terraform, CloudShell admin sweep, decommission cleanup.
- Tie every high-confidence statement to evidence fields: actor, account, event names, source IPs, user agent, MFA, cadence, resource names.
