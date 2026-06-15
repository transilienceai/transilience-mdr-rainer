---
name: aws-cloudtrail-report-packager
description: Package AWS CloudTrail baselines, evidence packs, detection specs, and business triage into customer-facing reports. Use when producing Markdown or PDF-ready reports that need executive summaries, finding cards, remediation roadmaps, evidence appendices, reproduction commands, or Transilience-style CloudTrail investigation and business-baseline documents.
---

# AWS CloudTrail Report Packager

Use this skill at the end of a CloudTrail analysis workflow.

## Quick Start

```bash
python3 ../../skills/aws/cloudtrail/report-packager/scripts/package_markdown_report.py \
  --customer "Customer" \
  --baseline baseline.json \
  --evidence-pack evidence_pack \
  --triage triage_findings.md \
  --detection-specs cloudtrail_detection_specs.json \
  --output cloudtrail_report.md
```

## Report Requirements

- Lead with business impact and residual risk.
- Include evidence volume and source coverage.
- Include a remediation roadmap with control owner language.
- Include an appendix that points to raw evidence and reproduction commands.
- Preserve uncertainty: “likely sanctioned,” “requires ticket verification,” and “not enough evidence” are valid conclusions.
- Do not paste large raw JSON into the report; link to the evidence files and include compact examples only.

## PDF

If the user asks for a PDF, produce Markdown first and then use an explicit public renderer or downstream documentation pipeline so the content remains reviewable.
