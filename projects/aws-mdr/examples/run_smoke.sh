#!/usr/bin/env bash
set -euo pipefail

mkdir -p outputs

python ../../skills/aws/cloudtrail/normalize-observations/scripts/normalize_cloudtrail.py \
  --input examples/cloudtrail.sample.json \
  --output outputs/normalized_observations.jsonl

python ../../skills/aws/cloudtrail/raw-evidence-pack/scripts/package_raw_evidence.py \
  --input examples/cloudtrail.sample.json \
  --output outputs/evidence_pack \
  --case-config examples/cases.example.json

python ../../skills/aws/cloudtrail/business-baseline/scripts/build_business_baseline.py \
  --observations outputs/normalized_observations.jsonl \
  --output outputs/baseline.json \
  --customer "Example"

python ../../skills/aws/cloudtrail/detection-specs/scripts/generate_detection_specs.py \
  --baseline outputs/baseline.json \
  --output outputs/cloudtrail_detection_specs.json

python ../../skills/aws/cloudtrail/business-triage/scripts/triage_cloudtrail_findings.py \
  --evidence-pack outputs/evidence_pack \
  --baseline outputs/baseline.json \
  --detection-specs outputs/cloudtrail_detection_specs.json \
  --output outputs/triage_findings.md

python ../../skills/aws/cloudtrail/report-packager/scripts/package_markdown_report.py \
  --customer "Example" \
  --baseline outputs/baseline.json \
  --evidence-pack outputs/evidence_pack \
  --triage outputs/triage_findings.md \
  --detection-specs outputs/cloudtrail_detection_specs.json \
  --output outputs/cloudtrail_report.md

echo "Smoke workflow complete: projects/aws-mdr/outputs/cloudtrail_report.md"
