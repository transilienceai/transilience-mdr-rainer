# AWS MDR Project

This project exposes AWS CloudTrail MDR skills through real files under `.claude/skills`.

## Workflow

Use the smallest skill set needed:

- `lookup-collector` for live CloudTrail LookupEvents collection.
- `normalize-observations` for CloudTrail-shaped input normalization.
- `raw-evidence-pack` for reproducible raw evidence bundles.
- `business-baseline` for business-as-usual context.
- `detection-specs` for portable alert logic.
- `business-triage` for operational interpretation.
- `report-packager` for Markdown report assembly.

## Safety

Only run live AWS collection with authorization. Do not place real customer evidence, credentials, or generated outputs in git-tracked paths.
