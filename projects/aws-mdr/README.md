# AWS MDR Project

This project exposes the AWS CloudTrail MDR skills for local use. The `.claude/skills` directory contains real skill files so the project works immediately after cloning.

## Workflow

1. Collect live CloudTrail management events with `lookup-collector`, or place existing CloudTrail JSON in `examples/` or a local input directory.
2. Normalize records into JSONL observations.
3. Package raw evidence separately from analysis views.
4. Build a business baseline.
5. Generate portable detection specs.
6. Produce business-context triage.
7. Package the final Markdown report.

## Synthetic Smoke Test

```bash
bash examples/run_smoke.sh
```

Outputs are written under `outputs/` and are intentionally ignored by git.
