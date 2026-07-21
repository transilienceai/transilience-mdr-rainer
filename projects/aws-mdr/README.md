# AWS MDR Project

This project exposes the AWS CloudTrail MDR skills for local use. The `.claude/skills` directory contains real skill files so the project works immediately after cloning.

## Workflow

1. Collect live CloudTrail management events with `lookup-collector`, or place existing CloudTrail JSON in `examples/` or a local input directory.
2. Normalize records into JSONL observations. If data is already pre-flattened (from a SIEM or third-party exporter), use `adapt_preflattened.py` inside `normalize-observations/scripts/` instead.
3. Package raw evidence separately from analysis views (live or raw CloudTrail format only; skip for pre-flattened data).
4. Build a business baseline.
5. Generate portable detection specs.
6. Produce business-context triage.
7. Package the final Markdown report.

## Use Cases

See `use-cases/` for step-by-step guides for common deployment scenarios:

| # | Use Case |
|---|---|
| 01 | [Live LookupEvents — full pipeline](use-cases/01-live-lookup-full-pipeline/README.md) |
| 02 | [Pre-flattened exports from SIEMs or third-party collectors](use-cases/02-preflattened-exports/README.md) |
| 03 | [Multi-account business baseline](use-cases/03-multi-account-baseline/README.md) |
| 04 | [Detection spec export for SIEM import](use-cases/04-detection-spec-export/README.md) |

## Synthetic Smoke Test

```bash
bash examples/run_smoke.sh
```

Outputs are written under `outputs/` and are intentionally ignored by git.
