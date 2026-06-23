# AWS MDR Use Cases

Real-world patterns for running the seven AWS CloudTrail MDR skills together. Each use case is a self-contained directory with a walkthrough and runnable commands.

## Index

| # | Use Case | Entry point |
|---|---|---|
| 01 | [Live LookupEvents — full pipeline](01-live-lookup-full-pipeline/README.md) | Start here when you have live AWS access |
| 02 | [Pre-flattened exports from SIEMs or third-party collectors](02-preflattened-exports/README.md) | When CloudTrail is already exported and flattened |
| 03 | [Multi-account business baseline](03-multi-account-baseline/README.md) | Building a BAU baseline across many accounts |
| 04 | [Detection spec export for SIEM import](04-detection-spec-export/README.md) | Turn a baseline into portable detection logic |

## Skill dependency map

```
lookup-collector (live AWS) ──┐
                               ├──► normalize-observations ──► business-baseline ──► detection-specs
pre-flattened adapter  ────────┘                                       │
                                                                        └──► business-triage ──► report-packager
raw-evidence-pack (live AWS or raw CT JSON) ─────────────────────────────────► report-packager
```

## Common pitfalls

- **`normalize-observations` needs raw CloudTrail format**, not pre-flattened rows. If your input already has `event_name` / `username` flat fields (from a SIEM or a third-party exporter), use the adapter in use case 02.
- **`raw-evidence-pack` also needs raw CloudTrail** (`CloudTrailEvent` wrapper or `eventVersion` fields). It is designed for live `lookup-collector` output and raw S3 log JSON. Skip it or wire the adapter output when working with pre-flattened data.
- **`report-packager --output` must be a file path**, not a directory. Example: `--output reports/cloudtrail_report.md`.
- Run `pip install -r requirements.txt` once from the repo root before running any script.
