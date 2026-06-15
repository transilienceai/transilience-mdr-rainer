# Transilience MDR Rainer

<div align="center">

[![Built by Transilience](https://img.shields.io/badge/Built%20by-Transilience.ai-4A90D9)](https://www.transilience.ai)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![AWS](https://img.shields.io/badge/Cloud-AWS-orange)](https://aws.amazon.com/)
[![Claude AI](https://img.shields.io/badge/Powered%20by-Claude%20AI-blue)](https://claude.ai)

**Open-source Claude Code skills for authorized MDR, AWS CloudTrail investigation, detection engineering, and security operations reporting.**

[Quick Start](#quick-start) | [Skills](#skills) | [Architecture](#architecture) | [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md)

</div>

---

## Overview

Transilience MDR Rainer is a skills-first MDR toolkit. The initial release focuses on AWS CloudTrail workflows:

- Collect reproducible CloudTrail management events.
- Normalize CloudTrail-shaped records into stable observations.
- Preserve raw evidence separately from analysis views.
- Build business-as-usual baselines.
- Generate backend-neutral detection specs.
- Triage findings with business context and residual risk.
- Package Markdown reports for review.

The repository follows the same general architecture as `transilienceai/communitytools`: reusable skill source lives at the repo root under `skills/`, and runnable projects under `projects/` include the skill files they need directly so a plain clone works immediately.

## Prerequisites

- Python 3.11+ recommended.
- Claude Code for skill-driven workflows.
- AWS credentials only when running live collection.
- `boto3` and `botocore` for `lookup-collector`.

## Quick Start

```bash
git clone https://github.com/transilienceai/transilience-mdr-rainer.git
cd transilience-mdr-rainer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd projects/aws-mdr
```

Run the synthetic smoke workflow:

```bash
bash examples/run_smoke.sh
```

Outputs are written under `projects/aws-mdr/outputs/` and ignored by git.

## Skills

Reusable skill definitions live at `skills/`. The `projects/aws-mdr/.claude/skills/` directory contains real copied skill files for direct project use after cloning.

| Skill | Purpose |
|-------|---------|
| `skills/aws/cloudtrail/lookup-collector` | Collect CloudTrail management events with AWS-native credentials. |
| `skills/aws/cloudtrail/normalize-observations` | Normalize CloudTrail JSON, JSONL, LookupEvents, evidence-pack, and SIEM wrapper records. |
| `skills/aws/cloudtrail/raw-evidence-pack` | Package raw CloudTrail records with reproduction metadata. |
| `skills/aws/cloudtrail/business-baseline` | Build business-as-usual baselines from normalized observations. |
| `skills/aws/cloudtrail/detection-specs` | Generate backend-neutral detection specifications. |
| `skills/aws/cloudtrail/business-triage` | Convert evidence and detections into business-context findings. |
| `skills/aws/cloudtrail/report-packager` | Assemble Markdown reports from baseline, evidence, triage, and detection artifacts. |

See [skills/INDEX.md](skills/INDEX.md) for routing guidance.

## AWS Credentials

The public version uses AWS-native credential handling only:

- Ambient boto3 credentials.
- Named AWS profiles.
- Explicit `role_arn` entries in an accounts JSON file.

No customer-specific brokers, secrets, or private account configurations are included.

## Architecture

```text
transilience-mdr-rainer/
├── .claude-plugin/                  # Plugin and marketplace metadata
├── .github/                         # Issue templates, PR template, CI
├── CLAUDE.md                        # Repository operating instructions
├── CONTRIBUTING.md                  # Contribution workflow
├── SECURITY.md                      # Private vulnerability reporting
├── docs/                            # Longer documentation
├── formats/                         # Future shared report formats
├── scripts/                         # Repo maintenance and linting scripts
├── skills/                          # Canonical skill definitions
│   └── aws/cloudtrail/
│       ├── lookup-collector/
│       ├── normalize-observations/
│       ├── raw-evidence-pack/
│       ├── business-baseline/
│       ├── detection-specs/
│       ├── business-triage/
│       └── report-packager/
├── tools/                           # Future shared utilities
└── projects/
    └── aws-mdr/
        ├── .claude/skills/          # Real skill copies for direct clone usage
        ├── examples/                # Synthetic test inputs
        └── outputs/                 # Runtime outputs, ignored except README
```

## Development Checks

```bash
python3 -m py_compile skills/aws/cloudtrail/*/scripts/*.py
python3 scripts/skill_linter.py
cd projects/aws-mdr && bash examples/run_smoke.sh
```

## Tags

`aws`, `cloudtrail`, `mdr`, `soc`, `detection-engineering`, `incident-response`, `security-operations`, `claude-code`

## Security and Legal

These skills are for authorized MDR, detection engineering, and incident response. Do not collect or analyze cloud telemetry unless you have permission. Never commit customer evidence, credentials, real account inventories, or sensitive logs.
