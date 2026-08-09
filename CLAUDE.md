# Cloud Detection Repository

Open-source Claude Code skills for authorized MDR, AWS CloudTrail investigation, detection engineering, and reporting.

## Repository Structure

Skills are grouped by lifecycle stage; each stage is a Claude Code plugin in `.claude-plugin/marketplace.json`.

- `detection/skills/` - Continuous detection & posture (CloudTrail baseline + detection specs; shadow-AI for AWS VPC Flow, Git, Google Workspace).
- `chaining/skills/` - Proactive attack-path chaining (collect exposure/identity/crown-jewel graph, merge, enumerate scored kill chains to crown jewels, correlate live threats, package red-team reports). Keep the 8 skills co-located: the shared primitive KB resolves by sibling path.
- `investigation/skills/` - Later-moment / post-incident examination (CloudTrail evidence packaging + triage; home for the AWS IR/forensics suite).
- `collection/skills/` - Shared collectors/exporters that feed detection and investigation.
- `reporting/skills/` - Cross-cutting report packagers.
- `projects/aws-mdr/` - Runnable end-to-end CloudTrail MDR demo; its `.claude/skills/` symlink into the canonical category skills.
- `blogs/` - Long-form writeups.
- `scripts/` - Repository validation and maintenance scripts.
- `.claude-plugin/` - Marketplace metadata (one plugin per category).
- `.github/` - Issue templates, PR template, and CI.

## Skill Selection

1. Pick the category for the task: `detection/`, `investigation/`, `collection/`, or `reporting/`.
2. Review that category's `skills/` and select the smallest set needed.
3. Read each selected skill's `SKILL.md`.
4. For a local end-to-end smoke test, use `projects/aws-mdr/examples/run_smoke.sh`.

## Data Handling Rules

- Never commit customer evidence, raw CloudTrail exports, generated reports, credentials, tokens, real account inventories, screenshots, or private configs.
- Keep examples synthetic.
- Keep public credential guidance AWS-native: boto3 ambient credentials, named profiles, and explicit role ARNs.
- Preserve raw evidence separately from normalized observations.

## Validation

```bash
python3 -m py_compile {detection,investigation,collection,reporting}/skills/*/scripts/*.py
python3 scripts/skill_linter.py
cd projects/aws-mdr && bash examples/run_smoke.sh
```

## Git Conventions

- Branches: `feature/name`, `bugfix/name`, `docs/name`, `enhancement/name`.
- Commits: `type(scope): description`.
- Pull requests must link an issue with `Closes #N`.
