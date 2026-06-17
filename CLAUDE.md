# Transilience MDR Rainer Repository

Open-source Claude Code skills for authorized MDR, AWS CloudTrail investigation, detection engineering, and reporting.

## Repository Structure

- `projects/` - Runnable Claude Code project environments.
- `projects/aws-mdr/.claude/skills/` - Canonical AWS CloudTrail skill definitions for direct clone usage.
- `scripts/` - Repository validation and maintenance scripts.
- `.claude-plugin/` - Plugin and marketplace metadata.
- `.github/` - Issue templates, PR template, and CI.

## Skill Selection

1. Review `projects/aws-mdr/.claude/skills/`.
2. Select the smallest set of skills needed for the task.
3. Read each selected skill's `SKILL.md`.
4. For local smoke testing, use `projects/aws-mdr/examples/run_smoke.sh`.

## Data Handling Rules

- Never commit customer evidence, raw CloudTrail exports, generated reports, credentials, tokens, real account inventories, screenshots, or private configs.
- Keep examples synthetic.
- Keep public credential guidance AWS-native: boto3 ambient credentials, named profiles, and explicit role ARNs.
- Preserve raw evidence separately from normalized observations.

## Validation

```bash
python3 -m py_compile projects/aws-mdr/.claude/skills/*/scripts/*.py
python3 scripts/skill_linter.py
cd projects/aws-mdr && bash examples/run_smoke.sh
```

## Git Conventions

- Branches: `feature/name`, `bugfix/name`, `docs/name`, `enhancement/name`.
- Commits: `type(scope): description`.
- Pull requests must link an issue with `Closes #N`.
