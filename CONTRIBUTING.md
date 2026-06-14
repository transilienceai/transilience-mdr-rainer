# Contributing to Transilience MDR Rainer

Contributions are welcome for MDR skills, examples, documentation, and test coverage.

## Code of Conduct

Be respectful, professional, and focused on useful security operations outcomes. Do not publish another party's private information, customer evidence, credentials, or sensitive logs.

## Ways to Contribute

- Fix bugs in existing skills or scripts.
- Improve documentation and examples.
- Add synthetic test cases.
- Propose new MDR skills for AWS, Azure, Google Cloud, SIEM, evidence packaging, or reporting.
- Improve detection logic, schemas, or report structure.

## Development Workflow

1. Create an issue first using the relevant GitHub issue template.
2. Create a branch from `main`.
3. Make focused changes.
4. Run validation.
5. Open a PR linked to the issue.

Branch naming:

- `feature/description`
- `bugfix/description`
- `docs/description`
- `enhancement/description`

Commit format:

```text
<type>(scope): <description>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.

## Skill Requirements

Every skill must include:

- `SKILL.md` with YAML frontmatter containing `name` and `description`.
- Clear inputs, outputs, and workflow expectations.
- References or examples when the workflow is non-trivial.
- No customer-specific identifiers, real account IDs, raw evidence, credentials, or private paths.

Public examples must be synthetic or safely anonymized.

## Validation

Run these before opening a PR:

```bash
python3 -m py_compile skills/aws/cloudtrail/*/scripts/*.py
python3 scripts/skill_linter.py
cd projects/aws-mdr && bash examples/run_smoke.sh
```

## Pull Requests

PRs should include:

- A short summary.
- A linked issue with `Closes #N`.
- Test results.
- Documentation updates for changed commands, schemas, or outputs.
- Confirmation that no secrets or customer data are included.

## Licensing

By contributing, you agree that your contribution is licensed under the repository's MIT License.
