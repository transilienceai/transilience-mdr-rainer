# Evidence Confidence

Use confidence labels consistently so reports do not overstate weak evidence.

## Levels

- `confirmed_code_usage`: Direct source evidence such as imports, constructors, API calls, model IDs, provider clients, MCP server configuration, vector-store setup, or runtime environment wiring.
- `dependency_signal`: Dependency manifests, lockfiles, package installs, Docker images, or build scripts mention AI libraries or provider SDKs, but usage was not found.
- `prompt_or_data_signal`: Prompt templates, eval files, fine-tuning data, datasets, benchmark fixtures, or model cards exist in the repo.
- `ci_cd_signal`: AI tools, providers, API-key names, or AI dependencies appear in CI/CD workflows, release automation, code review bots, or build jobs.
- `keyword_only`: A weak match from documentation, comments, names, or generic words. Validate before treating it as AI usage.

## Review Rules

- Prefer the strongest confidence found for the same repo, path, and component.
- Redact values for keys, tokens, URLs with embedded credentials, and long bearer-like strings.
- Record the reason in plain language: what matched, why it matters, and what evidence would raise or lower confidence.
- Do not infer exact SaaS model names unless the repo contains explicit model IDs or configuration.
