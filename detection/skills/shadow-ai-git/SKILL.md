---
name: shadow-ai-git
description: Detect and triage shadow AI usage from Git repositories and source trees, including model/provider SDKs, agent frameworks, MCP configs, prompts, RAG/vector stores, eval or training artifacts, CI/CD AI usage, AI supply-chain dependencies, and secret-name indicators. Use when Codex needs to catalog AI usage from code, dependency manifests, lockfiles, GitHub Actions, Dockerfiles, prompt files, or repository configuration.
---

# Git Shadow AI Detection

Use this skill to identify AI usage and AI-adjacent risk from source repositories.

## Workflow

1. Start from one checked-out repo, a directory containing multiple repos, or a text file of repo paths.
2. Run `scripts/analyze_git_shadow_ai.py --input <repo-or-folder> --output-dir <analysis>`.
3. For multiple explicit paths, use `--repo-list <paths.txt>` instead of `--input`.
4. Review confidence before making claims:
   - `confirmed_code_usage`: direct import, API call, MCP config, model ID, provider client, or runtime configuration.
   - `dependency_signal`: package, lockfile, image, or build dependency without direct usage.
   - `prompt_or_data_signal`: prompt, eval, training, dataset, or benchmark artifact.
   - `ci_cd_signal`: AI provider, AI tool, or AI dependency in build or workflow automation.
   - `keyword_only`: weak naming, docs, or comments signal; validate manually.
5. Hand the output directory to `git-security-report` for consolidated reporting.

## Evidence Interpretation

- Treat code/config evidence as stronger than dependency-only evidence.
- Treat MCP server definitions as tool-exposure evidence even when no model call is present.
- Treat prompts, evals, and datasets as data-governance evidence, not proof of runtime usage by themselves.
- Treat CI/CD AI evidence as a separate operational risk because code, secrets, build logs, and artifacts may be exposed.
- Use `references/ai-code-patterns.yaml` for match classes, `references/evidence-confidence.md` for scoring, and `references/git-ai-risk-categories.md` for review categories.

## Outputs

The analyzer writes:

- `git_shadow_ai_summary.json`
- `git_shadow_ai_findings.csv`
- `git_ai_dependencies.csv`
- `git_ai_prompts.csv`
- `git_ai_mcp_findings.csv`
- `git_ai_rag_findings.csv`

Keep source repositories and customer evidence separate from reusable skill fixtures.
