# Git AI Risk Categories

Use these categories when triaging findings.

- `model_provider_usage`: Direct or indirect calls to foundation-model APIs.
- `agent_framework`: Agent orchestration frameworks, planning loops, tool routers, or autonomous workflows.
- `mcp_tooling`: MCP server/client definitions, tool exposure, local command bridges, or external service connectors.
- `prompt_surface`: System prompts, prompt templates, jailbreak tests, prompt injection fixtures, or user-provided prompt assembly.
- `rag_vector_store`: Embedding pipelines, vector databases, search indices, retrieval tools, and document chunking code.
- `training_eval_data`: Fine-tuning, eval harnesses, benchmark datasets, labeling files, or model comparison runs.
- `ai_supply_chain`: AI packages, model downloads, container images, GitHub Actions, package-manager installs, or model registry access.
- `secret_configuration`: Environment variable names or config keys for AI vendors, vector stores, tracing tools, or model gateways.
- `ci_cd_ai_usage`: AI code review, release-note generation, test generation, repo summarization, or build-time model calls.

Prioritize findings where AI usage overlaps with secrets, customer data, source code, production automation, broad tools, or unreviewed MCP servers.
