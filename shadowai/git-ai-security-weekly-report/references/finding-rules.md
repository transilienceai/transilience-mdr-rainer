# Git AI Finding Rules

## Severity

- `critical`: AI usage exposes secrets, source code, production credentials, customer data, broad MCP tools, or privileged CI/CD automation.
- `high`: Confirmed model/provider, agent, MCP, RAG, training, or eval usage without an approval marker or security controls.
- `medium`: Dependency or prompt/data evidence that suggests AI usage but lacks direct runtime wiring.
- `low`: Documentation, comments, weak naming, or keyword-only evidence.

## Priority Actions

- Identify owner and business purpose.
- Confirm whether the AI usage is approved.
- Verify secrets are managed centrally and not committed.
- Review prompt/data surfaces for customer, employee, credential, or source-code exposure.
- Review MCP servers and agent tools for command, filesystem, browser, network, and SaaS access.
- Add egress, logging, model gateway, or vendor controls where runtime usage is confirmed.
