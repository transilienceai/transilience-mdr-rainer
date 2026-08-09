# Confidence Levels

- `high`: Bedrock CloudTrail invocation, historical DNS/proxy join, service inventory confirmation, or gateway telemetry confirms the provider or AI service.
- `medium`: current DNS, reverse DNS, or endpoint catalog match points to a known AI provider, broker, vector service, observability service, or artifact source.
- `low`: internal private-IP port heuristic, package registry/model artifact source, or internal inference-style destination without workload inventory.
- `context`: cadence, bytes, packets, fanout, or timing evidence supports another finding but is not standalone proof.

Do not use flow logs alone to claim prompt content, exact SaaS model name, SDK/framework, user identity, or data exfiltration.
