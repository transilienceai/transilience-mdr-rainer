---
name: aws-vpc-flow-shadow-ai-detection
description: Detect and triage shadow AI usage from AWS VPC Flow Logs, including model-provider egress, Bedrock-adjacent runtime evidence, RAG/vector traffic, model downloads, internal inference services, model brokers, LLM observability, and agent-like timing or fanout patterns. Use when Codex needs to analyze CloudWatch VPC Flow Logs or normalized flow CSV exports for AI usage from network metadata.
---

# AWS VPC Flow Shadow AI Detection

Use this skill to turn VPC Flow Logs into AI-usage evidence.

## Workflow

1. Confirm the log source, AWS account/region, time window, and whether the input is CloudWatch Logs or an offline CSV export.
2. Run `scripts/analyze_vpc_flow_shadow_ai.py` with either `--log-group` or `--input-csv`.
3. Review confidence levels before making claims:
   - `high`: Bedrock CloudTrail model invocation or trusted historical DNS/proxy/service-inventory join.
   - `medium`: current DNS, PTR, or endpoint catalog match to known AI infrastructure.
   - `low`: internal port or private-IP heuristic without workload inventory.
   - `context`: supporting cadence, bytes, packet, registry, or fanout evidence.
4. Review NAT and workload-attribution limitations before naming a source workload.
5. Hand the output directory to `aws-vpc-flow-ai-security-report` for reporting.

## Evidence Interpretation

- Treat public SaaS endpoint matches as provider-path evidence, not proof of exact model name.
- Treat internal Qdrant, Redis, Postgres, OpenSearch, Ollama, vLLM, and Triton-style ports as low-confidence until inventory confirms purpose.
- Treat NAT gateway rows as egress evidence unless packet source fields or inventory preserve the original workload.
- Use CloudTrail or gateway logs for Bedrock model IDs and exact API actions.
- Use Route 53 Resolver, proxy, SNI, gateway, or OpenTelemetry logs to raise confidence beyond current DNS/PTR matching.

## Outputs

The analyzer writes:

- `flow-summary.csv`
- `ai-candidate-flows.csv`
- `workload-ai-summary.csv`
- `hourly-top-destinations.csv`
- `ai-domain-resolution.csv`
- `bedrock-cloudtrail-events.json`
- `raw-query-manifest.json`

Keep customer raw logs and generated reports out of public repositories.
