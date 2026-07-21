# VPC Flow AI Finding Rules

## Severity

- `critical`: High-confidence AI traffic from production or sensitive-data workloads, direct approved-gateway bypass, confirmed Bedrock model invocation with broad IAM, or high-volume outbound flow to unapproved provider.
- `high`: Medium-confidence foundation-model provider, model broker, vector DB, or LLM observability traffic from a named workload.
- `medium`: Low-confidence internal inference/vector ports, model artifact downloads, package registries, or unattributed NAT egress.
- `low`: Context-only cadence, heartbeat, or weak port evidence without AI endpoint or inventory support.

## Priority Actions

- Identify source workload and owner.
- Confirm whether AI usage is approved.
- Join Route 53 Resolver, proxy, SNI, gateway, CloudTrail, and workload inventory.
- Validate data systems reached by the same source.
- Review egress path, secrets, IAM policy, logging, and model gateway coverage.
- Add approved workload/provider/model/vector-store inventory where usage is legitimate.
