# Logging Requirements And Limitations

## Best Inputs

- VPC Flow Logs in CloudWatch, S3, or Security Lake with one-minute aggregation.
- Custom format including `vpc-id`, `subnet-id`, `instance-id`, `interface-id`, `srcaddr`, `dstaddr`, `srcport`, `dstport`, `pkt-srcaddr`, `pkt-dstaddr`, `protocol`, `bytes`, `packets`, `start`, `end`, `action`, `tcp-flags`, `flow-direction`, `traffic-path`, and `log-status`.
- Route 53 Resolver query logs for historical domain-to-IP joins.
- CloudTrail for Bedrock model IDs, IAM principals, and model invocation events.
- ECS, EKS, Batch, SageMaker, and EC2 metadata for source workload attribution.
- Proxy, SNI, gateway, or OpenTelemetry logs for URL paths, model IDs, user agents, prompts, token counts, and app spans.

## What Flow Logs Cannot Prove

- Actual prompt or response content.
- SaaS model name for OpenAI, Anthropic, Gemini, Perplexity, or similar providers.
- HTTP path, method, headers, SDK user-agent, or TLS SNI.
- Exact individual packet sizes or token-level streaming.
- LangChain versus raw SDK from network alone.
- Direct workload behind NAT unless original packet fields or correlation data are present.

## Confidence Rules

- Historical DNS plus flow timing is stronger provider attribution.
- Current DNS or PTR only is medium confidence.
- Internal port-only match is low confidence.
- NAT gateway source is egress evidence, not workload identity.
- CloudTrail Bedrock `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, or `ConverseStream` with `modelId` is high-confidence Bedrock runtime evidence.
