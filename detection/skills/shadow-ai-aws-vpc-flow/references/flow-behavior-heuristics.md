# Flow Behavior Heuristics

VPC Flow Logs expose aggregate records, not payloads or exact packet sequences. Use `bytes`, `packets`, `start`, `end`, ports, flow count, destination category, and timing to infer behavior.

## Derived Features

- `avg_packet_size = bytes / packets`
- `duration_seconds = end - start`
- `bytes_per_second = bytes / max(duration, 1)`
- `connection_rate = flows per source per minute`
- `burstiness = variance of bytes/packets per time bucket`
- `fanout = unique destination count per source/window`
- `alternation_score = count of category transitions involving LLM <-> tool/vector/search/SaaS`

## Behavior Patterns

| Pattern | Flow Shape | Confidence Notes |
|---|---|---|
| Chat completion | moderate request/response size, short-medium duration, user-traffic aligned | Exact model unavailable from flows |
| Streaming chat | longer HTTPS duration, many packets, sustained traffic | Needs app/proxy logs for confirmation |
| Embeddings | many repetitive short flows, outbound-heavy, followed by vector writes | Stronger with vector DB co-occurrence |
| Reranking | vector query, medium outbound docs, smaller response, then LLM call | Sequence matters |
| RAG indexing | S3/doc reads, embedding bursts, vector DB upserts, scheduled batch | High-value detector |
| Query-time RAG | inbound app request, vector query, LLM call, app response | Needs timing correlation |
| Agent workflow | repeated LLM calls interleaved with search/SaaS/internal APIs, high fanout | Use alternation score |
| Eval harness | many similar calls, multiple providers, observability/eval backends | Often off-hours or batch |
| Local inference | model download, GPU/internal inference node, callers to `8000`, `8080`, `11434`, or Triton ports | Needs compute inventory |
| Heartbeat | tiny fixed-interval flows, low byte variance, no data-store correlation | Avoid false positives |

## Scoring Guidance

- `+50` direct known model-provider destination.
- `+40` Bedrock invocation correlated with CloudTrail model ID.
- `+35` vector DB or confirmed internal vector/data destination.
- `+30` LLM observability or eval backend.
- `+25` LLM plus search/tool/SaaS destinations in one window.
- `+20` large model artifact download.
- `+20` first-seen AI destination or approved-gateway bypass.
- `+15` high fanout with LLM traffic or agent-like alternation.
- `-30` approved AI workload tag.
- `-20` approved AI gateway path.

Return evidence with the score. Never return only the score.
