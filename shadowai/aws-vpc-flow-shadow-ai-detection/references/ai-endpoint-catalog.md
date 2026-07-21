# AI Endpoint Catalog

Use this catalog to tag destinations after DNS, reverse-DNS, proxy, Resolver-log, or service-inventory enrichment. Prefer historical DNS answers over current DNS. Current DNS is useful but normally medium-confidence because SaaS IPs change.

## Foundation Model Providers

| Provider | Domains / Services | Category |
|---|---|---|
| OpenAI | `api.openai.com` | `foundation_model_provider` |
| Anthropic | `api.anthropic.com` | `foundation_model_provider` |
| Google Gemini / Vertex | `generativelanguage.googleapis.com`, `aiplatform.googleapis.com` | `foundation_model_provider` |
| Cohere | `api.cohere.ai` | `foundation_model_provider` |
| Mistral | `api.mistral.ai` | `foundation_model_provider` |
| Together | `api.together.xyz` | `foundation_model_provider` |
| Groq | `api.groq.com` | `foundation_model_provider` |
| Fireworks | `api.fireworks.ai` | `foundation_model_provider` |
| Perplexity | `api.perplexity.ai` | `foundation_model_provider` |
| DeepSeek | `api.deepseek.com` | `foundation_model_provider` |
| Voyage | `api.voyageai.com` | `embedding_reranking_provider` |
| Jina | `api.jina.ai` | `embedding_reranking_provider` |
| Replicate | `api.replicate.com` | `model_provider` |
| Hugging Face | `huggingface.co`, `api-inference.huggingface.co` | `model_provider_or_registry` |

## Brokers, Gateways, Observability

| Tool | Domains | Category |
|---|---|---|
| OpenRouter | `openrouter.ai` | `model_broker` |
| Helicone | `api.helicone.ai`, `helicone.ai` | `llm_observability_or_gateway` |
| LangSmith | `api.smith.langchain.com`, `api.langchain.com` | `llm_observability` |
| Langfuse | `cloud.langfuse.com` | `llm_observability` |
| Braintrust | `api.braintrust.dev`, `braintrust.dev` | `eval_observability` |
| Weights & Biases | `api.wandb.ai`, `wandb.ai` | `ml_observability` |

## RAG / Vector / Data

| Service | Domains / Ports | Category |
|---|---|---|
| Pinecone | `*.pinecone.io` | `vector_database` |
| Qdrant Cloud | `*.qdrant.io`, `*.qdrant.tech`; internal ports `6333`, `6334` | `vector_database` |
| Weaviate | `*.weaviate.cloud`, `*.weaviate.network`; internal `8080` if confirmed | `vector_database` |
| Zilliz / Milvus | `*.zillizcloud.com`; internal `19530` | `vector_database` |
| Postgres pgvector | internal `5432` with app/config confirmation | `internal_vector_or_database` |
| Redis vector capable | internal `6379` with app/config confirmation | `internal_vector_or_database` |
| OpenSearch vector capable | internal `9200` or AWS OpenSearch endpoints | `internal_vector_or_database` |

## Package / Model Artifact Sources

Use these as supporting evidence, not standalone proof of AI runtime use: `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `docker.io`, `ghcr.io`, `github.com`, `objects.githubusercontent.com`, `huggingface.co`, S3 model buckets, and ECR image pulls.
