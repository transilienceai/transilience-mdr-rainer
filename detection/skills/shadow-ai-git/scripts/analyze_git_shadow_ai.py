#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".cs",
    ".css",
    ".env",
    ".go",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".lock",
    ".md",
    ".mjs",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

MAX_FILE_BYTES = 1_500_000
SNIPPET_LIMIT = 260

PATTERNS = [
    ("model_provider_usage", "openai", r"\b(openai|chatgpt|gpt-4|gpt-4o|gpt-5)\b"),
    ("model_provider_usage", "anthropic", r"\b(anthropic|claude|claude-3|claude-4)\b"),
    ("model_provider_usage", "google_gemini_vertex", r"\b(gemini|google-generativeai|generativelanguage|vertexai|aiplatform)\b"),
    ("model_provider_usage", "aws_bedrock", r"\b(bedrock-runtime|bedrock|InvokeModel|ConverseStream|Converse)\b"),
    ("model_provider_usage", "cohere", r"\b(cohere|command-r|rerank)\b"),
    ("model_provider_usage", "mistral", r"\b(mistral|mixtral)\b"),
    ("model_provider_usage", "groq", r"\b(groq)\b"),
    ("model_provider_usage", "hugging_face", r"\b(huggingface|hugging face|transformers|sentence-transformers|text-generation-inference)\b"),
    ("model_provider_usage", "replicate", r"\b(replicate)\b"),
    ("model_provider_usage", "together", r"\b(together\.ai|togetherai|together)\b"),
    ("model_provider_usage", "openrouter", r"\b(openrouter)\b"),
    ("model_provider_usage", "perplexity", r"\b(perplexity)\b"),
    ("agent_framework", "langchain", r"\b(langchain|langgraph|LangChain|LangGraph)\b"),
    ("agent_framework", "llama_index", r"\b(llama-index|llamaindex|LlamaIndex)\b"),
    ("agent_framework", "crewai", r"\b(crewai|CrewAI)\b"),
    ("agent_framework", "autogen", r"\b(autogen|AutoGen)\b"),
    ("agent_framework", "semantic_kernel", r"\b(semantic-kernel|SemanticKernel|Microsoft\.SemanticKernel)\b"),
    ("agent_framework", "haystack", r"\b(haystack)\b"),
    ("agent_framework", "dspy", r"\b(dspy)\b"),
    ("mcp_tooling", "mcp", r"\b(mcpServers|modelcontextprotocol|@modelcontextprotocol|mcp-server|mcp server)\b"),
    ("rag_vector_store", "pinecone", r"\b(pinecone)\b"),
    ("rag_vector_store", "qdrant", r"\b(qdrant)\b"),
    ("rag_vector_store", "weaviate", r"\b(weaviate)\b"),
    ("rag_vector_store", "chroma", r"\b(chroma|chromadb)\b"),
    ("rag_vector_store", "milvus_zilliz", r"\b(milvus|zilliz)\b"),
    ("rag_vector_store", "pgvector", r"\b(pgvector|vector\(.*\)|embedding)\b"),
    ("rag_vector_store", "opensearch_elastic", r"\b(opensearch|elasticsearch|knn_vector)\b"),
    ("rag_vector_store", "redis_vector", r"\b(redis.*vector|vector.*redis)\b"),
    ("prompt_surface", "prompt", r"\b(system[_-]?prompt|prompt_template|prompt template|jailbreak|prompt injection|few-shot|few shot)\b"),
    ("training_eval_data", "training_eval", r"\b(fine[-_ ]?tune|finetune|evals?|benchmark|golden dataset|labeling|training dataset)\b"),
    ("ai_supply_chain", "observability_eval", r"\b(langsmith|langfuse|helicone|braintrust|promptlayer|wandb|weights-and-biases|mlflow)\b"),
    ("secret_configuration", "secret_name", r"\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|COHERE_API_KEY|MISTRAL_API_KEY|PINECONE_API_KEY|QDRANT_API_KEY|LANGCHAIN_API_KEY|HF_TOKEN)\b"),
    ("ci_cd_ai_usage", "coding_assistant", r"\b(copilot|cursor|codeium|tabnine|aider|continue)\b"),
]

COMPILED = [(category, component, re.compile(pattern, re.IGNORECASE)) for category, component, pattern in PATTERNS]
DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Dockerfile",
}
PROMPT_HINT_RE = re.compile(r"(prompt|system|template|eval|jailbreak)", re.IGNORECASE)
WORKFLOW_RE = re.compile(r"(\.github[/\\]workflows|gitlab-ci|buildkite|circleci|jenkins)", re.IGNORECASE)
MCP_FILE_RE = re.compile(r"(^|[/\\.])mcp(\.|-|_|/|$)|mcpServers", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|bearer)\s*[:=]\s*['\"]?[^'\"\s,}]+")
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def redact(text: str) -> str:
    text = SECRET_VALUE_RE.sub(lambda match: re.sub(r"[:=]\s*['\"]?.*$", "=<redacted>", match.group(0)), text)
    return LONG_TOKEN_RE.sub("<redacted-token>", text)


def is_text_candidate(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.name in DEPENDENCY_FILES:
        return True
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    if path.name.startswith(".") and path.suffix.lower() in {".json", ".yaml", ".yml", ".env"}:
        return True
    return False


def discover_repos(input_path: Path | None, repo_list: Path | None) -> list[Path]:
    if repo_list:
        repos = [Path(line.strip()).expanduser().resolve() for line in repo_list.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]
        return [repo for repo in repos if repo.exists()]
    if not input_path:
        return []
    root = input_path.expanduser().resolve()
    if (root / ".git").is_dir():
        return [root]
    repos = [path.parent for path in root.rglob(".git") if path.is_dir()]
    return sorted(set(repos)) or [root]


def git_commit(repo: Path) -> str:
    try:
        result = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def iter_files(repo: Path) -> Iterable[Path]:
    for path in repo.rglob("*"):
        if path.is_file() and is_text_candidate(path):
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    yield path
            except OSError:
                continue


def confidence_for(path: Path, line: str, category: str) -> str:
    rel = str(path).lower()
    if WORKFLOW_RE.search(rel):
        return "ci_cd_signal"
    if path.name in DEPENDENCY_FILES or "lock" in path.name.lower():
        return "dependency_signal"
    if category == "mcp_tooling" or MCP_FILE_RE.search(rel):
        return "confirmed_code_usage"
    if category in {"prompt_surface", "training_eval_data"} or PROMPT_HINT_RE.search(rel):
        return "prompt_or_data_signal"
    if category in {"model_provider_usage", "agent_framework", "rag_vector_store", "secret_configuration"}:
        if re.search(r"\b(import|from|require|new |client|api|model|invoke|chat|embed|completion|vector|server|config)\b", line, re.IGNORECASE):
            return "confirmed_code_usage"
    return "keyword_only"


def reason_for(category: str, component: str, confidence: str) -> str:
    if confidence == "confirmed_code_usage":
        return f"Direct code or configuration evidence matched {component} in {category}."
    if confidence == "dependency_signal":
        return f"Dependency or build metadata references {component}; validate actual runtime usage."
    if confidence == "prompt_or_data_signal":
        return f"Prompt, eval, training, or dataset artifact references {component}."
    if confidence == "ci_cd_signal":
        return f"CI/CD or automation file references {component}; review build-time data and secret exposure."
    return f"Weak keyword evidence references {component}; manual validation required."


def write_csv(path: Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def analyze(repos: list[Path], output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    files_scanned = 0
    for repo in repos:
        commit = git_commit(repo)
        for path in iter_files(repo):
            files_scanned += 1
            rel = str(path.relative_to(repo)) if path.is_relative_to(repo) else str(path)
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line_number, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                for category, component, regex in COMPILED:
                    if not regex.search(line) and not (category == "mcp_tooling" and MCP_FILE_RE.search(rel)):
                        continue
                    confidence = confidence_for(path, line, category)
                    rows.append({
                        "repo": repo.name,
                        "repo_path": str(repo),
                        "commit_sha": commit,
                        "file_path": rel,
                        "line_number": str(line_number),
                        "category": category,
                        "component": component,
                        "confidence": confidence,
                        "evidence_excerpt": redact(line.strip())[:SNIPPET_LIMIT],
                        "reason": reason_for(category, component, confidence),
                    })

    fields = ["repo", "repo_path", "commit_sha", "file_path", "line_number", "category", "component", "confidence", "evidence_excerpt", "reason"]
    write_csv(output_dir / "git_shadow_ai_findings.csv", rows, fields)
    write_csv(output_dir / "git_ai_dependencies.csv", [row for row in rows if row["confidence"] == "dependency_signal"], fields)
    write_csv(output_dir / "git_ai_prompts.csv", [row for row in rows if row["category"] in {"prompt_surface", "training_eval_data"}], fields)
    write_csv(output_dir / "git_ai_mcp_findings.csv", [row for row in rows if row["category"] == "mcp_tooling"], fields)
    write_csv(output_dir / "git_ai_rag_findings.csv", [row for row in rows if row["category"] == "rag_vector_store"], fields)

    summary = {
        "repos_scanned": len(repos),
        "files_scanned": files_scanned,
        "findings": len(rows),
        "confidence_counts": Counter(row["confidence"] for row in rows).most_common(),
        "category_counts": Counter(row["category"] for row in rows).most_common(),
        "component_counts": Counter(row["component"] for row in rows).most_common(25),
        "repositories": [repo.name for repo in repos],
    }
    (output_dir / "git_shadow_ai_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Git repositories for shadow AI usage.")
    parser.add_argument("--input", type=Path, help="Repo or folder containing repos.")
    parser.add_argument("--repo-list", type=Path, help="Text file with one repo path per line.")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    repos = discover_repos(args.input, args.repo_list)
    print(json.dumps(analyze(repos, args.output_dir), indent=2))


if __name__ == "__main__":
    main()
