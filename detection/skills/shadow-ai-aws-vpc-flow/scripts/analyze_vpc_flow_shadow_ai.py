#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

AI_DOMAINS = {
    "OpenAI": ["api.openai.com"],
    "Anthropic": ["api.anthropic.com"],
    "Google Gemini/Vertex": ["generativelanguage.googleapis.com", "aiplatform.googleapis.com"],
    "Cohere": ["api.cohere.ai"],
    "Mistral": ["api.mistral.ai"],
    "Together": ["api.together.xyz"],
    "Groq": ["api.groq.com"],
    "Fireworks": ["api.fireworks.ai"],
    "Perplexity": ["api.perplexity.ai"],
    "DeepSeek": ["api.deepseek.com"],
    "Voyage": ["api.voyageai.com"],
    "Jina": ["api.jina.ai"],
    "Replicate": ["api.replicate.com"],
    "Hugging Face": ["huggingface.co", "api-inference.huggingface.co"],
    "OpenRouter": ["openrouter.ai"],
    "LangSmith": ["api.smith.langchain.com", "api.langchain.com"],
    "Langfuse": ["cloud.langfuse.com"],
    "Helicone": ["api.helicone.ai", "helicone.ai"],
    "Braintrust": ["api.braintrust.dev", "braintrust.dev"],
    "Weights & Biases": ["api.wandb.ai", "wandb.ai"],
    "Pinecone": ["api.pinecone.io", "controller.us-east-1.pinecone.io"],
    "Qdrant Cloud": ["cloud.qdrant.io"],
    "Weaviate Cloud": ["console.weaviate.cloud", "weaviate.cloud"],
    "Zilliz": ["cloud.zilliz.com"],
    "Chroma": ["trychroma.com"],
    "MongoDB Atlas": ["cloud.mongodb.com"],
    "Supabase": ["supabase.com"],
    "GitHub": ["github.com", "api.github.com", "objects.githubusercontent.com", "pkg-containers.githubusercontent.com"],
    "PyPI": ["pypi.org", "files.pythonhosted.org"],
    "npm": ["registry.npmjs.org"],
    "Docker Hub": ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"],
    "GHCR": ["ghcr.io"],
}

PROVIDER_CATEGORY = {
    "OpenAI": "foundation_model_provider",
    "Anthropic": "foundation_model_provider",
    "Google Gemini/Vertex": "foundation_model_provider",
    "Cohere": "foundation_model_provider",
    "Mistral": "foundation_model_provider",
    "Together": "foundation_model_provider",
    "Groq": "foundation_model_provider",
    "Fireworks": "foundation_model_provider",
    "Perplexity": "foundation_model_provider",
    "DeepSeek": "foundation_model_provider",
    "Voyage": "embedding_reranking_provider",
    "Jina": "embedding_reranking_provider",
    "Replicate": "model_provider",
    "Hugging Face": "model_provider_or_registry",
    "OpenRouter": "model_broker",
    "LangSmith": "llm_observability",
    "Langfuse": "llm_observability",
    "Helicone": "llm_observability_or_gateway",
    "Braintrust": "eval_observability",
    "Weights & Biases": "ml_observability",
    "Pinecone": "vector_database",
    "Qdrant Cloud": "vector_database",
    "Weaviate Cloud": "vector_database",
    "Zilliz": "vector_database",
    "Chroma": "vector_database",
    "MongoDB Atlas": "database_vector_capable",
    "Supabase": "database_vector_capable",
    "GitHub": "package_or_model_artifact_source",
    "PyPI": "package_or_model_artifact_source",
    "npm": "package_or_model_artifact_source",
    "Docker Hub": "package_or_model_artifact_source",
    "GHCR": "package_or_model_artifact_source",
}

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
]

INTERNAL_PORTS = {
    "5432": "internal_vector_or_database",
    "6379": "internal_vector_or_database",
    "9200": "internal_vector_or_database",
    "6333": "internal_vector_or_database",
    "6334": "internal_vector_or_database",
    "19530": "internal_vector_or_database",
    "8000": "internal_inference_service",
    "8001": "internal_inference_service",
    "8002": "internal_inference_service",
    "8080": "internal_inference_service",
    "11434": "internal_inference_service",
}

FLOW_FIELDS = [
    "interface_id",
    "workload",
    "srcaddr",
    "dstaddr",
    "dst_reverse_dns",
    "srcport",
    "dstport",
    "protocol",
    "flows",
    "bytes",
    "packets",
    "avg_packet_size",
    "avg_duration_seconds",
    "first_start_epoch",
    "last_end_epoch",
    "src_is_private",
    "dst_is_private",
    "dst_category",
    "provider",
    "matched_domain",
    "confidence",
    "match_basis",
    "eni_description",
    "eni_name",
    "eni_private_ip",
    "eni_subnet_id",
    "eni_security_groups",
    "eni_tags",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze VPC Flow Logs for shadow AI usage.")
    parser.add_argument("--input-csv", type=Path, help="Offline normalized flow CSV export.")
    parser.add_argument("--log-group", help="CloudWatch Logs log group containing VPC Flow Logs.")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", help="Optional AWS profile.")
    parser.add_argument("--role-arn", help="Optional read-only role ARN to assume.")
    parser.add_argument("--window-days", type=int, default=7)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--filter-event-limit", type=int, default=250000)
    parser.add_argument("--skip-current-dns", action="store_true", help="Do not resolve catalog domains at runtime.")
    return parser.parse_args()


def parse_number(value: Any, default: float = 0.0) -> float:
    try:
        if value in ("", None):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in PRIVATE_NETS)


def reverse_dns(ip: str) -> str:
    if not ip or is_private_ip(ip):
        return ""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def resolve_domain_catalog(skip_current_dns: bool) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, str]]]:
    ip_catalog: dict[str, list[dict[str, str]]] = defaultdict(list)
    domain_rows: list[dict[str, str]] = []
    for provider, domains in AI_DOMAINS.items():
        for domain in domains:
            if skip_current_dns:
                domain_rows.append({"provider": provider, "domain": domain, "ip": "", "error": "skipped"})
                continue
            ips: set[str] = set()
            try:
                for family, _, _, _, sockaddr in socket.getaddrinfo(domain, 443):
                    if family == socket.AF_INET:
                        ips.add(sockaddr[0])
            except OSError as exc:
                domain_rows.append({"provider": provider, "domain": domain, "ip": "", "error": str(exc)})
                continue
            for ip in sorted(ips):
                record = {"provider": provider, "domain": domain, "category": PROVIDER_CATEGORY.get(provider, "unknown")}
                ip_catalog[ip].append(record)
                domain_rows.append({"provider": provider, "domain": domain, "ip": ip, "error": ""})
    return dict(ip_catalog), domain_rows


def assume_session(profile: str | None, role_arn: str | None, region: str):
    import boto3

    source = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    if not role_arn:
        return source
    sts = source.client("sts", region_name=region)
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="vpc-flow-ai-discovery")
    creds = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def parse_flow_message(message: str) -> dict[str, str] | None:
    parts = message.split()
    if len(parts) < 14:
        return None
    version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes_value, start, end, action, log_status = parts[:14]
    if action != "ACCEPT" or log_status != "OK":
        return None
    return {
        "version": version,
        "accountId": account_id,
        "interfaceId": interface_id,
        "srcaddr": srcaddr,
        "dstaddr": dstaddr,
        "srcport": srcport,
        "dstport": dstport,
        "protocol": protocol,
        "packets": packets,
        "bytes": bytes_value,
        "start": start,
        "end": end,
        "action": action,
        "logStatus": log_status,
    }


def aggregate_records(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    aggregates: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    hourly: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for record in records:
        if str(record.get("action", "ACCEPT")).upper() not in {"", "ACCEPT"}:
            continue
        if str(record.get("logStatus", record.get("log_status", "OK"))).upper() not in {"", "OK"}:
            continue
        interface_id = str(record.get("interfaceId") or record.get("interface_id") or record.get("interface-id") or "")
        srcaddr = str(record.get("srcaddr") or record.get("src_addr") or record.get("src") or "")
        dstaddr = str(record.get("dstaddr") or record.get("dst_addr") or record.get("dst") or "")
        srcport = str(record.get("srcport") or record.get("src_port") or "")
        dstport = str(record.get("dstport") or record.get("dst_port") or "")
        protocol = str(record.get("protocol") or "")
        packets = int(parse_number(record.get("packets")))
        bytes_value = int(parse_number(record.get("bytes")))
        start = int(parse_number(record.get("start") or record.get("start_epoch") or record.get("first_start_epoch")))
        end = int(parse_number(record.get("end") or record.get("end_epoch") or record.get("last_end_epoch") or start))
        duration = max(0, end - start)
        key = (interface_id, srcaddr, dstaddr, dstport, protocol)
        item = aggregates.setdefault(
            key,
            {
                "interfaceId": interface_id,
                "srcaddr": srcaddr,
                "dstaddr": dstaddr,
                "dst_reverse_dns": str(record.get("dst_reverse_dns") or record.get("ptr") or ""),
                "srcport": srcport,
                "dstport": dstport,
                "protocol": protocol,
                "flows": 0,
                "bytes": 0,
                "packets": 0,
                "firstStart": start,
                "lastEnd": end,
                "_duration_sum": 0,
            },
        )
        item["flows"] += int(parse_number(record.get("flows"), 1) or 1)
        item["bytes"] += bytes_value
        item["packets"] += packets
        if not item.get("dst_reverse_dns") and (record.get("dst_reverse_dns") or record.get("ptr")):
            item["dst_reverse_dns"] = str(record.get("dst_reverse_dns") or record.get("ptr") or "")
        item["firstStart"] = min(item["firstStart"], start) if item["firstStart"] else start
        item["lastEnd"] = max(item["lastEnd"], end)
        item["_duration_sum"] += duration
        if start:
            hour = datetime.fromtimestamp(start, tz=timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
        else:
            hour = ""
        hkey = (hour, interface_id, dstaddr, dstport)
        hitem = hourly.setdefault(hkey, {"bin(1h)": hour, "interfaceId": interface_id, "dstaddr": dstaddr, "dstport": dstport, "flows": 0, "bytes": 0, "packets": 0})
        hitem["flows"] += 1
        hitem["bytes"] += bytes_value
        hitem["packets"] += packets
    rows = []
    for item in aggregates.values():
        flows = item["flows"] or 1
        item["avgDuration"] = item.pop("_duration_sum", 0) / flows
        rows.append({k: str(v) for k, v in item.items()})
    rows.sort(key=lambda row: int(parse_number(row.get("bytes"))), reverse=True)
    hourly_rows = [{k: str(v) for k, v in item.items()} for item in hourly.values()]
    hourly_rows.sort(key=lambda row: int(parse_number(row.get("bytes"))), reverse=True)
    return rows, hourly_rows


def read_input_csv(path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        raw_rows = list(csv.DictReader(handle))
    top_rows, hourly_rows = aggregate_records(raw_rows)
    return top_rows, hourly_rows, {"method": "offline_csv", "input_rows": len(raw_rows)}


def collect_cloudwatch(args: argparse.Namespace) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, Any], list[dict[str, str]], dict[str, str]]:
    from botocore.exceptions import ClientError

    if not args.log_group:
        raise SystemExit("--log-group is required unless --input-csv is used")
    session = assume_session(args.profile, args.role_arn, args.region)
    logs = session.client("logs", region_name=args.region)
    sts = session.client("sts", region_name=args.region)
    identity = sts.get_caller_identity()
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.window_days)
    kwargs = {"logGroupName": args.log_group, "startTime": int(start.timestamp() * 1000), "endTime": int(end.timestamp() * 1000), "limit": 10000}
    records = []
    scanned = 0
    while True:
        response = logs.filter_log_events(**kwargs)
        for event in response.get("events", []):
            scanned += 1
            parsed = parse_flow_message(event.get("message", ""))
            if parsed:
                records.append(parsed)
        token = response.get("nextToken")
        if not token or scanned >= args.filter_event_limit:
            break
        kwargs["nextToken"] = token
    top_rows, hourly_rows = aggregate_records(records)
    bedrock_events = lookup_bedrock_events(session, start, end, args.region)
    stats = {"method": "cloudwatch_filter_log_events", "scanned_events": scanned, "parsed_events": len(records), "event_limit": args.filter_event_limit, "truncated": bool(scanned >= args.filter_event_limit)}
    account = {"account": identity.get("Account", ""), "arn": identity.get("Arn", ""), "window_start": start.isoformat(), "window_end": end.isoformat()}
    return top_rows, hourly_rows, stats, bedrock_events, account


def lookup_bedrock_events(session: Any, start: datetime, end: datetime, region: str) -> list[dict[str, str]]:
    from botocore.exceptions import ClientError

    cloudtrail = session.client("cloudtrail", region_name=region)
    events: list[dict[str, str]] = []
    for name in ["InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream"]:
        kwargs: dict[str, Any] = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": name}], "StartTime": start, "EndTime": end, "MaxResults": 50}
        while True:
            try:
                response = cloudtrail.lookup_events(**kwargs)
            except ClientError as exc:
                return [{"error": exc.response.get("Error", {}).get("Code", "ClientError"), "message": exc.response.get("Error", {}).get("Message", "")}]
            for event in response.get("Events", []):
                raw = {}
                try:
                    raw = json.loads(event.get("CloudTrailEvent", "{}"))
                except json.JSONDecodeError:
                    pass
                req = raw.get("requestParameters") or {}
                events.append({
                    "event_time": event.get("EventTime").isoformat() if event.get("EventTime") else "",
                    "event_name": event.get("EventName", ""),
                    "username": event.get("Username", ""),
                    "source_ip": raw.get("sourceIPAddress", ""),
                    "user_agent": raw.get("userAgent", ""),
                    "model_id": req.get("modelId") or req.get("modelIdentifier") or "",
                    "event_source": raw.get("eventSource", ""),
                })
            token = response.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
    return events


def classify_row(row: dict[str, Any], ip_catalog: dict[str, list[dict[str, str]]]) -> dict[str, str]:
    dstaddr = str(row.get("dstaddr", ""))
    matches = ip_catalog.get(dstaddr, [])
    if matches:
        first = matches[0]
        return {"dst_category": first["category"], "provider": first["provider"], "matched_domain": first["domain"], "confidence": "medium", "match_basis": "current_dns_resolution"}
    ptr = str(row.get("dst_reverse_dns", "")).lower()
    for provider, domains in AI_DOMAINS.items():
        for domain in domains:
            suffix = domain.lower()
            if ptr == suffix or ptr.endswith("." + suffix):
                return {"dst_category": PROVIDER_CATEGORY.get(provider, "unknown"), "provider": provider, "matched_domain": domain, "confidence": "medium", "match_basis": "reverse_dns_suffix"}
    dstport = str(row.get("dstport", ""))
    if is_private_ip(dstaddr) and dstport in INTERNAL_PORTS:
        bytes_value = parse_number(row.get("bytes"))
        packets_value = parse_number(row.get("packets"))
        duration_value = parse_number(row.get("avg_duration_seconds"))
        if bytes_value < 1000 and packets_value <= 10 and duration_value <= 5:
            return {"dst_category": "heartbeat_or_healthcheck", "provider": "heartbeat_or_healthcheck", "matched_domain": "", "confidence": "context", "match_basis": "tiny_fixed_internal_flow"}
        return {"dst_category": INTERNAL_PORTS[dstport], "provider": INTERNAL_PORTS[dstport], "matched_domain": "", "confidence": "low", "match_basis": "private_ip_port_heuristic"}
    return {"dst_category": "unclassified", "provider": "", "matched_domain": "", "confidence": "", "match_basis": ""}


def workload_label(row: dict[str, Any]) -> str:
    for key in ("workload", "eni_name", "interfaceId", "interface_id", "srcaddr"):
        value = str(row.get(key, ""))
        if value:
            return value[:240]
    return "unknown"


def enrich_rows(top_rows: list[dict[str, str]], ip_catalog: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    enriched = []
    for row in top_rows:
        srcaddr = row.get("srcaddr", "")
        dstaddr = row.get("dstaddr", "")
        bytes_v = parse_number(row.get("bytes"))
        packets_v = parse_number(row.get("packets"))
        item: dict[str, Any] = {
            "interface_id": row.get("interfaceId") or row.get("interface_id", ""),
            "workload": workload_label(row),
            "srcaddr": srcaddr,
            "dstaddr": dstaddr,
            "dst_reverse_dns": row.get("dst_reverse_dns") or reverse_dns(dstaddr),
            "srcport": row.get("srcport", ""),
            "dstport": row.get("dstport", ""),
            "protocol": row.get("protocol", ""),
            "flows": int(parse_number(row.get("flows"), 1)),
            "bytes": int(bytes_v),
            "packets": int(packets_v),
            "avg_packet_size": round(bytes_v / packets_v, 2) if packets_v else 0,
            "avg_duration_seconds": round(parse_number(row.get("avgDuration") or row.get("avg_duration_seconds")), 2),
            "first_start_epoch": int(parse_number(row.get("firstStart") or row.get("first_start_epoch"))),
            "last_end_epoch": int(parse_number(row.get("lastEnd") or row.get("last_end_epoch"))),
            "src_is_private": str(is_private_ip(srcaddr)),
            "dst_is_private": str(is_private_ip(dstaddr)),
            "eni_description": row.get("eni_description", ""),
            "eni_name": row.get("eni_name", ""),
            "eni_private_ip": row.get("eni_private_ip", ""),
            "eni_subnet_id": row.get("eni_subnet_id", ""),
            "eni_security_groups": row.get("eni_security_groups", ""),
            "eni_tags": row.get("eni_tags", ""),
        }
        item.update(classify_row(item, ip_catalog))
        enriched.append(item)
    return enriched


def score_workload(rows: list[dict[str, Any]]) -> tuple[int, str]:
    categories = Counter(row["dst_category"] for row in rows)
    providers = {row["provider"] for row in rows if row["provider"]}
    score = 0
    reasons = []
    if categories["foundation_model_provider"]:
        score += 50
        reasons.append("direct foundation-model provider traffic")
    if categories["model_broker"]:
        score += 35
        reasons.append("model broker traffic")
    if categories["vector_database"] or categories["internal_vector_or_database"]:
        score += 35
        reasons.append("vector/database destination compatible with RAG")
    if categories["internal_inference_service"]:
        score += 25
        reasons.append("internal inference-style destination port")
    if categories["llm_observability"] or categories["llm_observability_or_gateway"] or categories["eval_observability"] or categories["ml_observability"]:
        score += 30
        reasons.append("LLM observability or eval backend traffic")
    if categories["foundation_model_provider"] and categories["package_or_model_artifact_source"]:
        score += 20
        reasons.append("model/API traffic co-occurs with package or model artifact destinations")
    if categories["foundation_model_provider"] and len(providers) >= 3:
        score += 20
        reasons.append("multiple model providers from one workload")
    if categories["foundation_model_provider"] and len({row["dstaddr"] for row in rows}) >= 20:
        score += 15
        reasons.append("high destination fanout with LLM traffic")
    return min(score, 100), "; ".join(reasons)


def candidate_filter(row: dict[str, Any]) -> bool:
    return row["dst_category"] != "unclassified" or str(row.get("dstport", "")) in INTERNAL_PORTS


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_workload_rows(candidate_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_workload: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidate_rows:
        by_workload[row["workload"]].append(row)
    workload_rows = []
    for workload, rows in by_workload.items():
        score, reasons = score_workload(rows)
        first_values = [int(parse_number(row.get("first_start_epoch"))) for row in rows if parse_number(row.get("first_start_epoch"))]
        last_values = [int(parse_number(row.get("last_end_epoch"))) for row in rows if parse_number(row.get("last_end_epoch"))]
        workload_rows.append({
            "workload": workload,
            "score": score,
            "classification_reasons": reasons,
            "providers": ";".join(sorted({row["provider"] for row in rows if row["provider"]})),
            "categories": ";".join(f"{key}:{value}" for key, value in Counter(row["dst_category"] for row in rows).most_common()),
            "flows": sum(int(parse_number(row.get("flows"))) for row in rows),
            "bytes": sum(int(parse_number(row.get("bytes"))) for row in rows),
            "first_start_epoch": min(first_values) if first_values else "",
            "last_end_epoch": max(last_values) if last_values else "",
            "unique_destinations": len({row["dstaddr"] for row in rows}),
        })
    return sorted(workload_rows, key=lambda row: (int(row["score"]), int(row["bytes"])), reverse=True)


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    account = {"account": "", "arn": "", "window_start": "", "window_end": ""}
    bedrock_events: list[dict[str, str]] = []
    if args.input_csv:
        top_rows, hourly_rows, stats = read_input_csv(args.input_csv)
        collection_method = "offline_csv"
    else:
        top_rows, hourly_rows, stats, bedrock_events, account = collect_cloudwatch(args)
        collection_method = "cloudwatch_filter_log_events"
    ip_catalog, domain_rows = resolve_domain_catalog(args.skip_current_dns)
    enriched = enrich_rows(top_rows, ip_catalog)
    candidate_rows = sorted([row for row in enriched if candidate_filter(row)], key=lambda row: (row["dst_category"], int(parse_number(row["bytes"]))), reverse=True)
    workload_rows = build_workload_rows(candidate_rows)
    if not bedrock_events:
        bedrock_events = []
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "collection_method": collection_method,
        "region": args.region,
        "log_group": args.log_group or "",
        "input_csv": str(args.input_csv or ""),
        "account": account.get("account", ""),
        "assumed_arn": account.get("arn", ""),
        "window_start": account.get("window_start", ""),
        "window_end": account.get("window_end", ""),
        "query_statistics": stats,
        "limitations": [
            "Current DNS/PTR/IP intelligence is medium-confidence unless joined to historical Resolver, proxy, or gateway logs.",
            "Flow logs cannot reveal prompts, SaaS model names, HTTP paths, SDK user agents, or TLS SNI.",
            "Internal port matches require service inventory before they can be treated as confirmed AI systems.",
            "NAT, proxy, firewall, and egress gateway sources require packet-source fields or inventory joins for workload attribution.",
        ],
    }
    write_csv(args.output_dir / "flow-summary.csv", enriched, FLOW_FIELDS)
    write_csv(args.output_dir / "ai-candidate-flows.csv", candidate_rows, FLOW_FIELDS)
    write_csv(args.output_dir / "workload-ai-summary.csv", workload_rows, ["workload", "score", "classification_reasons", "providers", "categories", "flows", "bytes", "first_start_epoch", "last_end_epoch", "unique_destinations"])
    write_csv(args.output_dir / "hourly-top-destinations.csv", hourly_rows, ["bin(1h)", "interfaceId", "dstaddr", "dstport", "flows", "bytes", "packets"])
    write_csv(args.output_dir / "ai-domain-resolution.csv", domain_rows, ["provider", "domain", "ip", "error"])
    (args.output_dir / "bedrock-cloudtrail-events.json").write_text(json.dumps(bedrock_events, indent=2, default=str), encoding="utf-8")
    (args.output_dir / "raw-query-manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"rows": len(enriched), "candidate_rows": len(candidate_rows), "workloads": len(workload_rows), "out_dir": str(args.output_dir)}, indent=2))


if __name__ == "__main__":
    main()
