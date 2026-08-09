#!/usr/bin/env python3
"""Merge one or more `aws_attack_model/v1` envelopes into a single attack model.

Deterministic, stdlib-only. Never calls datetime.now at import time; any
timestamp comes from --now so re-runs are reproducible.

Merge semantics
---------------
- accounts/nodes/edges/findings/crown_jewels/active_threats/gaps are concatenated
  across every input envelope.
- nodes are de-duplicated by `id`; when the same id appears twice its `attributes`,
  `exposure`, and scalar fields are shallow-merged (later, non-empty values win).
- edges are de-duplicated by the tuple (src, dst, type).
- accounts are de-duplicated by `account_id` (shallow-merge, later non-empty wins).
- crown_jewels / active_threats are de-duplicated by `id`.
- findings are de-duplicated by `id` (findings without an id are kept as-is).
- gaps are de-duplicated by (area, reason).
- every edge is validated to reference existing node ids; dangling edges are dropped
  and recorded as a single Gap note (with the dropped edges listed).
- a `metadata` block of counts is emitted.
"""
import argparse
import json
import sys


SCHEMA = "aws_attack_model/v1"
ARRAY_KEYS = (
    "accounts",
    "nodes",
    "edges",
    "findings",
    "crown_jewels",
    "active_threats",
    "gaps",
)


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("%s: envelope must be a JSON object" % path)
    schema = data.get("schema")
    if schema and schema != SCHEMA:
        sys.stderr.write(
            "warning: %s has schema %r, expected %r\n" % (path, schema, SCHEMA)
        )
    return data


def _shallow_merge(base, incoming):
    """Merge incoming into base in place: later non-empty scalar values win;
    dict fields (attributes/exposure) are shallow-merged key by key."""
    for key, val in incoming.items():
        if isinstance(val, dict) and isinstance(base.get(key), dict):
            merged = dict(base[key])
            for k, v in val.items():
                if v not in (None, "", [], {}) or k not in merged:
                    merged[k] = v
            base[key] = merged
        elif val not in (None, "", [], {}) or key not in base:
            base[key] = val
    return base


def _concat(envelopes):
    out = {k: [] for k in ARRAY_KEYS}
    for env in envelopes:
        for key in ARRAY_KEYS:
            items = env.get(key) or []
            if not isinstance(items, list):
                raise ValueError("%r must be a list" % key)
            out[key].extend(items)
    return out


def _dedup_by_id(items, id_field="id"):
    """De-dup preserving first-seen order; shallow-merge dupes into the first."""
    order = []
    by_id = {}
    passthrough = []
    for item in items:
        if not isinstance(item, dict) or item.get(id_field) in (None, ""):
            passthrough.append(item)
            continue
        key = item[id_field]
        if key in by_id:
            _shallow_merge(by_id[key], item)
        else:
            by_id[key] = dict(item)
            order.append(key)
    return [by_id[k] for k in order] + passthrough


def _dedup_edges(edges):
    order = []
    seen = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        key = (edge.get("src"), edge.get("dst"), edge.get("type"))
        if key in seen:
            _shallow_merge(seen[key], edge)
        else:
            seen[key] = dict(edge)
            order.append(key)
    return [seen[k] for k in order]


def _dedup_gaps(gaps):
    order = []
    seen = {}
    passthrough = []
    for gap in gaps:
        if not isinstance(gap, dict):
            passthrough.append(gap)
            continue
        key = (gap.get("area"), gap.get("reason"))
        if key in seen:
            _shallow_merge(seen[key], gap)
        else:
            seen[key] = dict(gap)
            order.append(key)
    return [seen[k] for k in order] + passthrough


def merge_models(envelopes, customer, now):
    concat = _concat(envelopes)

    accounts = _dedup_by_id(concat["accounts"], id_field="account_id")
    nodes = _dedup_by_id(concat["nodes"], id_field="id")
    edges = _dedup_edges(concat["edges"])
    findings = _dedup_by_id(concat["findings"], id_field="id")
    crown_jewels = _dedup_by_id(concat["crown_jewels"], id_field="id")
    active_threats = _dedup_by_id(concat["active_threats"], id_field="id")
    gaps = _dedup_gaps(concat["gaps"])

    # Validate edges reference existing node ids; drop danglers.
    node_ids = {n.get("id") for n in nodes}
    kept_edges = []
    dangling = []
    for edge in edges:
        src, dst = edge.get("src"), edge.get("dst")
        if src in node_ids and dst in node_ids:
            kept_edges.append(edge)
        else:
            missing = [x for x in (src, dst) if x not in node_ids]
            dangling.append(
                {"src": src, "dst": dst, "type": edge.get("type"), "missing": missing}
            )

    if dangling:
        gaps.append(
            {
                "area": "graph-integrity",
                "reason": "%d edge(s) referenced node ids not present in the merged "
                "model and were dropped during merge." % len(dangling),
                "accounts": [],
                "recommended_collection": "Re-run the collector(s) that emitted these "
                "edges so their endpoint nodes are also emitted, or add the missing "
                "nodes.",
                "dropped_edges": dangling,
            }
        )

    source_skills = sorted(
        {e.get("source_skill") for e in envelopes if e.get("source_skill")}
    )

    model = {
        "schema": SCHEMA,
        "customer": customer,
        "collected_at": now,
        "source_skill": "aws-attack-graph-builder",
        "source_inputs": source_skills,
        "accounts": accounts,
        "nodes": nodes,
        "edges": kept_edges,
        "findings": findings,
        "crown_jewels": crown_jewels,
        "active_threats": active_threats,
        "gaps": gaps,
        "metadata": {
            "customer": customer,
            "generated_at": now,
            "input_count": len(envelopes),
            "account_count": len(accounts),
            "node_count": len(nodes),
            "edge_count": len(kept_edges),
            "dropped_edge_count": len(dangling),
            "finding_count": len(findings),
            "crown_jewel_count": len(crown_jewels),
            "active_threat_count": len(active_threats),
            "gap_count": len(gaps),
        },
    }
    return model


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Merge aws_attack_model/v1 envelopes into a single attack model."
    )
    ap.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="One or more aws_attack_model/v1 JSON envelopes from the collectors.",
    )
    ap.add_argument("--customer", default="", help="Customer label for the merged model.")
    ap.add_argument(
        "--now",
        default="",
        help="ISO-8601 timestamp stamped into the output (no datetime.now).",
    )
    ap.add_argument(
        "--output",
        default="attack_model.json",
        help="Path to write the merged aws_attack_model/v1 (default attack_model.json).",
    )
    args = ap.parse_args(argv)

    envelopes = [_load(p) for p in args.inputs]

    # If --customer omitted, take the first non-empty customer from inputs.
    customer = args.customer
    if not customer:
        for env in envelopes:
            if env.get("customer"):
                customer = env["customer"]
                break

    model = merge_models(envelopes, customer, args.now)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=2, sort_keys=False)
        fh.write("\n")

    meta = model["metadata"]
    sys.stderr.write(
        "merged %d input(s) -> %s: %d nodes, %d edges (%d dropped), %d findings, "
        "%d crown jewels\n"
        % (
            meta["input_count"],
            args.output,
            meta["node_count"],
            meta["edge_count"],
            meta["dropped_edge_count"],
            meta["finding_count"],
            meta["crown_jewel_count"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
