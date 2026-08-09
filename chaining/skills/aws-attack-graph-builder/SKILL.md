---
name: aws-attack-graph-builder
description: Merge one or more aws_attack_model/v1 envelopes from the AWS attack-surface / identity-trust / crown-jewel / active-threat collectors into a single, de-duplicated attack graph ready for chain enumeration. Use when combining multiple collector outputs into one model, reconciling nodes and edges across accounts, validating that every edge references a real node, or producing the merged attack_model.json that aws-attack-chain-enumerator traverses.
---

# AWS Attack Graph Builder

The graph-assembly stage of the AWS red-team attack-chain suite. Each collector
emits an `aws_attack_model/v1` envelope (see
`references/attack_model_schema.md` — the frozen shared contract) that fills only
the arrays it owns. This skill concatenates those envelopes, de-duplicates the
graph, drops dangling edges, and writes one merged `aws_attack_model/v1` model
that the enumerator can traverse. Generic AWS — no customer data is baked in.

## Purpose

- Turn N partial collector envelopes into one coherent attack graph.
- Guarantee referential integrity: every surviving edge points at real nodes.
- Preserve every collection blind spot (`gaps`) so "find more next time" survives.
- Emit a `metadata` block of counts for the report packager.

## Inputs

- One or more `aws_attack_model/v1` JSON files (`--inputs a.json b.json ...`),
  e.g. from `aws-attack-surface-collector`, `aws-identity-trust-collector`,
  crown-jewel and active-threat collectors. Each fills its own arrays and leaves
  the rest empty.
- `--customer` label (falls back to the first non-empty `customer` in the inputs).
- `--now` ISO-8601 timestamp (the script never calls `datetime.now`).

## CLI

```bash
python3 aws-attack-graph-builder/scripts/build_attack_graph.py \
  --inputs surface.json identity.json crown_jewels.json threats.json \
  --customer acme \
  --now 2026-08-08T00:00:00Z \
  --output attack_model.json
```

## Merge semantics

- **Concatenate** `accounts / nodes / edges / findings / crown_jewels /
  active_threats / gaps` across all envelopes.
- **De-dup nodes** by `id`; duplicate ids shallow-merge (later non-empty values
  win, `attributes`/`exposure` merge key-by-key).
- **De-dup edges** by `(src, dst, type)`.
- **De-dup** accounts by `account_id`, crown_jewels/active_threats by `id`,
  findings by `id`, gaps by `(area, reason)`.
- **Validate edges**: any edge whose `src` or `dst` is not a known node id is
  dropped and recorded in a single `graph-integrity` Gap note listing the dropped
  edges — the model stays traversable and the loss is auditable.

## Output

A single merged `aws_attack_model/v1` document (default `attack_model.json`) with
all arrays de-duplicated plus a `metadata` block:
`input_count, account_count, node_count, edge_count, dropped_edge_count,
finding_count, crown_jewel_count, active_threat_count, gap_count`.

Feed the result to `aws-attack-chain-enumerator` to produce `aws_attack_chains/v1`.

## Notes

- stdlib only; deterministic; safe to re-run.
- `references/sample_model.json` is a tiny, clearly-labeled **sample** model for
  smoke-testing the pipeline — illustrative only, not real AWS data.
