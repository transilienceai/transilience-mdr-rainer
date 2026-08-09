---
name: aws-attack-chain-enumerator
description: Traverse a merged aws_attack_model/v1 attack graph and emit aws_attack_chains/v1 - ranked kill chains from an entry (internet or a single stolen credential) to crown jewels, the atomic technique catalog of attack primitives actually present, and root causes rolled up by control. Use when turning a merged AWS attack model into scored attacker kill chains, an ATT&CK-mapped technique catalog, prioritized root causes, or the input a red-team report packager renders.
---

# AWS Attack Chain Enumerator

The traversal-and-scoring stage of the AWS red-team attack-chain suite. It takes
the merged `aws_attack_model/v1` from `aws-attack-graph-builder`, tags the graph
with attack primitives from `aws-attack-primitive-kb`, and enumerates:

- **kill chains** — deterministic ENTRY -> ... -> CROWN-JEWEL paths, scored and ranked;
- **techniques** — one per attack primitive actually present in the model (the atomic
  ATT&CK-mapped catalog), grouped by KB category;
- **root causes** — findings rolled up by control, with the technique numbers they feed.

Generic AWS. Deterministic, stdlib only. `live` is always `false` here — a downstream
correlator sets it from active-threat telemetry.

## Inputs

- `--model attack_model.json` — a merged `aws_attack_model/v1` document.
- `--kb <attack_primitives.json>` — the primitive KB (defaults to the bundled
  `aws-attack-primitive-kb/references/attack_primitives.json`).
- `--customer`, `--now` (ISO-8601; no `datetime.now`).
- `--max-chains N` (default 200), `--max-depth N` (default 6).

## CLI

```bash
python3 aws-attack-chain-enumerator/scripts/enumerate_chains.py \
  --model attack_model.json \
  --kb aws-attack-primitive-kb/references/attack_primitives.json \
  --customer acme \
  --now 2026-08-08T00:00:00Z \
  --max-chains 200 \
  --output attack_chains.json
```

## Algorithm (summary)

1. **Tag** findings by matching `finding.control` against KB `signature.controls`
   (attach `primitive_ids` + `mitre`); use `edge.attributes.primitive_id` too.
2. **Entries** = the internet node (via `exposes`) plus every principal/access_key
   flagged as a plausible single stolen credential (long-lived key, no-MFA admin,
   CI robot). **Targets** = crown jewels and any data node with `can_reach` in-degree.
3. **Kill chains** = paths ENTRY -> TARGET over a non-decreasing tactic order
   (`exposes -> has_credential/can_assume -> can_passrole/can_escalate -> can_reach`),
   bounded depth; dedup by node path; keep top `--max-chains` by score.
4. **Techniques** = one per distinct primitive present, numbered, grouped by category,
   with real resource/account strings, MITRE, severity, refs.
5. **Root causes** = findings by control -> class, scope, count, feeds.
6. Pass through model `gaps` and `active_threats`; fill `metadata` counts.

Full detail and the scoring formula are in `references/enumeration.md`.

## Output

`aws_attack_chains/v1` (default `attack_chains.json`): `metadata`, `kill_chains`,
`techniques`, `root_causes`, `active_threats`, `gaps`. If the model has zero nodes,
a valid empty document is still emitted.

Feed the result to the report packager. Smoke-test with the shared
`../aws-attack-graph-builder/references/sample_model.json` (a labeled sample only).
