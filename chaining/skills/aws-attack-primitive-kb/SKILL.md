---
name: aws-attack-primitive-kb
description: Extensible AWS attack-primitive knowledge base that maps a misconfiguration signature to an attack primitive, its MITRE ATT&CK technique and tactic, what it enables downstream, and its remediation. Use when you need to tag attack-model findings/nodes/edges with primitives and MITRE techniques, grow the shared misconfig->primitive->MITRE->enables catalog after an engagement, compute tactic coverage for an attack model, or validate the KB before the graph builder and chain enumerator consume it. Part of the generic AWS red-team attack-chain suite (pairs with aws-attack-graph-builder and aws-threat-correlator).
---

# AWS Attack-Primitive Knowledge Base

The reusable, generic (customer-agnostic) catalog that turns raw AWS misconfigurations
into attacker-meaningful primitives. Each primitive says: *this misconfiguration
signature* → *this attack primitive* → *this MITRE technique/tactic* → *this is what it
enables next* → *this is how you fix it*. You grow this file every engagement so the
graph builder and chain enumerator find more and deeper attack chains over time.

The knowledge lives in `references/attack_primitives.json`. The scripts here **map**
`aws_attack_model/v1` findings against it and **validate** it.

## Where it sits in the suite

```
collectors  ->  aws-attack-primitive-kb  ->  aws-attack-graph-builder  ->  chain enumerator  ->  report
(findings)      (tag findings w/ primitives)  (merge model)                (traverse enables)
```

The shared model contract is `aws-attack-graph-builder/references/attack_model_schema.md`
(`aws_attack_model/v1`). Read it before extending the KB or the scripts.

## Quick start

```bash
# 1. Validate the KB (run this before every engagement and after every edit)
python3 aws-attack-primitive-kb/scripts/validate_kb.py

# 2. Tag an attack model's findings with primitives + MITRE, print coverage
python3 aws-attack-primitive-kb/scripts/map_findings.py \
  --model attack_model.json \
  --output attack_model.tagged.json
# (--kb defaults to the bundled references/attack_primitives.json)
```

## Primitive record schema

Each entry in `primitives[]` is:

```json
{
  "id": "ca_imds_theft",
  "name": "Instance-role credential theft via IMDS/SSRF",
  "tactic": "credential-access",
  "mitre": ["T1552.005"],
  "category": "B. Credential Access",
  "default_severity": "high",
  "signature": {
    "controls": ["EC2_IMDSV2_NOT_ENFORCED", "INSTANCE_ROLE_EXFILTRATION_DETECTED"],
    "conditions": ["ec2_instance.attributes.http_tokens==optional"]
  },
  "enables": ["pe_instance_role_broad", "lm_ssm_lateral"],
  "remediation": "Enforce IMDSv2 (HttpTokens=required, hop-limit=1); scope roles least-priv."
}
```

Field meanings:

| Field | Meaning |
|---|---|
| `id` | Stable, unique primitive id. Prefix by tactic (`ia_`, `ca_`, `pe_`, `lm_`, `ps_`, `de_`, `co_`, `ai_`, `im_`, `rc_`). Referenced by `enables`. |
| `name` | Human-readable primitive name. |
| `tactic` | One of: `reconnaissance`, `initial-access`, `credential-access`, `privilege-escalation`, `lateral-movement`, `persistence`, `defense-evasion`, `collection`, `exfiltration`, `impact`. |
| `mitre` | Non-empty list of MITRE ATT&CK technique ids (e.g. `T1552.005`). |
| `category` | Report grouping label (e.g. `C. Privilege Escalation`). |
| `default_severity` | `critical` / `high` / `medium` / `low`. |
| `signature.controls` | CSPM/finding control ids that fire this primitive. The mapper matches `finding.control` against these (case-insensitive). |
| `signature.conditions` | Human/normalized condition strings. Node/edge type tokens inside them drive best-effort node/edge tagging. Descriptive — not an executable DSL. |
| `enables` | Downstream primitive ids this one unlocks. Must resolve to real `id`s (validator enforces). This is the graph the enumerator traverses. |
| `remediation` | Fix guidance surfaced in the report. |

## How the mapper works (`map_findings.py`)

1. Load the `aws_attack_model/v1` envelope (`--model`) and the KB (`--kb`, default bundled).
2. Build a case-insensitive index: control id → primitive ids.
3. For each `finding`: match `finding.control` against the index; attach `primitive_ids`
   and the de-duplicated union of those primitives' `mitre` techniques onto the finding.
   Findings with no match get empty `primitive_ids`/`mitre`.
4. Best-effort tag `nodes` and `edges`: if a primitive's `signature.conditions` mention a
   node/edge **type** token (e.g. `s3_bucket`, `can_reach`), the matching nodes/edges get
   `attributes.primitive_hints`. This is a string-level hint only, not a claim of exploitability.
5. Write the enriched model to `--output` and print a summary: findings tagged, distinct
   primitives hit, and coverage by tactic.

Deterministic: stable ordering, no clock reads. stdlib only.

## How to add a primitive (grow the KB)

1. Read the model contract so your `signature.controls` match what collectors emit and
   your `signature.conditions` reference real node/edge types.
2. Add a new object to `primitives[]` in `references/attack_primitives.json` with all
   required fields and a unique `id`.
3. Wire it into the chain graph: add its `id` to the `enables` list of whatever precedes
   it, and point its own `enables` at what it unlocks (often a `pe_*` state or `pe_admin`).
4. Run `validate_kb.py` — fix any duplicate id, invalid tactic, or unresolved `enables`.
5. Re-run `map_findings.py` on a representative model and confirm the new primitive shows
   up in the coverage summary.
6. Commit the KB edit with a one-line note on the engagement that motivated it.

## Rules

- **Generic only.** No customer names, account ids, or resource arns in the KB — those
  live in the attack model, not here.
- **Never rename an `id`.** Other primitives' `enables` and prior tagged models depend on
  it. Add new ids; deprecate in `remediation`/`name` if needed.
- **`enables` must resolve.** The validator fails on dangling references.
- **Do not invent data.** The mapper only tags from real finding controls; it never
  fabricates findings.

## Files

```
aws-attack-primitive-kb/
  SKILL.md
  agents/openai.yaml
  references/attack_primitives.json   # the KB (extend this)
  scripts/map_findings.py             # tag a model's findings + coverage summary
  scripts/validate_kb.py              # KB sanity checks (PASS/FAIL)
```
