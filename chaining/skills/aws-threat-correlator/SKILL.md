---
name: aws-threat-correlator
description: Correlate live AWS GuardDuty findings and investigation evidence onto a static attack-chain model, so theoretical chains that are actually under attack right now light up. Use when you have an aws_attack_chains/v1 file from the chain enumerator and want to mark kill-chains and techniques live=true where GuardDuty findings intersect their accounts, resources, or crown jewels, parse GuardDuty into ActiveThreat records, populate the top-level active_threats array, and roll up a threat-actor indicator list (source IPs, actors, access keys). Part of the generic AWS red-team attack-chain suite (pairs with aws-attack-primitive-kb and aws-attack-graph-builder).
---

# AWS Threat Correlator

Turns a *possible* attack-chain model into a *prioritized* one. The chain enumerator
produces `aws_attack_chains/v1` describing what an attacker could do. This skill
overlays what is **actually happening** — GuardDuty findings and prior investigation
evidence — and flags the chains/techniques that are live so responders work the real
fire first.

## Where it sits in the suite

```
aws-attack-graph-builder -> chain enumerator -> aws-threat-correlator -> report packager
(attack model)             (aws_attack_chains/v1)  (mark live + threats)   (render)
```

The shared model contract is `aws-attack-graph-builder/references/attack_model_schema.md`
(`aws_attack_chains/v1` and the `ActiveThreat` type). Read it first.

## Quick start

```bash
python3 aws-threat-correlator/scripts/correlate_threats.py \
  --chains attack_chains.json \
  --guardduty ./guardduty/ \
  --ingest ./investigation/ \
  --now 2026-08-08T00:00:00Z \
  --output attack_chains.json
```

`--guardduty` and `--ingest` each accept a directory, a glob, or a single file and are
repeatable. At least one source should be supplied. `--now` stamps the run (no clock is
read, so re-runs are reproducible).

## What it does

1. **Parse threats.** Every GuardDuty finding (or investigation record) becomes an
   `ActiveThreat`: `{id, account_id, finding_type, severity, resource, indicators,
   first_seen, maps_to_nodes}`. Numeric GuardDuty severity is normalized to
   critical/high/medium/low. Resource identifiers and candidate model node ids
   (`ec2_instance:<acct>:<id>`, `s3_bucket:<acct>:<name>`, `access_key:<acct>:<id>`,
   `iam_user:<acct>:<name>`, `rds_instance:<acct>:<id>`) are derived best-effort.
2. **Mark live.** For each kill-chain and technique, it collects the accounts, resources,
   and crown-jewel it references and marks `live=true` if any active threat intersects
   them. It appends a short `evidence` / `live_evidence` string citing the GuardDuty
   finding type and an indicator.
3. **Populate `active_threats`.** The top-level array is merged (existing entries kept,
   new ones added) and sorted by id.
4. **Roll up indicators.** A top-level `threat_actor_indicators` object lists distinct
   `source_ips`, `actors`, and `access_keys` seen across all threats.
5. **Preserve everything else.** Only `live`/`evidence`/`active_threats`/
   `threat_actor_indicators` and two `metadata` stamps are written; all other fields pass
   through untouched.

Deterministic, stdlib only.

## Input shapes handled

| Shape | Detected by | Handling |
|---|---|---|
| Raw GuardDuty GetFindings | `{"Findings": [...]}` | full parse |
| Simplified | `{"findings": [...]}` | full parse |
| Investigation passthrough | `{"active_threats": [...]}` | records used as-is |
| Bare list | `[ {...} ]` | full parse |
| Raw GuardDuty ListFindings | `{"FindingIds": [...]}` | skipped w/ note (ids only, no detail) |
| Anything else / bad JSON | — | skipped w/ note, never crashes |

Notes for every skipped file are printed in the summary.

## Matching rules

An active threat lights up a chain/technique when any of:

- the threat's `account_id` is in the element's accounts
  (technique `refs.account_ids`; kill-chain account ids parsed from `node_path` ids
  of the form `type:account:name`), **or**
- the threat's `resource`/`maps_to_nodes` intersect the element's resources
  (technique `refs.resources`; kill-chain `node_path` + `crown_jewel_id`), **or**
- the element's `crown_jewel_id` is one of the threat's `maps_to_nodes`.

See `references/guardduty_mapping.md` for how GuardDuty finding types map to tactics and
attack primitives.

## Rules

- **Do not invent data.** Threats come only from the supplied GuardDuty/investigation
  files. No source files -> no live flags.
- **Additive only.** Existing chain fields are preserved; the script never renames or
  drops fields.
- **Deterministic.** Timestamps come from `--now`; ordering is stable.

## Files

```
aws-threat-correlator/
  SKILL.md
  agents/openai.yaml
  references/guardduty_mapping.md      # GD finding type -> tactic/primitive
  scripts/correlate_threats.py         # overlay live threats onto the chains
```
