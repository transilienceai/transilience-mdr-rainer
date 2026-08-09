# Enumeration algorithm & scoring — `aws_attack_chains/v1`

This documents exactly what `scripts/enumerate_chains.py` does. It is deterministic
(sorted iteration everywhere), pure-Python, stdlib-only, and never calls
`datetime.now` — every timestamp comes from `--now`.

## Inputs

- A merged `aws_attack_model/v1` graph (from `aws-attack-graph-builder`).
- The attack-primitive KB (`aws_attack_primitive_kb/v1`).

## 1. Primitive tagging

Build two indexes from the KB:

- `prim_by_id[pid] -> primitive`
- `control_to_prims[control] -> [pid, ...]` from every primitive's
  `signature.controls`.

Then tag each finding: `finding.control` is matched against `control_to_prims`, and
the matched `primitive_ids` + the union of their `mitre` ids are attached to the
finding. Pre-existing `finding.primitive_ids` are preserved. Edges carry their own
primitive via `edge.attributes.primitive_id` when the collector set one.

## 2. Entries and targets

**Entry seeds** (where an attacker can start):

- the `internet` node, whenever it exists and/or has outbound `exposes` edges;
- every principal/`access_key` node that looks like a *single stolen credential*:
  - `access_key` with `attributes.age_days > 180` or `attributes.multiple_active`
    (**long-lived key**),
  - `iam_user` with `attributes.admin_like && console_login && !mfa`
    (**no-MFA admin**),
  - a principal whose name matches a CI hint (`jenkins|teamcity|cloudagent|pipeline|
    bitbucket|robot|runner|gitlab|circleci|codebuild`) and is `admin_like`/`ci_robot`
    (**CI robot**).

**Targets** (what the attacker wants):

- every crown jewel node id (impact = `value_score`);
- any data-type node (`s3_bucket`, `rds_instance`, `secret`, `bedrock_kb`, ...) that
  has `can_reach` in-degree > 0 (default impact 50).

## 3. Kill chains

Adjacency is built from non-self-loop edges. Self-loop edges (e.g. an `iam_user`
`can_escalate` to itself via `IAMFullAccess`) are recorded as *node-level*
escalation primitives instead of traversal hops, so they enrich a chain's severity
and misconfiguration list without creating cycles.

Each edge type has a tactic **rank**:

| rank | edge types |
|---|---|
| 0 | `exposes` |
| 1 | `has_credential`, `can_assume`, `trusts`, `member_of`, `stores_credential_for` |
| 2 | `can_passrole`, `can_escalate`, `runs_as` |
| 3 | `can_reach`, `replicates_to`, `writes_logs_to` |

A DFS from each entry explores paths where the edge rank is **non-decreasing**, no
node repeats, and the number of edges is `<= --max-depth` (default 6). This yields
the intended tactic order `exposes -> credential -> privesc -> reach`. Any node that
is itself a target closes a chain (a target may still be an intermediate hop toward a
deeper crown jewel).

Paths are de-duplicated by their node-path signature, sorted by
`(-score, title, node_path)`, and truncated to `--max-chains`. Chains are then
numbered `KC-1..KC-n`.

### Scoring

For a chain, collect *member severities* from: edge primitives on the path,
node-level self-loop escalation primitives, findings attached to nodes on the path,
and the crown-jewel value band (`>=80 critical, >=60 high, >=40 medium, else low`).

- `severity` = the maximum member severity.
- severity weights: `critical 1.0, high 0.8, medium 0.5, low 0.3`.
- `base` = mean of member severity weights (0.4 if none).
- `length_factor = 1 / (1 + edges * 0.3)` — longer chains are less likely.
- `entry_factor = 1.0` for an internet entry, `0.7` for a stolen credential.
- `likelihood = min(1, base * length_factor * entry_factor)`.
- `impact = crown_jewel.value_score / 100` (0.5 default).
- **`score = round(likelihood * impact, 4)`** in `[0, 1]`.

Each kill chain carries `title`, `tactic_sequence`, `steps` (short pill labels),
`objective` (crown-jewel name), `crown_jewel_id`, `severity`, `score`,
`live=false`, `misconfigurations` (human strings from findings/primitives on the
path), `evidence=""`, and `node_path`.

## 4. Techniques (atomic catalog)

A primitive is *present* if a finding matches one of its `signature.controls` or an
edge references it via `attributes.primitive_id`. For each present primitive emit one
technique, ordered by `(category, -default_severity, id)` and numbered `1..n`
(`T-001..`). Each technique records `category`, `tactic`, `title` (primitive name),
`chain` (`name -> enables: ...`), `misconfigurations` (real
`control on resource (acct id)` strings from matching findings), `mitre`,
`severity` (max of default and matching-finding severities), `live=false`, and
`refs.account_ids` / `refs.resources`.

## 5. Root causes

Findings are rolled up by `control`: `class` (the KB category of the representative
primitive), `scope` (`N account(s): ...`), `count`, and `feeds` (the technique
numbers that control's primitives produced).

## 6. Pass-through and metadata

Model `gaps` and `active_threats` pass straight through. `metadata` carries
`customer, generated_at, account_count, node_count, edge_count, finding_count,
crown_jewel_count, technique_count, kill_chain_count, root_cause_count`.

## Empty model

If the model has zero nodes, a valid empty `aws_attack_chains/v1` is still written
(empty `kill_chains`, techniques still reflect any findings present, metadata counts
zeroed appropriately).
