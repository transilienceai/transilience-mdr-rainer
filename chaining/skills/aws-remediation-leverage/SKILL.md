---
name: aws-remediation-leverage
description: Rank AWS remediations by how many attack chains each one severs, so a team gets maximum blast-radius reduction per fix. Use when you have an aws_attack_chains/v1 file from the chain enumerator and need to turn it into a prioritized "biggest bang for the buck" remediation plan - which single control fix breaks the most kill chains and techniques, a severity-weighted leverage ranking, the crown jewels and accounts each fix protects, and a greedy do-in-this-order roadmap (marginal set-cover) showing how few fixes cover most of the attack surface, and a compounding matrix (which misconfiguration enables the next) so fixing the source control cuts a chain early. Final decision-support stage of the AWS red-team attack-chain suite.
---

# aws-remediation-leverage

Turns an enumerated attack-chain model into a **prioritized remediation plan** ranked by
chains-severed-per-fix. A chain needs every link to work, so removing any one control it
depends on severs it — which is why a single fix (e.g. enforce IMDSv2) can break dozens of
chains at once.

## Inputs
- `--chains attack_chains.json` — `aws_attack_chains/v1` from `aws-attack-chain-enumerator`.
- `--kb attack_primitives.json` — optional; supplies the remediation text per control (defaults to the bundled KB).
- `--now <ISO>` — timestamp stamped into output (no datetime.now).
- `--top N` — rows/roadmap steps to keep (default 20).
- `--output out.json`, `--markdown report.md` — outputs.

## Outputs (`aws_remediation_leverage/v1`)
1. **remediations** — per control: `chains_broken`, kill-chain vs technique split, `by_severity`,
   `impact_score` (severity-weighted), `crown_jewels_protected`, `accounts`, and the KB `remediation` text. Sorted by impact.
2. **roadmap** — greedy marginal set-cover: step 1 = highest-leverage fix; each subsequent step is
   the fix that severs the most *remaining* chains. Shows `marginal_chains_severed` and `cumulative_pct`.
3. **compounding_matrix** — KB-derived `A enables B` edges scoped to controls present in these chains (fix A to cut compounding before B).
4. **metadata** — remediable chains, distinct controls, roadmap coverage %, compounding edges.

## Example
```
python3 scripts/rank_remediations.py --chains attack_chains.json \
  --now 2026-01-15T00:00:00Z --top 20 \
  --output remediation_leverage.json --markdown remediation_leverage.md
```

## Method
Chains (kill chains + techniques) are reduced to the set of controls they depend on (parsed from
their misconfiguration tags + the technique's primitive signature). Leverage(control) = the chains
whose dependency set contains it. The roadmap re-ranks after each pick so it reflects marginal, not
overlapping, value. See `references/methodology.md`.

## Data notes
- Only chains with at least one identifiable control are remediable here; others are reported out of scope.
- Remediation text comes from the KB; controls with no KB mapping are flagged.
