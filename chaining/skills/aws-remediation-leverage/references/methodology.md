# Remediation-leverage methodology

## Chain dependency model
An attack chain is an AND of links: it needs every misconfiguration in its path to work.
Therefore removing **any one** control the chain depends on **severs** the chain. This is what
makes leverage possible — one control fix can appear in the dependency set of many chains.

## Deriving a chain's control set
- Kill chains: parse control ids (regex `[A-Z][A-Z0-9]+(_[A-Z0-9]+)+`) from `misconfigurations`.
- Techniques: parse controls from `misconfigurations` AND union the KB `signature.controls` of the
  technique's `primitive_id` (more reliable than string parsing).
- Chains with no identifiable control are excluded from the remediable set (reported in metadata).

## Leverage ranking (independent)
`impact_score(control) = sum over chains-broken of severity_weight` where
critical=4, high=3, medium=2, low=1. Ties break on raw chains-broken, then control name.
Also reported: kill-chain vs technique split, distinct crown jewels protected, accounts touched.

## Roadmap (greedy marginal set-cover)
Set cover is NP-hard; the greedy heuristic is within a ln(n) factor and is the standard choice.
Repeat: pick the control that severs the most *not-yet-severed* chains (severity-weighted); record
its marginal chains and cumulative coverage; remove those chains; re-rank. This yields the
do-in-this-order plan where each step is the best remaining move — not just the globally biggest
control (which may overlap with step 1). Stop at `--top` steps or when all chains are covered.

## Interpreting output
- Top of the **roadmap** = the fixes to fund first; cumulative_pct shows how few fixes cover most chains.
- The **leverage table** answers "if I can only do one thing in service X, which control?".
- `crown_jewels_protected` / `accounts` help route each fix to the owning team.
