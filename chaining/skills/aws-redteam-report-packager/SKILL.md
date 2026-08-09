---
name: aws-redteam-report-packager
description: >-
  Package an enumerated AWS attack-chain model into customer-facing red-team reports — a Markdown
  attack-chain catalog and a Transilience-styled dark-theme PDF. Use as the FINAL stage of the AWS
  red-team attack-chain suite, after aws-attack-graph-builder has merged collectors into an attack
  model and the chain enumerator has emitted an aws_attack_chains/v1 file. Use when you need to render
  flagship kill chains (steps + misconfigurations + evidence + LIVE badges), atomic techniques grouped
  by tactic, a misconfiguration root-cause table, active threats, and explicit data gaps into a
  polished report. Generic across any AWS estate — all content is read from the JSON, nothing is
  hardcoded.
---

# AWS Red-Team Report Packager

Final-stage renderer of the AWS red-team attack-chain suite. It turns the enumerator's
`aws_attack_chains/v1` JSON into two deliverables:

1. **Markdown attack-chain catalog** — `scripts/build_markdown_report.py`
2. **Transilience dark-theme PDF** — `scripts/build_transilience_pdf.py`

Both are fully data-driven: every kill chain, technique, root cause, active threat, and data gap
is read from the input JSON. Nothing is invented and no customer-specific content is hardcoded.

## Where this sits in the suite

```
collectors  →  aws-attack-graph-builder  →  chain enumerator  →  aws-redteam-report-packager
(surface,       (merge → attack_model.json)  (attack_chains.json)   (Markdown + PDF)
 identity,
 reachability)
```

The shared interoperability contract is defined in
`aws-attack-graph-builder/references/attack_model_schema.md`
(`aws_attack_model/v1` for the model; `aws_attack_chains/v1` for the enumerator output this skill
renders). Read it first — it is the source of truth for the fields consumed here.

## Input — `aws_attack_chains/v1`

```json
{ "schema": "aws_attack_chains/v1",
  "metadata": { "customer", "generated_at", "account_count", "node_count", "edge_count",
                "technique_count", "kill_chain_count", "crown_jewel_count", "org_id",
                "management_account_id", "role_name", "evidence_basis" },
  "kill_chains":   [ { "id", "title", "tactic_sequence", "steps", "objective", "crown_jewel_id",
                       "severity", "score", "live", "misconfigurations", "evidence", "node_path" } ],
  "techniques":    [ { "id", "number", "category", "tactic", "title", "chain",
                       "misconfigurations", "mitre", "severity", "live", "refs" } ],
  "root_causes":   [ { "class", "scope", "count", "feeds" } ],
  "active_threats":[ ActiveThreat ],
  "gaps":          [ Gap ] }
```

A complete, generic example lives in `references/sample_chains.json` (2 kill chains, 6 techniques
across 3 categories, 3 root causes, 1 active threat, 2 gaps, full metadata).

**Severity is accepted in both forms**: single-letter (`C`/`H`/`M`/`L`) and full words
(`critical`/`high`/`medium`/`low`), case-insensitive.

## Quick start

```bash
SKILL=aws-redteam-report-packager

# Markdown catalog (pure stdlib)
python3 $SKILL/scripts/build_markdown_report.py \
  --chains attack_chains.json \
  --model attack_model.json \        # optional, for extra account context
  --customer "Example Corp" \
  --now 2026-01-15T00:00:00Z \
  --output report.md

# Transilience PDF (needs reportlab + the shared base module)
python3 $SKILL/scripts/build_transilience_pdf.py \
  --chains attack_chains.json \
  --customer "Example Corp" \
  --title "AWS Red-Team Attack-Chain Analysis" \
  --now 2026-01-15T00:00:00Z \
  --logo /path/to/logo.png \         # optional
  --output report.pdf
```

Run against the bundled sample to smoke-test:

```bash
python3 $SKILL/scripts/build_markdown_report.py  --chains $SKILL/references/sample_chains.json --output /tmp/rtpack_test.md
python3 $SKILL/scripts/build_transilience_pdf.py --chains $SKILL/references/sample_chains.json --output /tmp/rtpack_test.pdf
```

## The two renderers

### `build_markdown_report.py` (pure stdlib)

Emulates the proven catalog shape:

- **Cover context** — customer, scope (accounts / org / management account / role), method, one-line posture.
- **Legend** — tactic labels, severity letters, LIVE meaning.
- **Part 1 — Flagship kill chains** — objective, `Chain: step → step → …`, misconfigs, crown jewel, evidence, severity; sorted by severity then score.
- **Part 2 — Atomic techniques** — grouped by `category`, one Markdown table per group (`# | Technique | Tactic | Chain | Misconfigurations | MITRE | Sev`), pipe characters escaped.
- **Part 3 — Misconfiguration root-cause table** — class, count/scope, chains fed.
- **Part 4 — Active threats** — the already-evidenced findings.
- **Part 5 — Data gaps** — blind spots + recommended collection commands.
- **Account reference** — from merged-model `accounts` if present, else derived from technique/threat refs.

### `build_transilience_pdf.py` (ReportLab)

A generalization of the working per-customer generator. Keeps the full visual system:

- Dark theme, gradient page frame, cover page with logo + metric grid.
- **Metric rows** — numbers derived from `metadata` (accounts, findings/edges, techniques, kill chains, nodes, crown jewels, LIVE chains, gaps).
- **HBar charts** — technique severity distribution (from `techniques`); exposure counts (from `root_causes.count`).
- **Section 03 flagship kill chains** — each a `CardBox` + `ChainFlow` pill/arrow diagram with a severity-accent objective pill and a LIVE badge.
- **Section 05 techniques-by-tactic** — one table per category with colored severity chips.
- **Section 04 misconfiguration root-cause table** and **Section 06 data-gaps** section.
- LIVE active threats surfaced as an executive-summary card.

## Fonts & fallback

Font registration is handled by the shared base module. It registers **Poppins** (headings) and
**Carlito** (body) if the local TTFs are present, and **falls back to Helvetica / Helvetica-Bold /
Helvetica-Oblique** otherwise. No action is needed for the fallback — the PDF builds either way.

## Transilience design system

The PDF imports the shared base module
`generate_cloudtrail_business_baseline_transilience_pdf` for its design system: the color tokens
(`BG`/`BGC`/`BGCA`/`GL`/`BS`/`BP`/`BPL`, severity `SC`/`SH`/`SM`/`SL`, accents `AB`/`AE`/`AA`, text
`T1`/`T2`/`T3`), the flowables (`CardBox`, `GradientLine`, `MetricBox`, `SectionNumber`), page
geometry (`PAGE_W`/`PAGE_H`/`MARGIN`/`CW`), and helpers (`esc`, `gradient_on_canvas`, `make_styles`).
Two custom flowables — `ChainFlow` and `HBar` — are defined locally in the PDF script.

**Import robustness**: the script locates the base module by trying, in order,
`--base-module-dir`, the `TRANSILIENCE_BASE_MODULE_DIR` env var, then neutral local
directories (the script dir and CWD). If none contain the module it exits with a
clear message telling you to pass `--base-module-dir`. See `references/design_system.md`.

## Rules

- **Deterministic** — no time/date is read at import; always pass `--now` (ISO string) so re-runs are reproducible.
- **Nothing invented** — render only what the input contains; empty arrays produce honest "none present" notes, never fabricated data.
- **Preserve uncertainty** — LIVE means evidenced; the data-gaps section must survive ("do not read absence as safety").
