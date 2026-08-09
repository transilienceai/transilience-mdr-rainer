# Transilience PDF design system (pointer)

The PDF renderer (`scripts/build_transilience_pdf.py`) does not reinvent the Transilience look — it
imports the shared base module and reuses its building blocks. This file is a short pointer to what
that module provides and to the two custom flowables added on top.

## Source of the design system

Base module: `generate_cloudtrail_business_baseline_transilience_pdf.py`
(supplied by the caller via `--base-module-dir` or `TRANSILIENCE_BASE_MODULE_DIR`).

Located at runtime via, in order:

1. `--base-module-dir <dir>` CLI arg
2. `TRANSILIENCE_BASE_MODULE_DIR` environment variable
3. default: the script directory and current working directory

If none contain the module, the script exits with a message telling you to pass `--base-module-dir`.

## What the base module exports (and this skill uses)

- **Color tokens** — background `BG` / `BGC` / `BGCA`, lines `GL` / `BS`, brand purple `BP` / `BPL`,
  magenta `BM`; text `T1` / `T2` / `T3`; severity `SC` (critical, red) / `SH` (high, orange) /
  `SM` (medium, yellow) / `SL` (low, green); accents `AB` (blue) / `AE` (emerald) / `AA` (amber).
- **Fonts** — `FH` (heading), `FM` (medium), `FR` (regular), `FB` (body), `FBI` (italic). Registered
  from Poppins + Carlito TTFs when present; automatic **Helvetica** family fallback otherwise.
- **Geometry** — `PAGE_W`, `PAGE_H`, `MARGIN`, `CW` (content width) on A4.
- **Flowables** — `CardBox` (rounded accent-bar card), `GradientLine`, `MetricBox` (KPI tile),
  `SectionNumber` (oversized ghost section index).
- **Helpers** — `esc` (HTML-escape), `gradient_on_canvas` (top gradient bar), `make_styles`
  (paragraph style sheet).

## Custom flowables (defined locally in the PDF script)

- **`ChainFlow`** — the kill-chain diagram: rounded "pills" (one per step) connected by arrows and
  wrapping across rows to fit the content width. The **last pill is the objective**, drawn filled in
  the chain's severity accent color; a triangle marks each arrow.
- **`HBar`** — a horizontal bar chart of `(label, value, color)` rows with a track background and a
  right-aligned value label. Used for the technique severity distribution and the root-cause
  exposure counts.

Both were carried over verbatim (behavior-wise) from a proven per-customer Transilience generator; the only change is that their inputs now
come from `aws_attack_chains/v1` JSON rather than hardcoded Python literals.

## Page structure produced

Cover (logo + title + metric grid) → 01 Executive Summary (metric rows, LIVE card, severity HBar)
→ 02 Attack Surface (root-cause exposure HBar) → 03 Flagship Kill Chains (CardBox + ChainFlow)
→ 04 Misconfiguration Root Causes (table) → 05 Techniques by Tactic (per-category tables with
severity chips) → 06 Data Gaps & Recommended Collection.
