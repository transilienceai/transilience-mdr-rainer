#!/usr/bin/env python3
"""Render an AWS red-team attack-chain catalog (Markdown) from an ``aws_attack_chains/v1`` file.

This is the final-stage renderer of the AWS red-team attack-chain suite. It emulates the
proven per-customer catalog shape: cover context, flagship kill chains, N techniques grouped by
category as tables, a misconfiguration root-cause table, active threats, data gaps, and an
account reference. Every value is read from the enumerator output; nothing is invented.

Pure stdlib. Deterministic: no time/date is read at import; pass ``--now`` for any timestamp.

Usage:
    python3 build_markdown_report.py \
        --chains attack_chains.json \
        [--model attack_model.json] \
        [--customer "Example Corp"] \
        [--now 2026-01-15T00:00:00Z] \
        --output report.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- severity

# Accept both single-letter (C/H/M/L) and full words (critical/high/medium/low).
_SEV_CANON = {
    "c": "critical", "crit": "critical", "critical": "critical",
    "h": "high", "high": "high",
    "m": "med", "med": "medium", "medium": "medium",
    "l": "low", "low": "low",
    "i": "info", "info": "info", "informational": "info",
}
_SEV_LETTER = {"critical": "C", "high": "H", "medium": "M", "med": "M", "low": "L", "info": "I"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "med": 2, "low": 3, "info": 4}


def sev_canon(value: Any) -> str:
    return _SEV_CANON.get(str(value or "").strip().lower(), "medium")


def sev_letter(value: Any) -> str:
    return _SEV_LETTER.get(sev_canon(value), "M")


def sev_rank(value: Any) -> int:
    return _SEV_RANK.get(sev_canon(value), 2)


# --------------------------------------------------------------------------- helpers

def md_escape(value: Any) -> str:
    """Escape pipe characters so free-form strings survive inside Markdown tables."""
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ").strip()


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def join_misconfigs(items: Any, sep: str = "; ") -> str:
    return sep.join(str(i) for i in as_list(items) if str(i).strip())


def feeds_str(feeds: Any) -> str:
    vals = [str(f).lstrip("#") for f in as_list(feeds)]
    return "#" + ", #".join(vals) if vals else "-"


# --------------------------------------------------------------------------- sections

def render(data: dict[str, Any], customer: str, now: str, model: dict[str, Any] | None) -> str:
    meta = data.get("metadata", {}) or {}
    customer = customer or meta.get("customer") or "the AWS estate"
    now = now or meta.get("generated_at") or ""

    kill_chains = data.get("kill_chains", []) or []
    techniques = data.get("techniques", []) or []
    root_causes = data.get("root_causes", []) or []
    active_threats = data.get("active_threats", []) or []
    gaps = data.get("gaps", []) or []

    lines: list[str] = []
    W = lines.append

    # ---- header / cover context
    W(f"# {customer} AWS Estate — Internal Red-Team Attack-Chain & Misconfiguration Catalog")
    W("")
    if now:
        W(f"**Generated:** {now}  ")
    W("**Author:** Transilience internal red-team analysis (authorized)  ")
    scope_bits = []
    if meta.get("account_count"):
        scope_bits.append(f"{meta['account_count']} AWS accounts")
    if meta.get("org_id"):
        scope_bits.append(f"AWS Organization `{meta['org_id']}`")
    if meta.get("management_account_id"):
        scope_bits.append(f"management account `{meta['management_account_id']}`")
    if meta.get("role_name"):
        scope_bits.append(f"enrolled under `{meta['role_name']}`")
    if scope_bits:
        W(f"**Scope:** {', '.join(scope_bits)}.  ")
    if meta.get("evidence_basis"):
        W(f"**Method:** {meta['evidence_basis']}")
    W("")

    live_kc = [kc for kc in kill_chains if kc.get("live")]
    live_tech = [t for t in techniques if t.get("live")]
    W("> **Posture in one line:** This attack-chain catalog is derived entirely from the merged "
      f"attack model — {meta.get('node_count', '?')} nodes / {meta.get('edge_count', '?')} edges across "
      f"{meta.get('account_count', '?')} accounts. It enumerates "
      f"**{len(kill_chains)} flagship kill chains** and **{len(techniques)} atomic techniques**, of which "
      f"**{len(live_kc)} chains and {len(live_tech)} techniques are already evidenced (LIVE)** by "
      "GuardDuty/investigation. Nothing below is invented; every item cites the misconfiguration that enables it.")
    W("")
    W("---")
    W("")

    # ---- legend
    W("## Legend")
    W("")
    W("- **Tactic** uses MITRE ATT&CK-for-Cloud style labels (Initial Access, Credential Access, "
      "Privilege Escalation, Lateral Movement, Persistence, Defense Evasion, Collection, Exfiltration, Impact).")
    W("- **Sev**: C=Critical, H=High, M=Medium, L=Low.")
    W("- **[LIVE]** = the technique or a step in it is already evidenced by GuardDuty/investigation in this estate.")
    W("")
    W("---")
    W("")

    _render_kill_chains(W, kill_chains)
    _render_techniques(W, techniques)
    _render_root_causes(W, root_causes)
    _render_active_threats(W, active_threats)
    _render_gaps(W, gaps)
    _render_account_reference(W, data, meta)

    W("")
    W("---")
    W("")
    W("*Prepared as authorized internal red-team analysis for remediation prioritization. Chains marked "
      "[LIVE] have supporting GuardDuty/investigation evidence and should be treated as confirmed exposure, "
      "not theory.*")
    W("")
    return "\n".join(lines)


def _render_kill_chains(W, kill_chains: list[dict[str, Any]]) -> None:
    W("## Part 1 — Flagship end-to-end kill chains (crown-jewel objectives)")
    W("")
    if not kill_chains:
        W("_No kill chains present in the input._")
        W("")
        W("---")
        W("")
        return
    W("These stitch multiple atomic techniques (Part 2) into full paths from the internet "
      "(or a single stolen credential) to a crown jewel.")
    W("")
    for kc in sorted(kill_chains, key=lambda k: (sev_rank(k.get("severity")), -float(k.get("score") or 0))):
        kc_id = kc.get("id", "KC")
        title = kc.get("title", "")
        sev = sev_canon(kc.get("severity"))
        live = " **[LIVE, already evidenced]**" if kc.get("live") else ""
        W(f"### {kc_id} — {title}{live}")
        if kc.get("objective"):
            W(f"**Objective:** {kc['objective']}")
        steps = as_list(kc.get("steps"))
        if steps:
            W(f"**Chain:** {' → '.join(str(s) for s in steps)}")
        misc = as_list(kc.get("misconfigurations"))
        if misc:
            W("**Misconfigs:** " + join_misconfigs(misc))
        if kc.get("crown_jewel_id"):
            W(f"**Crown jewel:** `{kc['crown_jewel_id']}`")
        if kc.get("evidence"):
            W(f"**Evidence it already occurred:** {kc['evidence']}")
        score = kc.get("score")
        score_txt = f" · Score {score}" if score not in (None, "") else ""
        W(f"**Sev {sev_letter(sev)} ({sev}).**{score_txt}")
        W("")
    W("---")
    W("")


def _render_techniques(W, techniques: list[dict[str, Any]]) -> None:
    W(f"## Part 2 — {len(techniques)} atomic techniques, chains & the misconfigurations found")
    W("")
    if not techniques:
        W("_No techniques present in the input._")
        W("")
        W("---")
        W("")
        return

    # Group by category, preserving first-seen category order.
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for t in techniques:
        cat = t.get("category") or t.get("tactic") or "Uncategorized"
        if cat not in groups:
            groups[cat] = []
            order.append(cat)
        groups[cat].append(t)

    for cat in order:
        rows = sorted(groups[cat], key=lambda t: t.get("number") or 0)
        W(f"### {cat}")
        W("")
        W("| # | Technique | Tactic | Chain | Misconfigurations found | MITRE | Sev |")
        W("|---|---|---|---|---|---|---|")
        for t in rows:
            num = t.get("number", "")
            title = md_escape(t.get("title", ""))
            if t.get("live"):
                title += " **[LIVE]**"
            tactic = md_escape(t.get("tactic", ""))
            chain = md_escape(t.get("chain", ""))
            misc = md_escape(join_misconfigs(t.get("misconfigurations")))
            mitre = md_escape(", ".join(str(m) for m in as_list(t.get("mitre"))))
            sev = sev_letter(t.get("severity"))
            W(f"| {num} | {title} | {tactic} | {chain} | {misc} | {mitre} | {sev} |")
        W("")
    W("---")
    W("")


def _render_root_causes(W, root_causes: list[dict[str, Any]]) -> None:
    W("## Part 3 — Misconfiguration summary (the root causes feeding the chains)")
    W("")
    if not root_causes:
        W("_No root-cause records present in the input._")
        W("")
        W("---")
        W("")
        return
    W("| # | Misconfiguration class | Count / scope | Chains fed |")
    W("|---|---|---|---|")
    for i, rc in enumerate(root_causes, 1):
        cls = md_escape(rc.get("class", ""))
        count = rc.get("count")
        scope = rc.get("scope", "")
        count_scope = md_escape(f"{count} — {scope}" if count not in (None, "") and scope else (scope or count or ""))
        feeds = md_escape(feeds_str(rc.get("feeds")))
        W(f"| {i} | {cls} | {count_scope} | {feeds} |")
    W("")
    W("---")
    W("")


def _render_active_threats(W, active_threats: list[dict[str, Any]]) -> None:
    W("## Part 4 — Active threats (already evidenced)")
    W("")
    if not active_threats:
        W("_No active-threat records present in the input (this is not proof of safety — see data gaps)._")
        W("")
        W("---")
        W("")
        return
    W("| ID | Finding type | Sev | Account | Resource | Indicators | First seen |")
    W("|---|---|---|---|---|---|---|")
    for at in sorted(active_threats, key=lambda a: sev_rank(a.get("severity"))):
        W("| {id} | {ft} | {sev} | {acct} | {res} | {ind} | {seen} |".format(
            id=md_escape(at.get("id", "")),
            ft=md_escape(at.get("finding_type", "")),
            sev=sev_letter(at.get("severity")),
            acct=md_escape(at.get("account_id", "")),
            res=md_escape(at.get("resource", "")),
            ind=md_escape(", ".join(str(x) for x in as_list(at.get("indicators")))),
            seen=md_escape(at.get("first_seen", "")),
        ))
    W("")
    W("---")
    W("")


def _render_gaps(W, gaps: list[dict[str, Any]]) -> None:
    W("## Part 5 — Explicit data gaps (do NOT read absence as safety)")
    W("")
    if not gaps:
        W("_No collection gaps recorded._")
        W("")
        W("---")
        W("")
        return
    W("These blind spots mean several chains are **undercounted, not absent**:")
    W("")
    for i, g in enumerate(gaps, 1):
        area = g.get("area", "")
        reason = g.get("reason", "")
        accts = ", ".join(str(a) for a in as_list(g.get("accounts")))
        acct_txt = f" (accounts: {accts})" if accts else ""
        W(f"{i}. **{area}** — {reason}{acct_txt}")
    W("")
    rec = [g.get("recommended_collection") for g in gaps if g.get("recommended_collection")]
    if rec:
        W("**Recommended targeted collection to close gaps:**")
        W("")
        for cmd in rec:
            W(f"- `{cmd}`")
        W("")
    W("---")
    W("")


def _render_account_reference(W, data: dict[str, Any], meta: dict[str, Any]) -> None:
    W("## Account reference")
    W("")
    # Prefer explicit account records if the merged model was supplied; otherwise derive
    # the account set from technique/kill-chain/active-threat references.
    accounts = data.get("accounts") or []
    if accounts:
        W("| Account ID | Label | Env | Notes |")
        W("|---|---|---|---|")
        for a in accounts:
            W("| {id} | {label} | {env} | {notes} |".format(
                id=md_escape(a.get("account_id", "")),
                label=md_escape(a.get("label", "")),
                env=md_escape(a.get("env", "")),
                notes=md_escape(a.get("notes", "")),
            ))
        W("")
        return

    seen: list[str] = []
    for t in data.get("techniques", []) or []:
        for aid in as_list((t.get("refs") or {}).get("account_ids")):
            if aid not in seen:
                seen.append(str(aid))
    for at in data.get("active_threats", []) or []:
        aid = at.get("account_id")
        if aid and str(aid) not in seen:
            seen.append(str(aid))
    if meta.get("management_account_id") and str(meta["management_account_id"]) not in seen:
        seen.insert(0, str(meta["management_account_id"]))
    if seen:
        W("Accounts referenced by the enumerated chains and techniques:")
        W("")
        W(", ".join(f"`{a}`" for a in seen))
    else:
        W("_No account references present in the input._")
    W("")


# --------------------------------------------------------------------------- main

def main() -> None:
    parser = argparse.ArgumentParser(description="Render an AWS red-team attack-chain Markdown catalog.")
    parser.add_argument("--chains", type=Path, required=True, help="aws_attack_chains/v1 JSON (enumerator output)")
    parser.add_argument("--model", type=Path, default=None, help="Optional aws_attack_model/v1 JSON for extra context")
    parser.add_argument("--customer", type=str, default="", help="Customer name (overrides metadata.customer)")
    parser.add_argument("--now", type=str, default="", help="ISO timestamp for the report header (deterministic)")
    parser.add_argument("--output", type=Path, required=True, help="Output Markdown path")
    args = parser.parse_args()

    data = json.loads(args.chains.read_text(encoding="utf-8"))
    model = None
    if args.model and args.model.exists():
        model = json.loads(args.model.read_text(encoding="utf-8"))

    text = render(data, customer=args.customer, now=args.now, model=model)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
