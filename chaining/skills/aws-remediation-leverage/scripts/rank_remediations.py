#!/usr/bin/env python3
"""Rank AWS remediations by how many attack chains each one severs.

Consumes an `aws_attack_chains/v1` file (from aws-attack-chain-enumerator) and the
attack-primitive KB, and answers: *which single fixes break the most chains?* — so a
team spends remediation effort where it has maximum blast-radius reduction.

Two views:
  1. Leverage table  — per control/remediation: how many chains it breaks (kill chains +
     techniques), severity-weighted impact, crown jewels protected, accounts touched.
  2. Greedy roadmap  — a marginal set-cover: pick the highest-leverage fix, remove the
     chains it breaks, re-rank on the remainder, repeat. This is the do-in-this-order plan;
     each step lists the *marginal* chains it newly severs and cumulative coverage.

A chain is "broken" by fixing any single control it depends on (a chain needs all its
links; removing one severs it). Stdlib only. Deterministic. No datetime.now (pass --now).
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

DEFAULT_KB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "aws-attack-primitive-kb", "references", "attack_primitives.json",
)
CONTROL_RE = re.compile(r"\b[A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)+\b")   # e.g. RDS_PUBLIC_ACCESS
ACCT_RE = re.compile(r"\b(\d{12})\b")
SEV_W = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def load_kb(path):
    try:
        kb = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}, {}
    control_to_remediation, control_to_prims, prim_controls = {}, {}, {}
    for p in kb.get("primitives", []):
        controls = p.get("signature", {}).get("controls", []) or []
        prim_controls[p["id"]] = controls
        for c in controls:
            control_to_remediation.setdefault(c, [])
            if p.get("remediation") and p["remediation"] not in control_to_remediation[c]:
                control_to_remediation[c].append(p["remediation"])
            control_to_prims.setdefault(c, set()).add(p["id"])
    return {"remediation": control_to_remediation, "prims": control_to_prims,
            "prim_controls": prim_controls}, kb


def controls_in(text_items):
    controls = set()
    for t in text_items or []:
        controls |= set(CONTROL_RE.findall(str(t)))
    return controls


def accts_in(text_items):
    accts = set()
    for t in text_items or []:
        accts |= set(ACCT_RE.findall(str(t)))
    return accts


def build_chains(data, kbidx):
    """Unify kill_chains + techniques into one list of {id, kind, severity, weight, controls, crown, accts}."""
    chains = []
    for kc in data.get("kill_chains", []):
        controls = controls_in(kc.get("misconfigurations"))
        chains.append({
            "id": kc.get("id"), "kind": "kill_chain", "severity": (kc.get("severity") or "medium").lower(),
            "weight": SEV_W.get((kc.get("severity") or "medium").lower(), 2),
            "controls": controls, "crown": kc.get("crown_jewel_id"),
            "accts": accts_in(kc.get("misconfigurations")),
        })
    for t in data.get("techniques", []):
        controls = controls_in(t.get("misconfigurations"))
        pid = t.get("primitive_id")
        if pid and pid in kbidx.get("prim_controls", {}):
            controls |= set(kbidx["prim_controls"][pid])
        chains.append({
            "id": t.get("id"), "kind": "technique", "severity": (t.get("severity") or "medium").lower(),
            "weight": SEV_W.get((t.get("severity") or "medium").lower(), 2),
            "controls": controls, "crown": None,
            "accts": accts_in(t.get("misconfigurations")),
        })
    # only chains with at least one identifiable control are remediable here
    return [c for c in chains if c["controls"]]


def leverage_table(chains, kbidx):
    controls = sorted({c for ch in chains for c in ch["controls"]})
    rows = []
    for ctrl in controls:
        broken = [ch for ch in chains if ctrl in ch["controls"]]
        by_sev = {}
        for ch in broken:
            by_sev[ch["severity"]] = by_sev.get(ch["severity"], 0) + 1
        rows.append({
            "control": ctrl,
            "remediation": " / ".join(kbidx.get("remediation", {}).get(ctrl, [])) or "(no KB remediation mapped)",
            "chains_broken": len(broken),
            "kill_chains": sum(1 for ch in broken if ch["kind"] == "kill_chain"),
            "techniques": sum(1 for ch in broken if ch["kind"] == "technique"),
            "by_severity": by_sev,
            "impact_score": sum(ch["weight"] for ch in broken),
            "crown_jewels_protected": sorted({ch["crown"] for ch in broken if ch["crown"]}),
            "accounts": sorted({a for ch in broken for a in ch["accts"]}),
        })
    rows.sort(key=lambda r: (-r["impact_score"], -r["chains_broken"], r["control"]))
    return rows


def greedy_roadmap(chains, kbidx, max_steps):
    total = len(chains)
    remaining = {i for i in range(total)}
    roadmap, covered = [], set()
    step = 0
    while remaining and step < max_steps:
        candidates = {c for i in remaining for c in chains[i]["controls"]}
        best, best_gain, best_set = None, -1, set()
        for c in sorted(candidates):
            cover = {i for i in remaining if c in chains[i]["controls"]}
            gain = sum(chains[i]["weight"] for i in cover)
            if gain > best_gain or (gain == best_gain and len(cover) > len(best_set)):
                best, best_gain, best_set = c, gain, cover
        if not best or not best_set:
            break
        step += 1
        covered |= best_set
        remaining -= best_set
        roadmap.append({
            "step": step, "control": best,
            "remediation": " / ".join(kbidx.get("remediation", {}).get(best, [])) or "(no KB remediation mapped)",
            "marginal_chains_severed": len(best_set),
            "marginal_impact": best_gain,
            "cumulative_chains_severed": len(covered),
            "cumulative_pct": round(100.0 * len(covered) / total, 1) if total else 0.0,
        })
    return roadmap, total, len(covered)


def build_compounding(chains, kb, top):
    """KB-derived 'misconfiguration A enables misconfiguration B' edges, scoped to the
    controls actually present in these chains. This is the compounding matrix: it shows how
    one finding feeds the next, so fixing the *source* control cuts the compounding early."""
    from collections import Counter
    chain_count = Counter(c for ch in chains for c in ch["controls"])
    prims = (kb.get("primitives", []) if kb else [])
    prim_by_id = {p["id"]: p for p in prims}
    edges, seen = [], set()
    for p in prims:
        a_controls = p.get("signature", {}).get("controls", []) or []
        for q in p.get("enables", []) or []:
            qp = prim_by_id.get(q)
            if not qp:
                continue
            for a in a_controls:
                if chain_count.get(a, 0) == 0:
                    continue  # source control not present in this estate's chains
                for b in qp.get("signature", {}).get("controls", []) or []:
                    if a == b or (a, b) in seen:
                        continue
                    seen.add((a, b))
                    edges.append({"from": a, "to": b, "kb_confirmed": True,
                                  "via_primitive": p["id"],
                                  "from_chains": chain_count.get(a, 0),
                                  "to_chains": chain_count.get(b, 0)})
    edges.sort(key=lambda e: (-e["from_chains"], -e["to_chains"], e["from"], e["to"]))
    return edges[:top] if top else edges


def build(data, kb_path, now, top):
    kbidx, kb = load_kb(kb_path)
    chains = build_chains(data, kbidx)
    table = leverage_table(chains, kbidx)
    roadmap, total, covered = greedy_roadmap(chains, kbidx, top)
    compounding = build_compounding(chains, kb, top)
    meta_in = data.get("metadata", {})
    return {
        "schema": "aws_remediation_leverage/v1",
        "metadata": {
            "customer": meta_in.get("customer", ""), "generated_at": now,
            "source_chains": {"kill_chains": len(data.get("kill_chains", [])),
                              "techniques": len(data.get("techniques", []))},
            "remediable_chains": total,
            "distinct_controls": len(table),
            "roadmap_steps": len(roadmap),
            "roadmap_cumulative_pct": roadmap[-1]["cumulative_pct"] if roadmap else 0.0,
            "compounding_edges": len(compounding),
        },
        "remediations": table[:top] if top else table,
        "remediations_full_count": len(table),
        "roadmap": roadmap,
        "compounding_matrix": compounding,
    }


def markdown(out):
    m = out["metadata"]
    L = ["# AWS Remediation Leverage — biggest bang for the buck", "",
         f"- Generated: {m.get('generated_at','')}",
         f"- Remediable chains analyzed: **{m['remediable_chains']}** "
         f"(kill chains {m['source_chains']['kill_chains']}, techniques {m['source_chains']['techniques']})",
         f"- A single-fix roadmap of **{m['roadmap_steps']}** steps severs **{m['roadmap_cumulative_pct']}%** of them.", "",
         "## Do-in-this-order roadmap (greedy marginal cover)", "",
         "| # | Fix (control) | Marginal chains severed | Cumulative % | Remediation |",
         "|---|---|---|---|---|"]
    for r in out["roadmap"]:
        L.append(f"| {r['step']} | `{r['control']}` | {r['marginal_chains_severed']} | "
                 f"{r['cumulative_pct']}% | {r['remediation'][:90]} |")
    L += ["", "## Highest-leverage fixes (independent ranking)", "",
          "| Control | Chains broken | Crit/High | Crown jewels | Accounts | Remediation |",
          "|---|---|---|---|---|---|"]
    for r in out["remediations"]:
        ch = r["by_severity"]
        crit_high = f"{ch.get('critical',0)}C/{ch.get('high',0)}H"
        L.append(f"| `{r['control']}` | {r['chains_broken']} | {crit_high} | "
                 f"{len(r['crown_jewels_protected'])} | {len(r['accounts'])} | {r['remediation'][:80]} |")
    cm = out.get("compounding_matrix", [])
    if cm:
        L += ["", "## Compounding matrix (misconfiguration A enables B)", "",
              "Fixing the **A** control cuts the compounding before it reaches **B**.", "",
              "| A (fix here) | enables → | B | A appears in chains | source |",
              "|---|---|---|---|---|"]
        for e in cm:
            L.append(f"| `{e['from']}` | → | `{e['to']}` | {e['from_chains']} | "
                     f"{'KB' if e['kb_confirmed'] else 'observed'} |")
    return "\n".join(L) + "\n"


def _self_test():
    sample = {"metadata": {"customer": "sample"},
              "kill_chains": [
                  {"id": "KC-1", "severity": "critical", "crown_jewel_id": "s3:1:a",
                   "misconfigurations": ["RDS_PUBLIC_ACCESS on x (acct 111111111111)", "EC2_IMDSV2_NOT_ENFORCED on y"]},
                  {"id": "KC-2", "severity": "high", "crown_jewel_id": "s3:1:b",
                   "misconfigurations": ["EC2_IMDSV2_NOT_ENFORCED on z (acct 222222222222)"]}],
              "techniques": [
                  {"id": "T-1", "severity": "high", "primitive_id": "ca_imds_theft",
                   "misconfigurations": ["EC2_IMDSV2_NOT_ENFORCED on q"]}]}
    out = build(sample, "/nonexistent-kb.json", "1970-01-01T00:00:00Z", 10)
    assert out["metadata"]["remediable_chains"] == 3, out
    top = out["roadmap"][0]["control"]
    assert top == "EC2_IMDSV2_NOT_ENFORCED", ("expected IMDS as top-leverage", out["roadmap"])
    print("self_test: PASS  top-leverage =", top, "| roadmap steps =", len(out["roadmap"]),
          "| cumulative% =", out["metadata"]["roadmap_cumulative_pct"])


def main():
    ap = argparse.ArgumentParser(description="Rank AWS remediations by attack chains severed.")
    ap.add_argument("--chains", type=Path, help="aws_attack_chains/v1 JSON from the enumerator.")
    ap.add_argument("--kb", default=DEFAULT_KB, help="attack_primitives.json (for remediation text).")
    ap.add_argument("--now", default="", help="ISO-8601 timestamp (no datetime.now).")
    ap.add_argument("--top", type=int, default=20, help="Rows/roadmap steps to keep (default 20).")
    ap.add_argument("--output", type=Path, default=Path("remediation_leverage.json"))
    ap.add_argument("--markdown", type=Path, help="Optional Markdown report path.")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        _self_test(); return
    if not args.chains:
        ap.error("--chains is required (or use --self-test)")
    data = json.loads(args.chains.read_text(encoding="utf-8"))
    out = build(data, args.kb, args.now, args.top)
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(markdown(out), encoding="utf-8")
    m = out["metadata"]
    print(f"wrote {args.output} :: remediable_chains={m['remediable_chains']} "
          f"controls={m['distinct_controls']} roadmap={m['roadmap_steps']} "
          f"cover={m['roadmap_cumulative_pct']}%")
    for r in out["roadmap"][:5]:
        print(f"  #{r['step']} {r['control']}  +{r['marginal_chains_severed']} chains  -> {r['cumulative_pct']}% cumulative")


if __name__ == "__main__":
    main()
