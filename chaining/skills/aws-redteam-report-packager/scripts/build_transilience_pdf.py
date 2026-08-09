#!/usr/bin/env python3
"""Render an AWS red-team attack-chain catalog in the Transilience dark PDF style.

Final-stage renderer of the AWS red-team attack-chain suite. This is a fully data-driven
generalization of a proven per-customer Transilience generator: ALL content is read from an
``aws_attack_chains/v1`` JSON file (kill_chains / techniques / root_causes / active_threats /
gaps + metadata) rather than being hardcoded.

It reuses the shared Transilience ReportLab base module
(generate_cloudtrail_business_baseline_transilience_pdf) for the design system — dark theme,
BG/CardBox/GradientLine/MetricBox/SectionNumber, gradient page frame, and font registration
(Poppins/Carlito with a Helvetica fallback) — and keeps the two custom flowables ChainFlow (kill-chain pill/arrow diagrams) and HBar (horizontal bars).

Deterministic: no time/date is read at import; pass ``--now`` for the report timestamp.

Usage:
    python3 build_transilience_pdf.py \
        --chains attack_chains.json \
        [--customer "Example Corp"] \
        [--title "AWS Red-Team Attack-Chain Analysis"] \
        [--now 2026-01-15T00:00:00Z] \
        [--logo /path/to/logo.png] \
        [--base-module-dir /path/to/transilience-pdf-toolkit] \
        --output report.pdf
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- base module import
#
# The Transilience design system ships with this skill as the self-contained
# ``transilience_base`` module (no external/customer path dependency). A caller may
# still override it via --base-module-dir or TRANSILIENCE_BASE_MODULE_DIR to reuse an
# alternate module exposing the same primitives.

def _import_base(extra_dir: str | None = None):
    import os
    candidates: list[Path] = []
    if extra_dir:
        candidates.append(Path(extra_dir))
    env_dir = os.environ.get("TRANSILIENCE_BASE_MODULE_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    # Try an override module first (same API surface), else fall back to the vendored base.
    for d in candidates:
        if (d / "generate_cloudtrail_business_baseline_transilience_pdf.py").exists():
            if str(d) not in sys.path:
                sys.path.insert(0, str(d))
            try:
                import generate_cloudtrail_business_baseline_transilience_pdf as base  # noqa: E402
                return base
            except ImportError:
                pass
    # Vendored, customer-agnostic default that lives next to this script.
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import transilience_base as base  # noqa: E402
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "Could not import the Transilience base module. The vendored "
            "'transilience_base.py' should sit next to build_transilience_pdf.py; "
            "or pass --base-module-dir / set TRANSILIENCE_BASE_MODULE_DIR.\n"
            f"Original error: {exc}"
        )
    return base


# --------------------------------------------------------------------------- severity

# Accept both single-letter (C/H/M/L) and full words (critical/high/medium/low).
_SEV_CANON = {
    "c": "critical", "crit": "critical", "critical": "critical",
    "h": "high", "high": "high",
    "m": "medium", "med": "medium", "medium": "medium",
    "l": "low", "low": "low",
    "i": "info", "info": "info", "informational": "info",
}
_SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
_SEV_LETTER = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sev_canon(value: Any) -> str:
    return _SEV_CANON.get(str(value or "").strip().lower(), "medium")


def sev_rank(value: Any) -> int:
    return _SEV_RANK.get(sev_canon(value), 2)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def build_pdf(data: dict[str, Any], output: Path, customer: str, title: str,
              now: str, logo: str | None, base) -> None:
    # Pull the design-system tokens / flowables from the shared base module.
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.platypus import (
        Flowable, Image, KeepTogether, PageBreak, Paragraph,
        SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    BG, BGC, BGCA, GL, BS, BP, BPL = base.BG, base.BGC, base.BGCA, base.GL, base.BS, base.BP, base.BPL
    T1, T2, T3 = base.T1, base.T2, base.T3
    SC, SH, SM, SL = base.SC, base.SH, base.SM, base.SL
    AB, AE, AA = base.AB, base.AE, base.AA
    FH, FM, FR, FB, FBI = base.FH, base.FM, base.FR, base.FB, base.FBI
    PAGE_W, PAGE_H, MARGIN, CW = base.PAGE_W, base.PAGE_H, base.MARGIN, base.CW
    CardBox, GradientLine, MetricBox, SectionNumber = base.CardBox, base.GradientLine, base.MetricBox, base.SectionNumber
    esc, gradient_on_canvas, make_styles = base.esc, base.gradient_on_canvas, base.make_styles

    SEV_COLOR = {"critical": SC, "high": SH, "medium": SM, "low": SL, "info": BPL}

    def sev_color(value: Any) -> colors.Color:
        return SEV_COLOR.get(sev_canon(value), BPL)

    def hx(c: colors.Color) -> str:
        return "#%02x%02x%02x" % (int(c.red * 255), int(c.green * 255), int(c.blue * 255))

    def phtml(text, style):
        return Paragraph(text, style)

    def _tri(c, cx, cy, size, color):
        c.setFillColor(color)
        p = c.beginPath()
        p.moveTo(cx - size / 2, cy - size / 2)
        p.lineTo(cx + size / 2, cy)
        p.lineTo(cx - size / 2, cy + size / 2)
        p.close()
        c.drawPath(p, fill=1, stroke=0)

    # ---- custom flowables (carried over from the per-customer generator) ----
    class ChainFlow(Flowable):
        """Kill-chain diagram: rounded pills connected by arrows, last pill = objective."""

        def __init__(self, steps, accent, width=CW, pill_h=18, vgap=10, font=FM, fsize=7.4):
            super().__init__()
            self.steps = [str(s) for s in steps]
            self.accent = accent
            self.width = width
            self.pill_h = pill_h
            self.vgap = vgap
            self.font = font
            self.fsize = fsize
            self._rows = None
            self._height = pill_h

        def _compute(self):
            arrow_w = 15
            padx = 9
            rows, cur, x = [], [], 0.0
            for s in self.steps:
                tw = stringWidth(s, self.font, self.fsize)
                pw = min(tw + 2 * padx, self.width)
                if cur and (x + arrow_w + pw) > self.width:
                    rows.append(cur)
                    cur, x = [], 0.0
                if cur:
                    x += arrow_w
                cur.append((s, x, pw))
                x += pw
            if cur:
                rows.append(cur)
            self._rows = rows
            self._height = len(rows) * self.pill_h + max(len(rows) - 1, 0) * self.vgap

        def wrap(self, aw, ah):
            self._compute()
            return self.width, self._height

        def draw(self):
            c = self.canv
            y = self._height - self.pill_h
            last_r = len(self._rows) - 1
            for ri, row in enumerate(self._rows):
                last_p = len(row) - 1
                for pi, (s, x, pw) in enumerate(row):
                    obj = (ri == last_r and pi == last_p)
                    c.setFillColor(self.accent if obj else BGCA)
                    c.setStrokeColor(self.accent if obj else BS)
                    c.setLineWidth(1)
                    c.roundRect(x, y, pw, self.pill_h, 4, stroke=1, fill=1)
                    c.setFillColor(T1 if obj else T2)
                    c.setFont(self.font, self.fsize)
                    c.drawCentredString(x + pw / 2, y + self.pill_h / 2 - self.fsize / 2 + 1, s)
                    if pi > 0:
                        _tri(c, x - 15 / 2 - 1, y + self.pill_h / 2, 7, BPL)
                y -= self.pill_h + self.vgap

    class HBar(Flowable):
        """Horizontal bar chart: rows of (label, value, color)."""

        def __init__(self, data, width=CW, label_w=210, bar_h=13, gap=8, unit=""):
            super().__init__()
            self.data = data
            self.width = width
            self.label_w = label_w
            self.bar_h = bar_h
            self.gap = gap
            self.unit = unit
            self._height = max(len(data), 1) * (bar_h + gap)

        def wrap(self, aw, ah):
            return self.width, self._height

        def draw(self):
            c = self.canv
            maxv = max((v for _, v, _ in self.data), default=1) or 1
            track_x = self.label_w + 6
            track_w = self.width - track_x - 46
            y = self._height - self.bar_h
            for label, val, color in self.data:
                c.setFont(FR, 8)
                c.setFillColor(T2)
                c.drawString(0, y + self.bar_h / 2 - 3, label)
                c.setFillColor(GL)
                c.roundRect(track_x, y, track_w, self.bar_h, 2, stroke=0, fill=1)
                bw = max(track_w * (val / maxv), 2)
                c.setFillColor(color)
                c.roundRect(track_x, y, bw, self.bar_h, 2, stroke=0, fill=1)
                c.setFont(FH, 8)
                c.setFillColor(T1)
                c.drawString(track_x + track_w + 6, y + self.bar_h / 2 - 3, f"{val:,}{self.unit}")
                y -= self.bar_h + self.gap

    # ---- styles ----
    styles = make_styles()
    sbase = getSampleStyleSheet()
    styles["sev"] = ParagraphStyle("sev", parent=sbase["BodyText"], fontName=FM, fontSize=7.4, leading=9.5, textColor=T2, alignment=TA_CENTER)
    styles["tc"] = ParagraphStyle("tc", parent=sbase["BodyText"], fontName=FB, fontSize=7.5, leading=9.5, textColor=T2)
    styles["tcb"] = ParagraphStyle("tcb", parent=sbase["BodyText"], fontName=FB, fontSize=7.6, leading=9.6, textColor=T1)
    styles["th"] = ParagraphStyle("th", parent=sbase["BodyText"], fontName=FM, fontSize=7.6, leading=10, textColor=BPL)
    styles["cover_sub"] = ParagraphStyle("cover_sub", parent=sbase["BodyText"], fontName=FM, fontSize=13, leading=18, textColor=T3)

    def sev_cell(sev):
        col = sev_color(sev)
        name = _SEV_LABEL.get(sev_canon(sev), "MED")
        return phtml(f"<font color='{hx(col)}'>&#9679;</font> <font color='{hx(col)}'><b>{name}</b></font>", styles["sev"])

    def add_section(story, num, title_text):
        story.extend([SectionNumber(f"{num:02d}"), phtml(esc(title_text), styles["h1"]), GradientLine(CW, 2), Spacer(1, 4 * mm)])

    def metric_row(items):
        row = [MetricBox(v, l, c) for v, l, c in items]
        t = Table([row], colWidths=[(CW - 24) / 4] * 4)
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 0),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        return t

    def _style_table(t, nrows):
        cmds = [
            ("TEXTCOLOR", (0, 0), (-1, -1), T2),
            ("GRID", (0, 0), (-1, -1), 0.35, GL),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("BACKGROUND", (0, 0), (-1, 0), BGC),
            ("ALIGN", (-1, 0), (-1, -1), "CENTER"),
        ]
        for r in range(1, nrows):
            cmds.append(("BACKGROUND", (0, r), (-1, r), BGCA if r % 2 else BGC))
        t.setStyle(TableStyle(cmds))

    # ---- data extraction ----
    meta = data.get("metadata", {}) or {}
    customer = customer or meta.get("customer") or "AWS Estate"
    title = title or "AWS Red-Team Attack-Chain Analysis"
    kill_chains = data.get("kill_chains", []) or []
    techniques = data.get("techniques", []) or []
    root_causes = data.get("root_causes", []) or []
    active_threats = data.get("active_threats", []) or []
    gaps = data.get("gaps", []) or []

    logo_path = None
    if logo and Path(logo).exists():
        logo_path = logo
    else:
        import os as _os
        _env_logo = _os.environ.get("TRANSILIENCE_LOGO")
        for cand in [
            Path(_env_logo) if _env_logo else None,
            Path(__file__).resolve().parent / "assets" / "logo.png",
        ]:
            if cand and cand.exists():
                logo_path = str(cand)
                break

    # page frame (mirrors the per-customer generator's _page)
    footer = f"TRANSILIENCE AI  —  {customer.upper()} AWS RED-TEAM ATTACK-CHAIN ANALYSIS  —  CONFIDENTIAL"

    def _page(c, doc):
        c.saveState()
        c.setFillColor(BG)
        c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        gradient_on_canvas(c, 0, PAGE_H - 3.5, PAGE_W, 3.5)
        c.setFillColor(colors.Color(105 / 255, 65 / 255, 198 / 255, alpha=0.12))
        c.rect(0, 26, 2.5, PAGE_H - 26, stroke=0, fill=1)
        c.setFillColor(GL)
        c.rect(0, 0, PAGE_W, 26, stroke=0, fill=1)
        c.setFont(FR, 7)
        c.setFillColor(T3)
        c.drawString(MARGIN, 9, footer)
        c.setFont(FR, 8)
        c.setFillColor(T2)
        c.drawRightString(PAGE_W - MARGIN - 14, 9, "Page")
        c.setFont(FH, 9)
        c.setFillColor(BP)
        c.drawRightString(PAGE_W - MARGIN, 9, str(doc.page))
        c.restoreState()

    story: list[Flowable] = []

    # ------------------------------------------------------------------ cover
    header_cells = []
    if logo_path:
        header_cells.append(Image(logo_path, width=20 * mm, height=20 * mm))
    else:
        header_cells.append(phtml("TRANSILIENCE AI", styles["h2"]))
    header_cells.append(phtml("<font color='#8B5CF6'><b>RED TEAM</b></font>", styles["h2"]))
    ht = Table([header_cells], colWidths=[CW - 60 * mm, 60 * mm])
    ht.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT")]))

    cover_title_words = title.upper().split()
    mid = (len(cover_title_words) + 1) // 2
    line1 = " ".join(cover_title_words[:mid]) or "AWS RED-TEAM"
    line2 = " ".join(cover_title_words[mid:])

    story.extend([
        ht,
        Spacer(1, 30 * mm),
        GradientLine(CW, 3),
        Spacer(1, 12 * mm),
        phtml(esc(line1), styles["cover_title"]),
    ])
    if line2:
        story.append(phtml(esc(line2), styles["cover_title"]))
    story.extend([
        Spacer(1, 5 * mm),
        phtml(esc(customer), styles["cover_client"]),
        Spacer(1, 3 * mm),
        phtml("Lateral movement, privilege-escalation &amp; crown-jewel chains", styles["cover_sub"]),
        Spacer(1, 5 * mm),
        GradientLine(CW * 0.35, 2),
        Spacer(1, 8 * mm),
    ])

    live_kc = sum(1 for kc in kill_chains if kc.get("live"))
    scope = f"{meta.get('account_count', '?')} AWS accounts"
    if meta.get("role_name"):
        scope += f" under {meta['role_name']}"
    if meta.get("org_id"):
        scope += f" (org {meta['org_id']})"
    cover_rows = [
        ["REPORT DATE", now or meta.get("generated_at", "")],
        ["CLASSIFICATION", "CONFIDENTIAL — RED TEAM / AUTHORIZED"],
        ["ESTATE SCOPE", scope],
        ["CONTENT", f"{len(kill_chains)} flagship kill chains + {len(techniques)} techniques + {len(root_causes)} root-cause classes"],
        ["EVIDENCE BASIS", meta.get("evidence_basis", "Merged attack model from the AWS red-team collectors")],
        ["GENERATED BY", "Transilience AI internal red-team analysis"],
    ]
    cr = Table([[phtml(esc(k), styles["label"]), phtml(esc(v), styles["small"])] for k, v in cover_rows],
               colWidths=[CW * 0.30, CW * 0.70])
    cr.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.35, GL), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("BACKGROUND", (0, 0), (-1, -1), BGC), ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 6)]))
    story.extend([
        cr,
        Spacer(1, 12 * mm),
        phtml("Authorized internal red-team analysis prepared for remediation prioritization. Grounded entirely "
              "in the merged attack model; nothing invented. Chains marked LIVE have supporting "
              "GuardDuty/investigation evidence and should be treated as confirmed exposure, not theory.",
              styles["notice"]),
        PageBreak(),
    ])

    # ------------------------------------------------------------------ 01 exec summary
    add_section(story, 1, "Executive Summary")
    story.append(metric_row([
        (str(meta.get("account_count", len({a for t in techniques for a in as_list((t.get('refs') or {}).get('account_ids'))}))), "AWS accounts", BPL),
        (str(meta.get("finding_count", meta.get("edge_count", "-"))), "Findings / edges", SH),
        (str(len(techniques)), "Attack techniques", AB),
        (str(len(kill_chains)), "Flagship kill chains", SC),
    ]))
    story.append(Spacer(1, 4 * mm))
    story.append(metric_row([
        (str(meta.get("node_count", "-")), "Attack-graph nodes", AB),
        (str(meta.get("crown_jewel_count", "-")), "Crown jewels", AA),
        (str(live_kc), "LIVE kill chains", SC),
        (str(len(gaps)), "Data gaps", SM),
    ]))
    story.append(Spacer(1, 6 * mm))
    story.append(phtml(
        f"This report enumerates {len(kill_chains)} flagship kill chains and {len(techniques)} atomic techniques "
        f"across {meta.get('account_count', 'the')} AWS accounts, derived entirely from the merged attack model "
        f"({meta.get('node_count', '?')} nodes / {meta.get('edge_count', '?')} edges). Each chain stitches atomic "
        "techniques into a full path from the internet (or a single stolen credential) to a crown jewel. Items "
        "marked LIVE are already evidenced and should be treated as confirmed exposure.", styles["body"]))

    # LIVE / active-threat card
    if active_threats:
        at_sorted = sorted(active_threats, key=lambda a: sev_rank(a.get("severity")))
        at_cap = 12
        at_lines = []
        for at in at_sorted[:at_cap]:
            col = sev_color(at.get("severity"))
            ind = ", ".join(str(x) for x in as_list(at.get("indicators")))
            at_lines.append(
                f"<font color='{hx(col)}'>&#9679;</font> <b>{esc(str(at.get('finding_type', ''))[:60])}</b> on "
                f"<b>{esc(str(at.get('resource', ''))[:48])}</b> (acct {esc(at.get('account_id', ''))})"
                + (f" — {esc(ind[:60])}" if ind else "")
            )
        if len(at_sorted) > at_cap:
            at_lines.append(f"<font color='#E0E3E8'><i>+ {len(at_sorted) - at_cap} more active threats "
                            f"(full list in the companion markdown and JSON).</i></font>")
        story.append(CardBox([
            phtml("Already-happened (LIVE) events", styles["h3"]),
            phtml("<br/>".join(at_lines), styles["body"]),
        ], accent=SC))
        story.append(Spacer(1, 5 * mm))

    # severity distribution across techniques
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in techniques:
        sev_counts[sev_canon(t.get("severity"))] = sev_counts.get(sev_canon(t.get("severity")), 0) + 1
    story.append(phtml("Technique severity distribution", styles["h3"]))
    story.append(HBar([
        ("Critical", sev_counts.get("critical", 0), SC),
        ("High", sev_counts.get("high", 0), SH),
        ("Medium", sev_counts.get("medium", 0), SM),
        ("Low", sev_counts.get("low", 0), SL),
    ], label_w=70))
    story.append(PageBreak())

    # ------------------------------------------------------------------ 02 attack surface / root-cause exposure
    add_section(story, 2, "Attack Surface at a Glance")
    if root_causes:
        story.append(phtml("Exposure counts by misconfiguration root-cause class (each feeds one or more chains):", styles["body"]))
        story.append(Spacer(1, 3 * mm))
        palette = [AA, BPL, SH, SC, AB, SM, AE, SL]
        rc_sorted = sorted(root_causes, key=lambda r: -(r.get("count") or 0))
        bars = []
        for i, rc in enumerate(rc_sorted):
            label = str(rc.get("class", ""))[:34]
            val = rc.get("count") or 0
            try:
                val = int(val)
            except (TypeError, ValueError):
                val = 0
            bars.append((label, val, palette[i % len(palette)]))
        story.append(HBar(bars, label_w=200))
    else:
        story.append(phtml("No root-cause exposure counts present in the input.", styles["body"]))
    story.append(PageBreak())

    # ------------------------------------------------------------------ 03 kill chains
    add_section(story, 3, "Flagship Kill Chains")
    story.append(phtml("End-to-end paths from the internet (or a single stolen credential) to a crown jewel. Each "
                       "stitches multiple atomic techniques from Section 05. The final pill in every flow is the "
                       "objective.", styles["body"]))
    story.append(Spacer(1, 4 * mm))
    if not kill_chains:
        story.append(phtml("No kill chains present in the input.", styles["body"]))
    _kc_sorted = sorted(kill_chains, key=lambda k: (sev_rank(k.get("severity")), -float(k.get("score") or 0)))
    _max_kc = 24
    flagship = _kc_sorted[:_max_kc]
    if len(_kc_sorted) > len(flagship):
        story.append(phtml(f"<font color='#E0E3E8'><i>Showing the top {len(flagship)} of "
                           f"{len(_kc_sorted)} enumerated kill chains (highest severity &#215; score). "
                           f"The complete set is in the companion markdown and JSON.</i></font>",
                           styles["small"]))
        story.append(Spacer(1, 3 * mm))
    for kc in flagship:
        sev = sev_canon(kc.get("severity"))
        col = sev_color(sev)
        badge = " <font color='#EF4444'><b>&#9679; LIVE</b></font>" if kc.get("live") else ""
        # cap steps + text so a single card never exceeds one page (KeepTogether can't split)
        steps = [str(s)[:30] for s in (as_list(kc.get("steps")) or as_list(kc.get("tactic_sequence")))][:9]
        content = [
            phtml(f"<font color='{hx(col)}'><b>{esc(kc.get('id', 'KC'))}</b></font>  "
                  f"<font color='#FFFFFF'><b>{esc(str(kc.get('title', ''))[:110])}</b></font>  "
                  f"<font color='{hx(col)}'>[{_SEV_LABEL.get(sev, 'MED')}]</font>{badge}", styles["body"]),
        ]
        if kc.get("objective"):
            content.append(phtml(f"<font color='#E0E3E8'><i>{esc(str(kc['objective'])[:180])}</i></font>", styles["small"]))
        if steps:
            content.append(ChainFlow(steps, accent=col, width=CW - 32))
        if kc.get("misconfigurations"):
            mtext = "; ".join(str(m) for m in as_list(kc["misconfigurations"]))[:600]
            content.append(phtml(f"<font color='#8B5CF6'><b>Misconfigurations:</b></font> {esc(mtext)}", styles["small"]))
        if kc.get("evidence"):
            content.append(phtml(f"<font color='#10B981'><b>Evidence:</b></font> {esc(str(kc['evidence'])[:400])}", styles["small"]))
        story.append(KeepTogether([CardBox(content, accent=col, width=CW - 14), Spacer(1, 4 * mm)]))
    story.append(PageBreak())

    # ------------------------------------------------------------------ 04 misconfig root causes
    add_section(story, 4, "Misconfiguration Root Causes")
    if root_causes:
        story.append(phtml("The root-cause classes feeding the chains, with scope and the techniques each enables.", styles["body"]))
        story.append(Spacer(1, 3 * mm))
        rows = [[phtml("Misconfiguration class", styles["th"]), phtml("Scope / count", styles["th"]), phtml("Feeds techniques", styles["th"])]]
        for rc in root_causes:
            count = rc.get("count")
            scope_txt = rc.get("scope", "")
            if count not in (None, "") and scope_txt:
                cs = f"{count} — {scope_txt}"
            else:
                cs = str(scope_txt or count or "")
            feeds = ", ".join("#" + str(f).lstrip("#") for f in as_list(rc.get("feeds")))
            rows.append([phtml(esc(rc.get("class", "")), styles["tcb"]), phtml(esc(cs), styles["tc"]), phtml(esc(feeds), styles["tc"])])
        mt = Table(rows, colWidths=[160, 210, CW - 370], repeatRows=1)
        _style_table(mt, len(rows))
        story.append(mt)
    else:
        story.append(phtml("No root-cause records present in the input.", styles["body"]))
    story.append(PageBreak())

    # ------------------------------------------------------------------ 05 techniques by tactic
    add_section(story, 5, "Techniques by Tactic")
    story.append(phtml("Atomic techniques grouped by category. Chain = the move; Misconfigurations = the specific real "
                       "findings (with account IDs / resource identifiers). LIVE = already evidenced in this estate.", styles["body"]))
    story.append(Spacer(1, 4 * mm))

    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for t in techniques:
        cat = t.get("category") or t.get("tactic") or "Uncategorized"
        if cat not in groups:
            groups[cat] = []
            order.append(cat)
        groups[cat].append(t)

    first = True
    for cat in order:
        rows_data = sorted(groups[cat], key=lambda t: t.get("number") or 0)
        blk = [] if first else [Spacer(1, 5 * mm)]
        first = False
        blk.append(phtml(esc(cat), styles["h3"]))
        header = [phtml("#", styles["th"]), phtml("Technique", styles["th"]), phtml("Chain", styles["th"]),
                  phtml("Misconfigurations found", styles["th"]), phtml("Sev", styles["th"])]
        trows = [header]
        for t in rows_data:
            live_badge = " <font color='#EF4444'><b>[LIVE]</b></font>" if t.get("live") else ""
            mlist = [str(m) for m in as_list(t.get("misconfigurations"))]
            misc = "; ".join(mlist)
            if len(misc) > 320:
                misc = misc[:320].rstrip() + f" … (+{max(len(mlist) - 3, 0)} more)"
            trows.append([
                phtml(f"<b>{esc(t.get('number', ''))}</b>", styles["tc"]),
                phtml(f"<b>{esc(str(t.get('title', ''))[:70])}</b>{live_badge}", styles["tc"]),
                phtml(esc(str(t.get("chain", ""))[:180]), styles["tc"]),
                phtml(esc(misc), styles["tc"]),
                sev_cell(t.get("severity")),
            ])
        tt = Table(trows, colWidths=[20, 128, 118, CW - 20 - 128 - 118 - 40, 40], repeatRows=1)
        _style_table(tt, len(trows))
        blk.append(tt)
        if len(rows_data) <= 8:
            story.append(KeepTogether(blk))
        else:
            story.extend(blk)
    story.append(PageBreak())

    # ------------------------------------------------------------------ 06 data gaps
    add_section(story, 6, "Data Gaps & Recommended Collection")
    story.append(CardBox([
        phtml("Do not read absence as safety", styles["h3"]),
        phtml("These blind spots mean several chains are <b>undercounted, not absent</b>.", styles["body"]),
    ], accent=SH))
    story.append(Spacer(1, 4 * mm))
    if gaps:
        for g in gaps:
            area = esc(g.get("area", ""))
            reason = esc(g.get("reason", ""))
            accts = ", ".join(str(a) for a in as_list(g.get("accounts")))
            acct_txt = f" <font color='#E0E3E8'>(accounts: {esc(accts)})</font>" if accts else ""
            story.append(phtml(f"<font color='#8B5CF6'>&#8226;</font> <b>{area}</b> — {reason}{acct_txt}", styles["body"]))
        rec = [g.get("recommended_collection") for g in gaps if g.get("recommended_collection")]
        if rec:
            story.append(Spacer(1, 5 * mm))
            story.append(phtml("Targeted collection to close the gaps", styles["h2"]))
            story.append(Spacer(1, 2 * mm))
            for cmd in rec:
                story.append(phtml(f"<font color='#10B981'>&#8250;</font> <font name='Courier'>{esc(cmd)}</font>", styles["small"]))
    else:
        story.append(phtml("No collection gaps recorded.", styles["body"]))
    story.append(Spacer(1, 8 * mm))
    story.append(phtml("Prepared as authorized internal red-team analysis for remediation prioritization. "
                       "Companion detail: the Markdown attack-chain catalog produced by build_markdown_report.py.",
                       styles["notice"]))

    doc = SimpleDocTemplate(
        str(output), pagesize=A4, rightMargin=MARGIN - 10, leftMargin=MARGIN - 10,
        topMargin=28 * mm, bottomMargin=26 * mm,
        title=f"{customer} {title}", author="Transilience AI",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    doc.build(story, onFirstPage=_page, onLaterPages=_page)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render an AWS red-team attack-chain Transilience PDF.")
    parser.add_argument("--chains", type=Path, required=True, help="aws_attack_chains/v1 JSON (enumerator output)")
    parser.add_argument("--customer", type=str, default="", help="Customer name (overrides metadata.customer)")
    parser.add_argument("--title", type=str, default="", help="Report title (default: AWS Red-Team Attack-Chain Analysis)")
    parser.add_argument("--now", type=str, default="", help="ISO timestamp for the cover (deterministic)")
    parser.add_argument("--logo", type=str, default=None, help="Optional logo image path")
    parser.add_argument("--base-module-dir", type=str, default=None,
                        help="Dir containing generate_cloudtrail_business_baseline_transilience_pdf.py")
    parser.add_argument("--output", type=Path, required=True, help="Output PDF path")
    args = parser.parse_args()

    base = _import_base(args.base_module_dir)
    data = json.loads(args.chains.read_text(encoding="utf-8"))
    build_pdf(data, args.output, customer=args.customer, title=args.title,
              now=args.now, logo=args.logo, base=base)
    print(args.output)


if __name__ == "__main__":
    main()
