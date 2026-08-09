#!/usr/bin/env python3
"""Transilience dark-theme PDF design system — self-contained, customer-agnostic.

Reusable ReportLab building blocks (colors, fonts, flowables, styles) for
Transilience-styled reports. Vendored into the report packager so the skill has
no external, customer-specific path dependency. Fonts fall back to Helvetica when
the optional Poppins/Carlito files are not present.
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Flowable, Table, TableStyle  # noqa: F401 (re-export convenience)

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CW = PAGE_W - (2 * MARGIN)

# palette
BG = colors.HexColor("#07040B")
BGC = colors.HexColor("#13101C")
BGCA = colors.HexColor("#1A1625")
GL = colors.HexColor("#1E1A2E")
BS = colors.HexColor("#2A2535")
BP = colors.HexColor("#6941C6")
BPL = colors.HexColor("#8B5CF6")
BM = colors.HexColor("#C9317C")
T1 = colors.HexColor("#FFFFFF")
T2 = colors.HexColor("#F0F2F5")
T3 = colors.HexColor("#E0E3E8")
SC = colors.HexColor("#EF4444")
SH = colors.HexColor("#FB923C")
SM = colors.HexColor("#EAB308")
SL = colors.HexColor("#22C55E")
AB = colors.HexColor("#3B82F6")
AE = colors.HexColor("#10B981")
AA = colors.HexColor("#F59E0B")

FH = "Helvetica-Bold"
FM = "Helvetica-Bold"
FR = "Helvetica"
FB = "Helvetica"
FBB = "Helvetica-Bold"
FBI = "Helvetica-Oblique"

# Optional brand fonts; harmless if absent (Helvetica fallback). Not customer-specific.
_POPPINS_DIR = Path.home() / "Library/Group Containers/UBF8T346G9.Office/FontCache/4/CloudFonts/Poppins"
_CARLITO_DIR = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/libreoffice-headless/libreoffice/LibreOfficeDev.app/Contents/Resources/fonts/truetype"


def register_fonts() -> None:
    global FH, FM, FR, FB, FBB, FBI
    poppins = {
        "Poppins-Bold": _POPPINS_DIR / "26433847794.ttf",
        "Poppins-Medium": _POPPINS_DIR / "24215180385.ttf",
        "Poppins-Regular": _POPPINS_DIR / "27231098576.ttf",
    }
    carlito = {
        "Carlito": _CARLITO_DIR / "Carlito-Regular.ttf",
        "Carlito-Bold": _CARLITO_DIR / "Carlito-Bold.ttf",
        "Carlito-Italic": _CARLITO_DIR / "Carlito-Italic.ttf",
        "Carlito-BoldItalic": _CARLITO_DIR / "Carlito-BoldItalic.ttf",
    }
    try:
        for name, path in {**poppins, **carlito}.items():
            if path.exists():
                pdfmetrics.registerFont(TTFont(name, str(path)))
        if carlito["Carlito"].exists():
            pdfmetrics.registerFontFamily(
                "Carlito", normal="Carlito", bold="Carlito-Bold",
                italic="Carlito-Italic", boldItalic="Carlito-BoldItalic",
            )
        FH = "Poppins-Bold" if poppins["Poppins-Bold"].exists() else FH
        FM = "Poppins-Medium" if poppins["Poppins-Medium"].exists() else FM
        FR = "Poppins-Regular" if poppins["Poppins-Regular"].exists() else FR
        FB = "Carlito" if carlito["Carlito"].exists() else FB
        FBB = "Carlito-Bold" if carlito["Carlito-Bold"].exists() else FBB
        FBI = "Carlito-Italic" if carlito["Carlito-Italic"].exists() else FBI
    except Exception as exc:  # noqa: BLE001
        print(f"warning: using fallback PDF fonts: {exc}")


register_fonts()


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def severity_color(severity: str) -> colors.Color:
    return {"critical": SC, "high": SH, "medium": SM, "low": SL}.get(str(severity).lower(), BPL)


class GradientLine(Flowable):
    def __init__(self, width: float = CW, height: float = 2.0):
        super().__init__()
        self.width = width
        self.height = height

    def draw(self) -> None:
        steps = 80
        for i in range(steps):
            frac = i / max(steps - 1, 1)
            r = 105 + (201 - 105) * frac
            g = 65 + (49 - 65) * frac
            b = 198 + (124 - 198) * frac
            self.canv.setFillColor(colors.Color(r / 255, g / 255, b / 255))
            self.canv.rect(i * self.width / steps, 0, self.width / steps + 0.5, self.height, stroke=0, fill=1)


class SectionNumber(Flowable):
    def __init__(self, number: str):
        super().__init__()
        self.number = number
        self.width = CW
        self.height = 38

    def draw(self) -> None:
        self.canv.setFont(FH, 42)
        self.canv.setFillColor(colors.Color(105 / 255, 65 / 255, 198 / 255, alpha=0.70))
        self.canv.drawString(0, 0, self.number)
        self.canv.setFillColor(colors.Color(140 / 255, 92 / 255, 230 / 255, alpha=0.50))
        self.canv.drawString(1, 1, self.number)


class MetricBox(Flowable):
    def __init__(self, value: str, label: str, accent: colors.Color):
        super().__init__()
        self.value = value
        self.label = label
        self.accent = accent
        self.width = (CW - 24) / 4
        self.height = 58

    def draw(self) -> None:
        c = self.canv
        c.setFillColor(BGC)
        c.setStrokeColor(BS)
        c.roundRect(0, 0, self.width, self.height, 6, stroke=1, fill=1)
        c.setFillColor(self.accent)
        c.roundRect(0, self.height - 4, self.width, 4, 1, stroke=0, fill=1)
        c.setFont(FH, 19)
        c.setFillColor(self.accent)
        c.drawCentredString(self.width / 2, 25, self.value)
        c.setFont(FR, 8)
        c.setFillColor(T2)
        c.drawCentredString(self.width / 2, 9, self.label.upper())


class CardBox(Flowable):
    def __init__(self, content, accent: colors.Color = BPL, width: float = CW, padding: float = 10):
        super().__init__()
        self.content = content
        self.accent = accent
        self.width = width
        self.padding = padding
        self._height = 80

    def wrap(self, availWidth: float, availHeight: float):
        y = self.padding
        inner_w = self.width - (2 * self.padding) - 8
        for flowable in self.content:
            _, h = flowable.wrap(inner_w, availHeight)
            y += h + 5
        self._height = y + self.padding
        return self.width, self._height

    def draw(self) -> None:
        c = self.canv
        c.setFillColor(BGC)
        c.setStrokeColor(BS)
        c.roundRect(0, 0, self.width, self._height, 6, stroke=1, fill=1)
        c.setFillColor(self.accent)
        c.roundRect(0, 0, 4, self._height, 2, stroke=0, fill=1)
        y = self._height - self.padding
        inner_w = self.width - (2 * self.padding) - 8
        for flowable in self.content:
            _, h = flowable.wrap(inner_w, self._height)
            y -= h
            flowable.drawOn(c, self.padding + 8, y)
            y -= 5


def gradient_on_canvas(c, x: float, y: float, w: float, h: float) -> None:
    steps = 80
    for i in range(steps):
        frac = i / max(steps - 1, 1)
        r = 105 + (201 - 105) * frac
        g = 65 + (49 - 65) * frac
        b = 198 + (124 - 198) * frac
        c.setFillColor(colors.Color(r / 255, g / 255, b / 255))
        c.rect(x + i * w / steps, y, w / steps + 0.5, h, stroke=0, fill=1)


def make_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("cover_title", parent=base["Normal"], fontName=FH, fontSize=34, leading=41, textColor=T1, alignment=TA_LEFT, spaceAfter=0),
        "cover_client": ParagraphStyle("cover_client", parent=base["Normal"], fontName=FM, fontSize=18, leading=24, textColor=BPL, alignment=TA_LEFT),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=FH, fontSize=20, leading=26, textColor=T1, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=FM, fontSize=15, leading=20, textColor=T1, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName=FM, fontSize=12, leading=16, textColor=BPL, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName=FB, fontSize=10.5, leading=15, textColor=T2, spaceAfter=7),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontName=FB, fontSize=8.5, leading=11, textColor=T2),
        "label": ParagraphStyle("label", parent=base["BodyText"], fontName=FR, fontSize=8, leading=11, textColor=T3),
        "table_header": ParagraphStyle("table_header", parent=base["BodyText"], fontName=FM, fontSize=8, leading=10, textColor=BPL),
        "table_cell": ParagraphStyle("table_cell", parent=base["BodyText"], fontName=FB, fontSize=7.4, leading=9.2, textColor=T2),
        "metric_label": ParagraphStyle("metric_label", parent=base["BodyText"], fontName=FM, fontSize=9, leading=12, textColor=BPL),
        "notice": ParagraphStyle("notice", parent=base["BodyText"], fontName=FBI, fontSize=9, leading=13, textColor=T3),
        "toc_num": ParagraphStyle("toc_num", parent=base["BodyText"], fontName=FH, fontSize=13, leading=16, textColor=BP, alignment=TA_LEFT),
        "toc_title": ParagraphStyle("toc_title", parent=base["BodyText"], fontName=FM, fontSize=10.5, leading=16, textColor=T1),
        "toc_page": ParagraphStyle("toc_page", parent=base["BodyText"], fontName=FH, fontSize=10.5, leading=16, textColor=T1, alignment=TA_CENTER),
    }
