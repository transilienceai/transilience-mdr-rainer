#!/usr/bin/env python3
"""Lightweight public-release checks for MDR skills."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOTS = [
    ROOT / "detection" / "skills",
    ROOT / "investigation" / "skills",
    ROOT / "collection" / "skills",
    ROOT / "reporting" / "skills",
    ROOT / "chaining" / "skills",
]

PRIVATE_PATTERNS = [
    re.compile(r"/Users/"),
    re.compile(r"~/.codex"),
    re.compile(r"\bmodal\b", re.IGNORECASE),
    re.compile(r"\baucctus\b", re.IGNORECASE),
    re.compile(r"\bstraive\b", re.IGNORECASE),
    re.compile(r"\bchcs\b", re.IGNORECASE),
    re.compile(r"\bfinmont\b", re.IGNORECASE),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*="),
    re.compile(r"AWS_ACCESS_KEY_ID\s*="),
    re.compile(r"client_secret", re.IGNORECASE),
]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_skill(path: Path) -> None:
    skill = path / "SKILL.md"
    if not skill.is_file():
        fail(f"missing SKILL.md in {path.relative_to(ROOT)}")
    text = skill.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        fail(f"missing YAML frontmatter in {skill.relative_to(ROOT)}")
    if "\nname:" not in text or "\ndescription:" not in text:
        fail(f"frontmatter must include name and description in {skill.relative_to(ROOT)}")


def check_private_markers(path: Path) -> None:
    if path == Path(__file__).resolve():
        return
    if ".git" in path.parts:
        return
    if "outputs" in path.parts:  # gitignored generated artifacts, not shipped
        return
    if path.is_dir() or path.suffix in {".pyc", ".png", ".jpg", ".jpeg", ".gif"}:
        return
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    for pattern in PRIVATE_PATTERNS:
        if pattern.search(text):
            fail(f"private marker {pattern.pattern!r} in {path.relative_to(ROOT)}")


def main() -> None:
    for root in SKILL_ROOTS:
        if not root.is_dir():
            continue
        for skill_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            check_skill(skill_dir)
    for path in ROOT.rglob("*"):
        check_private_markers(path)
    print("skill_linter: ok")


if __name__ == "__main__":
    main()
