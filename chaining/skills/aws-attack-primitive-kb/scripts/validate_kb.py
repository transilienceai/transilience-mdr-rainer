#!/usr/bin/env python3
"""Sanity-check the AWS attack-primitive KB.

Checks:
  - top-level schema/version present
  - every primitive has required fields
  - primitive ids are unique
  - tactic values are from the allowed set
  - MITRE lists are non-empty lists of strings
  - signature has controls[] and conditions[] arrays
  - every `enables` reference resolves to a known primitive id

Prints PASS/FAIL with details. Exit 0 on PASS, 1 on FAIL. stdlib only.
"""

import argparse
import json
import os
import sys

DEFAULT_KB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references",
    "attack_primitives.json",
)

ALLOWED_TACTICS = {
    "reconnaissance", "initial-access", "credential-access",
    "privilege-escalation", "lateral-movement", "persistence",
    "defense-evasion", "collection", "exfiltration", "impact",
}

REQUIRED_FIELDS = ["id", "name", "tactic", "mitre", "category",
                   "default_severity", "signature", "enables", "remediation"]

ALLOWED_SEVERITY = {"critical", "high", "medium", "low"}


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(kb):
    errors = []
    warnings = []

    if kb.get("schema") != "aws_attack_primitive_kb/v1":
        warnings.append("top-level schema is %r (expected 'aws_attack_primitive_kb/v1')"
                        % kb.get("schema"))
    if not kb.get("version"):
        warnings.append("missing top-level 'version'")

    primitives = kb.get("primitives")
    if not isinstance(primitives, list) or not primitives:
        errors.append("'primitives' missing or not a non-empty list")
        return errors, warnings

    seen_ids = set()
    all_ids = set()
    for p in primitives:
        pid = p.get("id")
        if pid:
            all_ids.add(pid)

    for i, p in enumerate(primitives):
        pid = p.get("id") or "<index %d>" % i

        for field in REQUIRED_FIELDS:
            if field not in p:
                errors.append("%s: missing required field '%s'" % (pid, field))

        if p.get("id"):
            if p["id"] in seen_ids:
                errors.append("%s: duplicate primitive id" % pid)
            seen_ids.add(p["id"])

        tactic = p.get("tactic")
        if tactic is not None and tactic not in ALLOWED_TACTICS:
            errors.append("%s: invalid tactic %r" % (pid, tactic))

        sev = p.get("default_severity")
        if sev is not None and sev not in ALLOWED_SEVERITY:
            errors.append("%s: invalid default_severity %r" % (pid, sev))

        mitre = p.get("mitre")
        if not isinstance(mitre, list) or not mitre:
            errors.append("%s: 'mitre' must be a non-empty list" % pid)
        elif not all(isinstance(m, str) for m in mitre):
            errors.append("%s: 'mitre' must contain only strings" % pid)

        sig = p.get("signature")
        if not isinstance(sig, dict):
            errors.append("%s: 'signature' must be an object" % pid)
        else:
            if not isinstance(sig.get("controls"), list):
                errors.append("%s: signature.controls must be a list" % pid)
            if not isinstance(sig.get("conditions"), list):
                errors.append("%s: signature.conditions must be a list" % pid)

        enables = p.get("enables")
        if not isinstance(enables, list):
            errors.append("%s: 'enables' must be a list" % pid)
        else:
            for ref in enables:
                if ref not in all_ids:
                    errors.append("%s: enables -> unknown primitive id %r" % (pid, ref))

    return errors, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kb", default=DEFAULT_KB, help="attack_primitives.json (default: bundled KB)")
    args = ap.parse_args(argv)

    kb = load_json(args.kb)
    errors, warnings = validate(kb)

    primitives = kb.get("primitives") or []
    print("KB: %s" % args.kb)
    print("primitives: %d" % len(primitives))

    for w in warnings:
        print("  WARN: %s" % w)

    if errors:
        print("FAIL (%d error(s)):" % len(errors))
        for e in errors:
            print("  - %s" % e)
        return 1

    print("PASS: all primitives well-formed, ids unique, tactics valid, enables resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
