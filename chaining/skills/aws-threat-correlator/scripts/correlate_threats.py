#!/usr/bin/env python3
"""Correlate live GuardDuty / investigation threats onto an attack-chain model.

Reads an `aws_attack_chains/v1` file plus GuardDuty findings and/or investigation
JSON, turns findings into ActiveThreat records, marks any kill-chain / technique
`live=true` when its accounts/resources/crown-jewel intersect an active threat,
appends a short evidence string, populates the top-level `active_threats` array,
and rolls up a threat-actor indicator list.

Preserves everything else in the chains file. stdlib only, deterministic
(no clock reads; timestamp comes from --now).

Input shapes handled:
  - raw GuardDuty GetFindings : {"Findings": [ {...}, ... ]}
  - raw GuardDuty ListFindings: {"FindingIds": [ ... ]}   (ids only -> skipped w/ note)
  - simplified               : {"findings": [ {...}, ... ]}
  - investigation passthrough: {"active_threats": [ ActiveThreat, ... ]}
  - a bare list              : [ {...}, ... ]
  - anything else            : skipped with a note (never crash)
"""

import argparse
import glob
import json
import os
import sys


# ----------------------------------------------------------------------------- helpers

def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def expand_inputs(spec):
    """A dir, a glob, or a single file -> sorted list of .json file paths."""
    if not spec:
        return []
    paths = []
    if os.path.isdir(spec):
        paths = glob.glob(os.path.join(spec, "**", "*.json"), recursive=True)
    else:
        paths = glob.glob(spec, recursive=True)
        if not paths and os.path.isfile(spec):
            paths = [spec]
    return sorted(set(paths))


def ci_get(d, *keys):
    """Case-insensitive first-match get from a dict."""
    if not isinstance(d, dict):
        return None
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in lower:
            return lower[k.lower()]
    return None


def normalize_severity(sev):
    if isinstance(sev, str):
        s = sev.strip().lower()
        if s in ("critical", "high", "medium", "low"):
            return s
        try:
            sev = float(s)
        except ValueError:
            return "medium"
    if isinstance(sev, (int, float)):
        if sev >= 8.0:
            return "critical"
        if sev >= 7.0:
            return "high"
        if sev >= 4.0:
            return "medium"
        return "low"
    return "medium"


def recursive_find(obj, key_names, out):
    """Collect string values of any key in key_names (case-insensitive), anywhere."""
    lowered = {k.lower() for k in key_names}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in lowered:
                if isinstance(v, str) and v:
                    out.add(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item:
                            out.add(item)
            recursive_find(v, key_names, out)
    elif isinstance(obj, list):
        for item in obj:
            recursive_find(item, key_names, out)


# ----------------------------------------------------------------------------- parsing

def parse_finding_to_threat(f):
    """Map one GuardDuty (or simplified) finding dict -> ActiveThreat record."""
    account_id = ci_get(f, "AccountId", "account_id") or "unknown"

    finding_type = ci_get(f, "Type", "finding_type") or "unknown"

    sev = ci_get(f, "Severity", "severity")
    severity = normalize_severity(sev)

    first_seen = (
        ci_get(f, "CreatedAt", "first_seen", "createdAt")
        or ci_get(ci_get(f, "Service", "service") or {}, "EventFirstSeen", "eventFirstSeen")
        or ""
    )

    fid = ci_get(f, "Id", "id", "FindingId") or ""

    # indicators: explicit list wins, else harvest IPs / keys / user names.
    indicators = []
    explicit = ci_get(f, "indicators")
    if isinstance(explicit, list):
        indicators = [str(i) for i in explicit if isinstance(i, (str, int))]
    else:
        found = set()
        recursive_find(f, ["IpAddressV4", "ipAddressV4", "AccessKeyId", "accessKeyId"], found)
        recursive_find(f, ["UserName", "userName", "PrincipalId", "principalId"], found)
        indicators = sorted(found)

    # resource + node mappings.
    # Only a *string* "resource" is the simplified field; a "Resource"/"resource"
    # dict is the raw GuardDuty object and must be derived, not used directly.
    resource = ci_get(f, "resource")
    if not isinstance(resource, str):
        resource = None
    maps_to_nodes = ci_get(f, "maps_to_nodes")
    if not isinstance(maps_to_nodes, list):
        maps_to_nodes = []
    if not resource or not maps_to_nodes:
        r, nodes = derive_resource_nodes(f, account_id)
        if not resource:
            resource = r
        if not maps_to_nodes:
            maps_to_nodes = nodes

    return {
        "id": fid or ("gd:%s:%s" % (account_id, finding_type)),
        "account_id": account_id,
        "finding_type": finding_type,
        "severity": severity,
        "resource": resource or "",
        "indicators": indicators,
        "first_seen": first_seen,
        "maps_to_nodes": maps_to_nodes,
    }


def derive_resource_nodes(f, account_id):
    """Best-effort resource identifier + candidate model node ids from a finding."""
    res = ci_get(f, "Resource", "resource") or {}
    if not isinstance(res, dict):
        return "", []
    nodes = []
    resource_id = ""

    rtype = ci_get(res, "ResourceType", "resourceType") or ""

    inst = ci_get(res, "InstanceDetails", "instanceDetails")
    if isinstance(inst, dict):
        iid = ci_get(inst, "InstanceId", "instanceId")
        if iid:
            resource_id = resource_id or iid
            nodes.append("ec2_instance:%s:%s" % (account_id, iid))

    s3 = ci_get(res, "S3BucketDetails", "s3BucketDetails")
    if isinstance(s3, list):
        for b in s3:
            name = ci_get(b, "Name", "name")
            if name:
                resource_id = resource_id or name
                nodes.append("s3_bucket:%s:%s" % (account_id, name))

    ak = ci_get(res, "AccessKeyDetails", "accessKeyDetails")
    if isinstance(ak, dict):
        kid = ci_get(ak, "AccessKeyId", "accessKeyId")
        uname = ci_get(ak, "UserName", "userName")
        if kid:
            resource_id = resource_id or kid
            nodes.append("access_key:%s:%s" % (account_id, kid))
        if uname:
            resource_id = resource_id or uname
            nodes.append("iam_user:%s:%s" % (account_id, uname))

    rds = ci_get(res, "RdsDbInstanceDetails", "rdsDbInstanceDetails")
    if isinstance(rds, dict):
        dbid = ci_get(rds, "DbInstanceIdentifier", "dbInstanceIdentifier")
        if dbid:
            resource_id = resource_id or dbid
            nodes.append("rds_instance:%s:%s" % (account_id, dbid))

    if not resource_id and rtype:
        resource_id = rtype
    return resource_id, nodes


def ingest_document(doc, path, notes):
    """Return a list of ActiveThreat records from one loaded JSON document."""
    if isinstance(doc, list):
        return [parse_finding_to_threat(x) for x in doc if isinstance(x, dict)]

    if isinstance(doc, dict):
        # investigation passthrough: already-shaped ActiveThreats
        at = ci_get(doc, "active_threats")
        if isinstance(at, list) and at:
            out = []
            for x in at:
                if isinstance(x, dict):
                    x.setdefault("indicators", [])
                    x.setdefault("maps_to_nodes", [])
                    out.append(x)
            return out

        findings = ci_get(doc, "Findings")           # raw GetFindings
        if isinstance(findings, list):
            return [parse_finding_to_threat(x) for x in findings if isinstance(x, dict)]

        findings = ci_get(doc, "findings")           # simplified
        if isinstance(findings, list):
            return [parse_finding_to_threat(x) for x in findings if isinstance(x, dict)]

        if ci_get(doc, "FindingIds") is not None:    # ListFindings ids only
            notes.append("SKIP %s: ListFindings shape has ids only, no finding detail"
                         % path)
            return []

    notes.append("SKIP %s: unrecognized shape (no Findings/findings/active_threats)"
                 % path)
    return []


def collect_threats(specs, notes):
    threats = []
    for spec in specs:
        for path in expand_inputs(spec):
            try:
                doc = load_json(path)
            except (ValueError, OSError) as e:
                notes.append("SKIP %s: could not read/parse JSON (%s)" % (path, e))
                continue
            threats.extend(ingest_document(doc, path, notes))
    return threats


# ----------------------------------------------------------------------------- correlation

def killchain_tokens(kc):
    accounts, resources = set(), set()
    for nid in kc.get("node_path") or []:
        if isinstance(nid, str):
            resources.add(nid)
            parts = nid.split(":")
            if len(parts) >= 2 and parts[1].isdigit():
                accounts.add(parts[1])
    for aid in kc.get("account_ids") or []:
        accounts.add(aid)
    cj = kc.get("crown_jewel_id") or ""
    if cj:
        resources.add(cj)
    return accounts, resources, cj


def technique_tokens(t):
    refs = t.get("refs") or {}
    accounts = set(refs.get("account_ids") or [])
    resources = set(refs.get("resources") or [])
    return accounts, resources, ""


def threat_tokens(threat):
    accounts = {threat.get("account_id")} - {None, ""}
    resources = set(threat.get("maps_to_nodes") or [])
    if threat.get("resource"):
        resources.add(threat["resource"])
    return accounts, resources


def matching_threats(el_accounts, el_resources, el_cj, threats):
    hits = []
    for t in threats:
        t_acc, t_res = threat_tokens(t)
        if (el_accounts & t_acc) or (el_resources & t_res) or (
            el_cj and el_cj in (t.get("maps_to_nodes") or [])
        ):
            hits.append(t)
    return hits


def evidence_string(hits):
    parts = []
    for t in sorted(hits, key=lambda x: x.get("id", "")):
        ind = ", ".join((t.get("indicators") or [])[:2])
        tag = "%s" % t.get("finding_type", "unknown")
        if ind:
            tag += " (%s)" % ind
        tag += " [finding %s]" % t.get("id", "")
        parts.append(tag)
    return "GuardDuty: " + "; ".join(parts)


def append_evidence(el, text):
    existing = el.get("evidence")
    if existing:
        el["evidence"] = existing + " | " + text
    else:
        el["evidence"] = text
    el["live_evidence"] = text


def correlate(chains, threats):
    live_kc = 0
    live_tech = 0

    for kc in chains.get("kill_chains") or []:
        acc, res, cj = killchain_tokens(kc)
        hits = matching_threats(acc, res, cj, threats)
        if hits:
            kc["live"] = True
            append_evidence(kc, evidence_string(hits))
            live_kc += 1

    for t in chains.get("techniques") or []:
        acc, res, cj = technique_tokens(t)
        hits = matching_threats(acc, res, cj, threats)
        if hits:
            t["live"] = True
            append_evidence(t, evidence_string(hits))
            live_tech += 1

    return live_kc, live_tech


def merge_active_threats(chains, threats):
    existing = {}
    for t in chains.get("active_threats") or []:
        if isinstance(t, dict) and t.get("id"):
            existing[t["id"]] = t
    for t in threats:
        existing[t["id"]] = t
    chains["active_threats"] = sorted(existing.values(), key=lambda x: x.get("id", ""))


def rollup_indicators(threats):
    ips, actors, keys = set(), set(), set()
    for t in threats:
        for ind in t.get("indicators") or []:
            s = str(ind)
            if _looks_like_ip(s):
                ips.add(s)
            elif s.startswith("AKIA") or s.startswith("ASIA"):
                keys.add(s)
            else:
                actors.add(s)
    return {
        "source_ips": sorted(ips),
        "actors": sorted(actors),
        "access_keys": sorted(keys),
    }


def _looks_like_ip(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


# ----------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chains", required=True, help="aws_attack_chains/v1 JSON")
    ap.add_argument("--guardduty", action="append", default=[],
                    help="GuardDuty findings JSON dir/glob/file (repeatable)")
    ap.add_argument("--ingest", action="append", default=[],
                    help="investigation JSON dir/glob/file (repeatable)")
    ap.add_argument("--now", required=True, help="ISO-8601 timestamp for this run")
    ap.add_argument("--output", required=True, help="output attack_chains.json path")
    args = ap.parse_args(argv)

    chains = load_json(args.chains)
    if chains.get("schema") != "aws_attack_chains/v1":
        sys.stderr.write("WARN: chains schema is %r, expected 'aws_attack_chains/v1'\n"
                         % chains.get("schema"))

    notes = []
    threats = collect_threats(list(args.guardduty) + list(args.ingest), notes)

    # de-dupe threats by id (stable, keep last)
    dedup = {}
    for t in threats:
        dedup[t["id"]] = t
    threats = sorted(dedup.values(), key=lambda x: x.get("id", ""))

    live_kc, live_tech = correlate(chains, threats)
    merge_active_threats(chains, threats)
    chains["threat_actor_indicators"] = rollup_indicators(threats)

    md = chains.setdefault("metadata", {})
    md["correlated_at"] = args.now
    md["active_threat_count"] = len(threats)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(chains, fh, indent=2, sort_keys=False)
        fh.write("\n")

    ind = chains["threat_actor_indicators"]
    print("threat correlation summary")
    print("  active threats parsed : %d" % len(threats))
    print("  kill_chains -> live   : %d" % live_kc)
    print("  techniques  -> live   : %d" % live_tech)
    print("  indicator rollup      : %d ip(s), %d actor(s), %d key(s)"
          % (len(ind["source_ips"]), len(ind["actors"]), len(ind["access_keys"])))
    if notes:
        print("  notes:")
        for n in notes:
            print("    - %s" % n)
    print("  wrote                 : %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
