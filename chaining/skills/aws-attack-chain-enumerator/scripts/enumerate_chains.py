#!/usr/bin/env python3
"""Enumerate AWS attack chains from a merged `aws_attack_model/v1` graph.

Reads a merged attack model and the attack-primitive KB and produces an
`aws_attack_chains/v1` document: kill chains (entry -> crown jewel paths),
techniques (the atomic primitive catalog actually present in the model),
root causes (findings rolled up by control), plus pass-through active_threats
and gaps.

Pure Python, stdlib only, deterministic. Never calls datetime.now at import
time; any timestamp comes from --now.
"""
import argparse
import json
import os
import sys


OUT_SCHEMA = "aws_attack_chains/v1"

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0, None: 0}
SEV_NAME = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "low"}
SEV_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}

# Edge traversal ordering: a valid kill chain follows non-decreasing rank
# exposes -> credential -> privesc -> reach.
EDGE_RANK = {
    "exposes": 0,
    "has_credential": 1,
    "can_assume": 1,
    "trusts": 1,
    "member_of": 1,
    "stores_credential_for": 1,
    "can_passrole": 2,
    "can_escalate": 2,
    "runs_as": 2,
    "can_reach": 3,
    "replicates_to": 3,
    "writes_logs_to": 3,
}
EDGE_TACTIC = {
    "exposes": "initial-access",
    "has_credential": "credential-access",
    "can_assume": "lateral-movement",
    "trusts": "lateral-movement",
    "member_of": "discovery",
    "stores_credential_for": "credential-access",
    "can_passrole": "privilege-escalation",
    "can_escalate": "privilege-escalation",
    "runs_as": "privilege-escalation",
    "can_reach": "collection",
    "replicates_to": "lateral-movement",
    "writes_logs_to": "defense-evasion",
}

DATA_TYPES = {
    "s3_bucket", "rds_instance", "redshift", "documentdb", "elasticache",
    "dynamodb", "secret", "ssm_parameter", "kms_key", "bedrock_kb",
    "bedrock_agent", "sagemaker", "ebs_snapshot", "ami", "rds_snapshot",
    "ecr_repo", "log_bucket",
}
PRINCIPAL_TYPES = {"iam_user", "iam_role", "access_key", "instance_profile"}
CI_HINTS = ("jenkins", "teamcity", "cloudagent", "pipeline", "bitbucket",
            "robot", "runner", "gitlab", "circleci", "codebuild")

DEFAULT_KB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "aws-attack-primitive-kb", "references", "attack_primitives.json",
)


# --------------------------------------------------------------------------- io
def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def sev_max(*names):
    return SEV_NAME[max((SEV_RANK.get(n, 0) for n in names), default=0)]


def value_to_sev(value_score):
    try:
        v = float(value_score)
    except (TypeError, ValueError):
        return "low"
    if v >= 80:
        return "critical"
    if v >= 60:
        return "high"
    if v >= 40:
        return "medium"
    return "low"


# ------------------------------------------------------------------- kb / model
def build_kb_index(kb):
    prims = kb.get("primitives", []) or []
    prim_by_id = {}
    control_to_prims = {}
    for p in prims:
        pid = p.get("id")
        if not pid:
            continue
        prim_by_id[pid] = p
        for ctl in (p.get("signature", {}) or {}).get("controls", []) or []:
            control_to_prims.setdefault(ctl, []).append(pid)
    for ctl in control_to_prims:
        control_to_prims[ctl] = sorted(set(control_to_prims[ctl]))
    return prim_by_id, control_to_prims


def tag_findings(findings, control_to_prims, prim_by_id):
    """Attach primitive_ids + mitre to each finding by control match. Returns
    (tagged_findings, finding_prims_by_id)."""
    tagged = []
    fp_by_id = {}
    for f in findings:
        f2 = dict(f)
        ctl = f.get("control")
        pids = list(control_to_prims.get(ctl, []))
        mitre = []
        for pid in pids:
            for m in prim_by_id[pid].get("mitre", []) or []:
                if m not in mitre:
                    mitre.append(m)
        # preserve any pre-existing tags
        for pid in f.get("primitive_ids", []) or []:
            if pid not in pids:
                pids.append(pid)
        f2["primitive_ids"] = pids
        if not f2.get("mitre"):
            f2["mitre"] = mitre
        tagged.append(f2)
        if f2.get("id"):
            fp_by_id[f2["id"]] = pids
    return tagged, fp_by_id


def index_findings_by_resource(findings):
    by_res = {}
    for f in findings:
        res = f.get("resource")
        if res:
            by_res.setdefault(res, []).append(f)
    return by_res


def node_findings(node, findings_by_res):
    out = []
    for key in (node.get("arn"), node.get("name"), node.get("id")):
        if key and key in findings_by_res:
            for f in findings_by_res[key]:
                if f not in out:
                    out.append(f)
    return out


# -------------------------------------------------------------- entries/targets
def is_stolen_cred_seed(node):
    t = node.get("type")
    if t not in PRINCIPAL_TYPES:
        return None
    attrs = node.get("attributes", {}) or {}
    name = (node.get("name") or "").lower()
    # long-lived key
    if t == "access_key":
        age = attrs.get("age_days")
        if (isinstance(age, (int, float)) and age > 180) or attrs.get("multiple_active"):
            return "long-lived-key"
    # no-mfa admin console user
    if t == "iam_user" and attrs.get("admin_like") and attrs.get("console_login") \
            and not attrs.get("mfa"):
        return "no-mfa-admin"
    # CI robot
    if any(h in name for h in CI_HINTS) and (attrs.get("admin_like")
                                             or attrs.get("ci_robot")):
        return "ci-robot"
    return None


def compute_entries(nodes, edges):
    entries = {}  # node_id -> kind
    node_by_id = {n["id"]: n for n in nodes if n.get("id")}
    # internet node reachable via exposes edges
    exposed = {e.get("src") for e in edges if e.get("type") == "exposes"}
    for nid in exposed:
        n = node_by_id.get(nid)
        if n and n.get("type") == "internet":
            entries[nid] = "internet"
    for n in nodes:
        if n.get("type") == "internet" and n["id"] not in entries:
            # internet node is always a plausible entry if it exists
            entries[n["id"]] = "internet"
    for n in nodes:
        kind = is_stolen_cred_seed(n)
        if kind and n["id"] not in entries:
            entries[n["id"]] = kind
    return entries


def compute_targets(nodes, edges, crown_jewels):
    targets = {}  # node_id -> value_score
    cj_score = {}
    for cj in crown_jewels:
        if cj.get("id"):
            targets[cj["id"]] = cj.get("value_score", 50)
            cj_score[cj["id"]] = cj.get("value_score", 50)
    node_by_id = {n["id"]: n for n in nodes if n.get("id")}
    reach_in = {}
    for e in edges:
        if e.get("type") == "can_reach":
            reach_in[e.get("dst")] = reach_in.get(e.get("dst"), 0) + 1
    for nid, _cnt in reach_in.items():
        n = node_by_id.get(nid)
        if n and n.get("type") in DATA_TYPES and nid not in targets:
            targets[nid] = 50
    return targets, cj_score


# ---------------------------------------------------------------- graph / paths
def build_adjacency(edges):
    """Non-self-loop edges for traversal; self-loops recorded separately."""
    adj = {}
    self_loops = {}
    for e in edges:
        src, dst = e.get("src"), e.get("dst")
        if src is None or dst is None:
            continue
        if src == dst:
            self_loops.setdefault(src, []).append(e)
        else:
            adj.setdefault(src, []).append(e)
    for src in adj:
        adj[src].sort(key=lambda e: (str(e.get("dst")), str(e.get("type"))))
    return adj, self_loops


def find_paths(entry, targets, adj, max_depth):
    """DFS from entry to any target with non-decreasing edge rank, no node
    revisits, bounded edge count. Returns list of edge-lists."""
    results = []
    start_nodes = [entry]

    def dfs(node, min_rank, path_nodes, path_edges):
        if node in targets and path_edges:
            results.append(list(path_edges))
            # do not return; a target may also be an intermediate to a deeper CJ
        if len(path_edges) >= max_depth:
            return
        for e in adj.get(node, []):
            rank = EDGE_RANK.get(e.get("type"), 2)
            if rank < min_rank:
                continue
            dst = e.get("dst")
            if dst in path_nodes:
                continue
            path_nodes.add(dst)
            path_edges.append(e)
            dfs(dst, rank, path_nodes, path_edges)
            path_edges.pop()
            path_nodes.discard(dst)

    for s in start_nodes:
        dfs(s, -1, {s}, [])
    return results


# --------------------------------------------------------------- kill chain fmt
def edge_primitive(edge, prim_by_id):
    pid = (edge.get("attributes", {}) or {}).get("primitive_id")
    if pid and pid in prim_by_id:
        return prim_by_id[pid]
    return None


def node_selfloop_prims(node_id, self_loops, prim_by_id):
    out = []
    for e in self_loops.get(node_id, []):
        p = edge_primitive(e, prim_by_id)
        if p and p not in out:
            out.append(p)
    return out


def kill_chain_from_path(kc_id, entry_id, entry_kind, edge_path, node_by_id,
                         self_loops, prim_by_id, findings_by_res, targets, cj_score):
    node_path = [entry_id] + [e.get("dst") for e in edge_path]
    target_id = node_path[-1]
    target_node = node_by_id.get(target_id, {})
    objective = target_node.get("name") or target_id

    # collect primitives + tactic sequence + severities + misconfigs
    member_sevs = []
    tactic_seq = []
    misconfigs = []
    steps = []

    def add_misc(s):
        if s and s not in misconfigs:
            misconfigs.append(s)

    def add_tactic(t):
        if t and t not in tactic_seq:
            tactic_seq.append(t)

    # entry pill
    entry_node = node_by_id.get(entry_id, {})
    entry_label = entry_node.get("name") or entry_id
    steps.append("%s [%s]" % (entry_label, entry_kind))

    # walk nodes: node self-loop escalations, then outgoing edge
    for i, nid in enumerate(node_path):
        n = node_by_id.get(nid, {})
        for p in node_selfloop_prims(nid, self_loops, prim_by_id):
            member_sevs.append(p.get("default_severity"))
            add_tactic(p.get("tactic"))
            add_misc(p.get("name"))
            steps.append("^ %s" % p.get("name"))
        for f in node_findings(n, findings_by_res):
            add_misc("%s on %s" % (f.get("control"), f.get("resource")))
            member_sevs.append(f.get("severity"))
        if i < len(edge_path):
            e = edge_path[i]
            dst_node = node_by_id.get(e.get("dst"), {})
            dst_label = dst_node.get("name") or e.get("dst")
            steps.append("%s > %s" % (e.get("type"), dst_label))
            p = edge_primitive(e, prim_by_id)
            if p:
                member_sevs.append(p.get("default_severity"))
                add_tactic(p.get("tactic"))
                add_misc(p.get("name"))
            else:
                add_tactic(EDGE_TACTIC.get(e.get("type")))

    # crown-jewel severity band
    cj_sev = value_to_sev(cj_score.get(target_id, targets.get(target_id, 50)))
    member_sevs.append(cj_sev)
    severity = sev_max(*member_sevs)

    # score = normalized likelihood * impact
    weights = [SEV_WEIGHT.get(s, 0.3) for s in member_sevs if s]
    base = sum(weights) / len(weights) if weights else 0.4
    length_factor = 1.0 / (1.0 + (len(edge_path)) * 0.3)
    entry_factor = 1.0 if entry_kind == "internet" else 0.7
    likelihood = min(1.0, base * length_factor * entry_factor)
    impact = float(cj_score.get(target_id, targets.get(target_id, 50))) / 100.0
    score = round(likelihood * impact, 4)

    title = "%s -> %s" % (entry_label, objective)

    return {
        "id": kc_id,
        "title": title,
        "tactic_sequence": tactic_seq,
        "steps": steps,
        "objective": objective,
        "crown_jewel_id": target_id,
        "severity": severity,
        "score": score,
        "live": False,
        "misconfigurations": misconfigs,
        "evidence": "",
        "node_path": node_path,
    }


# ------------------------------------------------------------------- techniques
def build_techniques(model, prim_by_id, control_to_prims):
    findings = model.get("findings", []) or []
    edges = model.get("edges", []) or []

    # which primitives are present, and their supporting findings
    present = {}  # pid -> {findings:[], resources:set, accounts:set}
    for f in findings:
        ctl = f.get("control")
        for pid in control_to_prims.get(ctl, []):
            rec = present.setdefault(pid, {"findings": [], "resources": set(),
                                           "accounts": set()})
            rec["findings"].append(f)
            if f.get("resource"):
                rec["resources"].add(f["resource"])
            if f.get("account_id"):
                rec["accounts"].add(f["account_id"])
    node_by_id = {n["id"]: n for n in model.get("nodes", []) if n.get("id")}
    for e in edges:
        pid = (e.get("attributes", {}) or {}).get("primitive_id")
        if pid and pid in prim_by_id:
            rec = present.setdefault(pid, {"findings": [], "resources": set(),
                                           "accounts": set()})
            for endp in (e.get("src"), e.get("dst")):
                n = node_by_id.get(endp)
                if n:
                    if n.get("arn") or n.get("name"):
                        rec["resources"].add(n.get("arn") or n.get("name"))
                    if n.get("account_id") and len(str(n.get("account_id"))) == 12:
                        rec["accounts"].add(n["account_id"])

    # order: by category label, then default severity desc, then id
    def sort_key(pid):
        p = prim_by_id[pid]
        return (p.get("category", "Z"), -SEV_RANK.get(p.get("default_severity"), 0), pid)

    ordered = sorted(present.keys(), key=sort_key)

    techniques = []
    pid_to_number = {}
    for i, pid in enumerate(ordered, start=1):
        p = prim_by_id[pid]
        rec = present[pid]
        pid_to_number[pid] = i
        misc = []
        for f in rec["findings"]:
            s = "%s on %s (acct %s)" % (f.get("control"), f.get("resource"),
                                        f.get("account_id"))
            if s not in misc:
                misc.append(s)
        # severity = max(default, matching finding sevs)
        sevs = [p.get("default_severity")] + [f.get("severity") for f in rec["findings"]]
        enables = p.get("enables", []) or []
        chain = p.get("name")
        if enables:
            chain = "%s -> enables: %s" % (p.get("name"), ", ".join(enables))
        techniques.append({
            "id": "T-%03d" % i,
            "number": i,
            "category": p.get("category", ""),
            "tactic": p.get("tactic", ""),
            "title": p.get("name", pid),
            "chain": chain,
            "misconfigurations": misc,
            "mitre": p.get("mitre", []) or [],
            "severity": sev_max(*sevs),
            "live": False,
            "refs": {
                "account_ids": sorted(rec["accounts"]),
                "resources": sorted(rec["resources"]),
            },
            "primitive_id": pid,
        })
    return techniques, pid_to_number, control_to_prims


# ------------------------------------------------------------------ root causes
def build_root_causes(model, control_to_prims, prim_by_id, pid_to_number):
    findings = model.get("findings", []) or []
    by_control = {}
    for f in findings:
        ctl = f.get("control")
        if not ctl:
            continue
        rec = by_control.setdefault(ctl, {"count": 0, "accounts": set(), "feeds": set()})
        rec["count"] += 1
        if f.get("account_id"):
            rec["accounts"].add(f["account_id"])
        for pid in control_to_prims.get(ctl, []):
            if pid in pid_to_number:
                rec["feeds"].add(pid_to_number[pid])

    root_causes = []
    for ctl in sorted(by_control.keys()):
        rec = by_control[ctl]
        # class = category of the first matching primitive
        klass = "uncategorized"
        for pid in control_to_prims.get(ctl, []):
            klass = prim_by_id[pid].get("category", "uncategorized")
            break
        accounts = sorted(rec["accounts"])
        root_causes.append({
            "control": ctl,
            "class": klass,
            "scope": "%d account(s): %s" % (len(accounts), ", ".join(accounts))
                     if accounts else "0 account(s)",
            "count": rec["count"],
            "feeds": sorted(rec["feeds"]),
        })
    return root_causes


# ------------------------------------------------------------------------- main
def enumerate_chains(model, kb, customer, now, max_chains, max_depth):
    prim_by_id, control_to_prims = build_kb_index(kb)

    nodes = model.get("nodes", []) or []
    edges = model.get("edges", []) or []
    accounts = model.get("accounts", []) or []
    crown_jewels = model.get("crown_jewels", []) or []
    findings = model.get("findings", []) or []

    tagged_findings, _fp = tag_findings(findings, control_to_prims, prim_by_id)
    findings_by_res = index_findings_by_resource(tagged_findings)
    node_by_id = {n["id"]: n for n in nodes if n.get("id")}

    kill_chains = []
    if nodes:
        entries = compute_entries(nodes, edges)
        targets, cj_score = compute_targets(nodes, edges, crown_jewels)
        adj, self_loops = build_adjacency(edges)

        raw = []
        for entry_id in sorted(entries):
            paths = find_paths(entry_id, set(targets), adj, max_depth)
            for edge_path in paths:
                raw.append((entry_id, entries[entry_id], edge_path))

        # dedup near-identical by node_path signature
        seen_sigs = set()
        built = []
        for entry_id, kind, edge_path in raw:
            node_path = tuple([entry_id] + [e.get("dst") for e in edge_path])
            if node_path in seen_sigs:
                continue
            seen_sigs.add(node_path)
            kc = kill_chain_from_path(
                "KC-TMP", entry_id, kind, edge_path, node_by_id, self_loops,
                prim_by_id, findings_by_res, targets, cj_score)
            built.append(kc)

        built.sort(key=lambda kc: (-kc["score"], kc["title"], "".join(kc["node_path"])))
        built = built[:max_chains]
        for i, kc in enumerate(built, start=1):
            kc["id"] = "KC-%d" % i
        kill_chains = built

    techniques, pid_to_number, control_to_prims = build_techniques(
        model, prim_by_id, control_to_prims)
    root_causes = build_root_causes(model, control_to_prims, prim_by_id, pid_to_number)

    account_count = len({a.get("account_id") for a in accounts if a.get("account_id")}) \
        or len({n.get("account_id") for n in nodes
                if n.get("account_id") and len(str(n.get("account_id"))) == 12})

    return {
        "schema": OUT_SCHEMA,
        "metadata": {
            "customer": customer,
            "generated_at": now,
            "account_count": account_count,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "finding_count": len(findings),
            "crown_jewel_count": len(crown_jewels),
            "technique_count": len(techniques),
            "kill_chain_count": len(kill_chains),
            "root_cause_count": len(root_causes),
        },
        "kill_chains": kill_chains,
        "techniques": techniques,
        "root_causes": root_causes,
        "active_threats": model.get("active_threats", []) or [],
        "gaps": model.get("gaps", []) or [],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Enumerate AWS attack chains (aws_attack_chains/v1) from a "
                    "merged aws_attack_model/v1 graph.")
    ap.add_argument("--model", required=True, help="Merged aws_attack_model/v1 JSON.")
    ap.add_argument("--kb", default=DEFAULT_KB,
                    help="attack_primitives.json KB (default: bundled aws-attack-primitive-kb).")
    ap.add_argument("--customer", default="", help="Customer label.")
    ap.add_argument("--now", default="", help="ISO-8601 timestamp (no datetime.now).")
    ap.add_argument("--max-chains", type=int, default=200,
                    help="Keep top N kill chains by score (default 200).")
    ap.add_argument("--max-depth", type=int, default=6,
                    help="Max edges per kill chain path (default 6).")
    ap.add_argument("--output", default="attack_chains.json",
                    help="Output aws_attack_chains/v1 path (default attack_chains.json).")
    args = ap.parse_args(argv)

    model = _load(args.model)
    kb = _load(args.kb)
    customer = args.customer or model.get("customer", "")

    result = enumerate_chains(model, kb, customer, args.now, args.max_chains,
                              args.max_depth)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=False)
        fh.write("\n")

    m = result["metadata"]
    sys.stderr.write(
        "enumerated %s -> %s: %d kill chains, %d techniques, %d root causes\n"
        % (args.model, args.output, m["kill_chain_count"], m["technique_count"],
           m["root_cause_count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
