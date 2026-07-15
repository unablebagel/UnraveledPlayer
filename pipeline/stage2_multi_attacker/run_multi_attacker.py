"""
run_multi_attacker.py — per-attacker state decomposition.

    python -m ComparisonToTM.log_to_diagram_demo.stage2_multi_attacker.run_multi_attacker

Outputs (output/):
    MultiAttacker_Snapshots.json   full-topology timeline; each node carries an
                                   aggregate distribution PLUS a per-session map.
    MultiAttacker_Sessions.json    inferred-session registry, final per-node
                                   per-attacker breakdown, and eval vs ground truth.

The aggregate distribution per node is the UNCHANGED global noisy-OR (identical
to the streaming/batch pipeline), so the existing consistency invariant
(1 - P(clean) == batch score) still holds on the aggregate. The per-session
distributions split that evidence by inferred attacker.

LABEL-FREE scoring: attacker sessions are inferred from observables only.
Ground-truth attacker_attribution appears solely in the eval section.
"""

import sys
import json
import math
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

from ..unraveled_diagram import create_unraveled_complete_diagram
from ..mapping_layer import MappingLayer
from ..state_demo import get_node_predicates
from ..stage1_streaming.replay import (
    state_distribution, _label_of, change_checkpoints, iso, _COMPROMISE_FACT_TYPES,
)
from .attribution import build_events, attribute, split_by_sink, merge_by_rendezvous


def v_measure(sessions):
    """
    Cluster-quality of inferred sessions vs ground-truth attribution (EVAL ONLY),
    weighted by per-session alert counts. Clusters = sessions, classes = ground
    truth. Returns homogeneity (no session mixes attackers), completeness (each
    attacker stays in one session), and their harmonic mean V. Standard
    Rosenberg-Hirschberg V-measure; log base cancels.
    """
    rows = {s.name: dict(s.gt_counter) for s in sessions}
    N = sum(sum(v.values()) for v in rows.values())
    if N == 0:
        return None
    a_k = {k: sum(v.values()) for k, v in rows.items()}      # cluster sizes
    a_c: dict = {}                                           # class sizes
    for v in rows.values():
        for c, n in v.items():
            a_c[c] = a_c.get(c, 0) + n

    def _xlogx(p):
        return p * math.log(p) if p > 0 else 0.0

    HC = -sum(_xlogx(a_c[c] / N) for c in a_c)
    HK = -sum(_xlogx(a_k[k] / N) for k in a_k)
    HCK = -sum((n / N) * math.log(n / a_k[k])
               for k, v in rows.items() for c, n in v.items())
    HKC = -sum((n / N) * math.log(n / a_c[c])
               for k, v in rows.items() for c, n in v.items())
    h = 1.0 if HC == 0 else 1 - HCK / HC
    comp = 1.0 if HK == 0 else 1 - HKC / HK
    V = 0.0 if (h + comp) == 0 else 2 * h * comp / (h + comp)
    return {
        "homogeneity": round(h, 3),
        "completeness": round(comp, 3),
        "v_measure": round(V, 3),
        "n_inferred_sessions": len(sessions),
        "n_ground_truth_attackers": len(a_c),
    }


def _dist_view(d):
    """Distribution dict -> {status, confidence, distribution}."""
    status, conf = _label_of(d)
    return {
        "status": status,
        "confidence": conf,
        "distribution": {k: round(v, 4) for k, v in d.items()},
    }


def _session_facts_upto(session, t):
    return [f for f in session.facts if (f.details.get("time") or 0) <= t]


def _session_role_at(session, t):
    """Time-evolving role: 'foothold/active' once the session has compromised any
    node BY time t (an attack_source/execCode fact at or before t), else
    'recon-only'. Unlike Session.role (final, whole-campaign), this reflects the
    session's status as of the snapshot — recon-only until its first compromise."""
    for f in session.facts:
        if (f.fact_type in _COMPROMISE_FACT_TYPES
                and (f.details.get("time") or 0) <= t):
            return "foothold/active"
    return "recon-only"


def build_snapshots(diagram, all_facts, sessions):
    """One snapshot per checkpoint. Each node carries ONLY per-attacker state:
    per_attacker[session] = {status, confidence, distribution, role, predicates,
    techniques} — each scoped to THAT session's facts (its own predicates and
    MITRE techniques, not the merged aggregate). The top-level summary buckets
    still give the aggregate overview. Consecutive identical snapshots collapse."""
    checkpoints = change_checkpoints(all_facts, MappingLayer(diagram))
    out = []
    prev = None
    for t in checkpoints:
        prefix = [f for f in all_facts if (f.details.get("time") or 0) <= t]
        agg = state_distribution(prefix, MappingLayer(diagram))   # summary buckets only

        # per-session: distribution + a SystemState (for that session's predicates
        # and MITRE techniques) + time-evolving role, all at time t.
        sess_dist, sess_state, sess_role = {}, {}, {}
        for s in sessions:
            sfacts = _session_facts_upto(s, t)
            sess_dist[s.name] = state_distribution(sfacts, MappingLayer(diagram))
            sess_state[s.name] = MappingLayer(diagram).build_diagram_state(sfacts)
            sess_role[s.name] = _session_role_at(s, t)

        buckets = {"COMPROMISED": [], "ACCESSED": [], "CLEAN": []}
        details = {}
        for node in diagram.nodes:
            # aggregate status -> summary buckets (overview only)
            d = agg.get(node.id)
            buckets["CLEAN" if d is None else _label_of(d)[0]].append(node.id)

            # per-attacker state, each scoped to its own session's evidence
            per_attacker = {}
            for s in sessions:
                sd = sess_dist[s.name].get(node.id)
                if sd is None:
                    continue
                view = _dist_view(sd)
                st = sess_state[s.name]
                mitre = st.get_mitre_summary(node.id) or {}
                per_attacker[s.name] = {
                    "status": view["status"],
                    "confidence": view["confidence"],
                    "distribution": view["distribution"],
                    "role": sess_role[s.name],
                    "predicates": get_node_predicates(st, node.id),
                    "techniques": mitre.get("mitre_techniques", []),
                }
            if not per_attacker:        # node_details lists only touched nodes
                continue
            details[node.id] = {
                "name": node.name,
                "trust_zone": node.trust_zone,
                "ips": node.ip_addresses,
                "per_attacker": per_attacker,
            }
        snap = {
            "summary": {
                "compromised": buckets["COMPROMISED"],
                "accessed": buckets["ACCESSED"],
                "clean": buckets["CLEAN"],
            },
            "node_details": details,
        }
        if snap["node_details"] == prev:
            continue
        prev = snap["node_details"]
        out.append({"index": len(out), "time": t, "iso": iso(t), **snap})
    return out


def session_registry(sessions):
    """Static per-session summary + eval vs ground-truth attribution."""
    reg = []
    for s in sessions:
        gt = dict(s.gt_counter)
        gt_majority = max(gt, key=gt.get) if gt else ""
        total = sum(gt.values()) or 1
        reg.append({
            "session": s.name,
            "role": s.role,
            "actor_ips": sorted(s.actor_ips),
            "touched_nodes": sorted(s.touched_nodes),
            "compromised_nodes": sorted(s.compromised_nodes),
            "techniques": sorted(s.techniques),
            "first_seen": iso(s.first_time),
            "last_seen": iso(s.last_time),
            "n_facts": len(s.facts),
            "eval_ground_truth": {
                "attribution_counts": gt,
                "majority": gt_majority,
                "purity": round(max(gt.values()) / total, 3) if gt else None,
            },
        })
    return reg


def main() -> int:
    script_dir = Path(__file__).parent.parent
    output_dir = script_dir / "output"
    output_dir.mkdir(exist_ok=True)

    print("=" * 70, flush=True)
    print("PER-ATTACKER STATE  --  session-linked noisy-OR decomposition", flush=True)
    print("=" * 70, flush=True)

    diagram = create_unraveled_complete_diagram()
    mapper = MappingLayer(diagram)
    events = build_events()
    all_facts = [f for ev in events for f in ev.facts]
    print(f"  {len(events)} scoring alerts -> {len(all_facts)} scoring facts", flush=True)

    raw_sessions = attribute(events, mapper, diagram)
    split_sessions = split_by_sink(raw_sessions, mapper)
    sessions = merge_by_rendezvous(split_sessions)
    print(f"  Inferred {len(raw_sessions)} session(s) -> {len(split_sessions)} after "
          f"sink-split (distinct external C2/exfil sink) -> {len(sessions)} after "
          f"rendezvous merge (shared sink)\n", flush=True)

    # eval: cluster quality vs ground truth, before split / after split / after merge
    v_before, v_split, v_after = (v_measure(raw_sessions),
                                  v_measure(split_sessions), v_measure(sessions))
    if v_before and v_after:
        print("  V-measure vs ground truth (eval only):", flush=True)
        for tag, vm in (("before split", v_before), ("after split ", v_split),
                        ("after merge ", v_after)):
            print(f"    {tag}: homogeneity={vm['homogeneity']} "
                  f"completeness={vm['completeness']} V={vm['v_measure']} "
                  f"({vm['n_inferred_sessions']} sessions)", flush=True)
        print("", flush=True)

    print(f"  {'sess':5s} {'role':15s} {'actors':22s} {'touched':28s} GT(majority)", flush=True)
    for s in sessions:
        actors = ",".join(sorted(s.actor_ips))[:21]
        touched = ",".join(sorted(s.touched_nodes))[:27]
        gt = max(s.gt_counter, key=s.gt_counter.get) if s.gt_counter else "-"
        print(f"  {s.name:5s} {s.role:15s} {actors:22s} {touched:28s} {gt}", flush=True)

    snapshots = build_snapshots(diagram, all_facts, sessions)
    registry = session_registry(sessions)

    # ── demonstration: a node multiple attackers disagree on ──────────────
    final = snapshots[-1] if snapshots else None
    if final:
        print("\n  Nodes where attackers DISAGREE (per-session status differs):", flush=True)
        for node, d in sorted(final["node_details"].items()):
            pa = d.get("per_attacker", {})
            statuses = {v["status"] for v in pa.values()}
            if len(pa) >= 2 and len(statuses) >= 2:
                print(f"    {node}:", flush=True)
                for sid, v in pa.items():
                    print(f"        {sid} ({v['role']}): {v['status']} "
                          f"(P={v['confidence']}) techniques={v['techniques']}", flush=True)

    # ── write outputs ──────────────────────────────────────────────────
    snap_out = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "n_sessions": len(sessions),
            "n_snapshots": len(snapshots),
            "note": "Each node carries ONLY per_attacker: {session: {status, "
                    "confidence, distribution, role, predicates, techniques}}, each "
                    "scoped to that session's own evidence. summary buckets give the "
                    "aggregate overview. Sessions inferred label-free via "
                    "actor-continuity + foothold-promotion + timing/path.",
        },
        "snapshots": snapshots,
    }
    snap_path = output_dir / "MultiAttacker_Snapshots.json"
    with open(snap_path, "w") as f:
        json.dump(snap_out, f, indent=2, default=str)
    print(f"\n  [OK] Saved: {snap_path.name}", flush=True)

    sess_out = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "n_sessions": len(sessions),
            "attribution": "actor-continuity + foothold-promotion + timing/path "
                           f"(window={60_000} ms), then sink-split on distinct "
                           "external sinks, then rendezvous merge on shared external "
                           "sink. Label-free; ground truth used only in eval.",
        },
        "eval_vmeasure": {"before_split": v_before, "after_split": v_split,
                          "after_merge": v_after},
        "sessions": registry,
        "final_node_breakdown": final["node_details"] if final else {},
    }
    sess_path = output_dir / "MultiAttacker_Sessions.json"
    with open(sess_path, "w") as f:
        json.dump(sess_out, f, indent=2, default=str)
    print(f"  [OK] Saved: {sess_path.name}", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("DONE", flush=True)
    print("=" * 70, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
