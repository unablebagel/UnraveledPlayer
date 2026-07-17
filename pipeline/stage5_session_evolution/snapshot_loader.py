"""
snapshot_loader.py — rebuild session-like objects DOWNSTREAM of a demo's
output files, so the evolution graph reflects exactly what the demo published
(no re-running of the attribution engine, no engine imports).

INPUTS (both produced/owned by the upstream demo, e.g. stage4_segmented_zone):

  <demo>/output/*Snapshots.json   streaming per-node per-attacker timeline:
                                  snapshots[i].node_details[node] =
                                  {name, trust_zone, ips, per_attacker:
                                   {S<n>: {status, techniques, ...}}}
                                  plus a "sessions" legend with eval-only
                                  ground truth.
  <demo>/synthetic_alerts.jsonl   the OCSF alerts the demo attributed — used
                                  ONLY for the observed src->dst arrows (the
                                  snapshots carry node STATES, not movement).

RECONSTRUCTION
  * (session, host) first-seen time = time of the first snapshot frame whose
    node_details show that session's state on that host. Frames are emitted at
    event times and never re-partitioned (forward-only streaming), so this
    equals the event time that created the state.
  * techniques / compromised status per (session, host) = final frame.
  * each alert is assigned to the session whose (session, dst-node) state
    FIRST APPEARED at exactly the alert's anchor time; alerts that created no
    new state are skipped (they can add no arrow).
  * the ip -> node mapper is rebuilt from the snapshots' own node ips.

The result is a list of duck-typed sessions + a mapper that plug straight into
graph_builder / plot_session_evolution. Generic: driven purely by the JSON
structure — no hardcoded node names, session ids, or zone names.
"""

import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple


class SnapshotMapper:
    """Minimal MappingLayer stand-in built from the snapshots' node ips."""

    def __init__(self, ip_to_node: Dict[str, str]):
        self._ip_to_node = dict(ip_to_node)

    def map_ip_to_node(self, ip: Optional[str]) -> Optional[str]:
        return self._ip_to_node.get(ip) if ip else None


def _load_jsonl(path) -> List[dict]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _alert_anchor(alert: dict) -> Optional[int]:
    """Time anchoring, mirroring attribution.build_events: host-log alerts at
    start_time (behavior onset), network alerts at time (window end)."""
    raw = alert.get("unmapped", {}).get("raw_data", {})
    if raw.get("data_type") == "host_log":
        return alert.get("start_time")
    return alert.get("time")


def _alert_endpoints(alert: dict) -> Tuple[Optional[str], Optional[str]]:
    """src/dst IPs from the OCSF evidences block (the demo generators' shape)."""
    ev = (alert.get("evidences") or [{}])[0]
    src = (ev.get("src_endpoint") or {}).get("ip")
    dst = (ev.get("dst_endpoint") or {}).get("ip")
    return src, dst


def sessions_from_snapshots(snap_doc: dict, alerts: List[dict]):
    """(snapshots doc, alerts) -> (duck-typed sessions, SnapshotMapper).

    The sessions carry exactly what graph_builder consumes: name, events
    (time/src_ip/dst_ip), facts (details: node/technique/time),
    compromised_nodes, external_dst_times (unused here — the snapshots carry
    no sink info), first_time, gt_counter.
    """
    snapshots = snap_doc.get("snapshots", [])
    legend = {s["session"]: s for s in snap_doc.get("sessions", [])}

    # ip -> node id from the frames themselves (any frame; nodes accumulate)
    ip_to_node: Dict[str, str] = {}
    for snap in snapshots:
        for node_id, d in snap.get("node_details", {}).items():
            for ip in d.get("ips") or []:
                ip_to_node.setdefault(ip, node_id)
    mapper = SnapshotMapper(ip_to_node)
    node_ip = {}                                   # node id -> primary ip
    for ip, node_id in ip_to_node.items():
        node_ip.setdefault(node_id, ip)

    # (session, node) -> first-seen time; final frame -> techniques + status
    first_seen: Dict[Tuple[str, str], int] = {}
    for snap in snapshots:
        t = snap.get("time")
        for node_id, d in snap.get("node_details", {}).items():
            for sname in (d.get("per_attacker") or {}):
                first_seen.setdefault((sname, node_id), t)
    final = snapshots[-1]["node_details"] if snapshots else {}

    session_names = sorted(
        {sname for sname, _node in first_seen} | set(legend),
        key=lambda n: (min((t for (s, _n), t in first_seen.items() if s == n),
                           default=0), n))

    sessions = {}
    for sname in session_names:
        gt = (legend.get(sname, {}).get("eval_ground_truth", {})
              .get("attribution_counts", {}))
        times = [t for (s, _n), t in first_seen.items() if s == sname]
        sessions[sname] = SimpleNamespace(
            name=sname,
            events=[],
            facts=[],
            compromised_nodes=set(),
            external_dst_times={},
            first_time=min(times) if times else None,
            gt_counter=Counter(gt),
        )

    # facts: one per (session, host, technique), stamped at first-seen time
    for (sname, node_id), t in sorted(first_seen.items(), key=lambda kv: kv[1]):
        s = sessions[sname]
        pa = (final.get(node_id, {}).get("per_attacker") or {}).get(sname, {})
        if pa.get("status") == "COMPROMISED":
            s.compromised_nodes.add(node_id)
        techniques = pa.get("techniques") or [None]
        ip = node_ip.get(node_id, node_id)
        for tech in techniques:
            s.facts.append(SimpleNamespace(
                details={"node": ip, "technique": tech, "time": t}))

    # events: assign each alert to the session whose dst-state it CREATED
    by_birth: Dict[Tuple[str, int], List[str]] = {}
    for (sname, node_id), t in first_seen.items():
        by_birth.setdefault((node_id, t), []).append(sname)
    for alert in alerts:
        t = _alert_anchor(alert)
        src_ip, dst_ip = _alert_endpoints(alert)
        dst_node = mapper.map_ip_to_node(dst_ip)
        if dst_node is None or t is None:
            continue
        for sname in by_birth.get((dst_node, t), []):
            sessions[sname].events.append(
                SimpleNamespace(time=t, src_ip=src_ip, dst_ip=dst_ip, gt=""))

    return [sessions[n] for n in session_names], mapper


def load_demo_output(demo_dir, snapshots_glob: str = "*Snapshots.json",
                     alerts_name: str = "synthetic_alerts.jsonl"):
    """Load (sessions, mapper, snapshots doc) from a demo folder's files.

    demo_dir must contain output/<...Snapshots.json> and the alerts jsonl the
    demo attributed. Raises FileNotFoundError with a run hint when the demo
    has not been run yet.
    """
    demo_dir = Path(demo_dir)
    candidates = sorted((demo_dir / "output").glob(snapshots_glob))
    if not candidates:
        raise FileNotFoundError(
            f"no {snapshots_glob} under {demo_dir / 'output'} — run the "
            f"upstream demo first (python -m ...{demo_dir.name}.run_demo)")
    snap_path = candidates[0]
    alerts_path = demo_dir / alerts_name
    if not alerts_path.exists():
        raise FileNotFoundError(f"missing {alerts_path} — run the upstream "
                                "demo first to (re)generate its alerts")

    snap_doc = json.load(open(snap_path, encoding="utf-8"))
    alerts = _load_jsonl(alerts_path)
    sessions, mapper = sessions_from_snapshots(snap_doc, alerts)
    return sessions, mapper, snap_doc
