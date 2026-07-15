"""
import_alerts.py — reverse a synthetic_alerts.jsonl (OCSF Detection Findings)
back into a scenario_builder spec, so an EXISTING hand-coded demo (stage3,
stage4, stage4b, ...) can be pulled INTO the editor and tweaked visually
instead of re-typed in Python. This is the exact inverse of compile.py:

    scenario.json  --compile.py-->        synthetic_alerts.jsonl   (forward)
    synthetic_alerts.jsonl  --import_alerts.py-->  scenario spec    (reverse)

Every field the spec needs is already present in the alert make_alert() emits:

    time                                   -> move.t
    evidences[0].src_endpoint.ip           -> move.src
    evidences[0].dst_endpoint.ip / .port   -> move.dst / move.port
    finding_info.attacks[0].technique.uid  -> move.technique
    unmapped.attacker_attribution          -> attacker.name (gt label, EVAL ONLY)
    unmapped.provenance.login_session      -> attacker.prov

The only non-trivial step is reversing IPs back to node ids using the SAME
topology compile.py used. The topology is inferred by whichever loader maps the
most of the alert's internal IPs onto real nodes (override with `topology=`).
An external source IP that is an attacker's first-seen origin becomes the
sentinel "external" (a foothold); an IP that maps to no node is kept as a raw
literal (external C2 sinks, or internal hosts the diagram leaves unpinned).

Timing is preserved but kept tidy: base_time is the first alert's time, step_ms
is the most common gap, and an explicit move.t is emitted ONLY where a move
breaks that cadence -- so an evenly-spaced demo round-trips to blank t's.

    python -m ComparisonToTM.log_to_diagram_demo.scenario_builder.import_alerts \
        path/to/synthetic_alerts.jsonl [-o scenario.json] \
        [--topology segmented|unraveled|toy]
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

from ..ocsf_to_facts import _is_internal
from .compile import _TOPOLOGY_LOADERS, _node_ip_map
from .techniques import TECHNIQUES


class AlertImportError(ValueError):
    """A synthetic_alerts.jsonl cannot be reversed into a scenario spec."""


def _extract(alert: dict) -> dict:
    """Pull the spec-relevant fields out of one OCSF Detection Finding."""
    attacks = (alert.get("finding_info") or {}).get("attacks") or []
    tech = attacks[0]["technique"]["uid"] if attacks else None
    ev = (alert.get("evidences") or [{}])[0]
    dst_ep = ev.get("dst_endpoint") or {}
    unmapped = alert.get("unmapped") or {}
    return {
        "time": alert.get("time"),
        "src_ip": (ev.get("src_endpoint") or {}).get("ip"),
        "dst_ip": dst_ep.get("ip"),
        "port": dst_ep.get("port"),
        "technique": tech,
        "attacker": unmapped.get("attacker_attribution"),
        "prov": (unmapped.get("provenance") or {}).get("login_session"),
    }


def _reverse_ip_map(diagram) -> Dict[str, str]:
    """ip -> node id (inverse of compile._node_ip_map's node id -> ip)."""
    return {ip: nid for nid, ip in _node_ip_map(diagram).items()}


def _internal_ips(tuples: List[dict]) -> set:
    ips = set()
    for t in tuples:
        for ip in (t["src_ip"], t["dst_ip"]):
            if ip and _is_internal(ip):
                ips.add(ip)
    return ips


def _infer_topology(tuples: List[dict]) -> Tuple[str, Dict[str, str]]:
    """Pick the topology whose node IPs cover the most of the alerts' internal
    IPs (ties resolve to loader order: segmented, then unraveled, then toy)."""
    internal = _internal_ips(tuples)
    best = None
    for name, loader in _TOPOLOGY_LOADERS.items():
        ip2node = _reverse_ip_map(loader())
        mapped = sum(1 for ip in internal if ip in ip2node)
        if best is None or mapped > best[0]:      # '>' keeps the earlier loader on a tie
            best = (mapped, name, ip2node)
    return best[1], best[2]


def alerts_to_spec(alerts: List[dict],
                   topology: Optional[str] = None) -> Tuple[dict, List[str]]:
    """Reverse a list of OCSF alerts into a scenario_builder spec dict + a
    human-readable import report. Alerts are consumed in list order (which is
    emission/interleave order); timestamps are NOT re-sorted."""
    report: List[str] = []
    tuples = [_extract(a) for a in alerts]
    tuples = [t for t in tuples
              if t["src_ip"] and t["dst_ip"] and t["technique"] and t["attacker"]]
    if not tuples:
        raise AlertImportError(
            "no usable alerts -- each move needs src+dst IPs, a technique, and "
            "unmapped.attacker_attribution")

    if topology is None:
        topology, ip2node = _infer_topology(tuples)
        report.append(f"inferred topology = {topology!r} "
                      "(most internal IPs mapped to nodes)")
    elif topology in _TOPOLOGY_LOADERS:
        ip2node = _reverse_ip_map(_TOPOLOGY_LOADERS[topology]())
    else:
        raise AlertImportError(f"unknown topology {topology!r}")

    # attacker roster, in first-seen order
    order: List[str] = []
    for t in tuples:
        if t["attacker"] not in order:
            order.append(t["attacker"])

    attackers, ext_entry = [], {}     # ext_entry: name -> external origin IP or None
    for name in order:
        mine = [t for t in tuples if t["attacker"] == name]
        entry = next((t["src_ip"] for t in mine
                      if not _is_internal(t["src_ip"]) and t["src_ip"] not in ip2node), None)
        foothold = next((t for t in mine if t["src_ip"] == entry), None) if entry else None
        if entry is None:                          # internal-only actor: no 'external' move
            entry = mine[0]["src_ip"]
            report.append(f"attacker {name!r}: no external foothold seen; entry_ip set "
                          f"to {entry!r} (informational -- no move uses 'external')")
        ext_entry[name] = foothold["src_ip"] if foothold else None
        attackers.append({
            "name": name,
            "entry_ip": entry,
            "initial_access": foothold["technique"] if foothold else "T1078",
            "prov": next((t["prov"] for t in mine if t["prov"]), None),
            "default_port": (foothold["port"] if foothold and foothold["port"] else 22),
        })
    by_name = {a["name"]: a for a in attackers}

    def resolve(ip: str, name: str, is_src: bool) -> str:
        if is_src and ext_entry.get(name) and ip == ext_entry[name]:
            return "external"
        return ip2node.get(ip, ip)                 # node id, else raw IP literal

    # timeline: base_time + the dominant gap; explicit t only where the cadence breaks
    times = [t["time"] for t in tuples]
    base_time = times[0]
    deltas = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
    step_ms = Counter(deltas).most_common(1)[0][0] if deltas else 1000

    moves, unmapped_internal = [], set()
    for i, t in enumerate(tuples):
        atk = by_name[t["attacker"]]
        src = resolve(t["src_ip"], t["attacker"], True)
        dst = resolve(t["dst_ip"], t["attacker"], False)
        for raw, mapped in ((t["src_ip"], src), (t["dst_ip"], dst)):
            if mapped == raw and _is_internal(raw):
                unmapped_internal.add(raw)
        expected = base_time if i == 0 else tuples[i - 1]["time"] + step_ms
        move = {"attacker": t["attacker"], "src": src, "dst": dst,
                "technique": t["technique"]}
        if t["port"] and t["port"] != atk["default_port"]:
            move["port"] = t["port"]
        if t["time"] != expected:
            move["t"] = t["time"]
        if src == "external":
            move["kind"] = "foothold"
        moves.append(move)

    spec = {"topology": topology, "base_time": base_time, "step_ms": step_ms,
            "attackers": attackers, "moves": moves}

    report.insert(0, f"imported {len(moves)} move(s), {len(attackers)} attacker(s), "
                     f"base_time={base_time}, step_ms={step_ms}")
    if unmapped_internal:
        report.append(f"internal IP(s) kept as raw literals (no node in {topology!r}): "
                      f"{sorted(unmapped_internal)}")
    unknown = sorted({m["technique"] for m in moves} - set(TECHNIQUES))
    if unknown:
        report.append(f"[WARN] technique(s) not in the editor registry -- fix before "
                      f"compile: {unknown}")
    return spec, report


def load_jsonl(path) -> List[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("alerts", help="path to a synthetic_alerts.jsonl")
    parser.add_argument("-o", "--out", default=None,
                        help="output scenario.json path (default: alongside the jsonl)")
    parser.add_argument("--topology", default=None, choices=list(_TOPOLOGY_LOADERS),
                        help="force a topology instead of inferring it")
    args = parser.parse_args(argv)

    alerts = load_jsonl(args.alerts)
    spec, report = alerts_to_spec(alerts, topology=args.topology)

    out = Path(args.out) if args.out else Path(args.alerts).with_suffix(".scenario.json")
    out.write_text(json.dumps(spec, indent=2), encoding="utf-8")
    print(f"[OK] wrote scenario spec -> {out}", flush=True)
    print("\n".join(report), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
