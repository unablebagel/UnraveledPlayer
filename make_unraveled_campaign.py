"""
make_unraveled_campaign.py — regenerate examples/unraveled_campaign.json, the
read-only scenario of the DEFAULT Unraveled attack campaign on the `unraveled`
topology.

The source of truth is the real enriched SIEM alert stream the stage1_streaming
demo replays (siem_alerts_enriched_v3.jsonl in the tm-unraveled research repo,
~2.3k OCSF Detection Findings). That stream is far too repetitive to be a
useful editor scenario (792 of the alerts are one C2 beacon repeating), so this
script reverses it with import_alerts.alerts_to_spec (topology pinned to
`unraveled`) and then CONDENSES it: one move per distinct
(attacker, src, dst, technique), keeping the FIRST-SEEN absolute time as the
move's explicit `t`, the modal destination port, and the aggregate alert count
in the informational `kind` field. Moves are emitted in chronological order.

Host-log alerts carry no dst_endpoint (a host log says "detected on this
host", not who sent it), so they cannot become src->dst moves directly.
They are represented instead of dropped:

  - an actor with NO network-flow presence (Skilled Hackers, seen only via
    one T1566.001 spearphish on hr_host_5) gets their initial-access
    host-log alert as a foothold move from EXTERNAL onto the observed host.
    Host logs record no source IP, so that attacker's entry_ip is a
    TEST-NET-3 placeholder (203.0.113.x), flagged in the move's `kind`;
  - every other host-log detection (e.g. the APT's valid-account logons,
    brute-force attempts, and account manipulation on the it hosts) becomes
    a SELF-LOOP move (src == dst == the host), which the editor renders as
    a small loop on the node — a local observation, no flow invented.

Both use the alert's start_time (first observed occurrence) as `t`.

What is intentionally lost relative to the raw stream:
  - alert volume (kept only as the "aggregates N alerts" note in `kind`);
  - host-log detections whose technique is not in the editor's registry
    (scenario_builder/techniques.py, vendored verbatim): currently the
    APT's T1572 SSH tunnel on it_host_1 — the generator prints a note.

Run from inside the tm-unraveled research repo (like sync_from_source.py, this
has no data to read once the repo is split out):

    python make_unraveled_campaign.py [path/to/siem_alerts_enriched_v3.jsonl]
"""

import json
import sys
from collections import Counter
from pathlib import Path

from pipeline.ocsf_to_facts import _load_jsonl
from pipeline.scenario_builder.compile import _TOPOLOGY_LOADERS
from pipeline.scenario_builder.import_alerts import _reverse_ip_map, alerts_to_spec
from pipeline.scenario_builder.spec import from_dict
from pipeline.scenario_builder.techniques import TECHNIQUES

HERE = Path(__file__).resolve().parent
DEFAULT_ALERTS = (HERE.parent.parent / "cybernatics_top7_alerts"
                  / "siem_alerts_enriched_v3.jsonl")
OUT = HERE / "pipeline" / "scenario_builder" / "examples" / "unraveled_campaign.json"


def condense(spec: dict) -> dict:
    """One move per distinct (attacker, src, dst, technique), chronological,
    each with an explicit first-seen `t` and the aggregate count in `kind`."""
    # Reconstruct every move's absolute time: import_alerts omits `t` when a
    # move lands exactly on the base_time/step_ms cadence.
    times, prev = [], None
    for i, m in enumerate(spec["moves"]):
        expected = spec["base_time"] if i == 0 else prev + spec["step_ms"]
        t = m.get("t", expected)
        times.append(t)
        prev = t

    groups: dict = {}
    for m, t in zip(spec["moves"], times):
        k = (m["attacker"], m["src"], m["dst"], m["technique"])
        g = groups.setdefault(k, {"first_t": t, "count": 0, "ports": Counter(),
                                  "kind": m.get("kind")})
        g["first_t"] = min(g["first_t"], t)
        g["count"] += 1
        g["ports"][m.get("port")] += 1

    default_port = {a["name"]: a["default_port"] for a in spec["attackers"]}
    moves = []
    for (attacker, src, dst, technique), g in sorted(
            groups.items(), key=lambda kv: kv[1]["first_t"]):
        note = f"aggregates {g['count']} alerts" if g["count"] > 1 else None
        kind = "; ".join(x for x in (g["kind"], note) if x) or None
        move = {"attacker": attacker, "src": src, "dst": dst,
                "technique": technique, "t": g["first_t"]}
        port = g["ports"].most_common(1)[0][0]
        if port and port != default_port[attacker]:
            move["port"] = port
        if kind:
            move["kind"] = kind
        moves.append(move)

    return {"topology": spec["topology"], "base_time": moves[0]["t"],
            "step_ms": spec["step_ms"],
            "attackers": spec["attackers"], "moves": moves}


_INITIAL_ACCESS = ("T1078", "T1566.001")
_PLACEHOLDER_ENTRY = "203.0.113.{}"     # TEST-NET-3: host logs record no source


def hostlog_moves(alerts: list, known_attackers: set) -> tuple:
    """(attackers, moves, notes) synthesized from the host-log alerts.

    An actor absent from `known_attackers` (no network-flow presence) gets
    their first initial-access detection as a foothold move from EXTERNAL
    onto the observed host; every other in-registry detection becomes a
    self-loop move on that host (deduped per attacker/host/technique)."""
    ip2node = _reverse_ip_map(_TOPOLOGY_LOADERS["unraveled"]())
    roster = set(known_attackers)
    attackers, moves, notes = [], [], []
    loops: dict = {}                    # (attacker, node, tech) -> move
    for a in alerts:
        unmapped = a.get("unmapped") or {}
        if unmapped.get("raw_data", {}).get("data_type") != "host_log":
            continue
        name = unmapped.get("attacker_attribution")
        attacks = (a.get("finding_info") or {}).get("attacks") or []
        tech = attacks[0]["technique"]["uid"] if attacks else None
        host_ip = ((a.get("evidences") or [{}])[0].get("src_endpoint") or {}).get("ip")
        if not name or not tech or not host_ip:
            continue
        node = ip2node.get(host_ip, host_ip)
        t = a.get("start_time") or a.get("time")
        if tech not in TECHNIQUES:
            notes.append(f"skipped host-log {tech} on {node} ({name}): not in "
                         "the editor technique registry")
            continue
        if name not in roster and tech in _INITIAL_ACCESS:
            roster.add(name)            # foothold for a host-log-only actor
            attackers.append({
                "name": name,
                "entry_ip": _PLACEHOLDER_ENTRY.format(50 + len(attackers)),
                "initial_access": tech, "prov": None, "default_port": 22,
            })
            moves.append({
                "attacker": name, "src": "external", "dst": node,
                "technique": tech, "t": t,
                "kind": "foothold; host-log detection (source IP unknown)",
            })
            continue
        key = (name, node, tech)        # local observation -> self-loop
        m = loops.get(key)
        if m is None:
            loops[key] = {"attacker": name, "src": node, "dst": node,
                          "technique": tech, "t": t, "_n": 1}
        else:
            m["t"] = min(m["t"], t)
            m["_n"] += 1
    for m in loops.values():
        n = m.pop("_n")
        m["kind"] = ("host-log detection (local observation)"
                     + (f"; aggregates {n} alerts" if n > 1 else ""))
        moves.append(m)
    return attackers, moves, notes


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    alerts_path = Path(args[0]) if args else DEFAULT_ALERTS
    if not alerts_path.exists():
        print(f"[ERR] alerts file not found: {alerts_path} — run from inside "
              "the tm-unraveled research repo, or pass the path explicitly "
              "(see module docstring)")
        return 1

    alerts = _load_jsonl(alerts_path)
    full, report = alerts_to_spec(alerts, topology="unraveled")
    campaign = condense(full)

    extra_attackers, extra_moves, notes = hostlog_moves(
        alerts, {a["name"] for a in campaign["attackers"]})
    campaign["attackers"] += extra_attackers
    campaign["moves"] = sorted(campaign["moves"] + extra_moves,
                               key=lambda m: m["t"])
    campaign["base_time"] = campaign["moves"][0]["t"]

    from_dict(campaign)                      # validate before writing
    OUT.write_text(json.dumps(campaign, indent=2) + "\n", encoding="utf-8")

    print(f"[OK] wrote {OUT}")
    print(f"condensed {len(full['moves'])} imported moves -> "
          f"{len(campaign['moves'])} campaign moves "
          f"({len(extra_moves)} from host logs), "
          f"{len(campaign['attackers'])} attacker(s)")
    print("\n".join(report + notes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
