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

Host-log alerts carry no dst_endpoint, so they cannot become src->dst moves
directly — but silently dropping all 10 of them would erase the "Skilled
Hackers" actor, who only ever appears in host logs (one T1566.001
spearphishing detection on hr_host_5). So attackers with NO network-flow
presence get their initial-access host-log alert (T1078/T1566.001)
represented as a foothold move from EXTERNAL onto the observed host, at the
alert's start_time. Host logs record no source IP, so such an attacker's
entry_ip is a TEST-NET-3 placeholder (203.0.113.x), flagged in the move's
`kind`.

What is intentionally lost relative to the raw stream:
  - alert volume (kept only as the "aggregates N alerts" note in `kind`);
  - host-log behaviors of attackers already present via network flows (e.g.
    the APT's valid-account logons and SSH tunneling on the it hosts): their
    source/destination is not observable, and the actor is already on the map.

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


def hostlog_footholds(alerts: list, known_attackers: set) -> tuple:
    """(attackers, moves) synthesized for actors that appear ONLY in host
    logs: their first initial-access host-log alert becomes a foothold move
    from EXTERNAL onto the observed host."""
    ip2node = _reverse_ip_map(_TOPOLOGY_LOADERS["unraveled"]())
    seen = set(known_attackers)
    attackers, moves = [], []
    for a in alerts:
        unmapped = a.get("unmapped") or {}
        if unmapped.get("raw_data", {}).get("data_type") != "host_log":
            continue
        name = unmapped.get("attacker_attribution")
        attacks = (a.get("finding_info") or {}).get("attacks") or []
        tech = attacks[0]["technique"]["uid"] if attacks else None
        host_ip = ((a.get("evidences") or [{}])[0].get("src_endpoint") or {}).get("ip")
        if not name or name in seen or tech not in _INITIAL_ACCESS or not host_ip:
            continue
        seen.add(name)
        attackers.append({
            "name": name,
            "entry_ip": _PLACEHOLDER_ENTRY.format(50 + len(attackers)),
            "initial_access": tech, "prov": None, "default_port": 22,
        })
        moves.append({
            "attacker": name, "src": "external",
            "dst": ip2node.get(host_ip, host_ip), "technique": tech,
            "t": a.get("start_time") or a.get("time"),
            "kind": "foothold; host-log detection (source IP unknown)",
        })
    return attackers, moves


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

    extra_attackers, extra_moves = hostlog_footholds(
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
          f"({len(extra_moves)} host-log foothold(s)), "
          f"{len(campaign['attackers'])} attacker(s)")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
