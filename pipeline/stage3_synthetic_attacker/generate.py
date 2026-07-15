"""
generate.py — synthesize OCSF alerts for the two multi-attacker demo scenarios.

The real UNRAVELED dataset has a single APT, so the multi-attacker splits never
fire on it. This module fabricates clean, minimal scenarios that do:

  build_c2_scenario          TWO attackers (A="APT", Z) SHARE the gateway foothold
                             (compromised, NO C2 there), then DIVERGE: A pivots to
                             it_host_1 and Z to it_host_5, and each performs
                             exfil-over-C2 from THAT host to its OWN external sink.
                             split_by_sink attributes each downstream host to the
                             right attacker by the distinct sink it exfils to.

  build_provenance_scenario  TWO operators share ONE internal foothold and move
                             internal->internal only (no external sink); told apart
                             by login-session provenance (split_by_provenance).

  build_trust_zone_scenario  TWO attackers (APT09, APT54) share ONE internal
                             foothold and DIVERGE toward different trust zones —
                             APT09 progressively into the public/DMZ web tier,
                             APT54 into the private DB tier. No external sink, no
                             provenance; told apart by the destination TRUST ZONE
                             each moves toward (split_by_target_zone).

Alerts are emitted in the OCSF "Detection Finding" shape the real pipeline loads
(see ocsf_to_facts._load_jsonl / _get_observables / _alert_to_facts), so they flow
through build_events -> attribute -> split_by_* unchanged. Both scenarios are
deliberately tiny (a handful of events) so the timeline stays to a few snapshots.

    python -m ComparisonToTM.log_to_diagram_demo.stage3_synthetic_attacker.generate
"""

import json
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

_OUT = Path(__file__).parent / "synthetic_alerts.jsonl"

# --- C2 scenario: two attackers SHARE the gateway foothold, then diverge ------ #
# Each compromises the gateway (foothold, NO C2/exfil there), pivots to its OWN
# internal host, and exfils-over-C2 from that host to its OWN external sink. The
# distinct sinks are what split_by_sink uses to attribute the two downstream hosts.
C2_PIVOT = "192.168.0.11"          # shared gateway foothold (perimeter)
C2_ATTACKERS = [
    # (gt label, external entry IP, downstream host IP, external C2/exfil sink)
    ("Advanced Persistent Threat", "203.0.113.7",  "10.1.3.8",  "198.51.100.10"),  # -> it_host_1
    ("Synthetic Attacker (Z)",     "198.51.100.7", "10.1.3.17", "203.0.113.66"),   # -> it_host_5
]

# --- provenance scenario: two operators on ONE internal pivot, internal-only -- #
# Both source from this foothold (so attribute() fuses them on source IP), move
# INTERNAL -> INTERNAL (no external sink), and are told apart ONLY by their
# login-session key (audit `ses` + the `auth` SSH-accept source).
PROV_PIVOT = "10.1.3.8"            # shared internal foothold (it_host_1)
PROV_ATTACKERS = [
    # (gt label, login_session key, [internal targets it pivots toward])
    ("Operator P", "ses=1142@10.1.1.18", ["10.1.3.12", "10.1.5.21"]),
    ("Operator Q", "ses=2207@10.1.3.14", ["10.1.2.17", "10.1.1.11"]),
]

# --- trust-zone scenario: shared foothold, then diverge toward distinct zones - #
# Both attackers compromise the SAME IT-subnet foothold (10.1.3.10), then pivot
# progressively into DIFFERENT trust zones: APT09 toward the public/DMZ web tier
# (10.1.4.x = dmz_public), APT54 toward the private DB tier (10.1.5.x =
# intranet_private, ending at the MySQL database). No external sink, no
# provenance; the destination trust zone is the only separating signal.
TZ_PIVOT = "10.1.3.10"             # shared IT-subnet foothold (it_host_2)
TZ_ATTACKERS = [
    # (gt label, external entry IP, initial-access technique-id,
    #  [internal hops it pivots toward, in order])
    ("APT09", "203.0.113.9",  "T1078",     ["10.1.4.16", "10.1.4.20"]),   # -> dmz_public (honeypot, web)
    ("APT54", "198.51.100.54", "T1078.003", ["10.1.5.10", "10.1.5.21"]),   # -> intranet_private (intranet, db)
]

# (technique, tactic, tactic-name, kill-chain phase, phase_id, stage, desc)
_FOOTHOLD = ("T1078", "TA0001", "Initial Access", "Initial Access", 1,
             "Initial Access", "Valid-accounts login (shared gateway foothold)")
_SSH_LATERAL = ("T1021.004", "TA0008", "Lateral Movement", "Lateral Movement", 5,
                "Lateral Movement", "SSH lateral movement to internal host")
_EXFIL = ("T1041", "TA0010", "Exfiltration", "Exfiltration", 7,
          "Exfiltration", "Exfiltration over C2 channel")


def make_alert(time, src_ip, dst_ip, dst_port, spec, attribution, uid, count=12,
               prov=None):
    """Build one OCSF Detection Finding matching the real schema.

    `prov` (optional) is a login-session identity (host provenance). When set it is
    written to unmapped.provenance.login_session, where build_events picks it up so
    stage2_multi_attacker.provenance.split_by_provenance can separate co-mingled attackers
    on it. Left None for the C2 scenario (which separates on the external sink).
    """
    tech, tactic, tac_name, phase, phase_id, stage, desc = spec
    obs = [
        {"type_id": 2, "name": "evidences[0].src_endpoint.ip", "value": src_ip},
    ]
    evid = {"src_endpoint": {"ip": src_ip}}
    if dst_ip:
        obs.append({"type_id": 2, "name": "evidences[0].dst_endpoint.ip",
                    "value": dst_ip})
        evid["dst_endpoint"] = {"ip": dst_ip, "port": dst_port}
        if dst_port:
            obs.append({"type_id": 11, "name": "evidences[0].dst_endpoint.port",
                        "value": str(dst_port)})
    unmapped = {
        "unraveled_stage": stage, "unraveled_signature": "SYNZ",
        "unraveled_activity": desc, "top7_category_display": "Synthetic Activity",
        "severity_display": "HIGH", "cloud_provider": "Unknown",
        "raw_data": {"total_records": count, "data_type": "network_flow",
                     "unique_dst_ips": 1 if dst_ip else 0},
        "attacker_attribution": attribution, "is_apt": False,
        "synthetic": True,
    }
    if prov is not None:
        unmapped["provenance"] = {"login_session": prov}
    return {
        "class_uid": 2004, "class_name": "Detection Finding",
        "category_uid": 2, "category_name": "Findings",
        "activity_id": 1, "activity_name": "Create",
        "type_uid": 200401, "type_name": "Detection Finding: Create",
        "time": time, "severity_id": 4,
        "message": f"Synthetic: {desc} ({count} records aggregated)",
        "finding_info": {
            "uid": uid, "title": "Synthetic Activity", "desc": desc,
            "types": [f"mitre_attack:{tech}", f"mitre_tactic:{tactic}"],
            "attacks": [{
                "technique": {"uid": tech, "name": desc},
                "tactic": {"uid": tactic, "name": tac_name},
                "version": "v14.1",
            }],
            "kill_chain": [{"phase": phase, "phase_id": phase_id}],
        },
        "start_time": time - count * 1000, "end_time": time,
        "count": count, "status_id": 1,
        "evidences": [evid],
        "observables": obs,
        "metadata": {"version": "1.8.0",
                     "product": {"name": "Synthetic Generator",
                                 "vendor_name": "TM Project (synthetic)"}},
        "unmapped": unmapped,
    }


def build_c2_scenario(base_time, pivot=C2_PIVOT, attackers=C2_ATTACKERS,
                      campaign_gap_ms=10 * 60 * 1000):
    """
    Two attackers share the gateway foothold, then diverge to distinct internal
    hosts and exfil-over-C2 to DISTINCT external sinks.

    Per attacker, 3 events: (1) Valid-accounts foothold on the gateway — compromise,
    NO C2; (2) SSH lateral gateway -> its own host — compromise that host; (3)
    exfil-over-C2 from that host to its own sink. The two campaigns are placed
    `campaign_gap_ms` apart (>> the 60 s attach window) so each internal move
    attaches to its OWN attacker's sink anchor, never the other's. Foothold and
    lateral share a timestamp (foothold first, so the lateral's gateway source
    links by actor-continuity); the exfil follows a second later. Result after
    split_by_sink: it_host_1 -> A's sink, it_host_5 -> Z's sink; gateway shared.
    """
    alerts = []
    for i, (gt, entry, node, sink) in enumerate(attackers):
        t = base_time + i * campaign_gap_ms
        alerts.append(make_alert(t, entry, pivot, 22, _FOOTHOLD, gt, f"SYNC2-{i}-FH"))
        alerts.append(make_alert(t, pivot, node, 22, _SSH_LATERAL, gt, f"SYNC2-{i}-LAT"))
        alerts.append(make_alert(t + 1000, node, sink, 443, _EXFIL, gt, f"SYNC2-{i}-EXF"))
    return alerts


def build_provenance_scenario(base_time, span_ms=0, pivot=PROV_PIVOT,
                              attackers=PROV_ATTACKERS):
    """
    Two attackers sharing ONE internal foothold, INTERNAL -> INTERNAL only.

    Both source from `pivot` (so attribute() fuses them on source-IP continuity)
    and beacon to NO external sink (so split_by_sink no-ops). The ONLY thing that
    tells them apart is the per-event login-session key (`prov`) — exactly the gap
    split_by_provenance closes. Their moves are INTERLEAVED in time so a temporal
    "closest in time" split would mix them; only the provenance key separates them.

    Events are spread across [base_time, base_time + span_ms]; pass span_ms>0 for a
    genuinely concurrent (interleaved) burst.
    """
    # round-robin the attackers' targets so the two operators overlap in time
    queues = [[(gt, prov, tgt) for tgt in targets] for gt, prov, targets in attackers]
    interleaved = []
    for i in range(max(len(q) for q in queues)):
        for q in queues:
            if i < len(q):
                interleaved.append(q[i])

    n = len(interleaved)
    step = (span_ms // max(n - 1, 1)) if span_ms else 1000
    alerts = []
    t = base_time
    for k, (gt, prov, tgt) in enumerate(interleaved):
        uid = f"SYNPROV-{k:04d}"
        alerts.append(make_alert(t, pivot, tgt, 22, _SSH_LATERAL, gt, uid, prov=prov))
        t += step
    return alerts


def build_trust_zone_scenario(base_time, span_ms=5 * 60 * 1000,
                              pivot=TZ_PIVOT, attackers=TZ_ATTACKERS):
    """
    Two attackers share ONE internal foothold, then DIVERGE toward distinct trust
    zones — APT09 into the public/DMZ web tier, APT54 into the private DB tier.

    Timeline is PHASED, matching the real narrative:

      PHASE 1 — both attackers compromise the SHARED foothold first, in order
      (APT09's foothold, then APT54's), each via its OWN initial-access technique
      ("initial steps differ"). Two distinct external origins authenticate into one
      node: the attacker CARDINALITY (there are 2) is observable here, but neither
      login can yet be BOUND to an objective — both land in the same zone with no
      divergence. split_by_target_zone keeps these ingress events in one shared
      "__ingress__" bucket: cardinality known, binding deferred.

      PHASE 2 — ONLY after both footholds do the attackers DIVERGE toward their
      objectives (APT09 into the public/DMZ web tier, APT54 into the private DB
      tier). The 4 hops are INTERLEAVED round-robin (A,B,A,B) so a "closest in
      time" split cannot separate them; only the destination TRUST ZONE each hop
      crosses into does — exactly the gap split_by_target_zone closes.

    Both source from `pivot`, so attribute() fuses them on source-IP continuity;
    there is NO external sink (split_by_sink no-ops) and NO provenance
    (split_by_provenance no-ops). The destination trust zone is the only signal
    that re-separates the diverged threads.
    """
    # ports chosen to match each target node's service; they do not affect zone
    # attribution. .16 honeypot=SSH(22, default), .20 web=HTTP(80),
    # .10 intranet_app=HTTP(80), .21 database=MySQL(3306).
    hop_port = {"10.1.4.20": 80, "10.1.5.10": 80, "10.1.5.21": 3306}

    n_foot = len(attackers)
    n_hops = sum(len(hops) for _g, _e, _t, hops in attackers)
    step = (span_ms // (n_foot + n_hops)) if span_ms else 1000

    alerts = []
    t = base_time + step

    # PHASE 1 — footholds, ordered (APT09 then APT54), both BEFORE any divergence.
    for i, (gt, entry, ia_tech, _hops) in enumerate(attackers):
        foothold_spec = (ia_tech, "TA0001", "Initial Access", "Initial Access", 1,
                         "Initial Access",
                         f"Valid-accounts login ({gt} shared foothold)")
        alerts.append(make_alert(t, entry, pivot, 22, foothold_spec, gt,
                                 f"SYNTZ-{i}-FH"))
        t += step

    # PHASE 2 — lateral hops, interleaved round-robin, all AFTER both footholds.
    queues = [[(gt, hop) for hop in hops] for gt, _e, _t, hops in attackers]
    interleaved = []
    for k in range(max(len(q) for q in queues)):
        for q in queues:
            if k < len(q):
                interleaved.append(q[k])
    for j, (gt, hop) in enumerate(interleaved):
        alerts.append(make_alert(t, pivot, hop, hop_port.get(hop, 22),
                                  _SSH_LATERAL, gt, f"SYNTZ-LAT-{j:02d}"))
        t += step
    return alerts


def write_jsonl(alerts, path=_OUT):
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
    return path


def main() -> int:
    alerts = build_c2_scenario(base_time=1_700_000_000_000)
    path = write_jsonl(alerts)
    print(f"[OK] wrote {len(alerts)} synthetic C2-scenario alerts -> {path}", flush=True)
    for gt, entry, node, sink in C2_ATTACKERS:
        print(f"     {gt}: {entry} -> {C2_PIVOT} (foothold) -> {node} -> {sink} (exfil)",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
