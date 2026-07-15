"""
streaming_timeline.py — ONLINE (causally honest) per-attacker timeline, Option 2.

WHAT CHANGED (and why)
----------------------
The batch pipeline attributes with split_by_target_zone, which is a RETROSPECTIVE
partition: it waits until a session's crossings reach >= 2 distinct trust zones, then
re-buckets ALL of that session's events — including the shared non-crossing host
it_host_3 — by nearest crossing anchor in time (attribution.py:_nearest_sink). Re-run
per checkpoint, that shows up as a "re-split": it_host_3 sits in one thread (S2) through
t=5000, then at t=6000 (when the DB crossing is first seen) its earlier compromise is
retroactively re-partitioned so it lands in {S2, S3}. History gets rewritten.

Option 2 uses the SAME trust-zone signal, but PROSPECTIVELY and forward-only. A boundary
crossing is read as a forward commitment: the instant a campaign crosses OUT of a zone,
it has vacated the hosts it held there. So a FRESH compromise of an already-owned host,
whose owner has since crossed into a different zone, is attributed to a NEW actor at the
moment it is observed — never by rewriting the past.

    once a campaign compromises it_host_3 (IT zone) and then CROSSES into the App zone,
    a later compromise of it_host_3 is a different actor -> seed a new session there,
    right then (t=5000), instead of retro-binding it to the App campaign at t=6000.

The signal is still the trust zone (the crossing is what says "has departed the IT
zone"). Two things are layered on top: (1) causal ordering — the crossing is used
forward, the past is never re-partitioned; (2) a no-backtrack prior — an actor that
crossed out of a zone is assumed not to return to it. The prior is the one heuristic
ingredient: a legitimate return (e.g. cleanup) is over-segmented as a new actor, which
is the safe (over-, not wrong-merge) failure mode.

THE ONLINE ATTRIBUTOR (_forward_attribute)
------------------------------------------
Walk events in time order, assign each PERMANENTLY (never re-partitioned):

  * INGRESS (external src -> internal foothold): group by DISTINCT SOURCE IP -> one
    ingress session per origin. Two source IPs into one foothold is an observed fact, so
    the foothold's attacker CARDINALITY (S0, S1) surfaces the moment the 2nd login lands.
    Binding an origin to a downstream campaign is deferred (no host-login provenance).

  * INTERNAL move (src internal), in priority order:
      - RE-COMPROMISE / no-backtrack: if the destination is already held by a campaign
        that has since CROSSED into a different zone, this is a new actor -> seed a new
        campaign session here.
      - CONTINUE: otherwise extend the most recent campaign active at the SOURCE node
        (temporal continuity from the shared foothold; deterministic under the
        per-attacker-block ordering the scenario emits).
      - SEED: if no campaign is active at the source yet, start a fresh one (the first
        internal lateral becomes a real session immediately — no "unresolved").

Because every event's session is fixed once assigned, session ids are stable by
construction (no frame-to-frame tracking needed) and NOTHING is ever re-split: it_host_3
becomes {S2, S3} at t=5000 — the instant the re-compromise is observed — and stays that
way. Only the engine's session/fact folding (_session_from_events) and the trust-zone
crossing test (_crosses) are imported; nothing shared is modified.
"""

from ..mapping_layer import MappingLayer
from ..state_demo import get_node_predicates
from ..stage1_streaming.replay import (
    state_distribution, _label_of, iso, _COMPROMISE_FACT_TYPES,
)
from ..stage2_multi_attacker.attribution import _session_from_events
from ..stage2_multi_attacker.trust_zone import _crosses


def _ingress_origins(session, zone_of):
    """Distinct external source IPs that logged into an internal node (foothold)."""
    return {ev.src_ip for ev in session.events
            if zone_of(ev.src_ip) is None and zone_of(ev.dst_ip) is not None}


def _forward_attribute(events, mapper, zone_of):
    """Forward-only, causal session assignment (Option 2). No re-partitioning.

    Returns {id(event): session_id}. Each event is assigned exactly once, in time
    order, and never moved — so ids are stable across every prefix and no frame is
    ever re-split.
    """
    node_of = lambda ip: mapper.map_ip_to_node(ip) if ip else None

    assign = {}                 # id(ev)          -> session id
    origin_sid = {}             # external src_ip -> ingress session id
    last_campaign = {}          # node id         -> most recent campaign active there
    held_by = {}                # node id         -> most recent campaign holding it
    comp_time = {}              # (sid, node id)  -> time that campaign compromised it
    crossings = {}              # sid             -> [(time, dst_zone), ...]
    next_sid = 0

    def new_sid():
        nonlocal next_sid
        sid = next_sid
        next_sid += 1
        return sid

    def has_departed(sid, node, node_zone):
        """Did campaign `sid` cross into a DIFFERENT zone after taking `node`?"""
        t0 = comp_time.get((sid, node))
        if t0 is None:
            return False
        return any(t > t0 and z != node_zone for t, z in crossings.get(sid, []))

    for ev in sorted(events, key=lambda e: e.time):
        s_zone, d_zone = zone_of(ev.src_ip), zone_of(ev.dst_ip)
        d_node = node_of(ev.dst_ip)

        # INGRESS: external src -> internal foothold. One session per distinct origin.
        if s_zone is None and d_zone is not None:
            sid = origin_sid.get(ev.src_ip)
            if sid is None:
                sid = origin_sid[ev.src_ip] = new_sid()
            assign[id(ev)] = sid
            if d_node is not None:
                held_by[d_node] = sid
                comp_time.setdefault((sid, d_node), ev.time)
            continue

        # INTERNAL move (lateral or boundary crossing).
        s_node = node_of(ev.src_ip)
        prior = held_by.get(d_node)
        if prior is not None and has_departed(prior, d_node, d_zone):
            sid = new_sid()                                 # re-compromise: new actor
        else:
            sid = last_campaign.get(s_node)                 # continue current campaign
            if sid is None:
                sid = new_sid()                             # or seed the first one here

        assign[id(ev)] = sid
        if s_node is not None:
            last_campaign[s_node] = sid
        if d_node is not None:
            last_campaign[d_node] = sid
            held_by[d_node] = sid
            comp_time[(sid, d_node)] = ev.time
        crossing_zone = _crosses(ev, zone_of)
        if crossing_zone:
            crossings.setdefault(sid, []).append((ev.time, crossing_zone))

    return assign


def _describe(session, zone_of):
    """Human-readable session kind from its content (for the legend)."""
    origins = sorted(_ingress_origins(session, zone_of))
    crossings = sorted({z for ev in session.events if (z := _crosses(ev, zone_of))})
    if crossings:
        return "objective campaign -> " + ",".join(crossings)
    if origins:
        return "foothold ingress from " + ", ".join(origins)
    return "campaign (objective not yet observed)"


def _role(session):
    """recon-only until the session has any compromise (attack_source) fact."""
    return ("foothold/active"
            if any(f.fact_type in _COMPROMISE_FACT_TYPES for f in session.facts)
            else "recon-only")


def build_streaming_snapshots(diagram, events, zone_of):
    """One snapshot per checkpoint, each attributed from ONLY the events up to `t`.

    Returns (snapshots, sessions): snapshots share the shape build_snapshots emits
    (per-node `per_attacker` map keyed by stable session id "S<n>"), and `sessions` is
    the legend registry. Attribution is forward-only (_forward_attribute), so a session,
    once formed, is never re-partitioned — the shared host it_host_3 gains its second
    state at the instant the re-compromise is observed and keeps it thereafter.
    """
    mapper = MappingLayer(diagram)
    times = sorted({ev.time for ev in events})

    # forward-only assignment, computed once; ids are stable across every prefix.
    assign = _forward_attribute(events, mapper, zone_of)

    # per checkpoint, group the observed-so-far events by their fixed session id.
    labeled = []
    for t in times:
        groups = {}
        for ev in events:
            if ev.time <= t:
                groups.setdefault(assign[id(ev)], []).append(ev)
        row = [(sid, _session_from_events(sid, evs, mapper))
               for sid, evs in sorted(groups.items())]
        labeled.append((t, row))

    # render per-node per-attacker state, collapsing identical frames.
    snapshots, prev = [], None
    for t, row in labeled:
        per_sess = {}
        for sid, s in row:
            name = f"S{sid}"
            per_sess[name] = {
                "dist": state_distribution(s.facts, MappingLayer(diagram)),
                "state": MappingLayer(diagram).build_diagram_state(s.facts),
                "role": _role(s),
            }

        buckets = {"COMPROMISED": [], "ACCESSED": [], "CLEAN": []}
        details = {}
        agg = state_distribution([f for _sid, s in row for f in s.facts],
                                 MappingLayer(diagram))
        for node in diagram.nodes:
            d = agg.get(node.id)
            buckets["CLEAN" if d is None else _label_of(d)[0]].append(node.id)

            per_attacker = {}
            for name, blob in per_sess.items():
                sd = blob["dist"].get(node.id)
                if sd is None:
                    continue
                status, conf = _label_of(sd)
                st = blob["state"]
                mitre = st.get_mitre_summary(node.id) or {}
                per_attacker[name] = {
                    "status": status,
                    "confidence": conf,
                    "distribution": {k: round(v, 4) for k, v in sd.items()},
                    "role": blob["role"],
                    "predicates": get_node_predicates(st, node.id),
                    "techniques": mitre.get("mitre_techniques", []),
                }
            if not per_attacker:
                continue
            details[node.id] = {
                "name": node.name, "trust_zone": node.trust_zone,
                "ips": node.ip_addresses, "per_attacker": per_attacker,
            }

        snap = {"summary": {"compromised": buckets["COMPROMISED"],
                            "accessed": buckets["ACCESSED"],
                            "clean": buckets["CLEAN"]},
                "node_details": details}
        if snap["node_details"] == prev:
            continue
        prev = snap["node_details"]
        snapshots.append({"index": len(snapshots), "time": t, "iso": iso(t), **snap})

    # legend registry — richest info from the LAST frame each id appears in.
    last = {}
    for t, row in labeled:
        for sid, s in row:
            last[sid] = s
    sessions = []
    for sid, s in sorted(last.items()):
        gt = dict(s.gt_counter)
        sessions.append({
            "session": f"S{sid}",
            "kind": _describe(s, zone_of),
            "actor_ips": sorted(s.actor_ips),
            "compromised_nodes": sorted(s.compromised_nodes),
            "eval_ground_truth": {
                "attribution_counts": gt,
                "majority": max(gt, key=gt.get) if gt else "",
            },
        })
    return snapshots, sessions
