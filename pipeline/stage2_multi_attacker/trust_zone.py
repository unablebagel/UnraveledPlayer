"""
trust_zone.py — split co-mingled attackers by the TRUST ZONE each moves toward.

THE GAP THIS CLOSES
-------------------
split_by_sink (attribution.py) separates two attackers who share a pivot by the
EXTERNAL sink each beacons to; split_by_provenance (provenance.py) separates them
by the host LOGIN SESSION each operates under. But neither fires when two
attackers share a foothold, then DIVERGE toward different INTERNAL targets with
NO external sink and NO host provenance — e.g. one pivots toward the public/DMZ
web tier while the other pivots toward the private DB tier. Their apparent source
IP collapses to the shared foothold and actor-continuity (rule A/B) FUSES them.

The identity that survives a shared INTERNAL pivot here is OBJECTIVE: which
trust zone each thread is heading into. Two attackers with different goals cross
different trust boundaries — the DB-bound one enters `intranet_private`, the
web-bound one enters `dmz_public` — and that destination zone is a stable
attribution key even when the source IP is shared. Motive is the OUTPUT (a
thread's dominant target zone), never an input: this is goal/plan recognition,
not a hardcoded "A->web, B->db" rule.

split_by_target_zone is the STRUCTURAL MIRROR of split_by_sink: it anchors on the
TRUST ZONE of each boundary-crossing destination instead of an external sink. The
three are complementary primitives — sink-key splits attackers who EGRESS
distinctly, prov-key splits attackers who LOG IN distinctly, zone-key splits
attackers who move toward distinct OBJECTIVES — and all no-op when their key does
not diverge (a single-zone or single-APT run leaves this a pass-through, so it
cannot disturb the real-data V-measure).
"""

from typing import Callable, Dict, List, Optional

from .attribution import (
    Session, TIME_WINDOW_MS, _nearest_sink, _session_from_events,
)


def make_zone_of(mapper, diagram) -> Callable[[Optional[str]], Optional[str]]:
    """Build an ip -> trust_zone resolver from the diagram.

    Resolution order:
      1. A mapped diagram node -> that node's trust_zone (pinned hosts).
      2. Subnet fallback: the IP's first three octets -> the trust_zone of any
         node declaring that /24 in properties["subnet"]. Lets unmapped intranet
         / DMZ IPs (e.g. 10.1.4.20, 10.1.5.10) still resolve to their zone.
      3. None (external / unknown).
    """
    node_zone: Dict[str, str] = {n.id: n.trust_zone for n in diagram.nodes}

    # {first-3-octets: trust_zone} from each node's declared subnet.
    prefix_zone: Dict[str, str] = {}
    for n in diagram.nodes:
        subnet = n.properties.get("subnet") if n.properties else None
        if not subnet:
            continue
        octets = subnet.split("/")[0].split(".")
        if len(octets) >= 3:
            prefix_zone.setdefault(".".join(octets[:3]), n.trust_zone)

    def zone_of(ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        node_id = mapper.map_ip_to_node(ip)
        if node_id and node_id in node_zone:
            return node_zone[node_id]
        octets = ip.split(".")
        if len(octets) >= 3:
            return prefix_zone.get(".".join(octets[:3]))
        return None

    return zone_of


def _crosses(ev, zone_of) -> Optional[str]:
    """The destination trust zone IFF this event crosses a trust boundary.

    A move anchors to zone_of(dst) only when BOTH endpoints resolve to a zone and
    those zones DIFFER. Initial-access events (external src -> zone None) and
    intra-zone moves are not crossings -> they attach by time, keeping the shared
    foothold as the genuinely shared part.
    """
    src_zone = zone_of(ev.src_ip)
    dst_zone = zone_of(ev.dst_ip)
    if src_zone and dst_zone and src_zone != dst_zone:
        return dst_zone
    return None


def split_by_target_zone(sessions: List[Session], mapper, zone_of,
                         time_window_ms: int = TIME_WINDOW_MS) -> List[Session]:
    """
    SPLIT one inferred session whose boundary-crossing events target MULTIPLE
    distinct trust zones into one sub-session per target zone — the complement of
    split_by_sink, keyed on the destination's trust zone instead of an external
    sink.

      1. ANCHOR every trust-boundary-crossing event (zone_of(src) != zone_of(dst))
         to its destination-zone thread.
      2. Each shared INGRESS login (external src -> internal foothold) is grouped
         by its DISTINCT SOURCE IP -> one thread per origin. The source IP is an
         OBSERVED fact, so N distinct origins into one foothold surface as N
         sessions (attacker CARDINALITY — the foothold is under attack from N
         source IPs). This is NOT binding: no ingress thread is merged into a
         downstream zone campaign (that would need host-login provenance we do not
         have here), so the foothold is shown compromised by N distinct origins
         without guessing which origin fed which objective.
      3. ATTACH each remaining non-crossing event (intra-zone move) to the
         nearest-in-time anchor within time_window_ms; if none is in range it
         goes to an "__unattributed__" thread (honest: no signal => no guess).
      4. Rebuild one fresh Session per thread.

    Sessions whose crossings reach <= 1 distinct zone pass through unchanged.
    Generic: keyed on an opaque zone string, no hardcoded IPs. NO-OP whenever the
    target zones do not diverge (e.g. the real single-APT run).
    """
    out: List[Session] = []
    for s in sessions:
        zones = {z for z in (_crosses(ev, zone_of) for ev in s.events) if z}
        if len(zones) <= 1:
            out.append(s)
            continue

        # 1. anchors: (time, target-zone) for every boundary-crossing event.
        anchors = sorted((ev.time, _crosses(ev, zone_of)) for ev in s.events
                         if _crosses(ev, zone_of))
        threads: Dict[str, list] = {}
        for ev in s.events:
            zone = _crosses(ev, zone_of)
            if zone:
                threads.setdefault(zone, []).append(ev)              # anchored
                continue
            # 2. INGRESS (external src -> internal zone): a shared foothold. Group
            #    by DISTINCT SOURCE IP -> one thread per origin. The source IP is an
            #    observed fact (cardinality: how many attackers entered), so two
            #    origins into one foothold surface as two sessions. This is NOT
            #    binding: neither is merged into a downstream zone campaign (that
            #    needs host-login provenance), so the foothold is shown compromised
            #    by each origin without guessing which fed which objective.
            if zone_of(ev.src_ip) is None and zone_of(ev.dst_ip) is not None:
                threads.setdefault(f"__ingress__::{ev.src_ip}", []).append(ev)
                continue
            # 3. other non-crossing (intra-zone move) -> nearest anchor in time.
            key = _nearest_sink(ev.time, anchors, time_window_ms)
            threads.setdefault(key or "__unattributed__", []).append(ev)

        # 4. rebuild a fresh session per thread.
        for thread_events in threads.values():
            out.append(_session_from_events(s.id, thread_events, mapper))

    for new_id, s in enumerate(out):
        s.id = new_id
    return out
