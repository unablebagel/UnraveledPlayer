"""
attribution.py — generic, label-free attacker-session inference.

PROBLEM
-------
The merged pipeline folds every scoring fact for a node into ONE noisy-OR
distribution. So a perimeter node that attacker A merely *scanned* (recon ->
ACCESSED) and that attacker B's NAT-egress C2 traffic appears to *source from*
(-> COMPROMISED) collapses into a single COMPROMISED verdict. To keep the two
apart we must first decide WHICH attacker each fact belongs to.

GENERIC SESSION-LINKING (no hardcoded IPs / topology roles)
-----------------------------------------------------------
Process alerts in time order. Each carries an apparent actor (source observable),
a victim node, and a timestamp. An alert joins an existing session, or seeds a
new one, by these rules — in priority order:

  A. ACTOR CONTINUITY.  The alert's source IP is already a known actor identity
     of some session  ->  join it.

  B. FOOTHOLD PROMOTION.  When a session COMPROMISES a node (a fact that implies
     execCode on it), that node's IP is added to the session's actor-identity
     set. Thereafter alerts sourced from that node link via rule A. This is the
     generic lateral-movement link: a node can launch attacks for a session only
     AFTER that session owns it — which also means a node that merely *appears*
     to source traffic (NAT egress, never actually compromised) never silently
     adopts someone else's activity.

  C. TIMING + PATH (fallback, only when A/B miss).  If the source is unknown or
     unmatched, attach to the most recent still-active session (within
     TIME_WINDOW_MS) that has touched the same node or a topology-adjacent one.
     Requires BOTH tight time AND adjacency, so it links bursts of the same
     actor without merging unrelated campaigns.

  Otherwise  ->  seed a NEW session with the source as its first actor identity.

The result over-segments a campaign whenever the linking hops were never
observed (e.g. lateral movement that left no alert) — which is the honest,
label-free outcome: the algorithm cannot connect what it never saw. Where the
hops ARE observed, rule B collapses the chain automatically.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..ocsf_to_facts import (
    _alert_to_facts, _get_observables, _is_internal, _load_jsonl, _DEFAULT_JSONL,
)
from ..stage1_streaming.replay import _COMPROMISE_FACT_TYPES, _SCORING_FACT_TYPES

# How close in time (ms) two events must be for the rule-C timing fallback.
# "those within less than a minute of each other are likely the same person."
TIME_WINDOW_MS = 60_000

# Window for the rendezvous merge (rule D, post-pass): two sessions that beacon
# to the SAME external sink within this gap are the same campaign. Wide on
# purpose — C2 infrastructure is reused across a whole campaign (days/weeks); the
# window only guards against fusing unrelated incidents that recycled an IP much
# later.
RENDEZVOUS_WINDOW_MS = 14 * 24 * 60 * 60 * 1000   # 14 days


@dataclass
class AlertEvent:
    """One alert reduced to what attribution needs, plus its scoring facts."""
    time: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    facts: list                       # scoring ObservedFacts (time-stamped)
    gt: str = ""                      # ground-truth attribution — EVAL ONLY
    prov: Optional[str] = None        # login-session identity (host provenance)


@dataclass
class Session:
    """An inferred attacker. Identity is the set of IPs it operates from."""
    id: int
    actor_ips: set = field(default_factory=set)
    touched_nodes: set = field(default_factory=set)       # node IDs (mapped)
    compromised_nodes: set = field(default_factory=set)
    techniques: set = field(default_factory=set)
    facts: list = field(default_factory=list)             # scoring facts
    events: list = field(default_factory=list)            # source AlertEvents (for sink-split)
    external_dst_times: dict = field(default_factory=dict)  # ext sink IP -> [times]
    first_time: Optional[int] = None
    last_time: Optional[int] = None
    gt_counter: Counter = field(default_factory=Counter)  # EVAL ONLY

    @property
    def name(self) -> str:
        return f"S{self.id}"

    @property
    def role(self) -> str:
        """Coarse, label-free role: did this session ever gain a foothold?"""
        return "recon-only" if not self.compromised_nodes else "foothold/active"


def build_events(path=None) -> List[AlertEvent]:
    """
    Load alerts and reduce each to an AlertEvent carrying its time-stamped
    scoring facts. Time anchoring mirrors stage1_streaming.loader: host-log alerts
    are anchored at start_time (when the behavior began), network alerts at time
    (window end). LABEL-FREE except gt, which is stored separately for eval.
    """
    alerts = _load_jsonl(_DEFAULT_JSONL if path is None else path)
    events: List[AlertEvent] = []
    for alert in alerts:
        unmapped = alert.get("unmapped", {})
        is_host_log = unmapped.get("raw_data", {}).get("data_type") == "host_log"
        anchor = alert.get("start_time") if is_host_log else alert.get("time")
        src_ip, dst_ip, _ = _get_observables(alert)

        facts = []
        for f in _alert_to_facts(alert):
            if f.fact_type not in _SCORING_FACT_TYPES:
                continue
            f.details.setdefault("time", anchor)
            facts.append(f)
        if not facts:
            continue
        events.append(AlertEvent(
            time=anchor or 0,
            src_ip=src_ip,
            dst_ip=dst_ip,
            facts=facts,
            gt=unmapped.get("attacker_attribution", ""),
            # Login-session provenance, if the source log carried it (auth `from`
            # IP + sshd PID, audit `auid`/`ses`). Absent on summarized network
            # alerts -> None -> the provenance split (provenance.py) no-ops.
            prov=unmapped.get("provenance", {}).get("login_session"),
        ))
    return events


def _fact_node(fact, mapper) -> Optional[str]:
    ip = fact.details.get("node") or fact.details.get("data_store")
    return mapper.map_ip_to_node(ip) if ip else None


def _adjacency(diagram) -> Dict[str, set]:
    """Undirected node adjacency from diagram edges (for the rule-C path test)."""
    adj: Dict[str, set] = {}
    for e in diagram.edges:
        adj.setdefault(e.source_id, set()).add(e.target_id)
        adj.setdefault(e.target_id, set()).add(e.source_id)
    return adj


def attribute(events: List[AlertEvent], mapper, diagram,
              time_window_ms: int = TIME_WINDOW_MS) -> List[Session]:
    """Assign every event to an inferred Session. Returns sessions in birth order."""
    adj = _adjacency(diagram)
    sessions: List[Session] = []
    actor_index: Dict[str, Session] = {}   # ip -> session that operates from it

    def event_nodes(ev) -> set:
        return {n for n in (_fact_node(f, mapper) for f in ev.facts) if n}

    def path_link(ev) -> Optional[Session]:
        """Rule C: most recent active session touching this/adjacent node."""
        ev_nodes = event_nodes(ev)
        if not ev_nodes:
            return None
        reachable = set(ev_nodes)
        for n in ev_nodes:
            reachable |= adj.get(n, set())
        best = None
        for s in sessions:
            if s.last_time is None or ev.time - s.last_time > time_window_ms:
                continue
            if s.touched_nodes & reachable:
                if best is None or s.last_time > best.last_time:
                    best = s
        return best

    for ev in sorted(events, key=lambda e: e.time):
        # Rule A (+ B, since promoted footholds live in actor_index).
        sess = actor_index.get(ev.src_ip) if ev.src_ip else None
        # Rule C: timing + path fallback.
        if sess is None:
            sess = path_link(ev)
        # Otherwise a new session.
        if sess is None:
            sess = Session(id=len(sessions))
            sessions.append(sess)
            if ev.src_ip:
                sess.actor_ips.add(ev.src_ip)
                actor_index[ev.src_ip] = sess

        # Fold the event into the chosen session.
        sess.events.append(ev)
        sess.first_time = ev.time if sess.first_time is None else min(sess.first_time, ev.time)
        sess.last_time = ev.time if sess.last_time is None else max(sess.last_time, ev.time)
        # Record an EXTERNAL destination as a rendezvous identity (rule D below).
        # Internal destinations never count — a scan OF a perimeter node must not
        # share identity with C2 traffic THROUGH it.
        if ev.dst_ip and not _is_internal(ev.dst_ip):
            sess.external_dst_times.setdefault(ev.dst_ip, []).append(ev.time)
        if ev.gt:
            sess.gt_counter[ev.gt] += 1
        for f in ev.facts:
            node = _fact_node(f, mapper)
            if not node:
                continue
            sess.facts.append(f)
            sess.touched_nodes.add(node)
            tech = f.details.get("technique")
            if tech:
                sess.techniques.add(tech)
            if f.fact_type in _COMPROMISE_FACT_TYPES:
                sess.compromised_nodes.add(node)
                # Rule B: this node now launches attacks for this session.
                node_ip = f.details.get("node") or f.details.get("data_store")
                if node_ip and node_ip not in actor_index:
                    sess.actor_ips.add(node_ip)
                    actor_index[node_ip] = sess

    return sessions


def _merge_group(group: List[Session]) -> Session:
    """Fold several sessions into one (used by the rendezvous merge).

    Always returns a FRESH Session — never mutates or returns an input object —
    so the caller's pre-merge session list (and its eval) stays intact.
    """
    m = Session(id=min(s.id for s in group))
    for s in group:
        m.actor_ips |= s.actor_ips
        m.touched_nodes |= s.touched_nodes
        m.compromised_nodes |= s.compromised_nodes
        m.techniques |= s.techniques
        m.facts.extend(s.facts)
        m.events.extend(s.events)
        m.gt_counter.update(s.gt_counter)
        for ip, ts in s.external_dst_times.items():
            m.external_dst_times.setdefault(ip, []).extend(ts)
        if s.first_time is not None:
            m.first_time = s.first_time if m.first_time is None else min(m.first_time, s.first_time)
        if s.last_time is not None:
            m.last_time = s.last_time if m.last_time is None else max(m.last_time, s.last_time)
    return m


def _session_from_events(orig_id: int, events: list, mapper) -> Session:
    """Re-fold a subset of events into a FRESH Session, mirroring attribute()'s
    fold. Self-contained: a thread owns the IPs it sources from plus any node it
    compromised (foothold), so the split is internally consistent without the
    cross-session actor_index."""
    s = Session(id=orig_id)
    for ev in sorted(events, key=lambda e: e.time):
        s.events.append(ev)
        if ev.src_ip:
            s.actor_ips.add(ev.src_ip)
        s.first_time = ev.time if s.first_time is None else min(s.first_time, ev.time)
        s.last_time = ev.time if s.last_time is None else max(s.last_time, ev.time)
        if ev.dst_ip and not _is_internal(ev.dst_ip):
            s.external_dst_times.setdefault(ev.dst_ip, []).append(ev.time)
        if ev.gt:
            s.gt_counter[ev.gt] += 1
        for f in ev.facts:
            node = _fact_node(f, mapper)
            if not node:
                continue
            s.facts.append(f)
            s.touched_nodes.add(node)
            tech = f.details.get("technique")
            if tech:
                s.techniques.add(tech)
            if f.fact_type in _COMPROMISE_FACT_TYPES:
                s.compromised_nodes.add(node)
                node_ip = f.details.get("node") or f.details.get("data_store")
                if node_ip:
                    s.actor_ips.add(node_ip)
    return s


def split_by_sink(sessions: List[Session], mapper,
                  time_window_ms: int = TIME_WINDOW_MS) -> List[Session]:
    """
    Rule D-inverse (post-pass): SPLIT one inferred session whose events fan out to
    MULTIPLE distinct EXTERNAL sinks (C2 / exfil) into one sub-session per sink.

    The complement of merge_by_rendezvous. When two attackers share a pivot, their
    apparent source IP collapses and actor-continuity (rule A/B) fuses them into one
    session. The identity that SURVIVES the shared pivot is the external sink each
    one beacons to: distinct sinks => distinct attackers. So:

      1. ANCHOR every event that hits an external sink to that sink's thread.
      2. ATTACH each internal-only event (lateral move / recon, no external dst)
         to the nearest-in-time anchor within time_window_ms; if none is in range
         it cannot be attributed and goes to an "__unattributed__" thread (honest:
         we do not guess what no signal separates).
      3. Rebuild one fresh Session per thread.

    Sessions with <=1 external sink are passed through unchanged. Generic: keyed on
    "external destination", no hardcoded IPs. NOTE: a no-op on single-sink datasets
    (e.g. UNRAVELED, which has one C2 sink); it activates when concurrent attackers
    use distinct sinks. Runs BEFORE merge_by_rendezvous, which then re-links any
    fragments of one campaign that genuinely share a sink.
    """
    out: List[Session] = []
    for s in sessions:
        sinks = {ev.dst_ip for ev in s.events
                 if ev.dst_ip and not _is_internal(ev.dst_ip)}
        if len(sinks) <= 1:
            out.append(s)
            continue

        # 1. anchors: (time, sink) for every external-sink event.
        anchors = sorted((ev.time, ev.dst_ip) for ev in s.events
                         if ev.dst_ip and not _is_internal(ev.dst_ip))
        threads: Dict[str, list] = {}
        for ev in s.events:
            if ev.dst_ip and not _is_internal(ev.dst_ip):
                threads.setdefault(ev.dst_ip, []).append(ev)        # anchored
                continue
            # 2. internal-only -> nearest anchor in time within the window.
            sink = _nearest_sink(ev.time, anchors, time_window_ms)
            threads.setdefault(sink or "__unattributed__", []).append(ev)

        # 3. rebuild a fresh session per thread.
        for thread_events in threads.values():
            out.append(_session_from_events(s.id, thread_events, mapper))

    for new_id, s in enumerate(out):
        s.id = new_id
    return out


def _nearest_sink(t: int, anchors: list, window_ms: int) -> Optional[str]:
    """Sink of the closest anchor in time; None if none within window_ms."""
    best, best_gap = None, None
    for at, sink in anchors:
        gap = abs(t - at)
        if gap <= window_ms and (best_gap is None or gap < best_gap):
            best, best_gap = sink, gap
    return best


def merge_by_rendezvous(sessions: List[Session],
                        window_ms: int = RENDEZVOUS_WINDOW_MS) -> List[Session]:
    """
    Rule D (post-pass, order-independent): UNION sessions that share an EXTERNAL
    destination (C2 / exfil sink) used within window_ms of each other.

    Source-side identity churns as an attacker pivots and NAT rewrites the
    apparent origin, so fragments of one campaign look like separate sessions.
    The external sink they all converge on is the stable campaign fingerprint
    that recovers the link. Internal destinations are never rendezvous points
    (recorded that way in attribute()), so scanning a perimeter node cannot fuse
    with C2 traffic that merely egresses through it.

    Caveat: assumes distinct campaigns don't share infrastructure — a heuristic
    link, hence evaluated (V-measure), not treated as ground truth.
    """
    parent = {s.id: s.id for s in sessions}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    by_dst: Dict[str, list] = {}
    for s in sessions:
        for ip, times in s.external_dst_times.items():
            by_dst.setdefault(ip, []).append((s, min(times), max(times)))

    for lst in by_dst.values():
        for i in range(len(lst)):
            for j in range(i + 1, len(lst)):
                sa, amin, amax = lst[i]
                sb, bmin, bmax = lst[j]
                gap = max(amin, bmin) - min(amax, bmax)   # <=0 means overlapping
                if gap <= window_ms:
                    union(sa.id, sb.id)

    groups: Dict[int, List[Session]] = {}
    for s in sessions:
        groups.setdefault(find(s.id), []).append(s)

    merged = [_merge_group(g) for g in groups.values()]
    merged.sort(key=lambda s: (s.first_time if s.first_time is not None else 0))
    for new_id, s in enumerate(merged):
        s.id = new_id
    return merged
