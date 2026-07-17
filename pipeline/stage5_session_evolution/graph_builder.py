"""
graph_builder.py — build a SESSION-EVOLUTION graph from attribution Session
objects and emit Graphviz DOT source.

WHAT THIS DRAWS (deliberately NOT the network topology)
-------------------------------------------------------
One node per (attributed session, host): "S3 · db_primary" — how each inferred
attacker session evolves across hosts, and where attribution ambiguity lives.

  rounded box   one attributed session AT one host. Fill = that session's
                color; a RED DASHED border marks a session whose events mix
                more than one ground-truth attacker (an OVER-MERGE — this is
                an eval-only overlay, see below).
  diamond       an external sink (C2 / exfil destination). Every session that
                communicates with the same sink terminates at the SAME diamond.

  black solid   observed progression: an alert whose source host carries the
                tail node's state and whose destination carries the head
                node's state. When the source host holds state for SEVERAL
                sessions, one edge is drawn from EACH of them — that fan-in IS
                the attribution ambiguity (the engine cannot tell which
                foothold session launched the move).
  blue          external-sink communication (C2 beacon / exfil).
  red dashed    ground-truth correction (EVAL ONLY, labeled synthetic data):
                the head session actually belongs to the same attacker as the
                tail session — an OVER-SPLIT that only the label reveals. The
                correction is drawn COMPLETELY: every head node whose black
                in-edges fan in from >1 session gets a red edge along the TRUE
                tail, so each ambiguous move is resolved (not just the
                session's first node); when no ambiguous hop connects the two
                sessions (pure fragmentation), a single session-level
                "belongs to" arrow is drawn instead.

LAYOUT: left-to-right workflow. Session nodes that share the same first-seen
timestamp share a vertical column (rank=same anchored to an invisible time
axis), so the x-axis reads as time: earlier events left, later events right.

GENERIC + LABEL-FREE
--------------------
No hardcoded host names, session ids, IPs, or UNRAVELED assumptions, and no
imports from the engine. The builder consumes the engine's existing Session
objects directly (duck-typed) — no data structures are duplicated:

    session.name                str        "S<n>"
    session.events              iterable   .time  .src_ip  .dst_ip
    session.facts               iterable   .details {node|data_store,
                                                     technique, time}
    session.compromised_nodes   set        node ids (IPs when no mapper)
    session.external_dst_times  dict       sink ip -> [times]
    session.first_time          int|None   epoch ms
    session.gt_counter          Counter    ground-truth labels (EVAL ONLY)

`mapper` (optional) needs one method: map_ip_to_node(ip) -> node id | None.
Without a mapper, raw IPs stand in for host names. Ground truth feeds ONLY
the red correction arrows and the dashed over-merge border; pass
include_ground_truth=False to strip both (attribution itself never sees a
label — the overlay is drawn on top of, never into, the sessions).
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# (fill, border) cycled per session — session 0 purple, session 1 yellow, ...
_PALETTE = [
    ("#dcc9f5", "#6f42c1"),   # purple
    ("#ffef9e", "#8f7700"),   # yellow
    ("#c9e5ff", "#1864ab"),   # blue
    ("#ffd8c2", "#d9480f"),   # orange
    ("#c3ecd0", "#2b8a3e"),   # green
    ("#ffc9de", "#c2255c"),   # pink
    ("#c5f2ee", "#0b7285"),   # teal
    ("#e6ddca", "#7f6a3f"),   # tan
]
_SINK_FILL, _SINK_BORDER = "#f1f3f5", "#495057"
_GT_RED = "#d1383a"
_SINK_BLUE = "#1c7ed6"
_AXIS_GRAY = "#868e96"


@dataclass
class SessionNode:
    """One attributed session at one host."""
    session: str
    host: str
    first_time: Optional[int] = None
    techniques: set = field(default_factory=set)
    compromised: bool = False
    has_facts: bool = False       # False = created only as a launch/transit point


@dataclass
class EvoGraph:
    """Renderer-independent session-evolution graph."""
    nodes: Dict[Tuple[str, str], SessionNode] = field(default_factory=dict)
    sinks: Dict[str, Optional[int]] = field(default_factory=dict)   # ip -> first t
    progression: list = field(default_factory=list)   # (tail key, head key)
    sink_edges: list = field(default_factory=list)    # (tail key, sink ip)
    corrections: list = field(default_factory=list)   # (tail, head, gt, show_label)
    session_order: list = field(default_factory=list)             # session names
    mixed_sessions: Dict[str, dict] = field(default_factory=dict)  # name -> gt mix
    t0: Optional[int] = None


def _session_first(s) -> int:
    """First-seen time of a session (first_time, else min event time)."""
    t = getattr(s, "first_time", None)
    if t is not None:
        return t
    times = [ev.time for ev in getattr(s, "events", []) if ev.time is not None]
    return min(times) if times else 0


def build_session_graph(sessions, mapper=None,
                        include_ground_truth: bool = True) -> EvoGraph:
    """Convert attribution Session objects into an EvoGraph (see module doc).

    Pass 1 folds each session's facts into (session, host) nodes; pass 2 walks
    each session's events to draw progression and sink edges (creating a bare
    launch/transit node only when traffic references a host the facts never
    scored); pass 3 overlays the eval-only ground-truth corrections.
    """
    g = EvoGraph()
    g.session_order = [getattr(s, "name", f"S{i}") for i, s in enumerate(sessions)]

    # Sink identity comes from the ENGINE's own decision (external_dst_times),
    # never re-derived here.
    all_sinks = set()
    for s in sessions:
        all_sinks |= set(getattr(s, "external_dst_times", {}) or {})

    # Mapper-less fallback: an IP counts as a host only if the sessions
    # themselves treat it as one (fact node or internal destination).
    known_hosts = set()
    if mapper is None:
        for s in sessions:
            for f in getattr(s, "facts", []):
                ip = f.details.get("node") or f.details.get("data_store")
                if ip and ip not in all_sinks:
                    known_hosts.add(ip)
            for ev in getattr(s, "events", []):
                if ev.dst_ip and ev.dst_ip not in all_sinks:
                    known_hosts.add(ev.dst_ip)

    def host_of(ip):
        if not ip:
            return None
        if mapper is not None:
            return mapper.map_ip_to_node(ip)
        return ip if ip in known_hosts else None

    def ensure(s, host, t=None, has_facts=False):
        name = getattr(s, "name")
        key = (name, host)
        n = g.nodes.get(key)
        if n is None:
            comp_nodes = getattr(s, "compromised_nodes", set()) or set()
            n = g.nodes[key] = SessionNode(
                session=name, host=host, compromised=host in comp_nodes)
        if t is not None:
            n.first_time = t if n.first_time is None else min(n.first_time, t)
        n.has_facts = n.has_facts or has_facts
        return key

    # ── pass 1: facts -> (session, host) nodes with times + techniques ──
    for s in sessions:
        for f in getattr(s, "facts", []):
            ip = f.details.get("node") or f.details.get("data_store")
            host = host_of(ip)
            if not host:
                continue
            key = ensure(s, host, f.details.get("time"), has_facts=True)
            tech = f.details.get("technique")
            if tech:
                g.nodes[key].techniques.add(tech)

    def tails(s, host, t):
        """Tail node(s) for traffic sourced from `host` at time `t`: prefer the
        session's own node there; otherwise EVERY session already holding state
        on that host (the fan-in that visualizes shared-pivot ambiguity)."""
        own = (getattr(s, "name"), host)
        if own in g.nodes:
            return [own]
        cands = [k for k, n in g.nodes.items()
                 if n.host == host
                 and (n.first_time is None or t is None or n.first_time <= t)]
        return cands or [ensure(s, host, t)]

    # ── pass 2: events -> progression (black) and sink (blue) edges ──
    seen_prog, seen_sink = set(), set()
    for s in sessions:
        ext = getattr(s, "external_dst_times", {}) or {}
        for ev in sorted(getattr(s, "events", []), key=lambda e: e.time or 0):
            if ev.dst_ip and ev.dst_ip in ext:
                prev = g.sinks.get(ev.dst_ip)
                g.sinks[ev.dst_ip] = ev.time if prev is None else min(prev, ev.time)
                src_host = host_of(ev.src_ip)
                if src_host:
                    for tail in tails(s, src_host, ev.time):
                        if (tail, ev.dst_ip) not in seen_sink:
                            seen_sink.add((tail, ev.dst_ip))
                            g.sink_edges.append((tail, ev.dst_ip))
                continue
            src_host, dst_host = host_of(ev.src_ip), host_of(ev.dst_ip)
            if not dst_host:
                continue
            head = ensure(s, dst_host, ev.time)
            if not src_host or src_host == dst_host:
                continue                      # ingress from outside, or self-loop
            for tail in tails(s, src_host, ev.time):
                if tail != head and (tail, head) not in seen_prog:
                    seen_prog.add((tail, head))
                    g.progression.append((tail, head))

    # ── pass 3: ground-truth overlay (EVAL ONLY, synthetic labeled data) ──
    if include_ground_truth:
        groups: Dict[str, list] = {}
        for s in sessions:
            gtc = getattr(s, "gt_counter", None)
            if not gtc:
                continue
            groups.setdefault(max(gtc, key=gtc.get), []).append(s)
            if len(gtc) > 1:
                g.mixed_sessions[getattr(s, "name")] = dict(gtc)

        def nodes_of(name):
            return [k for k in g.nodes if k[0] == name]

        for gt_label, group in groups.items():
            group = sorted(group, key=_session_first)
            for a, b in zip(group, group[1:]):
                a_name, b_name = getattr(a, "name"), getattr(b, "name")
                a_nodes = nodes_of(a_name)
                b_nodes = nodes_of(b_name)
                if not a_nodes or not b_nodes:
                    continue
                # COMPLETE correction: resolve EVERY ambiguous move into b — a
                # head node whose black in-edges fan in from >1 other session
                # gets a red edge along the TRUE tail (the one in a). One gt
                # label per pair; the rest carry it in the tooltip only.
                labeled = False
                for head in sorted(b_nodes,
                                   key=lambda k: g.nodes[k].first_time or 0):
                    in_tails = {t for t, h in g.progression
                                if h == head and t[0] != b_name}
                    if len({t[0] for t in in_tails}) < 2:
                        continue
                    for tail in sorted(t for t in in_tails if t[0] == a_name):
                        g.corrections.append((tail, head, gt_label, not labeled))
                        labeled = True
                if labeled:
                    continue
                # no ambiguous hop connects the pair (pure fragmentation, e.g.
                # a re-entry from a fresh origin): one session-level arrow from
                # a's node closest in time BEFORE b starts to b's first node.
                b_start = _session_first(b)
                before = [k for k in a_nodes
                          if g.nodes[k].first_time is not None
                          and g.nodes[k].first_time <= b_start]
                tail = (max(before, key=lambda k: g.nodes[k].first_time)
                        if before else
                        min(a_nodes, key=lambda k: g.nodes[k].first_time or 0))
                head = min(b_nodes, key=lambda k: g.nodes[k].first_time or 0)
                g.corrections.append((tail, head, gt_label, True))

    times = [n.first_time for n in g.nodes.values() if n.first_time is not None]
    times += [t for t in g.sinks.values() if t is not None]
    g.t0 = min(times) if times else None
    return g


# ─────────────────────────── DOT emission ───────────────────────────

def _dot_id(text: str, taken: set) -> str:
    base = re.sub(r"\W+", "_", text).strip("_") or "n"
    out, i = base, 1
    while out in taken:
        i += 1
        out = f"{base}_{i}"
    taken.add(out)
    return out


def _esc(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def _rel(t, t0) -> str:
    if t is None or t0 is None:
        return ""
    sec = (t - t0) / 1000.0
    if sec >= 3600:
        return f"+{sec / 3600:g}h"
    if sec >= 60:
        return f"+{sec / 60:g}min"
    return f"+{sec:g}s"


def _iso(t) -> str:
    if t is None:
        return ""
    return datetime.fromtimestamp(t / 1000.0, tz=timezone.utc) \
        .strftime("%Y-%m-%d %H:%M:%S UTC")


def to_dot(g: EvoGraph, title: Optional[str] = None) -> str:
    """Emit Graphviz DOT for an EvoGraph: rankdir=LR, one vertical column per
    distinct first-seen timestamp (rank=same on an invisible time axis)."""
    color_of = {name: _PALETTE[i % len(_PALETTE)]
                for i, name in enumerate(g.session_order)}
    taken: set = set()
    ids = {key: _dot_id(f"{key[0]}__{key[1]}", taken) for key in g.nodes}
    sink_ids = {ip: _dot_id(f"sink__{ip}", taken) for ip in g.sinks}

    gt_shown = bool(g.corrections or g.mixed_sessions)
    legend = ("black = observed progression   ·   blue = external-sink "
              "communication"
              + ("   ·   red dashed = ground-truth correction (eval only): "
                 "the TRUE launcher of each ambiguous move" if gt_shown else "")
              + "\\nrounded box = attributed session at a host"
              + (" (red dashed border = mixes ground-truth attackers)"
                 if gt_shown else "")
              + "   ·   diamond = external sink   ·   columns = event time "
                "(earlier on the left)")
    label = f"{_esc(title)}\\n\\n{legend}" if title else legend

    out: List[str] = [
        "digraph session_evolution {",
        "  rankdir=LR;",
        "  ranksep=0.7; nodesep=0.45;",
        '  fontname="Segoe UI,Helvetica,Arial";',
        f'  labelloc=b; fontsize=10; fontcolor="#495057"; label="{label}";',
        '  node [fontname="Segoe UI,Helvetica,Arial", fontsize=10];',
        '  edge [fontname="Segoe UI,Helvetica,Arial", fontsize=9,'
        ' arrowsize=0.7];',
        "",
    ]

    # time axis: one invisible-chained marker per distinct timestamp column
    columns = sorted({n.first_time for n in g.nodes.values()
                      if n.first_time is not None})
    col_of = {t: i for i, t in enumerate(columns)}
    if len(columns) >= 2:
        for i, t in enumerate(columns):
            out.append(f'  __t{i} [shape=plaintext, fontsize=9, '
                       f'fontcolor="{_AXIS_GRAY}", label="{_esc(_rel(t, g.t0))}"];')
        chain = " -> ".join(f"__t{i}" for i in range(len(columns)))
        out.append(f"  {chain} [style=invis];")
        out.append("")

    # session nodes, grouped into rank=same columns by first-seen time
    by_col: Dict[int, list] = {}
    for key, n in g.nodes.items():
        fill, border = color_of.get(n.session, _PALETTE[0])
        lines = [f"{n.session} · {n.host}"]
        rel = _rel(n.first_time, g.t0)
        if rel:
            lines.append(rel)
        if n.techniques:
            techs = sorted(n.techniques)
            shown = ", ".join(techs[:3]) + (f" +{len(techs) - 3}" if len(techs) > 3 else "")
            lines.append(shown)
        tip = [f"{n.session} at {n.host}",
               f"first seen: {_iso(n.first_time)}" if n.first_time else "",
               "compromised" if n.compromised else
               ("launch/transit point (no attributed facts)"
                if not n.has_facts else "touched"),
               ("MIXES ground-truth attackers: " + str(g.mixed_sessions[n.session]))
               if n.session in g.mixed_sessions else ""]
        style = "rounded,filled"
        pen, line_color = "1.2", border
        if n.session in g.mixed_sessions:
            style += ",dashed"
            pen, line_color = "1.8", _GT_RED
        label_text = "\\n".join(_esc(line) for line in lines)
        out.append(
            f'  {ids[key]} [shape=box, style="{style}", fillcolor="{fill}", '
            f'color="{line_color}", penwidth={pen}, '
            f'label="{label_text}", '
            f'tooltip="{_esc(" | ".join(x for x in tip if x))}"];')
        if n.first_time is not None:
            by_col.setdefault(col_of[n.first_time], []).append(ids[key])
    out.append("")
    if len(columns) >= 2:
        for i, node_ids in sorted(by_col.items()):
            members = "; ".join([f"__t{i}"] + node_ids)
            out.append(f"  {{ rank=same; {members}; }}")
        out.append("")

    # external sinks
    for ip, sid in sink_ids.items():
        out.append(f'  {sid} [shape=diamond, style=filled, '
                   f'fillcolor="{_SINK_FILL}", color="{_SINK_BORDER}", '
                   f'label="{_esc(ip)}\\nexternal sink", '
                   f'tooltip="external sink {_esc(ip)} | first contact: '
                   f'{_esc(_iso(g.sinks[ip]))}"];')
    if sink_ids:
        out.append("")

    # edges: observed progression (black), sink communication (blue),
    # ground-truth corrections (red dashed, layout-neutral)
    for tail, head in g.progression:
        out.append(f'  {ids[tail]} -> {ids[head]} [color="#212529"];')
    for tail, ip in g.sink_edges:
        out.append(f'  {ids[tail]} -> {sink_ids[ip]} '
                   f'[color="{_SINK_BLUE}", penwidth=1.4];')
    for tail, head, gt_label, show_label in g.corrections:
        label_attr = f'label="{_esc(gt_label)}", ' if show_label else ""
        out.append(
            f'  {ids[tail]} -> {ids[head]} [color="{_GT_RED}", style=dashed, '
            f'constraint=false, fontcolor="{_GT_RED}", {label_attr}'
            f'tooltip="ground truth: {_esc(head[0])} belongs to {_esc(tail[0])} '
            f'({_esc(gt_label)})"];')

    out.append("}")
    return "\n".join(out) + "\n"
