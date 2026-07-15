"""
replay.py — streaming replay of the noisy-OR state pipeline.

The noisy-OR fold (predicates.SystemState.accumulate_confidence) is
order-independent and monotonic, and MappingLayer.build_diagram_state rebuilds
the whole SystemState from a fact list on every call. Therefore the cumulative
state at time t is EXACTLY:

    build_diagram_state([f for f in facts if f.time <= t])

So we reproduce the time series by replaying the UNCHANGED batch builder over
growing time-prefixes — no reimplementation of the scoring logic.

CONFIDENCE AS A PER-STATE PROBABILITY
-------------------------------------
The batch pipeline keeps ONE noisy-OR score per host (P that *something*
happened) and turns it into a label by thresholding. Here we instead express
the confidence as a probability *distribution over the three states*, summing to
1, so "labelled ACCESSED, P=0.9" literally means "90% chance the true state is
ACCESSED." We do this with TWO nested noisy-OR accumulators built from the SAME
0.3/0.6/0.9 tiers (nothing new is invented):

    C      = P(COMPROMISED)            noisy-OR over compromise evidence
                                       (attack_source -> execCode)
    A_acc  = P(access evidence seen)   noisy-OR over access-only evidence
                                       (attack_target / data_access)

A technique's fact_type is fixed in RULE_TABLE, so compromise and access
evidence never share a (node, technique) key -> C and A_acc are independent and
the kill-chain nesting (compromise implies access) gives a clean distribution:

    P(COMPROMISED) = C
    P(ACCESSED)    = (1 - C) * A_acc
    P(CLEAN)       = (1 - C) * (1 - A_acc)

The label is the argmax; the confidence is that state's probability. The total
"touched-or-worse" mass 1 - P(CLEAN) = 1 - (1-C)(1-A_acc) equals the existing
single noisy-OR score exactly — that invariant is what run_stream checks.

LABEL-FREE: keys only off time + technique + IP->node mapping. unraveled_stage
is never read here.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from ..mapping_layer import MappingLayer
from ..state_demo import get_node_predicates
# Self-contained, label-free loader. Reuses ocsf_to_facts by import only;
# nothing in the core pipeline is modified. The replay reflects exactly the
# SIEM-emitted OCSF alert stream — no host-log events are re-injected.
from .loader import load_timestamped_facts

# Fact types that move node state, split by what they imply.
_COMPROMISE_FACT_TYPES = ("attack_source",)            # -> execCode (compromise)
_ACCESS_FACT_TYPES = ("attack_target", "data_access")  # -> hasAppAccess (touch)
_SCORING_FACT_TYPES = _COMPROMISE_FACT_TYPES + _ACCESS_FACT_TYPES

# Per-fact-type default confidence — mirrors mapping_layer.build_diagram_state.
_DEFAULT_CONF = {"attack_source": 0.9, "attack_target": 0.3, "data_access": 0.3}


def iso(ms: Optional[int]) -> Optional[str]:
    """Epoch milliseconds -> ISO-8601 UTC."""
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def _fact_node_ip(fact) -> Optional[str]:
    """The IP this fact scores against (node for src/target, data_store for data_access)."""
    return fact.details.get("node") or fact.details.get("data_store")


def change_checkpoints(facts, mapper: MappingLayer) -> List[int]:
    """
    The timestamps at which the topology can actually change.

    noisy-OR folds each (node, technique) at most once (mapping_layer dedupe), so
    a (node, technique) pair only matters the FIRST time it appears. The set of
    those first-occurrence times is the set of meaningful checkpoints. Returned
    sorted ascending.

    A pair is dated by the MINIMUM timestamp across its facts, not by whichever
    fact happens to come first in the list: the loader emits facts grouped by
    alert, so list order is not time order, and "first in list" can be later than
    the earliest occurrence. Keying off min(time) makes the checkpoint correct
    regardless of fact ordering (otherwise a mis-dated checkpoint only stays
    invisible because the snapshot collapse happens to absorb it).
    """
    first_time: Dict[tuple, int] = {}   # (node, technique) -> earliest time
    for f in facts:
        if f.fact_type not in _SCORING_FACT_TYPES:
            continue
        t = f.details.get("time")
        if t is None:
            continue
        ip = _fact_node_ip(f)
        if not ip:
            continue
        node = mapper.map_ip_to_node(ip)
        if not node:
            continue
        key = (node, f.details.get("technique"))
        if t < first_time.get(key, t + 1):
            first_time[key] = t
    return sorted(set(first_time.values()))


def state_distribution(facts, mapper: MappingLayer) -> Dict[str, Dict[str, float]]:
    """
    Per-node probability distribution over {clean, accessed, compromised}.

    Two nested noisy-OR accumulators over the SAME tier confidences:
      C     = noisy-OR over compromise evidence (attack_source)
      A_acc = noisy-OR over access evidence     (attack_target / data_access)
    each deduped by (node, technique) exactly like the batch pipeline.

      compromised = C
      accessed    = (1 - C) * A_acc
      clean       = (1 - C) * (1 - A_acc)
    """
    comp: Dict[str, float] = {}   # node -> C
    acc: Dict[str, float] = {}    # node -> A_acc
    seen_comp = set()
    seen_acc = set()

    for f in facts:
        if f.fact_type not in _SCORING_FACT_TYPES:
            continue
        ip = _fact_node_ip(f)
        if not ip:
            continue
        node = mapper.map_ip_to_node(ip)
        if not node:
            continue
        tech = f.details.get("technique")
        conf = f.details.get("confidence", _DEFAULT_CONF[f.fact_type])

        if f.fact_type in _COMPROMISE_FACT_TYPES:
            key = (node, tech)
            if key in seen_comp:
                continue
            seen_comp.add(key)
            comp[node] = 1.0 - (1.0 - comp.get(node, 0.0)) * (1.0 - conf)
        else:
            key = (node, tech)
            if key in seen_acc:
                continue
            seen_acc.add(key)
            acc[node] = 1.0 - (1.0 - acc.get(node, 0.0)) * (1.0 - conf)

    dist: Dict[str, Dict[str, float]] = {}
    for node in set(comp) | set(acc):
        c = comp.get(node, 0.0)
        a = acc.get(node, 0.0)
        dist[node] = {
            "clean": (1.0 - c) * (1.0 - a),
            "accessed": (1.0 - c) * a,
            "compromised": c,
        }
    return dist


def _label_of(d: Dict[str, float]):
    """argmax state -> ('CLEAN'|'ACCESSED'|'COMPROMISED', probability)."""
    label = max(d, key=d.get)
    return label.upper(), round(d[label], 4)


def classify_state(diagram, state, dist: Dict[str, Dict[str, float]]) -> Dict:
    """
    Render the topology at one point in time. node_details carries the full
    distribution; status = argmax; confidence = P(that state). Same node_details
    shape as SystemState_FullTopology.json, plus a `distribution` field.
    """
    buckets = {"COMPROMISED": [], "ACCESSED": [], "CLEAN": []}
    details: Dict[str, Dict] = {}
    for node in diagram.nodes:
        d = dist.get(node.id)
        if d is None:
            buckets["CLEAN"].append(node.id)   # no evidence at all
            continue
        status, conf = _label_of(d)
        buckets[status].append(node.id)
        details[node.id] = {
            "name": node.name,
            "trust_zone": node.trust_zone,
            "ips": node.ip_addresses,
            "status": status,
            "confidence": conf,
            "distribution": {k: round(v, 4) for k, v in d.items()},
            "predicates": get_node_predicates(state, node.id),
            # MITRE technique / kill-chain context behind this state, so a probe
            # is identifiable (e.g. hr_host_5 = T1566.001 spearphishing, Initial
            # Access) instead of an anonymous 0.3 hit. {} when no enrichment.
            "mitre": state.get_mitre_summary(node.id),
        }
    return {
        "summary": {
            "compromised": buckets["COMPROMISED"],
            "accessed": buckets["ACCESSED"],
            "clean": buckets["CLEAN"],
        },
        "node_details": details,
    }


class StreamingReplay:
    """Replays facts in time order, emitting a full-topology snapshot per change."""

    def __init__(self, diagram, facts):
        self.diagram = diagram
        self.facts = facts

    def _prefix(self, t: int):
        return [f for f in self.facts if (f.details.get("time") or 0) <= t]

    def snapshots(self) -> List[Dict]:
        """
        One snapshot per checkpoint at which the topology changes. Each snapshot:
        {index, time, iso, summary, node_details}. Consecutive snapshots with
        identical node_details (status, confidence AND distribution) are collapsed.
        """
        mapper = MappingLayer(self.diagram)
        checkpoints = change_checkpoints(self.facts, mapper)

        out: List[Dict] = []
        prev_details = None
        for t in checkpoints:
            prefix = self._prefix(t)
            state = MappingLayer(self.diagram).build_diagram_state(prefix)
            dist = state_distribution(prefix, MappingLayer(self.diagram))
            view = classify_state(self.diagram, state, dist)
            if view["node_details"] == prev_details:
                continue
            prev_details = view["node_details"]
            out.append({
                "index": len(out),
                "time": t,
                "iso": iso(t),
                "summary": view["summary"],
                "node_details": view["node_details"],
            })
        return out


def host_history(snapshots: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Per-host view derived from the snapshots: each moment a host's distribution
    changed. { node: [{time, iso, status, confidence, distribution}, ...] }.
    """
    history: Dict[str, List[Dict]] = {}
    last: Dict[str, tuple] = {}
    for snap in snapshots:
        for node, d in snap["node_details"].items():
            key = (d["status"], tuple(sorted(d["distribution"].items())))
            if last.get(node) == key:
                continue
            last[node] = key
            history.setdefault(node, []).append({
                "time": snap["time"],
                "iso": snap["iso"],
                "status": d["status"],
                "confidence": d["confidence"],
                "distribution": d["distribution"],
            })
    return history
