"""
State Tracker Demo (W3-W6)  --  Full Unraveled Topology
========================================================
Runs the compromise-state-tracking pipeline on the FULL Unraveled topology
(`unraveled_diagram.py`) instead of the 4-node toy diagram.

Differences from `demo.py`:
  - Diagram: `create_unraveled_complete_diagram()` (~19 nodes, all subnets)
              vs. the 4-node toy diagram.
  - Skipped: Step 4 (StepEvaluator + hardcoded `attack_steps`) is W7-W9
              territory and assumes toy-diagram node IDs. Removed entirely.
  - Output:  Per-host `SystemState` -- the W3-W6 deliverable -- pulled
              directly from the SystemState dataclass (no evaluator needed).

Usage:
    python -m ComparisonToTM.log_to_diagram_demo.state_demo

Output:
    output/SystemState_FullTopology.json
    output/UnraveledDiagram.json  (the diagram, for reference)

Expected baseline behaviour (read this before evaluating the output):
    Until the rule table inside `_alert_to_facts` is built, every host that
    appears as `src_ip` in any alert will be flagged COMPROMISED, and every
    host that appears as `dst_ip` will be flagged ACCESSED. This is the
    "pipeline wired" checkpoint, not a correctness check. Building the rule
    table is the next step; re-run this demo afterwards to see the state
    shrink to the genuinely-compromised hosts.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

# Force immediate output on Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)


# ---------------------------------------------------------------------------
# Helpers -- extract per-node predicates from SystemState
# ---------------------------------------------------------------------------

def get_node_predicates(state, node_id):
    """Return all state-predicates currently TRUE for a given diagram node."""
    preds = []
    if node_id in state.exec_code:
        preds.append(f"execCode({node_id}, {state.exec_code[node_id].value})")
    if node_id in state.app_access:
        for perm in state.app_access[node_id]:
            preds.append(f"hasAppAccess({node_id}, {perm.value})")
    if node_id in state.credentials:
        preds.append(f"credentialPossession({node_id})")
    if node_id in state.net_control:
        for perm in state.net_control[node_id]:
            preds.append(f"netControl({node_id}, {perm.value})")
    return preds


# Confidence thresholds for the graded -> label mapping.
# These sit ON TOP of the noisy-OR confidence (state.node_confidence):
# the labels are a view, the probability is the primitive.
COMPROMISED_THRESHOLD = 0.8
ACCESSED_THRESHOLD = 0.3


def classify(confidence, preds):
    """Label = predicate KIND gated by confidence MAGNITUDE.

    Confidence answers "how sure?"; the predicate kind answers "how deep?".
    A datastore read with P=0.9 is high-confidence ACCESS, not compromise —
    the attacker read rows, they never got code execution. So:
      COMPROMISED: an execCode/credentialPossession predicate AND P >= 0.8
      ACCESSED:    any access predicate            AND P >= 0.3
      CLEAN:       otherwise
    """
    has_exec = any(p.startswith(("execCode", "credentialPossession")) for p in preds)
    has_access = has_exec or any(p.startswith("hasAppAccess") for p in preds)
    if has_exec and confidence >= COMPROMISED_THRESHOLD:
        return "COMPROMISED"
    if has_access and confidence >= ACCESSED_THRESHOLD:
        return "ACCESSED"
    return "CLEAN"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir = Path(__file__).parent
    output_dir = script_dir / "output"
    output_dir.mkdir(exist_ok=True)

    print("=" * 70, flush=True)
    print("W3-W6 STATE TRACKER  --  FULL UNRAVELED TOPOLOGY", flush=True)
    print("=" * 70, flush=True)
    print(flush=True)

    # -----------------------------------------------------------------------
    # STEP 1  --  Load the full Unraveled diagram
    # -----------------------------------------------------------------------
    print("-" * 70, flush=True)
    print("STEP 1: Load Full Unraveled Diagram", flush=True)
    print("-" * 70, flush=True)

    from .unraveled_diagram import create_unraveled_complete_diagram
    from .toy_diagram import diagram_to_json, get_ip_to_node_mapping

    diagram = create_unraveled_complete_diagram()
    print(f"  Nodes: {len(diagram.nodes)}", flush=True)
    print(f"  Edges: {len(diagram.edges)}", flush=True)
    print(f"  Trust zones ({len(diagram.trust_zones)}): {list(diagram.trust_zones.keys())}", flush=True)

    ip_map = get_ip_to_node_mapping(diagram)
    pinned_node_ids = set(ip_map.values())
    nodes_without_ips = [n.id for n in diagram.nodes if n.id not in pinned_node_ids]

    print(f"  IPs pinned: {len(ip_map)}", flush=True)
    print(f"  Nodes WITHOUT pinned IPs (cannot receive facts): {len(nodes_without_ips)}", flush=True)
    if nodes_without_ips:
        print(f"    -> {nodes_without_ips}", flush=True)
        print(f"    Pin their IPs in unraveled_diagram.py to make them visible.", flush=True)

    with open(output_dir / "UnraveledDiagram.json", "w") as f:
        json.dump(diagram_to_json(diagram), f, indent=2)
    print(f"  [OK] Saved: UnraveledDiagram.json", flush=True)

    # -----------------------------------------------------------------------
    # STEP 2  --  Load OCSF alerts -> ObservedFacts
    # -----------------------------------------------------------------------
    print(flush=True)
    print("-" * 70, flush=True)
    print("STEP 2: Load OCSF Alerts and Convert to Facts", flush=True)
    print("-" * 70, flush=True)

    from .ocsf_to_facts import OCSFToFacts
    facts = OCSFToFacts().load().convert()

    print(f"  Total facts: {len(facts)}", flush=True)
    fact_types = Counter(f.fact_type for f in facts)
    for ft, count in fact_types.most_common():
        print(f"    {ft}: {count}", flush=True)

    # -----------------------------------------------------------------------
    # STEP 3  --  Build SystemState (the W3-W6 core)
    # -----------------------------------------------------------------------
    print(flush=True)
    print("-" * 70, flush=True)
    print("STEP 3: Map Facts to Diagram Nodes -> Build SystemState", flush=True)
    print("-" * 70, flush=True)

    from .mapping_layer import MappingLayer
    mapper = MappingLayer(diagram)
    state = mapper.build_diagram_state(facts)

    print(f"  Mapped facts:  {len(mapper.mapped_facts)}", flush=True)
    print(f"  Unmapped IPs:  {len(mapper.unmapped_ips)}", flush=True)
    if mapper.unmapped_ips:
        print(f"    Sample (first 10): {list(mapper.unmapped_ips)[:10]}", flush=True)
        print(f"    These are alerts whose IPs aren't in the diagram.", flush=True)
        print(f"    Expected: attacker/C2 IPs (10.8.10.x), external IPs.", flush=True)

    # -----------------------------------------------------------------------
    # STEP 4  --  Per-host report  (THE W3-W6 OUTPUT)
    # -----------------------------------------------------------------------
    print(flush=True)
    print("=" * 70, flush=True)
    print("W3-W6 OUTPUT  --  Per-Host SystemState", flush=True)
    print("=" * 70, flush=True)

    buckets = {"COMPROMISED": [], "ACCESSED": [], "CLEAN": []}
    details = {}

    for node in diagram.nodes:
        preds = get_node_predicates(state, node.id)
        confidence = state.get_confidence(node.id)
        status = classify(confidence, preds)
        buckets[status].append(node.id)
        if preds or confidence > 0:
            details[node.id] = {
                "name":       node.name,
                "trust_zone": node.trust_zone,
                "ips":        node.ip_addresses,
                "status":     status,
                "confidence": round(confidence, 4),
                "predicates": preds,
            }

    marker = {"COMPROMISED": "[RED]   ", "ACCESSED": "[YELLOW]", "CLEAN": "[GREEN] "}
    for status in ("COMPROMISED", "ACCESSED", "CLEAN"):
        print(f"\n{marker[status]} {status}  ({len(buckets[status])} nodes)", flush=True)
        for nid in buckets[status]:
            if nid in details:
                d = details[nid]
                print(f"  - {nid:25s} [{d['trust_zone']}]  P={d['confidence']:.3f}  ip={d['ips']}", flush=True)
                for p in d["predicates"]:
                    print(f"      * {p}", flush=True)
            else:
                # CLEAN nodes with no facts -- just list them
                print(f"  - {nid}", flush=True)

    # data_possession is keyed by data name, not node -- report separately
    if state.data_possession:
        print(f"\n[DATA] Possessed data items ({len(state.data_possession)}):", flush=True)
        for data, perms in state.data_possession.items():
            perm_str = ", ".join(p.value for p in perms)
            print(f"  - {data}: [{perm_str}]", flush=True)

    # -----------------------------------------------------------------------
    # STEP 5  --  Save outputs
    # -----------------------------------------------------------------------
    print(flush=True)
    print("-" * 70, flush=True)
    print("Saving outputs...", flush=True)

    output = {
        "metadata": {
            "generated_at":         datetime.now().isoformat(),
            "diagram_nodes":        len(diagram.nodes),
            "diagram_edges":        len(diagram.edges),
            "diagram_ips_pinned":   len(ip_map),
            "nodes_without_ips":    nodes_without_ips,
            "total_facts":          len(facts),
            "mapped_facts":         len(mapper.mapped_facts),
            "unmapped_ips_count":   len(mapper.unmapped_ips),
            "unmapped_ips_sample":  list(mapper.unmapped_ips)[:20],
        },
        "summary": {
            "compromised": buckets["COMPROMISED"],
            "accessed":    buckets["ACCESSED"],
            "clean":       buckets["CLEAN"],
        },
        "node_details":       details,
        "data_possession":    {data: [p.value for p in perms]
                               for data, perms in state.data_possession.items()},
    }

    out_path = output_dir / "SystemState_FullTopology.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"  [OK] Saved: {out_path.name}", flush=True)

    # -----------------------------------------------------------------------
    # Footer
    # -----------------------------------------------------------------------
    print(flush=True)
    print("=" * 70, flush=True)
    print("DONE", flush=True)
    print("=" * 70, flush=True)
    print(flush=True)
    print("NOTE -- this is the 'pipeline wired' baseline.", flush=True)
    print("  Until the rule table inside _alert_to_facts is built, expect", flush=True)
    print("  over-compromise (every host with any inbound alert flagged).", flush=True)
    print("  Build the rule table next; re-run to see state shrink to the", flush=True)
    print("  genuinely-compromised hosts.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
