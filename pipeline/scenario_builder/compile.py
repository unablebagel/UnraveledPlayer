"""
compile.py — turn a scenario_builder.spec.ScenarioSpec into real OCSF alerts
via the existing stage3_synthetic_attacker.generate.make_alert, then validate
the result through the real attribution pipeline (the part hand-writing a
generate.py scenario never had).

    python -m ComparisonToTM.log_to_diagram_demo.scenario_builder.compile \
        scenario_builder/examples/trust_zone.json -o out/synthetic_alerts.jsonl --report

serve.py (Phase 2) calls compile_scenario() directly -- the browser editor
never fabricates OCSF JSON itself.
"""

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

from ..mapping_layer import MappingLayer
from ..ocsf_to_facts import _is_internal
from ..toy_diagram import create_unraveled_toy_diagram
from ..unraveled_diagram import create_unraveled_complete_diagram
from ..stage2_multi_attacker.attribution import attribute, build_events, split_by_sink
from ..stage2_multi_attacker.run_multi_attacker import session_registry, v_measure
from ..stage2_multi_attacker.trust_zone import make_zone_of, split_by_target_zone
from ..stage4_segmented_zone.streaming_timeline import _describe
from ..stage3_synthetic_attacker.generate import make_alert, write_jsonl
from ..stage4_segmented_zone.topology import create_segmented_diagram
from .spec import AttackerSpec, ScenarioSpec, load
from .techniques import TECHNIQUES

_TOPOLOGY_LOADERS = {
    "segmented": create_segmented_diagram,
    "unraveled": create_unraveled_complete_diagram,
    "toy": create_unraveled_toy_diagram,
}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class CompileError(ValueError):
    """A validated spec still cannot be compiled (unmappable move endpoint, ...)."""


@dataclass
class ValidationReport:
    lines: List[str] = field(default_factory=list)
    sessions: List[dict] = field(default_factory=list)   # inferred S0..S3, for the editor overlay

    def line(self, text: str) -> None:
        self.lines.append(text)

    def warn(self, text: str) -> None:
        self.lines.append(f"[WARN] {text}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _node_ip_map(diagram) -> Dict[str, str]:
    """node id -> primary IP, mirroring visualize.py's _layout ip lookup."""
    out = {}
    for n in diagram.nodes:
        if getattr(n, "ip_addresses", None):
            out[n.id] = n.ip_addresses[0]
    return out


def _resolve_endpoint(ref: str, attacker: AttackerSpec, node_ips: Dict[str, str],
                       move_index: int, role: str) -> str:
    """Node id -> its primary IP; 'external' -> the attacker's entry IP; a raw
    dotted-quad literal -> itself unchanged (external C2 sinks, or topology
    hosts the diagram intentionally leaves unpinned, are never diagram nodes)."""
    if ref == "external":
        return attacker.entry_ip
    if ref in node_ips:
        return node_ips[ref]
    if _IP_RE.match(ref):
        return ref
    raise CompileError(
        f"move[{move_index}]: {role} {ref!r} is neither a known node id nor a "
        "raw IP literal -- nodes without ip_addresses can't be move endpoints "
        "unless referenced by their raw IP"
    )


def compile_scenario(spec: ScenarioSpec) -> Tuple[List[dict], ValidationReport]:
    """Compile a validated ScenarioSpec (see spec.load/from_dict) into OCSF
    alerts + a validation report. Assumes the spec is already validated --
    attacker/technique references are trusted, not re-checked here."""
    report = ValidationReport()
    loader = _TOPOLOGY_LOADERS[spec.topology]
    diagram = loader()
    mapper = MappingLayer(diagram)
    node_ips = _node_ip_map(diagram)
    attackers_by_name = {a.name: a for a in spec.attackers}
    attacker_index = {a.name: i for i, a in enumerate(spec.attackers)}

    alerts: List[dict] = []
    t = spec.base_time
    prev_t: Optional[int] = None
    for i, move in enumerate(spec.moves):
        attacker = attackers_by_name[move.attacker]
        src_ip = _resolve_endpoint(move.src, attacker, node_ips, i, "src")
        dst_ip = _resolve_endpoint(move.dst, attacker, node_ips, i, "dst")
        port = move.port if move.port is not None else attacker.default_port

        if move.t is not None:
            t = move.t
        elif prev_t is not None:
            t = prev_t + spec.step_ms
        prev_t = t

        uid = f"SB-{attacker_index[attacker.name]}-{i}"
        alerts.append(make_alert(t, src_ip, dst_ip, port, TECHNIQUES[move.technique],
                                  attacker.name, uid, prov=attacker.prov))

    report.line(f"compiled {len(alerts)} alerts from {len(spec.moves)} move(s), "
                f"{len(spec.attackers)} attacker(s), topology={spec.topology!r}")
    _validate(alerts, diagram, mapper, report)
    return alerts, report


def _sessions_payload(zoned, zone_of) -> List[dict]:
    """The editor's inferred-session overlay contract (the S0..S3 the pipeline
    reconstructs). Node state is by MEMBERSHIP -- ACCESSED for touched nodes,
    overridden to COMPROMISED for compromised nodes -- so no extra scoring pass
    is needed. LABEL-FREE: eval_ground_truth is a display-only readout and must
    NEVER drive node coloring; it stays out of `nodes`."""
    payload = []
    for s, reg in zip(zoned, session_registry(zoned)):
        nodes = {nid: "ACCESSED" for nid in s.touched_nodes}
        for nid in s.compromised_nodes:
            nodes[nid] = "COMPROMISED"
        payload.append({
            "name": reg["session"],                 # positional label, display only
            "role": reg["role"],
            "kind": _describe(s, zone_of),           # stable content identity
            "actor_ips": reg["actor_ips"],
            "nodes": nodes,                          # node_id -> ACCESSED | COMPROMISED
            "eval_ground_truth": reg["eval_ground_truth"],   # eval-only readout
        })
    return payload


def _validate(alerts: List[dict], diagram, mapper: MappingLayer,
              report: ValidationReport) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                      encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
        tmp_path = Path(f.name)
    try:
        events = build_events(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    report.line(f"build_events: {len(events)}/{len(alerts)} alert(s) produced "
                "scoring facts")
    if len(events) < len(alerts):
        report.warn(f"{len(alerts) - len(events)} alert(s) produced ZERO scoring "
                    "facts and were dropped -- check the technique registry")

    internal_unmapped, external_unmapped = set(), set()
    for ev in events:
        for ip in (ev.src_ip, ev.dst_ip):
            if not ip or mapper.map_ip_to_node(ip) is not None:
                continue
            (internal_unmapped if _is_internal(ip) else external_unmapped).add(ip)
    if external_unmapped:
        report.line(f"external (expected-unmapped) IPs: {sorted(external_unmapped)}")
    if internal_unmapped:
        report.warn(f"internal IP(s) not mapped to any diagram node: "
                    f"{sorted(internal_unmapped)} -- check node id -> IP resolution")

    raw = attribute(events, mapper, diagram)
    sink = split_by_sink(raw, mapper)
    zone_of = make_zone_of(mapper, diagram)
    zoned = split_by_target_zone(sink, mapper, zone_of)
    report.sessions = _sessions_payload(zoned, zone_of)

    report.line("V-measure vs ground truth (eval only):")
    for label, sessions in (("attribute            ", raw),
                            ("after split_by_sink  ", sink),
                            ("after split_by_zone  ", zoned)):
        vm = v_measure(sessions)
        if vm is None:
            report.line(f"  {label}: no ground-truth labels (eval skipped)")
        else:
            report.line(
                f"  {label}: homogeneity={vm['homogeneity']} "
                f"completeness={vm['completeness']} V={vm['v_measure']} "
                f"({vm['n_inferred_sessions']} sessions)"
            )

    # Ordering-hazard diagnostic (stage4b lesson: interleaving can shift
    # nearest-anchor attachment and merge two attackers' events into one
    # session). Eval-only: gt_counter is never consulted by the linking
    # logic above, only read here for the report.
    for s in zoned:
        if len(s.gt_counter) > 1:
            dominant = max(s.gt_counter.values())
            minority = {gt: n for gt, n in s.gt_counter.items() if n < dominant}
            if minority:
                report.warn(
                    f"session {s.name} mixes attacker labels {dict(s.gt_counter)} -- "
                    f"minority label(s) {sorted(minority)} likely attached to a "
                    "different attacker's thread (ordering/interleaving hazard)"
                )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="path to a scenario.json spec")
    parser.add_argument("-o", "--out", default=None,
                        help="output .jsonl path (default: alongside the spec)")
    parser.add_argument("--report", action="store_true",
                        help="also write a <out>.report.txt validation report")
    args = parser.parse_args(argv)

    spec_path = Path(args.scenario)
    spec = load(spec_path)
    alerts, report = compile_scenario(spec)

    out_path = Path(args.out) if args.out else spec_path.with_suffix(".jsonl")
    write_jsonl(alerts, out_path)
    print(f"[OK] wrote {len(alerts)} alerts -> {out_path}", flush=True)
    print(report.text(), flush=True)

    if args.report:
        report_path = out_path.with_suffix(out_path.suffix + ".report.txt")
        report_path.write_text(report.text(), encoding="utf-8")
        print(f"[OK] wrote validation report -> {report_path}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
