"""
test_compile.py — round-trip: scenario_builder specs vs the hand-written
stage3_synthetic_attacker generators they re-express.

Confirms the compiler is format-conformant (same build_events count, same
post-split session/V-measure structure) without freezing byte-level JSON --
identical technique tuples + identical timestamps should attribute
identically regardless of which code path produced the alerts.

    python -m ComparisonToTM.log_to_diagram_demo.scenario_builder.test_compile
"""

import os
import sys
import tempfile
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

PASS = "[PASS]"
FAIL = "[FAIL]"
_failures = []


def check(label, condition, detail=""):
    if condition:
        print(f"  {PASS} {label}")
    else:
        msg = f"  {FAIL} {label}" + (f": {detail}" if detail else "")
        print(msg)
        _failures.append(label)


def _pipeline(alerts):
    """build_events -> attribute -> split_by_sink -> split_by_target_zone."""
    from ..mapping_layer import MappingLayer
    from ..unraveled_diagram import create_unraveled_complete_diagram
    from ..stage2_multi_attacker.attribution import attribute, build_events, split_by_sink
    from ..stage2_multi_attacker.trust_zone import make_zone_of, split_by_target_zone
    from ..stage3_synthetic_attacker.generate import write_jsonl

    diagram = create_unraveled_complete_diagram()
    mapper = MappingLayer(diagram)
    fd, tmp_name = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    tmp_path = Path(tmp_name)
    write_jsonl(alerts, tmp_path)
    try:
        events = build_events(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    raw = attribute(events, mapper, diagram)
    sink = split_by_sink(raw, mapper)
    zoned = split_by_target_zone(sink, mapper, make_zone_of(mapper, diagram))
    return events, raw, sink, zoned


def _vm(sessions):
    from ..stage2_multi_attacker.run_multi_attacker import v_measure
    return v_measure(sessions)


def test_registry_covered_by_rule_table():
    print("\n--- Registry coverage ---")
    from ..ocsf_to_facts import RULE_TABLE
    from .techniques import TECHNIQUES

    missing = sorted(set(TECHNIQUES) - set(RULE_TABLE))
    check("every registry technique is in ocsf_to_facts.RULE_TABLE",
          not missing, f"missing: {missing}")


def test_c2_roundtrip():
    print("\n--- Round-trip: C2 scenario (split_by_sink) ---")
    from ..stage3_synthetic_attacker.generate import build_c2_scenario
    from .compile import compile_scenario
    from .spec import load

    gen_alerts = build_c2_scenario(base_time=1_700_000_000_000)
    _, _, gen_sink, _ = _pipeline(gen_alerts)

    spec = load(Path(__file__).parent / "examples" / "c2.json")
    sb_alerts, _report = compile_scenario(spec)
    sb_events, _, sb_sink, _ = _pipeline(sb_alerts)
    gen_events, *_ = _pipeline(gen_alerts)

    check("same alert count", len(sb_alerts) == len(gen_alerts),
          f"{len(sb_alerts)} vs {len(gen_alerts)}")
    check("same build_events count", len(sb_events) == len(gen_events),
          f"{len(sb_events)} vs {len(gen_events)}")
    check("same session count after split_by_sink",
          len(sb_sink) == len(gen_sink), f"{len(sb_sink)} vs {len(gen_sink)}")
    check("same V-measure after split_by_sink", _vm(sb_sink) == _vm(gen_sink),
          f"{_vm(sb_sink)} vs {_vm(gen_sink)}")


def test_provenance_roundtrip():
    print("\n--- Round-trip: provenance scenario ---")
    from ..stage3_synthetic_attacker.generate import build_provenance_scenario
    from .compile import compile_scenario
    from .spec import load

    gen_alerts = build_provenance_scenario(base_time=1_700_000_000_000)
    gen_events, gen_raw, _, _ = _pipeline(gen_alerts)

    spec = load(Path(__file__).parent / "examples" / "provenance.json")
    sb_alerts, _report = compile_scenario(spec)
    sb_events, sb_raw, _, _ = _pipeline(sb_alerts)

    check("same alert count", len(sb_alerts) == len(gen_alerts),
          f"{len(sb_alerts)} vs {len(gen_alerts)}")
    check("same build_events count", len(sb_events) == len(gen_events),
          f"{len(sb_events)} vs {len(gen_events)}")
    check("same login_session provenance sequence",
          [e.prov for e in sb_events] == [e.prov for e in gen_events],
          f"{[e.prov for e in sb_events]} vs {[e.prov for e in gen_events]}")
    check("same V-measure after attribute()", _vm(sb_raw) == _vm(gen_raw),
          f"{_vm(sb_raw)} vs {_vm(gen_raw)}")


def test_trust_zone_roundtrip():
    print("\n--- Round-trip: trust-zone scenario (split_by_target_zone) ---")
    from ..stage3_synthetic_attacker.generate import build_trust_zone_scenario
    from .compile import compile_scenario
    from .spec import load

    gen_alerts = build_trust_zone_scenario(base_time=1_700_000_000_000)
    gen_events, _, _, gen_zoned = _pipeline(gen_alerts)

    spec = load(Path(__file__).parent / "examples" / "trust_zone.json")
    sb_alerts, _report = compile_scenario(spec)
    sb_events, _, _, sb_zoned = _pipeline(sb_alerts)

    check("same alert count", len(sb_alerts) == len(gen_alerts),
          f"{len(sb_alerts)} vs {len(gen_alerts)}")
    check("same build_events count", len(sb_events) == len(gen_events),
          f"{len(sb_events)} vs {len(gen_events)}")
    check("same session count after split_by_target_zone",
          len(sb_zoned) == len(gen_zoned), f"{len(sb_zoned)} vs {len(gen_zoned)}")
    check("same V-measure after split_by_target_zone",
          _vm(sb_zoned) == _vm(gen_zoned), f"{_vm(sb_zoned)} vs {_vm(gen_zoned)}")


def test_toy_topology_compiles():
    print("\n--- Toy topology dispatch ---")
    from .compile import compile_scenario
    from .spec import load

    spec = load(Path(__file__).parent / "examples" / "toy.json")
    alerts, report = compile_scenario(spec)
    check("toy scenario compiles to 3 alerts", len(alerts) == 3, len(alerts))
    check("no internal-unmapped warnings",
          not any("internal IP" in l for l in report.lines), report.text())


def main():
    print("=" * 60)
    print("scenario_builder -- round-trip test suite")
    print("=" * 60)

    test_registry_covered_by_rule_table()
    test_c2_roundtrip()
    test_provenance_roundtrip()
    test_trust_zone_roundtrip()
    test_toy_topology_compiles()

    print("\n" + "=" * 60)
    if _failures:
        print(f"RESULT: {len(_failures)} FAILED -- {_failures}")
        sys.exit(1)
    else:
        print("RESULT: all tests passed")


if __name__ == "__main__":
    main()
