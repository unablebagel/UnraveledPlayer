"""
test_import.py — round-trip: import_alerts reverses a synthetic_alerts.jsonl
into a spec that RE-COMPILES to the same alerts.

The strong invariant: for any demo's jsonl, alerts_to_spec -> from_dict ->
compile_scenario must reproduce every alert's semantic tuple
(time, src_ip, dst_ip, port, technique, attacker) exactly. compile.py and
import_alerts.py are inverses, so this pins that they stay so.

    python -m ComparisonToTM.log_to_diagram_demo.scenario_builder.test_import
"""

import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

from .compile import compile_scenario
from .import_alerts import alerts_to_spec, load_jsonl
from .spec import from_dict

PASS = "[PASS]"
FAIL = "[FAIL]"
_failures = []

_DEMO = Path(__file__).resolve().parents[1]        # log_to_diagram_demo/
_JSONLS = [
    _DEMO / "stage4_segmented_zone" / "synthetic_alerts.jsonl",
    _DEMO / "stage3_synthetic_attacker" / "synthetic_alerts.jsonl",
]


def check(label, condition, detail=""):
    if condition:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label}" + (f": {detail}" if detail else ""))
        _failures.append(label)


def _tuples(alerts):
    out = []
    for a in alerts:
        ev = a["evidences"][0]
        dst = ev.get("dst_endpoint", {})
        out.append((a["time"], ev["src_endpoint"]["ip"], dst.get("ip"), dst.get("port"),
                    a["finding_info"]["attacks"][0]["technique"]["uid"],
                    a["unmapped"]["attacker_attribution"]))
    return out


def run():
    for jsonl in _JSONLS:
        print(f"\n[{jsonl.parent.name}]")
        if not jsonl.exists():
            check(f"{jsonl.parent.name} jsonl present", False, f"missing {jsonl}")
            continue
        orig = load_jsonl(jsonl)
        spec_dict, report = alerts_to_spec(orig)

        # the spec must validate through the real gate (spec.from_dict)
        try:
            spec = from_dict(spec_dict)
            valid = True
        except Exception as e:                          # noqa: BLE001 -- surfaced as a failure
            valid = False
            check("imported spec validates", False, str(e))
        if not valid:
            continue
        check("imported spec validates", True)

        recompiled, _ = compile_scenario(spec)
        check("alert count preserved", len(recompiled) == len(orig),
              f"{len(orig)} -> {len(recompiled)}")
        check("semantic tuples identical after re-compile",
              _tuples(orig) == _tuples(recompiled))

        # spot-check the reverse mapping actually recovered node ids (not all raw IPs)
        node_dsts = [m for m in spec_dict["moves"] if not m["dst"][0].isdigit()]
        check("some moves reference node ids (IPs reversed to nodes)",
              len(node_dsts) > 0, "every dst stayed a raw IP")

    print("\n" + "=" * 60)
    if _failures:
        print(f"RESULT: {len(_failures)} FAILED: {_failures}")
        return 1
    print("RESULT: all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(run())
