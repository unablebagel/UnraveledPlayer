"""
sync_from_source.py — re-copy the vendored pipeline/ files from upstream.

Run from inside the tm-unraveled research repo, where this folder lives at
ComparisonToTM/log_to_diagram_demo/scenario_builder_space/ next to the
upstream modules it vendors:

    python sync_from_source.py

Copies every VERBATIM file listed below from ../ (log_to_diagram_demo) into
pipeline/, preserving the package layout. Three files are OWNED by this
deployment and are never overwritten:

    pipeline/__init__.py                     (trimmed: docstring only)
    pipeline/evidence_extractor.py           (trimmed: ObservedFact, no pandas)
    pipeline/scenario_builder/serve.py       (binds 0.0.0.0, reads $PORT)

After the standalone repo is split out of tm-unraveled this script has no
upstream to copy from and simply errors — that's expected; sync by hand or
re-clone the research repo next to it.
"""

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
UPSTREAM = HERE.parent                      # log_to_diagram_demo/
DEST = HERE / "pipeline"

VERBATIM = [
    "predicates.py",
    "toy_diagram.py",
    "unraveled_diagram.py",
    "mapping_layer.py",
    "state_demo.py",
    "ocsf_to_facts.py",
    "stage1_streaming/__init__.py",
    "stage1_streaming/loader.py",
    "stage1_streaming/replay.py",
    "stage2_multi_attacker/__init__.py",
    "stage2_multi_attacker/attribution.py",
    "stage2_multi_attacker/run_multi_attacker.py",
    "stage2_multi_attacker/trust_zone.py",
    "stage3_synthetic_attacker/__init__.py",
    "stage3_synthetic_attacker/generate.py",
    "stage3_synthetic_attacker/synthetic_alerts.jsonl",   # test_import fixture
    "stage4_segmented_zone/__init__.py",
    "stage4_segmented_zone/streaming_timeline.py",
    "stage4_segmented_zone/topology.py",
    "stage4_segmented_zone/synthetic_alerts.jsonl",       # test_import fixture
    "scenario_builder/__init__.py",
    "scenario_builder/spec.py",
    "scenario_builder/techniques.py",
    "scenario_builder/compile.py",
    "scenario_builder/import_alerts.py",
    "scenario_builder/editor.html",
    "scenario_builder/test_compile.py",
    "scenario_builder/test_import.py",
    "scenario_builder/examples/c2.json",
    "scenario_builder/examples/provenance.json",
    "scenario_builder/examples/toy.json",
    "scenario_builder/examples/trust_zone.json",
]


def main() -> int:
    probe = UPSTREAM / "scenario_builder" / "serve.py"
    if not probe.exists():
        print(f"[ERR] upstream not found at {UPSTREAM} — run this from inside "
              f"the tm-unraveled repo (see module docstring)")
        return 1
    for rel in VERBATIM:
        src, dst = UPSTREAM / rel, DEST / rel
        if not src.exists():
            print(f"[ERR] missing upstream file: {src}")
            return 1
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"[OK] {rel}")
    print(f"[DONE] {len(VERBATIM)} files synced; owned files left untouched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
