"""
scenario_builder — interactive synthetic-attacker authoring tool.

Two layers, so the UI is never the source of truth (see PLAN.md):

    scenario.json (spec)  --compile.py-->  synthetic_alerts.jsonl
                                            (via stage3_synthetic_attacker.generate.make_alert)

`techniques.py` / `spec.py` / `compile.py` are usable standalone (Phase 1,
write a scenario.json by hand or by asking Claude). `serve.py` + `editor.html`
add a self-contained browser editor on top (Phase 2); the editor edits the
spec only — it never fabricates OCSF JSON itself.
"""
