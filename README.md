# UnraveledPlayer

Interactive authoring tool for synthetic multi-attacker scenarios: draw an
attacker's move progression over a network topology in the browser, compile it
to OCSF-style `synthetic_alerts.jsonl`, and see the inferred attacker sessions
(S0..S3) overlaid back onto the editor — or import an existing alerts JSONL
and reverse it into an editable scenario.

This repo is a **standalone deployment snapshot** of the `scenario_builder`
tool from the `tm-unraveled` research codebase, packaged as a Docker app
deployed on Render's free tier (`render.yaml` is the blueprint). The UI is
a single `editor.html`; the backend is a stateless
stdlib-only `http.server` (the scenario spec lives in the browser's
localStorage). There are **no third-party Python dependencies**.

## Endpoints

| Route | What it does |
| --- | --- |
| `GET /` or `/editor.html` | the editor UI; its topology dropdown includes **Unraveled Attack Model (read only)**, a view-only load of the real campaign (deployment-owned patch injected by `serve.py`) |
| `GET /topology?name=segmented\|unraveled\|toy` | zones, nodes, edges, technique catalog |
| `GET /examples` | names of the built-in scenario specs |
| `GET /examples/<name>[.json]` | a built-in spec, read-only (e.g. `unraveled_campaign`) |
| `POST /compile` | scenario spec JSON → `{report, jsonl, alert_count, sessions}` |
| `POST /import[?topology=...]` | alerts JSONL → editor spec (reverse compile) |
| `GET /evolution` | session-evolution viewer (reads the editor's spec from localStorage) |
| `POST /evolution[?gt=0\|1]` | scenario spec JSON → stage5 session-evolution graph `{dot, svg, note, sessions}` |

## Run locally

```bash
python -m pipeline.scenario_builder.serve --host localhost --port 8765
# then open http://localhost:8765/editor.html
```

Or with Docker:

```bash
docker build -t scenario-builder .
docker run -p 7860:7860 scenario-builder
```

## Layout

- `pipeline/` — vendored subset of the upstream `log_to_diagram_demo`
  package, same layout so relative imports run unchanged. Four files are
  owned here and intentionally differ from (or don't exist in) upstream:
  `pipeline/__init__.py` (trimmed), `pipeline/evidence_extractor.py`
  (trimmed to drop the pandas dependency),
  `pipeline/scenario_builder/serve.py` (binds `0.0.0.0`, reads `$PORT`, adds
  the `/evolution` routes), and `pipeline/scenario_builder/evolution.html`
  (deployment-only viewer page). Everything else is a verbatim copy — fix
  bugs upstream, then re-run `python sync_from_source.py` (only works from
  inside the original research repo).
- `pipeline/stage5_session_evolution/` — vendored verbatim; `serve.py` uses
  its `build_session_graph`/`to_dot` to render the `/evolution` graph. The
  SVG render needs the Graphviz `dot` binary (installed in the Docker image;
  without it the endpoint returns DOT source only).
- `pipeline/scenario_builder/examples/` — example scenario specs to try in
  the editor or feed to `/compile`, served read-only at `/examples/<name>`.
  `unraveled_campaign.json` is owned here (no upstream copy): it is the real
  default Unraveled attack campaign on the `unraveled` topology, generated
  from the enriched SIEM alert stream (`siem_alerts_enriched_v3.jsonl`, the
  stage1_streaming replay input) by `make_unraveled_campaign.py` — 2,272
  network-flow alerts reverse-imported and condensed to 13 moves (one per
  distinct attacker/src/dst/technique, first-seen times, aggregate counts in
  each move's `kind`). Like `sync_from_source.py`, the generator only runs
  from inside the tm-unraveled research repo.

## Tests

```bash
python -m pipeline.scenario_builder.test_compile
python -m pipeline.scenario_builder.test_import
```

## Caveats

- No auth: anyone with the deployment URL can hit `/compile` with arbitrary
  spec JSON. The compiler is bounded and the server holds no state, so the
  blast radius is CPU only — but don't put anything sensitive behind it.
- Render's free instances spin down after ~15 min without traffic; the
  first visit after that wakes the container (takes up to a minute).
