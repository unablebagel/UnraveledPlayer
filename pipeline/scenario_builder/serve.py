"""
serve.py — localhost bridge for the scenario_builder editor (Phase 2).

Stdlib http.server only, no third-party deps, no server-side state -- the
scenario spec lives in the browser page/localStorage. Serves editor.html
plus two endpoints the page calls over fetch():

    GET  /topology?name=segmented|unraveled|toy
         -> {topology, zones, techniques}, for the topology canvas and the
            move-technique dropdown. Zones are an ORDERED list, each with its
            nodes nested inside; NO pixel coordinates -- editor.html lays the
            zones/nodes out with CSS (flex/grid) so any topology fits without
            clipping. Zone display metadata (title, fill) is owned here in
            _ZONE_META, with a deterministic pastel fallback for zones not in
            the segmented palette (e.g. unraveled's intranet_private).

    POST /compile
         -> runs the Phase 1 compiler (compile.compile_scenario) on the
            posted spec JSON and returns {report, jsonl, alert_count}. The
            editor never constructs OCSF JSON itself -- this is the only
            path it uses to produce alerts.

    POST /import[?topology=segmented|unraveled|toy]
         -> reverses a posted synthetic_alerts.jsonl (body = the raw jsonl)
            back into an editor spec via import_alerts.alerts_to_spec, so an
            existing hand-coded demo can be pulled INTO the editor. Returns
            {spec, report}; topology is inferred unless the query pins it.

    GET  / (editor.html)
         -> the editor, with _EDITOR_PATCH appended at serve time: it adds an
            "Unraveled Attack Model (read only)" entry to the topology
            dropdown that loads /examples/unraveled_campaign.json view-only
            (the vendored editor.html itself stays a verbatim upstream copy).

    GET  /examples
         -> {"examples": [...]} — the names of the built-in scenario specs
            shipped in scenario_builder/examples/.

    GET  /examples/<name>[.json]
         -> the named built-in spec, verbatim. READ-ONLY: there is no write
            path; `unraveled_campaign` is the canonical scenario of the real
            default Unraveled campaign on the `unraveled` topology (generated
            by make_unraveled_campaign.py from the enriched SIEM alert
            stream). Save the response and feed it to the editor's
            "Load spec" button, or POST it to /compile or /evolution.

    GET  /evolution
         -> evolution.html, the stage5 session-evolution viewer. The page
            reads the spec from the browser's localStorage (the same
            "scenario_builder_spec" key the editor writes) and POSTs it back.

    POST /evolution[?gt=0|1]
         -> compiles the posted spec JSON, re-runs the same attribution chain
            compile._validate uses, and renders the stage5 session-evolution
            graph. Returns {dot, svg, sessions}; svg is null when the
            Graphviz `dot` executable is unavailable (the DOT source always
            comes back). gt=0 strips the eval-only ground-truth overlay.

    python -m pipeline.scenario_builder.serve [--port 7860]

Vendored copy for scenario_builder_space (Hugging Face Spaces). Differs from
upstream serve.py only in the bind address/port: binds HOST (default 0.0.0.0)
and reads the port from $PORT (default 7860, the HF Spaces convention) so the
container is reachable from outside. Owned by scenario_builder_space —
sync_from_source.py never overwrites this file.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

from ..mapping_layer import MappingLayer
from ..toy_diagram import create_unraveled_toy_diagram
from ..unraveled_diagram import create_unraveled_complete_diagram
from ..stage2_multi_attacker.attribution import attribute, build_events, split_by_sink
from ..stage2_multi_attacker.trust_zone import make_zone_of, split_by_target_zone
from ..stage4_segmented_zone.topology import create_segmented_diagram
from ..stage5_session_evolution import build_session_graph, find_dot, to_dot
from .compile import CompileError, compile_scenario
from .import_alerts import AlertImportError, alerts_to_spec
from .spec import SpecError, from_dict
from .techniques import TECHNIQUES

_EDITOR_HTML = Path(__file__).parent / "editor.html"
_EVOLUTION_HTML = Path(__file__).parent / "evolution.html"
_EXAMPLES_DIR = Path(__file__).parent / "examples"

# Deployment-owned patch appended to editor.html at serve time (the file
# itself stays a verbatim upstream copy). Adds "Unraveled Attack Model
# (read only)" to the topology dropdown: selecting it stashes the user's
# draft, loads /examples/unraveled_campaign.json for viewing, and blocks
# every mutating control until another topology is chosen. View-only
# controls (playback, compile, inferred sessions, save-a-copy) stay live.
_EDITOR_PATCH = """
<style>
 #roBanner{display:none;background:#8e2f2f;color:#fff;border-radius:12px;
           padding:3px 10px;font-size:12px;font-weight:600;letter-spacing:.3px}
 body.readonly-model #roBanner{display:inline-block}
 body.readonly-model #sidebar input,body.readonly-model #sidebar select,
 body.readonly-model #sidebar button{pointer-events:none;opacity:.55}
 body.readonly-model #stage .node .nbox,body.readonly-model #external{cursor:default}
</style>
<script>
(() => {
'use strict';
const RO_VALUE = '__unraveled_campaign__';
let roActive = false, roBackup = null;

const sel = document.getElementById('topologySelect');
const opt = document.createElement('option');
opt.value = RO_VALUE;
opt.textContent = 'Unraveled Attack Model (read only)';
sel.appendChild(opt);

const banner = document.createElement('span');
banner.id = 'roBanner';
banner.textContent = 'READ ONLY \\u2014 real Unraveled campaign';
document.getElementById('bar').appendChild(banner);

const LOCKED = ['baseTime', 'stepMs', 'defaultTech', 'loadSpecBtn', 'importAlertsBtn'];
function setLocked(on) {
  LOCKED.forEach(id => { document.getElementById(id).disabled = on; });
  document.body.classList.toggle('readonly-model', on);
}

// Block every mutation path while read-only. All editor handlers run in the
// target phase, so capture-phase stopPropagation reaches them first.
document.getElementById('stage').addEventListener('click', e => {
  if (roActive) e.stopPropagation();            // no new moves from the canvas
}, true);
document.addEventListener('dragstart', e => {
  if (roActive) { e.preventDefault(); e.stopPropagation(); }   // no row reorder
}, true);
const RO_ALLOWED = new Set(['topologySelect', 'stepSlider']);  // view-only controls
['input', 'change'].forEach(t => document.addEventListener(t, e => {
  if (roActive && !RO_ALLOWED.has(e.target.id)) { e.stopPropagation(); e.preventDefault(); }
}, true));
document.addEventListener('focusin', e => {
  if (roActive && !RO_ALLOWED.has(e.target.id) && e.target.matches('input, select')
      && e.target.closest('#sidebar, #bar')) e.target.blur();
}, true);

async function enterModel() {
  if (roActive) { sel.value = RO_VALUE; return; }
  let spec;
  try {
    const res = await fetch('/examples/unraveled_campaign.json');
    if (!res.ok) throw new Error((await res.json()).error || ('HTTP ' + res.status));
    spec = await res.json();
  } catch (e) {
    toast('Could not load the campaign model: ' + e);
    sel.value = state.topology;
    return;
  }
  roBackup = JSON.stringify(state);
  roActive = true;
  applyLoadedSpec(spec);                          // renders + persists the model...
  localStorage.setItem(STORAGE_KEY, roBackup);    // ...so put the user's draft back
  sel.value = RO_VALUE;
  setLocked(true);
  toast('Unraveled Attack Model \\u2014 read only. Press \\u25b6 to replay; pick '
        + 'another topology to go back to your own scenario.');
}

function exitModel(topology) {
  const spec = JSON.parse(roBackup);
  roActive = false; roBackup = null;
  setLocked(false);
  spec.topology = topology;
  applyLoadedSpec(spec);
}

const prevOnChange = sel.onchange;
sel.onchange = ev => {
  if (ev.target.value === RO_VALUE) enterModel();
  else if (roActive) exitModel(ev.target.value);
  else prevOnChange(ev);
};
})();
</script>
"""

_TOPOLOGY_LOADERS = {
    "segmented": create_segmented_diagram,
    "unraveled": create_unraveled_complete_diagram,
    "toy": create_unraveled_toy_diagram,
}

# Zone display metadata, owned here (not imported from stage4). Dict order is
# the display order for known zones; colors mirror stage4's segmented palette so
# that map looks identical. Any zone not listed gets a deterministic pastel.
_ZONE_META = {
    "marketing":       {"title": "Marketing",            "fill": "#eef1f4"},
    "it":              {"title": "IT",                    "fill": "#f8d7da"},
    "hr_executive":    {"title": "HR & Executive",        "fill": "#e2e3e5"},
    "perimeter":       {"title": "Perimeter",             "fill": "#dfe7f3"},
    "dmz_public":      {"title": "Public Subnet (DMZ)",   "fill": "#ffe3b3"},
    "intranet_app":    {"title": "Private · App Tier",    "fill": "#d6ecd8"},
    "intranet_db":     {"title": "Private · DB Tier",     "fill": "#ffd9b3"},
    "intranet_backup": {"title": "Private · Backup Tier", "fill": "#e6d6f0"},
}


def _zone_meta(zone_id: str) -> dict:
    """Display title + fill for a zone; deterministic pastel for unknown zones."""
    meta = _ZONE_META.get(zone_id)
    if meta:
        return meta
    hue = sum(ord(c) for c in zone_id) * 37 % 360     # stable per zone id
    return {"title": zone_id.replace("_", " ").title(),
            "fill": f"hsl({hue}, 45%, 92%)"}


def _topology_payload(name: str) -> dict:
    diagram = _TOPOLOGY_LOADERS[name]()
    by_zone = {}                                       # insertion-ordered
    for n in diagram.nodes:
        by_zone.setdefault(n.trust_zone, []).append(n)
    # known zones first (in _ZONE_META order), then unknown zones as they appear
    ordered = [z for z in _ZONE_META if z in by_zone] + \
              [z for z in by_zone if z not in _ZONE_META]
    zones = []
    for zid in ordered:
        meta = _zone_meta(zid)
        zones.append({
            "id": zid, "title": meta["title"], "fill": meta["fill"],
            "nodes": [{
                "id": n.id, "name": n.name,
                "ip": n.ip_addresses[0] if getattr(n, "ip_addresses", None) else "",
                "has_ip": bool(getattr(n, "ip_addresses", None)),
            } for n in by_zone[zid]],
        })
    techniques = {tid: {"desc": t[6], "tactic": t[2]} for tid, t in TECHNIQUES.items()}
    edges = [{"source": e.source_id, "target": e.target_id, "label": e.label} for e in getattr(diagram, "edges", [])]
    # The editor renders an EXTERNAL (internet) box on every topology, but the
    # diagrams intentionally exclude external entities, so nothing connects it.
    # Give it a display-only backbone edge into each perimeter node ('external'
    # is the editor's sentinel id, resolved specially by its renderer); the toy
    # topology has no perimeter zone and is left unchanged.
    for z in zones:
        if z["id"] == "perimeter":
            for n in z["nodes"]:
                edges.append({"source": "external", "target": n["id"],
                              "label": "Inbound Internet"})
    return {"topology": name, "zones": zones, "techniques": techniques, "edges": edges}


class Handler(BaseHTTPRequestHandler):
    # don't advertise BaseHTTP/Python versions in the Server header
    server_version = "UnraveledPlayer"
    sys_version = ""

    def _send_security_headers(self) -> None:
        # 'unsafe-inline' is required: both pages are single-file apps with
        # inline <script>/<style> by design (no external assets to pin).
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, path: Path, patch: str = "") -> None:
        body = path.read_bytes()
        if patch:
            body = body.replace(b"</body>",
                                patch.encode("utf-8") + b"\n</body>", 1)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/editor.html"):
            self._send_html(_EDITOR_HTML, patch=_EDITOR_PATCH)
            return
        if parsed.path in ("/evolution", "/evolution.html"):
            self._send_html(_EVOLUTION_HTML)
            return
        if parsed.path == "/examples":
            names = sorted(p.stem for p in _EXAMPLES_DIR.glob("*.json"))
            self._send_json(200, {"examples": names})
            return
        if parsed.path.startswith("/examples/"):
            name = parsed.path[len("/examples/"):]
            if name.endswith(".json"):
                name = name[:-len(".json")]
            # whitelist the name shape; no separators, so no path traversal
            if not name.replace("-", "").replace("_", "").isalnum():
                self._send_json(400, {"error": f"bad example name {name!r}"})
                return
            path = _EXAMPLES_DIR / f"{name}.json"
            if not path.is_file():
                self._send_json(404, {"error": f"no such example {name!r}"})
                return
            self._send_json(200, json.loads(path.read_text(encoding="utf-8")))
            return
        if parsed.path == "/topology":
            name = parse_qs(parsed.query).get("name", ["segmented"])[0]
            if name not in _TOPOLOGY_LOADERS:
                self._send_json(400, {"error": f"unknown topology {name!r}"})
                return
            self._send_json(200, _topology_payload(name))
            return
        self._send_json(404, {"error": f"no such route {parsed.path!r}"})

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        if path == "/compile":
            self._do_compile(raw)
        elif path == "/import":
            self._do_import(raw, parse_qs(urlparse(self.path).query))
        elif path == "/evolution":
            self._do_evolution(raw, parse_qs(urlparse(self.path).query))
        else:
            self._send_json(404, {"error": "no such route"})

    def _do_compile(self, raw: bytes) -> None:
        try:
            spec = from_dict(json.loads(raw))
            alerts, report = compile_scenario(spec)
        except (SpecError, CompileError) as e:
            self._send_json(400, {"error": str(e)})
            return
        except json.JSONDecodeError as e:
            self._send_json(400, {"error": f"invalid JSON: {e}"})
            return
        jsonl = "\n".join(json.dumps(a) for a in alerts) + "\n"
        self._send_json(200, {
            "report": report.text(), "jsonl": jsonl, "alert_count": len(alerts),
            "sessions": report.sessions,          # inferred S0..S3 for the editor overlay
        })

    def _do_evolution(self, raw: bytes, query: dict) -> None:
        """Compile the posted spec, re-run the attribution chain, and render
        the stage5 session-evolution graph (DOT always, SVG when Graphviz's
        `dot` is available). Mirrors compile._validate's session pipeline —
        that helper keeps the sessions internal, so the chain is repeated
        here rather than reaching into a verbatim upstream file."""
        include_gt = query.get("gt", ["1"])[0] not in ("0", "false")
        try:
            spec = from_dict(json.loads(raw))
            alerts, _report = compile_scenario(spec)
        except (SpecError, CompileError) as e:
            self._send_json(400, {"error": str(e)})
            return
        except json.JSONDecodeError as e:
            self._send_json(400, {"error": f"invalid JSON: {e}"})
            return

        diagram = _TOPOLOGY_LOADERS[spec.topology]()
        mapper = MappingLayer(diagram)
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                         encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(a) + "\n")
            tmp_path = Path(f.name)
        try:
            events = build_events(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        zoned = split_by_target_zone(
            split_by_sink(attribute(events, mapper, diagram), mapper),
            mapper, make_zone_of(mapper, diagram))

        graph = build_session_graph(zoned, mapper=mapper,
                                    include_ground_truth=include_gt)
        title = (f"{spec.topology} — session evolution"
                 + ("" if include_gt else ", LABEL-FREE view (no ground truth)"))
        dot_src = to_dot(graph, title=title)

        svg, note = None, None
        exe = find_dot()
        if exe is None:
            note = ("Graphviz 'dot' not found on the server -- returning DOT "
                    "source only")
        else:
            proc = subprocess.run([exe, "-Tsvg"], input=dot_src,
                                  capture_output=True, text=True)
            if proc.returncode == 0:
                svg = proc.stdout
            else:
                note = f"dot -Tsvg failed: {proc.stderr.strip()}"
        self._send_json(200, {"dot": dot_src, "svg": svg, "note": note,
                              "sessions": len(zoned)})

    def _do_import(self, raw: bytes, query: dict) -> None:
        """Reverse a posted synthetic_alerts.jsonl into an editor spec."""
        topology = query.get("topology", [None])[0]
        try:
            alerts = [json.loads(line) for line in raw.decode("utf-8").splitlines()
                      if line.strip()]
        except json.JSONDecodeError as e:
            self._send_json(400, {"error": f"invalid JSONL (one alert per line): {e}"})
            return
        try:
            spec, report = alerts_to_spec(alerts, topology=topology)
        except AlertImportError as e:
            self._send_json(400, {"error": str(e)})
            return
        self._send_json(200, {"spec": spec, "report": "\n".join(report)})

    def log_message(self, fmt, *args):
        print(f"[serve] {self.address_string()} - {fmt % args}", flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("PORT", "7860")))
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    args = parser.parse_args(argv)

    server = HTTPServer((args.host, args.port), Handler)
    print(f"[OK] scenario_builder editor at http://{args.host}:{args.port}/editor.html",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
