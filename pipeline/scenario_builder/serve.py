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
            dropdown (the vendored editor.html itself stays a verbatim
            upstream copy). Selecting it ILLUSTRATES the research pipeline's
            published output (see /reference): the step slider walks the
            reference inference CHECKPOINTS (each a moment some host's
            inferred state changed), node colors show that checkpoint's
            compromised/accessed buckets, and the "Inferred sessions" view
            shows the reference's final 4-session attribution — while the
            condensed campaign moves (/examples/unraveled_campaign.json)
            stay on the canvas as the attack-path storyline.

    GET  /examples
         -> {"examples": [...]} — the names of the built-in scenario specs
            shipped in scenario_builder/examples/.

    GET  /reference/sessions | /reference/snapshots
         -> the research pipeline's published stage2 output for the REAL
            Unraveled campaign (MultiAttacker_Sessions.json /
            MultiAttacker_Snapshots.json), vendored verbatim in
            scenario_builder/reference/ and refreshed by
            make_unraveled_campaign.py. This is the ground truth the
            read-only editor model illustrates: the full 2.3k-alert stream's
            inferred sessions and per-checkpoint host compromise states —
            NOT a re-compile of the condensed 21-move spec.

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

    POST /evolution[?gt=0|1][&merge=1]
         -> compiles the posted spec JSON, re-runs the same attribution chain
            compile._validate uses, and renders the stage5 session-evolution
            graph. Returns {dot, svg, sessions}; svg is null when the
            Graphviz `dot` executable is unavailable (the DOT source always
            comes back). gt=0 strips the eval-only ground-truth overlay.
            merge=1 swaps the final zone-split for stage2's rendezvous merge
            (sessions sharing an external C2 sink combine) — the chain that
            produced the published reference output, used by the read-only
            campaign model so its session graph matches /reference/sessions.

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
from ..stage2_multi_attacker.attribution import (attribute, build_events,
                                                 merge_by_rendezvous, split_by_sink)
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
_REFERENCE_DIR = Path(__file__).parent / "reference"
_REFERENCE_FILES = {                       # /reference/<key> -> vendored file
    "sessions": "MultiAttacker_Sessions.json",
    "snapshots": "MultiAttacker_Snapshots.json",
}

# Deployment-owned patch appended to editor.html at serve time (the file
# itself stays a verbatim upstream copy). Adds "Unraveled Attack Model
# (read only)" to the topology dropdown: selecting it ILLUSTRATES the
# research pipeline's published output (/reference) — the step slider walks
# the reference inference checkpoints (node colors = that checkpoint's
# compromised/accessed buckets, tooltips = per-session beliefs) and the
# "Inferred sessions" view shows the reference's final 4-session
# attribution, with the condensed campaign moves kept on the canvas as the
# attack-path storyline. The user's draft is stashed on entry and restored
# when another topology is chosen. Also adds a "Session evolution" button
# that opens /evolution on the current spec (the campaign model hands off
# with merge=1 so the graph matches the reference session structure).
# (Self-loop fan-out, timeline date labels, and the sessions staleness dot
# started here but are native in editor.html now — upstream owns them.)
_EDITOR_PATCH = """
<style>
 #roBanner{display:none;background:#8e2f2f;color:#fff;border-radius:12px;
           padding:3px 10px;font-size:12px;font-weight:600;letter-spacing:.3px}
 body.readonly-model #roBanner{display:inline-block}
 body.readonly-model #sidebar input,body.readonly-model #sidebar select,
 body.readonly-model #sidebar button{pointer-events:none;opacity:.55}
 body.readonly-model #stage .node .nbox,body.readonly-model #external{cursor:default}
 body.readonly-model .hint{display:none}
</style>
<script>
(() => {
'use strict';
const RO_VALUE = '__unraveled_campaign__';
// Written for /evolution when the editor shows something OTHER than the
// draft in STORAGE_KEY: {title, spec, merge}. Cleared on exit / normal use.
const HANDOFF_KEY = 'scenario_builder_evolution_spec';
let roActive = false, roBackup = null;
let roSnaps = null;        // reference checkpoints (MultiAttacker_Snapshots)
let roSnapIdx = null;      // slider position while read-only
let savedSliderInput = null, savedPlayClick = null;

const sel = document.getElementById('topologySelect');
const opt = document.createElement('option');
opt.value = RO_VALUE;
opt.textContent = 'Unraveled Attack Model (read only)';
sel.appendChild(opt);

const banner = document.createElement('span');
banner.id = 'roBanner';
banner.textContent = 'READ ONLY \\u2014 real Unraveled campaign';
document.getElementById('bar').appendChild(banner);

// "Session evolution" button: opens the stage5 session graph for whatever
// the editor is showing. The campaign model hands its spec off with
// merge=1 (rendezvous merge, the reference chain); otherwise /evolution
// reads the draft from localStorage as usual.
const evoBtn = document.createElement('button');
evoBtn.id = 'evolutionBtn';
evoBtn.textContent = 'Session evolution \\u2197';
evoBtn.title = 'open the inferred session-evolution graph in a new tab';
evoBtn.onclick = () => {
  if (roActive) {
    localStorage.setItem(HANDOFF_KEY, JSON.stringify(
        {title: 'Unraveled Attack Model (read only)', spec: state, merge: true}));
  } else {
    localStorage.removeItem(HANDOFF_KEY);
  }
  window.open('/evolution', '_blank', 'noopener');
};
const helpBtn = document.getElementById('helpBtn');
helpBtn.parentNode.insertBefore(evoBtn, helpBtn);

const LOCKED = ['baseTime', 'stepMs', 'defaultTech', 'loadSpecBtn',
                'importAlertsBtn', 'compileBtn'];
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

// ---- reference illustration ------------------------------------------------
// The read-only model does NOT re-infer anything from the condensed spec: the
// session legend/overlay and the per-checkpoint node states below come
// verbatim from the research pipeline's published output (/reference/*),
// computed from the full alert stream.

// reference session registry -> the editor's inferred-session overlay contract
function roConvertSessions(regs) {
  return regs.map(r => {
    const nodes = {};
    (r.touched_nodes || []).forEach(n => { nodes[n] = 'ACCESSED'; });
    (r.compromised_nodes || []).forEach(n => { nodes[n] = 'COMPROMISED'; });
    return {
      name: r.session, role: r.role,
      kind: r.role + '; actors ' + (r.actor_ips || []).join(', ')
            + '; ' + (r.n_facts || '?') + ' facts',
      actor_ips: r.actor_ips || [], nodes,
      eval_ground_truth: r.eval_ground_truth || null,
    };
  });
}

// campaign moves visible at a checkpoint (every campaign move has explicit t)
function roMovesUpTo(t) {
  return state.moves.filter(m => m.t != null && m.t <= t).length;
}

// checkpoint node paint: bucket border colors + per-session belief tooltips
function roPaintSnapshot(snap) {
  const paint = (ids, cls) => ids.forEach(nid => {
    const box = stage.querySelector('.node[data-node-id="' + CSS.escape(nid) + '"] .nbox');
    if (box) box.classList.add(cls);
  });
  paint(snap.summary.accessed, 'sess-ACCESSED');
  paint(snap.summary.compromised, 'sess-COMPROMISED');
  stage.querySelectorAll('.node').forEach(el => {
    const d = snap.node_details[el.dataset.nodeId];
    el.title = !d ? '' : Object.entries(d.per_attacker).map(([s, v]) =>
        s + ' ' + v.status + ' (P=' + v.confidence + ')'
          + (v.techniques.length ? ' \\u00b7 ' + v.techniques.join(', ') : '')
      ).join('\\n');
  });
}

const origUpdateOverlay = updateOverlay;
updateOverlay = function () {
  origUpdateOverlay();
  // sessions view keeps the native final-state render (= the reference's
  // MultiAttacker_Sessions end state); the checkpoint replay drives the
  // authored view.
  if (roActive && roSnaps && roSnapIdx !== null && viewMode === 'attackers')
    roPaintSnapshot(roSnaps[roSnapIdx]);
};

const origSyncProgressUI = syncProgressUI;
syncProgressUI = function () {
  origSyncProgressUI();
  if (!roActive || !roSnaps) return;
  const slider = document.getElementById('stepSlider');
  slider.max = roSnaps.length - 1;
  slider.value = roSnapIdx === null ? roSnaps.length - 1 : roSnapIdx;
  document.getElementById('stepCount').textContent =
      ((roSnapIdx === null ? roSnaps.length : roSnapIdx + 1)) + ' / ' + roSnaps.length;
};

const origUpdateStepBar = updateStepBar;
updateStepBar = function () {
  if (!roActive || !roSnaps || roSnapIdx === null) { origUpdateStepBar(); return; }
  const snap = roSnaps[roSnapIdx];
  const prev = roSnapIdx > 0 ? roSnaps[roSnapIdx - 1].summary : null;
  const delta = [];
  [['compromised', 'COMPROMISED'], ['accessed', 'ACCESSED']].forEach(([b, lbl]) => {
    snap.summary[b].forEach(n => {
      if (!prev || prev[b].indexOf(n) === -1) delta.push(n + ' \\u2192 ' + lbl);
    });
  });
  const bar = document.getElementById('stepBar');
  bar.classList.remove('warn');
  document.getElementById('stepSwatch').style.display = 'none';
  document.getElementById('stepAttacker').textContent = 'Unraveled campaign';
  document.getElementById('stepMsg').innerHTML =
      '\\u2014 checkpoint <b>' + (roSnapIdx + 1) + '/' + roSnaps.length + '</b> \\u00b7 '
      + fmtUtcMinute(snap.time) + ' \\u2014 '
      + snap.summary.compromised.length + ' compromised, '
      + snap.summary.accessed.length + ' accessed'
      + (delta.length ? ' \\u00b7 new: <b>' + delta.join(', ') + '</b>' : '');
};

function roShowSnap(i, keepPlaying) {
  if (!keepPlaying) stopPlayback();
  roSnapIdx = Math.max(0, Math.min(i, roSnaps.length - 1));
  const v = roMovesUpTo(roSnaps[roSnapIdx].time);
  viewStep = v >= state.moves.length ? null : v;
  redrawMoveLines();        // -> emphasis, overlay (wrapped), progress (wrapped)
  updateStepBar();
}

// while read-only, the scrubber and play button walk the reference
// checkpoints instead of the authored move list
function roBindControls() {
  const slider = document.getElementById('stepSlider');
  const play = document.getElementById('playBtn');
  savedSliderInput = slider.oninput;
  savedPlayClick = play.onclick;
  slider.oninput = ev => roShowSnap(parseInt(ev.target.value, 10) || 0);
  play.onclick = () => {
    if (playTimer) { stopPlayback(); syncProgressUI(); return; }
    if (roSnapIdx === null || roSnapIdx >= roSnaps.length - 1) roSnapIdx = -1;
    playTimer = setInterval(() => {
      if (roSnapIdx >= roSnaps.length - 1) { stopPlayback(); syncProgressUI(); return; }
      roShowSnap(roSnapIdx + 1, true);
    }, 900);
    roShowSnap(roSnapIdx + 1, true);
  };
}
function roUnbindControls() {
  document.getElementById('stepSlider').oninput = savedSliderInput;
  document.getElementById('playBtn').onclick = savedPlayClick;
  savedSliderInput = savedPlayClick = null;
}

// applyLoadedSpec kicks off an async topology fetch; wait until the canvas
// belongs to the campaign topology before painting the first checkpoint.
function roWaitCanvas(topology) {
  return new Promise(resolve => {
    const t0 = Date.now();
    (function tick() {
      if ((topologyData && topologyData.topology === topology)
          || Date.now() - t0 > 4000) resolve();
      else setTimeout(tick, 40);
    })();
  });
}

async function enterModel() {
  if (roActive) { sel.value = RO_VALUE; return; }
  let spec, snapsDoc, sessDoc;
  try {
    const [r1, r2, r3] = await Promise.all([
      fetch('/examples/unraveled_campaign.json'),
      fetch('/reference/snapshots'),
      fetch('/reference/sessions'),
    ]);
    for (const r of [r1, r2, r3])
      if (!r.ok) throw new Error((await r.json()).error || ('HTTP ' + r.status));
    spec = await r1.json(); snapsDoc = await r2.json(); sessDoc = await r3.json();
  } catch (e) {
    toast('Could not load the campaign model: ' + e);
    sel.value = state.topology;
    return;
  }
  roBackup = JSON.stringify(state);
  roActive = true;
  roSnaps = snapsDoc.snapshots;
  applyLoadedSpec(spec);                          // renders + persists the model...
  localStorage.setItem(STORAGE_KEY, roBackup);    // ...so put the user's draft back
  sessionData = roConvertSessions(sessDoc.sessions);   // reference sessions, not a re-compile
  syncStaleBadge();
  sel.value = RO_VALUE;
  setLocked(true);
  roBindControls();
  await roWaitCanvas(spec.topology);
  roShowSnap(roSnaps.length - 1);                 // open on the final state
  toast('Unraveled Attack Model \\u2014 read only. The slider replays the '
        + 'inference checkpoints; Inferred sessions shows the final attribution.');
}

function exitModel(topology) {
  const spec = JSON.parse(roBackup);
  roActive = false; roBackup = null;
  roSnaps = null; roSnapIdx = null;
  roUnbindControls();
  localStorage.removeItem(HANDOFF_KEY);     // don't leak the campaign handoff
  setLocked(false);
  stage.querySelectorAll('.node').forEach(el => { el.title = ''; });
  spec.topology = topology;
  applyLoadedSpec(spec);
  syncStaleBadge();
}

const prevOnChange = sel.onchange;
sel.onchange = ev => {
  if (ev.target.value === RO_VALUE) enterModel();
  else if (roActive) exitModel(ev.target.value);
  else prevOnChange(ev);
};

// document the deployment-only features inside the built-in guide
const guideActions = document.querySelector('#guideModal .guide-actions');
if (guideActions) {
  const h = document.createElement('h3');
  h.textContent = 'Built-in campaign & session graph';
  const p = document.createElement('p');
  p.innerHTML = 'Pick <b>Unraveled Attack Model (read only)</b> in the topology '
    + 'dropdown to replay the real Unraveled campaign as the research pipeline '
    + 'inferred it from ~2.3k SIEM alerts: the slider walks the inference '
    + 'checkpoints (each a moment a host\\u2019s state changed \\u2014 node colors and '
    + 'tooltips show that checkpoint\\u2019s beliefs), and <b>Inferred sessions</b> '
    + 'shows the final published attribution (S0\\u2013S3). The faint arrows are the '
    + 'campaign\\u2019s condensed moves, for orientation. <b>Session evolution \\u2197</b> '
    + 'opens the stage5 session graph for whatever the editor is showing.';
  guideActions.parentNode.insertBefore(h, guideActions);
  guideActions.parentNode.insertBefore(p, guideActions);
}
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
        if parsed.path.startswith("/reference/"):
            key = parsed.path[len("/reference/"):]
            fname = _REFERENCE_FILES.get(key)
            if fname is None:
                self._send_json(400, {"error": f"bad reference name {key!r} -- "
                                      f"one of {sorted(_REFERENCE_FILES)}"})
                return
            path = _REFERENCE_DIR / fname
            if not path.is_file():
                self._send_json(404, {"error": f"{fname} not vendored -- rerun "
                                      "make_unraveled_campaign.py from inside "
                                      "the research repo"})
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
        here rather than reaching into a verbatim upstream file. merge=1
        finishes with stage2's rendezvous merge instead of the zone split
        (the chain behind the published reference output)."""
        include_gt = query.get("gt", ["1"])[0] not in ("0", "false")
        merge = query.get("merge", ["0"])[0] in ("1", "true")
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
        sink = split_by_sink(attribute(events, mapper, diagram), mapper)
        if merge:
            zoned = merge_by_rendezvous(sink)
        else:
            zoned = split_by_target_zone(sink, mapper, make_zone_of(mapper, diagram))

        graph = build_session_graph(zoned, mapper=mapper,
                                    include_ground_truth=include_gt)
        title = (f"{spec.topology} — session evolution"
                 + (", rendezvous-merged" if merge else "")
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
