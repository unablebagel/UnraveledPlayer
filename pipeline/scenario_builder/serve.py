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
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except (AttributeError, ValueError):
        pass

from ..toy_diagram import create_unraveled_toy_diagram
from ..unraveled_diagram import create_unraveled_complete_diagram
from ..stage4_segmented_zone.topology import create_segmented_diagram
from .compile import CompileError, compile_scenario
from .import_alerts import AlertImportError, alerts_to_spec
from .spec import SpecError, from_dict
from .techniques import TECHNIQUES

_EDITOR_HTML = Path(__file__).parent / "editor.html"

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
    return {"topology": name, "zones": zones, "techniques": techniques, "edges": edges}


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/editor.html"):
            body = _EDITOR_HTML.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
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
