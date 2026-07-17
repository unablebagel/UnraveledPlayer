"""
visualize.py — render a session-evolution graph to PNG + SVG via Graphviz.

The one-call entry point, usable right after attribution:

    from ComparisonToTM.log_to_diagram_demo.stage5_session_evolution import (
        plot_session_evolution)

    sessions = attribute(events, mapper, diagram)     # or any split/merge output
    plot_session_evolution(sessions, "output/evolution", mapper=mapper)

writes output/evolution.dot, output/evolution.svg, output/evolution.png.

Rendering uses the Graphviz `dot` layout engine (never a force/spring layout):
the graph is a left-to-right workflow with time columns. The DOT source is
always written; SVG/PNG additionally require the `dot` executable, resolved
from GRAPHVIZ_DOT, PATH, or the standard install locations.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from .graph_builder import build_session_graph, to_dot

_PNG_DPI = "144"


def find_dot() -> Optional[str]:
    """Locate the Graphviz `dot` executable (env var, PATH, common installs)."""
    env = os.environ.get("GRAPHVIZ_DOT")
    if env and Path(env).exists():
        return env
    on_path = shutil.which("dot")
    if on_path:
        return on_path
    for root in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        cand = Path(root) / "Graphviz" / "bin" / "dot.exe"
        if cand.exists():
            return str(cand)
    return None


def render_dot(dot_source: str, output_path,
               formats=("svg", "png")) -> List[Path]:
    """Write `<base>.dot` and render `<base>.<fmt>` for each format.

    `output_path` may carry a .dot/.svg/.png suffix or none; it is treated as
    the base name either way. Returns the list of files written. If the `dot`
    executable cannot be found, only the .dot file is written (with a warning).
    """
    base = Path(output_path)
    if base.suffix.lower() in (".dot", ".svg", ".png"):
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)

    dot_file = base.with_suffix(".dot")
    dot_file.write_text(dot_source, encoding="utf-8")
    written = [dot_file]

    exe = find_dot()
    if exe is None:
        print(f"  [WARN] Graphviz 'dot' not found - wrote {dot_file} only. "
              "Install Graphviz (https://graphviz.org/download/) or set "
              "GRAPHVIZ_DOT to the dot executable.", flush=True)
        return written

    for fmt in formats:
        target = base.with_suffix(f".{fmt}")
        cmd = [exe, f"-T{fmt}", "-o", str(target), str(dot_file)]
        if fmt == "png":
            cmd.insert(2, f"-Gdpi={_PNG_DPI}")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"  [WARN] dot -T{fmt} failed: {proc.stderr.strip()}",
                  flush=True)
            continue
        written.append(target)
    return written


def plot_session_evolution(sessions, output_path, mapper=None,
                           title: Optional[str] = None,
                           include_ground_truth: bool = True,
                           formats=("svg", "png")) -> List[Path]:
    """Build and render the session-evolution graph for attributed sessions.

    Call after any attribution stage (attribute / split_by_* / merge_by_*):

        plot_session_evolution(sessions, "output/after_split", mapper=mapper)

    sessions              Session objects from the attribution engine (used
                          directly; nothing is copied or re-derived).
    output_path           base path; .dot + the requested formats are written.
    mapper                optional MappingLayer-like object (map_ip_to_node)
                          to show host names instead of raw IPs.
    title                 optional heading rendered under the graph.
    include_ground_truth  False strips the red eval-only overlay even when the
                          sessions carry labels (labels never affect layout or
                          session content either way).

    Returns the list of files written.
    """
    graph = build_session_graph(sessions, mapper=mapper,
                                include_ground_truth=include_ground_truth)
    return render_dot(to_dot(graph, title=title), output_path, formats=formats)
