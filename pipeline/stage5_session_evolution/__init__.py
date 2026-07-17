"""stage5_session_evolution — visualize how attributed attacker sessions evolve.

Public API:

    from ComparisonToTM.log_to_diagram_demo.stage5_session_evolution import (
        plot_session_evolution,   # one call: sessions -> .dot/.svg/.png
        build_session_graph,      # Session objects -> EvoGraph model
        to_dot,                   # EvoGraph -> Graphviz DOT source
    )
"""

from .graph_builder import build_session_graph, to_dot
from .visualize import plot_session_evolution, render_dot, find_dot
from .snapshot_loader import load_demo_output, sessions_from_snapshots

__all__ = ["plot_session_evolution", "build_session_graph", "to_dot",
           "render_dot", "find_dot", "load_demo_output",
           "sessions_from_snapshots"]
