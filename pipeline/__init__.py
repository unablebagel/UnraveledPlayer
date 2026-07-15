"""
pipeline — vendored subset of ComparisonToTM/log_to_diagram_demo.

This package mirrors the upstream layout so the vendored modules run with
their relative imports unchanged. It is OWNED BY the scenario_builder_space
deployment and intentionally differs from upstream in two ways:

  * this __init__.py is a docstring only — the upstream one eagerly imports
    step_evaluator / EvidenceExtractor (pandas), which the scenario builder
    never uses;
  * evidence_extractor.py is trimmed to the ObservedFact dataclass for the
    same reason.

Everything else is a verbatim copy — do not edit those files here; fix them
upstream and re-run sync_from_source.py.
"""
