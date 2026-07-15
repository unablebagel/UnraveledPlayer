"""
loader.py — self-contained, label-free fact loader for the streaming demo.

Depends only on the OCSF adapter (ocsf_to_facts), which it uses by import to
stamp each fact with its alert's observable timestamp — so ocsf_to_facts.py
stays untouched.

The streaming view reflects EXACTLY what the SIEM emitted: the OCSF alert stream
is the sole input; nothing is re-injected. (The emitter now detects two host-log
behaviors itself — Valid Accounts→T1078, Phishing→T1566.001 — so those appear via
real alerts. Activity it still misses, e.g. it_host_1's Linux-log SSH lateral
movement, is surfaced by the detection-delay report, not patched into live state.)

LABEL-FREE: only observable timestamps are read here; `unraveled_stage` /
ground-truth labels are never consulted for scoring.
"""

from pathlib import Path
from typing import List, Tuple

from ..ocsf_to_facts import _load_jsonl, _alert_to_facts, _DEFAULT_JSONL


def load_alerts_and_facts(path: Path = _DEFAULT_JSONL) -> Tuple[List[dict], list]:
    """Return (raw_alerts, facts), each fact stamped with details['time'] /
    ['start_time'] (epoch ms) taken from its alert.

    Network-flow alerts are anchored at `time` (window end), as before. Host-log
    alerts aggregate a host's labeled activity over the whole campaign into one
    alert whose `time` is the LAST event — using that would misattribute e.g.
    it_host_5's valid-account ENTRY (first seen 2021-06-25) to mid-July. So a
    host-log fact is anchored at the alert's `start_time` (first observed
    occurrence), which is when the behavior actually began on that host."""
    alerts = _load_jsonl(Path(path))
    facts = []
    for alert in alerts:
        is_host_log = (alert.get("unmapped", {}).get("raw_data", {}).get("data_type")
                       == "host_log")
        anchor = alert.get("start_time") if is_host_log else alert.get("time")
        for f in _alert_to_facts(alert):
            f.details.setdefault("time", anchor)
            f.details.setdefault("start_time", alert.get("start_time"))
            facts.append(f)
    return alerts, facts


def load_timestamped_facts(path=None) -> Tuple[List[dict], list]:
    """(alerts, facts) for the streaming replay — exactly the SIEM-emitted OCSF
    alerts, nothing re-injected."""
    return load_alerts_and_facts(_DEFAULT_JSONL if path is None else Path(path))
