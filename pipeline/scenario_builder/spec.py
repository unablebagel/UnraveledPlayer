"""
spec.py — declarative scenario spec: dataclasses + JSON (de)serialization.

See PLAN.md for the schema rationale. A ScenarioSpec is the ONLY thing the
browser editor (Phase 2, editor.html) edits; compile.py is the only thing
that turns it into OCSF alerts. `load`/`from_dict` are the sole validation
gate: everything downstream (compile.py) trusts a ScenarioSpec it receives.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

from .techniques import TECHNIQUES

_TOPOLOGIES = ("segmented", "unraveled", "toy")


class SpecError(ValueError):
    """A scenario.json fails to parse or validate."""


@dataclass
class AttackerSpec:
    name: str                       # ground-truth label -- EVAL ONLY, never scored
    entry_ip: str
    initial_access: str = "T1078"
    prov: Optional[str] = None      # -> unmapped.provenance.login_session
    default_port: int = 22


@dataclass
class MoveSpec:
    attacker: str
    src: str                        # node id, "external", or a raw IP literal
    dst: str                        # node id, or a raw IP literal
    technique: str
    port: Optional[int] = None
    t: Optional[int] = None         # explicit time; else base_time/prev + step_ms
    kind: Optional[str] = None      # e.g. "foothold" -- informational only


@dataclass
class ScenarioSpec:
    topology: str
    base_time: int
    attackers: List[AttackerSpec] = field(default_factory=list)
    moves: List[MoveSpec] = field(default_factory=list)
    step_ms: int = 1000


def _attacker_from_dict(d: dict) -> AttackerSpec:
    if "name" not in d or "entry_ip" not in d:
        raise SpecError(f"attacker missing required 'name'/'entry_ip': {d!r}")
    return AttackerSpec(
        name=d["name"], entry_ip=d["entry_ip"],
        initial_access=d.get("initial_access", "T1078"),
        prov=d.get("prov"), default_port=d.get("default_port", 22),
    )


def _move_from_dict(d: dict) -> MoveSpec:
    for k in ("attacker", "src", "dst", "technique"):
        if k not in d:
            raise SpecError(f"move missing required {k!r}: {d!r}")
    return MoveSpec(
        attacker=d["attacker"], src=d["src"], dst=d["dst"],
        technique=d["technique"], port=d.get("port"), t=d.get("t"),
        kind=d.get("kind"),
    )


def from_dict(data: dict) -> ScenarioSpec:
    topology = data.get("topology")
    if topology not in _TOPOLOGIES:
        raise SpecError(f"topology must be one of {_TOPOLOGIES}, got {topology!r}")
    if "base_time" not in data:
        raise SpecError("scenario spec missing required 'base_time'")

    attackers = [_attacker_from_dict(a) for a in data.get("attackers", [])]
    names = {a.name for a in attackers}
    moves = [_move_from_dict(m) for m in data.get("moves", [])]

    for i, m in enumerate(moves):
        if m.attacker not in names:
            raise SpecError(f"move[{i}]: unknown attacker {m.attacker!r}")
        if m.technique not in TECHNIQUES:
            raise SpecError(
                f"move[{i}]: technique {m.technique!r} not in the scenario_builder "
                "technique registry (scenario_builder/techniques.py)"
            )

    return ScenarioSpec(
        topology=topology, base_time=data["base_time"],
        attackers=attackers, moves=moves,
        step_ms=data.get("step_ms", 1000),
    )


def load(path: Union[str, Path]) -> ScenarioSpec:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
