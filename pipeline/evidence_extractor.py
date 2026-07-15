"""
evidence_extractor (trimmed vendored copy) — ObservedFact only.

Upstream, this module also defines EvidenceExtractor, which imports pandas to
parse the raw Unraveled CSV dataset. The scenario builder only ever touches
ObservedFact (via ocsf_to_facts), so the deployment vendors just the dataclass
and stays free of third-party dependencies. Owned by scenario_builder_space —
sync_from_source.py never overwrites this file.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ObservedFact:
    """A single fact observed in logs"""
    fact_type: str      # connection, attack_source, service, etc.
    subject: str        # node or edge identifier
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)  # Log records as evidence
