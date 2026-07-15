"""
Predicate Definitions - Aligned with TM Attack Flow Rules
=========================================================

Based on "General Logic Rules" document:
- State predicates: execCode, hasAppAccess, credentialPossession, dataPossession, netControl
- Structure predicates: dataStore, dataflow, netAccess, nodeType, childOf, trustZone
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set
from enum import Enum


class Permission(Enum):
    """Permission levels"""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    USER = "user"
    BLOCK = "block"


# ============================================================
# State Predicates (can change during attack)
# ============================================================

@dataclass
class ExecCode:
    """execCode(X, privilege) - Attacker can execute code on node X"""
    node: str
    privilege: Permission  # admin or user
    
    def __str__(self):
        return f"execCode({self.node}, {self.privilege.value})"


@dataclass
class HasAppAccess:
    """hasAppAccess(X, permission) - Attacker has application access to X"""
    node: str
    permission: Permission  # read or write
    
    def __str__(self):
        return f"hasAppAccess({self.node}, {self.permission.value})"


@dataclass
class CredentialPossession:
    """credentialPossession(X) - Attacker possesses credentials for X"""
    node: str
    
    def __str__(self):
        return f"credentialPossession({self.node})"


@dataclass
class DataPossession:
    """dataPossession(data, permission) - Attacker possesses data"""
    data: str
    permission: Permission  # read or write
    
    def __str__(self):
        return f"dataPossession({self.data}, {self.permission.value})"


@dataclass
class NetControl:
    """netControl(X, permission) - Attacker has network control"""
    network: str
    permission: Permission  # block, read, or write
    
    def __str__(self):
        return f"netControl({self.network}, {self.permission.value})"


# ============================================================
# Structure Predicates (derived from architecture diagram)
# ============================================================

@dataclass
class DataStore:
    """dataStore(X, data) - Node X stores data"""
    node: str
    data: str
    
    def __str__(self):
        return f"dataStore({self.node}, {self.data})"


@dataclass
class DataFlow:
    """dataflow(X, Y) - Data flow from X to Y"""
    source: str
    target: str
    
    def __str__(self):
        return f"dataflow({self.source}, {self.target})"


@dataclass
class NetAccess:
    """netAccess(X, Y) - Network access from X to Y"""
    source: str
    target: str
    port: Optional[int] = None
    
    def __str__(self):
        if self.port:
            return f"netAccess({self.source}, {self.target}, {self.port})"
        return f"netAccess({self.source}, {self.target})"


@dataclass
class NodeType:
    """nodeType(X, type) - Node X is of type"""
    node: str
    node_type: str  # Database, Compute, Controller, etc.
    
    def __str__(self):
        return f"nodeType({self.node}, {self.node_type})"


@dataclass
class ChildOf:
    """childOf(X, Y) - X is child of Y (e.g., in subnet)"""
    child: str
    parent: str
    
    def __str__(self):
        return f"childOf({self.child}, {self.parent})"


@dataclass
class TrustZone:
    """trustZone(X, Y) - X and Y are in same trust zone"""
    node1: str
    node2: str
    zone: str
    
    def __str__(self):
        return f"trustZone({self.node1}, {self.node2}, {self.zone})"


# ============================================================
# Attack Step Definition
# ============================================================

@dataclass
class AttackStep:
    """
    An attack step with pre/postconditions.
    
    From General Logic Rules:
    - Preconditions: conditions that must be TRUE for step to execute
    - Postconditions: conditions that become TRUE after execution
    """
    id: str
    name: str
    rule_name: str  # From the "Rule Name" column
    description: str
    preconditions: List[Any]   # Mix of predicates
    postconditions: List[Any]  # Mix of predicates
    mitre_techniques: List[str] = field(default_factory=list)  # Associated techniques
    
    def __str__(self):
        pre_str = ", ".join(str(p) for p in self.preconditions)
        post_str = ", ".join(str(p) for p in self.postconditions)
        return f"[{self.rule_name}] pre=[{pre_str}] -> post=[{post_str}]"


# ============================================================
# System State (tracks what predicates are TRUE)
# ============================================================

@dataclass
class SystemState:
    """
    Tracks the current state of all predicates.
    Updated when log evidence shows a postcondition is satisfied.
    """
    # State predicates (can be set True by log evidence)
    exec_code: Dict[str, Permission] = field(default_factory=dict)
    app_access: Dict[str, Set[Permission]] = field(default_factory=dict)
    credentials: Set[str] = field(default_factory=set)
    data_possession: Dict[str, Set[Permission]] = field(default_factory=dict)
    net_control: Dict[str, Set[Permission]] = field(default_factory=dict)
    
    # MITRE enrichment context per node (populated from OCSF alert enrichment)
    node_mitre_context: Dict[str, List[dict]] = field(default_factory=dict)

    # Graded compromise confidence per node, accumulated via noisy-OR.
    # P = 1 - Π(1 - cᵢ): independent weak signals compound into strong ones
    # (three brute-force-then-login alerts > any single alert). This is the
    # graded counterpart to the binary exec_code/app_access dicts above —
    # the COMPROMISED/ACCESSED labels become thresholds on top of this.
    node_confidence: Dict[str, float] = field(default_factory=dict)

    # Structure predicates (derived from diagram, usually static)
    data_stores: Dict[str, Set[str]] = field(default_factory=dict)
    data_flows: List[tuple] = field(default_factory=list)
    net_access: List[tuple] = field(default_factory=list)
    node_types: Dict[str, str] = field(default_factory=dict)
    child_relations: List[tuple] = field(default_factory=list)
    trust_zones: Dict[str, str] = field(default_factory=dict)
    
    def add_mitre_context(self, node: str, enrichment: dict,
                          fact_type: str = "", confidence: float = 0.0,
                          time: int = None):
        """Store MITRE enrichment from an OCSF alert that triggered a predicate on this node.

        `fact_type`/`confidence`/`time` describe the predicate this alert fired so
        `get_mitre_summary` can attribute the node's status to the technique that
        actually drove it (the compromise-tier entry), not whichever alert happened
        to be processed first.
        """
        if not enrichment or not enrichment.get("mitre_techniques"):
            return
        if node not in self.node_mitre_context:
            self.node_mitre_context[node] = []
        self.node_mitre_context[node].append({
            "mitre_techniques":    enrichment.get("mitre_techniques", []),
            "mitre_tactics":       enrichment.get("mitre_tactics", []),
            "kill_chain_phase":    enrichment.get("kill_chain_phase", ""),
            "severity":            enrichment.get("severity", ""),
            "top7_category":       enrichment.get("top7_category", ""),
            "is_apt":              enrichment.get("is_apt", False),
            "attacker_attribution":enrichment.get("attacker_attribution", ""),
            "fact_type":           fact_type,
            "confidence":          confidence,
            "time":                time,
        })

    # fact_types that establish code execution (COMPROMISED) vs mere access.
    _COMPROMISE_FACT_TYPES = ("attack_source",)

    def get_mitre_summary(self, node: str) -> dict:
        """Return deduplicated MITRE context for a node, ready for the overlay."""
        contexts = self.node_mitre_context.get(node, [])
        if not contexts:
            return {}
        techniques = list(dict.fromkeys(t for c in contexts for t in c["mitre_techniques"]))
        tactics    = list(dict.fromkeys(t for c in contexts for t in c["mitre_tactics"]))
        phases     = list(dict.fromkeys(c["kill_chain_phase"] for c in contexts if c["kill_chain_phase"]))
        severities = list(dict.fromkeys(c["severity"] for c in contexts if c["severity"]))
        return {
            "mitre_techniques":  techniques,
            "mitre_tactics":     tactics,
            "kill_chain_phases": phases,
            "severity":          severities[0] if severities else "",
            "is_apt":            any(c["is_apt"] for c in contexts),
            "why": self._driving_why(contexts),
        }

    def _driving_why(self, contexts: list) -> str:
        """The technique that drives the node's status, as 'Txxxx (Top7 Category)'.

        A node is COMPROMISED because of compromise-tier (attack_source) evidence,
        so when any exists we attribute the status to the EARLIEST such technique —
        the entry that established code execution — rather than a later consequence
        (e.g. T1030 exfil) or whichever alert merely happened to be processed first.
        Falls back to access-tier evidence (ACCESSED), then to the first context.
        """
        compromise = [c for c in contexts if c["fact_type"] in self._COMPROMISE_FACT_TYPES]
        pool = compromise or contexts
        # earliest by observed time; contexts without a time sort last (None -> inf)
        chosen = min(pool, key=lambda c: (c["time"] is None, c["time"] or 0))
        tech = chosen["mitre_techniques"][0] if chosen["mitre_techniques"] else "?"
        return f"{tech} ({chosen['top7_category']})"

    def accumulate_confidence(self, node: str, c: float):
        """
        Fold one alert's confidence into the node's running total via noisy-OR:
            P_new = 1 - (1 - P_old)(1 - c)
        Order-independent and monotonic — re-running alerts never lowers P.
        """
        prior = self.node_confidence.get(node, 0.0)
        self.node_confidence[node] = 1.0 - (1.0 - prior) * (1.0 - c)

    def get_confidence(self, node: str) -> float:
        """Accumulated P(compromised) for a node; 0.0 if no evidence."""
        return self.node_confidence.get(node, 0.0)

    def set_exec_code(self, node: str, privilege: Permission):
        """Mark that attacker has code execution on node"""
        self.exec_code[node] = privilege
        
    def set_app_access(self, node: str, permission: Permission):
        """Mark that attacker has app access to node"""
        if node not in self.app_access:
            self.app_access[node] = set()
        self.app_access[node].add(permission)
    
    def set_credential(self, node: str):
        """Mark that attacker has credentials for node"""
        self.credentials.add(node)
    
    def set_data_possession(self, data: str, permission: Permission):
        """Mark that attacker possesses data"""
        if data not in self.data_possession:
            self.data_possession[data] = set()
        self.data_possession[data].add(permission)
    
    def has_exec_code(self, node: str, privilege: Permission = None) -> bool:
        """Check if attacker has code execution"""
        if node not in self.exec_code:
            return False
        if privilege is None:
            return True
        return self.exec_code[node] == privilege or self.exec_code[node] == Permission.ADMIN
    
    def has_app_access(self, node: str, permission: Permission = None) -> bool:
        """Check if attacker has app access"""
        if node not in self.app_access:
            return False
        if permission is None:
            return len(self.app_access[node]) > 0
        return permission in self.app_access[node]
    
    def has_credential(self, node: str) -> bool:
        """Check if attacker has credentials"""
        return node in self.credentials
    
    def has_net_access(self, source: str, target: str) -> bool:
        """Check if network access exists"""
        return (source, target) in self.net_access or any(
            s == source and t == target for s, t, *_ in self.net_access
        )
    
    def get_node_type(self, node: str) -> Optional[str]:
        """Get node type"""
        return self.node_types.get(node)
    
    def has_data_store(self, node: str, data: str = None) -> bool:
        """Check if node stores the given data (or any data when data=None)"""
        stored = self.data_stores.get(node, set())
        if data is None:
            return len(stored) > 0
        return data in stored
