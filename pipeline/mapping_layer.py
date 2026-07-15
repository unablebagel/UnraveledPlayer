"""
Mapping Layer - Connect Logs to Diagram Entities
=================================================

This is the CRITICAL layer that bridges:
- Log data (speaks in IPs, ports, protocols)
- Diagram entities (speaks in node IDs, data flows, trust zones)

Without this layer, we can't answer:
"Does the log evidence show that diagram node X is compromised?"
"""

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field

from .toy_diagram import ToyDiagram, DiagramNode, get_ip_to_node_mapping
from .predicates import SystemState, Permission


@dataclass
class MappedFact:
    """A fact that has been mapped from log data to diagram entities"""
    fact_type: str
    diagram_entity: str       # Node ID or Edge ID from diagram
    original_data: Dict       # Original log data (IP, port, etc.)
    predicate: str            # The predicate this satisfies
    confidence: float = 1.0   # How confident is this mapping


class MappingLayer:
    """
    Maps log evidence to diagram entities.
    
    This enables answering questions like:
    - "Is diagram node 'production_db' compromised?"
    - "Was there unexpected traffic to 'production_db'?"
    
    Instead of:
    - "Is IP 10.1.5.21 compromised?" (meaningless without diagram context)
    """
    
    def __init__(self, diagram: ToyDiagram):
        self.diagram = diagram
        self.ip_to_node = get_ip_to_node_mapping(diagram)
        self.unmapped_ips: set = set()  # IPs we couldn't map
        self.mapped_facts: List[MappedFact] = []
        
    def map_ip_to_node(self, ip: str) -> Optional[str]:
        """
        Map an IP address to a diagram node ID.
        
        Returns None if IP is not in the diagram (unknown/external entity).
        """
        node_id = self.ip_to_node.get(ip)
        if node_id is None:
            self.unmapped_ips.add(ip)
        return node_id
    
    def map_connection(self, src_ip: str, dst_ip: str, port: int = None) -> Optional[Tuple[str, str]]:
        """
        Map a network connection to diagram edge.
        
        Returns (source_node_id, target_node_id) or None if can't map.
        """
        src_node = self.map_ip_to_node(src_ip)
        dst_node = self.map_ip_to_node(dst_ip)
        
        if src_node and dst_node:
            return (src_node, dst_node)
        return None
    
    def is_expected_edge(self, src_node: str, dst_node: str, port: int = None) -> bool:
        """Check if this edge exists in the diagram (expected traffic)"""
        for edge in self.diagram.edges:
            if edge.source_id == src_node and edge.target_id == dst_node:
                if port is None or edge.port is None or edge.port == port:
                    return True
        return False
    
    def map_attack_source(self, ip: str, signatures: List[str], stages: List[str]) -> Optional[MappedFact]:
        """
        Map an attack source IP to a diagram node.
        
        If the IP maps to a diagram node, it means that node is compromised.
        """
        node_id = self.map_ip_to_node(ip)
        
        if node_id:
            return MappedFact(
                fact_type="attack_source",
                diagram_entity=node_id,
                original_data={"ip": ip, "signatures": signatures, "stages": stages},
                predicate=f"execCode({node_id}, admin)"
            )
        else:
            # Unknown IP - could be external attacker
            return MappedFact(
                fact_type="unknown_attack_source",
                diagram_entity="EXTERNAL",
                original_data={"ip": ip, "signatures": signatures, "stages": stages},
                predicate=f"external_attacker({ip})",
                confidence=0.8
            )
    
    def map_attack_target(self, ip: str, port: int, access_type: str) -> Optional[MappedFact]:
        """
        Map an attack target to a diagram node.
        
        If the IP maps to a diagram node, it means that node was accessed.
        """
        node_id = self.map_ip_to_node(ip)
        
        if node_id:
            return MappedFact(
                fact_type="attack_target",
                diagram_entity=node_id,
                original_data={"ip": ip, "port": port, "access_type": access_type},
                predicate=f"hasAppAccess({node_id}, {access_type})"
            )
        return None
    
    def build_diagram_state(self, log_facts: List[Any]) -> SystemState:
        """
        Build SystemState using DIAGRAM NODE IDs instead of IPs.
        
        This is the key difference from the previous approach!
        
        Before: state.exec_code["10.1.3.8"] = admin
        After:  state.exec_code["it_workstation_1"] = admin
        """
        state = SystemState()
        
        # Add structure predicates from diagram
        for node in self.diagram.nodes:
            state.node_types[node.id] = node.node_type
            if node.data_stored:
                state.data_stores[node.id] = set(node.data_stored)
            state.trust_zones[node.id] = node.trust_zone
        
        # Add expected edges from diagram
        for edge in self.diagram.edges:
            state.net_access.append((edge.source_id, edge.target_id, edge.port))

        # Cross-alert dedupe for confidence accumulation.
        # Noisy-OR assumes INDEPENDENT signals. 1,327 identical brute-force
        # alerts on one host are one campaign re-counted, not independent
        # evidence — folding each one saturates P to 1.0 and mislabels probed
        # hosts as COMPROMISED. So a (node, technique) pair contributes its
        # confidence AT MOST ONCE. Volume per technique is captured elsewhere
        # (enrichment.alert_count); it must not inflate compromise probability.
        confidence_seen: set = set()

        def fold_once(node_id: str, technique, conf: float):
            key = (node_id, technique)
            if key in confidence_seen:
                return
            confidence_seen.add(key)
            state.accumulate_confidence(node_id, conf)

        # Map log facts to diagram entities
        for fact in log_facts:
            if fact.fact_type == "attack_source":
                ip = fact.details.get("node")
                node_id = self.map_ip_to_node(ip)
                if node_id:
                    state.set_exec_code(node_id, Permission.ADMIN)
                    fold_once(node_id, fact.details.get("technique"),
                              fact.details.get("confidence", 0.9))
                    state.add_mitre_context(node_id, fact.details.get("enrichment", {}),
                                            fact_type="attack_source",
                                            confidence=fact.details.get("confidence", 0.9),
                                            time=fact.details.get("time"))
                    self.mapped_facts.append(MappedFact(
                        fact_type="attack_source",
                        diagram_entity=node_id,
                        original_data={"ip": ip},
                        predicate=f"execCode({node_id}, admin)"
                    ))

            elif fact.fact_type == "attack_target":
                ip = fact.details.get("node")
                node_id = self.map_ip_to_node(ip)
                if node_id:
                    state.set_app_access(node_id, Permission.READ)
                    fold_once(node_id, fact.details.get("technique"),
                              fact.details.get("confidence", 0.3))
                    state.add_mitre_context(node_id, fact.details.get("enrichment", {}),
                                            fact_type="attack_target",
                                            confidence=fact.details.get("confidence", 0.3),
                                            time=fact.details.get("time"))
                    self.mapped_facts.append(MappedFact(
                        fact_type="attack_target",
                        diagram_entity=node_id,
                        original_data={"ip": ip},
                        predicate=f"hasAppAccess({node_id}, read)"
                    ))
            
            elif fact.fact_type == "net_access":
                src_ip = fact.details.get("source")
                dst_ip = fact.details.get("target")
                port = fact.details.get("port")

                mapping = self.map_connection(src_ip, dst_ip, port)
                if mapping:
                    src_node, dst_node = mapping
                    state.net_access.append((src_node, dst_node, port))

            elif fact.fact_type == "data_access":
                data_store_ip = fact.details.get("data_store")
                node_id = self.map_ip_to_node(data_store_ip)
                if node_id:
                    # The store itself was accessed (read), and its data is
                    # possessed/exfiltrated. ACCESSED, not COMPROMISED — the
                    # attacker read rows over MySQL, they did not get execCode.
                    state.set_app_access(node_id, Permission.READ)
                    fold_once(node_id, fact.details.get("technique"),
                              fact.details.get("confidence", 0.3))
                    state.add_mitre_context(node_id, fact.details.get("enrichment", {}),
                                            fact_type="data_access",
                                            confidence=fact.details.get("confidence", 0.3),
                                            time=fact.details.get("time"))
                    node = next((n for n in self.diagram.nodes if n.id == node_id), None)
                    if node:
                        for data in node.data_stored:
                            state.set_data_possession(data, Permission.READ)
                    self.mapped_facts.append(MappedFact(
                        fact_type="data_access",
                        diagram_entity=node_id,
                        original_data={"ip": data_store_ip},
                        predicate=f"hasAppAccess({node_id}, read) + dataPossession(read)"
                    ))

        return state
    
    def get_unexpected_connections(self, observed_connections: List[Tuple]) -> List[Dict]:
        """
        Find connections that were observed in logs but NOT in the diagram.
        
        These are potential security issues!
        """
        unexpected = []
        
        for conn in observed_connections:
            src_ip, dst_ip, port = conn[:3] if len(conn) >= 3 else (*conn, None)
            
            src_node = self.map_ip_to_node(src_ip)
            dst_node = self.map_ip_to_node(dst_ip)
            
            if src_node and dst_node:
                if not self.is_expected_edge(src_node, dst_node, port):
                    unexpected.append({
                        "type": "unexpected_internal_connection",
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "source_node": src_node,
                        "target_node": dst_node,
                        "port": port,
                        "severity": "HIGH",
                        "reason": "Connection not defined in architecture diagram"
                    })
            elif src_node and not dst_node:
                # Internal to external
                unexpected.append({
                    "type": "external_connection",
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "source_node": src_node,
                    "target_node": None,
                    "port": port,
                    "severity": "MEDIUM",
                    "reason": "Connection to unknown external IP"
                })
        
        return unexpected
    
    def get_mapping_report(self) -> Dict:
        """Generate a report of the mapping process"""
        return {
            "total_diagram_nodes": len(self.diagram.nodes),
            "total_diagram_edges": len(self.diagram.edges),
            "ip_mappings": dict(self.ip_to_node),
            "unmapped_ips": list(self.unmapped_ips),
            "mapped_facts_count": len(self.mapped_facts),
            "mapped_facts": [
                {
                    "type": f.fact_type,
                    "entity": f.diagram_entity,
                    "predicate": f.predicate,
                    "original": f.original_data
                }
                for f in self.mapped_facts
            ]
        }
