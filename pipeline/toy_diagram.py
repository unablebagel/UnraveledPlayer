"""
Toy Diagram - Simulating a TM User Diagram
==========================================

This simulates what a user would draw in TM's architecture diagram editor.
In real TM, this would come from the frontend/database.

Purpose:
- Provide diagram nodes/edges that logs can be MAPPED to
- Provide structure predicates (nodeType, dataStore, netAccess, etc.)
- Enable "observed vs expected" comparison
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class DiagramNode:
    """A node in the user's architecture diagram"""
    id: str                          # Unique ID in diagram
    name: str                        # Display name
    node_type: str                   # TOSCA type: Database, Compute, etc.
    trust_zone: str                  # Which trust zone it belongs to
    ip_addresses: List[str] = field(default_factory=list)  # For mapping
    services: List[Dict] = field(default_factory=list)     # Expected services
    data_stored: List[str] = field(default_factory=list)   # What data it stores
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass  
class DiagramEdge:
    """An edge (data flow) in the user's diagram"""
    id: str
    source_id: str
    target_id: str
    label: str
    port: int = None
    protocol: str = None
    data_transferred: List[str] = field(default_factory=list)


@dataclass
class ToyDiagram:
    """
    A minimal diagram for testing the Unraveled dataset.
    
    This represents what a user THINKS their network looks like.
    The logs will reveal what ACTUALLY happens.
    """
    nodes: List[DiagramNode]
    edges: List[DiagramEdge]
    trust_zones: Dict[str, List[str]]  # zone_name -> [node_ids]


def create_unraveled_toy_diagram() -> ToyDiagram:
    """
    Create a toy diagram that matches the Unraveled dataset topology.
    
    Based on Unraveled paper:
    - IT Network (10.1.3.x): Workstations
    - Production (10.1.5.x): Servers, databases
    - External (10.8.x.x): C2 servers
    """
    
    nodes = [
        # IT Network - Corporate workstations
        DiagramNode(
            id="it_workstation_1",
            name="IT Workstation",
            node_type="Compute",
            trust_zone="corporate_it",
            ip_addresses=["10.1.3.8"],
            services=[{"name": "RDP", "port": 3389}],
            properties={"publiclyAccessible": False}
        ),
        
        DiagramNode(
            id="db_admin_workstation",
            name="DB Admin Workstation",
            node_type="Compute", 
            trust_zone="corporate_it",
            ip_addresses=["10.1.3.17"],
            services=[
                {"name": "RDP", "port": 3389},
                {"name": "MySQL Client", "port": None}
            ],
            properties={"hasDBCredentials": True}
        ),
        
        # Production Network - Servers
        DiagramNode(
            id="production_db",
            name="Production MySQL Database",
            node_type="Database",
            trust_zone="production",
            ip_addresses=["10.1.5.21"],
            services=[{"name": "MySQL", "port": 3306}],
            data_stored=["customer_data", "transaction_logs"],
            properties={"publiclyAccessible": False, "encrypted": True}
        ),
        
        DiagramNode(
            id="web_server",
            name="Web Application Server",
            node_type="Compute",
            trust_zone="production",
            ip_addresses=["10.1.4.25"],
            services=[
                {"name": "HTTP", "port": 80},
                {"name": "HTTPS", "port": 443}
            ],
            properties={"publiclyAccessible": True}
        ),
        
        # External (not in diagram but exists in logs)
        # This is intentionally NOT in the diagram to test "unknown node" detection
    ]
    
    edges = [
        # Expected data flows in the diagram
        DiagramEdge(
            id="edge_dbadmin_to_db",
            source_id="db_admin_workstation",
            target_id="production_db",
            label="MySQL Management",
            port=3306,
            protocol="MySQL",
            data_transferred=["queries", "admin_commands"]
        ),
        
        DiagramEdge(
            id="edge_web_to_db",
            source_id="web_server",
            target_id="production_db",
            label="Application Data",
            port=3306,
            protocol="MySQL",
            data_transferred=["customer_data"]
        ),
        
        # Note: No edge from it_workstation_1 to production_db
        # If logs show this connection, it's SUSPICIOUS
    ]
    
    trust_zones = {
        "corporate_it": ["it_workstation_1", "db_admin_workstation"],
        "production": ["production_db", "web_server"],
        "external": []  # C2 servers would be here if detected
    }
    
    return ToyDiagram(nodes=nodes, edges=edges, trust_zones=trust_zones)


def get_ip_to_node_mapping(diagram: ToyDiagram) -> Dict[str, str]:
    """
    Create IP -> Node ID mapping for log processing.
    
    This is the MAPPING LAYER that connects logs to diagram entities.
    """
    mapping = {}
    for node in diagram.nodes:
        for ip in node.ip_addresses:
            mapping[ip] = node.id
    return mapping


def extract_structure_predicates(diagram: ToyDiagram) -> Dict[str, Any]:
    """
    Extract structure predicates from the diagram.
    
    These are facts that come from the diagram, not from logs:
    - nodeType(X, type)
    - dataStore(X, data)
    - netAccess(X, Y) - expected connections
    - trustZone(X, Y) - same zone relationships
    """
    predicates = {
        "node_types": {},      # node_id -> type
        "data_stores": {},     # node_id -> [data]
        "expected_edges": [],  # [(source_id, target_id, port)]
        "trust_zones": {},     # node_id -> zone_name
        "same_trust_zone": [], # [(node1, node2, zone)]
    }
    
    # Extract node types
    for node in diagram.nodes:
        predicates["node_types"][node.id] = node.node_type
        predicates["trust_zones"][node.id] = node.trust_zone
        if node.data_stored:
            predicates["data_stores"][node.id] = node.data_stored
    
    # Extract expected edges
    for edge in diagram.edges:
        predicates["expected_edges"].append((
            edge.source_id, 
            edge.target_id, 
            edge.port
        ))
    
    # Extract trust zone relationships
    for zone, node_ids in diagram.trust_zones.items():
        for i, n1 in enumerate(node_ids):
            for n2 in node_ids[i+1:]:
                predicates["same_trust_zone"].append((n1, n2, zone))
    
    return predicates


def diagram_to_json(diagram: ToyDiagram) -> Dict:
    """Export diagram to JSON format (similar to TM-backend)"""
    return {
        "nodes": [
            {
                "id": n.id,
                "name": n.name,
                "type": n.node_type,
                "trust_zone": n.trust_zone,
                "ip_addresses": n.ip_addresses,
                "services": n.services,
                "data_stored": n.data_stored,
                "properties": n.properties
            }
            for n in diagram.nodes
        ],
        "edges": [
            {
                "id": e.id,
                "source": e.source_id,
                "target": e.target_id,
                "label": e.label,
                "port": e.port,
                "protocol": e.protocol,
                "data_transferred": e.data_transferred
            }
            for e in diagram.edges
        ],
        "trust_zones": diagram.trust_zones
    }


# Quick test
if __name__ == "__main__":
    import json
    
    diagram = create_unraveled_toy_diagram()
    mapping = get_ip_to_node_mapping(diagram)
    predicates = extract_structure_predicates(diagram)
    
    print("=== Toy Diagram ===")
    print(json.dumps(diagram_to_json(diagram), indent=2))
    
    print("\n=== IP to Node Mapping ===")
    for ip, node_id in mapping.items():
        print(f"  {ip} -> {node_id}")
    
    print("\n=== Structure Predicates ===")
    print(f"  Node Types: {predicates['node_types']}")
    print(f"  Data Stores: {predicates['data_stores']}")
    print(f"  Expected Edges: {predicates['expected_edges']}")
