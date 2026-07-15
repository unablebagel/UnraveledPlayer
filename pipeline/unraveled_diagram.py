"""
Unraveled Complete Network Diagram
==================================

The full Unraveled topology as drawn in `system-model.png` and described in the
Unraveled dataset (https://gitlab.com/asu22/unraveled).

Unlike `toy_diagram.py` (a deliberately minimal 4-node sketch tuned for the
APT attack-path demo), this models the *complete* internal network:

- 3 corporate department subnets, 5 hosts each, with the actual dataset IPs:
    HR & Executive  10.1.1.0/24
    Marketing       10.1.2.0/24
    IT              10.1.3.0/24
- DMZ Public Subnet      10.1.4.0/24  (Honeypot Server, Web Server)
- Intranet Private Subnet 10.1.5.0/24 (SFTP, Intranet App, Database System)
- A Firewall separating the corporate network from the production network.

External entities (Internet, attacker groups, C2) are intentionally excluded —
this file models the internal network only.

Reuses the dataclasses and helpers from `toy_diagram.py`.
"""

from .toy_diagram import (
    DiagramNode, DiagramEdge, ToyDiagram,
    get_ip_to_node_mapping, extract_structure_predicates, diagram_to_json,
)


def create_unraveled_complete_diagram() -> ToyDiagram:
    """
    Build the complete internal Unraveled network diagram.

    Host IPs and OS come from the Unraveled README host table; the zone
    structure (departments, DMZ, intranet, firewall) comes from system-model.png.
    """

    nodes = []

    # ------------------------------------------------------------------
    # Corporate departments — 5 hosts each, real dataset IPs
    # ------------------------------------------------------------------
    # (id_prefix, zone, subnet, [(ip, os), ...])
    departments = [
        ("hr_host", "hr_executive", "10.1.1.0/24", [
            ("10.1.1.4", "Linux"),
            ("10.1.1.6", "Linux"),
            ("10.1.1.11", "Linux"),
            ("10.1.1.12", "Linux"),
            ("10.1.1.15", "Windows"),
        ]),
        ("mkt_host", "marketing", "10.1.2.0/24", [
            ("10.1.2.8", "Windows"),
            ("10.1.2.9", "Linux"),
            ("10.1.2.10", "Linux"),
            ("10.1.2.17", "Linux"),
            ("10.1.2.21", "Windows"),
        ]),
        ("it_host", "it", "10.1.3.0/24", [
            ("10.1.3.8", "Linux"),
            ("10.1.3.10", "Linux"),
            ("10.1.3.11", "Linux"),
            ("10.1.3.12", "Linux"),
            ("10.1.3.17", "Windows"),
        ]),
    ]

    zone_display = {
        "hr_executive": "HR & Executive",
        "marketing": "Marketing",
        "it": "IT",
    }

    for id_prefix, zone, subnet, hosts in departments:
        for i, (ip, os_name) in enumerate(hosts, start=1):
            # Windows hosts expose RDP; Linux hosts expose SSH
            service = ({"name": "RDP", "port": 3389} if os_name == "Windows"
                       else {"name": "SSH", "port": 22})
            nodes.append(DiagramNode(
                id=f"{id_prefix}_{i}",
                name=f"{zone_display[zone]} Host {i}",
                node_type="Compute",
                trust_zone=zone,
                ip_addresses=[ip],
                services=[service],
                properties={"os": os_name, "subnet": subnet,
                            "publiclyAccessible": False},
            ))

    # ------------------------------------------------------------------
    # DMZ Public Subnet (10.1.4.0/24)
    # IP pinning: 10.1.4.16 is the only 10.1.4.x IP that appears in
    # siem_alerts_enriched.jsonl (53 alerts, port 22, AA SSH-scan traffic).
    # Profile matches honeypot_server (SSH-exposed, scanner-bait), not the
    # HTTP/HTTPS web_server. web_server's true IP is not surfaced by any
    # alert in the current dataset — left unpinned rather than guessed.
    # ------------------------------------------------------------------
    nodes.append(DiagramNode(
        id="honeypot_server",
        name="Honeypot Server",
        node_type="Compute",
        trust_zone="dmz_public",
        ip_addresses=["10.1.4.16"],
        services=[{"name": "SSH", "port": 22}],
        properties={"subnet": "10.1.4.0/24", "publiclyAccessible": True,
                    "role": "honeypot"},
    ))
    nodes.append(DiagramNode(
        id="web_server",
        name="Web Server",
        node_type="Compute",
        trust_zone="dmz_public",
        # ip_addresses intentionally unset — no 10.1.4.x IP besides .16
        # appears in current alerts. Pin once a real alert surfaces it.
        services=[
            {"name": "HTTP", "port": 80},
            {"name": "HTTPS", "port": 443},
        ],
        properties={"subnet": "10.1.4.0/24", "publiclyAccessible": True},
    ))

    # ------------------------------------------------------------------
    # Intranet Private Subnet (10.1.5.0/24)
    # IP pinning: 10.1.5.21 is the only 10.1.5.x IP in current alerts
    # (220 mentions, T1030 exfil traffic from APT-compromised IT host).
    # Matches the toy_diagram's `production_db` IP. sftp_server and
    # intranet_app_server have no alert evidence — left unpinned.
    # ------------------------------------------------------------------
    nodes.append(DiagramNode(
        id="sftp_server",
        name="SFTP Server",
        node_type="Compute",
        trust_zone="intranet_private",
        # ip_addresses unset — no SFTP-shaped alert in current dataset.
        services=[{"name": "SFTP", "port": 22}],
        properties={"subnet": "10.1.5.0/24", "publiclyAccessible": False},
    ))
    nodes.append(DiagramNode(
        id="intranet_app_server",
        name="Intranet App Server",
        node_type="Compute",
        trust_zone="intranet_private",
        # ip_addresses unset — no intranet-app-shaped alert in current dataset.
        services=[{"name": "HTTP", "port": 80}],
        properties={"subnet": "10.1.5.0/24", "publiclyAccessible": False},
    ))
    nodes.append(DiagramNode(
        id="database_system",
        name="Database System",
        node_type="Database",
        trust_zone="intranet_private",
        ip_addresses=["10.1.5.21"],
        services=[{"name": "MySQL", "port": 3306}],
        data_stored=["customer_data", "transaction_logs"],
        properties={"subnet": "10.1.5.0/24", "publiclyAccessible": False,
                    "encrypted": True},
    ))

    # ------------------------------------------------------------------
    # Perimeter — Firewall + external-facing gateway
    # ------------------------------------------------------------------
    nodes.append(DiagramNode(
        id="firewall",
        name="Firewall",
        node_type="Firewall",
        trust_zone="perimeter",
        properties={"role": "corporate/production boundary"},
    ))
    # 192.168.0.11 is in a separate /24 from the corporate/dmz/intranet
    # subnets. Receives 1,327 alerts — overwhelmingly AA T1110.001 SSH
    # brute-force attempts (port 22). Modelled as an external-facing
    # gateway / jump host since it sits outside the documented internal
    # subnets and is the primary external-attack target.
    nodes.append(DiagramNode(
        id="external_gateway",
        name="External Gateway",
        node_type="Compute",
        trust_zone="perimeter",
        ip_addresses=["192.168.0.11"],
        services=[{"name": "SSH", "port": 22}],
        properties={"subnet": "192.168.0.0/24", "publiclyAccessible": True,
                    "role": "external_facing_gateway"},
    ))

    # ------------------------------------------------------------------
    # Edges (expected data flows)
    # ------------------------------------------------------------------
    edges = []

    # Every department host egresses through the firewall.
    department_host_ids = [n.id for n in nodes
                           if n.trust_zone in ("hr_executive", "marketing", "it")]
    for host_id in department_host_ids:
        edges.append(DiagramEdge(
            id=f"edge_{host_id}_to_firewall",
            source_id=host_id,
            target_id="firewall",
            label="Corporate Egress",
        ))

    # Firewall reaches the production servers.
    for server_id, label in [
        ("web_server", "Inbound Web"),
        ("honeypot_server", "Inbound (Honeypot)"),
        ("intranet_app_server", "Intranet App Access"),
        ("sftp_server", "SFTP Access"),
    ]:
        edges.append(DiagramEdge(
            id=f"edge_firewall_to_{server_id}",
            source_id="firewall",
            target_id=server_id,
            label=label,
        ))

    # Application data flows into the database.
    edges.append(DiagramEdge(
        id="edge_web_to_db",
        source_id="web_server",
        target_id="database_system",
        label="Application Data",
        port=3306,
        protocol="MySQL",
        data_transferred=["customer_data"],
    ))
    edges.append(DiagramEdge(
        id="edge_app_to_db",
        source_id="intranet_app_server",
        target_id="database_system",
        label="Application Data",
        port=3306,
        protocol="MySQL",
        data_transferred=["customer_data", "transaction_logs"],
    ))

    # ------------------------------------------------------------------
    # Trust zones
    # ------------------------------------------------------------------
    trust_zones = {}
    for node in nodes:
        trust_zones.setdefault(node.trust_zone, []).append(node.id)

    return ToyDiagram(nodes=nodes, edges=edges, trust_zones=trust_zones)


# Quick test
if __name__ == "__main__":
    import json

    diagram = create_unraveled_complete_diagram()
    mapping = get_ip_to_node_mapping(diagram)
    predicates = extract_structure_predicates(diagram)

    print("=== Unraveled Complete Diagram ===")
    print(json.dumps(diagram_to_json(diagram), indent=2))

    print(f"\n=== Totals ===")
    print(f"  Nodes: {len(diagram.nodes)}")
    print(f"  Edges: {len(diagram.edges)}")
    print(f"  Trust Zones: {len(diagram.trust_zones)}")

    print("\n=== IP to Node Mapping ===")
    for ip, node_id in mapping.items():
        print(f"  {ip} -> {node_id}")

    print("\n=== Trust Zones ===")
    for zone, node_ids in diagram.trust_zones.items():
        print(f"  {zone}: {node_ids}")
