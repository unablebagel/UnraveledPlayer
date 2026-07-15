"""
topology.py — the segmented-private-subnet diagram.

Reuses the full UNRAVELED topology (create_unraveled_complete_diagram) and rewrites
ONLY the private subnet: the single flat `intranet_private` zone (10.1.5.0/24, with
sftp / intranet_app / database) becomes THREE micro-segments, each its own trust zone
and its own /26 out of the same 10.1.5.0/24 block:

    intranet_app     10.1.5.0/26     app_server_1 (10.1.5.10), app_server_2 (10.1.5.11)
    intranet_db      10.1.5.64/26    db_primary   (10.1.5.68),  db_replica   (10.1.5.69)
    intranet_backup  10.1.5.128/26   sftp_server  (10.1.5.130), backup_store (10.1.5.131)

Every host IP is PINNED. make_zone_of (stage2_multi_attacker/trust_zone.py) resolves an IP
first by mapped node -> its trust_zone, and only falls back to a /24-PREFIX match if
unmapped. All three micro-segments share the `10.1.5` prefix, so the prefix fallback
cannot tell them apart — pinning every IP makes the node lookup win, so the fallback
is never exercised for our IPs. (The IT foothold/lateral hosts it_host_2=10.1.3.10 and
it_host_3=10.1.3.11 are already pinned by the base topology.)

Nothing in the shared pipeline is modified; this only post-processes a copy of the
diagram it builds.
"""

from ..toy_diagram import DiagramNode, DiagramEdge, ToyDiagram
from ..unraveled_diagram import create_unraveled_complete_diagram

# node ids of the flat private subnet we replace with micro-segments
_OLD_PRIVATE_ZONE = "intranet_private"


def _micro_segment_nodes():
    """The six nodes of the three private micro-segments (all IPs pinned)."""
    return [
        # ---- App tier (intranet_app, 10.1.5.0/26) -----------------------------
        DiagramNode(
            id="app_server_1", name="App Server 1", node_type="Compute",
            trust_zone="intranet_app", ip_addresses=["10.1.5.10"],
            services=[{"name": "HTTP", "port": 80}],
            properties={"subnet": "10.1.5.0/26", "publiclyAccessible": False},
        ),
        DiagramNode(
            id="app_server_2", name="App Server 2", node_type="Compute",
            trust_zone="intranet_app", ip_addresses=["10.1.5.11"],
            services=[{"name": "HTTP", "port": 80}],
            properties={"subnet": "10.1.5.0/26", "publiclyAccessible": False},
        ),
        # ---- DB tier (intranet_db, 10.1.5.64/26) ------------------------------
        DiagramNode(
            id="db_primary", name="DB Primary", node_type="Database",
            trust_zone="intranet_db", ip_addresses=["10.1.5.68"],
            services=[{"name": "MySQL", "port": 3306}],
            data_stored=["customer_data", "transaction_logs"],
            properties={"subnet": "10.1.5.64/26", "publiclyAccessible": False,
                        "encrypted": True},
        ),
        DiagramNode(
            id="db_replica", name="DB Replica", node_type="Database",
            trust_zone="intranet_db", ip_addresses=["10.1.5.69"],
            services=[{"name": "MySQL", "port": 3306}],
            data_stored=["customer_data", "transaction_logs"],
            properties={"subnet": "10.1.5.64/26", "publiclyAccessible": False,
                        "encrypted": True},
        ),
        # ---- Backup tier (intranet_backup, 10.1.5.128/26) ---------------------
        DiagramNode(
            id="sftp_server", name="SFTP Server", node_type="Compute",
            trust_zone="intranet_backup", ip_addresses=["10.1.5.130"],
            services=[{"name": "SFTP", "port": 22}],
            properties={"subnet": "10.1.5.128/26", "publiclyAccessible": False},
        ),
        DiagramNode(
            id="backup_store", name="Backup Store", node_type="Storage",
            trust_zone="intranet_backup", ip_addresses=["10.1.5.131"],
            services=[{"name": "SFTP", "port": 22}],
            data_stored=["nightly_backups"],
            properties={"subnet": "10.1.5.128/26", "publiclyAccessible": False},
        ),
    ]


def _micro_segment_edges():
    """Expected data flows into and within the three micro-segments."""
    return [
        DiagramEdge(id="edge_firewall_to_app_1", source_id="firewall",
                    target_id="app_server_1", label="Intranet App Access"),
        DiagramEdge(id="edge_firewall_to_app_2", source_id="firewall",
                    target_id="app_server_2", label="Intranet App Access"),
        DiagramEdge(id="edge_app_1_to_db", source_id="app_server_1",
                    target_id="db_primary", label="Application Data",
                    port=3306, protocol="MySQL", data_transferred=["customer_data"]),
        DiagramEdge(id="edge_app_2_to_db", source_id="app_server_2",
                    target_id="db_primary", label="Application Data",
                    port=3306, protocol="MySQL", data_transferred=["customer_data"]),
        DiagramEdge(id="edge_db_primary_to_replica", source_id="db_primary",
                    target_id="db_replica", label="Replication",
                    port=3306, protocol="MySQL",
                    data_transferred=["customer_data", "transaction_logs"]),
        DiagramEdge(id="edge_firewall_to_sftp", source_id="firewall",
                    target_id="sftp_server", label="SFTP Access"),
        DiagramEdge(id="edge_sftp_to_backup", source_id="sftp_server",
                    target_id="backup_store", label="Backup Copy"),
    ]


def create_segmented_diagram() -> ToyDiagram:
    """The UNRAVELED topology with the private subnet split into three micro-segments."""
    base = create_unraveled_complete_diagram()

    # drop the flat private-subnet nodes and any edge that referenced them
    removed = {n.id for n in base.nodes if n.trust_zone == _OLD_PRIVATE_ZONE}
    nodes = [n for n in base.nodes if n.id not in removed]
    edges = [e for e in base.edges
             if e.source_id not in removed and e.target_id not in removed]

    nodes.extend(_micro_segment_nodes())
    edges.extend(_micro_segment_edges())

    # rebuild the zone index the same way unraveled_diagram.py does
    trust_zones: dict = {}
    for node in nodes:
        trust_zones.setdefault(node.trust_zone, []).append(node.id)

    return ToyDiagram(nodes=nodes, edges=edges, trust_zones=trust_zones)


if __name__ == "__main__":
    d = create_segmented_diagram()
    print(f"{len(d.nodes)} nodes, {len(d.edges)} edges")
    for zone in ("intranet_app", "intranet_db", "intranet_backup"):
        print(f"  {zone}: {d.trust_zones.get(zone)}")
