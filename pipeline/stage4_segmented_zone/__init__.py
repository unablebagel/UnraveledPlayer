"""
stage4_segmented_zone — microsegmentation multi-attacker demo.

Splits the flat private subnet (intranet_private = 10.1.5.0/24) into three smaller
trust zones — intranet_app / intranet_db / intranet_backup — so there are more
trust boundaries for attackers to cross, and stages TWO APTs that share a foothold,
do a short intra-subnet lateral hop, then diverge into different micro-segments.

It showcases three things, all via the EXISTING engine (imported, never edited):
  1. Compromise state of a node          — CLEAN / ACCESSED / COMPROMISED.
  2. Per-node multi-state                 — the shared foothold AND a shared
                                            intermediate host each carry ONE state
                                            per attacker.
  3. Multi-attacker attribution           — split_by_target_zone attributes each
                                            downstream micro-segment to the right APT.

Pure trust-zone mechanism only (no provenance / TTP splitters). Ground-truth
attacker labels are used ONLY for the V-measure eval, never for linking.
"""
