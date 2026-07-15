"""
stage1_streaming — replay the noisy-OR pipeline in timestamp order.

Same scoring algorithm as state_demo.py (no changes to it), but instead of one
final snapshot it produces a SEQUENCE of full-topology snapshots over time, so
you can see when each host crossed CLEAN -> ACCESSED -> COMPROMISED.

LABEL-FREE: the operational path keys only off time + technique + IP->node
mapping. `unraveled_stage` is never read here.
"""
