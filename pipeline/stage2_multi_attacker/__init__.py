"""
stage2_multi_attacker — per-attacker state decomposition on top of the noisy-OR pipeline.

A node no longer carries a single {clean, accessed, compromised} distribution;
it carries ONE distribution per inferred attacker *session*, plus an aggregate
(the unchanged global noisy-OR). This separates situations the merged view
conflates — e.g. a perimeter node that one attacker only *scanned* (ACCESSED)
while another's NAT-egress traffic makes it look COMPROMISED.

Sessions are inferred LABEL-FREE (no ground-truth attacker_attribution is read
for scoring). Ground-truth labels are consulted only in the eval report.

Nothing in the existing pipeline is modified; this package imports it.
"""
