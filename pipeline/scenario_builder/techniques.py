"""
techniques.py — MITRE ATT&CK technique registry for scenario_builder.

One dict, technique id -> the 7-tuple `make_alert`
(stage3_synthetic_attacker/generate.py) expects:

    (tech, tactic_uid, tactic_name, phase, phase_id, stage, desc)

Consolidates the tuples already hand-written across the generators
(`_FOOTHOLD`, `_SSH_LATERAL`, `_EXFIL` in stage3; `_ACCT_MANIP` in stage4)
plus the rest of the techniques `ocsf_to_facts.RULE_TABLE` already knows how
to score, so a scenario author has a full palette without inventing new
tuples. `desc` is kept generic (not attacker-name-specific) — the existing
per-attacker inline specs interpolate the ground-truth label into `desc`
(e.g. stage4_segmented_zone/generate.py's foothold), but `desc` only feeds
the alert's `message`/`finding_info.desc` (cosmetic, never scored), and one
registry entry serves every attacker that uses that technique.

CONSTRAINT: every key here must also be a key in `ocsf_to_facts.RULE_TABLE`.
A technique missing from RULE_TABLE does not vanish from the pipeline —
`_alert_to_facts` falls back to `DEFAULT_RULE` (a weak, "touched only"
attack_target fact, confidence 0.3), so an attacker using an unregistered
technique silently never earns compromise credit (Session.compromised_nodes
stays wrong even though the session itself still exists). The module-level
check below, plus test_compile.py, guard against that.
"""

from ..ocsf_to_facts import RULE_TABLE

# (technique, tactic_uid, tactic_name, phase, phase_id, stage, desc)
TECHNIQUES = {
    # -- Reconnaissance --
    "T1595.001": ("T1595.001", "TA0043", "Reconnaissance", "Reconnaissance", 0,
                  "Reconnaissance", "Active scanning: IP block sweep"),
    "T1595.002": ("T1595.002", "TA0043", "Reconnaissance", "Reconnaissance", 0,
                  "Reconnaissance", "Active scanning: vulnerability scan"),

    # -- Initial access --
    "T1078": ("T1078", "TA0001", "Initial Access", "Initial Access", 1,
              "Initial Access", "Valid-accounts login"),
    "T1078.003": ("T1078.003", "TA0001", "Initial Access", "Initial Access", 1,
                  "Initial Access", "Valid-accounts login (local account)"),
    "T1566.001": ("T1566.001", "TA0001", "Initial Access", "Initial Access", 1,
                  "Initial Access", "Spearphishing attachment (attempt)"),

    # -- Discovery --
    "T1018": ("T1018", "TA0007", "Discovery", "Discovery", 2,
              "Discovery", "Remote system discovery"),
    "T1046": ("T1046", "TA0007", "Discovery", "Discovery", 2,
              "Discovery", "Network service discovery"),

    # -- Credential access --
    "T1110.001": ("T1110.001", "TA0006", "Credential Access", "Credential Access", 3,
                  "Credential Access", "Brute force: password guessing (attempt)"),
    "T1552": ("T1552", "TA0006", "Credential Access", "Credential Access", 3,
              "Credential Access", "Unsecured credentials"),

    # -- Persistence --
    "T1098": ("T1098", "TA0003", "Persistence", "Persistence", 4,
              "Persistence", "Account manipulation on shared host"),

    # -- Lateral movement --
    "T1021.004": ("T1021.004", "TA0008", "Lateral Movement", "Lateral Movement", 5,
                  "Lateral Movement", "SSH lateral movement to internal host"),
    "T1021": ("T1021", "TA0008", "Lateral Movement", "Lateral Movement", 5,
              "Lateral Movement", "Remote services lateral movement (generic)"),

    # -- Command & control --
    "T1573.001": ("T1573.001", "TA0011", "Command and Control", "Command and Control", 6,
                  "Command and Control", "Encrypted C2 channel"),
    "T1071.001": ("T1071.001", "TA0011", "Command and Control", "Command and Control", 6,
                  "Command and Control", "Application-layer C2"),

    # -- Collection / exfiltration --
    "T1213": ("T1213", "TA0009", "Collection", "Collection", 6,
              "Collection", "Data from information repositories"),
    "T1041": ("T1041", "TA0010", "Exfiltration", "Exfiltration", 7,
              "Exfiltration", "Exfiltration over C2 channel"),
    "T1030": ("T1030", "TA0010", "Exfiltration", "Exfiltration", 7,
              "Exfiltration", "Exfiltration with data transfer size limits"),

    # -- Defense evasion --
    "T1070": ("T1070", "TA0005", "Defense Evasion", "Defense Evasion", 8,
              "Defense Evasion", "Indicator removal"),
}

_missing = sorted(set(TECHNIQUES) - set(RULE_TABLE))
if _missing:
    raise RuntimeError(
        f"scenario_builder.techniques: {_missing} not in ocsf_to_facts.RULE_TABLE "
        "-- would silently downgrade to DEFAULT_RULE (weak attack_target only)"
    )
