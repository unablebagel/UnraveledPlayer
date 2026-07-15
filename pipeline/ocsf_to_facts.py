"""
OCSF Alerts -> ObservedFacts Adapter
=====================================
Bridges cybernatics_top7_alerts/ -> log_to_diagram_demo/ pipeline.

Replaces EvidenceExtractor as the source of ObservedFacts, using
pre-processed MITRE-enriched OCSF alerts instead of raw CSV logs.

    Input:  siem_alerts_enriched.jsonl  (cybernatics_top7_alerts/)
    Output: List[ObservedFact]          (same interface as EvidenceExtractor.extract_facts())

Tradeoff vs EvidenceExtractor:
    + MITRE technique, kill-chain, severity, APT attribution preserved per fact
    + No re-scanning of 6M+ raw CSV records
    - Drops events below MIN_ALERT_THRESHOLD=3 (filtered in siem_alerts_demo.py)
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple

from .evidence_extractor import ObservedFact

_DEFAULT_JSONL = (
    Path(__file__).parent.parent / "cybernatics_top7_alerts" / "siem_alerts_enriched_v3.jsonl"
)

# Ports that signal database access -> emit a data_access fact
_DB_PORTS = {3306, 5432, 27017}

# Internal address space of the modelled topology (corporate 10.1.x.x + perimeter
# 192.168.x.x). Anything else (e.g. 10.8.10.x) is an external attacker / C2 that
# is not a diagram node. Used to re-point maintain-access/C2 facts onto the
# internal foothold instead of dropping them. See findings/lateral_movement_mapping_gaps.md.
_INTERNAL_PREFIXES = ("10.1.", "192.168.")


def _is_internal(ip: Optional[str]) -> bool:
    return bool(ip) and ip.startswith(_INTERNAL_PREFIXES)

# ─────────────────────────────────────────────────────────────────────
# RULE TABLE  —  technique_id → predicate semantics.
# Source: General Logic Rules.docx + MITRE ATT&CK kill-chain conventions.
# Edit this dict to teach the algorithm about new techniques.
# ─────────────────────────────────────────────────────────────────────
#
# Field meanings:
#   victim_role:   "src" or "dst" — which side of the alert is the victim?
#   fact_type:     "attack_source" -> mapping_layer sets execCode    (compromise)
#                  "attack_target" -> mapping_layer sets hasAppAccess (touch only)
#   permission:    label carried on the predicate string
#   confidence:    P(this single alert correctly implies the predicate). TIERED,
#                  not continuous — only three defensible values:
#                    0.3  WEAK     — recon/scanning/attempts. Probing ≠ ownership.
#                    0.6  MODERATE — access implied but ambiguous (user-level C2,
#                                    repo reads, generic remote services).
#                    0.9  STRONG   — confirmed code exec / valid-account login /
#                                    exfil. You don't exfil from a box you don't own.
#                  Tiers map to kill-chain stage, so each value is auditable.
#                  Multiple alerts on one host COMPOUND via noisy-OR downstream.
#   note:          short justification, for auditability
#
RULE_TABLE = {
    # ── Reconnaissance / scanning — touched, not compromised ──
    "T1595.001": {"victim_role": "dst", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.3,
                  "note": "Active scanning: IP blocks. Target was probed, not owned."},
    "T1595.002": {"victim_role": "dst", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.3,
                  "note": "Active scanning: vuln scanning. Probed."},
    "T1018":     {"victim_role": "src", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.3,
                  "note": "Remote system discovery. Source enumerated targets; no state change."},
    "T1046":     {"victim_role": "src", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.3,
                  "note": "Network service discovery."},

    # ── Initial access attempts ──
    "T1110.001": {"victim_role": "dst", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.3,
                  "note": "Brute force ATTEMPT. Target was probed — does NOT imply login success."},
    "T1566.001": {"victim_role": "dst", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.3,
                  "note": "Phishing: spearphishing attachment. Initial-access ATTEMPT — "
                          "target probed, not owned. (Host-log alert: victim is the host.)"},

    # ── Initial access / privilege escalation — successful ──
    "T1078":     {"victim_role": "dst", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Valid accounts. Attacker is logged in as a real user on the target."},
    "T1078.003": {"victim_role": "dst", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Valid accounts (local)."},
    "T1098":     {"victim_role": "dst", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Account manipulation. Attacker is modifying accounts on target."},

    # ── Lateral movement ──
    # Logic Rule 6: netAccess(X,Y) + credentialPossession(Y) + execCode(X,admin) → execCode(Y,admin)
    "T1021.004": {"victim_role": "dst", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Remote services: SSH. Rule 6: lateral movement via credentials → execCode(dst, admin)."},
    "T1021":     {"victim_role": "dst", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.6,
                  "note": "Remote services (generic). Lateral movement plausible but sub-technique unknown."},

    # ── Command & control — source is the foothold ──
    # Logic Rule 2: dataflow(X,Y) + execCode(X,user) + AppLayerProtocol → execCode(Y,user)
    "T1573.001": {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Encrypted C2 channel. Source IS the implanted foothold; admin assumed for persistent C2."},
    "T1572":     {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Protocol tunneling. Source running tunnel; admin assumed."},
    "T1071.001": {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "user", "confidence": 0.6,
                  "note": "Application layer C2. Rule 2: execCode(src,user) + AppLayerProtocol propagates at user level."},

    # ── Collection / exfiltration — source is the foothold ──
    # Logic Rule 1: dataStore(X) + execCode(X,_) → dataPossession(data, read/write)
    "T1213":     {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "user", "confidence": 0.9, "dst_datastore_effect": True,
                  "note": "Data from information repos. Rule 1 precondition: execCode(src) to pull data; dst repo is read/exfiltrated."},
    "T1041":     {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9, "dst_datastore_effect": True,
                  "note": "Exfiltration over C2. Rule 1: execCode(src,admin) to exfiltrate; dst store's data is exfiltrated."},
    "T1030":     {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9, "dst_datastore_effect": True,
                  "note": "Data transfer size limits. Rule 1: execCode(src,admin) to stage chunked exfil; dst store's data is exfiltrated."},

    # ── Credential access ──
    # Component Rule 9: credentialPossession(X) + UnsecuredCreds → credentialPossession(Y)
    # No credentialPossession fact type yet; attack_target approximates the partial access.
    "T1552":     {"victim_role": "dst", "fact_type": "attack_target",
                  "permission": "read", "confidence": 0.6,
                  "note": "Unsecured credentials. CRule 9: ideally credentialPossession(dst); approximated as hasAppAccess(dst,read)."},

    # ── Defense evasion ──
    "T1070":     {"victim_role": "src", "fact_type": "attack_source",
                  "permission": "admin", "confidence": 0.9,
                  "note": "Indicator removal. Source must have execCode(admin) to delete its own traces."},
}

DEFAULT_RULE = {
    "victim_role": "dst", "fact_type": "attack_target",
    "permission": "read", "confidence": 0.3,
    "note": "Unknown technique — default to ACCESSED only, weak confidence.",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path) -> List[dict]:
    """
    Parse enriched JSONL.
    Handles both compact (one JSON per line) and pretty-printed formats,
    because siem_alerts_enriched.jsonl is written with indent by some script
    versions.
    """
    text = path.read_text(encoding="utf-8").strip()
    alerts: List[dict] = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        chunk = text[idx:].lstrip()
        if not chunk:
            break
        skipped = len(text[idx:]) - len(chunk)
        obj, end = decoder.raw_decode(chunk)
        alerts.append(obj)
        idx += skipped + end
    return alerts


def _get_observables(alert: dict) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Extract (src_ip, dst_ip, dst_port) from observables[].

    dst_port fallback: when an alert is grouped by (src_ip, dst_ip) only —
    e.g. C2/exfiltration alerts — the port is absent from observables but
    present in unmapped.raw_data.top_ports[0].
    """
    src_ip = dst_ip = None
    dst_port: Optional[int] = None

    for obs in alert.get("observables", []):
        name = obs.get("name", "")
        value = obs.get("value", "")
        if name in ("src_ip", "evidences[0].src_endpoint.ip"):
            src_ip = value or None
        elif name in ("dst_ip", "evidences[0].dst_endpoint.ip"):
            dst_ip = value or None
        elif name in ("dst_port", "evidences[0].dst_endpoint.port") and value:
            try:
                dst_port = int(value)
            except ValueError:
                pass

    if dst_port is None:
        top_ports = alert.get("unmapped", {}).get("raw_data", {}).get("top_ports", [])
        if top_ports:
            try:
                dst_port = int(top_ports[0])
            except (ValueError, TypeError):
                pass

    return src_ip, dst_ip, dst_port


def _enrichment_context(alert: dict) -> dict:
    """
    Build a dict of MITRE + kill-chain + severity fields to attach to
    ObservedFact.details["enrichment"]. Downstream consumers (mapping_layer)
    ignore this key; it is available for future diagram overlay extensions.
    """
    unmapped = alert.get("unmapped", {})
    # Techniques live under finding_info.attacks, NOT top-level alert["attacks"]
    # (which is empty in this dataset). Read the same place _alert_to_facts does.
    attacks = alert.get("finding_info", {}).get("attacks", [])
    return {
        "top7_category":       alert.get("finding_info", {}).get("title", ""),
        "severity_id":         alert.get("severity_id", 0),
        "severity":            unmapped.get("severity_display", ""),
        "alert_uid":           alert.get("finding_info", {}).get("uid", ""),
        "unraveled_stage":     unmapped.get("unraveled_stage", ""),
        "unraveled_activity":  unmapped.get("unraveled_activity", ""),
        "kill_chain_phase":    unmapped.get("kill_chain_phase", ""),
        "is_apt":              unmapped.get("is_apt", False),
        "attacker_attribution":unmapped.get("attacker_attribution", ""),
        "mitre_techniques":    [a["technique"]["uid"] for a in attacks if a.get("technique")],
        "mitre_tactics":       [a["tactic"]["uid"] for a in attacks if a.get("tactic")],
        "alert_count":         alert.get("count", 1),
    }


def _alert_to_facts(alert: dict) -> List[ObservedFact]:
    """Convert one OCSF alert into ObservedFacts, driven by RULE_TABLE."""
    src_ip, dst_ip, dst_port = _get_observables(alert)
    if not src_ip and not dst_ip:
        return []

    ctx = _enrichment_context(alert)
    evidence_str = (
        f"OCSF {ctx['alert_uid']}: {ctx['top7_category']} "
        f"({ctx['alert_count']} alerts, severity_id={ctx['severity_id']}, "
        f"stage={ctx['unraveled_stage']})"
    )

    # Host-log alerts describe activity ON one host and carry only src_endpoint
    # (the host); there is no network dst. RULE_TABLE victim_role (src/dst) encodes
    # network-flow directionality that does not apply here, so for a host-log alert
    # the victim is always the host itself (src). Without this, dst-victim rules
    # (e.g. T1078 Valid Accounts) would resolve to a None victim and be dropped.
    is_host_log = (alert.get("unmapped", {}).get("raw_data", {}).get("data_type")
                   == "host_log")

    facts: List[ObservedFact] = []
    attacks = alert.get("finding_info", {}).get("attacks", [])

    # One fact per ATT&CK technique, deduplicated by (fact_type, victim_ip).
    # victim_ip and predicate semantics are fully driven by RULE_TABLE —
    # no ground-truth labels (defender response, blocked flags) consulted.
    seen: set = set()
    for atk in attacks:
        tech_uid = atk.get("technique", {}).get("uid", "")
        rule = RULE_TABLE.get(tech_uid, DEFAULT_RULE)

        if is_host_log:
            # Host log is about the host; src_endpoint is the only endpoint.
            victim_ip = src_ip
            retargeted = False
        else:
            victim_ip = src_ip if rule["victim_role"] == "src" else dst_ip
            other_ip = dst_ip if rule["victim_role"] == "src" else src_ip

            # Maintain-access / C2 fallback: if the rule's victim endpoint is
            # EXTERNAL (e.g. T1078/T1021 "Maintain Access" beaconing internal
            # foothold -> external C2) while the other endpoint is INTERNAL, the
            # meaningful victim is the internal foothold. Re-point so it is
            # credited instead of the unmappable external IP being dropped.
            retargeted = victim_ip and not _is_internal(victim_ip) and _is_internal(other_ip)
            if retargeted:
                victim_ip = other_ip

        if not victim_ip:
            continue

        key = (rule["fact_type"], victim_ip)
        if key in seen:
            continue
        seen.add(key)

        predicate_str = (
            f"execCode({victim_ip}, {rule['permission']})"
            if rule["fact_type"] == "attack_source"
            else f"hasAppAccess({victim_ip}, {rule['permission']})"
        )

        facts.append(ObservedFact(
            fact_type=rule["fact_type"],
            subject=victim_ip,
            details={
                "node":              victim_ip,
                "port":              dst_port,
                "technique":         tech_uid,
                "rule_note":         rule["note"] + (
                    " [victim re-pointed to internal foothold; original target was "
                    "external C2]" if retargeted else ""),
                "confidence":        rule["confidence"],
                "implied_predicate": predicate_str,
                "enrichment":        ctx,
            },
            evidence=[evidence_str],
        ))

        # Dual effect for exfil/collection techniques: the SOURCE is credited
        # with execCode above, but the DESTINATION datastore is also read /
        # exfiltrated. Emit a data_access fact on the dst when it sits on a
        # known DB port, so the victim store registers (ACCESSED + data
        # possessed) instead of staying CLEAN.
        if rule.get("dst_datastore_effect") and dst_ip and dst_port in _DB_PORTS:
            ds_key = ("data_access", dst_ip)
            if ds_key not in seen:
                seen.add(ds_key)
                facts.append(ObservedFact(
                    fact_type="data_access",
                    subject=dst_ip,
                    details={
                        "data_store": dst_ip,
                        "node":       dst_ip,
                        "port":       dst_port,
                        "technique":  tech_uid,
                        "rule_note":  "dst datastore read/exfiltrated by exfil technique",
                        "confidence": rule["confidence"],
                        "enrichment": ctx,
                    },
                    evidence=[evidence_str],
                ))

    # Fallback when the alert carries no recognised techniques.
    if not facts:
        victim_ip = dst_ip or src_ip
        facts.append(ObservedFact(
            fact_type=DEFAULT_RULE["fact_type"],
            subject=victim_ip,
            details={
                "node":              victim_ip,
                "port":              dst_port,
                "technique":         None,
                "rule_note":         DEFAULT_RULE["note"],
                "confidence":        DEFAULT_RULE["confidence"],
                "implied_predicate": f"hasAppAccess({victim_ip}, {DEFAULT_RULE['permission']})",
                "enrichment":        ctx,
            },
            evidence=[evidence_str],
        ))

    # net_access — always emit when both endpoints are known.
    if src_ip and dst_ip:
        facts.append(ObservedFact(
            fact_type="net_access",
            subject=f"{src_ip}->{dst_ip}",
            details={
                "source":           src_ip,
                "target":           dst_ip,
                "port":             dst_port,
                "connection_count": ctx["alert_count"],
            },
            evidence=[evidence_str],
        ))

    return facts


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class OCSFToFacts:
    """
    Converts siem_alerts_enriched.jsonl into ObservedFact objects.

    Drop-in replacement for EvidenceExtractor in the mapping_layer pipeline:

        # Before (raw CSV logs):
        facts = EvidenceExtractor(data_dir).load_data().extract_facts()

        # After (enriched OCSF alerts):
        facts = OCSFToFacts().load().convert()

        # Remainder of pipeline unchanged:
        state = MappingLayer(diagram).build_diagram_state(facts)
        report = StepEvaluator(state).generate_report(attack_steps)
    """

    def __init__(self, jsonl_path: Path = _DEFAULT_JSONL):
        self.path = Path(jsonl_path)
        self.alerts: List[dict] = []
        self._facts: List[ObservedFact] = []

    def load(self) -> "OCSFToFacts":
        if not self.path.exists():
            raise FileNotFoundError(
                f"Enriched alerts not found: {self.path}\n"
                "Run cybernatics_top7_alerts/siem_alerts_demo.py "
                "then enrich_mitre_ioc.py first."
            )
        self.alerts = _load_jsonl(self.path)
        print(f"[OCSF] Loaded {len(self.alerts)} enriched alerts from {self.path.name}")
        return self

    def convert(self) -> List[ObservedFact]:
        """Convert all loaded alerts to ObservedFacts. Results cached in self.facts."""
        self._facts = []
        for alert in self.alerts:
            self._facts.extend(_alert_to_facts(alert))

        counts: dict = {}
        for f in self._facts:
            counts[f.fact_type] = counts.get(f.fact_type, 0) + 1
        print(f"[OCSF] Produced {len(self._facts)} ObservedFacts:")
        for ft, n in sorted(counts.items()):
            print(f"         {ft}: {n}")
        return self._facts

    @property
    def facts(self) -> List[ObservedFact]:
        return self._facts
