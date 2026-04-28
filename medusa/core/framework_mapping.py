#!/usr/bin/env python3
"""
Framework mapping engine.

This module enriches a normalized MEDUSA finding with structured references to
MITRE and compliance frameworks. It is intentionally conservative:
- Prefer explicit rule/scanner metadata (owasp_llm/category/mitre_atlas/cwe)
- Use lightweight heuristics only when metadata is missing
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ComplianceRef:
    framework: str
    control_id: str
    title: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"framework": self.framework, "control_id": self.control_id}
        if self.title:
            d["title"] = self.title
        if self.url:
            d["url"] = self.url
        return d


@dataclass(frozen=True)
class MitreAttackRef:
    technique_id: str
    technique_name: Optional[str] = None
    tactic_ids: Optional[List[str]] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"technique_id": self.technique_id}
        if self.technique_name:
            d["technique_name"] = self.technique_name
        if self.tactic_ids:
            d["tactic_ids"] = self.tactic_ids
        if self.url:
            d["url"] = self.url
        return d


def _norm_str(v: Any) -> str:
    return str(v).strip()


def _uniq_dicts(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[Tuple[Tuple[str, str], ...]] = set()
    out: List[Dict[str, Any]] = []
    for d in items:
        key = tuple(sorted((k, _norm_str(v)) for k, v in d.items() if v is not None))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _extract_text(finding: Dict[str, Any]) -> str:
    issue = finding.get("issue", "") or ""
    code = finding.get("code", "") or ""
    category = finding.get("category", "") or ""
    scanner = finding.get("scanner", "") or ""
    return f"{issue} {code} {category} {scanner}".lower()


def _mitre_attack_url(technique_or_tactic_id: str) -> Optional[str]:
    """
    Build a canonical `https://attack.mitre.org/` URL for an ATT&CK ID.

    Supports:
    - Techniques: Txxxx (e.g., T1566) -> /techniques/T1566/
    - Sub-techniques: Txxxx.yyy (e.g., T1566.001) -> /techniques/T1566/001/
    - Tactics: TAxxxx (e.g., TA0010) -> /tactics/TA0010/
    """
    if not technique_or_tactic_id:
        return None
    raw = _norm_str(technique_or_tactic_id).upper()
    if raw.startswith("TA") and raw[2:].isdigit():
        return f"https://attack.mitre.org/tactics/{raw}/"
    if raw.startswith("T"):
        # Technique or sub-technique
        parts = raw.split(".", 1)
        base = parts[0]
        if len(parts) == 1:
            if base[1:].isdigit():
                return f"https://attack.mitre.org/techniques/{base}/"
            return None
        sub = parts[1]
        # ATT&CK sub-techniques are typically 3 digits.
        sub_digits = "".join(ch for ch in sub if ch.isdigit())
        if base[1:].isdigit() and sub_digits:
            sub_digits = sub_digits.zfill(3)
            return f"https://attack.mitre.org/techniques/{base}/{sub_digits}/"
    return None


def _split_csv_ids(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        parts: List[str] = []
        for v in value:
            parts.extend(_split_csv_ids(v))
        return parts
    s = _norm_str(value)
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


def _mitre_atlas_url(atlas_id: str) -> Optional[str]:
    """
    Build a canonical `https://atlas.mitre.org/` URL for an ATLAS technique ID.

    Common ID format: `AML.T0051` (sometimes with suffixes like `AML.T0051.001`).
    Canonical pattern: https://atlas.mitre.org/techniques/<ID>/
    """
    if not atlas_id:
        return None
    raw = _norm_str(atlas_id)
    up = raw.upper()

    # Tactics
    if up.startswith("AML.TA"):
        return f"https://atlas.mitre.org/tactics/{raw}/"
    # Techniques / sub-techniques
    if up.startswith("AML.T"):
        return f"https://atlas.mitre.org/techniques/{raw}/"
    # Mitigations
    if up.startswith("AML.M"):
        return f"https://atlas.mitre.org/mitigations/{raw}/"
    # Case studies
    if up.startswith("AML.CS"):
        return f"https://atlas.mitre.org/studies/{raw}/"

    return None
# Curated, conservative mapping from OWASP LLM Top 10 (2025 IDs)
# to (a) likely compliance control families, (b) a handful of ATT&CK techniques.
#
# This is not a strict equivalence. It is used to provide helpful crosswalk
# for governance workflows and should be treated as "related controls".
_OWASP_LLM_TO_COMPLIANCE: Dict[str, List[ComplianceRef]] = {
    "LLM01:2025": [
        ComplianceRef("NIST_800-53r5", "SI-10", "Information Input Validation"),
        ComplianceRef("NIST_800-53r5", "SA-11", "Developer Testing and Evaluation"),
        ComplianceRef("NIST_AI_RMF_1.0", "MAP-2.3", "Context documentation"),
        ComplianceRef("NIST_AI_RMF_1.0", "MEASURE-2.4", "Model monitoring and evaluation"),
        ComplianceRef("ISO_27001:2022", "A.8.9", "Configuration management"),
        ComplianceRef("SOC2", "CC7.2", "Detect anomalous activity"),
        ComplianceRef("CISv8", "8.2", "Software Vulnerability Remediation"),
    ],
    "LLM02:2025": [
        ComplianceRef("NIST_800-53r5", "AC-3", "Access Enforcement"),
        ComplianceRef("NIST_800-53r5", "AC-6", "Least Privilege"),
        ComplianceRef("NIST_AI_RMF_1.0", "GOV-3.1", "Roles, responsibilities, and accountability"),
        ComplianceRef("ISO_27001:2022", "A.5.15", "Access control"),
        ComplianceRef("SOC2", "CC6.1", "Logical access security"),
        ComplianceRef("CISv8", "6.3", "Access Control Management"),
    ],
    "LLM03:2025": [
        ComplianceRef("NIST_800-53r5", "SC-7", "Boundary Protection"),
        ComplianceRef("NIST_800-53r5", "SI-4", "System Monitoring"),
        ComplianceRef("NIST_AI_RMF_1.0", "MANAGE-2.2", "Incident response and recovery"),
        ComplianceRef("ISO_27001:2022", "A.8.16", "Monitoring activities"),
        ComplianceRef("SOC2", "CC7.1", "System monitoring"),
        ComplianceRef("CISv8", "13.1", "Network Monitoring and Defense"),
    ],
    "LLM04:2025": [
        ComplianceRef("NIST_800-53r5", "SC-8", "Transmission Confidentiality and Integrity"),
        ComplianceRef("NIST_800-53r5", "SC-23", "Session Authenticity"),
        ComplianceRef("NIST_AI_RMF_1.0", "MAP-3.3", "System interaction and integration"),
        ComplianceRef("ISO_27001:2022", "A.8.20", "Network security"),
        ComplianceRef("SOC2", "CC6.7", "Transmission and disposal"),
        ComplianceRef("CISv8", "12.4", "Network Infrastructure Management"),
    ],
    "LLM05:2025": [
        ComplianceRef("NIST_800-53r5", "SA-3", "System Development Life Cycle"),
        ComplianceRef("NIST_800-53r5", "CM-2", "Baseline Configuration"),
        ComplianceRef("NIST_AI_RMF_1.0", "GOV-2.2", "Policies, processes, and procedures"),
        ComplianceRef("ISO_27001:2022", "A.8.9", "Configuration management"),
        ComplianceRef("SOC2", "CC8.1", "Change management"),
        ComplianceRef("CISv8", "4.1", "Establish and Maintain a Secure Configuration Process"),
    ],
    "LLM06:2025": [
        ComplianceRef("NIST_800-53r5", "SC-28", "Protection of Information at Rest"),
        ComplianceRef("NIST_800-53r5", "SC-13", "Cryptographic Protection"),
        ComplianceRef("NIST_AI_RMF_1.0", "MAP-5.1", "Data governance and management"),
        ComplianceRef("ISO_27001:2022", "A.8.24", "Use of cryptography"),
        ComplianceRef("SOC2", "CC6.6", "Encryption and key management"),
        ComplianceRef("PCI_DSS_4.0", "3.5", "Protect cryptographic keys"),
    ],
    "LLM07:2025": [
        ComplianceRef("NIST_800-53r5", "AU-2", "Event Logging"),
        ComplianceRef("NIST_800-53r5", "AU-12", "Audit Record Generation"),
        ComplianceRef("NIST_AI_RMF_1.0", "MEASURE-4.2", "Monitoring for performance and risks"),
        ComplianceRef("ISO_27001:2022", "A.8.15", "Logging"),
        ComplianceRef("SOC2", "CC7.2", "Detect and respond"),
        ComplianceRef("CISv8", "8.8", "Collect Audit Logs"),
    ],
    "LLM08:2025": [
        ComplianceRef("NIST_800-53r5", "PL-2", "System Security and Privacy Plans"),
        ComplianceRef("NIST_800-53r5", "RA-5", "Vulnerability Monitoring and Scanning"),
        ComplianceRef("NIST_AI_RMF_1.0", "GOV-1.1", "Risk management strategy"),
        ComplianceRef("ISO_27001:2022", "A.5.1", "Policies for information security"),
        ComplianceRef("SOC2", "CC3.2", "Risk identification and assessment"),
        ComplianceRef("CISv8", "7.1", "Establish and Maintain a Vulnerability Management Process"),
    ],
    "LLM09:2025": [
        ComplianceRef("NIST_800-53r5", "SA-4", "Acquisition Process"),
        ComplianceRef("NIST_800-53r5", "SA-11", "Developer Testing and Evaluation"),
        ComplianceRef("NIST_AI_RMF_1.0", "MEASURE-3.3", "Robustness and reliability evaluation"),
        ComplianceRef("ISO_27001:2022", "A.8.2", "Information security in project management"),
        ComplianceRef("SOC2", "CC7.3", "Vulnerability identification"),
        ComplianceRef("CISv8", "16.11", "Application Security Testing"),
    ],
    "LLM10:2025": [
        ComplianceRef("NIST_800-53r5", "SA-12", "Supply Chain Protection"),
        ComplianceRef("NIST_800-53r5", "SR-3", "Supply Chain Controls and Processes"),
        ComplianceRef("NIST_AI_RMF_1.0", "GOV-2.3", "Third-party risk management"),
        ComplianceRef("ISO_27001:2022", "A.5.21", "Managing ICT supply chain risk"),
        ComplianceRef("SOC2", "CC1.2", "Risk assessment"),
        ComplianceRef("CISv8", "15.1", "Service Provider Management"),
    ],
}

_OWASP_LLM_TO_MITRE_ATTACK: Dict[str, List[MitreAttackRef]] = {
    # Prompt injection / instruction hijacking is closest to social engineering style influence
    # and use of user execution, but there is no perfect ATT&CK equivalent. We keep this minimal.
    "LLM01:2025": [
        MitreAttackRef("T1204", "User Execution", url="https://attack.mitre.org/techniques/T1204/"),
        MitreAttackRef("T1566", "Phishing", url="https://attack.mitre.org/techniques/T1566/"),
    ],
    # Excessive agency / over-privileged tools aligns with abusing valid accounts/permissions.
    "LLM02:2025": [
        MitreAttackRef("T1078", "Valid Accounts", url="https://attack.mitre.org/techniques/T1078/"),
    ],
    # Data exfiltration style issues (if categorized) can map to Exfiltration.
    "LLM03:2025": [
        MitreAttackRef("T1041", "Exfiltration Over C2 Channel", url="https://attack.mitre.org/techniques/T1041/"),
        MitreAttackRef("T1020", "Automated Exfiltration", url="https://attack.mitre.org/techniques/T1020/"),
    ],
    "LLM04:2025": [
        MitreAttackRef("T1557", "Adversary-in-the-Middle", url="https://attack.mitre.org/techniques/T1557/"),
        MitreAttackRef("T1040", "Network Sniffing", url="https://attack.mitre.org/techniques/T1040/"),
    ],
    "LLM05:2025": [
        MitreAttackRef("T1649", "Steal or Forge Authentication Certificates", url="https://attack.mitre.org/techniques/T1649/"),
    ],
    "LLM06:2025": [
        MitreAttackRef("T1552", "Unsecured Credentials", url="https://attack.mitre.org/techniques/T1552/"),
        MitreAttackRef("T1005", "Data from Local System", url="https://attack.mitre.org/techniques/T1005/"),
    ],
    "LLM07:2025": [
        MitreAttackRef("T1562", "Impair Defenses", url="https://attack.mitre.org/techniques/T1562/"),
        MitreAttackRef("T1070", "Indicator Removal", url="https://attack.mitre.org/techniques/T1070/"),
    ],
    "LLM08:2025": [
        MitreAttackRef("T1592", "Gather Victim Host Information", url="https://attack.mitre.org/techniques/T1592/"),
    ],
    "LLM09:2025": [
        MitreAttackRef("T1601", "Modify System Image", url="https://attack.mitre.org/techniques/T1601/"),
    ],
    "LLM10:2025": [
        MitreAttackRef("T1195", "Supply Chain Compromise", url="https://attack.mitre.org/techniques/T1195/"),
    ],
}


def map_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a normalized finding to framework references.

    Expected finding fields (best-effort):
    - cwe: int|str
    - owasp_llm: str
    - category: str
    - issue: str
    - code: str
    - metadata: dict (optional)
    """
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    existing_mappings = finding.get("mappings") if isinstance(finding.get("mappings"), dict) else {}

    cwe = finding.get("cwe") or meta.get("cwe")
    owasp_llm = (
        finding.get("owasp_llm")
        or existing_mappings.get("owasp_llm")
        or meta.get("owasp_llm")
        or meta.get("owasp")
    )
    mitre_atlas = finding.get("mitre_atlas") or meta.get("mitre_atlas")

    # Allow future explicit overrides from scanners/rules.
    explicit_attack = meta.get("mitre_attack")
    mitre_attack: List[Dict[str, Any]] = []
    existing_attack = existing_mappings.get("mitre_attack")
    if isinstance(existing_attack, list):
        for item in existing_attack:
            if isinstance(item, dict) and item.get("technique_id"):
                mitre_attack.append(item)
    if isinstance(explicit_attack, list):
        for item in explicit_attack:
            if isinstance(item, dict) and item.get("technique_id"):
                mitre_attack.append(item)

    compliance: List[Dict[str, Any]] = []
    existing_compliance = existing_mappings.get("compliance")
    if isinstance(existing_compliance, list):
        for item in existing_compliance:
            if isinstance(item, dict) and item.get("framework") and item.get("control_id"):
                compliance.append(item)
    inferred_owasp: Optional[str] = None

    if owasp_llm:
        owasp_llm = _norm_str(owasp_llm)
        for ref in _OWASP_LLM_TO_COMPLIANCE.get(owasp_llm, []):
            compliance.append(ref.to_dict())
        for ref in _OWASP_LLM_TO_MITRE_ATTACK.get(owasp_llm, []):
            mitre_attack.append(ref.to_dict())

    # Heuristic fallback: infer OWASP bucket when rule metadata is missing.
    text = _extract_text(finding)
    if not owasp_llm:
        inferred: Optional[str] = None
        if any(k in text for k in ("prompt injection", "indirect prompt injection", "jailbreak", "instruction hijack")):
            inferred = "LLM01:2025"
        elif any(k in text for k in ("over-privileged", "excessive agency", "tool access", "least privilege")):
            inferred = "LLM02:2025"
        elif any(k in text for k in ("exfil", "data exfiltration", "leak", "secrets", "credential")):
            inferred = "LLM03:2025"
        elif any(k in text for k in ("ssrf", "web request", "fetch", "http request", "callback url")):
            inferred = "LLM04:2025"
        elif any(k in text for k in ("misconfig", "unsafe default", "debug mode", "insecure config")):
            inferred = "LLM05:2025"
        elif any(k in text for k in ("pii", "personal data", "privacy", "gdpr")):
            inferred = "LLM06:2025"
        elif any(k in text for k in ("logging", "audit", "monitor", "telemetry")):
            inferred = "LLM07:2025"
        elif any(k in text for k in ("risk", "threat model", "governance", "policy")):
            inferred = "LLM08:2025"
        elif any(k in text for k in ("eval", "exec", "rce", "code execution", "shell")):
            inferred = "LLM09:2025"
        elif any(k in text for k in ("supply chain", "repo poisoning", "dependency", "typosquat", "slopsquat")):
            inferred = "LLM10:2025"

        if inferred:
            inferred_owasp = inferred
            for ref in _OWASP_LLM_TO_COMPLIANCE.get(inferred, []):
                compliance.append(ref.to_dict())
            for ref in _OWASP_LLM_TO_MITRE_ATTACK.get(inferred, []):
                mitre_attack.append(ref.to_dict())

    mappings: Dict[str, Any] = {
        "cwe": cwe,
        "owasp_llm": owasp_llm or inferred_owasp,
        "mitre_atlas": mitre_atlas,
        "mitre_attack": _uniq_dicts(mitre_attack),
        "compliance": _uniq_dicts(compliance),
    }

    # Ensure all emitted MITRE ATT&CK refs have canonical URLs.
    ma = mappings.get("mitre_attack")
    if isinstance(ma, list):
        for ref in ma:
            if not isinstance(ref, dict):
                continue
            tid = ref.get("technique_id")
            if tid and not ref.get("url"):
                url = _mitre_attack_url(str(tid))
                if url:
                    ref["url"] = url

    atlas_ids = _split_csv_ids(mitre_atlas)
    if atlas_ids:
        atlas_refs: List[Dict[str, Any]] = []
        for aid in atlas_ids:
            url = _mitre_atlas_url(aid)
            atlas_refs.append({"technique_id": aid, "url": url} if url else {"technique_id": aid})
        mappings["mitre_atlas_refs"] = _uniq_dicts(atlas_refs)

    # Drop empty fields to keep reports clean.
    return {k: v for k, v in mappings.items() if v not in (None, "", [], {})}

