"""SentinelAI AI SOC Analyst.

Provides an optional OpenAI-powered SOC assessment.

If OpenAI API access is unavailable because of quota, billing,
connection, or configuration problems, SentinelAI automatically
falls back to a local evidence-based assessment.

This means the SentinelAI API continues working even when
OpenAI is unavailable.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from openai import (
    APIConnectionError,
    APIError,
    OpenAI,
    RateLimitError,
)


# ============================================================
# Configuration
# ============================================================

MODEL = os.getenv(
    "SENTINELAI_AI_MODEL",
    "gpt-5.4-mini"
)


# ============================================================
# OpenAI Client
# ============================================================

def _get_client() -> OpenAI:
    """Create an OpenAI client using the environment API key."""

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY environment variable is not set."
        )

    return OpenAI(
        api_key=api_key
    )


# ============================================================
# Local Fallback Assessment
# ============================================================

def _local_assessment(
    analysis: Dict[str, Any],
    risk: Dict[str, Any],
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    mitre_attack: List[Dict[str, Any]],
    enrichment: Dict[str, Any],
    reason: str
) -> Dict[str, Any]:
    """
    Generate a local SOC assessment without calling OpenAI.

    This is intentionally evidence-based and does not perform
    external threat intelligence lookups.
    """

    risk_level = risk.get(
        "level",
        "UNKNOWN"
    )

    risk_score = risk.get(
        "score",
        0
    )

    failed_logins = analysis.get(
        "failed_logins",
        0
    )

    total_events = analysis.get(
        "total_events",
        0
    )

    detection_count = len(
        detections or []
    )

    source_ips = set()

    for detection in detections or []:

        for ip in detection.get(
            "source_ips",
            []
        ):

            source_ips.add(ip)

    for ip in iocs.get(
        "ip_addresses",
        []
    ):

        source_ips.add(ip)

    attack_types = []

    for detection in detections or []:

        attack_type = detection.get(
            "attack_type"
        )

        if attack_type and attack_type not in attack_types:

            attack_types.append(
                attack_type
            )

    technique_ids = []

    for item in mitre_attack or []:

        technique_id = item.get(
            "technique_id"
        )

        if (
            technique_id
            and technique_id not in technique_ids
        ):

            technique_ids.append(
                technique_id
            )

    # --------------------------------------------------------
    # Threat assessment
    # --------------------------------------------------------

    if detection_count:

        threat_assessment = (
            f"SentinelAI identified {detection_count} "
            f"security detection type(s) in {total_events} "
            f"log event(s). The calculated risk level is "
            f"{risk_level} with a score of {risk_score}. "
            f"The activity requires analyst investigation."
        )

    else:

        threat_assessment = (
            f"SentinelAI analyzed {total_events} log event(s) "
            f"and did not identify a known attack pattern. "
            f"The calculated risk level is {risk_level} "
            f"with a score of {risk_score}."
        )

    # --------------------------------------------------------
    # Key findings
    # --------------------------------------------------------

    key_findings = []

    if failed_logins:

        key_findings.append(
            f"{failed_logins} failed authentication "
            f"event(s) were detected."
        )

    if attack_types:

        key_findings.append(
            "Detected activity: "
            + ", ".join(attack_types)
            + "."
        )

    if source_ips:

        key_findings.append(
            "Relevant source IP address(es): "
            + ", ".join(sorted(source_ips))
            + "."
        )

    if not key_findings:

        key_findings.append(
            "No significant attack indicators were identified "
            "by the configured detection rules."
        )

    # --------------------------------------------------------
    # Attack interpretation
    # --------------------------------------------------------

    if attack_types:

        attack_interpretation = (
            "The detected patterns may represent malicious "
            "or unauthorized activity. The evidence should "
            "be correlated with authentication, network, "
            "endpoint, and application logs before declaring "
            "a confirmed incident."
        )

    else:

        attack_interpretation = (
            "No configured attack pattern was triggered. "
            "This does not prove that the environment is "
            "completely free of malicious activity."
        )

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    if mitre_attack:

        mitre_lines = []

        for item in mitre_attack:

            technique_id = item.get(
                "technique_id",
                "Unknown"
            )

            technique = item.get(
                "technique",
                "Unknown"
            )

            tactic = item.get(
                "tactic",
                "Unknown"
            )

            mitre_lines.append(
                f"- {technique_id} — "
                f"{technique} "
                f"({tactic})"
            )

        mitre_summary = "\n".join(
            mitre_lines
        )

    else:

        mitre_summary = (
            "No MITRE ATT&CK technique mapping was generated."
        )

    # --------------------------------------------------------
    # IOC summary
    # --------------------------------------------------------

    ioc_lines = []

    ip_addresses = iocs.get(
        "ip_addresses",
        []
    )

    domains = iocs.get(
        "domains",
        []
    )

    urls = iocs.get(
        "urls",
        []
    )

    email_addresses = iocs.get(
        "email_addresses",
        []
    )

    file_hashes = iocs.get(
        "file_hashes",
        {}
    )

    if ip_addresses:

        ioc_lines.append(
            "IP addresses: "
            + ", ".join(ip_addresses)
        )

    if domains:

        ioc_lines.append(
            "Domains: "
            + ", ".join(domains)
        )

    if urls:

        ioc_lines.append(
            "URLs: "
            + ", ".join(urls)
        )

    if email_addresses:

        ioc_lines.append(
            "Email addresses: "
            + ", ".join(email_addresses)
        )

    for hash_type in (
        "md5",
        "sha1",
        "sha256"
    ):

        hashes = file_hashes.get(
            hash_type,
            []
        )

        if hashes:

            ioc_lines.append(
                f"{hash_type.upper()} hashes: "
                + ", ".join(hashes)
            )

    if not ioc_lines:

        ioc_summary = (
            "No indicators of compromise were extracted."
        )

    else:

        ioc_summary = "\n".join(
            ioc_lines
        )

    # --------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------

    recommendations = []

    if failed_logins:

        recommendations.append(
            "Review authentication logs for the affected "
            "accounts and surrounding events."
        )

        recommendations.append(
            "Apply appropriate authentication rate limiting "
            "and account protection controls."
        )

    if source_ips:

        recommendations.append(
            "Investigate the identified source IP addresses "
            "within the organization's authorized security "
            "monitoring environment."
        )

    if attack_types:

        recommendations.append(
            "Correlate the detections with firewall, endpoint, "
            "application, and authentication telemetry."
        )

        recommendations.append(
            "Determine whether any suspicious activity resulted "
            "in successful access or system compromise."
        )

    if not recommendations:

        recommendations.append(
            "Continue monitoring the environment for anomalous "
            "activity."
        )

        recommendations.append(
            "Review detection rules periodically to improve "
            "coverage."
        )

    # --------------------------------------------------------
    # Build fallback report
    # --------------------------------------------------------

    assessment = f"""
THREAT ASSESSMENT:
{threat_assessment}

KEY FINDINGS:
{chr(10).join("- " + item for item in key_findings)}

ATTACK INTERPRETATION:
{attack_interpretation}

MITRE ATT&CK:
{mitre_summary}

IOC SUMMARY:
{ioc_summary}

RECOMMENDED ACTIONS:
{chr(10).join("- " + item for item in recommendations)}

CONFIDENCE:
MEDIUM

ANALYSIS MODE:
Local evidence-based fallback analysis.
"""

    return {
        "status": "fallback",

        "model": None,

        "provider": "SentinelAI Local Detection Engine",

        "assessment": assessment.strip(),

        "reason": reason,

        "risk_level": risk_level,

        "risk_score": risk_score,

        "detection_count": detection_count,

        "ioc_count": len(
            ip_addresses
        )
        + len(domains)
        + len(urls)
        + len(email_addresses),

        "mitre_technique_count": len(
            technique_ids
        )
    }


# ============================================================
# Build OpenAI Prompt
# ============================================================

def _build_prompt(
    analysis: Dict[str, Any],
    risk: Dict[str, Any],
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    mitre_attack: List[Dict[str, Any]],
    enrichment: Dict[str, Any]
) -> str:

    security_context = {

        "analysis": analysis,

        "risk": risk,

        "detections": detections,

        "iocs": iocs,

        "mitre_attack": mitre_attack,

        "enrichment": enrichment
    }

    return f"""
You are SentinelAI, a defensive cybersecurity SOC analyst assistant.

Analyze the supplied structured security evidence.

RULES:

1. Use ONLY the supplied evidence.
2. Do not invent threat intelligence.
3. Do not invent IP reputation.
4. Do not invent domains, malware families, users,
   vulnerabilities, or events.
5. Clearly distinguish evidence from interpretation.
6. Do not claim an attack is confirmed unless the evidence
   supports that conclusion.
7. Provide practical defensive recommendations.
8. Keep the assessment concise and suitable for a SOC dashboard.
9. This is defensive cybersecurity analysis.

SECURITY EVIDENCE:

{json.dumps(
    security_context,
    indent=2
)}

Return exactly these sections:

THREAT ASSESSMENT:

KEY FINDINGS:

ATTACK INTERPRETATION:

MITRE ATT&CK:

IOC SUMMARY:

RECOMMENDED ACTIONS:

CONFIDENCE:
Choose LOW, MEDIUM, or HIGH.
"""


# ============================================================
# OpenAI Assessment
# ============================================================

def _openai_assessment(
    analysis: Dict[str, Any],
    risk: Dict[str, Any],
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    mitre_attack: List[Dict[str, Any]],
    enrichment: Dict[str, Any]
) -> Dict[str, Any]:

    client = _get_client()

    prompt = _build_prompt(
        analysis=analysis,
        risk=risk,
        detections=detections,
        iocs=iocs,
        mitre_attack=mitre_attack,
        enrichment=enrichment
    )

    response = client.responses.create(

        model=MODEL,

        instructions=(
            "You are a professional defensive "
            "cybersecurity SOC analyst assistant. "
            "Remain evidence-based and concise."
        ),

        input=prompt
    )

    assessment = response.output_text.strip()

    return {

        "status": "success",

        "model": MODEL,

        "provider": "OpenAI",

        "assessment": assessment
    }


# ============================================================
# Public AI Assessment Function
# ============================================================

def generate_ai_assessment(
    analysis: Dict[str, Any],
    risk: Dict[str, Any],
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    mitre_attack: List[Dict[str, Any]],
    enrichment: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate an AI SOC assessment.

    OpenAI is attempted first.

    If OpenAI is unavailable because of missing configuration,
    quota, API errors, or connection problems, SentinelAI
    automatically performs a local evidence-based assessment.
    """

    try:

        return _openai_assessment(
            analysis=analysis,
            risk=risk,
            detections=detections,
            iocs=iocs,
            mitre_attack=mitre_attack,
            enrichment=enrichment
        )

    except RateLimitError as exc:

        return _local_assessment(
            analysis,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment,
            "OpenAI API quota is currently unavailable."
        )

    except APIConnectionError:

        return _local_assessment(
            analysis,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment,
            "Unable to connect to the OpenAI API."
        )

    except APIError as exc:

        return _local_assessment(
            analysis,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment,
            f"OpenAI API error: {type(exc).__name__}."
        )

    except RuntimeError as exc:

        return _local_assessment(
            analysis,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment,
            str(exc)
        )

    except Exception as exc:

        return _local_assessment(
            analysis,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment,
            f"AI analysis unavailable: {type(exc).__name__}."
        )