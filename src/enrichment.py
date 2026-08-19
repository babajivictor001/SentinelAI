"""SentinelAI security enrichment engine.

Transforms raw detections, risk information, IOCs, and MITRE
ATT&CK mappings into a structured SOC incident summary.

This module is deterministic and does not call an external AI model.
"""

from __future__ import annotations

from typing import Any, Dict, List


# ============================================================
# Severity ranking
# ============================================================

SEVERITY_PRIORITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


# ============================================================
# Get highest severity
# ============================================================

def _highest_severity(
    detections: List[Dict[str, Any]]
) -> str:

    if not detections:
        return "LOW"

    highest = "LOW"

    for detection in detections:

        severity = str(
            detection.get(
                "severity",
                "LOW"
            )
        ).upper()

        if SEVERITY_PRIORITY.get(
            severity,
            0
        ) > SEVERITY_PRIORITY.get(
            highest,
            0
        ):

            highest = severity

    return highest


# ============================================================
# Build incident title
# ============================================================

def _build_title(
    detections: List[Dict[str, Any]]
) -> str:

    if not detections:
        return "No significant security threat detected"

    attack_types = [
        detection.get(
            "attack_type",
            "Unknown threat"
        )
        for detection in detections
    ]

    if len(attack_types) == 1:

        return (
            f"Potential {attack_types[0]} detected"
        )

    return (
        f"Multiple security threats detected "
        f"({len(attack_types)} detection types)"
    )


# ============================================================
# Build incident summary
# ============================================================

def _build_summary(
    detections: List[Dict[str, Any]],
    risk: Dict[str, Any]
) -> str:

    if not detections:

        return (
            "No known attack patterns were detected "
            "in the analyzed log data."
        )

    risk_level = risk.get(
        "level",
        "UNKNOWN"
    )

    risk_score = risk.get(
        "score",
        0
    )

    attack_types = ", ".join(
        sorted(
            {
                str(
                    detection.get(
                        "attack_type",
                        "Unknown"
                    )
                )
                for detection in detections
            }
        )
    )

    return (
        f"SentinelAI detected {attack_types}. "
        f"The calculated security risk is {risk_level} "
        f"with a risk score of {risk_score}. "
        f"The findings should be reviewed by a security "
        f"analyst to determine whether the activity "
        f"represents a confirmed security incident."
    )


# ============================================================
# Collect affected IP addresses
# ============================================================

def _collect_source_ips(
    detections: List[Dict[str, Any]]
) -> List[str]:

    ips = set()

    for detection in detections:

        for ip in detection.get(
            "source_ips",
            []
        ):

            if ip:
                ips.add(ip)

    return sorted(ips)


# ============================================================
# Build recommended actions
# ============================================================

def _build_recommendations(
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any]
) -> List[str]:

    recommendations = []

    attack_types = {
        detection.get(
            "attack_type",
            ""
        )
        for detection in detections
    }

    # --------------------------------------------------------
    # Brute force
    # --------------------------------------------------------

    if "Brute Force" in attack_types:

        recommendations.extend([
            "Review authentication logs for the affected accounts.",
            "Investigate the source IP addresses responsible for repeated failures.",
            "Apply authentication rate limiting or account lockout controls.",
        ])

    # --------------------------------------------------------
    # Suspicious authentication
    # --------------------------------------------------------

    if "Suspicious Authentication Activity" in attack_types:

        recommendations.extend([
            "Review successful and failed authentication activity around the detected events.",
            "Check whether affected accounts show signs of compromise.",
        ])

    # --------------------------------------------------------
    # Port scanning
    # --------------------------------------------------------

    if "Port Scanning" in attack_types:

        recommendations.extend([
            "Investigate the scanning source and targeted systems.",
            "Review exposed network services and unnecessary open ports.",
        ])

    # --------------------------------------------------------
    # SQL injection
    # --------------------------------------------------------

    if "Possible SQL Injection" in attack_types:

        recommendations.extend([
            "Review application and web-server logs for related requests.",
            "Check database access logs for unauthorized activity.",
            "Validate that application inputs use secure parameterized queries.",
        ])

    # --------------------------------------------------------
    # Command execution
    # --------------------------------------------------------

    if "Suspicious Command Execution" in attack_types:

        recommendations.extend([
            "Investigate the host where the command was executed.",
            "Review process execution and shell activity around the event.",
        ])

    # --------------------------------------------------------
    # Malware indicators
    # --------------------------------------------------------

    if "Malware / Suspicious File Indicator" in attack_types:

        recommendations.extend([
            "Investigate the suspicious file or hash on affected systems.",
            "Check endpoint security logs for related execution activity.",
        ])

    # --------------------------------------------------------
    # IOC-specific recommendation
    # --------------------------------------------------------

    ip_addresses = iocs.get(
        "ip_addresses",
        []
    )

    if ip_addresses:

        recommendations.append(
            "Investigate the extracted IP addresses and determine whether they are associated with legitimate or malicious activity."
        )

    # --------------------------------------------------------
    # Remove duplicates while preserving order
    # --------------------------------------------------------

    unique_recommendations = []

    for recommendation in recommendations:

        if recommendation not in unique_recommendations:

            unique_recommendations.append(
                recommendation
            )

    if not unique_recommendations:

        unique_recommendations.append(
            "Continue monitoring the environment and review the analyzed events for additional suspicious activity."
        )

    return unique_recommendations


# ============================================================
# Build SOC enrichment
# ============================================================

def enrich_security_findings(
    detections: List[Dict[str, Any]],
    risk: Dict[str, Any],
    iocs: Dict[str, Any],
    mitre_attack: List[Dict[str, Any]]
) -> Dict[str, Any]:

    detections = detections or []
    risk = risk or {}
    iocs = iocs or {}
    mitre_attack = mitre_attack or []

    severity = _highest_severity(
        detections
    )

    source_ips = _collect_source_ips(
        detections
    )

    recommendations = _build_recommendations(
        detections,
        iocs
    )

    return {

        "incident_title": _build_title(
            detections
        ),

        "severity": severity,

        "risk_level": risk.get(
            "level",
            "UNKNOWN"
        ),

        "risk_score": risk.get(
            "score",
            0
        ),

        "summary": _build_summary(
            detections,
            risk
        ),

        "detection_count": len(
            detections
        ),

        "source_ips": source_ips,

        "ioc_count": (
            len(
                iocs.get(
                    "ip_addresses",
                    []
                )
            )
            + len(
                iocs.get(
                    "domains",
                    []
                )
            )
            + len(
                iocs.get(
                    "urls",
                    []
                )
            )
            + len(
                iocs.get(
                    "email_addresses",
                    []
                )
            )
            + len(
                iocs.get(
                    "file_hashes",
                    {}
                ).get(
                    "md5",
                    []
                )
            )
            + len(
                iocs.get(
                    "file_hashes",
                    {}
                ).get(
                    "sha1",
                    []
                )
            )
            + len(
                iocs.get(
                    "file_hashes",
                    {}
                ).get(
                    "sha256",
                    []
                )
            )
        ),

        "mitre_technique_count": len(
            mitre_attack
        ),

        "recommendations": recommendations,

        "status": (
            "REQUIRES_INVESTIGATION"
            if detections
            else "NO_SIGNIFICANT_THREAT"
        )

    }