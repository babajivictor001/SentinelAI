"""SentinelAI MITRE ATT&CK mapping engine.

Maps detected security events to relevant MITRE ATT&CK
techniques using transparent rule-based mappings.
"""

from __future__ import annotations

from typing import Any, Dict, List


# ============================================================
# MITRE ATT&CK technique mappings
# ============================================================

MITRE_MAPPINGS = {

    "Brute Force": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute-force techniques "
            "to gain access to accounts by repeatedly "
            "attempting authentication."
        )
    },

    "Suspicious Authentication Activity": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Initial Access",
        "description": (
            "Suspicious authentication activity may indicate "
            "attempts to use valid or compromised accounts."
        )
    },

    "Port Scanning": {
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "Adversaries may scan systems to identify "
            "available network services and attack surfaces."
        )
    },

    "Possible SQL Injection": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "SQL injection indicators may represent attempts "
            "to exploit a vulnerable public-facing application."
        )
    },

    "Suspicious Command Execution": {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Suspicious command execution may indicate an "
            "attempt to execute commands through a shell "
            "or scripting interpreter."
        )
    },

    "Malware / Suspicious File Indicator": {
        "technique_id": "T1204",
        "technique": "User Execution",
        "tactic": "Execution",
        "description": (
            "Suspicious files or malware indicators may be "
            "associated with malicious payload execution."
        )
    }
}


# ============================================================
# Map a single detection
# ============================================================

def map_detection_to_mitre(
    detection: Dict[str, Any]
) -> Dict[str, Any]:

    attack_type = detection.get(
        "attack_type",
        "Unknown"
    )

    mapping = MITRE_MAPPINGS.get(
        attack_type
    )

    if not mapping:

        return {
            "attack_type": attack_type,
            "technique_id": "UNKNOWN",
            "technique": "Unknown",
            "tactic": "Unknown",
            "description": (
                "No MITRE ATT&CK mapping is currently "
                "available for this detection."
            )
        }

    return {

        "attack_type": attack_type,

        "technique_id": mapping[
            "technique_id"
        ],

        "technique": mapping[
            "technique"
        ],

        "tactic": mapping[
            "tactic"
        ],

        "description": mapping[
            "description"
        ]

    }


# ============================================================
# Map all detections
# ============================================================

def map_detections_to_mitre(
    detections: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    mappings = []

    for detection in detections or []:

        mappings.append(
            map_detection_to_mitre(
                detection
            )
        )

    return mappings