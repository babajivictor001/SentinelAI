"""SentinelAI rule-based attack detection engine.

Transparent, deterministic pattern matching over parsed log lines.
No machine learning, no external threat-intelligence lookups.

Usage from src/analyzer.py:

    from src.detection_engine import detect_attacks

    detections = detect_attacks(lines, login_attempts, failed_logins)
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List


# ============================================================
# Detection thresholds
# ============================================================

BRUTE_FORCE_THRESHOLD = 5
SUSPICIOUS_AUTH_THRESHOLD = 3
PORT_SCAN_DISTINCT_PORTS = 5


# ============================================================
# Regular expressions
# ============================================================

IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

PORT_RE = re.compile(
    r"(?:port|:)\s?(\d{2,5})\b",
    re.IGNORECASE
)


# ============================================================
# SQL Injection patterns
# ============================================================

SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s*'1'\s*=\s*'1",
    r";\s*drop\s+table",
    r"information_schema",
    r"sleep\(\s*\d+\s*\)",
    r"benchmark\(",
    r"xp_cmdshell",
    r"--\s*$",
]


# ============================================================
# Suspicious command patterns
# ============================================================

COMMAND_PATTERNS = [
    r"/bin/(?:ba)?sh\s+-c",
    r"\bnc\s+-[a-z]*e\b",
    r"powershell(?:\.exe)?\s+-(?:enc|encodedcommand|nop|w\s+hidden)",
    r"\bcurl\b[^\n]*\|\s*(?:ba)?sh",
    r"\bwget\b[^\n]*\|\s*(?:ba)?sh",
    r"\bchmod\s+\+x\b",
    r"\bbase64\s+-d\b",
]


# ============================================================
# Malware / suspicious file patterns
# ============================================================

MALWARE_PATTERNS = [
    r"\b\w[\w.-]*\.(?:exe|dll|scr|bat|ps1|vbs|jar)\b",
    r"\b(?:malware|trojan|ransomware|backdoor|webshell|keylogger)\b",
    r"\b[a-fA-F0-9]{32}\b",
    r"\b[a-fA-F0-9]{64}\b",
]


# ============================================================
# Failed authentication patterns
# ============================================================

FAILED_AUTH_PATTERNS = [
    r"failed\s+(?:password|login|authentication)",
    r"authentication\s+failure",
    r"invalid\s+user",
    r"login\s+failed",
    r"unauthorized",
]


# ============================================================
# Port scanning patterns
# ============================================================

PORT_SCAN_PATTERNS = [
    r"connection\s+attempt",
    r"port\s+scan",
    r"syn\s+flood",
    r"refused\s+connect",
    r"blocked\s+connection",
]


# ============================================================
# Utility functions
# ============================================================

def _as_lines(lines: Iterable[Any]) -> List[str]:

    output: List[str] = []

    for line in lines or []:

        output.append(
            line if isinstance(line, str) else str(line)
        )

    return output


def _matches(
    text: str,
    patterns: List[str]
) -> List[str]:

    hits = []

    for pattern in patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):

            hits.append(pattern)

    return hits


def _finding(
    attack_type,
    severity,
    description,
    source_ips,
    evidence
) -> Dict[str, Any]:

    return {
        "attack_type": attack_type,
        "severity": severity,
        "description": description,
        "source_ips": sorted(set(source_ips)),
        "evidence": evidence,
    }


# ============================================================
# Brute-force detection
# ============================================================

def _brute_force(
    login_attempts: Dict[str, int]
) -> List[Dict[str, Any]]:

    offenders = {
        ip: attempts
        for ip, attempts in (login_attempts or {}).items()
        if attempts >= BRUTE_FORCE_THRESHOLD
    }

    if not offenders:
        return []

    evidence = [
        f"{attempts} failed authentication attempts from {ip}"
        for ip, attempts in sorted(offenders.items())
    ]

    return [
        _finding(
            "Brute Force",
            "HIGH",
            "Multiple failed authentication attempts detected from the same source IP.",
            list(offenders),
            evidence,
        )
    ]


# ============================================================
# Suspicious authentication detection
# ============================================================

def _suspicious_auth(
    lines: List[str],
    login_attempts: Dict[str, int]
) -> List[Dict[str, Any]]:

    evidence: List[str] = []
    ips: List[str] = []

    for line in lines:

        if _matches(
            line,
            FAILED_AUTH_PATTERNS
        ):

            evidence.append(
                line.strip()[:200]
            )

            ips.extend(
                IPV4_RE.findall(line)
            )

    below_brute_force = [
        ip
        for ip, attempts in (login_attempts or {}).items()
        if (
            SUSPICIOUS_AUTH_THRESHOLD
            <= attempts
            < BRUTE_FORCE_THRESHOLD
        )
    ]

    ips.extend(
        below_brute_force
    )

    if not evidence and not below_brute_force:
        return []

    return [
        _finding(
            "Suspicious Authentication Activity",
            "MEDIUM",
            "Repeated failed logins or unusual authentication events present in the log.",
            ips,
            evidence[:10]
            or [
                f"{ip}: {login_attempts[ip]} attempts"
                for ip in below_brute_force
            ],
        )
    ]


# ============================================================
# Port scanning detection
# ============================================================

def _port_scan(
    lines: List[str]
) -> List[Dict[str, Any]]:

    per_ip_ports: Dict[str, set] = {}
    evidence: List[str] = []

    for line in lines:

        if not _matches(
            line,
            PORT_SCAN_PATTERNS
        ):

            continue

        ports = set(
            PORT_RE.findall(line)
        )

        for ip in IPV4_RE.findall(line):

            per_ip_ports.setdefault(
                ip,
                set()
            ).update(ports)

        if ports:

            evidence.append(
                line.strip()[:200]
            )

    offenders = {
        ip: ports
        for ip, ports in per_ip_ports.items()
        if len(ports) >= PORT_SCAN_DISTINCT_PORTS
    }

    if not offenders:
        return []

    return [
        _finding(
            "Port Scanning",
            "MEDIUM",
            "Repeated connection attempts to multiple distinct ports from the same source IP.",
            list(offenders),
            [
                f"{ip} touched {len(ports)} distinct ports"
                for ip, ports in sorted(offenders.items())
            ]
            + evidence[:5],
        )
    ]


# ============================================================
# Generic pattern detection
# ============================================================

def _pattern_detection(
    lines,
    patterns,
    attack_type,
    severity,
    description
):

    evidence: List[str] = []
    ips: List[str] = []

    for line in lines:

        if _matches(
            line,
            patterns
        ):

            evidence.append(
                line.strip()[:200]
            )

            ips.extend(
                IPV4_RE.findall(line)
            )

    if not evidence:
        return []

    return [
        _finding(
            attack_type,
            severity,
            description,
            ips,
            evidence[:10]
        )
    ]


# ============================================================
# Main detection function
# ============================================================

def detect_attacks(
    lines,
    login_attempts=None,
    failed_logins=0
) -> List[Dict[str, Any]]:
    """Return structured security detections.

    Evidence is taken directly from the supplied log data.
    """

    text_lines = _as_lines(lines)

    login_attempts = login_attempts or {}

    detections: List[Dict[str, Any]] = []

    detections += _brute_force(
        login_attempts
    )

    detections += _suspicious_auth(
        text_lines,
        login_attempts
    )

    detections += _port_scan(
        text_lines
    )

    detections += _pattern_detection(
        text_lines,
        SQLI_PATTERNS,
        "Possible SQL Injection",
        "HIGH",
        "Log messages contain recognizable SQL injection indicators.",
    )

    detections += _pattern_detection(
        text_lines,
        COMMAND_PATTERNS,
        "Suspicious Command Execution",
        "HIGH",
        "Log messages contain recognizable suspicious command execution indicators.",
    )

    detections += _pattern_detection(
        text_lines,
        MALWARE_PATTERNS,
        "Malware / Suspicious File Indicator",
        "MEDIUM",
        "Log messages reference suspicious executables, malware keywords or file hashes.",
    )

    return detections