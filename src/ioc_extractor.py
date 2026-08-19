"""SentinelAI IOC extraction engine.

Extracts common Indicators of Compromise (IOCs) from security log lines.

Supported IOC types:
- IPv4 addresses
- Domains
- URLs
- Email addresses
- File hashes (MD5, SHA1, SHA256)
"""

from __future__ import annotations

import re
from typing import Dict, List


# ============================================================
# IOC patterns
# ============================================================

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


# ============================================================
# IPv4 validation
# ============================================================

def _valid_ipv4(ip: str) -> bool:

    try:

        parts = ip.split(".")

        if len(parts) != 4:
            return False

        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    except ValueError:

        return False


# ============================================================
# Extract IOCs
# ============================================================

def extract_iocs(lines) -> Dict[str, List[str]]:

    if isinstance(lines, str):

        lines = lines.splitlines()

    lines = list(lines or [])

    text = "\n".join(lines)

    # --------------------------------------------------------
    # Extract URLs first
    # --------------------------------------------------------

    urls = set(
        URL_PATTERN.findall(text)
    )

    # --------------------------------------------------------
    # Extract email addresses
    # --------------------------------------------------------

    emails = set(
        EMAIL_PATTERN.findall(text)
    )

    # --------------------------------------------------------
    # Extract IP addresses
    # --------------------------------------------------------

    ips = {
        ip
        for ip in IPV4_PATTERN.findall(text)
        if _valid_ipv4(ip)
    }

    # --------------------------------------------------------
    # Extract hashes
    # --------------------------------------------------------

    md5_hashes = set(
        MD5_PATTERN.findall(text)
    )

    sha1_hashes = set(
        SHA1_PATTERN.findall(text)
    )

    sha256_hashes = set(
        SHA256_PATTERN.findall(text)
    )

    # --------------------------------------------------------
    # Extract domains
    # --------------------------------------------------------

    domains = set(
        DOMAIN_PATTERN.findall(text)
    )

    # Remove domains that are actually part of email addresses
    for email in emails:

        domain = email.split("@")[-1]

        domains.discard(domain)

    # Remove domains that belong to URLs
    for url in urls:

        domain_match = re.search(
            r"https?://([^/:]+)",
            url,
            re.IGNORECASE
        )

        if domain_match:

            domains.discard(
                domain_match.group(1)
            )

    return {

        "ip_addresses": sorted(ips),

        "domains": sorted(domains),

        "urls": sorted(urls),

        "email_addresses": sorted(emails),

        "file_hashes": {

            "md5": sorted(md5_hashes),

            "sha1": sorted(sha1_hashes),

            "sha256": sorted(sha256_hashes)

        }

    }