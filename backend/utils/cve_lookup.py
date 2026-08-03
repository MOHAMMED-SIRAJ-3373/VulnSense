"""
VulnSense — CVE Lookup via NVD API v2.0
========================================
Looks up related CVEs for a finding based on its service and vuln type.
Uses a local keyword map so the NVD query is precise and fast.
Results are cached in-process to avoid hammering the API during a scan.
"""

import requests
import time
from functools import lru_cache

NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS  = {"User-Agent": "VulnSense/1.0 (CST3590 FYP; lab use only)"}
TIMEOUT  = 6   # seconds per request
MAX_CVES = 3   # returned per finding

# Keyword map: (service, vuln_type) → NVD search keywords
KEYWORD_MAP = {
    ("telnet",     "unencrypted_protocol"):  "telnet plaintext credentials",
    ("ftp",        "unencrypted_protocol"):  "ftp anonymous plaintext",
    ("ftp",        "anonymous_access"):      "ftp anonymous login",
    ("ssh",        "open_port_exposure"):    "openssh vulnerability",
    ("ssh",        "misconfiguration"):      "ssh weak cipher brute force",
    ("http",       "unencrypted_protocol"):  "http cleartext sensitive data",
    ("http",       "misconfiguration"):      "apache http missing security headers",
    ("https",      "ssl_weak_cipher"):       "ssl tls weak cipher",
    ("smb",        "open_port_exposure"):    "smb eternalblue ms17-010",
    ("rdp",        "open_port_exposure"):    "rdp remote desktop bluekeep",
    ("vnc",        "open_port_exposure"):    "vnc authentication bypass",
    ("redis",      "anonymous_access"):      "redis unauthenticated remote code execution",
    ("mongodb",    "anonymous_access"):      "mongodb no authentication exposed",
    ("mysql",      "open_port_exposure"):    "mysql remote access weak credentials",
    ("postgresql", "open_port_exposure"):    "postgresql remote access",
    ("snmp",       "information_disclosure"):"snmp community string information disclosure",
    ("ldap",       "information_disclosure"):"ldap anonymous bind",
    ("smtp",       "information_disclosure"):"smtp open relay banner",
    ("rpc",        "open_port_exposure"):    "rpc portmapper information disclosure",
    ("nfs",        "open_port_exposure"):    "nfs no authentication export",
}

DEFAULT_KEYWORDS = {
    "unencrypted_protocol":  "cleartext protocol credentials",
    "anonymous_access":      "anonymous unauthenticated access",
    "misconfiguration":      "security misconfiguration",
    "information_disclosure":"information disclosure banner",
    "open_port_exposure":    "exposed service network access",
    "ssl_weak_cipher":       "ssl weak cipher deprecated protocol",
    "default_credentials":   "default credentials authentication bypass",
}

_cache: dict = {}


def lookup_cves(service: str, vuln_type: str) -> list:
    """
    Return a list of up to MAX_CVES related CVE dicts:
    [{"id": "CVE-2021-xxxx", "description": "...", "severity": "HIGH", "score": 9.8}]
    Returns [] on error or timeout — never crashes the scan.
    """
    svc  = (service or "").lower()
    vt   = (vuln_type or "").lower()
    key  = f"{svc}:{vt}"

    if key in _cache:
        return _cache[key]

    keywords = KEYWORD_MAP.get((svc, vt)) or DEFAULT_KEYWORDS.get(vt) or svc
    if not keywords:
        return []

    try:
        resp = requests.get(
            NVD_URL,
            params={"keywordSearch": keywords, "resultsPerPage": 5, "startIndex": 0},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            _cache[key] = []
            return []

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        results = []

        for item in vulns[:MAX_CVES]:
            cve  = item.get("cve", {})
            cid  = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description.")
            desc = desc[:180] + "…" if len(desc) > 180 else desc

            metrics = cve.get("metrics", {})
            severity, score = "N/A", None
            for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if ver in metrics and metrics[ver]:
                    m = metrics[ver][0].get("cvssData", {})
                    severity = m.get("baseSeverity", "N/A")
                    score    = m.get("baseScore", None)
                    break

            results.append({
                "id":          cid,
                "description": desc,
                "severity":    severity,
                "score":       score,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cid}",
            })

        _cache[key] = results
        time.sleep(0.4)   # NVD rate limit: 5 req/30s without API key
        return results

    except Exception:
        _cache[key] = []
        return []
