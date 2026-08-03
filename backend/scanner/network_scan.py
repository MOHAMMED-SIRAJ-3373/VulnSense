"""
VulnSense — Network Scanner Module
===================================
Performs a lightweight, controlled port scan and service fingerprint on a
target host within the lab environment. Uses python-nmap as a wrapper around
nmap, supplemented by pure-Python socket probes for environments without nmap.

Scope (per proposal): network services, basic web access, simple config checks.
This is NOT a full vulnerability scanner — it identifies open ports, service
banners, and a small set of known-risky conditions, then produces structured
findings suitable for the ML pipeline.

Design decisions
----------------
- Falls back to a socket-based scanner if nmap is not installed.
- Scans only the ports and service categories in scope for a student lab.
- Never scans external / production networks. Target must be in a private range.
- Converts raw scan output into the feature schema required by the ML model.
"""

import socket
import ipaddress
import time
import json
from datetime import datetime

# Optional nmap import — graceful fallback
try:
    import nmap
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False

# ── Scope constants ───────────────────────────────────────────────────────────

LAB_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 143, 161,
    389, 443, 445, 1433, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 27017
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpc",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http", 8443: "https", 8888: "http", 27017: "mongodb"
}

HIGH_RISK_SERVICES = {"telnet", "rdp", "smb", "vnc", "ftp", "redis", "mongodb", "snmp"}
ENCRYPTED_SERVICES = {"https", "ssh", "imaps", "smtps"}

VULN_TYPE_RULES = {
    "telnet":   "unencrypted_protocol",
    "ftp":      "unencrypted_protocol",
    "http":     "unencrypted_protocol",
    "rdp":      "open_port_exposure",
    "smb":      "open_port_exposure",
    "vnc":      "open_port_exposure",
    "redis":    "anonymous_access",
    "mongodb":  "anonymous_access",
    "snmp":     "information_disclosure",
    "ssh":      "open_port_exposure",
    "smtp":     "information_disclosure",
    "dns":      "open_port_exposure",
    "mysql":    "open_port_exposure",
    "postgresql": "open_port_exposure",
    "mssql":    "open_port_exposure",
    "ldap":     "information_disclosure",
    "https":    "open_port_exposure",
    "pop3":     "unencrypted_protocol",
    "imap":     "unencrypted_protocol",
    "rpc":      "open_port_exposure",
}

# ── Validation ────────────────────────────────────────────────────────────────

def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False  # hostname — allow with warning


def _validate_target(host: str):
    """Raise ValueError if the host is not in a private range."""
    if not _is_private_ip(host):
        raise ValueError(
            f"VulnSense only scans lab/private IP addresses. "
            f"'{host}' appears to be a public or unroutable address. "
            f"Please use a VM on a private subnet (e.g. 192.168.x.x, 10.x.x.x)."
        )


# ── Socket-based port probe ───────────────────────────────────────────────────

def _socket_probe(host: str, port: int, timeout: float = 1.5) -> dict | None:
    """Probe a single port. Returns a partial finding dict or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        banner = ""
        if result == 0:
            try:
                s.send(b"\r\n")
                banner = s.recv(512).decode("utf-8", errors="replace").strip()
            except Exception:
                pass
        s.close()
        if result == 0:
            return {"port": port, "banner": banner[:120]}
        return None
    except Exception:
        return None


# ── nmap-based port scan ──────────────────────────────────────────────────────

def _nmap_scan(host: str, ports: list) -> list:
    """Return list of dicts: {port, service, version, state}."""
    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in ports)
    try:
        nm.scan(host, port_str, arguments="-sV --version-intensity 3 -T4 --open")
    except Exception as e:
        raise RuntimeError(f"nmap scan failed: {e}")

    results = []
    if host not in nm.all_hosts():
        return results

    for proto in nm[host].all_protocols():
        for port in nm[host][proto].keys():
            info = nm[host][proto][port]
            if info["state"] == "open":
                results.append({
                    "port":    port,
                    "service": info.get("name", SERVICE_MAP.get(port, "unknown")),
                    "version": info.get("version", ""),
                    "product": info.get("product", ""),
                    "state":   "open",
                })
    return results


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_host(host: str, scan_id: str = None) -> dict:
    """
    Perform a limited network scan on `host`.
    Returns a structured dict with findings ready for the ML pipeline.
    """
    _validate_target(host)

    scan_id = scan_id or f"scan_{int(time.time())}"
    started_at = datetime.utcnow().isoformat()
    open_ports = []

    if NMAP_AVAILABLE:
        try:
            open_ports = _nmap_scan(host, LAB_PORTS)
            method = "nmap"
        except Exception as e:
            # Fallback to socket probe
            open_ports = []
            method = "socket_fallback"
    else:
        method = "socket_fallback"

    if method == "socket_fallback":
        for port in LAB_PORTS:
            result = _socket_probe(host, port)
            if result:
                service = SERVICE_MAP.get(port, "unknown")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "version": "",
                    "product": "",
                    "state": "open",
                    "banner": result.get("banner", ""),
                })

    findings = []
    for entry in open_ports:
        port    = entry["port"]
        service = entry.get("service") or SERVICE_MAP.get(port, "unknown")
        service = service.lower().split("/")[0]  # normalise e.g. "http-proxy" → "http"

        protocol = "udp" if service in ("dns", "snmp") else "tcp"
        encrypted = 1 if service in ENCRYPTED_SERVICES else 0
        is_high_risk = 1 if service in HIGH_RISK_SERVICES else 0
        vuln_type = VULN_TYPE_RULES.get(service, "open_port_exposure")

        # Heuristic: default-creds risk if high-risk service with no version info
        uses_default_creds = 1 if (
            is_high_risk and not entry.get("version")
            and service in ("telnet", "rdp", "vnc", "ftp", "redis", "mongodb")
        ) else 0

        # Port exposure category
        if port < 1024:
            port_cat = "well_known"
        elif port < 49152:
            port_cat = "registered"
        else:
            port_cat = "dynamic"

        # Infer attack vector: network-exposed ports → network; local-only → local
        attack_vector = "network"  # all lab VM ports are network-reachable
        # Complexity / privs: heuristic based on service type
        if service in ("ssh", "mysql", "postgresql", "mssql", "ldap"):
            attack_complexity = "high"
            privileges_required = "low"
            user_interaction = "none"
        elif service in ("telnet", "ftp", "http", "rdp", "vnc"):
            attack_complexity = "low"
            privileges_required = "none"
            user_interaction = "none"
        elif service in ("smb", "rdp", "rpc"):
            attack_complexity = "low"
            privileges_required = "none"
            user_interaction = "required"
        else:
            attack_complexity = "low"
            privileges_required = "none"
            user_interaction = "none"

        # Impact: unencrypted + data services → high conf impact
        conf = "high" if not encrypted and service in ("ftp", "telnet", "http", "pop3", "imap", "smtp") else "low"
        intg = "high" if service in ("smb", "rdp", "vnc", "telnet", "ftp") else "low"
        avail = "low"

        scope = "unchanged"

        finding = {
            # Display fields
            "finding_id":   f"{scan_id}-{port}",
            "host":         host,
            "port":         port,
            "protocol":     protocol,
            "service":      service,
            "vuln_type":    vuln_type,
            "banner":       entry.get("banner", entry.get("product", "")),
            # ML features
            "attack_vector":          attack_vector,
            "attack_complexity":      attack_complexity,
            "privileges_required":    privileges_required,
            "user_interaction":       user_interaction,
            "scope":                  scope,
            "conf_impact":            conf,
            "integ_impact":           intg,
            "avail_impact":           avail,
            "encrypted":              encrypted,
            "uses_default_creds":     uses_default_creds,
            "is_high_risk_service":   is_high_risk,
            "port_exposure_category": port_cat,
        }
        findings.append(finding)

    return {
        "scan_id":    scan_id,
        "host":       host,
        "started_at": started_at,
        "method":     method,
        "total_open": len(findings),
        "findings":   findings,
    }
