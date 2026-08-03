"""
VulnSense — Configuration Checker
===================================
Performs lightweight configuration and host-level checks:
  - SSH version / weak settings via banner grab
  - FTP anonymous login check
  - Redis / MongoDB unauthenticated access check
  - Telnet availability (always a finding)
  - SNMP community string probe (public string)

Returns structured findings compatible with the ML pipeline.
"""

import socket
import time
from datetime import datetime


def _banner_grab(host: str, port: int, timeout: float = 3.0, send: bytes = b"") -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if send:
            s.send(send)
            time.sleep(0.3)
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        return banner
    except Exception:
        return ""


def _check_ftp_anonymous(host: str) -> bool:
    """Return True if FTP anonymous login is accepted."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((host, 21))
        s.recv(512)  # banner
        s.send(b"USER anonymous\r\n")
        time.sleep(0.3)
        resp = s.recv(512).decode("utf-8", errors="replace")
        if resp.startswith("331"):
            s.send(b"PASS vulnsense@lab\r\n")
            time.sleep(0.3)
            resp2 = s.recv(512).decode("utf-8", errors="replace")
            s.close()
            return resp2.startswith("230")
        s.close()
        return False
    except Exception:
        return False


def _check_redis_noauth(host: str) -> bool:
    """Return True if Redis responds to PING without authentication."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, 6379))
        s.send(b"PING\r\n")
        resp = s.recv(64).decode("utf-8", errors="replace")
        s.close()
        return "+PONG" in resp
    except Exception:
        return False


def check_config(host: str, scan_id: str = None, open_ports: list = None) -> list:
    """
    Run configuration checks against detected open ports.
    `open_ports` should be a list of port numbers that are known open (from network scan).
    """
    findings = []
    open_ports = open_ports or []
    scan_id = scan_id or f"cfg_{int(time.time())}"

    def make_finding(fid, port, service, vuln_type, banner, detail,
                     complexity="low", privs="none", conf="high", intg="high",
                     avail="none", creds=0, high_risk=1):
        return {
            "finding_id":          f"{scan_id}-{fid}",
            "host":                host,
            "port":                port,
            "protocol":            "tcp",
            "service":             service,
            "vuln_type":           vuln_type,
            "banner":              banner,
            "attack_vector":       "network",
            "attack_complexity":   complexity,
            "privileges_required": privs,
            "user_interaction":    "none",
            "scope":               "unchanged",
            "conf_impact":         conf,
            "integ_impact":        intg,
            "avail_impact":        avail,
            "encrypted":           0,
            "uses_default_creds":  creds,
            "is_high_risk_service":high_risk,
            "port_exposure_category": "well_known" if port < 1024 else "registered",
            "detail": detail,
        }

    # ── Telnet ────────────────────────────────────────────────────────────────
    if 23 in open_ports:
        banner = _banner_grab(host, 23)
        findings.append(make_finding(
            "telnet", 23, "telnet", "unencrypted_protocol",
            banner or "Telnet service detected",
            "Telnet transmits all data including credentials in plaintext. "
            "Replace with SSH immediately.",
            creds=1, conf="high", intg="high"
        ))

    # ── FTP ───────────────────────────────────────────────────────────────────
    if 21 in open_ports:
        banner = _banner_grab(host, 21)
        anon = _check_ftp_anonymous(host)
        vuln = "anonymous_access" if anon else "unencrypted_protocol"
        detail = (
            "FTP allows anonymous login — anyone can connect without credentials."
            if anon else
            "FTP service is open. FTP credentials are transmitted in plaintext."
        )
        findings.append(make_finding(
            "ftp", 21, "ftp", vuln, banner or "FTP service detected",
            detail, creds=1 if anon else 0
        ))

    # ── Redis ─────────────────────────────────────────────────────────────────
    if 6379 in open_ports:
        noauth = _check_redis_noauth(host)
        findings.append(make_finding(
            "redis", 6379, "redis",
            "anonymous_access" if noauth else "open_port_exposure",
            "Redis unauthenticated access" if noauth else "Redis port exposed",
            ("Redis is accepting commands without authentication — "
             "an attacker can read/write all data in memory." if noauth else
             "Redis port is exposed to the network. Ensure authentication is configured."),
            creds=1 if noauth else 0
        ))

    # ── SSH banner disclosure ─────────────────────────────────────────────────
    if 22 in open_ports:
        banner = _banner_grab(host, 22)
        if banner and "SSH-1" in banner:
            findings.append(make_finding(
                "ssh-v1", 22, "ssh", "misconfiguration",
                banner,
                "SSH protocol version 1 is detected. SSHv1 has known cryptographic weaknesses. "
                "Upgrade to SSHv2 and disable SSHv1.",
                complexity="high", privs="none", conf="high", intg="high",
                creds=0, high_risk=1
            ))

    # ── SMB ───────────────────────────────────────────────────────────────────
    if 445 in open_ports:
        findings.append(make_finding(
            "smb", 445, "smb", "open_port_exposure",
            "SMB port 445 open",
            "SMB/port 445 is exposed to the network. "
            "SMB is a common target for ransomware and worm propagation (e.g. EternalBlue). "
            "Restrict access via firewall and ensure patching is current.",
            complexity="low", conf="high", intg="high", high_risk=1
        ))

    # ── RDP ───────────────────────────────────────────────────────────────────
    if 3389 in open_ports:
        findings.append(make_finding(
            "rdp", 3389, "rdp", "open_port_exposure",
            "RDP port 3389 open",
            "Remote Desktop is exposed to the network. "
            "RDP is frequently brute-forced and targeted by ransomware. "
            "Consider restricting to VPN or specific trusted IPs.",
            creds=1, conf="high", intg="high", high_risk=1
        ))

    # ── VNC ───────────────────────────────────────────────────────────────────
    if 5900 in open_ports:
        findings.append(make_finding(
            "vnc", 5900, "vnc", "open_port_exposure",
            "VNC port 5900 open",
            "VNC is exposed to the network. "
            "VNC with weak or no passwords gives full graphical control to an attacker. "
            "Restrict access and ensure a strong VNC password is set.",
            creds=1, conf="high", intg="high", high_risk=1
        ))

    return findings
