"""
VulnSense — Web Security Checker (expanded)
============================================
Checks: HTTP→HTTPS redirect, security headers, SSL/TLS cert,
server banner/version disclosure, robots.txt sensitive paths,
common admin panel exposure, open directory listing detection.
"""

import ssl, socket, requests, urllib3, re
from datetime import datetime

urllib3.disable_warnings()

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/phpmyadmin", "/pma",
    "/wp-admin", "/login", "/manager", "/.env",
    "/config.php", "/server-status", "/server-info",
]

# Known vulnerable version patterns in server banners
VULNERABLE_VERSIONS = {
    "apache/2.2":  ("Apache 2.2.x is end-of-life and has multiple known CVEs.", "HIGH"),
    "apache/2.4.4": ("Apache 2.4.49/2.4.50 path traversal (CVE-2021-41773).", "HIGH"),
    "nginx/1.10":  ("Nginx 1.10.x is outdated with known vulnerabilities.", "MEDIUM"),
    "openssl/1.0": ("OpenSSL 1.0.x is end-of-life (Heartbleed era).", "HIGH"),
    "php/5":       ("PHP 5.x is end-of-life.", "HIGH"),
    "php/7.0":     ("PHP 7.0 is end-of-life.", "MEDIUM"),
    "vsftpd/2.3.4":("vsftpd 2.3.4 backdoor (CVE-2011-2523).", "HIGH"),
    "iis/6":       ("IIS 6.0 is end-of-life with multiple CVEs.", "HIGH"),
    "iis/7.0":     ("IIS 7.0 is outdated.", "MEDIUM"),
}


def _request(url, timeout=6):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                            headers={"User-Agent": "VulnSense/1.0 (Lab Scanner)"})
    except Exception:
        return None


def _check_ssl_cert(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, port))
            cert   = s.getpeercert()
            cipher = s.cipher()
            return {"valid": True, "cipher": cipher[0] if cipher else "",
                    "protocol": cipher[1] if cipher else "", "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate error: {e}", "cipher": "", "protocol": ""}
    except Exception as e:
        return {"valid": False, "error": str(e), "cipher": "", "protocol": ""}


def _make_finding(scan_id, fid, host, port, service, vuln_type, banner, detail,
                  av="network", ac="low", priv="none", ui="none",
                  conf="low", intg="low", avail="none", enc=0, creds=0, high_risk=0):
    return {
        "finding_id":          f"{scan_id}-{fid}",
        "host":                host,
        "port":                port,
        "protocol":            "tcp",
        "service":             service,
        "vuln_type":           vuln_type,
        "banner":              banner,
        "detail":              detail,
        "attack_vector":       av,
        "attack_complexity":   ac,
        "privileges_required": priv,
        "user_interaction":    ui,
        "scope":               "unchanged",
        "conf_impact":         conf,
        "integ_impact":        intg,
        "avail_impact":        avail,
        "encrypted":           enc,
        "uses_default_creds":  creds,
        "is_high_risk_service":high_risk,
        "port_exposure_category": "well_known",
    }


def check_web(host: str, scan_id: str = None) -> list:
    findings = []
    scan_id  = scan_id or f"web_{int(datetime.utcnow().timestamp())}"

    for scheme, port in [("http", 80), ("https", 443)]:
        url  = f"{scheme}://{host}:{port}/"
        resp = _request(url)
        if resp is None:
            continue

        headers     = {k.lower(): v for k, v in resp.headers.items()}
        server_hdr  = resp.headers.get("Server", "")
        server_low  = server_hdr.lower()
        status      = resp.status_code

        # ── HTTP → HTTPS redirect ──────────────────────────────
        if scheme == "http":
            redirected = resp.url.startswith("https://")
            if not redirected:
                findings.append(_make_finding(
                    scan_id, "http-noredir", host, 80, "http",
                    "unencrypted_protocol",
                    f"Server: {server_hdr}",
                    "HTTP site does not redirect to HTTPS. All traffic is transmitted in plaintext.",
                    conf="high", intg="low",
                ))

        # ── Missing security headers ───────────────────────────
        for hdr in SECURITY_HEADERS:
            if hdr.lower() not in headers:
                findings.append(_make_finding(
                    scan_id, f"header-{hdr.lower().replace('-','_')}-{port}",
                    host, port, scheme, "misconfiguration",
                    f"Missing header: {hdr}",
                    f"Security header '{hdr}' is not set. This weakens browser-level protections.",
                    ac="high", ui="required", enc=1 if scheme=="https" else 0,
                ))

        # ── Server banner version disclosure ───────────────────
        if server_hdr and any(c.isdigit() for c in server_hdr):
            findings.append(_make_finding(
                scan_id, f"{scheme}-banner-{port}",
                host, port, scheme, "information_disclosure",
                f"Server: {server_hdr}",
                f"Server header reveals version info: '{server_hdr}'. "
                f"Attackers use this to target known CVEs for that version.",
                enc=1 if scheme == "https" else 0,
            ))

        # ── Known vulnerable version check ─────────────────────
        for pattern, (desc, severity) in VULNERABLE_VERSIONS.items():
            if pattern in server_low:
                findings.append(_make_finding(
                    scan_id, f"{scheme}-vulnver-{pattern.replace('/','-')}-{port}",
                    host, port, scheme, "missing_patch",
                    f"Server: {server_hdr}",
                    f"Potentially vulnerable version detected: {desc}",
                    conf="high" if severity=="HIGH" else "low",
                    intg="high" if severity=="HIGH" else "low",
                    ac="low" if severity=="HIGH" else "high",
                ))

        # ── X-Powered-By / technology disclosure ───────────────
        xpb = resp.headers.get("X-Powered-By", "")
        if xpb and any(c.isdigit() for c in xpb):
            findings.append(_make_finding(
                scan_id, f"{scheme}-xpb-{port}",
                host, port, scheme, "information_disclosure",
                f"X-Powered-By: {xpb}",
                f"X-Powered-By header reveals technology stack: '{xpb}'.",
                enc=1 if scheme == "https" else 0,
            ))

        # ── Directory listing ──────────────────────────────────
        if "index of /" in resp.text.lower() or "parent directory" in resp.text.lower():
            findings.append(_make_finding(
                scan_id, f"{scheme}-dirlisting-{port}",
                host, port, scheme, "misconfiguration",
                "Directory listing enabled",
                "Web server directory listing is enabled. An attacker can browse "
                "the file system and discover sensitive files.",
                conf="high", ac="low",
                enc=1 if scheme == "https" else 0,
            ))

        # ── robots.txt sensitive path disclosure ───────────────
        robots_resp = _request(f"{scheme}://{host}:{port}/robots.txt")
        if robots_resp and robots_resp.status_code == 200:
            sensitive = re.findall(r"Disallow:\s*(/\S+)", robots_resp.text)
            sensitive_hit = [p for p in sensitive if any(
                kw in p.lower() for kw in
                ["admin", "config", "backup", "db", "secret", "password", "private", "internal"]
            )]
            if sensitive_hit:
                findings.append(_make_finding(
                    scan_id, f"{scheme}-robots-{port}",
                    host, port, scheme, "information_disclosure",
                    f"robots.txt Disallow: {', '.join(sensitive_hit[:5])}",
                    f"robots.txt reveals potentially sensitive paths: {', '.join(sensitive_hit[:5])}. "
                    f"These paths may be accessible despite being listed.",
                    enc=1 if scheme == "https" else 0,
                ))

        # ── Admin panel exposure ───────────────────────────────
        for path in ADMIN_PATHS:
            try:
                r = requests.get(
                    f"{scheme}://{host}:{port}{path}",
                    timeout=4, verify=False, allow_redirects=False,
                    headers={"User-Agent": "VulnSense/1.0"}
                )
                if r.status_code in (200, 301, 302, 403):
                    findings.append(_make_finding(
                        scan_id, f"{scheme}-admin-{path.replace('/','').replace('.','')}-{port}",
                        host, port, scheme, "open_port_exposure",
                        f"HTTP {r.status_code} — {scheme}://{host}{path}",
                        f"Admin or sensitive path '{path}' returned HTTP {r.status_code}. "
                        f"This path may be accessible or partially protected.",
                        conf="high" if r.status_code == 200 else "low",
                        ac="low" if r.status_code == 200 else "high",
                        enc=1 if scheme == "https" else 0,
                    ))
            except Exception:
                pass

        # ── SSL/TLS check ──────────────────────────────────────
        if scheme == "https":
            ssl_info = _check_ssl_cert(host, port=443)
            if not ssl_info["valid"]:
                findings.append(_make_finding(
                    scan_id, "ssl-invalid",
                    host, 443, "https", "ssl_weak_cipher",
                    ssl_info.get("error",""),
                    f"SSL certificate issue: {ssl_info.get('error')}",
                    ac="high", ui="required", conf="high", enc=0,
                ))
            elif ssl_info.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append(_make_finding(
                    scan_id, "ssl-weakproto",
                    host, 443, "https", "ssl_weak_cipher",
                    f"Protocol: {ssl_info['protocol']}  Cipher: {ssl_info['cipher']}",
                    f"Deprecated TLS protocol in use: {ssl_info['protocol']}. "
                    f"Upgrade to TLS 1.2 or TLS 1.3.",
                    ac="high", conf="high",
                ))

    return findings
