"""
VulnSense — Flask API Routes
==============================
All backend logic is triggered from here. The frontend sends HTTP
requests to these endpoints; Python runs the scan/ML/DB work and
returns JSON (or a file download) back to the browser.
"""

import os, sys, time, json, shutil, queue, threading
from datetime import datetime
from flask import Blueprint, request, jsonify, Response, stream_with_context

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, ROOT)

from backend.utils.db import (
    init_db, get_all_scans, get_scan_findings, get_dashboard_stats,
    create_scan, complete_scan, save_finding, delete_session,
    update_remediation, get_host_score
)
from backend.utils.auth import login, require_auth, require_admin, seed_default_admin
from backend.utils.cve_lookup import lookup_cves
from backend.utils.pdf_report import generate_pdf
from backend.ml.predictor import (
    classify_finding, classify_batch, is_ready,
    get_evaluation_report, get_feature_importances,
    classify_with_both_models
)

api = Blueprint("api", __name__, url_prefix="/api")

# ── Auth ──────────────────────────────────────────────────────

@api.route("/auth/login", methods=["POST"])
def auth_login():
    data     = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
    session = login(username, password)
    if not session:
        return jsonify({"error": "Invalid credentials. Please try again."}), 401
    return jsonify(session), 200


@api.route("/auth/logout", methods=["POST"])
@require_auth
def auth_logout():
    token = request.headers.get("Authorization", "")[7:]
    delete_session(token)
    return jsonify({"message": "Logged out."}), 200


# ── System Readiness ──────────────────────────────────────────

@api.route("/health", methods=["GET"])
def health():
    """
    Called by the readiness-checker page to verify that all
    required components are installed before letting the user in.
    """
    checks = {
        "python": {
            "ok":     sys.version_info >= (3, 10),
            "detail": f"Python {sys.version.split()[0]}",
        },
        "packages": _check_packages(),
        "nmap": {
            "ok":     shutil.which("nmap") is not None,
            "detail": shutil.which("nmap") or "nmap not found — socket fallback will be used",
        },
        "model": {
            "ok":     is_ready(),
            "detail": "Model artefacts loaded" if is_ready()
                      else "Run: python backend/ml/train_model.py",
        },
        "database": {
            "ok":     os.path.exists(os.path.join(ROOT, "data", "vulnsense.db")),
            "detail": os.path.join(ROOT, "data", "vulnsense.db"),
        },
    }
    return jsonify({"ready": all(c["ok"] for c in checks.values()), "checks": checks}), 200


def _check_packages():
    missing = []
    for mod in ["flask", "sklearn", "pandas", "numpy", "joblib", "bcrypt", "requests", "reportlab"]:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    return {
        "ok":     len(missing) == 0,
        "detail": "All packages installed" if not missing else f"Missing: {', '.join(missing)}",
    }


# ── Live Scan with Server-Sent Events (SSE) ───────────────────
#
# SSE lets us push progress updates from Python to the browser
# in real time without polling. The browser opens one long-lived
# connection; Python writes "data: ..." lines as each step finishes.

# One queue per active scan — stores progress messages
_scan_queues: dict = {}


@api.route("/scan/stream/<scan_id>", methods=["GET"])
@require_auth
def scan_stream(scan_id):
    """SSE endpoint — browser subscribes here to get live progress."""
    q = _scan_queues.get(scan_id)
    if not q:
        return jsonify({"error": "No active scan with that ID"}), 404

    def event_stream():
        while True:
            msg = q.get()
            if msg is None:   # None = sentinel, scan finished
                yield "data: [DONE]\n\n"
                break
            yield f"data: {json.dumps(msg)}\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


def _push(q, step, message, pct=0):
    """Helper: push a progress event into the SSE queue."""
    if q:
        q.put({"step": step, "message": message, "pct": pct})


@api.route("/scan/run", methods=["POST"])
@require_auth
def scan_run():
    """
    Full scan pipeline:
    1. Network scan     → open ports + service banners
    2. Web checks       → HTTP/HTTPS headers, SSL, admin paths
    3. Config checks    → Telnet, FTP anon, Redis noauth, etc.
    4. CVE lookup       → enrich each finding with related CVEs
    5. ML classify      → label each finding High/Medium/Low
    6. Persist          → save everything to SQLite
    """
    from backend.scanner.network_scan import scan_host
    from backend.scanner.web_check    import check_web
    from backend.scanner.config_check import check_config

    data = request.get_json(force=True) or {}
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"error": "A target host IP address is required."}), 400

    scan_id      = f"VS{int(time.time())}"
    initiated_by = request.current_user.get("username", "unknown")

    # Create a queue for this scan so the SSE stream can read from it
    q = queue.Queue()
    _scan_queues[scan_id] = q

    def run():
        try:
            _push(q, "network", "Starting network port scan…", 5)
            try:
                net = scan_host(host, scan_id=scan_id)
            except ValueError as e:
                q.put({"error": str(e)}); q.put(None); return
            except Exception as e:
                q.put({"error": f"Network scan failed: {e}"}); q.put(None); return

            create_scan(scan_id, host, net["started_at"], net["method"], initiated_by)
            open_ports = [f["port"] for f in net["findings"]]
            _push(q, "network", f"Found {len(net['findings'])} open ports.", 25)

            _push(q, "web", "Running web security checks…", 35)
            web_findings = check_web(host, scan_id=scan_id)
            _push(q, "web", f"{len(web_findings)} web findings.", 50)

            _push(q, "config", "Checking service configurations…", 55)
            cfg_findings = check_config(host, scan_id=scan_id, open_ports=open_ports)
            _push(q, "config", f"{len(cfg_findings)} config findings.", 65)

            # Deduplicate by finding_id
            seen, unique = set(), []
            for f in net["findings"] + web_findings + cfg_findings:
                if f.get("finding_id") not in seen:
                    seen.add(f.get("finding_id"))
                    unique.append(f)

            _push(q, "cve", "Looking up related CVEs from NVD…", 70)
            for f in unique:
                f["cves"] = lookup_cves(f.get("service",""), f.get("vuln_type",""))

            _push(q, "ml", "Classifying findings with AI model…", 80)
            if unique and is_ready():
                try:
                    ml_results = classify_batch(unique)
                except Exception:
                    ml_results = [{"label":"Medium","confidence":0.5,
                                   "uncertain":False,"explanation":"Classification unavailable.",
                                   "probabilities":{},"contributions":[]} for _ in unique]
            else:
                ml_results = [{"label":"Unknown","confidence":0.0,
                               "uncertain":False,"explanation":"Model not loaded.",
                               "probabilities":{},"contributions":[]} for _ in unique]

            _push(q, "save", "Saving results…", 90)
            for finding, ml in zip(unique, ml_results):
                save_finding(scan_id, finding, ml)
            complete_scan(scan_id, len(unique))

            summary = {"High":0,"Medium":0,"Low":0}
            enriched = []
            for f, ml in zip(unique, ml_results):
                lbl = ml.get("label","Unknown")
                if lbl in summary: summary[lbl] += 1
                enriched.append({**f, **ml})

            _push(q, "done", "Scan complete.", 100)
            q.put({
                "scan_id": scan_id, "host": host,
                "method": net["method"], "total": len(unique),
                "summary": summary, "findings": enriched,
            })
        finally:
            q.put(None)   # sentinel — tells SSE stream to close
            # Clean up queue after 5 min
            threading.Timer(300, lambda: _scan_queues.pop(scan_id, None)).start()

    # Run the scan in a background thread so we can return scan_id immediately
    threading.Thread(target=run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "message": "Scan started."}), 202


@api.route("/scan/result/<scan_id>", methods=["GET"])
@require_auth
def scan_result(scan_id):
    """Poll this endpoint if SSE is not available (fallback)."""
    findings = get_scan_findings(scan_id)
    if not findings:
        return jsonify({"status": "running"}), 202
    summary = {"High":0,"Medium":0,"Low":0}
    for f in findings:
        if f.get("risk_label") in summary:
            summary[f["risk_label"]] += 1
    return jsonify({
        "scan_id": scan_id,
        "status":  "complete",
        "total":   len(findings),
        "summary": summary,
        "findings":findings,
    }), 200


@api.route("/scan/classify", methods=["POST"])
@require_auth
def scan_classify():
    """Classify a single manually-entered finding (no live scan needed)."""
    data = request.get_json(force=True) or {}
    try:
        result       = classify_finding(data)
        both_models  = classify_with_both_models(data)
        cves         = lookup_cves(data.get("service",""), data.get("vuln_type",""))
        return jsonify({**result, "model_comparison": both_models, "cves": cves}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── History & Findings ────────────────────────────────────────

@api.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    return jsonify(get_all_scans()), 200


@api.route("/scans/<scan_id>/findings", methods=["GET"])
@require_auth
def scan_findings(scan_id):
    return jsonify(get_scan_findings(scan_id)), 200


# ── Remediation Tracker ───────────────────────────────────────

@api.route("/findings/<finding_id>/remediation", methods=["PATCH"])
@require_auth
def patch_remediation(finding_id):
    """
    Let an analyst update the status of a finding:
    open | in_progress | fixed | accepted_risk
    """
    data   = request.get_json(force=True) or {}
    status = data.get("status", "open")
    note   = data.get("note", "")
    valid  = {"open", "in_progress", "fixed", "accepted_risk"}
    if status not in valid:
        return jsonify({"error": f"Status must be one of: {valid}"}), 400
    update_remediation(finding_id, status, note)
    return jsonify({"finding_id": finding_id, "status": status}), 200


# ── Dashboard ─────────────────────────────────────────────────

@api.route("/dashboard/stats", methods=["GET"])
@require_auth
def dashboard_stats():
    return jsonify(get_dashboard_stats()), 200


@api.route("/host/<host>/score", methods=["GET"])
@require_auth
def host_score(host):
    """Return the 0-100 security score for a given host IP."""
    score = get_host_score(host)
    grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=60 else "D" if score>=40 else "F"
    return jsonify({"host": host, "score": score, "grade": grade}), 200


# ── ML Reports ────────────────────────────────────────────────

@api.route("/ml/report", methods=["GET"])
@require_auth
def ml_report():
    return jsonify(get_evaluation_report()), 200


@api.route("/ml/features", methods=["GET"])
@require_auth
def ml_features():
    return jsonify(get_feature_importances()), 200


# ── Reports (PDF + text) ──────────────────────────────────────

@api.route("/report/<scan_id>/pdf", methods=["GET"])
@require_auth
def report_pdf(scan_id):
    """Generate and return a formatted PDF report for the scan."""
    findings = get_scan_findings(scan_id)
    if not findings:
        return jsonify({"error": "No findings for this scan."}), 404
    host    = findings[0]["host"] if findings else "unknown"
    analyst = request.current_user.get("username", "admin")
    try:
        pdf_bytes = generate_pdf(scan_id, host, findings, analyst)
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vulnsense_{scan_id}.pdf"}
    )


@api.route("/report/<scan_id>", methods=["GET"])
@require_auth
def report_text(scan_id):
    """Plain-text fallback report."""
    findings = get_scan_findings(scan_id)
    if not findings:
        return jsonify({"error": "No findings."}), 404
    host   = findings[0]["host"]
    high   = [f for f in findings if f["risk_label"]=="High"]
    medium = [f for f in findings if f["risk_label"]=="Medium"]
    low    = [f for f in findings if f["risk_label"]=="Low"]
    lines  = [
        "="*65, "  VulnSense Security Report",
        f"  Scan   : {scan_id}", f"  Host   : {host}",
        f"  Date   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "="*65, "",
        f"  High   : {len(high)}",
        f"  Medium : {len(medium)}",
        f"  Low    : {len(low)}",
        f"  Total  : {len(findings)}", "",
    ]
    for label, group in [("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
        if group:
            lines.append(f"── {label} ──")
            for f in group:
                lines += [
                    f"  [{f['risk_label']}] {f['service'].upper()} port {f['port']}",
                    f"  Type: {f['vuln_type']}   Confidence: {round((f['confidence'] or 0)*100,1)}%",
                    f"  {f.get('detail','')}", "",
                ]
    lines += ["="*65, "VulnSense — FOR EDUCATIONAL USE ONLY"]
    return Response("\n".join(lines), mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=vulnsense_{scan_id}.txt"})


@api.route("/models/confusion_matrix.png")
def cm_image():
    from flask import send_file
    p = os.path.join(ROOT, "models", "confusion_matrix.png")
    return send_file(p, mimetype="image/png") if os.path.exists(p) else ("Not found", 404)


@api.route("/models/<filename>")
def model_image(filename):
    from flask import send_file
    p = os.path.join(ROOT, "models", filename)
    if os.path.exists(p) and filename.endswith(".png"):
        return send_file(p, mimetype="image/png")
    return ("Not found", 404)
