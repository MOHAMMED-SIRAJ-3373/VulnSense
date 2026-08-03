"""
VulnSense — Flask Application Entry Point
==========================================
Run:  python app.py
The backend serves the API on port 5050 and also serves the static
frontend files from frontend/templates/ and frontend/static/.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from flask import Flask, send_from_directory, send_file
from flask_cors import CORS

from backend.utils.db import init_db
from backend.utils.auth import seed_default_admin
from backend.routes.api import api

# ── App factory ───────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    static_folder=os.path.join(ROOT, "frontend", "static"),
    template_folder=os.path.join(ROOT, "frontend", "templates"),
)
app.secret_key = os.environ.get("VULNSENSE_SECRET", "vulnsense-dev-secret-changeme")

# CORS for local dev (frontend on a different port during development)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register API blueprint
app.register_blueprint(api)

# ── Static file serving ───────────────────────────────────────────────────────
@app.route("/")
def serve_login():
    return send_from_directory(
        os.path.join(ROOT, "frontend", "templates"), "login.html"
    )

@app.route("/dashboard")
def serve_dashboard():
    return send_from_directory(
        os.path.join(ROOT, "frontend", "templates"), "dashboard.html"
    )

@app.route("/readiness")
def serve_readiness():
    return send_from_directory(
        os.path.join(ROOT, "frontend", "templates"), "readiness.html"
    )

@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory(
        os.path.join(ROOT, "frontend", "static"), filename
    )

@app.route("/models/confusion_matrix.png")
def serve_cm_image():
    img_path = os.path.join(ROOT, "models", "confusion_matrix.png")
    if os.path.exists(img_path):
        return send_file(img_path, mimetype="image/png")
    return ("Image not found. Run training first.", 404)

# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  VulnSense — AI Vulnerability Risk Prioritization")
    print("  CST3590 Final Year Project — Mohammed Siraj (M00979305)")
    print("=" * 55)
    print()

    # Initialise database and seed default admin
    init_db()
    seed_default_admin()

    print("[VulnSense] Server starting on http://localhost:5050")
    print("[VulnSense] Open your browser → http://localhost:5050")
    print()

    app.run(host="0.0.0.0", port=5050, debug=False)
