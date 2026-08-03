#!/bin/bash
# ============================================================
# VulnSense — One-time Setup Script
# Run this script once on a fresh Linux machine or VM.
# ============================================================

set -e
echo "============================================================"
echo "  VulnSense Setup — CST3590 Final Year Project"
echo "============================================================"
echo ""

# ── 1. Python virtual environment ─────────────────────────────
echo "[1/5] Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# ── 2. Install Python dependencies ────────────────────────────
echo "[2/5] Installing Python packages..."
pip install --upgrade pip -q
pip install flask flask-cors bcrypt scikit-learn pandas numpy joblib \
            python-nmap requests matplotlib seaborn reportlab -q

echo "       Packages installed."

# ── 3. nmap (optional but recommended) ───────────────────────
echo "[3/5] Checking nmap..."
if ! command -v nmap &> /dev/null; then
    echo "       nmap not found. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y nmap > /dev/null 2>&1
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y nmap > /dev/null 2>&1
    else
        echo "       Could not auto-install nmap. Install manually: sudo apt install nmap"
        echo "       VulnSense will fall back to socket-based scanning."
    fi
else
    echo "       nmap found: $(nmap --version | head -1)"
fi

# ── 4. Generate dataset and train model ───────────────────────
echo "[4/5] Generating dataset and training ML model..."
python data/generate_dataset.py
python backend/ml/train_model.py

# ── 5. Initialise database ────────────────────────────────────
echo "[5/5] Initialising database..."
python -c "from backend.utils.db import init_db; init_db(); print('       Database ready.')"

echo ""
echo "============================================================"
echo "  Setup complete."
echo ""
echo "  To start VulnSense:"
echo "    source .venv/bin/activate"
echo "    python app.py"
echo ""
echo "  Open: http://localhost:5050"
echo "  Default login: admin / vulnsense2024"
echo "============================================================"
