# VulnSense - AI Vulnerability Risk Prioritization
**CST3590 Final Year Project | Mohammed Siraj | M00979305**

> A lightweight vulnerability risk classification and reporting tool for students and junior analysts.

---

## What this system does

VulnSense sits between raw vulnerability scan results and the final decision on what to fix. It runs a limited set of network, web, and configuration checks against a controlled lab VM, then uses a trained Random Forest classifier to categorise each finding as **High**, **Medium**, or **Low** risk. The dashboard explains *why* each finding received its label in plain language, so students and junior analysts can understand the reasoning.

---

## Quick Start 
Only use VulnSense against approved lab targets on private IP ranges. It is not intended for production or internet-facing systems.

### 1. One-time setup

```bash
cd vulnsense
chmod +x scripts/setup.sh
./scripts/setup.sh
```

This will:
- Create a virtual environment
- Install all Python dependencies
- Install nmap (if apt is available)
- Generate the training dataset
- Train and save the ML model
- Initialise the SQLite database


## Manual setup (step by step, alternative to setup.sh)

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt

# Install nmap (optional - improves scan accuracy)
sudo apt install nmap          # for Debian/Ubuntu

# Generate dataset (run once)
python data/generate_dataset.py

# Train the ML model (run once, or when retraining is needed)
python backend/ml/train_model.py

# Start the app
python app.py
```

---

## System flow

```
User logs in → System Readiness Check → Dashboard
                                              │
                              ┌───────────────┴───────────────┐
                              │                               │
                         Run Scan                      View ML Report
                              │
                   ┌──────────┼──────────┐
                   │          │          │
               Network      Web       Config
               Scan         Check     Check
                   │          │          │
                   └──────────┴──────────┘
                              │
                      Feature Extraction
                              │
                    ML Classification
                   (saved model loaded
                    once at startup)
                              │
                  ┌───────────┼──────────┐
                  │           │          │
                High         Medium     Low
                  │           │          │
                 Plain-language explanation
                              │
                      Store in SQLite
                              │
                    Dashboard + Report
```

---

## ML pipeline

| Task | When | Command |
|---|---|---|
| Generate dataset | Once | `python data/generate_dataset.py` |
| Train model | Once (or to retrain) | `python backend/ml/train_model.py` |
| Evaluate model | Output of training | See `models/evaluation_report.json` |
| Load model at runtime | Every app start (auto) | Handled by `backend/ml/predictor.py` |
| Predict on new findings | Every scan | Called by Flask routes, no retraining |

**The app never retrains during normal use.** Retraining is an explicit admin action.

---

## Dataset and labelling

The dataset (`data/vulnsense_dataset.csv`) contains 800 synthetic vulnerability findings with features derived from published NVD/CVSS feature distributions.

**Label scheme (CVSS + RBVM-inspired):**
- **High** - CVSS ≥ 7.0, OR network-facing + low complexity + no privileges required with CVSS ≥ 5.5, OR default credentials on a critical service
- **Medium** - CVSS 4.0–6.9, OR high-impact but partially mitigated (e.g. internal-only or requires higher privileges).
- **Low** - CVSS < 4.0, limited scope and impact

**Label leakage prevention:** The CVSS base score is stored in the CSV for audit comparison only (`cvss_base_score_audit`) and is explicitly excluded from all ML features. The model learns from component features (attack vector, impact dimensions, service type, etc.) - not from the computed score.

---

## Project structure

```
vulnsense/
├── app.py                          ← Flask entry point
├── requirements.txt
├── data/
│   ├── generate_dataset.py         ← Setup task: generate CSV
│   ├── vulnsense_dataset.csv       ← Generated training data
│   ├── feature_columns.json        ← Feature schema
│   └── vulnsense.db                ← SQLite database (auto-created)
├── models/
│   ├── vulnsense_model.joblib      ← Trained Random Forest (runtime model)
│   ├── vulnsense_preprocessor.joblib
│   ├── evaluation_report.json      ← Test metrics
│   ├── feature_importance.json
│   └── confusion_matrix.png
├── backend/
│   ├── ml/
│   │   ├── train_model.py          ← Setup task: train + save model
│   │   └── predictor.py            ← Runtime: load + predict
│   ├── scanner/
│   │   ├── network_scan.py         ← Port scan (nmap / socket)
│   │   ├── web_check.py            ← HTTP/HTTPS checks
│   │   └── config_check.py         ← Service config checks
│   ├── routes/
│   │   └── api.py                  ← All Flask API routes
│   └── utils/
│       ├── db.py                   ← SQLite helpers
│       └── auth.py                 ← bcrypt + session management
├── frontend/
│   ├── templates/
│   │   ├── login.html              ← Sign-in page
│   │   ├── readiness.html          ← System readiness checker
│   │   └── dashboard.html          ← Main dashboard
│   └── static/css/
│       └── vulnsense.css           ← Full design system
├── tests/
│   ├── test_ml.py
│   ├── test_auth.py
│   └── test_scanner.py
└── scripts/
    └── setup.sh
```

---

## API routes

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | - | Sign in, returns session token |
| POST | `/api/auth/logout` | ✓ | Invalidate session |
| GET | `/api/health` | ✓ | System readiness checks |
| POST | `/api/scan/run` | ✓ | Run full scan pipeline |
| POST | `/api/scan/classify` | ✓ | Classify a single finding |
| GET | `/api/scans` | ✓ | List all scans |
| GET | `/api/scans/<id>/findings` | ✓ | Get findings for a scan |
| GET | `/api/dashboard/stats` | ✓ | KPI summary |
| GET | `/api/ml/report` | ✓ | Classifier evaluation report |
| GET | `/api/ml/features` | ✓ | Feature importances |
| GET | `/api/report/<id>` | ✓ | Download plain-text report |

---

## Running tests (only if needed)

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```
