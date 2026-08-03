"""
VulnSense — Prediction Module
==============================
Loads both saved models once at startup. classify_finding() uses the best
model (Random Forest). Both models are available for the comparison UI.
Adds confidence threshold warnings and per-feature contribution display.
"""

import os, json
import joblib
import pandas as pd

ROOT        = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MODELS_DIR  = os.path.join(ROOT, "models")
SCHEMA_PATH = os.path.join(ROOT, "data", "feature_columns.json")

_model        = None   # best model
_model_dt     = None
_model_rf     = None
_preprocessor = None
_feature_cols = None
_eval_report  = None
_feat_imp     = None

CONFIDENCE_WARN_THRESHOLD = 0.60   # below this → flag as uncertain


def _load_artefacts():
    global _model, _model_dt, _model_rf, _preprocessor, _feature_cols, _eval_report, _feat_imp
    if _model is not None:
        return

    model_path = os.path.join(MODELS_DIR, "vulnsense_model.joblib")
    dt_path    = os.path.join(MODELS_DIR, "vulnsense_model_dt.joblib")
    rf_path    = os.path.join(MODELS_DIR, "vulnsense_model_rf.joblib")
    prep_path  = os.path.join(MODELS_DIR, "vulnsense_preprocessor.joblib")

    if not os.path.exists(model_path):
        raise FileNotFoundError("Model artefacts not found. Run: python backend/ml/train_model.py")

    _model        = joblib.load(model_path)
    _preprocessor = joblib.load(prep_path)
    _model_dt     = joblib.load(dt_path)  if os.path.exists(dt_path)  else _model
    _model_rf     = joblib.load(rf_path)  if os.path.exists(rf_path)  else _model

    with open(SCHEMA_PATH) as f:
        _feature_cols = json.load(f)["features"]

    eval_path = os.path.join(MODELS_DIR, "evaluation_report.json")
    if os.path.exists(eval_path):
        with open(eval_path) as f:
            _eval_report = json.load(f)

    feat_path = os.path.join(MODELS_DIR, "feature_importance.json")
    if os.path.exists(feat_path):
        with open(feat_path) as f:
            _feat_imp = json.load(f)


def is_ready() -> bool:
    return os.path.exists(os.path.join(MODELS_DIR, "vulnsense_model.joblib")) and \
           os.path.exists(os.path.join(MODELS_DIR, "vulnsense_preprocessor.joblib"))

def get_evaluation_report() -> dict:
    _load_artefacts(); return _eval_report or {}

def get_feature_importances() -> dict:
    _load_artefacts(); return _feat_imp or {}


# ── Plain-language explanation ────────────────────────────────

def _explain(finding: dict, label: str) -> str:
    parts = []
    av    = finding.get("attack_vector", "")
    ac    = finding.get("attack_complexity", "")
    priv  = finding.get("privileges_required", "")
    conf  = finding.get("conf_impact", "")
    intg  = finding.get("integ_impact", "")
    enc   = finding.get("encrypted", 0)
    creds = finding.get("uses_default_creds", 0)
    svc   = finding.get("service", "")
    port  = finding.get("port", "")
    vtype = finding.get("vuln_type", "")

    if label == "High":
        parts.append("This finding was classified as <strong>High</strong> risk because it poses an immediate, serious threat.")
        if av == "network":
            parts.append("The vulnerability is reachable directly over the network — no physical access required.")
        if ac == "low":
            parts.append("It requires no special conditions to exploit, making it accessible to less-skilled attackers.")
        if priv == "none":
            parts.append("No prior authentication is needed, so any unauthenticated user can attempt exploitation.")
        if conf == "high" or intg == "high":
            parts.append("Successful exploitation could result in full data disclosure or complete loss of integrity.")
        if creds == 1:
            parts.append(f"The service <em>{svc}</em> on port {port} appears to use default credentials — the first thing automated attackers try.")
    elif label == "Medium":
        parts.append("This finding was classified as <strong>Medium</strong> risk. It is a genuine concern but harder to exploit or with more limited impact.")
        if av in ("adjacent_network", "local"):
            parts.append("An attacker would need local network or physical access, limiting the exposure.")
        if ac == "high":
            parts.append("Exploitation requires specific conditions or timing, reducing the probability of a successful attack.")
        if priv in ("low", "high"):
            parts.append("Some form of authentication is required, which raises the bar for exploitation.")
        if not enc:
            parts.append(f"The service <em>{svc}</em> communicates without encryption — traffic could be intercepted on the same network.")
    else:
        parts.append("This finding was classified as <strong>Low</strong> risk. It is a minor weakness unlikely to cause significant compromise on its own.")
        if av == "physical":
            parts.append("Physical access to the machine is required — a significant barrier in most environments.")
        if conf == "none" and intg == "none":
            parts.append("The issue does not directly expose or corrupt sensitive data.")
        parts.append("Low-risk findings should still be tracked as part of a security hygiene baseline.")

    tips = {
        "default_credentials":  "Change default passwords immediately — this is the easiest entry point for attackers.",
        "unencrypted_protocol": "Replace unencrypted protocols (Telnet, FTP, HTTP) with encrypted equivalents (SSH, SFTP, HTTPS).",
        "open_port_exposure":   "Review whether this port needs to be exposed. Close or firewall ports not in active use.",
        "missing_patch":        "Apply the relevant security patch after testing in a staging environment.",
        "weak_authentication":  "Enforce strong password policies or multi-factor authentication.",
        "misconfiguration":     "Review the service configuration against a hardening guide (e.g. CIS Benchmark).",
        "information_disclosure":"Ensure error messages and banners do not reveal version numbers or internal paths.",
        "ssl_weak_cipher":      "Disable weak TLS ciphersuites and protocols. Enforce TLS 1.2 or higher.",
        "anonymous_access":     "Disable anonymous or guest access unless strictly required.",
    }
    tip = tips.get(vtype, "")
    if tip:
        parts.append(f"<em>Remediation tip:</em> {tip}")
    return " ".join(parts)


# ── Feature contribution (lightweight SHAP-style) ─────────────

def _feature_contribution(finding: dict, label: str) -> list:
    """
    Returns top contributing features for this prediction.
    Uses feature importances from the model weighted by the
    'riskiness' of the specific feature value.
    """
    _load_artefacts()
    feat_imp_data = (_feat_imp or {}).get("Random Forest") or (_feat_imp or {}).get("Decision Tree") or []
    imp_map = {name: val for name, val in feat_imp_data}

    HIGH_RISK_VALUES = {
        "attack_vector":       {"network": 1.0, "adjacent_network": 0.6, "local": 0.3, "physical": 0.1},
        "attack_complexity":   {"low": 1.0, "high": 0.3},
        "privileges_required": {"none": 1.0, "low": 0.5, "high": 0.2},
        "conf_impact":         {"high": 1.0, "low": 0.4, "none": 0.0},
        "integ_impact":        {"high": 1.0, "low": 0.4, "none": 0.0},
        "avail_impact":        {"high": 1.0, "low": 0.4, "none": 0.0},
        "encrypted":           {0: 0.8, 1: 0.0},
        "uses_default_creds":  {1: 1.0, 0: 0.0},
        "is_high_risk_service":{1: 0.7, 0: 0.0},
    }

    contributions = []
    for feat, risk_map in HIGH_RISK_VALUES.items():
        val      = finding.get(feat)
        risk_val = risk_map.get(val, 0.3)
        imp      = imp_map.get(feat, 0.0)
        score    = round(risk_val * imp, 4)
        if score > 0.001:
            contributions.append({
                "feature": feat,
                "value":   str(val),
                "score":   score,
                "label":   feat.replace("_", " ").title(),
            })

    contributions.sort(key=lambda x: x["score"], reverse=True)
    return contributions[:6]


# ── Public API ────────────────────────────────────────────────

def classify_finding(finding: dict) -> dict:
    _load_artefacts()
    row    = pd.DataFrame([finding])[_feature_cols]
    X_enc  = _preprocessor.transform(row)
    label  = _model.predict(X_enc)[0]
    proba  = _model.predict_proba(X_enc)[0]
    cls_map = {cls: float(p) for cls, p in zip(_model.classes_, proba)}
    confidence  = cls_map.get(label, 0.0)
    uncertain   = confidence < CONFIDENCE_WARN_THRESHOLD
    explanation = _explain(finding, label)
    contributions = _feature_contribution(finding, label)

    return {
        "label":         label,
        "confidence":    round(confidence, 4),
        "uncertain":     uncertain,
        "uncertainty_note": (
            "Confidence below 60% — manual review recommended. "
            "This finding sits near a classification boundary."
        ) if uncertain else None,
        "explanation":   explanation,
        "probabilities": {k: round(v, 4) for k, v in cls_map.items()},
        "contributions": contributions,
    }


def classify_batch(findings: list) -> list:
    _load_artefacts()
    rows   = pd.DataFrame(findings)[_feature_cols]
    X_enc  = _preprocessor.transform(rows)
    labels = _model.predict(X_enc)
    probas = _model.predict_proba(X_enc)

    results = []
    for finding, label, proba in zip(findings, labels, probas):
        cls_map    = {cls: float(p) for cls, p in zip(_model.classes_, proba)}
        confidence = cls_map.get(label, 0.0)
        uncertain  = confidence < CONFIDENCE_WARN_THRESHOLD
        results.append({
            "label":         label,
            "confidence":    round(confidence, 4),
            "uncertain":     uncertain,
            "uncertainty_note": (
                "Confidence below 60% — manual review recommended."
            ) if uncertain else None,
            "explanation":   _explain(finding, label),
            "probabilities": {k: round(v, 4) for k, v in cls_map.items()},
            "contributions": _feature_contribution(finding, label),
        })
    return results


def classify_with_both_models(finding: dict) -> dict:
    """Classify with both DT and RF — used by the comparison UI."""
    _load_artefacts()
    row   = pd.DataFrame([finding])[_feature_cols]
    X_enc = _preprocessor.transform(row)

    results = {}
    for name, mdl in [("Decision Tree", _model_dt), ("Random Forest", _model_rf)]:
        label  = mdl.predict(X_enc)[0]
        proba  = mdl.predict_proba(X_enc)[0]
        cls_map = {cls: float(p) for cls, p in zip(mdl.classes_, proba)}
        results[name] = {
            "label":      label,
            "confidence": round(cls_map.get(label, 0.0), 4),
            "probabilities": {k: round(v, 4) for k, v in cls_map.items()},
        }
    return results
