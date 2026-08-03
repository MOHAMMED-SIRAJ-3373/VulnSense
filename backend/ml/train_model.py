"""
VulnSense — ML Training Script (SETUP TASK — run once or to retrain)
=====================================================================
Trains TWO classifiers and compares them:
  1. Decision Tree  — interpretable, proposal-aligned
  2. Random Forest  — ensemble, stronger generalisation

Both are saved. The predictor loads whichever scored higher on CV F1
(Decision Tree wins ties — keeping interpretability as the tiebreaker).
The evaluation report stores side-by-side metrics for the dashboard.

Usage:
    python backend/ml/train_model.py

Output:
    models/vulnsense_model.joblib          — best classifier
    models/vulnsense_model_dt.joblib       — Decision Tree (always saved)
    models/vulnsense_model_rf.joblib       — Random Forest (always saved)
    models/vulnsense_preprocessor.joblib   — fitted ColumnTransformer
    models/evaluation_report.json          — full metrics + comparison
    models/feature_importance.json         — feature importances
    models/confusion_matrix.png            — confusion matrix (best model)
    models/confusion_matrix_dt.png         — confusion matrix (DT)
    models/confusion_matrix_rf.png         — confusion matrix (RF)
"""

import os, sys, json, warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OrdinalEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

ROOT        = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DATA_PATH   = os.path.join(ROOT, "data", "vulnsense_dataset.csv")
SCHEMA_PATH = os.path.join(ROOT, "data", "feature_columns.json")
MODELS_DIR  = os.path.join(ROOT, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────
df = pd.read_csv(DATA_PATH)
with open(SCHEMA_PATH) as f:
    schema = json.load(f)

FEATURE_COLS = schema["features"]
TARGET       = schema["target"]
X = df[FEATURE_COLS].copy()
y = df[TARGET].copy()

CATEGORICAL = [
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "conf_impact", "integ_impact",
    "avail_impact", "port_exposure_category", "service", "vuln_type", "protocol"
]
NUMERIC = ["port", "encrypted", "uses_default_creds", "is_high_risk_service"]

cat_encoder  = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1, encoded_missing_value=-2)
preprocessor = ColumnTransformer(transformers=[
    ("cat", cat_encoder, CATEGORICAL),
    ("num", "passthrough", NUMERIC),
])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
X_train_enc = preprocessor.fit_transform(X_train)
X_test_enc  = preprocessor.transform(X_test)

LABELS = ["High", "Medium", "Low"]
cv     = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# ── Helper: evaluate one model ────────────────────────────────
def evaluate_model(model, name):
    print(f"\n── {name} ──")
    # CV on training set
    cv_scores = cross_val_score(model, X_train_enc, y_train, cv=cv, scoring="f1_weighted")
    model.fit(X_train_enc, y_train)
    y_pred = model.predict(X_test_enc)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1   = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    cv_f1 = cv_scores.mean()
    cm   = confusion_matrix(y_test, y_pred, labels=LABELS)

    print(classification_report(y_test, y_pred, labels=LABELS, zero_division=0))
    print(f"  CV F1 (train): {cv_f1:.4f}  |  Test F1: {f1:.4f}")

    # Per-class
    rep = classification_report(y_test, y_pred, labels=LABELS, output_dict=True, zero_division=0)
    per_class = {}
    for lbl in LABELS:
        per_class[lbl] = {
            "precision": round(rep[lbl]["precision"], 4),
            "recall":    round(rep[lbl]["recall"], 4),
            "f1":        round(rep[lbl]["f1-score"], 4),
            "support":   int(rep[lbl]["support"]),
        }

    # Confusion matrix plot
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=LABELS, yticklabels=LABELS, ax=ax)
    ax.set_title(f"VulnSense — {name} Confusion Matrix")
    ax.set_ylabel("True Label"); ax.set_xlabel("Predicted Label")
    plt.tight_layout()
    tag  = "dt" if "Tree" in name else "rf"
    path = os.path.join(MODELS_DIR, f"confusion_matrix_{tag}.png")
    plt.savefig(path, dpi=150); plt.close()

    return {
        "name":       name,
        "accuracy":   round(acc, 4),
        "precision":  round(prec, 4),
        "recall":     round(rec, 4),
        "f1":         round(f1, 4),
        "cv_f1":      round(cv_f1, 4),
        "per_class":  per_class,
        "confusion_matrix": {"labels": LABELS, "matrix": cm.tolist()},
        "cm_image":   f"confusion_matrix_{tag}.png",
    }

# ── Decision Tree (grid search over depth) ───────────────────
print("Selecting Decision Tree depth via cross-validation...")
best_depth, best_cv = 5, 0
for depth in range(3, 12):
    clf = DecisionTreeClassifier(max_depth=depth, class_weight="balanced", random_state=42)
    score = cross_val_score(clf, X_train_enc, y_train, cv=cv, scoring="f1_weighted").mean()
    print(f"  depth={depth}  cv_f1={score:.4f}")
    if score > best_cv:
        best_cv, best_depth = score, depth

dt = DecisionTreeClassifier(max_depth=best_depth, class_weight="balanced", random_state=42)
dt_metrics = evaluate_model(dt, "Decision Tree")
dt_metrics["params"] = {"max_depth": best_depth, "class_weight": "balanced"}
joblib.dump(dt, os.path.join(MODELS_DIR, "vulnsense_model_dt.joblib"))

# ── Random Forest ─────────────────────────────────────────────
print("\nTraining Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=best_depth + 2,   # slightly deeper — ensemble handles variance
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
rf_metrics = evaluate_model(rf, "Random Forest")
rf_metrics["params"] = {"n_estimators": 200, "max_depth": best_depth + 2, "class_weight": "balanced"}
joblib.dump(rf, os.path.join(MODELS_DIR, "vulnsense_model_rf.joblib"))

# ── Baseline (CVSS threshold rule) ───────────────────────────
def rule_label(s):
    return "High" if s >= 7.0 else "Medium" if s >= 4.0 else "Low"

df_test = df.loc[X_test.index].copy()
y_baseline = df_test["cvss_base_score_audit"].apply(rule_label)
bl_acc = accuracy_score(y_test, y_baseline)
bl_f1  = f1_score(y_test, y_baseline, average="weighted", zero_division=0)
print(f"\nBaseline (CVSS threshold) — Acc: {bl_acc:.4f}  F1: {bl_f1:.4f}")

# ── Select best model ─────────────────────────────────────────
# RF wins on F1; DT wins ties (interpretability preference)
best_name = "Random Forest" if rf_metrics["cv_f1"] > dt_metrics["cv_f1"] else "Decision Tree"
best_model = rf if best_name == "Random Forest" else dt
print(f"\nBest model: {best_name}")
joblib.dump(best_model, os.path.join(MODELS_DIR, "vulnsense_model.joblib"))

# Copy best confusion matrix as the default
import shutil
best_tag = "rf" if best_name == "Random Forest" else "dt"
shutil.copy(
    os.path.join(MODELS_DIR, f"confusion_matrix_{best_tag}.png"),
    os.path.join(MODELS_DIR, "confusion_matrix.png")
)

# ── Feature importances ───────────────────────────────────────
feat_names   = CATEGORICAL + NUMERIC
feat_imp_dt  = sorted(zip(feat_names, dt.feature_importances_.tolist()), key=lambda x: x[1], reverse=True)
feat_imp_rf  = sorted(zip(feat_names, rf.feature_importances_.tolist()), key=lambda x: x[1], reverse=True)

# ── Save preprocessor ─────────────────────────────────────────
joblib.dump(preprocessor, os.path.join(MODELS_DIR, "vulnsense_preprocessor.joblib"))

# ── Save evaluation report ────────────────────────────────────
eval_report = {
    "best_model":  best_name,
    "models": {
        "Decision Tree":  dt_metrics,
        "Random Forest":  rf_metrics,
    },
    "baseline": {
        "accuracy":    round(bl_acc, 4),
        "f1":          round(bl_f1, 4),
        "description": "CVSS score threshold only (>= 7.0 → High, >= 4.0 → Medium)",
    },
    # Top-level fields kept for backward compat with dashboard
    "accuracy":   rf_metrics["accuracy"] if best_name == "Random Forest" else dt_metrics["accuracy"],
    "precision":  rf_metrics["precision"] if best_name == "Random Forest" else dt_metrics["precision"],
    "recall":     rf_metrics["recall"] if best_name == "Random Forest" else dt_metrics["recall"],
    "f1":         rf_metrics["f1"] if best_name == "Random Forest" else dt_metrics["f1"],
    "cv_f1":      rf_metrics["cv_f1"] if best_name == "Random Forest" else dt_metrics["cv_f1"],
    "per_class":  rf_metrics["per_class"] if best_name == "Random Forest" else dt_metrics["per_class"],
    "confusion_matrix": rf_metrics["confusion_matrix"] if best_name == "Random Forest" else dt_metrics["confusion_matrix"],
    "model_params": best_model.get_params(),
}

with open(os.path.join(MODELS_DIR, "evaluation_report.json"), "w") as f:
    json.dump(eval_report, f, indent=2)

with open(os.path.join(MODELS_DIR, "feature_importance.json"), "w") as f:
    json.dump({"Decision Tree": feat_imp_dt, "Random Forest": feat_imp_rf}, f, indent=2)

print(f"\n[Done] Models saved to {MODELS_DIR}/")
print(f"  Best: {best_name}  (CV F1={max(dt_metrics['cv_f1'], rf_metrics['cv_f1']):.4f})")
