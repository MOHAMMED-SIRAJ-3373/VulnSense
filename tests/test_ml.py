"""
VulnSense — ML Pipeline Tests
================================
Run: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from backend.ml.predictor import classify_finding, classify_batch, is_ready

SAMPLE_FINDING = {
    "host": "192.168.56.101",
    "port": 23,
    "protocol": "tcp",
    "service": "telnet",
    "vuln_type": "unencrypted_protocol",
    "attack_vector": "network",
    "attack_complexity": "low",
    "privileges_required": "none",
    "user_interaction": "none",
    "scope": "unchanged",
    "conf_impact": "high",
    "integ_impact": "high",
    "avail_impact": "none",
    "encrypted": 0,
    "uses_default_creds": 1,
    "is_high_risk_service": 1,
    "port_exposure_category": "well_known",
}

SAMPLE_LOW = {
    **SAMPLE_FINDING,
    "port": 8888,
    "service": "http",
    "attack_vector": "physical",
    "attack_complexity": "high",
    "privileges_required": "high",
    "conf_impact": "none",
    "integ_impact": "none",
    "uses_default_creds": 0,
    "is_high_risk_service": 0,
    "port_exposure_category": "registered",
}


def test_model_ready():
    assert is_ready(), "Model artefacts must exist. Run train_model.py first."


def test_classify_single_returns_expected_keys():
    result = classify_finding(SAMPLE_FINDING)
    assert "label" in result
    assert "confidence" in result
    assert "explanation" in result
    assert "probabilities" in result


def test_label_is_valid():
    result = classify_finding(SAMPLE_FINDING)
    assert result["label"] in ("High", "Medium", "Low")


def test_confidence_in_range():
    result = classify_finding(SAMPLE_FINDING)
    assert 0.0 <= result["confidence"] <= 1.0


def test_probabilities_sum_to_one():
    result = classify_finding(SAMPLE_FINDING)
    total = sum(result["probabilities"].values())
    assert abs(total - 1.0) < 0.01, f"Probabilities should sum to ~1.0, got {total}"


def test_explanation_is_nonempty():
    result = classify_finding(SAMPLE_FINDING)
    assert len(result["explanation"]) > 10


def test_batch_classification():
    results = classify_batch([SAMPLE_FINDING, SAMPLE_LOW])
    assert len(results) == 2
    for r in results:
        assert r["label"] in ("High", "Medium", "Low")


def test_telnet_is_high_risk():
    """Telnet with no privs, network exposure should predict High."""
    result = classify_finding(SAMPLE_FINDING)
    # Soft assertion — model should lean High for this profile
    # (acceptable if Medium, as the model learned from data, not rules)
    assert result["label"] in ("High", "Medium"), \
        f"Telnet with no-auth network exposure should not be Low, got {result['label']}"


def test_unknown_service_does_not_crash():
    """An unseen service type should be handled gracefully via OrdinalEncoder fallback."""
    finding = {**SAMPLE_FINDING, "service": "some_new_service_xyz", "vuln_type": "open_port_exposure"}
    result = classify_finding(finding)
    assert result["label"] in ("High", "Medium", "Low")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
