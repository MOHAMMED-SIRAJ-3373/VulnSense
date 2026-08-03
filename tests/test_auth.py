"""
VulnSense — Auth Layer Tests
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.utils.auth import hash_password, verify_password


def test_hash_password_returns_string():
    h = hash_password("testpassword")
    assert isinstance(h, str)
    assert len(h) > 20


def test_hash_is_not_plaintext():
    h = hash_password("secret123")
    assert "secret123" not in h


def test_verify_correct_password():
    h = hash_password("correct_horse_battery_staple")
    assert verify_password("correct_horse_battery_staple", h) is True


def test_verify_wrong_password():
    h = hash_password("correct_horse_battery_staple")
    assert verify_password("wrong_password", h) is False


def test_hash_is_unique_per_call():
    """bcrypt salts should produce different hashes for the same plaintext."""
    h1 = hash_password("samepassword")
    h2 = hash_password("samepassword")
    assert h1 != h2  # different salts
    assert verify_password("samepassword", h1) is True
    assert verify_password("samepassword", h2) is True


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
