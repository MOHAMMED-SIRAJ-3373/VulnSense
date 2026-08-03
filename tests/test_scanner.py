"""
VulnSense — Scanner Module Tests
Tests target validation and feature extraction logic.
Does NOT actually perform network scans (no VM required).
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from backend.scanner.network_scan import _is_private_ip, _validate_target


def test_private_ip_192():
    assert _is_private_ip("192.168.56.101") is True


def test_private_ip_10():
    assert _is_private_ip("10.0.0.5") is True


def test_private_ip_172():
    assert _is_private_ip("172.16.0.1") is True


def test_public_ip_is_not_private():
    assert _is_private_ip("8.8.8.8") is False


def test_validate_target_rejects_public():
    with pytest.raises(ValueError, match="private"):
        _validate_target("8.8.8.8")


def test_validate_target_accepts_private():
    # Should not raise
    _validate_target("192.168.56.101")


def test_validate_target_accepts_10_block():
    _validate_target("10.10.10.1")


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
