"""Unit tests for cryptographic utilities and pseudonymization."""

import pytest
from aegis_wm.common.crypto import compute_sha256, pseudonymize_ip, pseudonymize_endpoint


def test_sha256_computation():
    data = "aegis_wm_test_payload"
    h1 = compute_sha256(data)
    h2 = compute_sha256(data)
    assert len(h1) == 64
    assert h1 == h2


def test_pseudonymization_consistency_and_format():
    ip1 = "192.168.10.50"
    pseudo1 = pseudonymize_ip(ip1)
    pseudo2 = pseudonymize_ip(ip1)
    assert pseudo1.startswith("host_")
    assert pseudo1 == pseudo2


def test_pseudonymization_different_ips():
    ip1 = "192.168.10.50"
    ip2 = "192.168.10.51"
    pseudo1 = pseudonymize_ip(ip1)
    pseudo2 = pseudonymize_ip(ip2)
    assert pseudo1 != pseudo2


def test_pseudonymize_endpoint():
    ep = pseudonymize_endpoint("10.0.0.1", 443)
    assert ep.endswith(":443")
    assert ep.startswith("host_")
