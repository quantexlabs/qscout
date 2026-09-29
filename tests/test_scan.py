"""Scan integration tests."""

from pathlib import Path

import pytest

from qscout.models import ScanContext
from qscout.scan import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_requires_attestation() -> None:
    with pytest.raises(ValueError, match="attest-ownership"):
        scan_path(FIXTURES / "python_rsa", ScanContext(ownership_attestation=False))


def test_scan_python_rsa() -> None:
    ctx = ScanContext(ownership_attestation=True, scan_timeout_seconds=0)
    result = scan_path(FIXTURES / "python_rsa", ctx)
    check_ids = {f.check_id for f in result.findings}
    assert "CRYPTO-002" in check_ids
    assert "CRYPTO-006" in check_ids
    assert "CRYPTO-010" in check_ids


def test_scan_weak_tls_config() -> None:
    ctx = ScanContext(ownership_attestation=True, scan_timeout_seconds=0)
    result = scan_path(FIXTURES / "configs", ctx)
    assert any(f.check_id == "CRYPTO-008" for f in result.findings)


def test_scan_all_checks_fixture() -> None:
    ctx = ScanContext(ownership_attestation=True, scan_timeout_seconds=0)
    result = scan_path(FIXTURES / "all_checks.py", ctx)
    check_ids = {f.check_id for f in result.findings}
    expected = {
        "CRYPTO-001",
        "CRYPTO-003",
        "CRYPTO-004",
        "CRYPTO-006",
        "CRYPTO-007",
        "CRYPTO-011",
        "CRYPTO-012",
    }
    assert expected.intersection(check_ids)


def test_scan_certs(generate_certs: None) -> None:
    certs = FIXTURES / "certs"
    if not certs.exists():
        pytest.skip("certs not generated")
    ctx = ScanContext(ownership_attestation=True, scan_timeout_seconds=0)
    result = scan_path(certs, ctx)
    assert len(result.findings) > 0
