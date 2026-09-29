"""Import endpoint tests."""

from pathlib import Path

import pytest

from qscout.import_endpoint import detect_format, import_endpoint
from qscout.models import ScanContext

FIXTURES = Path(__file__).parent / "fixtures"


def test_import_testssl() -> None:
    ctx = ScanContext(ownership_attestation=True)
    result = import_endpoint(FIXTURES / "testssl_sample.json", ctx)
    assert any(f.check_id == "CRYPTO-008" for f in result.findings)


def test_import_ssh_audit() -> None:
    ctx = ScanContext(ownership_attestation=True)
    result = import_endpoint(FIXTURES / "ssh_audit_sample.json", ctx)
    assert len(result.findings) > 0


def test_import_sonar() -> None:
    ctx = ScanContext(ownership_attestation=True)
    result = import_endpoint(FIXTURES / "sonar_sample.json", ctx)
    check_ids = {f.check_id for f in result.findings}
    assert "CRYPTO-011" in check_ids


def test_import_requires_attestation() -> None:
    with pytest.raises(ValueError):
        import_endpoint(FIXTURES / "testssl_sample.json", ScanContext())


def test_detect_format() -> None:
    assert detect_format(FIXTURES / "testssl_sample.json") == "testssl"
