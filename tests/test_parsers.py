"""Parser tests."""

from pathlib import Path

from qscout.parsers.sonar import parse_sonar_cbom
from qscout.parsers.ssh_audit import parse_ssh_audit
from qscout.parsers.testssl import parse_testssl
from qscout.parsers.x509 import parse_certificate

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_testssl(fixtures_dir: Path) -> None:
    result = parse_testssl(fixtures_dir / "testssl_sample.json")
    kinds = {e["kind"] for e in result.evidence}
    assert "weak_tls" in kinds
    assert "ecdh" in kinds


def test_parse_ssh_audit(fixtures_dir: Path) -> None:
    result = parse_ssh_audit(fixtures_dir / "ssh_audit_sample.json")
    kinds = {e["kind"] for e in result.evidence}
    assert "rsa_key_size" in kinds or "ecdh" in kinds
    assert "weak_hash" in kinds


def test_parse_sonar(fixtures_dir: Path) -> None:
    result = parse_sonar_cbom(fixtures_dir / "sonar_sample.json")
    kinds = {e["kind"] for e in result.evidence}
    assert "pqc_present" in kinds
    assert "unresolved_dependency" in kinds
    assert "stateful_hash" in kinds


def test_parse_certificate_weak_key() -> None:
    cert_path = FIXTURES / "certs" / "rsa1024.pem"
    if cert_path.exists():
        result = parse_certificate(cert_path)
        kinds = {e["kind"] for e in result.evidence}
        assert "rsa_key_size" in kinds or "cert_issue" in kinds


def test_parse_certificate_invalid_returns_error(tmp_path: Path) -> None:
    bad = tmp_path / "invalid.pem"
    bad.write_text("not a cert")
    result = parse_certificate(bad)
    assert result.errors
    assert result.errors[0].error_type == "certificate_parse_error"
