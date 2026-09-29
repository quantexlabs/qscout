"""Regression tests for v0.2.0 review findings."""

from pathlib import Path

import pytest

from qscout.checks.engine import evaluate_evidence
from qscout.emit.report import render_html
from qscout.models import ScanContext, ScanResult
from qscout.parsers.manifests import parse_package_json, scan_python_source
from qscout.parsers.x509 import parse_certificate
from qscout.registry import classify_algorithm, detect_hybrid, normalize_algorithm
from qscout.scan import scan_path
from qscout.security import redact_secrets

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx() -> ScanContext:
    return ScanContext(ownership_attestation=True, scan_timeout_seconds=0)


def test_malformed_certificate_returns_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    result = parse_certificate(bad)
    assert not result.evidence
    assert len(result.errors) == 1
    assert result.errors[0].error_type == "certificate_parse_error"


def test_malformed_package_json_returns_error(tmp_path: Path) -> None:
    bad = tmp_path / "package.json"
    bad.write_text("{not valid json")
    result = parse_package_json(bad)
    assert not result.evidence
    assert result.errors[0].error_type == "json_parse_error"


def test_oversized_file_recorded_as_error(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.write_text("x = 1\n")
    result = scan_path(
        big,
        ScanContext(ownership_attestation=True, max_file_bytes=1, scan_timeout_seconds=0),
    )
    assert any(e.error_type == "oversized_file" for e in result.errors)


def test_scan_reports_parser_errors_in_cbom_and_html(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("garbage")
    result = scan_path(bad, _ctx())
    assert len(result.errors) >= 1
    html = render_html(result)
    assert "Scan errors:" in html
    assert "certificate_parse_error" in html


def test_rsa2048_cert_classical_not_cert_defect(generate_certs: None) -> None:
    cert_path = FIXTURES / "certs" / "rsa2048.pem"
    if not cert_path.exists():
        pytest.skip("certs not generated")
    result = parse_certificate(cert_path)
    kinds = {e["kind"] for e in result.evidence}
    assert "classical_asymmetric" in kinds
    assert not any(
        e.get("kind") == "cert_issue" and "classical" in e.get("message", "").lower()
        for e in result.evidence
    )


def test_hybrid_crypto_detection(tmp_path: Path) -> None:
    src = tmp_path / "hybrid.py"
    src.write_text("from oqs import KeyEncapsulation\n# ML-KEM with ECDH fallback\nECDH exchange")
    evidence = scan_python_source(src).evidence
    assert any(e["kind"] == "hybrid_crypto" for e in evidence)
    findings, _ = evaluate_evidence(evidence)
    assert any("Hybrid" in f.message for f in findings)


def test_slh_dsa_parameter_set_preserved() -> None:
    assert normalize_algorithm("SLH-DSA-SHA2-128s") == "SLH-DSA-SHA2-128s"


def test_unknown_rsa_key_size_not_assumed_strong() -> None:
    findings, _ = evaluate_evidence(
        [
            {
                "kind": "rsa_key_size",
                "location": "ssh:host",
                "algorithm": "RSA",
                "evidence_type": "endpoint",
                "confidence": "confirmed",
                "metadata": {"key_size_unknown": True},
            }
        ]
    )
    assert any(f.check_id == "CRYPTO-001" and f.result.value == "info" for f in findings)
    assert not any(f.check_id == "CRYPTO-001" and f.result.value == "fail" for f in findings)


def test_aes_classification_quantum_affected() -> None:
    record = classify_algorithm("AES-256")
    assert record.quantum_status.value == "quantum_affected"
    assert record.classical_security_level == 256


def test_hybrid_record() -> None:
    record = detect_hybrid("ECDH", "ML-KEM-768")
    assert record.hybrid is True
    assert "ML-KEM-768" in record.hybrid_components
    assert "ECDH" in record.hybrid_components


def test_redaction_in_report_output() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "SECRETKEYBODY\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = ScanResult(
        findings=[],
        target=redact_secrets(pem),
    )
    html = render_html(result)
    assert "SECRETKEYBODY" not in html
    assert "END RSA PRIVATE KEY" not in html
