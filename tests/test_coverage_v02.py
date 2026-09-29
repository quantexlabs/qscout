"""Coverage tests for v0.2.0 code paths."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qscout.cli import _load_cbom, app, cbom_round_trip
from qscout.collectors.config_tls import collect_tls_config
from qscout.emit.cyclonedx import emit_cbom
from qscout.models import (
    CryptoComponent,
    ScanContext,
    ScanResult,
    Severity,
)
from qscout.parsers.sonar import parse_sonar_cbom
from qscout.parsers.x509 import parse_certificate
from qscout.registry import classify_algorithm
from qscout.scan import ScanTimeoutError, scan_path

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_scan_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from concurrent.futures import TimeoutError as FuturesTimeout

    class FakeFuture:
        def result(self, timeout: float | None = None) -> object:
            raise FuturesTimeout()

    class FakePool:
        def __enter__(self) -> "FakePool":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def submit(self, *args: object, **kwargs: object) -> FakeFuture:
            return FakeFuture()

    monkeypatch.setattr("qscout.scan.ProcessPoolExecutor", lambda **kwargs: FakePool())
    with pytest.raises(ScanTimeoutError):
        scan_path(
            FIXTURES / "python_rsa",
            ScanContext(ownership_attestation=True, scan_timeout_seconds=5),
        )


def test_certificate_component_in_cbom(generate_certs: None) -> None:
    cert_path = FIXTURES / "certs" / "rsa2048.pem"
    if not cert_path.exists():
        pytest.skip("certs not generated")
    result = parse_certificate(cert_path)
    findings, components = __import__(
        "qscout.checks.engine", fromlist=["evaluate_evidence"]
    ).evaluate_evidence(result.evidence)
    scan = ScanResult(findings=findings, components=components, target="certs")
    cbom = emit_cbom(scan)
    cert_comp = next(
        c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate"
    )
    assert "certificateProperties" in cert_comp["cryptoProperties"]


def test_sonar_cbom_algorithm_properties(tmp_path: Path) -> None:
    data = {
        "components": [
            {
                "name": "RSA-2048",
                "bom-ref": "rsa-1",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "algorithmFamily": "RSA",
                        "parameterSetIdentifier": "2048",
                    },
                },
            }
        ]
    }
    path = tmp_path / "sonar.json"
    path.write_text(json.dumps(data))
    result = parse_sonar_cbom(path)
    assert any(e["kind"] == "rsa_encrypt" for e in result.evidence)


def test_sonar_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{bad")
    result = parse_sonar_cbom(path)
    assert result.errors[0].error_type == "json_parse_error"


def test_tls_config_read_error(tmp_path: Path) -> None:
    missing = tmp_path / "nginx.conf"
    result = collect_tls_config(missing)
    assert result.errors


def test_load_cbom_with_certificate_component(tmp_path: Path) -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": "test"}},
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "server-cert",
                "bom-ref": "cert-1",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": "CN=test",
                        "issuerName": "CN=ca",
                        "notValidBefore": "2025-01-01T00:00:00Z",
                        "notValidAfter": "2026-01-01T00:00:00Z",
                    },
                },
            }
        ],
        "vulnerabilities": [],
        "properties": [],
    }
    result = _load_cbom(cbom, tmp_path / "cbom.json")
    assert result.components[0].asset_type == "certificate"
    assert result.components[0].subject_name == "CN=test"


def test_classify_sha256() -> None:
    record = classify_algorithm("SHA-256")
    assert record.quantum_status.value == "quantum_affected"


def test_classify_unknown_algorithm() -> None:
    record = classify_algorithm("CUSTOM-ALGO")
    assert record.quantum_status.value == "unknown"


def test_engine_dsa_signature_path() -> None:
    from qscout.checks.engine import evaluate_evidence

    findings, _ = evaluate_evidence(
        [{"kind": "signature", "location": "x", "algorithm": "DSA", "evidence_type": "source"}]
    )
    assert any(f.check_id == "CRYPTO-005" for f in findings)


def test_engine_aes_symmetric_finding() -> None:
    from qscout.checks.engine import evaluate_evidence

    findings, _ = evaluate_evidence(
        [
            {
                "kind": "symmetric",
                "location": "crypto.py",
                "algorithm": "AES-256",
                "evidence_type": "source",
                "confidence": "confirmed",
            }
        ]
    )
    assert any(f.check_id == "CRYPTO-011" for f in findings)


def test_cli_scan_with_report(tmp_path: Path) -> None:
    html = tmp_path / "out.html"
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "configs"),
            "--attest-ownership",
            "--report",
            str(html),
        ],
    )
    assert result.exit_code == 0
    assert html.exists()


def test_cbom_round_trip_certificate() -> None:
    original = ScanResult(
        findings=[],
        components=[
            CryptoComponent(
                name="RSA",
                algorithm="RSA",
                bom_ref="c1",
                asset_type="certificate",
                subject_name="CN=test",
                issuer_name="CN=ca",
            )
        ],
        target="t",
    )
    restored = cbom_round_trip(original)
    assert restored.components[0].asset_type == "certificate"


def test_parse_expired_certificate(generate_certs: None) -> None:
    cert_path = FIXTURES / "certs" / "expired.pem"
    if not cert_path.exists():
        pytest.skip("certs not generated")
    result = parse_certificate(cert_path)
    kinds = {e.get("kind") for e in result.evidence}
    assert "cert_metadata" in kinds or "cert_issue" in kinds


def test_parse_weak_rsa1024_certificate(generate_certs: None) -> None:
    cert_path = FIXTURES / "certs" / "rsa1024.pem"
    if not cert_path.exists():
        pytest.skip("certs not generated")
    result = parse_certificate(cert_path)
    assert any(e.get("kind") == "rsa_key_size" for e in result.evidence)


def test_scan_max_files_skipped(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"file{i}.txt").write_text("hello")
    result = scan_path(
        tmp_path,
        ScanContext(ownership_attestation=True, max_files=2, scan_timeout_seconds=0),
    )
    assert len(result.skipped_files) >= 1


def test_scan_directory_with_package_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{bad json")
    result = scan_path(
        tmp_path,
        ScanContext(ownership_attestation=True, scan_timeout_seconds=0),
    )
    assert any(e.error_type == "json_parse_error" for e in result.errors)


def test_registry_grover_levels() -> None:
    from qscout.registry import _grover_nist_level

    assert _grover_nist_level(256) == 5
    assert _grover_nist_level(128) == 3
    assert _grover_nist_level(64) == 0
    assert _grover_nist_level(32) == 0
    assert _grover_nist_level(None) is None


def test_registry_nist_pqc_levels() -> None:
    from qscout.registry import _nist_pqc_level

    assert _nist_pqc_level("ML-KEM-512") == 1
    assert _nist_pqc_level("ML-DSA-87") == 5
    assert _nist_pqc_level("SLH-DSA-SHA2-256s") == 3
    assert _nist_pqc_level("SLH-DSA") == 1


def test_registry_classical_levels() -> None:
    from qscout.registry import _classical_asymmetric_level

    assert _classical_asymmetric_level("RSA", 4096) == 3072
    assert _classical_asymmetric_level("RSA", None) is None


def test_manifests_requirements_error(tmp_path: Path) -> None:
    from qscout.parsers.manifests import parse_requirements_txt

    missing = tmp_path / "requirements.txt"
    result = parse_requirements_txt(missing)
    assert result.errors


def test_manifests_pqc_only_source(tmp_path: Path) -> None:
    from qscout.parsers.manifests import scan_python_source

    src = tmp_path / "pqc.py"
    src.write_text("import liboqs  # ML-KEM-768")
    result = scan_python_source(src)
    assert any(e["kind"] == "pqc_present" for e in result.evidence)


def test_cli_import_stdout() -> None:
    result = runner.invoke(
        app,
        [
            "import-endpoint",
            str(FIXTURES / "testssl_sample.json"),
            "--attest-ownership",
        ],
    )
    assert result.exit_code == 0
    assert "findings" in result.stdout


def test_cli_prioritize_stdout(tmp_path: Path) -> None:
    scan_out = tmp_path / "scan.json"
    runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "configs"),
            "--attest-ownership",
            "--output",
            str(scan_out),
        ],
    )
    result = runner.invoke(
        app,
        [
            "prioritize",
            str(scan_out),
            "--context",
            str(FIXTURES / "systems.yaml"),
        ],
    )
    assert result.exit_code == 0


def test_report_safe_location_fallback() -> None:
    from qscout.emit.report import _safe_location

    assert "file.py" in _safe_location("file.py")


def test_parse_der_certificate(generate_certs: None) -> None:
    import subprocess

    cert_path = FIXTURES / "certs" / "rsa2048.pem"
    der_path = FIXTURES / "certs" / "rsa2048.der"
    if not cert_path.exists():
        pytest.skip("certs not generated")
    if not der_path.exists():
        subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-outform", "DER", "-out", str(der_path)],
            check=True,
            capture_output=True,
        )
    result = parse_certificate(der_path)
    assert result.evidence


def test_parse_oversized_certificate(tmp_path: Path) -> None:
    big = tmp_path / "big.pem"
    big.write_bytes(b"0" * 200)
    result = parse_certificate(big, max_bytes=50)
    assert result.errors[0].error_type == "oversized_file"


def test_scan_skips_oversized_in_directory(tmp_path: Path) -> None:
    small = tmp_path / "ok.py"
    small.write_text("x = 1")
    big = tmp_path / "big.py"
    big.write_text("x" * 500)
    result = scan_path(
        tmp_path,
        ScanContext(ownership_attestation=True, max_file_bytes=100, scan_timeout_seconds=0),
    )
    assert any(e.error_type == "oversized_file" for e in result.errors)
    assert str(big) in result.skipped_files


def test_sonar_oversized(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text("x" * 200)
    result = parse_sonar_cbom(path, max_bytes=50)
    assert result.errors[0].error_type == "oversized_file"


def test_ssh_audit_oversized(tmp_path: Path) -> None:
    from qscout.parsers.ssh_audit import parse_ssh_audit

    path = tmp_path / "big.json"
    path.write_text("x" * 200)
    result = parse_ssh_audit(path, max_bytes=50)
    assert result.errors[0].error_type == "oversized_file"


def test_registry_aes128_vulnerable() -> None:
    record = classify_algorithm("AES-128")
    assert record.quantum_status.value == "quantum_vulnerable"


def test_registry_aes_unknown_bits() -> None:
    record = classify_algorithm("AES")
    assert record.classical_security_level == 256


def test_scan_path_blocked_symlink(tmp_path: Path) -> None:
    base = tmp_path / "scanbase"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.pem"
    secret.write_text("not a real cert")
    link = base / "escape.pem"
    link.symlink_to(secret)
    result = scan_path(
        base,
        ScanContext(ownership_attestation=True, scan_timeout_seconds=0),
    )
    assert any(e.error_type == "path_blocked" for e in result.errors)


def test_report_many_skipped_files() -> None:
    from qscout.emit.report import render_html

    skipped = [f"/file{i}.txt" for i in range(55)]
    html = render_html(ScanResult(findings=[], target="t", skipped_files=skipped))
    assert "and 5 more" in html


def test_score_invalid_systems_yaml(tmp_path: Path) -> None:
    from qscout.score import load_systems_yaml

    bad = tmp_path / "systems.yaml"
    bad.write_text("not: a: valid: yaml: [")
    from qscout.security import SecurityError

    with pytest.raises(SecurityError):
        load_systems_yaml(bad)


def test_score_missing_systems_key(tmp_path: Path) -> None:
    from qscout.score import load_systems_yaml

    bad = tmp_path / "systems.yaml"
    bad.write_text("foo: bar")
    with pytest.raises(ValueError, match="systems"):
        load_systems_yaml(bad)


def test_load_cbom_invalid_metadata_json(tmp_path: Path) -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": "t"}},
        "components": [],
        "vulnerabilities": [
            {
                "id": "CRYPTO-001",
                "description": "x",
                "recommendation": "t",
                "properties": [
                    {"name": "evidence_type", "value": "source"},
                    {"name": "confidence", "value": "confirmed"},
                    {"name": "location", "value": "a.py"},
                    {"name": "severity", "value": "high"},
                    {"name": "result", "value": "fail"},
                    {"name": "metadata", "value": "not-json"},
                ],
            }
        ],
        "properties": [],
    }
    result = _load_cbom(cbom, tmp_path / "cbom.json")
    assert result.findings[0].metadata == {}


def test_load_cbom_vulnerability_fallback_analysis() -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": "t"}},
        "components": [],
        "vulnerabilities": [
            {
                "id": "CRYPTO-001",
                "description": "weak",
                "recommendation": "title",
                "analysis": {"state": "exploitable"},
                "properties": [
                    {"name": "evidence_type", "value": "source"},
                    {"name": "confidence", "value": "confirmed"},
                    {"name": "location", "value": "a.py"},
                    {"name": "severity", "value": "high"},
                    {"name": "result", "value": "fail"},
                ],
            }
        ],
        "properties": [],
    }
    result = _load_cbom(cbom, Path("x.json"))
    assert result.findings[0].severity == Severity.HIGH
