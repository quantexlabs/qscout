"""Emitter tests."""

import json
from pathlib import Path

import jsonschema

from qscout.cli import cbom_round_trip
from qscout.emit.cyclonedx import emit_cbom
from qscout.emit.report import render_html
from qscout.models import (
    CheckResult,
    Confidence,
    CryptoComponent,
    EvidenceType,
    Finding,
    QuantumStatus,
    ScanError,
    ScanResult,
    Severity,
)


def _schema_path() -> Path:
    return Path(__file__).parent.parent / "src" / "qscout" / "schemas" / "bom-1.6.schema.json"


def test_emit_cbom_structure() -> None:
    result = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-002",
                title="RSA encrypt",
                result=CheckResult.FAIL,
                severity=Severity.HIGH,
                evidence_type=EvidenceType.SOURCE,
                confidence=Confidence.CONFIRMED,
                location="app.py",
                message="RSA encryption",
                algorithm="RSA",
            )
        ],
        components=[
            CryptoComponent(
                name="RSA",
                algorithm="RSA",
                bom_ref="ref-1",
                key_size=2048,
                asset_type="algorithm",
                parameter_set="2048",
                primitive="pke",
                classical_security_level=2048,
                nist_quantum_security_level=0,
                quantum_status=QuantumStatus.QUANTUM_VULNERABLE,
            ),
        ],
        target="test-app",
        errors=[
            ScanError(path="bad.pem", error_type="certificate_parse_error", message="invalid"),
        ],
        skipped_files=["/tmp/huge.bin"],
    )
    cbom = emit_cbom(result)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 1
    assert len(cbom["vulnerabilities"]) == 1
    crypto = cbom["components"][0]["cryptoProperties"]
    assert crypto["assetType"] == "algorithm"
    assert "algorithmProperties" in crypto
    assert crypto["algorithmProperties"]["primitive"] == "pke"
    props = {p["name"]: p["value"] for p in cbom["properties"]}
    assert props["qscout:error-count"] == "1"
    assert props["qscout:skipped-file-count"] == "1"


def test_cbom_validates_against_cyclonedx_schema() -> None:
    result = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-011",
                title="PQC present",
                result=CheckResult.INFO,
                severity=Severity.INFO,
                evidence_type=EvidenceType.SOURCE,
                confidence=Confidence.CONFIRMED,
                location="app.py",
                message="ML-KEM-768 present",
                algorithm="ML-KEM-768",
            )
        ],
        components=[
            CryptoComponent(
                name="ML-KEM-768",
                algorithm="ML-KEM-768",
                bom_ref="ref-kem",
                asset_type="algorithm",
                parameter_set="768",
                primitive="kem",
                nist_quantum_security_level=3,
                quantum_status=QuantumStatus.POST_QUANTUM,
            ),
        ],
        target="schema-test",
    )
    cbom = emit_cbom(result)
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    jsonschema.validate(cbom, schema)


def test_vendored_schema_has_license() -> None:
    license_path = _schema_path().parent / "LICENSE"
    assert license_path.exists()
    text = license_path.read_text(encoding="utf-8")
    assert "Apache" in text
    assert "cyclonedx.org" in text


def test_cbom_round_trip_preserves_findings() -> None:
    original = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-002",
                title="RSA encrypt",
                result=CheckResult.FAIL,
                severity=Severity.HIGH,
                evidence_type=EvidenceType.SOURCE,
                confidence=Confidence.CONFIRMED,
                location="app.py",
                message="RSA encryption",
                algorithm="RSA",
                metadata={"line": 42},
            )
        ],
        components=[
            CryptoComponent(
                name="RSA",
                algorithm="RSA",
                bom_ref="ref-1",
                key_size=2048,
                asset_type="algorithm",
                primitive="pke",
            ),
        ],
        target="round-trip-test",
        errors=[ScanError(path="x", error_type="read_error", message="fail")],
        skipped_files=["/skipped"],
    )
    restored = cbom_round_trip(original)
    assert len(restored.findings) == 1
    f = restored.findings[0]
    assert f.check_id == "CRYPTO-002"
    assert f.severity == Severity.HIGH
    assert f.result == CheckResult.FAIL
    assert f.algorithm == "RSA"
    assert f.metadata == {"line": 42}
    assert len(restored.components) == 1
    assert restored.components[0].bom_ref == "ref-1"
    assert len(restored.errors) == 1
    assert restored.skipped_files == ["/skipped"]


def test_render_html_accessibility() -> None:
    result = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-001",
                title="Weak RSA",
                result=CheckResult.FAIL,
                severity=Severity.HIGH,
                evidence_type=EvidenceType.CERTIFICATE,
                confidence=Confidence.CONFIRMED,
                location='cert.pem"><script>alert(1)</script>',
                message="1024-bit RSA",
            )
        ],
        target="demo",
        errors=[ScanError(path="bad.json", error_type="json_parse_error", message="bad")],
        skipped_files=["/big/file"],
    )
    html = render_html(result)
    assert "<h1>" in html
    assert 'role="main"' in html
    assert "<caption>" in html
    assert 'scope="col"' in html
    assert "focus-visible" in html
    assert "Critical" in html or "High" in html
    assert "<script>" not in html
    assert "Scan errors:" in html
    assert "Skipped files:" in html
    assert "json_parse_error" in html


def test_render_html_hostile_certificate_hostname() -> None:
    result = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-009",
                title="Cert issue",
                result=CheckResult.FAIL,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.CERTIFICATE,
                confidence=Confidence.CONFIRMED,
                location='CN=<img src=x onerror=alert(1)>',
                message="expired",
            )
        ],
        target="demo",
    )
    html = render_html(result)
    assert "<img" not in html
    assert "&lt;img" in html
