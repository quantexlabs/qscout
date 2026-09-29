"""Additional tests for coverage gaps."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qscout.cli import app
from qscout.import_endpoint import detect_format
from qscout.models import ScanContext, ScanResult
from qscout.parsers.manifests import parse_package_json, scan_python_source
from qscout.scan import scan_path
from qscout.score import load_scan_result_json, prioritize_findings

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_parse_package_json(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"node-forge": "^1.0.0"}}))
    result = parse_package_json(pkg)
    assert any(e["kind"] == "unresolved_dependency" for e in result.evidence)


def test_scan_python_source_dsa(tmp_path: Path) -> None:
    src = tmp_path / "sign.py"
    src.write_text("from cryptography.hazmat.primitives.asymmetric import dsa\nDSAPrivateKey")
    result = scan_python_source(src)
    assert any(e.get("algorithm") == "DSA" for e in result.evidence)


def test_load_scan_result_json(tmp_path: Path) -> None:
    scan = ScanResult(target="demo", findings=[])
    path = tmp_path / "scan.json"
    path.write_text(scan.model_dump_json())
    loaded = load_scan_result_json(path)
    assert loaded.target == "demo"


def test_prioritize_with_system_id() -> None:
    from qscout.models import CheckResult, Confidence, EvidenceType, Finding, Severity
    from qscout.score import load_systems_yaml

    systems = load_systems_yaml(FIXTURES / "systems.yaml")
    scan = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-002",
                title="RSA",
                result=CheckResult.FAIL,
                severity=Severity.HIGH,
                evidence_type=EvidenceType.SOURCE,
                confidence=Confidence.CONFIRMED,
                location="a",
                message="rsa",
                algorithm="RSA",
            )
        ]
    )
    prioritized = prioritize_findings(scan, systems, default_system_id="internal-api")
    assert prioritized[0].system_id == "internal-api"


def test_scan_nonexistent_path() -> None:
    with pytest.raises(FileNotFoundError):
        scan_path(Path("/nonexistent/qscout-target"), ScanContext(ownership_attestation=True))


def test_cli_scan_stdout_only() -> None:
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "configs"), "--attest-ownership"],
    )
    assert result.exit_code == 0
    assert "findings" in result.stdout


def test_cli_report_with_context(tmp_path: Path) -> None:
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
    html_out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        [
            "report",
            str(scan_out),
            "--output",
            str(html_out),
            "--context",
            str(FIXTURES / "systems.yaml"),
        ],
    )
    assert result.exit_code == 0


def test_cli_prioritize_report(tmp_path: Path) -> None:
    scan_out = tmp_path / "scan.json"
    runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "python_rsa"),
            "--attest-ownership",
            "--output",
            str(scan_out),
        ],
    )
    html_out = tmp_path / "prio.html"
    result = runner.invoke(
        app,
        [
            "prioritize",
            str(scan_out),
            "--context",
            str(FIXTURES / "systems.yaml"),
            "--report",
            str(html_out),
        ],
    )
    assert result.exit_code == 0


def test_import_unknown_format(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"unknown": true}')
    with pytest.raises(ValueError):
        detect_format(bad)


def test_main_module() -> None:
    import runpy
    from unittest.mock import patch

    with patch("sys.argv", ["qscout", "--version"]):
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("qscout", run_name="__main__")
        assert exc_info.value.code == 0
