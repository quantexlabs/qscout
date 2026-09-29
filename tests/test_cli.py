"""CLI tests."""

import json
from pathlib import Path

from typer.testing import CliRunner

from qscout.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.stdout


def test_scan_without_attestation_fails() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "python_rsa")])
    assert result.exit_code != 0


def test_scan_with_attestation(tmp_path: Path) -> None:
    out = tmp_path / "cbom.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "python_rsa"),
            "--attest-ownership",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["bomFormat"] == "CycloneDX"


def test_import_endpoint(tmp_path: Path) -> None:
    out = tmp_path / "cbom.json"
    result = runner.invoke(
        app,
        [
            "import-endpoint",
            str(FIXTURES / "testssl_sample.json"),
            "--attest-ownership",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0


def test_prioritize(tmp_path: Path) -> None:
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
    prio_out = tmp_path / "prio.json"
    result = runner.invoke(
        app,
        [
            "prioritize",
            str(scan_out),
            "--context",
            str(FIXTURES / "systems.yaml"),
            "--output",
            str(prio_out),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(prio_out.read_text())
    assert isinstance(data, list)


def test_report(tmp_path: Path) -> None:
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
        ["report", str(scan_out), "--output", str(html_out)],
    )
    assert result.exit_code == 0
    assert "<h1>" in html_out.read_text()


def test_malicious_url_in_metadata_not_in_cli() -> None:
    """CLI does not accept URLs for scan target paths."""
    result = runner.invoke(
        app,
        ["scan", "javascript:alert(1)", "--attest-ownership"],
    )
    assert result.exit_code != 0
