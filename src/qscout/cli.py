"""qscout CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from qscout import __version__
from qscout.emit.cyclonedx import emit_cbom, write_cbom
from qscout.emit.report import write_report
from qscout.import_endpoint import import_endpoint
from qscout.models import (
    CheckResult,
    Confidence,
    CryptoComponent,
    EvidenceType,
    Finding,
    ScanContext,
    ScanError,
    ScanResult,
    Severity,
)
from qscout.scan import scan_path
from qscout.score import load_systems_yaml, prioritize_findings
from qscout.security import sanitize_location

app = typer.Typer(
    name="qscout",
    help="Offline evidence fusion for post-quantum cryptography inventory.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"qscout {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """qscout CLI entry."""


@app.command("scan")
def scan_cmd(
    target: Path = typer.Argument(..., help="Path to scan."),
    attest_ownership: bool = typer.Option(
        False,
        "--attest-ownership",
        help="Confirm you own or are authorized to scan the target.",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="CBOM JSON output path."),
    report: Path | None = typer.Option(None, "--report", "-r", help="HTML report output path."),
) -> None:
    """Scan a local path for cryptographic evidence."""
    context = ScanContext(ownership_attestation=attest_ownership)
    result = scan_path(target, context)
    if output:
        write_cbom(result, str(output))
        typer.echo(f"CBOM written to {output}")
    if report:
        write_report(result, str(report))
        typer.echo(f"Report written to {report}")
    if not output and not report:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))


@app.command("import-endpoint")
def import_endpoint_cmd(
    source: Path = typer.Argument(..., help="testssl.sh, ssh-audit, or sonar JSON."),
    attest_ownership: bool = typer.Option(
        False,
        "--attest-ownership",
        help="Confirm you own or are authorized to import this data.",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="CBOM JSON output path."),
) -> None:
    """Import endpoint scan results from external tools."""
    context = ScanContext(ownership_attestation=attest_ownership)
    result = import_endpoint(source, context)
    if output:
        write_cbom(result, str(output))
        typer.echo(f"CBOM written to {output}")
    else:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))


@app.command("prioritize")
def prioritize_cmd(
    cbom_or_scan: Path = typer.Argument(..., help="CBOM or scan result JSON."),
    context: Path = typer.Option(
        ...,
        "--context",
        help="systems.yaml with criticality and confidentiality_years.",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Prioritized JSON output."),
    report: Path | None = typer.Option(None, "--report", "-r", help="HTML report output path."),
) -> None:
    """Prioritize findings using systems.yaml context."""
    systems = load_systems_yaml(context)
    scan_result = _load_input(cbom_or_scan)
    prioritized = prioritize_findings(scan_result, systems)
    if output:
        data = [p.model_dump(mode="json") for p in prioritized]
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        typer.echo(f"Prioritized findings written to {output}")
    if report:
        write_report(scan_result, str(report), prioritized)
        typer.echo(f"Report written to {report}")
    if not output and not report:
        typer.echo(json.dumps([p.model_dump(mode="json") for p in prioritized], indent=2))


@app.command("report")
def report_cmd(
    input_file: Path = typer.Argument(..., help="Scan result or CBOM JSON."),
    output: Path = typer.Option(..., "--output", "-o", help="HTML report path."),
    context: Path | None = typer.Option(
        None, "--context", help="Optional systems.yaml for priority scores."
    ),
) -> None:
    """Generate accessible HTML report from scan results."""
    scan_result = _load_input(input_file)
    prioritized = None
    if context:
        systems = load_systems_yaml(context)
        prioritized = prioritize_findings(scan_result, systems)
    write_report(scan_result, str(output), prioritized)
    typer.echo(f"Report written to {output}")


def _load_input(path: Path) -> ScanResult:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if "bomFormat" in data:
        return _load_cbom(data, path)
    return ScanResult.model_validate(data)


def _load_cbom(data: dict[str, Any], path: Path) -> ScanResult:
    props = {p["name"]: p["value"] for p in data.get("properties", []) if isinstance(p, dict)}
    errors_raw = json.loads(props.get("qscout:errors", "[]"))
    skipped_raw = json.loads(props.get("qscout:skipped-files", "[]"))
    scanned_at = props.get("qscout:scanned-at")

    findings_raw: list[Finding] = []
    for vuln in data.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        vprops = {p["name"]: p["value"] for p in vuln.get("properties", []) if isinstance(p, dict)}
        severity_str = vprops.get("severity", "medium")
        result_str = vprops.get("result")
        if not result_str:
            analysis = vuln.get("analysis", {})
            if isinstance(analysis, dict):
                result_str = (
                    "fail" if analysis.get("state") == "exploitable" else "info"
                )
            else:
                result_str = "info"
        metadata_raw = vprops.get("metadata", "{}")
        try:
            metadata = json.loads(metadata_raw) if metadata_raw else {}
        except json.JSONDecodeError:
            metadata = {}
        location = vprops.get("location", "")
        if location:
            location = sanitize_location(location)
        findings_raw.append(
            Finding(
                check_id=str(vuln.get("id", "UNKNOWN")),
                title=str(vuln.get("recommendation", "")),
                result=CheckResult(result_str),
                severity=Severity(severity_str),
                algorithm=vprops.get("algorithm") or None,
                evidence_type=EvidenceType(vprops.get("evidence_type", "lexical")),
                confidence=Confidence(vprops.get("confidence", "inferred")),
                location=location,
                message=str(vuln.get("description", "")),
                standard_refs=vprops.get("standard_refs", "").split("; ")
                if vprops.get("standard_refs")
                else [],
                metadata=metadata if isinstance(metadata, dict) else {},
            )
        )

    components: list[CryptoComponent] = []
    for comp in data.get("components", []):
        if not isinstance(comp, dict):
            continue
        crypto_props = comp.get("cryptoProperties", {}) or {}
        asset_type = str(crypto_props.get("assetType", "algorithm"))
        algo_props = crypto_props.get("algorithmProperties", {}) or {}
        cert_props = crypto_props.get("certificateProperties", {}) or {}
        comp_props = {
            p["name"]: p["value"] for p in comp.get("properties", []) if isinstance(p, dict)
        }
        key_size = None
        param = algo_props.get("parameterSetIdentifier")
        if param and str(param).isdigit():
            key_size = int(param)
        components.append(
            CryptoComponent(
                name=str(comp.get("name", "")),
                algorithm=str(comp.get("name", "")),
                key_size=key_size,
                asset_type=asset_type,
                bom_ref=str(comp.get("bom-ref", "")),
                properties=comp_props,
                parameter_set=str(param) if param else None,
                primitive=algo_props.get("primitive"),
                classical_security_level=algo_props.get("classicalSecurityLevel"),
                nist_quantum_security_level=algo_props.get("nistQuantumSecurityLevel"),
                subject_name=cert_props.get("subjectName"),
                issuer_name=cert_props.get("issuerName"),
                not_valid_before=cert_props.get("notValidBefore"),
                not_valid_after=cert_props.get("notValidAfter"),
            )
        )

    metadata_block = data.get("metadata", {})
    target = str(path)
    if isinstance(metadata_block, dict):
        component = metadata_block.get("component", {})
        if isinstance(component, dict):
            target = str(component.get("name", target))

    result_data: dict[str, object] = {
        "findings": findings_raw,
        "components": components,
        "target": target,
        "errors": [ScanError.model_validate(e) for e in errors_raw],
        "skipped_files": skipped_raw,
        "negative_scope": props.get("qscout:negative-scope", "").split("; ")
        if props.get("qscout:negative-scope")
        else [],
    }
    if scanned_at:
        result_data["scanned_at"] = scanned_at
    return ScanResult.model_validate(result_data)


def cbom_round_trip(scan_result: ScanResult) -> ScanResult:
    """Export and re-import a scan result through CBOM format."""
    data = emit_cbom(scan_result)
    return _load_cbom(data, Path("round-trip.json"))
