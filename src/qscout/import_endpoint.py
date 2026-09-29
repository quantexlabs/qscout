"""Import endpoint scan results from external tools."""

from __future__ import annotations

import json
from pathlib import Path

from qscout.checks.engine import evaluate_evidence
from qscout.models import ScanContext, ScanResult, default_negative_scope
from qscout.parsers.result import ParseResult
from qscout.parsers.sonar import parse_sonar_cbom
from qscout.parsers.ssh_audit import parse_ssh_audit
from qscout.parsers.testssl import parse_testssl
from qscout.security import read_bounded_file


def detect_format(path: Path, max_bytes: int = 10_485_760) -> str:
    """Detect import file format."""
    content = read_bounded_file(path, max_bytes)
    data = json.loads(content)
    if "scanResult" in data:
        return "testssl"
    if "banner" in data:
        return "ssh-audit"
    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        return "sonar"
    raise ValueError(f"Unknown endpoint import format: {path}")


def import_endpoint(path: Path, context: ScanContext) -> ScanResult:
    """Import and evaluate endpoint scan JSON."""
    if not context.ownership_attestation:
        raise ValueError("--attest-ownership is required")

    max_bytes = context.max_file_bytes
    fmt = detect_format(path, max_bytes)
    parse_result: ParseResult
    if fmt == "testssl":
        parse_result = parse_testssl(path, max_bytes)
    elif fmt == "ssh-audit":
        parse_result = parse_ssh_audit(path, max_bytes)
    else:
        parse_result = parse_sonar_cbom(path, max_bytes)

    findings, components = evaluate_evidence(parse_result.evidence)
    return ScanResult(
        findings=findings,
        components=components,
        target=str(path),
        negative_scope=default_negative_scope(),
        errors=list(parse_result.errors),
    )
