"""CycloneDX 1.6 CBOM emitter."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from qscout import __version__
from qscout.models import CryptoComponent, Finding, ScanResult


def emit_cbom(scan_result: ScanResult) -> dict[str, Any]:
    """Emit CycloneDX 1.6 CBOM JSON."""
    serial = f"urn:uuid:{uuid.uuid4()}"
    components = [_component_to_cbom(comp) for comp in scan_result.components]
    vulnerabilities = _findings_to_vulnerabilities(scan_result.findings)

    properties = [
        {"name": "qscout:negative-scope", "value": "; ".join(scan_result.negative_scope)},
        {"name": "qscout:scanned-at", "value": scan_result.scanned_at.isoformat()},
        {"name": "qscout:error-count", "value": str(len(scan_result.errors))},
        {"name": "qscout:skipped-file-count", "value": str(len(scan_result.skipped_files))},
    ]
    if scan_result.errors:
        properties.append(
            {
                "name": "qscout:errors",
                "value": json.dumps([e.model_dump() for e in scan_result.errors]),
            }
        )
    if scan_result.skipped_files:
        properties.append(
            {
                "name": "qscout:skipped-files",
                "value": json.dumps(scan_result.skipped_files),
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "qscout",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": scan_result.target or "scan-target",
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
        "properties": properties,
    }


def _component_to_cbom(comp: CryptoComponent) -> dict[str, Any]:
    crypto_props: dict[str, Any] = {"assetType": comp.asset_type}
    if comp.asset_type == "algorithm":
        algo_props: dict[str, Any] = {}
        if comp.primitive:
            algo_props["primitive"] = comp.primitive
        if comp.parameter_set:
            algo_props["parameterSetIdentifier"] = comp.parameter_set
        elif comp.key_size is not None:
            algo_props["parameterSetIdentifier"] = str(comp.key_size)
        if comp.classical_security_level is not None:
            algo_props["classicalSecurityLevel"] = comp.classical_security_level
        if comp.nist_quantum_security_level is not None:
            algo_props["nistQuantumSecurityLevel"] = comp.nist_quantum_security_level
        if algo_props:
            crypto_props["algorithmProperties"] = algo_props
    elif comp.asset_type == "certificate":
        cert_props: dict[str, Any] = {"certificateFormat": "X.509"}
        if comp.subject_name:
            cert_props["subjectName"] = comp.subject_name
        if comp.issuer_name:
            cert_props["issuerName"] = comp.issuer_name
        if comp.not_valid_before:
            cert_props["notValidBefore"] = comp.not_valid_before
        if comp.not_valid_after:
            cert_props["notValidAfter"] = comp.not_valid_after
        crypto_props["certificateProperties"] = cert_props

    entry: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": comp.name,
        "bom-ref": comp.bom_ref,
        "cryptoProperties": crypto_props,
    }
    if comp.properties:
        entry["properties"] = [{"name": k, "value": v} for k, v in comp.properties.items()]
    return entry


def _findings_to_vulnerabilities(findings: list[Finding]) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    for f in findings:
        props = [
            {"name": "evidence_type", "value": f.evidence_type.value},
            {"name": "confidence", "value": f.confidence.value},
            {"name": "location", "value": f.location},
            {"name": "standard_refs", "value": "; ".join(f.standard_refs)},
            {"name": "severity", "value": f.severity.value},
            {"name": "result", "value": f.result.value},
            {"name": "algorithm", "value": f.algorithm or ""},
            {"name": "metadata", "value": json.dumps(f.metadata)},
        ]
        vulns.append(
            {
                "id": f.check_id,
                "description": f.message,
                "recommendation": f.title,
                "ratings": [
                    {
                        "severity": _map_severity(f.severity.value),
                        "method": "other",
                        "source": {
                            "name": "qscout",
                        },
                    }
                ],
                "analysis": {
                    "state": "exploitable" if f.result.value == "fail" else "not_affected",
                    "detail": f.message,
                },
                "properties": props,
            }
        )
    return vulns


def _map_severity(severity: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(severity, "unknown")


def write_cbom(scan_result: ScanResult, path: str) -> None:
    """Write CBOM JSON to file."""
    data = emit_cbom(scan_result)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
