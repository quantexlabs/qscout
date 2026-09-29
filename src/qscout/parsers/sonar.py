"""Parse sonar-cryptography / CBOMkit JSON output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qscout.models import ScanError
from qscout.parsers.result import ParseResult
from qscout.registry import is_pqc_algorithm, is_stateful_hash, normalize_algorithm
from qscout.security import read_bounded_file


def _extract_algorithm(crypto_props: dict[str, Any], name: str) -> str:
    asset_type = crypto_props.get("assetType", "")
    if asset_type == "algorithm":
        algo_props = crypto_props.get("algorithmProperties", {}) or {}
        family = algo_props.get("algorithmFamily")
        if family:
            return str(family)
        param = algo_props.get("parameterSetIdentifier")
        if param:
            return str(param)
    if asset_type == "certificate":
        return "certificate"
    legacy = crypto_props.get("algorithm")
    if legacy:
        return str(legacy)
    return name


def parse_sonar_cbom(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Parse sonar-cryptography or CBOMkit JSON."""
    location = str(path)
    try:
        content = read_bounded_file(path, max_bytes)
    except Exception as exc:
        from qscout.security import SecurityError

        error_type = "oversized_file" if isinstance(exc, SecurityError) else "read_error"
        return ParseResult(
            errors=[
                ScanError(
                    path=location,
                    error_type=error_type,
                    message=str(exc),
                    exception_class=type(exc).__name__,
                )
            ]
        )

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        return ParseResult(
            errors=[
                ScanError(
                    path=location,
                    error_type="json_parse_error",
                    message=str(exc),
                    exception_class=type(exc).__name__,
                )
            ]
        )

    evidence: list[dict[str, Any]] = []
    components = data.get("components", [])

    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = str(comp.get("name", ""))
        comp_location = str(comp.get("bom-ref", name))
        crypto_props = comp.get("cryptoProperties", {}) or {}
        algo = _extract_algorithm(crypto_props, name)
        norm = normalize_algorithm(str(algo))

        if is_pqc_algorithm(norm):
            evidence.append(
                {
                    "kind": "pqc_present",
                    "location": comp_location,
                    "algorithm": norm,
                    "evidence_type": "source",
                    "confidence": "confirmed",
                }
            )
        elif is_stateful_hash(norm):
            evidence.append(
                {
                    "kind": "stateful_hash",
                    "location": comp_location,
                    "algorithm": norm,
                    "evidence_type": "source",
                    "confidence": "confirmed",
                }
            )
        elif norm in ("RSA", "ECDSA", "EdDSA", "DSA", "DH", "ECDH"):
            kind_map = {
                "RSA": "rsa_encrypt",
                "ECDH": "ecdh",
                "DH": "dh",
                "ECDSA": "signature",
                "EdDSA": "signature",
                "DSA": "dsa",
            }
            evidence.append(
                {
                    "kind": kind_map.get(norm, "api_usage"),
                    "location": comp_location,
                    "algorithm": norm,
                    "evidence_type": "source",
                    "confidence": "confirmed",
                }
            )
        elif not algo or algo == "unknown":
            evidence.append(
                {
                    "kind": "unresolved_dependency",
                    "location": comp_location,
                    "evidence_type": "dependency",
                    "confidence": "dependency_only",
                    "message": f"Unresolved crypto component: {name}",
                }
            )

    return ParseResult(evidence=evidence)
