"""Parse testssl.sh JSON output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qscout.models import ScanError
from qscout.parsers.result import ParseResult
from qscout.security import read_bounded_file, sanitize_location


def parse_testssl(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Parse testssl.sh JSON and return evidence items."""
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
    target = str(data.get("targetHost", path.stem))
    endpoint = sanitize_location(f"endpoint:{target}")

    for item in data.get("scanResult", []):
        if not isinstance(item, dict):
            continue
        id_val = str(item.get("id", ""))
        severity = str(item.get("severity", "")).lower()
        finding = str(item.get("finding", ""))

        if id_val in ("SSLv2", "SSLv3", "TLS1", "TLS1_1"):
            evidence.append(
                {
                    "kind": "weak_tls",
                    "location": endpoint,
                    "evidence_type": "endpoint",
                    "confidence": "confirmed",
                    "message": f"Deprecated protocol {id_val}: {finding}",
                    "metadata": {"protocol": id_val, "severity": severity},
                }
            )

        weak_ciphers = ("RC4", "DES", "NULL", "EXPORT", "3DES", "ANON")
        if (
            "cipher" in id_val.lower()
            and severity in ("high", "critical", "warn")
            and any(weak in finding.upper() for weak in weak_ciphers)
        ):
            evidence.append(
                {
                    "kind": "weak_tls",
                    "location": endpoint,
                    "evidence_type": "endpoint",
                    "confidence": "confirmed",
                    "message": f"Weak cipher: {finding}",
                    "metadata": {"cipher": finding},
                }
            )

        if "RSA" in finding and "encrypt" in finding.lower():
            evidence.append(
                {
                    "kind": "rsa_encrypt",
                    "location": endpoint,
                    "algorithm": "RSA",
                    "evidence_type": "endpoint",
                    "confidence": "inferred",
                }
            )

        if "ECDH" in finding or "ECDHE" in finding:
            evidence.append(
                {
                    "kind": "ecdh",
                    "location": endpoint,
                    "algorithm": "ECDH",
                    "evidence_type": "endpoint",
                    "confidence": "confirmed",
                }
            )

    return ParseResult(evidence=evidence)
