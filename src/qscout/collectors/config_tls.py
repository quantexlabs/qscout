"""TLS configuration file collector."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from qscout.models import ScanError
from qscout.parsers.result import ParseResult
from qscout.security import read_bounded_file

_WEAK_TLS = re.compile(r"ssl_protocols\s+.*TLSv1(?:\.0|\.1)?", re.IGNORECASE)
_WEAK_CIPHER = re.compile(r"\b(RC4|DES|NULL|EXPORT|3DES)\b", re.IGNORECASE)
_TLS10 = re.compile(r"\bTLSv1\b(?!\.1)", re.IGNORECASE)
_TLS11 = re.compile(r"\bTLSv1\.1\b", re.IGNORECASE)


def collect_tls_config(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Scan TLS config files for weak settings with bounded reads."""
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

    evidence: list[dict[str, Any]] = []

    if _WEAK_TLS.search(content) or _TLS10.search(content) or _TLS11.search(content):
        evidence.append(
            {
                "kind": "weak_tls",
                "location": location,
                "evidence_type": "config",
                "confidence": "confirmed",
                "message": "TLS 1.0 or 1.1 enabled in configuration",
            }
        )

    if _WEAK_CIPHER.search(content):
        evidence.append(
            {
                "kind": "weak_tls",
                "location": location,
                "evidence_type": "config",
                "confidence": "confirmed",
                "message": "Weak cipher suite in configuration",
            }
        )

    return ParseResult(evidence=evidence)
