"""Parse ssh-audit JSON output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from qscout.models import ScanError
from qscout.parsers.result import ParseResult
from qscout.security import read_bounded_file, sanitize_location

_RSA_BITS = re.compile(r"(\d{3,5})\s*-?\s*bit", re.IGNORECASE)


def _extract_rsa_key_size(name: str) -> int | None:
    if "1024" in name:
        return 1024
    match = _RSA_BITS.search(name)
    if match:
        return int(match.group(1))
    return None


def parse_ssh_audit(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Parse ssh-audit JSON and return evidence items."""
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
    banner = str(data.get("banner", {}).get("raw", path.stem))
    endpoint = sanitize_location(f"ssh:{banner}")

    for algo_type in ("kex", "key", "mac", "enc"):
        for entry in data.get(algo_type, []):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("algorithm", entry.get("name", "")))
            status = str(entry.get("status", "")).lower()
            if status in ("fail", "warn"):
                if "rsa" in name.lower() and algo_type == "key":
                    key_size = _extract_rsa_key_size(name)
                    item: dict[str, Any] = {
                        "kind": "rsa_key_size",
                        "location": endpoint,
                        "algorithm": "RSA",
                        "evidence_type": "endpoint",
                        "confidence": "confirmed",
                        "message": f"SSH key algorithm issue: {name}",
                    }
                    if key_size is not None:
                        item["key_size"] = key_size
                    else:
                        item["metadata"] = {"key_size_unknown": True}
                    evidence.append(item)
                if "diffie-hellman" in name.lower() or name.lower().startswith("ecdh"):
                    evidence.append(
                        {
                            "kind": "ecdh" if "ecdh" in name.lower() else "dh",
                            "location": endpoint,
                            "algorithm": "ECDH" if "ecdh" in name.lower() else "DH",
                            "evidence_type": "endpoint",
                            "confidence": "confirmed",
                        }
                    )
                if "md5" in name.lower() or "sha1" in name.lower():
                    evidence.append(
                        {
                            "kind": "weak_hash",
                            "location": endpoint,
                            "algorithm": "MD5" if "md5" in name.lower() else "SHA-1",
                            "evidence_type": "endpoint",
                            "confidence": "confirmed",
                        }
                    )

    return ParseResult(evidence=evidence)
