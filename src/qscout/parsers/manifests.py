"""Parse dependency manifests for crypto libraries."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from qscout.models import ScanError
from qscout.parsers.result import ParseResult
from qscout.security import read_bounded_file

CRYPTO_LIBRARIES = frozenset(
    {
        "cryptography",
        "pycryptodome",
        "pycryptodomex",
        "openssl",
        "m2crypto",
        "nacl",
        "pynacl",
        "bcrypt",
        "passlib",
        "hashlib",
        "rsa",
        "ecdsa",
        "pyca/cryptography",
    }
)

_PQC_PATTERN = re.compile(
    r"\b(ml-kem|ml-dsa|slh-dsa|kyber|dilithium|sphincs)\b",
    re.IGNORECASE,
)
_LMS_PATTERN = re.compile(r"\b(lms|xmss)\b", re.IGNORECASE)
_RSA_ENCRYPT = re.compile(
    r"\.encrypt\s*\(|RSA\.encrypt|public_key\(\)\.encrypt",
    re.IGNORECASE,
)
_SIGN_PATTERN = re.compile(
    r"\.sign\s*\(|RSASigner|ECDSA|Ed25519PrivateKey|DSAPrivateKey",
    re.IGNORECASE,
)
_ECDH_PATTERN = re.compile(r"ECDH|generate_private_key|exchange", re.IGNORECASE)
_PEM_PRIVATE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE)
_WEAK_HASH = re.compile(r"\b(md5|sha1|sha-1)\b", re.IGNORECASE)
_HYBRID_PATTERN = re.compile(
    r"\b(ml-kem|kyber).*(ecdh|ecdhe)|\b(ecdh|ecdhe).*(ml-kem|kyber)",
    re.IGNORECASE,
)


def parse_requirements_txt(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Parse requirements.txt with bounded reads."""
    location = str(path)
    try:
        content = read_bounded_file(path, max_bytes)
    except Exception as exc:
        return _read_error(location, exc)

    evidence: list[dict[str, Any]] = []
    for line in content.splitlines():
        pkg = line.split("==")[0].split(">=")[0].strip().lower()
        if pkg in CRYPTO_LIBRARIES:
            evidence.append(
                {
                    "kind": "unresolved_dependency",
                    "location": f"{path}:{pkg}",
                    "evidence_type": "dependency",
                    "confidence": "dependency_only",
                    "message": f"Crypto library {pkg} without resolved algorithm",
                }
            )
    return ParseResult(evidence=evidence)


def parse_package_json(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Parse package.json with bounded reads and structured JSON errors."""
    location = str(path)
    try:
        content = read_bounded_file(path, max_bytes)
    except Exception as exc:
        return _read_error(location, exc)

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
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            deps.update(section_deps)
    for name in deps:
        if name.lower() in ("node-forge", "crypto-js", "jose", "jsonwebtoken"):
            evidence.append(
                {
                    "kind": "unresolved_dependency",
                    "location": f"{path}:{name}",
                    "evidence_type": "dependency",
                    "confidence": "dependency_only",
                    "message": f"Crypto library {name} without resolved algorithm",
                }
            )
    return ParseResult(evidence=evidence)


def scan_python_source(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Scan Python source for crypto patterns with bounded reads."""
    location = str(path)
    try:
        content = read_bounded_file(path, max_bytes)
    except Exception as exc:
        return _read_error(location, exc)

    evidence: list[dict[str, Any]] = []

    if _PEM_PRIVATE.search(content):
        evidence.append(
            {
                "kind": "hardcoded_key",
                "location": location,
                "evidence_type": "source",
                "confidence": "confirmed",
                "message": "PEM private key embedded in source",
            }
        )

    if _RSA_ENCRYPT.search(content):
        evidence.append(
            {
                "kind": "rsa_encrypt",
                "location": location,
                "algorithm": "RSA",
                "evidence_type": "source",
                "confidence": "lexical",
            }
        )

    if _SIGN_PATTERN.search(content):
        if "DSA" in content or "dsa" in content.lower():
            evidence.append(
                {
                    "kind": "dsa",
                    "location": location,
                    "algorithm": "DSA",
                    "evidence_type": "source",
                    "confidence": "lexical",
                }
            )
        else:
            evidence.append(
                {
                    "kind": "signature",
                    "location": location,
                    "algorithm": "RSA" if "RSA" in content else "ECDSA",
                    "evidence_type": "source",
                    "confidence": "lexical",
                }
            )

    if _ECDH_PATTERN.search(content):
        evidence.append(
            {
                "kind": "ecdh",
                "location": location,
                "algorithm": "ECDH",
                "evidence_type": "source",
                "confidence": "lexical",
            }
        )

    if _WEAK_HASH.search(content):
        match = _WEAK_HASH.search(content)
        algo = "MD5" if match and "md5" in match.group(0).lower() else "SHA-1"
        evidence.append(
            {
                "kind": "weak_hash",
                "location": location,
                "algorithm": algo,
                "evidence_type": "source",
                "confidence": "lexical",
            }
        )

    pqc_match = _PQC_PATTERN.search(content)
    ecdh_present = _ECDH_PATTERN.search(content)
    if pqc_match and ecdh_present:
        evidence.append(
            {
                "kind": "hybrid_crypto",
                "location": location,
                "algorithm": f"{pqc_match.group(0)}+ECDH",
                "evidence_type": "source",
                "confidence": "lexical",
                "metadata": {
                    "pqc_component": pqc_match.group(0),
                    "classical_component": "ECDH",
                },
            }
        )
    elif pqc_match:
        evidence.append(
            {
                "kind": "pqc_present",
                "location": location,
                "algorithm": pqc_match.group(0),
                "evidence_type": "source",
                "confidence": "lexical",
            }
        )

    if _LMS_PATTERN.search(content):
        evidence.append(
            {
                "kind": "stateful_hash",
                "location": location,
                "algorithm": "LMS",
                "evidence_type": "source",
                "confidence": "lexical",
            }
        )

    if re.search(r"RSA\.generate\s*\(\s*1024|key_size\s*=\s*1024", content):
        evidence.append(
            {
                "kind": "rsa_key_size",
                "location": location,
                "algorithm": "RSA",
                "key_size": 1024,
                "evidence_type": "source",
                "confidence": "lexical",
            }
        )

    return ParseResult(evidence=evidence)


def _read_error(location: str, exc: Exception) -> ParseResult:
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
