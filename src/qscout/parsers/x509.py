"""X.509 certificate metadata parser."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.oid import SignatureAlgorithmOID

from qscout.models import ScanError
from qscout.parsers.result import ParseResult
from qscout.registry import normalize_algorithm
from qscout.security import read_bounded_bytes


def _key_info(public_key: CertificatePublicKeyTypes) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "EdDSA", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "EdDSA", 448
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    return "unknown", None


def _signature_hash(oid: object) -> str | None:
    weak_hashes = {
        SignatureAlgorithmOID.RSA_WITH_MD5: "MD5",
        SignatureAlgorithmOID.ECDSA_WITH_SHA1: "SHA-1",
        SignatureAlgorithmOID.RSA_WITH_SHA1: "SHA-1",
        SignatureAlgorithmOID.DSA_WITH_SHA1: "SHA-1",
    }
    for weak_oid, name in weak_hashes.items():
        if oid == weak_oid:
            return name
    return None


def parse_certificate(path: Path, max_bytes: int = 10_485_760) -> ParseResult:
    """Parse certificate file and return evidence items or structured errors."""
    location = str(path)
    try:
        data = read_bounded_bytes(path, max_bytes)
    except (FileNotFoundError, OSError) as exc:
        return ParseResult(
            errors=[
                ScanError(
                    path=location,
                    error_type="read_error",
                    message=str(exc),
                    exception_class=type(exc).__name__,
                )
            ]
        )
    except Exception as exc:
        from qscout.security import SecurityError

        if isinstance(exc, SecurityError):
            return ParseResult(
                errors=[
                    ScanError(
                        path=location,
                        error_type="oversized_file",
                        message=str(exc),
                        exception_class=type(exc).__name__,
                    )
                ]
            )
        raise

    cert: x509.Certificate | None = None
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError as exc:
            return ParseResult(
                errors=[
                    ScanError(
                        path=location,
                        error_type="certificate_parse_error",
                        message="Invalid PEM/DER certificate",
                        exception_class=type(exc).__name__,
                    )
                ]
            )

    try:
        algo, key_size = _key_info(cert.public_key())
        sig_hash = _signature_hash(cert.signature_algorithm_oid)
    except Exception as exc:
        return ParseResult(
            errors=[
                ScanError(
                    path=location,
                    error_type="certificate_parse_error",
                    message=f"Unsupported certificate algorithm: {exc}",
                    exception_class=type(exc).__name__,
                )
            ]
        )

    norm = normalize_algorithm(algo)
    now = datetime.now(UTC)
    evidence: list[dict[str, object]] = []

    evidence.append(
        {
            "kind": "cert_metadata",
            "location": location,
            "algorithm": norm,
            "key_size": key_size,
            "evidence_type": "certificate",
            "confidence": "confirmed",
            "metadata": {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
                "asset_type": "certificate",
            },
        }
    )

    if norm in ("RSA", "ECDSA", "EdDSA", "DSA"):
        evidence.append(
            {
                "kind": "classical_asymmetric",
                "location": location,
                "algorithm": norm,
                "key_size": key_size,
                "evidence_type": "certificate",
                "confidence": "confirmed",
            }
        )

    if norm == "RSA" and key_size and key_size < 2048:
        evidence.append(
            {
                "kind": "rsa_key_size",
                "location": location,
                "algorithm": "RSA",
                "key_size": key_size,
                "evidence_type": "certificate",
                "confidence": "confirmed",
            }
        )

    if sig_hash:
        evidence.append(
            {
                "kind": "weak_hash",
                "location": location,
                "algorithm": sig_hash,
                "evidence_type": "certificate",
                "confidence": "confirmed",
                "message": f"Certificate signed with {sig_hash}",
            }
        )

    not_after = cert.not_valid_after_utc
    if not_after < now:
        evidence.append(
            {
                "kind": "cert_issue",
                "location": location,
                "algorithm": norm,
                "evidence_type": "certificate",
                "confidence": "confirmed",
                "message": f"Certificate expired on {not_after.isoformat()}",
            }
        )

    return ParseResult(evidence=evidence)
