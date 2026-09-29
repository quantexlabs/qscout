"""Check catalogue CRYPTO-001 through CRYPTO-012."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    title: str
    description: str
    standard_refs: tuple[str, ...]
    default_severity: str


CHECKS: dict[str, CheckDefinition] = {
    "CRYPTO-001": CheckDefinition(
        check_id="CRYPTO-001",
        title="RSA key size below 2048 bits",
        description="RSA keys smaller than 2048 bits are considered weak.",
        standard_refs=("informed by NIST SP 800-131A transitions",),
        default_severity="high",
    ),
    "CRYPTO-002": CheckDefinition(
        check_id="CRYPTO-002",
        title="RSA encryption or key transport",
        description="RSA used for encryption or key transport is quantum-vulnerable (HNDL).",
        standard_refs=("informed by NIST FIPS 203 (ML-KEM)", "informed by NIST IR 8547"),
        default_severity="high",
    ),
    "CRYPTO-003": CheckDefinition(
        check_id="CRYPTO-003",
        title="DH or ECDH key agreement",
        description="Finite-field DH or ECDH key agreement is quantum-vulnerable.",
        standard_refs=("informed by NIST FIPS 203 (ML-KEM)",),
        default_severity="high",
    ),
    "CRYPTO-004": CheckDefinition(
        check_id="CRYPTO-004",
        title="RSA, ECDSA, or EdDSA signatures",
        description="Classical signature algorithms have finite security lifetime.",
        standard_refs=(
            "informed by NIST FIPS 204 (ML-DSA)",
            "informed by NIST FIPS 205 (SLH-DSA)",
        ),
        default_severity="medium",
    ),
    "CRYPTO-005": CheckDefinition(
        check_id="CRYPTO-005",
        title="DSA signatures",
        description="DSA signatures are deprecated and quantum-vulnerable.",
        standard_refs=("informed by NIST FIPS 204 (ML-DSA)",),
        default_severity="high",
    ),
    "CRYPTO-006": CheckDefinition(
        check_id="CRYPTO-006",
        title="Hard-coded keys or PEM private keys",
        description="Private keys or symmetric secrets embedded in source or config.",
        standard_refs=("informed by CCCS ITSM.40.001 inventory quality",),
        default_severity="critical",
    ),
    "CRYPTO-007": CheckDefinition(
        check_id="CRYPTO-007",
        title="MD5 or SHA-1 for signatures or HMAC",
        description="Deprecated hash algorithms used for signatures or MACs.",
        standard_refs=("informed by NIST hash algorithm transitions",),
        default_severity="high",
    ),
    "CRYPTO-008": CheckDefinition(
        check_id="CRYPTO-008",
        title="Weak TLS configuration",
        description="TLS 1.0/1.1 or weak cipher suites in configuration.",
        standard_refs=("informed by CCCS ITSP.40.062",),
        default_severity="high",
    ),
    "CRYPTO-009": CheckDefinition(
        check_id="CRYPTO-009",
        title="X.509 certificate issues",
        description="Certificate uses weak key, SHA-1 signature, or is expired.",
        standard_refs=("informed by CCCS ITSM.40.001",),
        default_severity="medium",
    ),
    "CRYPTO-010": CheckDefinition(
        check_id="CRYPTO-010",
        title="Unresolved crypto library dependency",
        description="Dependency on cryptographic library without resolved algorithm.",
        standard_refs=("informed by CycloneDX CBOM practice",),
        default_severity="low",
    ),
    "CRYPTO-011": CheckDefinition(
        check_id="CRYPTO-011",
        title="Post-quantum algorithm present",
        description="ML-KEM, ML-DSA, or SLH-DSA detected (migration positive).",
        standard_refs=(
            "informed by NIST FIPS 203",
            "informed by NIST FIPS 204",
            "informed by NIST FIPS 205",
        ),
        default_severity="info",
    ),
    "CRYPTO-012": CheckDefinition(
        check_id="CRYPTO-012",
        title="Stateful hash signatures (LMS/XMSS)",
        description="Stateful hash-based signatures require careful key state management.",
        standard_refs=("informed by NIST SP 800-208",),
        default_severity="medium",
    ),
}


def all_check_ids() -> list[str]:
    return sorted(CHECKS.keys())
