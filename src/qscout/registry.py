"""Algorithm name normalization and classification registry."""

from __future__ import annotations

from dataclasses import dataclass

from qscout.models import QuantumStatus

ALGORITHM_ALIASES: dict[str, str] = {
    "kyber": "ML-KEM",
    "kyber512": "ML-KEM-512",
    "kyber768": "ML-KEM-768",
    "kyber1024": "ML-KEM-1024",
    "ml-kem": "ML-KEM",
    "ml-kem-512": "ML-KEM-512",
    "ml-kem-768": "ML-KEM-768",
    "ml-kem-1024": "ML-KEM-1024",
    "dilithium": "ML-DSA",
    "ml-dsa": "ML-DSA",
    "ml-dsa-44": "ML-DSA-44",
    "ml-dsa-65": "ML-DSA-65",
    "ml-dsa-87": "ML-DSA-87",
    "sphincs": "SLH-DSA",
    "slh-dsa": "SLH-DSA",
    "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s",
    "slh-dsa-sha2-128f": "SLH-DSA-SHA2-128f",
    "slh-dsa-sha2-256s": "SLH-DSA-SHA2-256s",
    "rsa": "RSA",
    "rsa-encryption": "RSA",
    "ecdh": "ECDH",
    "ecdhe": "ECDH",
    "dh": "DH",
    "dhe": "DH",
    "ecdsa": "ECDSA",
    "ed25519": "EdDSA",
    "ed448": "EdDSA",
    "eddsa": "EdDSA",
    "dsa": "DSA",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-512": "SHA-512",
    "lms": "LMS",
    "xmss": "XMSS",
    "aes": "AES",
    "aes-128": "AES-128",
    "aes-192": "AES-192",
    "aes-256": "AES-256",
    "chacha20": "ChaCha20",
}

PQC_ALGORITHMS = frozenset(
    {
        "ML-KEM",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-256s",
    }
)

STATEFUL_HASH_ALGORITHMS = frozenset({"LMS", "XMSS", "XMSSMT"})

WEAK_HASH_ALGORITHMS = frozenset({"MD5", "SHA-1"})

ASYMMETRIC_VULNERABLE = frozenset({"RSA", "DH", "ECDH", "ECDSA", "EdDSA", "DSA"})

CLASSICAL_PRIMITIVES: dict[str, str] = {
    "RSA": "pke",
    "DH": "key-agree",
    "ECDH": "key-agree",
    "ECDSA": "signature",
    "EdDSA": "signature",
    "DSA": "signature",
    "MD5": "hash",
    "SHA-1": "hash",
    "SHA-256": "hash",
    "SHA-384": "hash",
    "SHA-512": "hash",
    "AES": "block-cipher",
    "AES-128": "block-cipher",
    "AES-192": "block-cipher",
    "AES-256": "block-cipher",
    "ChaCha20": "stream-cipher",
    "ML-KEM": "kem",
    "ML-KEM-512": "kem",
    "ML-KEM-768": "kem",
    "ML-KEM-1024": "kem",
    "ML-DSA": "signature",
    "ML-DSA-44": "signature",
    "ML-DSA-65": "signature",
    "ML-DSA-87": "signature",
    "SLH-DSA": "signature",
    "SLH-DSA-SHA2-128s": "signature",
    "SLH-DSA-SHA2-128f": "signature",
    "SLH-DSA-SHA2-256s": "signature",
}


@dataclass(frozen=True)
class AlgorithmRecord:
    """Structured algorithm metadata for classification and CBOM export."""

    name: str
    normalized_name: str
    parameter_set: str | None
    key_size: int | None
    quantum_status: QuantumStatus
    classical_security_level: int | None
    nist_quantum_security_level: int | None
    primitive: str
    hybrid: bool
    hybrid_components: tuple[str, ...]
    confidence: str


def normalize_algorithm(name: str) -> str:
    """Normalize an algorithm name to canonical form."""
    key = name.strip().lower().replace("_", "-")
    return ALGORITHM_ALIASES.get(key, name.strip())


def is_pqc_algorithm(name: str) -> bool:
    normalized = normalize_algorithm(name)
    return normalized in PQC_ALGORITHMS or normalized.startswith(("ML-KEM", "ML-DSA", "SLH-DSA"))


def is_stateful_hash(name: str) -> bool:
    return normalize_algorithm(name) in STATEFUL_HASH_ALGORITHMS


def classify_algorithm(
    name: str,
    key_size: int | None = None,
    hybrid_components: tuple[str, ...] | None = None,
) -> AlgorithmRecord:
    """Classify an algorithm using NIST transition guidance.

    RSA/ECC/DH key sizes informed by NIST SP 800-131A Rev. 2 transition tables.
    Symmetric/hash Grover guidance informed by NIST SP 800-57 Part 1.
    ML-KEM/ML-DSA levels informed by FIPS 203/204 parameter sets.
    """
    normalized = normalize_algorithm(name)
    parameter_set = normalized if normalized != name.strip() else None
    if key_size is not None:
        parameter_set = str(key_size)
    elif "-" in normalized:
        parts = normalized.split("-", 1)
        if parts[-1].isdigit() or parts[-1] in {"44", "65", "87", "512", "768", "1024"}:
            parameter_set = parts[-1]

    components = tuple(hybrid_components or ())
    hybrid = len(components) >= 2

    if hybrid:
        return AlgorithmRecord(
            name=name,
            normalized_name=normalized,
            parameter_set=parameter_set,
            key_size=key_size,
            quantum_status=QuantumStatus.POST_QUANTUM,
            classical_security_level=None,
            nist_quantum_security_level=_nist_pqc_level(normalized),
            primitive="combiner",
            hybrid=True,
            hybrid_components=components,
            confidence="inferred",
        )

    if is_pqc_algorithm(normalized):
        return AlgorithmRecord(
            name=name,
            normalized_name=normalized,
            parameter_set=parameter_set or normalized,
            key_size=key_size,
            quantum_status=QuantumStatus.POST_QUANTUM,
            classical_security_level=None,
            nist_quantum_security_level=_nist_pqc_level(normalized),
            primitive=CLASSICAL_PRIMITIVES.get(normalized, "other"),
            hybrid=False,
            hybrid_components=(),
            confidence="confirmed",
        )

    if normalized in ASYMMETRIC_VULNERABLE:
        classical = _classical_asymmetric_level(normalized, key_size)
        return AlgorithmRecord(
            name=name,
            normalized_name=normalized,
            parameter_set=parameter_set,
            key_size=key_size,
            quantum_status=QuantumStatus.QUANTUM_VULNERABLE,
            classical_security_level=classical,
            nist_quantum_security_level=0,
            primitive=CLASSICAL_PRIMITIVES.get(normalized, "other"),
            hybrid=False,
            hybrid_components=(),
            confidence="confirmed" if key_size is not None else "inferred",
        )

    if normalized in WEAK_HASH_ALGORITHMS:
        return AlgorithmRecord(
            name=name,
            normalized_name=normalized,
            parameter_set=parameter_set,
            key_size=key_size,
            quantum_status=QuantumStatus.QUANTUM_VULNERABLE,
            classical_security_level=0,
            nist_quantum_security_level=0,
            primitive="hash",
            hybrid=False,
            hybrid_components=(),
            confidence="confirmed",
        )

    if normalized.startswith("AES"):
        bits = _aes_bits(normalized, key_size)
        effective = bits // 2 if bits else None
        status = (
            QuantumStatus.QUANTUM_AFFECTED
            if effective and effective >= 128
            else QuantumStatus.QUANTUM_VULNERABLE
        )
        return AlgorithmRecord(
            name=name,
            normalized_name=normalized,
            parameter_set=str(bits) if bits else parameter_set,
            key_size=key_size or bits,
            quantum_status=status,
            classical_security_level=bits,
            nist_quantum_security_level=_grover_nist_level(effective),
            primitive="block-cipher",
            hybrid=False,
            hybrid_components=(),
            confidence="confirmed",
        )

    if normalized.startswith("SHA-"):
        bits = int(normalized.split("-")[1]) if "-" in normalized else 256
        effective = bits // 2
        return AlgorithmRecord(
            name=name,
            normalized_name=normalized,
            parameter_set=str(bits),
            key_size=key_size,
            quantum_status=QuantumStatus.QUANTUM_AFFECTED,
            classical_security_level=bits,
            nist_quantum_security_level=_grover_nist_level(effective),
            primitive="hash",
            hybrid=False,
            hybrid_components=(),
            confidence="confirmed",
        )

    return AlgorithmRecord(
        name=name,
        normalized_name=normalized,
        parameter_set=parameter_set,
        key_size=key_size,
        quantum_status=QuantumStatus.UNKNOWN,
        classical_security_level=None,
        nist_quantum_security_level=None,
        primitive=CLASSICAL_PRIMITIVES.get(normalized, "unknown"),
        hybrid=False,
        hybrid_components=(),
        confidence="inferred",
    )


def detect_hybrid(classical: str, pqc: str) -> AlgorithmRecord:
    """Build a hybrid algorithm record from classical and PQC components."""
    classical_norm = normalize_algorithm(classical)
    pqc_norm = normalize_algorithm(pqc)
    return classify_algorithm(
        f"{pqc_norm}+{classical_norm}",
        hybrid_components=(pqc_norm, classical_norm),
    )


def _nist_pqc_level(name: str) -> int:
    mapping = {
        "ML-KEM-512": 1,
        "ML-KEM-768": 3,
        "ML-KEM-1024": 5,
        "ML-DSA-44": 2,
        "ML-DSA-65": 3,
        "ML-DSA-87": 5,
        "SLH-DSA-SHA2-128s": 1,
        "SLH-DSA-SHA2-128f": 1,
        "SLH-DSA-SHA2-256s": 3,
    }
    if name in mapping:
        return mapping[name]
    if name.startswith("ML-KEM"):
        return 3
    if name.startswith("ML-DSA"):
        return 3
    if name.startswith("SLH-DSA"):
        return 1
    return 1


def _classical_asymmetric_level(name: str, key_size: int | None) -> int | None:
    if key_size is None:
        return None
    if name == "RSA":
        return min(key_size, 3072)
    if name in ("ECDH", "ECDSA", "EdDSA"):
        return key_size
    if name == "DH":
        return key_size
    if name == "DSA":
        return key_size
    return None


def _aes_bits(name: str, key_size: int | None) -> int | None:
    if key_size:
        return key_size
    if name.endswith("128"):
        return 128
    if name.endswith("192"):
        return 192
    if name.endswith("256"):
        return 256
    if name == "AES":
        return 256
    return None


def _grover_nist_level(effective_bits: int | None) -> int | None:
    if effective_bits is None:
        return None
    if effective_bits >= 256:
        return 5
    if effective_bits >= 192:
        return 4
    if effective_bits >= 128:
        return 3
    if effective_bits >= 112:
        return 2
    if effective_bits >= 80:
        return 1
    return 0
