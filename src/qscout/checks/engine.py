"""Evaluate collected evidence against check catalogue."""

from __future__ import annotations

from typing import Any

from qscout.checks.rules import CHECKS
from qscout.models import (
    CheckResult,
    Confidence,
    CryptoComponent,
    EvidenceType,
    Finding,
    Severity,
)
from qscout.registry import (
    AlgorithmRecord,
    classify_algorithm,
    detect_hybrid,
    is_pqc_algorithm,
    is_stateful_hash,
    normalize_algorithm,
)


def _make_finding(
    check_id: str,
    result: CheckResult,
    location: str,
    message: str,
    evidence_type: EvidenceType,
    confidence: Confidence,
    algorithm: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    check = CHECKS[check_id]
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return Finding(
        check_id=check_id,
        title=check.title,
        result=result,
        severity=severity_map.get(check.default_severity, Severity.MEDIUM),
        algorithm=algorithm,
        evidence_type=evidence_type,
        confidence=confidence,
        location=location,
        message=message,
        standard_refs=list(check.standard_refs),
        metadata=metadata or {},
    )


def _component_from_record(
    location: str,
    record: AlgorithmRecord,
    bom_ref: str,
    asset_type: str = "algorithm",
    cert_meta: dict[str, str] | None = None,
) -> CryptoComponent:
    props = {"location": location}
    if record.hybrid:
        props["hybrid"] = "true"
        props["hybrid_components"] = ",".join(record.hybrid_components)
    if record.quantum_status:
        props["quantum_status"] = record.quantum_status.value

    comp = CryptoComponent(
        name=record.normalized_name,
        algorithm=record.normalized_name,
        key_size=record.key_size,
        asset_type=asset_type,
        bom_ref=bom_ref,
        properties=props,
        parameter_set=record.parameter_set,
        primitive=record.primitive,
        classical_security_level=record.classical_security_level,
        nist_quantum_security_level=record.nist_quantum_security_level,
        quantum_status=record.quantum_status,
        hybrid=record.hybrid,
        hybrid_components=list(record.hybrid_components),
    )
    if cert_meta:
        comp.subject_name = cert_meta.get("subject")
        comp.issuer_name = cert_meta.get("issuer")
        comp.not_valid_before = cert_meta.get("not_valid_before")
        comp.not_valid_after = cert_meta.get("not_valid_after")
    return comp


def evaluate_evidence(
    evidence: list[dict[str, Any]],
) -> tuple[list[Finding], list[CryptoComponent]]:
    """Map raw evidence dicts to findings and crypto components."""
    findings: list[Finding] = []
    components: list[CryptoComponent] = []
    seen_checks: set[str] = set()

    for item in evidence:
        kind = item.get("kind", "")
        location = str(item.get("location", "unknown"))
        algorithm = item.get("algorithm")
        norm_algo = normalize_algorithm(algorithm) if algorithm else None
        evidence_type = EvidenceType(item.get("evidence_type", "lexical"))
        confidence = Confidence(item.get("confidence", "inferred"))
        meta = dict(item.get("metadata", {}))
        key_size = item.get("key_size")

        if kind == "cert_metadata" and norm_algo:
            ref = f"cert-{hash(location + norm_algo) % 10_000_000:07d}"
            cert_meta = {
                k: str(v)
                for k, v in meta.items()
                if k in ("subject", "issuer", "not_valid_before", "not_valid_after")
            }
            record = classify_algorithm(norm_algo, key_size)
            components.append(
                _component_from_record(
                    location,
                    record,
                    ref,
                    asset_type="certificate",
                    cert_meta=cert_meta,
                )
            )
        elif norm_algo and kind not in ("cert_metadata",):
            ref = f"component-{hash(location + norm_algo) % 10_000_000:07d}"
            hybrid_meta = meta.get("pqc_component"), meta.get("classical_component")
            if kind == "hybrid_crypto" and hybrid_meta[0] and hybrid_meta[1]:
                record = detect_hybrid(str(hybrid_meta[1]), str(hybrid_meta[0]))
            else:
                record = classify_algorithm(norm_algo, key_size)
            components.append(_component_from_record(location, record, ref))

        if kind == "rsa_key_size" and norm_algo == "RSA":
            if key_size is None or meta.get("key_size_unknown"):
                findings.append(
                    _make_finding(
                        "CRYPTO-001",
                        CheckResult.INFO,
                        location,
                        "RSA key size unknown; manual verification required",
                        evidence_type,
                        confidence,
                        "RSA",
                        meta,
                    )
                )
            elif key_size < 2048:
                findings.append(
                    _make_finding(
                        "CRYPTO-001",
                        CheckResult.FAIL,
                        location,
                        f"RSA key size {key_size} bits is below 2048",
                        evidence_type,
                        confidence,
                        "RSA",
                        meta,
                    )
                )
                seen_checks.add("CRYPTO-001")

        elif kind == "rsa_encrypt" or (kind == "api_usage" and item.get("usage") == "encrypt"):
            findings.append(
                _make_finding(
                    "CRYPTO-002",
                    CheckResult.FAIL,
                    location,
                    "RSA used for encryption or key transport",
                    evidence_type,
                    confidence,
                    "RSA",
                    meta,
                )
            )
            seen_checks.add("CRYPTO-002")

        elif kind in ("dh", "ecdh", "key_agreement"):
            algo = norm_algo or "ECDH"
            findings.append(
                _make_finding(
                    "CRYPTO-003",
                    CheckResult.FAIL,
                    location,
                    f"{algo} key agreement detected",
                    evidence_type,
                    confidence,
                    algo,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-003")

        elif kind in ("signature", "ecdsa", "eddsa", "classical_asymmetric") or (
            kind == "api_usage" and item.get("usage") == "sign"
        ):
            algo = norm_algo or "ECDSA"
            if algo == "DSA":
                findings.append(
                    _make_finding(
                        "CRYPTO-005",
                        CheckResult.FAIL,
                        location,
                        "DSA signature usage detected",
                        evidence_type,
                        confidence,
                        "DSA",
                        meta,
                    )
                )
                seen_checks.add("CRYPTO-005")
            else:
                msg = (
                    f"{algo} classical asymmetric key detected"
                    if kind == "classical_asymmetric"
                    else f"{algo} signature usage detected"
                )
                findings.append(
                    _make_finding(
                        "CRYPTO-004",
                        CheckResult.FAIL,
                        location,
                        msg,
                        evidence_type,
                        confidence,
                        algo,
                        meta,
                    )
                )
                seen_checks.add("CRYPTO-004")

        elif kind == "dsa":
            findings.append(
                _make_finding(
                    "CRYPTO-005",
                    CheckResult.FAIL,
                    location,
                    "DSA signature usage detected",
                    evidence_type,
                    confidence,
                    "DSA",
                    meta,
                )
            )
            seen_checks.add("CRYPTO-005")

        elif kind == "hardcoded_key":
            findings.append(
                _make_finding(
                    "CRYPTO-006",
                    CheckResult.FAIL,
                    location,
                    item.get("message", "Hard-coded key or PEM private key detected"),
                    evidence_type,
                    confidence,
                    algorithm,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-006")

        elif kind == "weak_hash":
            algo = norm_algo or "SHA-1"
            findings.append(
                _make_finding(
                    "CRYPTO-007",
                    CheckResult.FAIL,
                    location,
                    f"Deprecated hash {algo} used for signature or HMAC",
                    evidence_type,
                    confidence,
                    algo,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-007")

        elif kind == "weak_tls":
            findings.append(
                _make_finding(
                    "CRYPTO-008",
                    CheckResult.FAIL,
                    location,
                    item.get("message", "Weak TLS configuration detected"),
                    evidence_type,
                    confidence,
                    None,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-008")

        elif kind == "cert_issue":
            findings.append(
                _make_finding(
                    "CRYPTO-009",
                    CheckResult.FAIL,
                    location,
                    item.get("message", "X.509 certificate issue detected"),
                    EvidenceType.CERTIFICATE,
                    confidence,
                    algorithm,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-009")

        elif kind == "unresolved_dependency":
            findings.append(
                _make_finding(
                    "CRYPTO-010",
                    CheckResult.FAIL,
                    location,
                    item.get("message", "Crypto library without resolved algorithm"),
                    EvidenceType.DEPENDENCY,
                    Confidence.DEPENDENCY_ONLY,
                    None,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-010")

        elif kind == "hybrid_crypto":
            pqc = str(meta.get("pqc_component", norm_algo or "ML-KEM"))
            classical = str(meta.get("classical_component", "ECDH"))
            findings.append(
                _make_finding(
                    "CRYPTO-011",
                    CheckResult.INFO,
                    location,
                    f"Hybrid cryptography detected: {pqc} with {classical}",
                    evidence_type,
                    confidence,
                    f"{normalize_algorithm(pqc)}+{normalize_algorithm(classical)}",
                    {**meta, "hybrid": True},
                )
            )
            seen_checks.add("CRYPTO-011")

        elif kind == "pqc_present" or (norm_algo and is_pqc_algorithm(norm_algo)):
            findings.append(
                _make_finding(
                    "CRYPTO-011",
                    CheckResult.INFO,
                    location,
                    f"Post-quantum algorithm {norm_algo} present",
                    evidence_type,
                    confidence,
                    norm_algo,
                    meta,
                )
            )
            seen_checks.add("CRYPTO-011")

        elif kind == "stateful_hash" or (norm_algo and is_stateful_hash(norm_algo)):
            findings.append(
                _make_finding(
                    "CRYPTO-012",
                    CheckResult.FAIL,
                    location,
                    f"Stateful hash signature {norm_algo or 'LMS/XMSS'} detected",
                    evidence_type,
                    confidence,
                    norm_algo or "LMS",
                    meta,
                )
            )
            seen_checks.add("CRYPTO-012")

        elif norm_algo and norm_algo.startswith(("AES", "SHA-")):
            record = classify_algorithm(norm_algo, key_size)
            if record.quantum_status and record.quantum_status.value != "unknown":
                findings.append(
                    _make_finding(
                        "CRYPTO-011",
                        CheckResult.INFO,
                        location,
                        (
                            f"{norm_algo} classified as {record.quantum_status.value} "
                            f"(classical security level {record.classical_security_level})"
                        ),
                        evidence_type,
                        confidence,
                        norm_algo,
                        {**meta, "quantum_status": record.quantum_status.value},
                    )
                )

    return findings, components
