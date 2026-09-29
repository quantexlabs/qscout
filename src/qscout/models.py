"""Core data models for qscout."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceType(StrEnum):
    SOURCE = "source"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    DEPENDENCY = "dependency"
    ENDPOINT = "endpoint"
    LEXICAL = "lexical"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    LEXICAL = "lexical"
    DEPENDENCY_ONLY = "dependency_only"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INFO = "info"


class QuantumStatus(StrEnum):
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    QUANTUM_SAFE = "quantum_safe"
    QUANTUM_AFFECTED = "quantum_affected"
    POST_QUANTUM = "post_quantum"
    UNKNOWN = "unknown"


class ScanError(BaseModel):
    """Structured scan or parser failure."""

    path: str
    error_type: str
    message: str
    exception_class: str | None = None


class Finding(BaseModel):
    check_id: str
    title: str
    result: CheckResult
    severity: Severity
    algorithm: str | None = None
    evidence_type: EvidenceType
    confidence: Confidence
    location: str
    message: str
    standard_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CryptoComponent(BaseModel):
    name: str
    algorithm: str
    key_size: int | None = None
    asset_type: str = "algorithm"
    component_type: str = "cryptographic-asset"
    bom_ref: str
    properties: dict[str, str] = Field(default_factory=dict)
    parameter_set: str | None = None
    primitive: str | None = None
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None
    quantum_status: QuantumStatus | None = None
    hybrid: bool = False
    hybrid_components: list[str] = Field(default_factory=list)
    subject_name: str | None = None
    issuer_name: str | None = None
    not_valid_before: str | None = None
    not_valid_after: str | None = None


class ScanContext(BaseModel):
    ownership_attestation: bool = False
    allow_endpoint_probe: bool = False
    redact_secrets: bool = True
    max_file_bytes: int = 10_485_760
    max_files: int = 10_000
    scan_timeout_seconds: int = 300


class SystemContext(BaseModel):
    system_id: str
    name: str
    criticality: int = Field(ge=1, le=5)
    confidentiality_years: int = Field(ge=0)
    exposure: str = "internal"
    description: str = ""


class PrioritizedFinding(Finding):
    priority_score: float = 0.0
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    system_id: str | None = None


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    components: list[CryptoComponent] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str = ""
    negative_scope: list[str] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    skipped_files: list[str] = Field(default_factory=list)


def default_negative_scope() -> list[str]:
    return [
        "KMS and cloud key management services",
        "Hardware security modules (HSM)",
        "Runtime memory and live process state",
        "Network traffic not captured in imported endpoint scans",
        "Encrypted data at rest without key metadata",
        "Third-party SaaS cryptographic implementations",
    ]
