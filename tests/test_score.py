"""Priority scoring tests."""

from pathlib import Path

import pytest

from qscout.models import CheckResult, Confidence, EvidenceType, Finding, ScanResult, Severity
from qscout.score import load_systems_yaml, prioritize_findings

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_systems_yaml() -> None:
    systems = load_systems_yaml(FIXTURES / "systems.yaml")
    assert len(systems) == 2
    assert systems[0].criticality == 5
    assert systems[0].confidentiality_years == 15


def test_load_systems_missing_fields(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("systems:\n  - system_id: x\n    name: y\n")
    with pytest.raises(ValueError, match="criticality"):
        load_systems_yaml(bad)


def test_prioritize_orders_by_score() -> None:
    systems = load_systems_yaml(FIXTURES / "systems.yaml")
    scan = ScanResult(
        findings=[
            Finding(
                check_id="CRYPTO-002",
                title="RSA",
                result=CheckResult.FAIL,
                severity=Severity.HIGH,
                evidence_type=EvidenceType.SOURCE,
                confidence=Confidence.CONFIRMED,
                location="a",
                message="rsa",
                algorithm="RSA",
            ),
            Finding(
                check_id="CRYPTO-010",
                title="dep",
                result=CheckResult.FAIL,
                severity=Severity.LOW,
                evidence_type=EvidenceType.DEPENDENCY,
                confidence=Confidence.DEPENDENCY_ONLY,
                location="b",
                message="dep",
            ),
        ]
    )
    prioritized = prioritize_findings(scan, systems)
    assert prioritized[0].priority_score >= prioritized[1].priority_score
    assert prioritized[0].score_breakdown
