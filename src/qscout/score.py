"""Priority scoring with systems.yaml context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qscout.models import Finding, PrioritizedFinding, ScanResult, SystemContext
from qscout.registry import ASYMMETRIC_VULNERABLE, normalize_algorithm
from qscout.security import safe_load_yaml


def load_systems_yaml(path: Path) -> list[SystemContext]:
    """Load systems context from YAML."""
    data = safe_load_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("systems.yaml must be a mapping with 'systems' key")
    systems_raw = data.get("systems")
    if not isinstance(systems_raw, list):
        raise ValueError("systems.yaml must contain a 'systems' list")
    systems: list[SystemContext] = []
    for entry in systems_raw:
        if not isinstance(entry, dict):
            continue
        if "criticality" not in entry or "confidentiality_years" not in entry:
            raise ValueError(
                f"System {entry.get('system_id', '?')} missing criticality or "
                "confidentiality_years"
            )
        systems.append(SystemContext.model_validate(entry))
    if not systems:
        raise ValueError("systems.yaml must define at least one system")
    return systems


def prioritize_findings(
    scan_result: ScanResult,
    systems: list[SystemContext],
    default_system_id: str | None = None,
) -> list[PrioritizedFinding]:
    """Score findings using HNDL-aware model."""
    default = systems[0]
    if default_system_id:
        for s in systems:
            if s.system_id == default_system_id:
                default = s
                break

    prioritized: list[PrioritizedFinding] = []
    for finding in scan_result.findings:
        system = default
        score, breakdown = _compute_score(finding, system)
        prioritized.append(
            PrioritizedFinding(
                **finding.model_dump(),
                priority_score=score,
                score_breakdown=breakdown,
                system_id=system.system_id,
            )
        )
    prioritized.sort(key=lambda f: f.priority_score, reverse=True)
    return prioritized


def _compute_score(finding: Finding, system: SystemContext) -> tuple[float, dict[str, float]]:
    """Explainable 0-100 score based on ITSM.40.001-informed factors."""
    breakdown: dict[str, float] = {}

    hndl = min(30.0, system.confidentiality_years * 3.0)
    breakdown["hndl_retention"] = hndl

    sensitivity = system.criticality * 4.0
    breakdown["data_sensitivity"] = sensitivity

    exposure_map = {"internet": 15.0, "partner": 10.0, "internal": 5.0}
    breakdown["exposure"] = exposure_map.get(system.exposure, 5.0)

    algo = normalize_algorithm(finding.algorithm or "")
    asym = 15.0 if algo in ASYMMETRIC_VULNERABLE else 0.0
    breakdown["asymmetric_vulnerability"] = asym

    severity_map = {
        "critical": 10.0,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
        "info": 0.0,
    }
    breakdown["finding_severity"] = severity_map.get(finding.severity.value, 5.0)

    friction = 10.0 if finding.check_id == "CRYPTO-010" else 5.0
    breakdown["migration_friction"] = friction

    total = min(100.0, sum(breakdown.values()))
    return round(total, 2), breakdown


def load_scan_result_json(path: Path) -> ScanResult:
    """Load scan result from JSON file."""
    import json

    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)
