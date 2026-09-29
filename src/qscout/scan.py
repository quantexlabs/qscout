"""Scan orchestration."""

from __future__ import annotations

import sys
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any

from qscout.checks.engine import evaluate_evidence
from qscout.collectors.config_tls import collect_tls_config
from qscout.models import ScanContext, ScanError, ScanResult, default_negative_scope
from qscout.parsers.manifests import (
    parse_package_json,
    parse_requirements_txt,
    scan_python_source,
)
from qscout.parsers.result import ParseResult
from qscout.parsers.x509 import parse_certificate
from qscout.security import SecurityError, resolve_safe_path

TEXT_EXTENSIONS = frozenset(
    {
        ".py",
        ".java",
        ".go",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".conf",
        ".cfg",
        ".cnf",
        ".yaml",
        ".yml",
        ".json",
        ".txt",
        ".pem",
        ".crt",
        ".cer",
        ".key",
    }
)

CERT_EXTENSIONS = frozenset({".pem", ".crt", ".cer", ".der"})
CONFIG_NAMES = frozenset(
    {"nginx.conf", "openssl.cnf", "java.security", "haproxy.cfg", "tls.conf"}
)


class ScanTimeoutError(TimeoutError):
    """Raised when scan exceeds timeout."""


def _scan_path_worker(args: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    target_s, context_data = args
    result = _scan_path_impl(Path(target_s), ScanContext.model_validate(context_data))
    return result.model_dump(mode="json")


def scan_path(target: Path, context: ScanContext) -> ScanResult:
    """Scan a directory tree and return findings."""
    if not context.ownership_attestation:
        raise ValueError("--attest-ownership is required")

    base = target.resolve()
    if not base.exists():
        raise FileNotFoundError(base)

    if context.scan_timeout_seconds > 0:
        with ProcessPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                _scan_path_worker,
                (str(base), context.model_dump()),
            )
            try:
                data = future.result(timeout=context.scan_timeout_seconds)
            except FuturesTimeout:
                raise ScanTimeoutError(
                    f"Scan exceeded {context.scan_timeout_seconds}s timeout"
                ) from None
            return ScanResult.model_validate(data)

    return _scan_path_impl(base, context)


def _scan_path_impl(target: Path, context: ScanContext) -> ScanResult:
    evidence: list[dict[str, Any]] = []
    errors: list[ScanError] = []
    skipped: list[str] = []
    file_count = 0

    if target.is_file():
        if target.stat().st_size > context.max_file_bytes:
            errors.append(
                ScanError(
                    path=str(target),
                    error_type="oversized_file",
                    message=(
                        f"File exceeds size limit "
                        f"({target.stat().st_size} > {context.max_file_bytes})"
                    ),
                )
            )
        else:
            _merge_scan_file(_scan_file(target, context), evidence, errors)
    else:
        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            file_count += 1
            if file_count > context.max_files:
                skipped.append(str(path))
                continue
            try:
                resolve_safe_path(target, path.relative_to(target))
            except SecurityError as exc:
                errors.append(
                    ScanError(
                        path=str(path),
                        error_type="path_blocked",
                        message=str(exc),
                        exception_class=type(exc).__name__,
                    )
                )
                skipped.append(str(path))
                continue
            if path.stat().st_size > context.max_file_bytes:
                errors.append(
                    ScanError(
                        path=str(path),
                        error_type="oversized_file",
                        message=(
                            f"File exceeds size limit "
                            f"({path.stat().st_size} > {context.max_file_bytes})"
                        ),
                    )
                )
                skipped.append(str(path))
                continue
            _merge_scan_file(_scan_file(path, context), evidence, errors)

    findings, components = evaluate_evidence(evidence)
    return ScanResult(
        findings=findings,
        components=components,
        target=str(target),
        negative_scope=default_negative_scope(),
        errors=errors,
        skipped_files=skipped,
    )


def _merge_scan_file(
    result: ParseResult,
    evidence: list[dict[str, Any]],
    errors: list[ScanError],
) -> None:
    evidence.extend(result.evidence)
    errors.extend(result.errors)


def _scan_file(path: Path, context: ScanContext) -> ParseResult:
    combined = ParseResult()
    suffix = path.suffix.lower()
    name = path.name.lower()
    max_bytes = context.max_file_bytes

    if suffix in CERT_EXTENSIONS or "certificate" in name:
        _merge_parse_result(combined, parse_certificate(path, max_bytes))

    if name in CONFIG_NAMES or "ssl" in name or suffix in (".conf", ".cnf"):
        _merge_parse_result(combined, collect_tls_config(path, max_bytes))

    if name == "requirements.txt":
        _merge_parse_result(combined, parse_requirements_txt(path, max_bytes))

    if name == "package.json":
        _merge_parse_result(combined, parse_package_json(path, max_bytes))

    if suffix == ".py":
        _merge_parse_result(combined, scan_python_source(path, max_bytes))

    return combined


def _merge_parse_result(target: ParseResult, source: ParseResult) -> None:
    target.evidence.extend(source.evidence)
    target.errors.extend(source.errors)


if __name__ == "__main__" and "pytest" not in sys.modules:
    pass
