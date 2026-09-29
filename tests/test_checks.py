"""Check engine tests for all CRYPTO-001 through CRYPTO-012."""

from qscout.checks.engine import evaluate_evidence
from qscout.checks.rules import CHECKS, all_check_ids


def test_all_twelve_checks_defined() -> None:
    ids = all_check_ids()
    assert len(ids) == 12
    assert ids[0] == "CRYPTO-001"
    assert ids[-1] == "CRYPTO-012"


def test_crypto_001_rsa_weak_key() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "rsa_key_size", "location": "t", "algorithm": "RSA", "key_size": 1024}]
    )
    assert any(f.check_id == "CRYPTO-001" and f.result.value == "fail" for f in findings)


def test_crypto_001_pass_no_finding_for_strong_key() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "rsa_key_size", "location": "t", "algorithm": "RSA", "key_size": 4096}]
    )
    assert not any(f.check_id == "CRYPTO-001" for f in findings)


def test_crypto_002_rsa_encrypt() -> None:
    findings, _ = evaluate_evidence([{"kind": "rsa_encrypt", "location": "app.py"}])
    assert any(f.check_id == "CRYPTO-002" for f in findings)


def test_crypto_003_ecdh() -> None:
    findings, _ = evaluate_evidence([{"kind": "ecdh", "location": "tls", "algorithm": "ECDH"}])
    assert any(f.check_id == "CRYPTO-003" for f in findings)


def test_crypto_003_dh() -> None:
    findings, _ = evaluate_evidence([{"kind": "dh", "location": "tls", "algorithm": "DH"}])
    assert any(f.check_id == "CRYPTO-003" for f in findings)


def test_crypto_004_signature() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "signature", "location": "sign.py", "algorithm": "ECDSA"}]
    )
    assert any(f.check_id == "CRYPTO-004" for f in findings)


def test_crypto_005_dsa() -> None:
    findings, _ = evaluate_evidence([{"kind": "dsa", "location": "sign.py"}])
    assert any(f.check_id == "CRYPTO-005" for f in findings)


def test_crypto_006_hardcoded() -> None:
    findings, _ = evaluate_evidence([{"kind": "hardcoded_key", "location": "secrets.py"}])
    assert any(f.check_id == "CRYPTO-006" for f in findings)


def test_crypto_007_weak_hash() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "weak_hash", "location": "h.py", "algorithm": "MD5"}]
    )
    assert any(f.check_id == "CRYPTO-007" for f in findings)


def test_crypto_008_weak_tls() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "weak_tls", "location": "nginx.conf", "message": "TLS 1.0"}]
    )
    assert any(f.check_id == "CRYPTO-008" for f in findings)


def test_crypto_009_cert() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "cert_issue", "location": "cert.pem", "message": "expired"}]
    )
    assert any(f.check_id == "CRYPTO-009" for f in findings)


def test_crypto_010_dependency() -> None:
    findings, _ = evaluate_evidence([{"kind": "unresolved_dependency", "location": "req.txt"}])
    assert any(f.check_id == "CRYPTO-010" for f in findings)


def test_crypto_011_pqc() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "pqc_present", "location": "pqc.py", "algorithm": "ML-KEM-768"}]
    )
    assert any(f.check_id == "CRYPTO-011" and f.result.value == "info" for f in findings)


def test_crypto_012_stateful() -> None:
    findings, _ = evaluate_evidence(
        [{"kind": "stateful_hash", "location": "fw", "algorithm": "LMS"}]
    )
    assert any(f.check_id == "CRYPTO-012" for f in findings)


def test_check_standard_refs_use_informed_by() -> None:
    for check_id, check in CHECKS.items():
        for ref in check.standard_refs:
            if "NIST" in ref or "CCCS" in ref:
                assert "informed by" in ref or check_id == "CRYPTO-011"
