"""Algorithm registry tests."""

from qscout.registry import (
    is_pqc_algorithm,
    is_stateful_hash,
    normalize_algorithm,
)


def test_normalize_kyber() -> None:
    assert normalize_algorithm("kyber768") == "ML-KEM-768"


def test_normalize_rsa() -> None:
    assert normalize_algorithm("RSA") == "RSA"


def test_is_pqc() -> None:
    assert is_pqc_algorithm("ML-KEM-768")
    assert not is_pqc_algorithm("RSA")


def test_is_stateful_hash() -> None:
    assert is_stateful_hash("XMSS")
    assert not is_stateful_hash("RSA")


def test_slh_dsa_parameter_set_preserved() -> None:
    assert normalize_algorithm("slh-dsa-sha2-128s") == "SLH-DSA-SHA2-128s"
    assert is_pqc_algorithm("SLH-DSA-SHA2-128s")
