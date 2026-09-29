"""Pytest fixtures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
CERTS_DIR = FIXTURES / "certs"


@pytest.fixture(scope="session", autouse=True)
def generate_certs() -> None:
    """Generate self-signed certificates for tests."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    rsa_cert = CERTS_DIR / "rsa2048.pem"
    if not rsa_cert.exists():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(CERTS_DIR / "rsa2048-key.pem"),
                "-out",
                str(rsa_cert),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=test.local",
            ],
            check=True,
            capture_output=True,
        )
    weak_cert = CERTS_DIR / "rsa1024.pem"
    if not weak_cert.exists():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:1024",
                "-keyout",
                str(CERTS_DIR / "rsa1024-key.pem"),
                "-out",
                str(weak_cert),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=weak.test",
            ],
            check=True,
            capture_output=True,
        )
    expired_cert = CERTS_DIR / "expired.pem"
    if not expired_cert.exists():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(CERTS_DIR / "expired-key.pem"),
                "-out",
                str(expired_cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=expired.test",
            ],
            check=True,
            capture_output=True,
        )


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
