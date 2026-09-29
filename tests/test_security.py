"""Security utility tests."""

from pathlib import Path

import pytest

from qscout.security import (
    SecurityError,
    enforce_no_network,
    escape_html,
    read_bounded_file,
    redact_secrets,
    resolve_safe_path,
    safe_delete_file,
    safe_load_yaml,
    sanitize_location,
    validate_url,
)


def test_validate_url_accepts_https() -> None:
    assert validate_url("https://example.com/path") == "https://example.com/path"


def test_validate_url_rejects_javascript() -> None:
    with pytest.raises(SecurityError, match="Blocked"):
        validate_url("javascript:alert(1)")


def test_validate_url_rejects_data() -> None:
    with pytest.raises(SecurityError, match="Blocked"):
        validate_url("data:text/html,<script>")


def test_validate_url_rejects_protocol_relative() -> None:
    with pytest.raises(SecurityError, match="Protocol-relative"):
        validate_url("//evil.com/path")


def test_validate_url_rejects_empty() -> None:
    with pytest.raises(SecurityError):
        validate_url("")


def test_escape_html() -> None:
    assert escape_html("<script>") == "&lt;script&gt;"


def test_safe_yaml_no_arbitrary_objects() -> None:
    data = safe_load_yaml("key: value\nlist:\n  - one")
    assert data["key"] == "value"


def test_path_traversal_blocked(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        resolve_safe_path(tmp_path, "../../etc/passwd")


def test_path_prefix_fallback_rejected(tmp_path: Path) -> None:
    base = tmp_path / "qscout-base"
    base.mkdir()
    evil = tmp_path / "qscout-base-evil"
    evil.mkdir()
    evil_file = evil / "secret.txt"
    evil_file.write_text("stolen")
    with pytest.raises(SecurityError):
        resolve_safe_path(base, "../qscout-base-evil/secret.txt")


def test_read_bounded_file(tmp_path: Path) -> None:
    f = tmp_path / "small.txt"
    f.write_text("hello")
    assert read_bounded_file(f, 100) == "hello"


def test_read_bounded_file_too_large(tmp_path: Path) -> None:
    f = tmp_path / "big.txt"
    f.write_text("x" * 100)
    with pytest.raises(SecurityError):
        read_bounded_file(f, 10)


def test_safe_delete_file_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        safe_delete_file(tmp_path)


def test_safe_delete_file_works(tmp_path: Path) -> None:
    f = tmp_path / "remove.txt"
    f.write_text("gone")
    safe_delete_file(f)
    assert not f.exists()


def test_enforce_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQC_INVENTORY_NO_NETWORK", "1")
    with pytest.raises(SecurityError):
        enforce_no_network()


def test_redact_secrets_removes_entire_block() -> None:
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAsecretbody\n"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted = redact_secrets(text)
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "END RSA PRIVATE KEY" not in redacted
    assert "secretbody" not in redacted
    assert "[REDACTED:private-key]" in redacted


def test_redact_secrets_openssh_block() -> None:
    text = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    redacted = redact_secrets(text)
    assert "OPENSSH PRIVATE KEY" not in redacted
    assert "b3BlbnNzaC1rZXk" not in redacted


def test_null_byte_in_path(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        resolve_safe_path(tmp_path, "foo\x00bar")


def test_validate_url_unsupported_scheme() -> None:
    with pytest.raises(SecurityError, match="Unsupported"):
        validate_url("ftp://example.com")


def test_validate_url_missing_scheme() -> None:
    with pytest.raises(SecurityError, match="missing scheme"):
        validate_url("example.com")


def test_resolve_absolute_path_outside_base(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    with pytest.raises(SecurityError):
        resolve_safe_path(tmp_path, outside)


def test_read_bounded_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        read_bounded_file(Path("/nonexistent/file.txt"), 100)


def test_sanitize_location_validates_endpoint_url() -> None:
    assert sanitize_location("endpoint:https://example.com") == "endpoint:https://example.com"


def test_sanitize_location_rejects_javascript_in_endpoint() -> None:
    with pytest.raises(SecurityError):
        sanitize_location("endpoint:javascript:alert(1)")
