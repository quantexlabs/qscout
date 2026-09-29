"""Malicious input handling tests."""

from pathlib import Path

import pytest

from qscout.security import SecurityError, escape_html, safe_load_yaml, validate_url


def test_yaml_safe_no_code_execution() -> None:
    with pytest.raises(SecurityError):
        safe_load_yaml("!!python/object/apply:os.system\nargs: ['echo hi']")


def test_html_injection_escaped() -> None:
    payload = '<img src=x onerror="alert(1)">'
    escaped = escape_html(payload)
    assert "<img" not in escaped
    assert "&lt;img" in escaped


@pytest.mark.parametrize(
    "url",
    [
        "javascript:void(0)",
        "data:text/html,base64,abc",
        "//attacker.example/evil",
        "vbscript:msgbox",
    ],
)
def test_blocked_urls(url: str) -> None:
    with pytest.raises(SecurityError):
        validate_url(url)


def test_oversized_json_import(tmp_path: Path) -> None:
    from qscout.parsers.testssl import parse_testssl

    big = tmp_path / "big.json"
    big.write_text("x" * 100)
    result = parse_testssl(big, max_bytes=10)
    assert result.errors
    assert result.errors[0].error_type == "oversized_file"
