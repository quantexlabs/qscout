"""Security utilities: URL validation, path safety, HTML escaping, safe YAML."""

from __future__ import annotations

import html
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

MAX_PATH_DEPTH = 64
BLOCKED_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})

_RE_PEM_PRIVATE_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s*"
    r".*?"
    r"\s*-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)


class SecurityError(ValueError):
    """Raised when a security constraint is violated."""


def validate_url(url: str) -> str:
    """Validate a URL; reject dangerous schemes and protocol-relative URLs."""
    if not url or not url.strip():
        raise SecurityError("URL must not be empty")
    stripped = url.strip()
    if stripped.startswith("//"):
        raise SecurityError("Protocol-relative URLs are not allowed")
    parsed = urlparse(stripped)
    if not parsed.scheme:
        raise SecurityError(f"URL missing scheme: {stripped}")
    scheme = parsed.scheme.lower()
    if scheme in BLOCKED_SCHEMES:
        raise SecurityError(f"Blocked URL scheme: {scheme}")
    if scheme not in ("http", "https", "ssh", "tls"):
        raise SecurityError(f"Unsupported URL scheme: {scheme}")
    return stripped


def sanitize_location(location: str) -> str:
    """Validate URL locations before persistence or rendering."""
    if location.startswith(("http://", "https://", "ssh://", "tls://")):
        return validate_url(location)
    if location.startswith(("endpoint:", "ssh:")):
        host_part = location.split(":", 1)[1]
        if host_part.startswith("//"):
            validate_url(f"https:{host_part}")
        elif "://" in host_part or (
            ":" in host_part and host_part.split(":", 1)[0].isalpha()
        ):
            validate_url(host_part)
    return location


def escape_html(text: str) -> str:
    """Escape text for safe HTML output."""
    return html.escape(text, quote=True)


def safe_load_yaml(content: str) -> Any:
    """Load YAML safely without arbitrary object construction."""
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise SecurityError(f"Unsafe or invalid YAML: {exc}") from exc


def resolve_safe_path(base: Path, user_path: str | Path) -> Path:
    """Resolve a path under base; reject traversal attempts."""
    base_resolved = base.resolve()
    if isinstance(user_path, str):
        if "\x00" in user_path:
            raise SecurityError("Null byte in path")
        candidate = (base_resolved / user_path).resolve()
    else:
        if "\x00" in str(user_path):
            raise SecurityError("Null byte in path")
        if user_path.is_absolute():
            candidate = user_path.resolve()
        else:
            candidate = (base_resolved / user_path).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        raise SecurityError(f"Path traversal blocked: {user_path}") from None
    parts = candidate.parts
    if len(parts) > MAX_PATH_DEPTH:
        raise SecurityError("Path exceeds maximum depth")
    return candidate


def read_bounded_bytes(path: Path, max_bytes: int) -> bytes:
    """Read a file with a byte limit."""
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise SecurityError(f"File exceeds size limit ({size} > {max_bytes}): {path}")
    return path.read_bytes()


def read_bounded_file(path: Path, max_bytes: int) -> str:
    """Read a text file with a byte limit."""
    return read_bounded_bytes(path, max_bytes).decode("utf-8", errors="replace")


def safe_delete_file(path: Path) -> None:
    """Delete a single file; never recurse into directories."""
    if path.is_dir():
        raise SecurityError(f"Refusing to delete directory: {path}")
    if path.is_file():
        path.unlink()


def enforce_no_network() -> None:
    """Raise if PQC_INVENTORY_NO_NETWORK is set and network would be used."""
    if os.environ.get("PQC_INVENTORY_NO_NETWORK") == "1":
        raise SecurityError("Network access disabled by PQC_INVENTORY_NO_NETWORK")


def redact_secrets(text: str) -> str:
    """Redact PEM private key blocks from text."""
    return _RE_PEM_PRIVATE_BLOCK.sub("[REDACTED:private-key]", text)
