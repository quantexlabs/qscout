"""Parser result containers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from qscout.models import ScanError


@dataclass
class ParseResult:
    """Evidence and structured errors from a single parser invocation."""

    evidence: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
