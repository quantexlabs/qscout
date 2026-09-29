"""Output emitters."""

from qscout.emit.cyclonedx import emit_cbom, write_cbom
from qscout.emit.report import render_html, write_report

__all__ = ["emit_cbom", "render_html", "write_cbom", "write_report"]
