"""Evidence parsers for external tool output."""

from qscout.parsers.sonar import parse_sonar_cbom
from qscout.parsers.ssh_audit import parse_ssh_audit
from qscout.parsers.testssl import parse_testssl
from qscout.parsers.x509 import parse_certificate

__all__ = [
    "parse_certificate",
    "parse_sonar_cbom",
    "parse_ssh_audit",
    "parse_testssl",
]
