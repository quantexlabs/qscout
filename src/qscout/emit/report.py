"""Accessible HTML report generator."""

from __future__ import annotations

from qscout.models import PrioritizedFinding, ScanResult
from qscout.security import escape_html, sanitize_location


def render_html(
    scan_result: ScanResult,
    prioritized: list[PrioritizedFinding] | None = None,
) -> str:
    """Render WCAG-minded HTML report."""
    findings = prioritized or [
        PrioritizedFinding(**f.model_dump(), priority_score=0.0) for f in scan_result.findings
    ]
    fail_count = sum(1 for f in findings if f.result.value == "fail")
    info_count = sum(1 for f in findings if f.result.value == "info")
    error_count = len(scan_result.errors)
    skipped_count = len(scan_result.skipped_files)

    rows = []
    for f in findings:
        severity_label = _severity_label(f.severity.value)
        safe_location = escape_html(_safe_location(f.location))
        rows.append(
            f"<tr>"
            f"<td>{escape_html(f.check_id)}</td>"
            f"<td>{escape_html(f.title)}</td>"
            f"<td><span class='severity severity-{escape_html(f.severity.value)}'>"
            f"{severity_label}</span></td>"
            f"<td>{escape_html(f.result.value)}</td>"
            f"<td>{safe_location}</td>"
            f"<td>{escape_html(f.message)}</td>"
            f"<td>{f.priority_score:.1f}</td>"
            f"</tr>"
        )

    negative_items = "".join(
        f"<li>{escape_html(item)}</li>" for item in scan_result.negative_scope
    )

    error_rows = "".join(
        f"<tr><td>{escape_html(e.path)}</td>"
        f"<td>{escape_html(e.error_type)}</td>"
        f"<td>{escape_html(e.message)}</td></tr>"
        for e in scan_result.errors
    )

    skipped_items = "".join(
        f"<li>{escape_html(path)}</li>" for path in scan_result.skipped_files[:50]
    )
    if len(scan_result.skipped_files) > 50:
        skipped_items += (
            f"<li>{escape_html(f'... and {len(scan_result.skipped_files) - 50} more')}</li>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>qscout Cryptographic Inventory Report</title>
  <style>
    :root {{ font-family: system-ui, sans-serif; line-height: 1.5; }}
    body {{ margin: 0; padding: 1rem 2rem; max-width: 1200px; }}
    main {{ display: block; }}
    nav[aria-label="Report sections"] {{ margin-bottom: 1.5rem; }}
    nav a {{ margin-right: 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #333; padding: 0.5rem; text-align: left; }}
    caption {{ caption-side: top; font-weight: bold; margin-bottom: 0.5rem; }}
    th {{ background: #eee; }}
    .severity {{ font-weight: bold; }}
    .severity-critical::before {{ content: "⛔ "; }}
    .severity-high::before {{ content: "⚠ "; }}
    .severity-medium::before {{ content: "◆ "; }}
    .severity-low::before {{ content: "· "; }}
    .severity-info::before {{ content: "[i] "; }}
    a:focus-visible, button:focus-visible {{
      outline: 3px solid #005fcc;
      outline-offset: 2px;
    }}
    .summary-stat {{ font-weight: bold; }}
  </style>
</head>
<body>
  <header role="banner">
    <h1>qscout Cryptographic Inventory Report</h1>
    <p>Target: {escape_html(scan_result.target)}</p>
    <p>Scanned: {escape_html(scan_result.scanned_at.isoformat())}</p>
  </header>
  <nav aria-label="Report sections">
    <a href="#summary">Summary</a>
    <a href="#findings">Findings</a>
    <a href="#diagnostics">Diagnostics</a>
    <a href="#scope">Scope limitations</a>
  </nav>
  <main role="main">
    <section id="summary" aria-labelledby="summary-heading">
      <h2 id="summary-heading">Executive Summary</h2>
      <p>
        This report summarizes cryptographic inventory findings for alignment assistance.
        It is incomplete by design and does not constitute compliance certification.
      </p>
      <p>
        <span class="summary-stat">Findings requiring action:</span> {fail_count}
        &nbsp;|&nbsp;
        <span class="summary-stat">Informational:</span> {info_count}
        &nbsp;|&nbsp;
        <span class="summary-stat">Components:</span> {len(scan_result.components)}
        &nbsp;|&nbsp;
        <span class="summary-stat">Scan errors:</span> {error_count}
        &nbsp;|&nbsp;
        <span class="summary-stat">Skipped files:</span> {skipped_count}
      </p>
    </section>
    <section id="findings" aria-labelledby="findings-heading">
      <h2 id="findings-heading">Findings</h2>
      <table>
        <caption>Cryptographic check results (CRYPTO-001 through CRYPTO-012)</caption>
        <thead>
          <tr>
            <th scope="col">Check ID</th>
            <th scope="col">Title</th>
            <th scope="col">Severity</th>
            <th scope="col">Result</th>
            <th scope="col">Location</th>
            <th scope="col">Message</th>
            <th scope="col">Priority Score</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rows) if rows else "<tr><td colspan='7'>No findings</td></tr>"}
        </tbody>
      </table>
    </section>
    <section id="diagnostics" aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">Scan Diagnostics</h2>
      <p>
        <span class="summary-stat">Errors:</span> {error_count}
        &nbsp;|&nbsp;
        <span class="summary-stat">Skipped files:</span> {skipped_count}
      </p>
      <table>
        <caption>Structured scan errors</caption>
        <thead>
          <tr>
            <th scope="col">Path</th>
            <th scope="col">Type</th>
            <th scope="col">Message</th>
          </tr>
        </thead>
        <tbody>
          {error_rows if error_rows else "<tr><td colspan='3'>No errors</td></tr>"}
        </tbody>
      </table>
      {"<h3>Skipped files</h3><ul>" + skipped_items + "</ul>" if skipped_items else ""}
    </section>
    <section id="scope" aria-labelledby="scope-heading">
      <h2 id="scope-heading">Negative Scope</h2>
      <p>The following areas were <strong>not</strong> inspected:</p>
      <ul>
        {negative_items}
      </ul>
    </section>
  </main>
  <footer role="contentinfo">
    <p>Generated by qscout. Standards mapping uses informed-by phrasing unless exact.</p>
  </footer>
</body>
</html>"""


def _safe_location(location: str) -> str:
    try:
        return sanitize_location(location)
    except Exception:
        return location


def _severity_label(severity: str) -> str:
    labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }
    return labels.get(severity, severity.title())


def write_report(
    scan_result: ScanResult,
    path: str,
    prioritized: list[PrioritizedFinding] | None = None,
) -> None:
    """Write HTML report to file."""
    html = render_html(scan_result, prioritized)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
