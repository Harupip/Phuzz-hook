from __future__ import annotations

import json
from pathlib import Path


def write_json_report(report, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def write_markdown_summary(report, output_path: Path) -> None:
    lines = [
        f"# Hook visualization summary for {report.metadata.label}",
        "",
        f"- requests_total: {report.summary.requests_total}",
        f"- executed_callbacks_total: {report.summary.executed_callbacks_total}",
        f"- blindspots_total: {report.summary.blindspots_total}",
        f"- boosted_decisions_count: {report.summary.boosted_decisions_count}",
        f"- avg_hook_energy: {report.summary.avg_hook_energy:.6f}",
        f"- avg_priority_delta: {report.summary.avg_priority_delta:.6f}",
        f"- avg_energy_delta: {report.summary.avg_energy_delta:.6f}",
    ]
    if report.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend([f"- {warning}" for warning in report.warnings])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_html_report(report, output_path: Path) -> None:
    candidate_title = "Concrete boosted candidate"
    warnings_html = ""
    if report.warnings:
        warning_items = "".join(f"<li>{warning}</li>" for warning in report.warnings)
        warnings_html = f"""
  <section>
    <h2>Warnings</h2>
    <ul>{warning_items}</ul>
  </section>"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Hook visualization report - {report.metadata.label}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e5e7eb; }}
    section {{ margin-bottom: 24px; padding: 16px; border: 1px solid #334155; background: #111827; }}
    .metric-grid {{ display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 12px; }}
    .metric {{ padding: 12px; border: 1px solid #334155; }}
  </style>
</head>
<body>
  <h1>Hook visualization report</h1>
  <section>
    <h2>Run overview</h2>
    <div class="metric-grid">
      <div class="metric">boosted_decisions_count: {report.summary.boosted_decisions_count}</div>
      <div class="metric">avg_hook_energy: {report.summary.avg_hook_energy:.6f}</div>
      <div class="metric">coverage_ratio: {report.summary.coverage_ratio:.4f}</div>
      <div class="metric">blindspots_total: {report.summary.blindspots_total}</div>
    </div>
  </section>
  <section>
    <h2>{candidate_title}</h2>
    <p>Show the first boosted decision here during implementation.</p>
  </section>
  {warnings_html}
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
