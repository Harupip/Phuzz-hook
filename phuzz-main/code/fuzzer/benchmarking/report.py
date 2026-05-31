from __future__ import annotations

import argparse
import csv
import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MODE_ORDER = {
    "PHUZZ_RAW": 0,
    "PHUZZ_TRACE": 1,
    "HOOK_TRACE": 2,
    "HOOK_FAST": 3,
}

MODE_COLORS = {
    "PHUZZ_RAW": "#1f77b4",
    "PHUZZ_TRACE": "#ff7f0e",
    "HOOK_TRACE": "#2ca02c",
    "HOOK_FAST": "#d62728",
}

MODE_LABELS = {
    "PHUZZ_RAW": "PHUZZ raw",
    "PHUZZ_TRACE": "PHUZZ original",
    "HOOK_TRACE": "HookPHuzz",
    "HOOK_FAST": "HookPHuzz fast",
}


@dataclass(frozen=True)
class ReportArtifacts:
    markdown_path: Path
    svg_path: Path


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _format_number(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "n/a"


def _format_ratio(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def _mode_sort_key(mode: str) -> tuple[int, str]:
    return MODE_ORDER.get(mode, 100), mode


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _read_timeline(path: Path) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            parsed: dict[str, float] = {}
            for key, value in row.items():
                if value in (None, ""):
                    parsed[key] = 0.0
                    continue
                try:
                    parsed[key] = float(value)
                except ValueError:
                    parsed[key] = 0.0
            rows.append(parsed)
    return rows


def _discover_run_dirs(root: Path) -> list[Path]:
    return sorted(
        [path for path in root.iterdir() if path.is_dir() and "-run-" in path.name],
        key=lambda item: (_mode_sort_key(item.name.split("-run-", 1)[0]), item.name),
    )


def _load_manifest(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "run_manifest.json"
    if not path.exists():
        return {}
    return _load_json(path)


def _mode_for_run(run_dir: Path) -> str:
    manifest = _load_manifest(run_dir)
    mode = str(manifest.get("mode", "")).strip()
    if mode:
        return mode
    return run_dir.name.split("-run-", 1)[0]


def _missing_artifacts(root: Path, run_dirs: list[Path]) -> list[str]:
    required = [
        root / "benchmark_results.json",
        root / "benchmark_results.csv",
    ]
    for run_dir in run_dirs:
        required.extend(
            [
                run_dir / "coverage_timeline.csv",
                run_dir / "benchmark_summary.json",
                run_dir / "run_manifest.json",
            ]
        )
        if _mode_for_run(run_dir) == "HOOK_FAST":
            required.extend(
                [
                    run_dir / "trace-phase",
                    run_dir / "seed-export" / "hook_gap_report.json",
                    run_dir / "seed-export" / "suggested_seeds.json",
                    run_dir / "hook-fast-config.json",
                ]
            )
    return [_relative(path, root) for path in required if not path.exists()]


def _seed_export_summary(run_dirs: list[Path]) -> str:
    hook_fast_dirs = [path for path in run_dirs if _mode_for_run(path) == "HOOK_FAST"]
    if not hook_fast_dirs:
        return "HOOK_FAST was not run."

    path = hook_fast_dirs[0] / "seed-export" / "hook_gap_report.json"
    if not path.exists():
        return "HOOK_FAST seed export is missing."

    payload = _load_json(path)
    summary = payload.get("summary", {})
    return (
        f"registered={summary.get('registered_callbacks', 'n/a')}, "
        f"uncovered={summary.get('uncovered_callbacks', 'n/a')}, "
        f"direct_http_candidates={summary.get('direct_http_seed_candidates', 'n/a')}"
    )


def _mode_rows(aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    rows = aggregate.get("modes", [])
    if not isinstance(rows, list):
        return []
    return sorted([row for row in rows if isinstance(row, dict)], key=lambda item: _mode_sort_key(str(item.get("mode", ""))))


def _run_rows(aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    rows = aggregate.get("runs", [])
    if not isinstance(rows, list):
        return []
    return sorted([row for row in rows if isinstance(row, dict)], key=lambda item: _mode_sort_key(str(item.get("mode", ""))))


def _build_eps_table(mode_rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Mode | EPS | UOPZ ratio | Vulns@budget | First vuln |",
        "|---|---:|---:|---:|---|",
    ]
    for row in mode_rows:
        mode = str(row.get("mode", "unknown"))
        first_vuln = row.get("median_time_to_first_unique_vuln_seconds")
        first_vuln_text = "none" if first_vuln is None else f"{_format_number(first_vuln, 0)}s"
        lines.append(
            "| {mode} | {eps} | {ratio} | {vulns} | {first_vuln} |".format(
                mode=mode,
                eps=_format_number(row.get("median_requests_per_second"), 4),
                ratio=_format_ratio(row.get("median_uopz_overhead_ratio")),
                vulns=_format_number(row.get("median_unique_vulns_found_after_30min"), 0),
                first_vuln=first_vuln_text,
            )
        )
    return lines


def _build_vuln_table(run_rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Mode | First vuln time | First vuln request | Unique vulns |",
        "|---|---:|---:|---:|",
    ]
    if not run_rows:
        lines.append("| n/a | n/a | n/a | n/a |")
        return lines
    for row in run_rows:
        first_time = row.get("time_to_first_unique_vuln_seconds")
        first_req = row.get("requests_to_first_unique_vuln")
        lines.append(
            "| {mode} | {time} | {request} | {vulns} |".format(
                mode=row.get("mode", "unknown"),
                time="none" if first_time is None else f"{_format_number(first_time, 0)}s",
                request="none" if first_req is None else _format_number(first_req, 0),
                vulns=_format_number(row.get("unique_vulns_found_within_budget"), 0),
            )
        )
    return lines


def _interpret_shallow_deep(run_rows: list[dict[str, Any]]) -> str:
    raw = next((row for row in run_rows if row.get("mode") == "PHUZZ_RAW"), None)
    hook = next((row for row in run_rows if row.get("mode") == "HOOK_TRACE"), None)
    if raw and raw.get("time_to_first_unique_vuln_seconds") is not None:
        return (
            "PHUZZ_RAW finds at least one vuln in this bounded pilot, so any early overlap should be treated as "
            "shallow-bug evidence. Deep-bug claims require sustained callback growth or hook-only findings in a longer run."
        )
    if hook and hook.get("unique_vulns_found_within_budget", 0):
        return (
            "HOOK_TRACE found vuln evidence while PHUZZ_RAW did not in this artifact set; treat this as candidate deep-bug "
            "evidence until confirmed by a longer repeated run."
        )
    return "No shallow/deep conclusion is supported by this artifact set."


def _collect_timeline_series(root: Path, run_dirs: list[Path]) -> dict[str, list[dict[str, float]]]:
    series: dict[str, list[dict[str, float]]] = {}
    for run_dir in run_dirs:
        mode = _mode_for_run(run_dir)
        rows = _read_timeline(run_dir / "coverage_timeline.csv")
        if rows:
            series[mode] = rows
    return series


def _points(
    rows: list[dict[str, float]],
    metric: str,
    *,
    left: int,
    top: int,
    plot_width: int,
    plot_height: int,
    max_x: float,
    max_y: float,
) -> str:
    coordinates = []
    for row in rows:
        x_value = row.get("elapsed_end_seconds", 0.0)
        y_value = row.get(metric, 0.0)
        x = left + (x_value / max_x * plot_width if max_x else 0)
        y = top + plot_height - (y_value / max_y * plot_height if max_y else 0)
        coordinates.append(f"{x:.1f},{y:.1f}")
    return " ".join(coordinates)


def _panel_max(series: dict[str, list[dict[str, float]]], metric: str) -> float:
    values = [row.get(metric, 0.0) for rows in series.values() for row in rows]
    return max(values + [1.0])


def _primary_coverage_series(series: dict[str, list[dict[str, float]]]) -> dict[str, list[dict[str, float]]]:
    primary = {mode: rows for mode, rows in series.items() if mode in {"PHUZZ_TRACE", "HOOK_TRACE"}}
    return primary or series


def _axis_label(value: float) -> str:
    if value >= 60:
        return f"{value / 60:.0f}m"
    return f"{value:.0f}s"


def _coverage_summary(mode: str, rows: list[dict[str, float]], metric: str) -> str:
    label = MODE_LABELS.get(mode, mode)
    if not rows:
        return f"{label}: no timeline"
    first = rows[0].get(metric, 0.0)
    last = rows[-1].get(metric, 0.0)
    delta = last - first
    direction = "growth" if delta > 0 else "plateau"
    return f"{mode} {direction}: {first:.0f} -> {last:.0f} ({delta:+.0f})"


def _text(lines: list[str], x: int | float, y: int | float, text: str, *, size: int = 12, color: str = "#111111", weight: int | None = None) -> None:
    weight_attr = f' font-weight="{weight}"' if weight else ""
    lines.append(
        f'<text x="{x}" y="{y}" font-family="Arial, sans-serif" font-size="{size}" fill="{color}"{weight_attr}>'
        f"{html.escape(text)}</text>"
    )


def _draw_panel(
    lines: list[str],
    *,
    title: str,
    metric: str,
    series: dict[str, list[dict[str, float]]],
    top: int,
    left: int,
    plot_width: int,
    plot_height: int,
    max_x: float,
    max_y: float,
    dashed: bool = False,
) -> None:
    bottom = top + plot_height
    right = left + plot_width
    lines.append(f'<text x="{left}" y="{top - 12}" font-family="Arial, sans-serif" font-size="15" font-weight="700">{html.escape(title)}</text>')
    lines.append(f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#333" stroke-width="1"/>')
    lines.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{bottom}" stroke="#333" stroke-width="1"/>')
    lines.append(f'<text x="{left - 52}" y="{top + 4}" font-family="Arial, sans-serif" font-size="11">{max_y:.2f}</text>')
    lines.append(f'<text x="{left - 20}" y="{bottom + 4}" font-family="Arial, sans-serif" font-size="11">0</text>')
    for mode in sorted(series.keys(), key=_mode_sort_key):
        color = MODE_COLORS.get(mode, "#444444")
        points = _points(
            series[mode],
            metric,
            left=left,
            top=top,
            plot_width=plot_width,
            plot_height=plot_height,
            max_x=max_x,
            max_y=max_y,
        )
        dash_attr = ' stroke-dasharray="5 4"' if dashed else ""
        lines.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="3"{dash_attr}/>')


def _write_svg(path: Path, series: dict[str, list[dict[str, float]]]) -> None:
    width = 1180
    height = 700
    metric = "cumulative_unique_callbacks"
    coverage_series = _primary_coverage_series(series)
    all_rows = [row for rows in coverage_series.values() for row in rows]
    max_x = max([row.get("elapsed_end_seconds", 0.0) for row in all_rows] + [1.0])
    max_y = _panel_max(coverage_series, metric)
    left = 92
    top = 108
    plot_width = 760
    plot_height = 420
    bottom = top + plot_height
    right = left + plot_width

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
    ]
    _text(lines, left, 34, "Coverage over time", size=24, weight=700)
    _text(lines, left, 58, "Y-axis: cumulative unique WordPress callbacks covered. A flat line means the run stopped discovering new callbacks.", size=12, color="#555555")
    _text(lines, left, 82, "Primary comparison: PHUZZ original vs HookPHuzz", size=13, color="#333333", weight=700)

    lines.append(f'<rect x="{left}" y="{top}" width="{plot_width}" height="{plot_height}" fill="#fbfbfb" stroke="#d0d0d0"/>')
    for step in range(0, 5):
        y = top + plot_height - (plot_height * step / 4)
        value = max_y * step / 4
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" stroke="#e6e6e6" stroke-width="1"/>')
        _text(lines, left - 46, y + 4, f"{value:.0f}", size=11, color="#555555")
    for step in range(0, 5):
        x = left + plot_width * step / 4
        value = max_x * step / 4
        lines.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{bottom}" stroke="#eeeeee" stroke-width="1"/>')
        _text(lines, x - 10, bottom + 24, _axis_label(value), size=11, color="#555555")
    _text(lines, left + plot_width / 2 - 52, bottom + 50, "elapsed time", size=12, color="#333333")
    _text(lines, 20, top + plot_height / 2, "covered callbacks", size=12, color="#333333")

    for mode in sorted(coverage_series.keys(), key=_mode_sort_key):
        color = MODE_COLORS.get(mode, "#444444")
        rows = coverage_series[mode]
        points = _points(
            rows,
            metric,
            left=left,
            top=top,
            plot_width=plot_width,
            plot_height=plot_height,
            max_x=max_x,
            max_y=max_y,
        )
        width_attr = "4" if mode in {"PHUZZ_TRACE", "HOOK_TRACE"} else "2"
        opacity_attr = "1" if mode in {"PHUZZ_TRACE", "HOOK_TRACE"} else "0.45"
        dash_attr = ' stroke-dasharray="7 5"' if mode == "PHUZZ_TRACE" else ""
        lines.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="{width_attr}" '
            f'stroke-linejoin="round" stroke-linecap="round" opacity="{opacity_attr}"{dash_attr}/>'
        )
        for row in rows:
            x_value = row.get("elapsed_end_seconds", 0.0)
            y_value = row.get(metric, 0.0)
            x = left + (x_value / max_x * plot_width if max_x else 0)
            y = top + plot_height - (y_value / max_y * plot_height if max_y else 0)
            lines.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.8" fill="#ffffff" stroke="{color}" stroke-width="2"/>')
        if rows:
            last = rows[-1]
            x_value = last.get("elapsed_end_seconds", 0.0)
            y_value = last.get(metric, 0.0)
            x = left + (x_value / max_x * plot_width if max_x else 0)
            y = top + plot_height - (y_value / max_y * plot_height if max_y else 0)
            _text(lines, min(x + 8, right - 110), y - 8, f"{MODE_LABELS.get(mode, mode)}: {y_value:.0f}", size=12, color=color, weight=700)

    panel_left = 890
    lines.append(f'<rect x="{panel_left}" y="{top}" width="250" height="240" fill="#f7f7f7" stroke="#d0d0d0"/>')
    _text(lines, panel_left + 18, top + 30, "Plateau check", size=17, weight=700)
    summary_y = top + 66
    for mode in sorted(coverage_series.keys(), key=_mode_sort_key):
        color = MODE_COLORS.get(mode, "#444444")
        lines.append(f'<rect x="{panel_left + 18}" y="{summary_y - 10}" width="22" height="4" fill="{color}"/>')
        _text(lines, panel_left + 50, summary_y, _coverage_summary(mode, coverage_series[mode], metric), size=12, color="#222222")
        summary_y += 28

    lines.append(f'<rect x="{panel_left}" y="{top + 270}" width="250" height="150" fill="#ffffff" stroke="#d0d0d0"/>')
    _text(lines, panel_left + 18, top + 300, "How to read", size=16, weight=700)
    _text(lines, panel_left + 18, top + 328, "PHUZZ plateau = early ceiling.", size=12, color="#444444")
    _text(lines, panel_left + 18, top + 352, "HookPHuzz growth = new callbacks", size=12, color="#444444")
    _text(lines, panel_left + 18, top + 376, "continue appearing later.", size=12, color="#444444")
    _text(lines, panel_left + 18, top + 404, "Numbers come from coverage_timeline.csv.", size=12, color="#444444")

    lines.append("</svg>")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_markdown(path: Path, root: Path, aggregate: dict[str, Any], run_dirs: list[Path], missing: list[str], svg_path: Path) -> None:
    mode_rows = _mode_rows(aggregate)
    run_rows = _run_rows(aggregate)
    lines = [
        f"# HookPHuzz bounded pilot report: {aggregate.get('plugin', root.name)}",
        "",
        "This report is bounded 7-hour pilot evidence, not 4-6h long-run proof.",
        "",
        f"- Artifact root: `{root}`",
        f"- Coverage chart: `{svg_path.name}`",
        "- HOOK_FAST fast phase runs with UOPZ off, so callback coverage in its fast summary is expected to stay at 0.",
        "",
        "## EPS and overhead",
        "",
        *_build_eps_table(mode_rows),
        "",
        "## Vuln discovery timeline",
        "",
        *_build_vuln_table(run_rows),
        "",
        "## HOOK_FAST seed export",
        "",
        f"- {_seed_export_summary(run_dirs)}",
        "",
        "## Shallow/deep interpretation",
        "",
        _interpret_shallow_deep(run_rows),
        "",
    ]
    if missing:
        lines.extend(
            [
                "## Missing artifacts",
                "",
                *[f"- `{item}`" for item in missing],
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def generate_report(benchmark_root: str | Path) -> ReportArtifacts:
    root = Path(benchmark_root)
    aggregate_path = root / "benchmark_results.json"
    aggregate = _load_json(aggregate_path)
    run_dirs = _discover_run_dirs(root)
    missing = _missing_artifacts(root, run_dirs)
    series = _collect_timeline_series(root, run_dirs)

    markdown_path = root / "benchmark_report.md"
    svg_path = root / "coverage_timeline.svg"
    _write_svg(svg_path, series)
    _write_markdown(markdown_path, root, aggregate, run_dirs, missing, svg_path)
    return ReportArtifacts(markdown_path=markdown_path, svg_path=svg_path)


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Markdown and SVG report for PHUZZ benchmark artifacts.")
    parser.add_argument("benchmark_root", help="Path to one benchmark artifact root.")
    return parser


def main() -> int:
    args = _build_cli().parse_args()
    artifacts = generate_report(args.benchmark_root)
    print(f"Report written: {artifacts.markdown_path}")
    print(f"Chart written: {artifacts.svg_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
