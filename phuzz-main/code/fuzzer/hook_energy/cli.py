from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from hook_energy.calculator import HookEnergyCalculator
    from hook_energy.collector import HookCollector
    from hook_energy.report_builder import build_run_pair_comparison, build_single_run_report
    from hook_energy.report_loader import load_run_artifacts
    from hook_energy.report_models import (
        CallbackRecord,
        ComparisonSummary,
        DecisionRecord,
        HookVisualizationReport,
        RequestRecord,
        RunMetadata,
        RunSummary,
    )
    from hook_energy.reporter import HookEnergyReporter
    from hook_energy.report_render import write_html_report, write_json_report, write_markdown_summary
    from hook_energy.state import HookEnergyDemoState
else:
    from .calculator import HookEnergyCalculator
    from .collector import HookCollector
    from .report_builder import build_run_pair_comparison, build_single_run_report
    from .report_loader import load_run_artifacts
    from .report_models import (
        CallbackRecord,
        ComparisonSummary,
        DecisionRecord,
        HookVisualizationReport,
        RequestRecord,
        RunMetadata,
        RunSummary,
    )
    from .reporter import HookEnergyReporter
    from .report_render import write_html_report, write_json_report, write_markdown_summary
    from .state import HookEnergyDemoState


def build_argument_parser() -> argparse.ArgumentParser:
    repo_root = Path(__file__).resolve().parents[3]
    output_dir = repo_root / "output"

    parser = argparse.ArgumentParser(description="Hook energy tooling for request artifacts and reports.")
    subparsers = parser.add_subparsers(dest="command")

    watch_parser = subparsers.add_parser("watch")
    watch_parser.add_argument("--requests-dir", default=str(output_dir / "requests"))
    watch_parser.add_argument("--state-file", default=str(output_dir / "hook_energy_state.json"))
    watch_parser.add_argument("--summary-file", default=str(output_dir / "hook_energy_summary.json"))
    watch_parser.add_argument("--limit", type=int, default=0)
    watch_parser.add_argument("--watch", action="store_true")
    watch_parser.add_argument("--interval", type=float, default=1.0)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--run-label", required=True)
    report_parser.add_argument("--mode", choices=["baseline", "hook-aware"], required=True)
    report_parser.add_argument("--decisions", required=True)
    report_parser.add_argument("--exceptions", required=True)
    report_parser.add_argument("--vulnerabilities", required=True)
    report_parser.add_argument("--requests-dir", required=True)
    report_parser.add_argument("--coverage-summary", required=True)
    report_parser.add_argument("--output-dir", required=True)
    report_parser.add_argument("--baseline-report-json")

    return parser


def process_pending_requests(
    collector: HookCollector,
    calculator: HookEnergyCalculator,
    reporter: HookEnergyReporter,
    requests_dir: str,
    limit: int = 0,
) -> list:
    reports = []
    pending_files = collector.list_pending_request_files(requests_dir)
    if limit > 0:
        pending_files = pending_files[:limit]

    for filepath in pending_files:
        payload = collector.read_request_file(filepath)
        if payload is None:
            continue

        observation = collector.collect_request(payload, request_file=filepath)
        report = calculator.calculate_request_energy(observation, collector)
        print(reporter.format_request_summary(report))
        print("-" * 60)
        collector.finalize_request(report)
        reports.append(report)

    return reports


def requests_dir_has_artifacts(requests_dir: str) -> bool:
    base = Path(requests_dir)
    return base.exists() and any(base.glob("*.json"))


def _report_from_dict(payload: dict) -> HookVisualizationReport:
    comparison_payload = payload.get("comparison")
    comparison = ComparisonSummary(**comparison_payload) if comparison_payload else None
    return HookVisualizationReport(
        metadata=RunMetadata(**payload["metadata"]),
        summary=RunSummary(**payload["summary"]),
        decision_records=[DecisionRecord(**item) for item in payload.get("decision_records", [])],
        callback_records=[CallbackRecord(**item) for item in payload.get("callback_records", [])],
        request_records=[RequestRecord(**item) for item in payload.get("request_records", [])],
        comparison=comparison,
        warnings=payload.get("warnings", []),
    )


def main() -> int:
    parser = build_argument_parser()
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        argv = ["watch", *argv]
    args = parser.parse_args(argv)

    if args.command == "report":
        loaded = load_run_artifacts(
            run_label=args.run_label,
            mode=args.mode,
            decisions_path=Path(args.decisions),
            exceptions_path=Path(args.exceptions),
            vulnerabilities_path=Path(args.vulnerabilities),
            requests_dir=Path(args.requests_dir),
            coverage_summary_path=Path(args.coverage_summary),
        )
        report = build_single_run_report(loaded)

        if args.baseline_report_json:
            baseline_payload = json.loads(Path(args.baseline_report_json).read_text(encoding="utf-8"))
            baseline_report = _report_from_dict(baseline_payload)
            report.comparison = build_run_pair_comparison(baseline_report, report)

        output_dir = Path(args.output_dir)
        write_json_report(report, output_dir / "report.json")
        write_markdown_summary(report, output_dir / "report-summary.md")
        write_html_report(report, output_dir / "report.html")
        return 0

    has_request_artifacts = requests_dir_has_artifacts(args.requests_dir)
    state = HookEnergyDemoState.load(args.state_file) if has_request_artifacts else HookEnergyDemoState()
    collector = HookCollector(state=state)
    calculator = HookEnergyCalculator()
    reporter = HookEnergyReporter()
    reports: list = []
    last_dashboard_signature = None

    def _flush_outputs() -> None:
        collector.state.save(args.state_file)
        reporter.write_summary(args.summary_file, reports, collector.state)

    def _dashboard_signature() -> tuple:
        callback_items = tuple(
            sorted(
                (
                    callback_id,
                    item.hook_name,
                    item.callback_identity,
                    item.priority,
                    item.status,
                    item.total_execution_count,
                    item.total_request_count,
                )
                for callback_id, item in collector.state.callbacks.items()
            )
        )
        return (
            len(reports),
            len(collector.state.processed_request_ids),
            callback_items,
        )

    def _render_watch_dashboard(force: bool = False) -> None:
        nonlocal last_dashboard_signature

        signature = _dashboard_signature()
        if not force and signature == last_dashboard_signature:
            return

        last_dashboard_signature = signature
        rankings = reporter.build_rankings(reports, collector.state)

        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")

        print(f"Watching {args.requests_dir} for new request artifacts...")
        print(
            "Live summary: "
            f"requests_processed={len(collector.state.processed_request_ids)} "
            f"| callbacks_tracked={len(collector.state.callbacks)} "
            f"| last_refresh={time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print()
        print(reporter.format_rankings(rankings))

    reports.extend(process_pending_requests(collector, calculator, reporter, args.requests_dir, args.limit))
    if reports:
        if not args.watch:
            print(reporter.format_rankings(reporter.build_rankings(reports, collector.state)))
        _flush_outputs()
    elif not has_request_artifacts:
        print("No request artifacts found. Starting a fresh session with empty state.")
        _flush_outputs()
    elif not args.watch:
        print("No pending request artifacts found. State remains unchanged.")
        _flush_outputs()

    if not args.watch:
        return 0

    _render_watch_dashboard(force=True)
    try:
        while True:
            new_reports = process_pending_requests(collector, calculator, reporter, args.requests_dir, args.limit)
            if new_reports:
                reports.extend(new_reports)
                _flush_outputs()
            _render_watch_dashboard()
            time.sleep(max(0.1, float(args.interval)))
    except KeyboardInterrupt:
        _flush_outputs()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
