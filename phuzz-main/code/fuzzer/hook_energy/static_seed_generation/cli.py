from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import StaticSeedScanner
from .validation import validate_static_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Static WordPress seed generation for HookPhuzz.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--plugin-path", required=True)
    scan.add_argument("--plugin-slug", required=True)
    scan.add_argument("--output-dir", required=True)
    scan.add_argument("--base-url", default="http://web")
    scan.add_argument("--min-confidence", choices=["high", "medium", "low"], default="low")
    scan.add_argument("--write-configs", action="store_true")
    scan.add_argument("--include-rest", action="store_true")
    scan.add_argument("--include-unresolved", action="store_true")
    scan.add_argument("--format", choices=["json"], default="json")
    validate = sub.add_parser("validate")
    validate.add_argument("--static-report", required=True)
    validate.add_argument("--hook-report", required=True)
    validate.add_argument("--output", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        report = StaticSeedScanner(base_url=args.base_url).scan(
            plugin_path=Path(args.plugin_path),
            plugin_slug=args.plugin_slug,
            output_dir=Path(args.output_dir),
            write_configs=args.write_configs,
            include_rest=args.include_rest,
            include_unresolved=args.include_unresolved,
            min_confidence=args.min_confidence,
        )
        print(json.dumps(report, ensure_ascii=False))
        return 0
    static_report = json.loads(Path(args.static_report).read_text(encoding="utf-8"))
    hook_report = json.loads(Path(args.hook_report).read_text(encoding="utf-8"))
    result = validate_static_report(static_report, hook_report)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
