from __future__ import annotations

import argparse

from helper_request_reader_analyzer import write_analysis_outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Build source-proven helper HTTP-reader registry.")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--display-root")
    parser.add_argument("--summary-output")
    parser.add_argument("--rejections-output")
    args = parser.parse_args()
    registry = write_analysis_outputs(
        args.source_root,
        args.output,
        display_root=args.display_root,
        summary_output=args.summary_output,
        rejections_output=args.rejections_output,
    )
    print(f"Helper reader registry: readers={len(registry['readers'])} rejections={len(registry['rejections'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

