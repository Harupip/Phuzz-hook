from __future__ import annotations

import argparse

from helper_request_reader_analyzer import write_registry


def main() -> int:
    parser = argparse.ArgumentParser(description="Build source-proven helper HTTP-reader registry.")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--display-root")
    args = parser.parse_args()
    registry = write_registry(args.source_root, args.output, display_root=args.display_root)
    print(f"Helper reader registry: readers={len(registry['readers'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
