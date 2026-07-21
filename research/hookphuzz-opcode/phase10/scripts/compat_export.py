#!/usr/bin/env python3
"""Bridge merged Phase 10 parameters into the existing HookPhuzz exporter."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any


def load_exporter(workspace: Path):
    source = workspace / "phuzz-main/code/fuzzer/hook_energy/seed_generation/config_exporter.py"
    spec = importlib.util.spec_from_file_location("phase10_hookphuzz_exporter", source)
    if not spec or not spec.loader:
        raise RuntimeError("existing_hookphuzz_exporter_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seed_for(parameter: dict[str, Any]) -> dict[str, Any]:
    entrypoint = parameter["entrypoint"]
    placement = parameter["placement"]
    path = parameter["parameter_name"]
    body: dict[str, str] = {}
    query: dict[str, str] = {}
    cookies: dict[str, str] = {}
    if entrypoint.startswith("wp_ajax_"):
        body["action"] = entrypoint.removeprefix("wp_ajax_").removeprefix("nopriv_")
        route = "/wp-admin/admin-ajax.php"
        auth_mode = "unauth-capable" if "nopriv" in entrypoint else "authenticated"
    elif entrypoint.startswith("rest_route:"):
        route = "/wp-json/" + entrypoint.removeprefix("rest_route:")
        auth_mode = "authenticated"
    else:
        raise ValueError("unsupported_phase10_entrypoint")
    {"body": body, "query": query, "cookie": cookies}[placement][path] = "PHASE10_MARKER"
    return {"hook_name": entrypoint, "callback_id": parameter["root_callback"], "entrypoint_type": "rest_route" if entrypoint.startswith("rest_route:") else "wp_ajax",
            "seed": {"auth_mode": auth_mode, "methods": ["GET"] if entrypoint.startswith("rest_route:") else ["POST"],
                     "path": route, "body": body, "query_params": query, "cookies": cookies,
                     "fixed_params": list(body) if "action" in body else [], "fuzzable_params": [path]}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--merged", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    payload = json.loads(args.merged.read_text(encoding="utf-8"))
    parameters = payload.get("parameters", [])
    exporter = load_exporter(args.workspace)
    report: dict[str, Any] = {"suggested_seeds": [seed_for(row) for row in parameters]}
    # The existing writer owns PHUZZ wire shape. Phase 10 only appends metadata.
    exporter.export_seed_configs(report, output_config_dir=args.output_dir, summary_path=args.summary)
    for path in args.output_dir.glob("*.json"):
        config = json.loads(path.read_text(encoding="utf-8"))
        config.setdefault("metadata", {})["phase10_compatibility_export"] = True
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
