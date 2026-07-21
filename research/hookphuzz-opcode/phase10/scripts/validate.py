#!/usr/bin/env python3
"""Fail-closed Phase 10 report writer.

The live harness supplies evidence JSON in results/input. This keeps the merge
contract runnable independently of Docker and never turns missing evidence into
a pass.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from phase10 import atomic_json, gate_summary, merge_evidence, normalize_helper, normalize_opcode, phuzz_config


MANDATORY = (
    "phase9_extension_integrated", "controlled_plugin", "two_real_plugin_targets",
    "direct_superglobals", "request_resolution", "helper_discovery", "nested_preservation",
    "parameter_association", "merge_deduplication", "phuzz_config_generation",
    "semantic_replays", "noise_isolation",
)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    input_dir = args.results / "input"
    manifest = read_json(input_dir / "manifest.json", {})
    evidence = []
    for item in manifest.get("opcode", []):
        artifact = read_json(input_dir / item["file"], {})
        try:
            evidence.extend(normalize_opcode(item["plugin"], item["entrypoint"], artifact,
                                             request_placement=item.get("request_placement")))
        except ValueError:
            pass
    for item in manifest.get("helper", []):
        row = normalize_helper(item["plugin"], read_json(input_dir / item["file"], {}),
                               request_placement=item.get("request_placement"))
        if row:
            evidence.append(row)
    evidence.extend(item for item in manifest.get("static", []) if isinstance(item, dict))
    evidence.extend(item for item in manifest.get("seeds", []) if isinstance(item, dict))
    try:
        merged = merge_evidence(evidence)
    except ValueError:
        merged = []

    generated = []
    for row in merged:
        target = manifest.get("targets", {}).get(row["plugin"], "")
        if target:
            generated.append({"logical_key": list(row.values())[:0], "config": phuzz_config(
                row, target=target, method=manifest.get("methods", {}).get(row["plugin"], "POST"),
                fixed=manifest.get("fixed", {}).get(row["entrypoint"], {}))})
    replays = read_json(input_dir / "replays.json", [])
    noise = read_json(input_dir / "noise.json", {})
    required_replays = [row for row in replays if row.get("mandatory", True)]
    semantic = bool(required_replays) and all(
        row.get("request_id") and row.get("target_plugin") and row.get("entrypoint") and row.get("root_callback")
        and row.get("parameter_path") and row.get("runtime_source") and row.get("http_placement")
        and row.get("marker_observed") and row.get("callback_reached") and row.get("semantic_equivalent")
        for row in required_replays)
    gates = {name: bool(manifest.get("gates", {}).get(name, False)) for name in MANDATORY}
    gates["parameter_association"] &= all(row.get("plugin") and row.get("entrypoint") and row.get("root_callback") for row in merged)
    gates["merge_deduplication"] &= len({(row["plugin"], row["entrypoint"], row["root_callback"], row["source"], tuple(row["parameter_path"]), row["placement"]) for row in merged}) == len(merged)
    gates["phuzz_config_generation"] &= bool(generated)
    gates["semantic_replays"] &= semantic
    gates["noise_isolation"] &= bool(noise.get("passed"))
    atomic_json(args.results / "discovery-summary.json", {"schema_version": 1, "run_id": args.run_id, "raw_evidence": evidence})
    atomic_json(args.results / "merge-summary.json", {"schema_version": 1, "run_id": args.run_id, "parameters": merged})
    atomic_json(args.results / "generated-config-summary.json", {"schema_version": 1, "run_id": args.run_id, "configs": generated})
    atomic_json(args.results / "replay-validation-summary.json", {"schema_version": 1, "run_id": args.run_id, "replays": replays})
    summary = gate_summary(gates, run_id=args.run_id, details={"target_plugins": manifest.get("target_plugins", []), "noise": noise})
    atomic_json(args.results / "phase10-validation-summary.json", summary)
    (args.results / "final-verdict.txt").write_text("PHASE_10_PASS\n" if summary["overall_pass"] else "PHASE_10_FAIL\nfailed_gates:\n" + "".join(f"- {gate}\n" for gate in summary["failed_gates"]), encoding="utf-8")
    print((args.results / "final-verdict.txt").read_text(encoding="utf-8"), end="")
    return 0 if summary["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
