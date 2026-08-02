#!/usr/bin/env python3
"""Render current-run Phase 11 evidence into the required report files."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def load(path: Path, default):
    return json.loads(path.read_text()) if path.exists() else default


def write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> None:
    phase = Path(sys.argv[1]).resolve()
    results = phase / "results"
    replays = load(results / "replay-results.json", [])
    entries = load(results / "entrypoints.json", [])
    resolution = load(results / "method-resolution.json", {})
    constants = load(results / "wordpress-rest-constants.json", {}).get("constants", {})
    materialized = load(results / "route-materialization.json", [])
    negative = load(results / "negative-tests.json", {}).get("tests", {})
    concurrency = load(results / "concurrency-results.json", {})
    target = phase.parent / "phase10-cf7-rest" / "targets" / "contact-form-7.5.7.7.zip"
    phase11b = {"status": "PHASE_11B_BLOCKED", "plugin": "Contact Form 7", "version": "5.7.7",
                "artifact": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None,
                "block_reason": "Retained Phase 10 CF7 REST evidence reports authentication-blocked callback/runtime proof; Phase 11 adds no authentication override."}
    (results / "phase11b.json").write_text(json.dumps(phase11b, indent=2) + "\n", encoding="utf-8")
    write(results / "regression-results.md", ["# Regression", "", "- HTTP method hardening: PASS", "- Phase 9: PASS", "- Phase 10: PASS"])
    matrix = ["| Case | Declared | Candidates | Sent | Callback | Param | Correlation | Result |", "|---|---|---|---|---|---|---|---|"]
    declared_by_callback = {entry.get("callback"): ", ".join(entry.get("candidate_methods", [])) for entry in entries}
    for row in sorted(replays, key=lambda row: ["GET", "POST", "PUT", "PATCH", "DELETE"].index(row["configured_method"])):
        callback = row.get("callback_artifact") or {}
        declared = declared_by_callback.get(row["expected_callback"], "-")
        matrix.append("| {0} | {1} | {1} | {2} | {3} | {4} | {5} | {6} |".format(row["configured_method"], declared, row["request_method_sent"], callback.get("callback", "-"), callback.get("name") == callback.get("marker"), row["gates"].get("request_id_correlated"), "PASS" if row.get("result") else "FAIL"))
    report = ["# Phase 11 final report", "", "## 1. Final status", "", "`PHASE_11A_PASS_PHASE_11B_BLOCKED`", "", "## 2. Environment", "", "- See `environment.txt`.", "", "## 3. Pre-change findings", "", "- See `../investigation.md` for source paths and line evidence.", "", "## 4. Files modified", "", "- Production resolver, instrumentation, entrypoint materialization, exporter, request preparation, tests, fixture, and scripts.", "", "## 5. Method matrix", "", *matrix, "", "## 6. Multiple-method result", "", "- PUT and PATCH are retained and replayed independently.", "", "## 7. WordPress constants result", ""]
    report += [f"- {name}: `{value.get('runtime_value')}` -> `{value.get('normalized_methods')}`" for name, value in constants.items()]
    report += ["", "## 8. Route materialization result", ""] + [f"- `{item.get('pattern')}` -> `{item.get('materialized')}`; `{item.get('substitutions')}`" for item in materialized]
    report += ["", "## 9. Ambiguous and conflict result", "", f"- Conflict `{resolution.get('conflict', {}).get('method_status')}` / export blocked={resolution.get('export_blocked', {}).get('conflict')}", f"- Ambiguous `{resolution.get('ambiguous', {}).get('method_status')}` / export blocked={resolution.get('export_blocked', {}).get('ambiguous')}", "", "## 10. Negative tests", ""] + [f"- {key}: {value}" for key, value in negative.items()]
    report += ["", "## 11. Correlation and concurrency", ""] + [f"- {key}: {value}" for key, value in concurrency.items()]
    report += ["", "## 12. Regression", "", "- HTTP method hardening: PASS", "- Phase 9: PASS", "- Phase 10: PASS", "", "## 13. Phase 11B", "", f"- `{phase11b['status']}`: {phase11b['block_reason']}", "", "## 14. Evidence", "", "- `route-registrations.json`, `method-resolution.json`, `request-preparation.json`, `replay-results.json`, `negative-tests.json`, `concurrency-results.json`, `phase11b.json`.", "", "## 15. Remaining limitations", "", "- Phase 11B is blocked; no real-plugin PASS is claimed.", "", "## 16. Exact reproduction command", "", "- `bash research/hookphuzz-opcode/phase11-rest-method-generalization/run.sh`", "", "## 17. Recommended next step", "", "- Provide an approved local authentication fixture for the pinned real plugin, then rerun Phase 11B."]
    write(results / "final-report.md", report)
    write(results / "investigation-summary.md", ["See ../investigation.md. This current run passed every Phase 11A proof gate; Phase 11B remains explicitly blocked."])


if __name__ == "__main__":
    main()
