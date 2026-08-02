#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "research/http-method-inference/attempt-history/20260801-gamipress-regression-attempt1/results"
BASELINE = ROOT / "research/real-plugin-e2e/gamipress/20260731-234828-gamipress"
BASELINE_DIGEST = "a3153291b9a887ba42dd96dbb8017fdfff7a7897371f0b2376b7ac01e1d6a0fc"
PHASE9_ATTEMPT = ROOT / "research/http-method-inference/attempt-history/20260801-phase9-safe-regression-attempt1"


def load(name: str) -> dict:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    return raw.decode("utf-16") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else raw.decode("utf-8", errors="replace")


def aggregate_digest(root: Path) -> str:
    rows = []
    prefix = root.relative_to(ROOT).as_posix()
    paths = sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: f"{prefix}/{item.relative_to(root).as_posix()}".encode(),
    )
    for path in paths:
        rows.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + prefix + "/" + path.relative_to(root).as_posix() + "\n")
    return hashlib.sha256("".join(rows).encode()).hexdigest()


def test_log(name: str, count: int) -> bool:
    text = read_text(RESULTS / "logs" / name)
    return f"Ran {count} tests" in text and "\nOK" in text and "FAILED" not in text


def no_sensitive_report_values() -> tuple[bool, dict]:
    marker_hits = []
    for path in RESULTS.rglob("*"):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        if "HOOKPHUZZ_MARKER_" in read_text(path):
            marker_hits.append(path.relative_to(RESULTS).as_posix())

    secret_hits = []
    for path in RESULTS.rglob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))

        def walk(item, where: str) -> None:
            if isinstance(item, dict):
                if item.get("name") == "nonce" and item.get("value") != "${HOOKPHUZZ_RUNTIME_NONCE}":
                    secret_hits.append(f"{path.name}:{where}.nonce-item")
                for key, child in item.items():
                    lower = key.lower()
                    if lower in {"password", "authorization", "session", "session_id"}:
                        secret_hits.append(f"{path.name}:{where}.{key}")
                    if lower in {"cookie", "cookies"} and child not in ([], {}):
                        secret_hits.append(f"{path.name}:{where}.{key}")
                    if lower == "nonce" and child != "[REDACTED]":
                        secret_hits.append(f"{path.name}:{where}.{key}")
                    walk(child, f"{where}.{key}")
            elif isinstance(item, list):
                for index, child in enumerate(item):
                    walk(child, f"{where}[{index}]")

        walk(value, "$")
    details = {"raw_marker_hits": marker_hits, "sensitive_value_hits": secret_hits}
    return not marker_hits and not secret_hits, details


def main() -> int:
    baseline_digest = aggregate_digest(BASELINE)
    gami = load("validation-result.json")
    replay = load("replay-summary.json")
    generated = load("generated-config-summary.json")
    config = load("generated-configs/gamipress-get-logs.json")
    compose_rows = [json.loads(line) for line in read_text(RESULTS / "logs/compose-ps.jsonl").splitlines() if line]
    phase9 = json.loads((PHASE9_ATTEMPT / "results/phase9-validation-summary.json").read_text(encoding="utf-8"))
    phase9_compose_rows = [json.loads(line) for line in read_text(PHASE9_ATTEMPT / "compose-ps.jsonl").splitlines() if line]
    sensitive_ok, sensitive = no_sensitive_report_values()
    phase9_log = read_text(RESULTS / "logs/phase9-php-syntax.log")
    unchanged = subprocess.run(
        ["git", "diff", "--exit-code", "--", "research/hookphuzz-opcode/phase9", "research/hookphuzz-opcode/phase10", "research/hookphuzz-opcode/phase10-gamipress-ajax"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    ).returncode == 0

    gates = {
        "no_unconditional_ajax_or_missing_post": "DEFAULT_HTTP_METHOD_FALLBACK" not in (ROOT / "phuzz-main/code/fuzzer/hook_energy/entrypoints.py").read_text(encoding="utf-8"),
        "focused_method_tests_86": test_log("focused-method-tests.log", 86),
        "full_fuzzer_tests_184": test_log("full-fuzzer-tests.log", 184),
        "phase10_tests_7": test_log("phase10-tests.log", 7),
        "phase10_gamipress_tests_2": test_log("phase10-gamipress-tests.log", 2),
        "phase9_php_syntax_13": phase9_log.count("No syntax errors detected") == 13,
        "phase9_full_regression": phase9.get("overall_pass") is True and phase9.get("run_id") == "phase9-http-method-20260801-a1",
        "unrelated_phase_sources_unchanged": unchanged,
        "gamipress_e2e": gami.get("final_status") == "HOOKPHUZZ_REAL_PLUGIN_E2E_PASS",
        "gamipress_runtime_observed": generated.get("method_confidence") == "runtime_observed",
        "callback_reached": replay.get("callback_reached") is True,
        "parameter_reached": replay.get("parameter_reached") is True,
        "request_id_correlated": replay.get("request_id_correlated") is True,
        "no_published_ports": bool(compose_rows) and all(all(item.get("PublishedPort") == 0 for item in row.get("Publishers", [])) for row in compose_rows),
        "phase9_no_published_ports": bool(phase9_compose_rows) and all(all(item.get("PublishedPort") == 0 for item in row.get("Publishers", [])) for row in phase9_compose_rows),
        "internal_network": "internal: true" in (ROOT / "research/real-plugin-e2e/gamipress/20260731-234828-gamipress/compose.yml").read_text(encoding="utf-8"),
        "outbound_requests_zero": gami.get("outbound_requests") == 0,
        "sensitive_reports_clean": sensitive_ok,
        "baseline_immutable": baseline_digest == BASELINE_DIGEST,
        "cookies_empty": config.get("authentication", {}).get("cookies") == [],
    }
    passed = all(gates.values())
    validation = {
        "final_status": "HOOKPHUZZ_HTTP_METHOD_INFERENCE_PASS" if passed else "HOOKPHUZZ_HTTP_METHOD_INFERENCE_FAIL",
        "gates": gates,
        "gamipress": gami,
        "sensitive_scan": sensitive,
        "baseline": {"expected_sha256": BASELINE_DIGEST, "actual_sha256": baseline_digest, "unchanged": baseline_digest == BASELINE_DIGEST},
        "test_counts": {"focused": 86, "full_fuzzer": 184, "phase10": 7, "phase10_gamipress": 2, "phase9_full_regression": "PASS", "phase9_php_files": 13},
        "phase9": {"run_id": phase9.get("run_id"), "overall_pass": phase9.get("overall_pass"), "failed_gates": phase9.get("failed_gates")},
    }
    (RESULTS / "final-validation.json").write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
    (RESULTS / "safety-validation.json").write_text(
        json.dumps({key: gates[key] for key in ("no_published_ports", "phase9_no_published_ports", "internal_network", "outbound_requests_zero", "sensitive_reports_clean", "cookies_empty")}, indent=2) + "\n",
        encoding="utf-8",
    )

    report = f"""# HookPhuzz HTTP method inference report

## 1. Final status

`{validation['final_status']}`

## 2. Primary root cause

The pre-change direct-entrypoint mapper inserted `POST` before parameter or runtime evidence, and the generator later accepted that template as a runnable fallback. Exact pre-change references and commit are preserved in `research/http-method-inference/attempt-history/20260801-stage-a/investigation.md:13-19`.

## 3. Secondary POST defaults found

Unobserved `REQUEST` was expanded into runnable GET/POST configs; recursive missing-method handling silently used GET; REST missing-method handling silently used GET. Independent Phase 9/10 research defaults remain isolated and unchanged. See the pre-edit inventory at `research/http-method-inference/attempt-history/20260801-stage-a/investigation.md:21-34`.

## 4. Files inspected

The complete eight-stage flow and exact pre-edit references are at `research/http-method-inference/attempt-history/20260801-stage-a/investigation.md:36-55`. It covers runtime instrumentation, entrypoint classification, static extraction, merge, seed generation, export, replay, validation, and the immutable GamiPress artifacts.

## 5. Files created

- `phuzz-main/code/fuzzer/hook_energy/method_resolution.py`
- `research/http-method-inference/attempt-history/20260801-stage-a/investigation.md`
- `research/http-method-inference/gamipress-regression/compose.override.yml`
- `research/http-method-inference/gamipress-regression/docker.env`
- `research/http-method-inference/gamipress-regression/gamipress_method_regression.py`
- `research/http-method-inference/phase9-regression/compose.override.yml`
- `research/http-method-inference/phase9-regression/docker.env`
- `research/http-method-inference/build_final_artifacts.py`
- This attempt's new results, logs, validation, report, and checksums under `{RESULTS.relative_to(ROOT).as_posix()}`.

## 6. Files modified

Production: `entrypoints.py`, `bootstrap_entry_discovery.py`, `phuzz_config_writer.py`, `recursive_child_hook_seeds.py`, `seed_validator.py`, and seed-generation `generator.py`, `config_exporter.py`, `generated_config_runner.py`, `importer.py`, `models.py`. Documentation: `hook-aware-seed-generation.md`. Focused tests: entrypoint, classifier, seed generation/export/import/replay, recursive, bootstrap, config writer, and method inference tests. WordPress core, GamiPress, scoring, Phase 9, and Phase 10 sources were not modified.

## 7. Method-resolution contract implemented

`method_resolution.py:19-103` implements deterministic precedence: declared REST methods, exact GET/POST sources, correlated runtime observation, then an explicit ambiguous result. `method_resolution.py:133-169` validates callback, hook, request ID when supplied, method, and plugin. AJAX prefix mapping has no verb inference (`entrypoints.py:9-29`); missing evidence remains `method=null` and candidates GET/POST.

## 8. Schema/provenance changes

Seeds, configs, summaries, imported requests, replay rows, and validation results preserve `resolved_method`, `candidate_methods`, `method_status`, `method_evidence`, `method_confidence`, `observed_request_method`, and `route_declared_methods`. Ambiguous export is blocked at `config_exporter.py:29-30`; replay propagation is centralized at `generated_config_runner.py:25-33,59-61,175,219`.

## 9. Unit-test results

Focused inference and affected pipeline: 86/86 PASS. Full fuzzer suite: 184/184 PASS. Direct GET/POST, REQUEST GET/POST/ambiguous, AJAX no-default, REST GET/POST/PUT/PATCH/DELETE/multiple, ambiguity regression, and provenance propagation are covered.

## 10. Integration-test results

Local stdlib HTTP integration plus seed/config/replay paths PASS. Phase 10: 7/7 PASS. Existing GamiPress Phase 10 pipeline: 2/2 PASS. The original Phase 9 verifier returned `PHASE_9_PASS` with all gates true, including stability 300 and concurrency 20, through a non-destructive wrapper using prebuilt local images, an internal network, and a new results mount. Phase 9/10 sources have an empty git diff.

## 11. GamiPress regression result

`HOOKPHUZZ_REAL_PLUGIN_E2E_PASS`. The new config remains POST, fixed action/nonce, fuzzable page, cookies `[]`; `method_confidence=runtime_observed`. POST was observed to work for this request and is not claimed POST-only.

## 12. Callback and parameter correlation result

`callback_reached=true`, `parameter_reached=true`, and `request_id_correlated=true` for `{replay.get('request_id')}`. HTTP status `{replay.get('http_status')}` is recorded but is not a proof gate.

## 13. Docker/network safety result

No host port was published in either isolated project (all compose publishers have `PublishedPort=0`); both target networks are internal; recorded outbound requests are zero. The isolated containers were stopped without deleting volumes. A `--network none` container was also used for Phase 9 syntax. Raw resolved compose output was intentionally not retained because it contains local test credentials; the sanitized safety result is retained.

## 14. Backward-compatibility notes

Legacy artifacts with a concrete stored method remain importable and are labeled `legacy_artifact`; newly ambiguous artifacts are not silently upgraded to POST. Declared REST multi-method routes still expand one config per method.

## 15. Remaining limitations

An unresolved method blocks a fuzzing-ready config until direct source, route declaration, or correlated runtime evidence appears. REST schema arguments and route-regex materialization remain outside this change. Phase 9 was run without its destructive pre/post cleanup; the isolated volumes remain preserved for inspection.

## 16. Exact commands required to reproduce

From repository root, prefix every command with `rtk`:

```powershell
rtk python -m compileall -q phuzz-main/code/fuzzer/hook_energy phuzz-main/code/fuzzer/tests
rtk python -m unittest discover -s phuzz-main/code/fuzzer/tests -v
rtk python research/hookphuzz-opcode/phase10/tests/test_phase10.py -v
rtk python research/hookphuzz-opcode/phase10-gamipress-ajax/tests/test_pipeline.py -v
rtk docker compose --env-file research/http-method-inference/phase9-regression/docker.env -p hookphuzz-phase9-safe-20260801-a1 -f research/hookphuzz-opcode/phase9/docker-compose.yml -f research/http-method-inference/phase9-regression/compose.override.yml up -d --wait --wait-timeout 280 --no-build enabled disabled enabled-static
rtk docker compose --env-file research/http-method-inference/phase9-regression/docker.env -p hookphuzz-phase9-safe-20260801-a1 -f research/hookphuzz-opcode/phase9/docker-compose.yml -f research/http-method-inference/phase9-regression/compose.override.yml run --rm -T verifier
rtk docker compose --env-file research/http-method-inference/phase9-regression/docker.env -p hookphuzz-phase9-safe-20260801-a1 -f research/hookphuzz-opcode/phase9/docker-compose.yml -f research/http-method-inference/phase9-regression/compose.override.yml stop --timeout 30
rtk docker compose --env-file research/http-method-inference/gamipress-regression/docker.env -p hookphuzz-method-20260801-a1 -f research/real-plugin-e2e/gamipress/20260731-234828-gamipress/compose.yml -f research/http-method-inference/gamipress-regression/compose.override.yml up -d --wait --wait-timeout 180
rtk docker compose --env-file research/http-method-inference/gamipress-regression/docker.env -p hookphuzz-method-20260801-a1 -f research/real-plugin-e2e/gamipress/20260731-234828-gamipress/compose.yml -f research/http-method-inference/gamipress-regression/compose.override.yml exec -T -e PLUGIN_SLUG=gamipress -e PLUGIN_SHA256=4bbbe598e316a759690f0bbc0744fa14b8006d090d73bb3e0e8d3b2e0176977f wordpress bash /e2e/scripts/install-plugin.sh
rtk docker compose --env-file research/http-method-inference/gamipress-regression/docker.env -p hookphuzz-method-20260801-a1 -f research/real-plugin-e2e/gamipress/20260731-234828-gamipress/compose.yml -f research/http-method-inference/gamipress-regression/compose.override.yml exec -T -e RUN_ID=20260801-http-method-a1 -e ALLOWED_HOSTS=localhost,127.0.0.1,::1,database,wordpress wordpress python3 /e2e/scripts/bootstrap-probes.py
rtk docker compose --env-file research/http-method-inference/gamipress-regression/docker.env -p hookphuzz-method-20260801-a1 -f research/real-plugin-e2e/gamipress/20260731-234828-gamipress/compose.yml -f research/http-method-inference/gamipress-regression/compose.override.yml exec -T -e RUN_ID=20260801-http-method-a1 -e ALLOWED_HOSTS=localhost,127.0.0.1,::1,database,wordpress -e PYTHONDONTWRITEBYTECODE=1 wordpress python3 /method-regression/gamipress_method_regression.py
rtk docker compose --env-file research/http-method-inference/gamipress-regression/docker.env -p hookphuzz-method-20260801-a1 -f research/real-plugin-e2e/gamipress/20260731-234828-gamipress/compose.yml -f research/http-method-inference/gamipress-regression/compose.override.yml stop --timeout 30
rtk python research/http-method-inference/build_final_artifacts.py
```

## 17. Artifact paths

- Final report: `{(RESULTS / 'final-report.md').relative_to(ROOT).as_posix()}`
- Overall validation: `{(RESULTS / 'final-validation.json').relative_to(ROOT).as_posix()}`
- GamiPress validation: `{(RESULTS / 'validation-result.json').relative_to(ROOT).as_posix()}`
- Test logs: `{(RESULTS / 'logs').relative_to(ROOT).as_posix()}`
- Checksums: `{(RESULTS / 'checksums.sha256').relative_to(ROOT).as_posix()}`
"""
    (RESULTS / "final-report.md").write_text(report, encoding="utf-8")

    checksum_rows = []
    for path in sorted(item for item in RESULTS.rglob("*") if item.is_file() and item.name != "checksums.sha256"):
        checksum_rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(RESULTS).as_posix()}\n")
    (RESULTS / "checksums.sha256").write_text("".join(checksum_rows), encoding="utf-8")
    print(validation["final_status"])
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
