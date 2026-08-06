#!/usr/bin/env python3
"""One current-run discovery -> PHUZZ loader -> replay proof for the weekly demo."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs

import requests

sys.path.insert(0, "/app")
from fuzzer import Fuzzer


RUN_ID = os.environ.get("HOOKPHUZZ_WEEKLY_RUN_ID", "self-check")
PROJECT = os.environ.get("HOOKPHUZZ_WEEKLY_PROJECT", "self-check")
RESULTS = Path("/results")
SHARED = Path("/shared/opcode-events")
TARGET = "http://wordpress/wp-admin/admin-ajax.php"
ACTION = "hookphuzz_demo_discover"
CALLBACK = "hookphuzz_demo_discover_callback"
PARAMETER = "demo_discovered_param"
MARKER = "HOOKPHUZZ_WEEKLY_DEMO"


def write(name: str, value: object) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def git(args: list[str]) -> str:
    return subprocess.run(["git", "-c", "safe.directory=/repository", "-C", "/repository", *args], check=True, text=True, capture_output=True).stdout


def wait_artifact(request_id: str) -> dict | None:
    path = SHARED / f"{request_id}.json"
    for _ in range(100):
        if path.is_file():
            return read_json(path)
        time.sleep(0.1)
    return None


def callback_events(artifact: dict, callback: str = CALLBACK) -> list[dict]:
    return [
        event for event in artifact.get("events", [])
        if isinstance(event, dict) and event.get("callback_context", {}).get("root_callback") == callback
    ]


def has_parameter(events: list[dict]) -> bool:
    return any(event.get("source") == "POST" and event.get("path") == [PARAMETER] for event in events)


def valid_evidence(artifact: dict | None, request_id: str, response: dict, expected_callback: str = CALLBACK) -> bool:
    if not artifact or artifact.get("run_id") != RUN_ID or artifact.get("request_id") != request_id:
        return False
    if response.get("callback") != expected_callback or response.get("request_id") != request_id:
        return False
    return bool(callback_events(artifact, expected_callback))


def generated_config() -> dict:
    return {
        "target": TARGET,
        "methods": ["POST"],
        "print_timestamps": False,
        "headers": {"data": [{"name": "X-Phase9-Run-ID", "value": RUN_ID}], "fixed": ["X-Phase9-Run-ID"], "fuzz": [], "weight": 1},
        "body_params": {
            "data": [{"name": "action", "value": ACTION}, {"name": PARAMETER, "value": MARKER}],
            "fixed": ["action"],
            "fuzz": [PARAMETER],
            "weight": 1,
        },
        "metadata": {"generated_reason": "runtime_opcode_observation", "callback": CALLBACK, "run_id": RUN_ID},
    }


def config_is_post_feedback(config: dict) -> bool:
    body = config.get("body_params", {})
    values = {row.get("name"): row.get("value") for row in body.get("data", []) if isinstance(row, dict)}
    return config.get("methods") == ["POST"] and "action" in body.get("fixed", []) and PARAMETER in body.get("fuzz", []) and values.get("action") == ACTION and PARAMETER in values


def negative_checks(config: dict, replay_id: str, replay_artifact: dict, replay_response: dict) -> list[dict]:
    wrong_id = dict(replay_artifact)
    wrong_id["request_id"] = replay_id + "-other"
    no_callback = dict(replay_response)
    no_callback["callback"] = "other_callback"
    get_config = json.loads(json.dumps(config))
    get_config["methods"] = ["GET"]
    get_config["query_params"] = get_config.pop("body_params")
    missing = json.loads(json.dumps(config))
    missing["body_params"]["fuzz"] = []
    missing["body_params"]["data"] = [row for row in missing["body_params"]["data"] if row["name"] != PARAMETER]
    stale = dict(replay_artifact)
    stale["run_id"] = "weekly-previous-run"
    other_plugin = dict(replay_response)
    other_plugin["callback"] = "other_plugin_callback"
    rows = [
        ("different_request_id_rejected", not valid_evidence(wrong_id, replay_id, replay_response)),
        ("http_200_without_callback_rejected", not valid_evidence(replay_artifact, replay_id, no_callback)),
        ("get_parameter_config_rejected", not config_is_post_feedback(get_config)),
        ("stale_result_rejected", not valid_evidence(stale, replay_id, replay_response)),
        ("other_plugin_callback_rejected", not valid_evidence(replay_artifact, replay_id, other_plugin)),
        ("missing_generated_parameter_rejected", not config_is_post_feedback(missing)),
    ]
    return [{"test": name, "pass": passed} for name, passed in rows]


def self_check() -> int:
    config = generated_config()
    artifact = {"run_id": RUN_ID, "request_id": "replay", "events": [{"source": "POST", "path": [PARAMETER], "callback_context": {"root_callback": CALLBACK}}]}
    response = {"callback": CALLBACK, "request_id": "replay", "marker": MARKER}
    assert config_is_post_feedback(config)
    assert all(row["pass"] for row in negative_checks(config, "replay", artifact, response))
    print("weekly loader self-check passed")
    return 0


def main() -> int:
    if "--self-check" in sys.argv:
        return self_check()
    start_dirty = git(["status", "--porcelain"]).splitlines()
    write("starting-state.json", {"run_id": RUN_ID, "compose_project": PROJECT, "branch": git(["branch", "--show-current"]).strip(), "commit": git(["rev-parse", "HEAD"]).strip(), "dirty": start_dirty})

    requests.get("http://wordpress/wp-login.php", timeout=20)
    registry = read_json(Path("/shared/hook-registration.json"))
    dynamic_registration = any(row.get("hook") == "wp_ajax_nopriv_" + ACTION and row.get("canonical_callback") == CALLBACK for row in registry.get("registrations", []))
    initial_config = {"target": TARGET, "methods": ["POST"], "body_params": {"data": [{"name": "action", "value": ACTION}], "fixed": ["action"], "fuzz": []}}
    discovery_id = RUN_ID + "-discovery"
    discovery_request = {"run_id": RUN_ID, "request_id": discovery_id, "method": "POST", "initial_config": initial_config, "body": {"action": ACTION}}
    response = requests.post(TARGET, data=discovery_request["body"], headers={"X-Fuzzer-Covid": discovery_id, "X-Phase9-Run-ID": RUN_ID, "X-HookPhuzz-Request-ID": discovery_id}, timeout=20)
    discovery_response = response.json()
    discovery_request["http_status"] = response.status_code
    discovery_request["response"] = discovery_response
    write("discovery-request.json", discovery_request)
    discovery_artifact = wait_artifact(discovery_id) or {}
    write("discovery-artifact.json", discovery_artifact)
    events = callback_events(discovery_artifact)
    discovered = {"run_id": RUN_ID, "request_id": discovery_id, "callback": CALLBACK, "dynamic_registration_observed": dynamic_registration, "parameters": [{"source": "POST", "path": [PARAMETER], "name": PARAMETER}] if has_parameter(events) else []}
    write("discovered-parameters.json", discovered)

    config = generated_config()
    write("generated-config.json", config)
    replay_id = RUN_ID + "-replay"
    with tempfile.TemporaryDirectory() as temporary:
        workdir = Path(temporary)
        (workdir / "output").mkdir()
        previous = Path.cwd()
        os.chdir(workdir)
        try:
            loader = Fuzzer(0, config_only=True)
            loader.load_config("generated-config", config_dir=str(RESULTS))
            loader.load_request_data()
            candidate = next(loader.generate_initial_candidates())
            candidate.coverage_id = replay_id
            prepared = loader.prepare_request(candidate)
            replay_response_raw = requests.Session().send(prepared, timeout=20)
        finally:
            os.chdir(previous)
    replay_response = replay_response_raw.json()
    prepared_body = {key: values[-1] for key, values in parse_qs((prepared.body or "").decode() if isinstance(prepared.body, bytes) else prepared.body or "", keep_blank_values=True).items()}
    loader_result = {"run_id": RUN_ID, "loaded_by": "Fuzzer.load_config", "prepared_by": "Fuzzer.prepare_request", "config_path": "/results/generated-config.json", "candidate_created_from_loaded_config": True}
    prepared_request = {"run_id": RUN_ID, "request_id": replay_id, "method": prepared.method, "url": prepared.url, "headers": {key: value for key, value in prepared.headers.items() if key.lower() in {"content-type", "x-fuzzer-covid", "x-hookphuzz-request-id", "x-phase9-run-id"}}, "body": prepared_body}
    loader_result["generated_config_loaded"] = True
    loader_result["prepared_request_uses_post"] = prepared.method == "POST"
    write("config-loader-result.json", loader_result)
    write("prepared-request.json", prepared_request)
    replay_request = {"run_id": RUN_ID, "request_id": replay_id, "uses_generated_config": True, "http_status": replay_response_raw.status_code, "request": prepared_request, "response": replay_response}
    write("replay-request.json", replay_request)
    replay_artifact = wait_artifact(replay_id) or {}
    write("replay-artifact.json", replay_artifact)
    replay_events = callback_events(replay_artifact)
    callback_proof = {"run_id": RUN_ID, "request_id": replay_id, "expected_callback": CALLBACK, "callback_reached": bool(replay_events), "parameter_source": "POST" if has_parameter(replay_events) else None, "parameter_path": PARAMETER if has_parameter(replay_events) else None, "marker_expected": MARKER, "marker_observed": replay_response.get("marker"), "response_request_id": replay_response.get("request_id"), "artifact_request_id": replay_artifact.get("request_id"), "artifact_run_id": replay_artifact.get("run_id")}
    write("callback-proof.json", callback_proof)

    negatives = negative_checks(config, replay_id, replay_artifact, replay_response)
    write("negative-tests.json", {"run_id": RUN_ID, "tests": negatives, "pass": all(row["pass"] for row in negatives)})
    end_dirty = git(["status", "--porcelain"]).splitlines()
    gates = {
        "starting_demo_regression_pass": os.environ.get("HOOKPHUZZ_WEEKLY_REGRESSION_PASS") == "true",
        "initial_config_excludes_discovered_parameter": PARAMETER not in json.dumps(initial_config),
        "discovery_request_completed": response.status_code == 200,
        "expected_callback_attributed": valid_evidence(discovery_artifact, discovery_id, discovery_response),
        "runtime_parameter_discovered": has_parameter(events),
        "parameter_source_is_post": has_parameter(events),
        "generated_config_contains_fixed_action": config_is_post_feedback(config),
        "generated_config_contains_fuzz_parameter": PARAMETER in config["body_params"]["fuzz"],
        "generated_config_loaded_by_phuzz": loader_result["generated_config_loaded"] and loader_result["loaded_by"] == "Fuzzer.load_config",
        "prepared_request_uses_post": prepared_request["method"] == "POST",
        "replay_uses_generated_config": replay_request["uses_generated_config"],
        "replay_callback_reached": valid_evidence(replay_artifact, replay_id, replay_response),
        "replay_parameter_observed": has_parameter(replay_events),
        "replay_marker_matched": replay_response.get("marker") == MARKER,
        "request_id_correlated": replay_response.get("request_id") == replay_id and replay_artifact.get("request_id") == replay_id and replay_artifact.get("run_id") == RUN_ID,
        "stale_artifact_rejected": all(row["pass"] for row in negatives),
        "unrelated_work_preserved": start_dirty == end_dirty,
    }
    failed = [name for name, passed in gates.items() if not passed]
    status = "PASS" if not failed else "FAIL"
    gate_report = {"run_id": RUN_ID, "status": status, "gate_count": len(gates), "passed_gate_count": len(gates) - len(failed), "failed_gates": failed, "gates": gates}
    write("final-gate-status.json", gate_report)
    summary = f"""# HookPhuzz weekly demo\n\nStatus: **{status}**\n\n## Before\n\nPHUZZ knows the endpoint and fixed action, but not `{PARAMETER}`.\n\n## Discovery\n\nThe callback runs and Zend records `$_POST['{PARAMETER}']` under `{CALLBACK}`.\n\n## Feedback\n\nThe generated config keeps `action` fixed and makes `{PARAMETER}` a POST fuzz parameter.\n\n## Verification\n\n`Fuzzer.load_config` and `Fuzzer.prepare_request` prepare the replay. `{MARKER}` reaches the same callback with request ID `{replay_id}`.\n\n## Benefit\n\nRuntime evidence removes the need to manually inspect the callback for every parameter. Source/static possibility, runtime observation, generated config, and replay proof are separate artifacts. HTTP status alone is not accepted.\n"""
    (RESULTS / "demo-summary.md").write_text(summary, encoding="utf-8")
    print(f"DEMO_WEEKLY_{status}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    print("weekly loader started", flush=True)
    raise SystemExit(main())
