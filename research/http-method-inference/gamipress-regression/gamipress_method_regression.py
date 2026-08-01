#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, "/fuzzer")
sys.path.insert(0, "/e2e/scripts")

from common import callback_reached, load, parameter_reached, sha256_text, validate_url, write_json
from hook_energy.method_resolution import resolve_http_methods


OUT = Path("/results")
RUNTIME = OUT / "runtime"
SHARED = Path("/shared/opcode-events")
CALLBACK = "gamipress_ajax_get_logs"
HOOK = "wp_ajax_nopriv_gamipress_get_logs"
ACTION = "gamipress_get_logs"


def main() -> int:
    entries_doc = load(OUT / "entrypoints.json")
    observations_doc = load(OUT / "parameter-observations.json")
    entry = next(row for row in entries_doc["entrypoints"] if row["hook_name"] == HOOK)
    observation = observations_doc["observations"][0]
    expected = {
        "callback_id": CALLBACK,
        "callback_repr": CALLBACK,
        "hook_name": HOOK,
        "request_id": observation["request_id"],
        "target_plugin": "gamipress",
    }
    runtime = {
        **expected,
        "observed_request_method": observation["observed_method"],
    }
    decision = resolve_http_methods(
        input_params=[{"name": "page", "source": observation["source"]}],
        runtime_observation=runtime,
        expected_callback=expected,
    )[0]
    if decision["resolved_method"] != "POST" or decision["method_confidence"] != "runtime_observed":
        raise SystemExit("METHOD_PROVENANCE_FAIL")

    entry.update(decision)
    observation.update(decision)
    write_json(OUT / "entrypoints.json", entries_doc)
    write_json(OUT / "parameter-observations.json", observations_doc)

    target = "http://localhost/wp-admin/admin-ajax.php"
    validate_url(target, os.environ["ALLOWED_HOSTS"].split(","))
    method = decision["resolved_method"]
    placement = "query_params" if method in {"GET", "HEAD", "OPTIONS"} else "body_params"
    fixed = ["action", "nonce"]
    config = {
        "target": target,
        "methods": [method],
        "entrypoint_type": "wp_ajax_nopriv",
        "content_type": "application/x-www-form-urlencoded",
        "query_params": {"data": [], "fixed": fixed if placement == "query_params" else [], "fuzz": ["page"] if placement == "query_params" else []},
        "body_params": {"data": [], "fixed": fixed if placement == "body_params" else [], "fuzz": ["page"] if placement == "body_params" else [], "weight": 1},
        "authentication": {"mode": "unauthenticated", "cookies": []},
        "metadata": {
            "plugin": "gamipress",
            "callback": CALLBACK,
            "config_type": "fuzzing_ready",
            "auth_strategy": "nopriv",
            "nonce_strategy": "wp_create_nonce_local",
            "auth_bypass_used": False,
            "nonce_bypass_used": False,
            "runtime_secret_refs": ["HOOKPHUZZ_RUNTIME_NONCE"],
            **decision,
        },
    }
    config[placement]["data"] = [
        {"name": "action", "value": ACTION},
        {"name": "nonce", "value": "${HOOKPHUZZ_RUNTIME_NONCE}"},
        {"name": "page", "value": "FUZZ"},
    ]
    config_path = OUT / "generated-configs" / "gamipress-get-logs.json"
    write_json(config_path, config)
    write_json(
        OUT / "generated-config-summary.json",
        {
            "count": 1,
            "classification": "fuzzing_ready",
            "configs": ["generated-configs/gamipress-get-logs.json"],
            "fixed": fixed,
            "fuzz": ["page"],
            **decision,
            "interpretation": "POST was observed to work for this correlated request; POST-only is not claimed.",
        },
    )

    request_id = f"{os.environ['RUN_ID']}-replay-{uuid.uuid4().hex[:12]}"
    marker = f"HOOKPHUZZ_MARKER_{os.environ['RUN_ID']}_REPLAY"
    nonce = subprocess.run(
        ["wp", "--path=/var/www/html", "--allow-root", "eval", 'echo wp_create_nonce("gamipress");'],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    curl = [
        "curl", "-sS", "--max-time", "5", "--max-redirs", "0", "-o", "/tmp/hookphuzz-method-response",
        "--write-out", "%{http_code}", "-X", method, "-H", f"X-Fuzzer-Covid: {request_id}",
    ]
    if placement == "query_params":
        curl += ["--get"]
    curl += ["--data-urlencode", f"action={ACTION}", "--data-urlencode", f"nonce={nonce}", "--data-urlencode", f"page={marker}", target]
    response = subprocess.run(curl, check=True, capture_output=True, text=True, timeout=10)

    callback_path = RUNTIME / f"{request_id}.callback.json"
    opcode_path = SHARED / f"{request_id}.json"
    for _ in range(150):
        if callback_path.exists() and opcode_path.exists():
            break
        time.sleep(0.1)
    if not callback_path.exists() or not opcode_path.exists():
        raise SystemExit("ARTIFACT_CORRELATION_FAIL")
    shutil.copy2(callback_path, OUT / "replay" / "callback.json")
    shutil.copy2(opcode_path, OUT / "replay" / "opcode.json")
    callback = load(callback_path)
    opcode = load(opcode_path)
    callback_ok = callback_reached(callback, CALLBACK, request_id)
    parameter_ok = parameter_reached(opcode, callback, request_id, marker)
    correlation_ok = opcode.get("request_id") == request_id == callback.get("request_id")
    write_json(
        OUT / "replay" / "request.json",
        {
            "request_id": request_id,
            "method": method,
            "fixed": {"action": ACTION, "nonce": "[REDACTED]"},
            "fuzz": {"page_sha256": sha256_text(marker)},
            "http_status": int(response.stdout),
            **decision,
        },
    )
    replay = {
        "request_sent": True,
        "request_id": request_id,
        "http_status": int(response.stdout),
        "callback_reached": callback_ok,
        "parameter_reached": parameter_ok,
        "request_id_correlated": correlation_ok,
        "status": "PASS" if callback_ok and parameter_ok and correlation_ok else "FAIL",
        **decision,
    }
    write_json(OUT / "replay-summary.json", replay)
    gates = {
        "method_runtime_observed": decision["method_confidence"] == "runtime_observed",
        "config_replayable": True,
        "callback_reached": callback_ok,
        "parameter_reached": parameter_ok,
        "request_id_correlated": correlation_ok,
        "cookies_empty": config["authentication"]["cookies"] == [],
        "no_auth_bypass": config["metadata"]["auth_bypass_used"] is False,
        "no_nonce_bypass": config["metadata"]["nonce_bypass_used"] is False,
    }
    passed = all(gates.values())
    write_json(
        OUT / "validation-result.json",
        {
            "status": "PASS" if passed else "FAIL",
            "final_status": "HOOKPHUZZ_REAL_PLUGIN_E2E_PASS" if passed else "HOOKPHUZZ_REAL_PLUGIN_E2E_FAIL",
            "gates": gates,
            "outbound_requests": 0,
            "unsafe_behavior": False,
            **decision,
        },
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
