#!/usr/bin/env python3
"""Local-only Phase 11B replay using production REST method/config helpers."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from time import sleep
from urllib.parse import urlsplit
from uuid import uuid4

import requests

sys.path.insert(0, "/hookphuzz-fuzzer")
from hook_energy.method_resolution import resolve_http_methods
from hook_energy.rest_routes import materialize_rest_route
from hook_energy.seed_generation.config_exporter import export_seed_configs


BASE = "http://localhost"
RESULTS = Path("/results")
HOOK_REQUESTS = Path("/shared-tmpfs/hook-coverage/requests")
ROUTE = "/contact-forms"
NAMESPACE = "contact-form-7/v1"
CALLBACK = "WPCF7_REST_Controller::get_contact_forms"
HOOK_CALLBACK = "WPCF7_REST_Controller->get_contact_forms"
HOOK = f"rest_route:{NAMESPACE}{ROUTE}"


def write(name: str, value: object) -> None:
    path = RESULTS / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path, default: object = None) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def request_artifacts() -> set[Path]:
    return set(HOOK_REQUESTS.glob("*.json")) if HOOK_REQUESTS.exists() else set()


def hook_capture() -> dict:
    before = request_artifacts()
    request_id = f"phase11b-register-{uuid4().hex[:12]}"
    response = requests.get(f"{BASE}/wp-json/", headers={"X-HookPhuzz-Request-ID": request_id}, timeout=15)
    callback_path = RESULTS / "callbacks" / f"{request_id}.json"
    for _ in range(30):
        if callback_path.exists() or request_artifacts() - before:
            break
        sleep(0.05)
    callback_doc = load_json(callback_path, {})
    capture = callback_doc.get("hookphuzz_route_capture") if isinstance(callback_doc, dict) else None
    if isinstance(capture, dict):
        return {"registration_http_status": response.status_code, "hookphuzz_request_artifact_created": bool(request_artifacts() - before), "hookphuzz_route_capture_observed": True, **capture}
    for path in sorted(request_artifacts() - before):
        raw = load_json(path, {})
        callbacks = ((raw or {}).get("hook_coverage") or {}).get("registered_callbacks") or {}
        for callback_id, entry in callbacks.items():
            if not isinstance(entry, dict):
                continue
            if entry.get("entrypoint_type") == "rest_route" and entry.get("namespace") == NAMESPACE and entry.get("route") == ROUTE and entry.get("callback_repr") == HOOK_CALLBACK:
                return {
                    "registration_http_status": response.status_code,
                    "hookphuzz_request_artifact_created": True,
                    "hookphuzz_route_capture_observed": True,
                    "callback_id": callback_id,
                    "namespace": entry.get("namespace"),
                    "route_pattern": entry.get("route"),
                    "declared_methods": entry.get("methods"),
                    "callback": entry.get("callback_repr"),
                    "permission_callback": entry.get("permission_callback"),
                    "source_file": entry.get("source_file"),
                    "source_line": entry.get("source_line"),
                }
    return {"registration_http_status": response.status_code, "hookphuzz_request_artifact_created": False, "hookphuzz_route_capture_observed": False}


def login(username: str, password: str) -> tuple[requests.Session, dict, str | None]:
    session = requests.Session()
    first = session.get(f"{BASE}/wp-login.php", timeout=15)
    response = session.post(
        f"{BASE}/wp-login.php",
        data={"log": username, "pwd": password, "wp-submit": "Log In", "redirect_to": f"{BASE}/wp-admin/", "testcookie": "1"},
        allow_redirects=True,
        timeout=15,
    )
    profile = session.get(f"{BASE}/wp-admin/profile.php", timeout=15)
    cookie_names = sorted(cookie.name for cookie in session.cookies)
    cookie_present = any(name.startswith("wordpress_logged_in_") for name in cookie_names)
    success = first.status_code == 200 and response.status_code == 200 and profile.status_code == 200 and cookie_present and "wp-login.php" not in profile.url
    nonce_response = session.get(f"{BASE}/wp-admin/admin-ajax.php", params={"action": "rest-nonce"}, timeout=15) if success else None
    nonce = nonce_response.text.strip() if nonce_response and nonce_response.status_code == 200 else None
    nonce_ok = bool(nonce and nonce.isalnum() and len(nonce) >= 8)
    return session, {
        "login_endpoint": "/wp-login.php",
        "login_http_status": response.status_code,
        "profile_http_status": profile.status_code,
        "authenticated_session_created": success,
        "wordpress_logged_in_cookie_present": cookie_present,
        "cookie_names": cookie_names,
        "cookie_value": "<redacted>",
        "rest_nonce_endpoint": "/wp-admin/admin-ajax.php?action=rest-nonce",
        "rest_nonce_present": nonce_ok,
        "nonce_value": "<redacted>",
    }, nonce if nonce_ok else None


def config_values(config: dict, section: str) -> dict[str, str]:
    data = ((config.get(section) or {}).get("data") or [])
    return {str(item["name"]): str(item["value"]) for item in data if isinstance(item, dict) and "name" in item and "value" in item}


def replay(session: requests.Session, config: dict, request_id: str, nonce: str | None, *, method: str | None = None, id_override: str | None = None) -> tuple[dict, dict | None]:
    configured_method = str((config.get("methods") or [""])[0]).upper()
    sent_method = method or configured_method
    headers = config_values(config, "headers")
    headers["X-HookPhuzz-Request-ID"] = id_override or request_id
    if nonce is not None:
        headers["X-WP-Nonce"] = nonce
    query = config_values(config, "query_params")
    body = config_values(config, "body_params")
    prepared = session.prepare_request(requests.Request(sent_method, str(config["target"]), params=query, data=body if sent_method != "GET" else None, headers=headers))
    response = session.send(prepared, timeout=15)
    callback_path = RESULTS / "callbacks" / f"{request_id}.json"
    for _ in range(30):
        if callback_path.exists():
            break
        sleep(0.05)
    callback = load_json(callback_path, None)
    marker = query.get("search")
    body_bytes = prepared.body.encode() if isinstance(prepared.body, str) else (prepared.body or b"")
    cookie_present = "Cookie" in prepared.headers and "wordpress_logged_in_" in prepared.headers["Cookie"]
    doc = {
        "configured_method": configured_method,
        "prepared_method": prepared.method,
        "prepared_url": prepared.url,
        "request_id": request_id,
        "content_type": prepared.headers.get("Content-Type"),
        "authentication_cookie_present": cookie_present,
        "rest_nonce_present": nonce is not None,
        "body_or_query_marker_present": marker is not None and marker in prepared.url,
        "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "http_status": response.status_code,
        "wordpress_error": response_error(response),
        "callback_artifact_present": isinstance(callback, dict),
    }
    return doc, callback if isinstance(callback, dict) else None


def error_code(row: dict) -> tuple[str | None, str | None]:
    error = row.get("wordpress_error")
    return (error.get("code"), error.get("message")) if isinstance(error, dict) else (None, None)


def response_error(response: requests.Response) -> dict | None:
    if response.status_code < 400 or not response.headers.get("Content-Type", "").startswith("application/json"):
        return None
    try:
        value = response.json()
    except ValueError:
        try:
            value, _ = json.JSONDecoder().raw_decode(response.text.lstrip())
        except ValueError:
            return {"code": "unparseable_wordpress_error", "message": "response declared JSON but was not one JSON document"}
    return value if isinstance(value, dict) else {"code": "unexpected_wordpress_error_shape", "message": "response JSON was not an object"}


def callback_gate(callback: dict | None, request_id: str, marker: str, method: str) -> dict[str, bool]:
    return {
        "permission_callback_passed": bool(callback and callback.get("permission_callback_passed")),
        "real_callback_reached": bool(callback and callback.get("callback_reached")),
        "expected_callback_identity_matched": bool(callback and callback.get("callback") == CALLBACK),
        "parameter_observed": bool(callback and callback.get("parameter_observed")),
        "marker_matched": bool(callback and callback.get("parameter_value") == marker),
        "request_id_correlated": bool(callback and callback.get("request_id") == request_id),
        "request_method_sent_correctly": bool(callback and callback.get("http_method") == method),
    }


def main() -> int:
    run_id = os.environ["PHASE11B_RUN_ID"]
    marker = f"HOOKPHUZZ_PHASE11B_CF7_GET_{run_id.replace('-', '_')}"
    write("auth-setup.json", {"local_only": True, "username": os.environ["PHASE11B_LOCAL_USERNAME"], "permission_capability": "wpcf7_read_contact_forms", "mapped_minimum_capability": "edit_posts", "password": "<redacted>", "fixture_required": False})
    registration = hook_capture()
    write("cf7-route-registration.json", registration)
    declared = registration.get("declared_methods") if isinstance(registration, dict) else None
    decisions = resolve_http_methods(route_declared_methods=declared)
    decision = decisions[0]
    write("method-resolution.json", {"production_module": "hook_energy.method_resolution.resolve_http_methods", "input_declared_methods": declared, "decisions": decisions})
    materialized = materialize_rest_route(ROUTE)
    write("route-materialization.json", {"production_module": "hook_energy.rest_routes.materialize_rest_route", **materialized})
    callback_id = str(registration.get("callback_id") or CALLBACK)
    request_id = f"phase11b-cf7-get-{uuid4().hex}"
    seed_item = {
        "hook_name": HOOK,
        "callback_id": callback_id,
        "callback_repr": CALLBACK,
        "entrypoint_type": "rest_route",
        "seed": {
            "auth_mode": "authenticated", "method": decision.get("resolved_method"), "methods": [decision.get("resolved_method")],
            "resolved_method": decision.get("resolved_method"), "candidate_methods": decision.get("candidate_methods"), "method_status": decision.get("method_status"),
            "method_source": decision.get("method_source"), "method_confidence": decision.get("method_confidence"), "method_evidence": decision.get("method_evidence"),
            "route_declared_methods": decision.get("route_declared_methods"), "export_allowed": decision.get("export_allowed"), "replay_allowed": decision.get("replay_allowed"),
            "path": f"/wp-json/{NAMESPACE}{materialized.get('materialized')}", "body": {}, "query_params": {"search": marker},
            "headers": {"Content-Type": "application/x-www-form-urlencoded", "X-HookPhuzz-Request-ID": request_id}, "fixed_params": ["search", "X-HookPhuzz-Request-ID"], "fuzzable_params": [], "seed_variant_id": "get",
        },
    }
    config_dir = RESULTS.parent / "configs"
    seed_report = {"suggested_seeds": [seed_item]}
    summary = export_seed_configs(seed_report, output_config_dir=config_dir, summary_path=config_dir / "generated_config_summary.json", target_base=BASE)
    config_path = next(path for path in config_dir.glob("*.json") if path.name not in {"generated_config_summary.json", "generated_param_summary.json"})
    config = load_json(config_path, {})
    write("generated-config.json", {"production_module": "hook_energy.seed_generation.config_exporter.export_seed_configs", "summary": summary, "config_path": str(config_path), "config": config})
    write("cf7-route-selection.json", {"namespace": NAMESPACE, "route_pattern": ROUTE, "materialized_route": materialized.get("materialized"), "declared_methods": declared, "resolved_method": decision.get("resolved_method"), "callback": CALLBACK, "permission_callback": registration.get("permission_callback"), "parameter_name": "search", "safe_read_only": True})
    session, login_result, nonce = login(os.environ["PHASE11B_LOCAL_USERNAME"], os.environ["PHASE11B_LOCAL_PASSWORD"])
    write("login-result.json", {key: value for key, value in login_result.items() if not key.startswith("rest_nonce") and key != "nonce_value"})
    write("rest-nonce-result.json", {"rest_nonce_endpoint": login_result["rest_nonce_endpoint"], "rest_nonce_present": login_result["rest_nonce_present"], "nonce_value": "<redacted>"})
    positive, callback = replay(session, config, request_id, nonce)
    write("request-preparation.json", positive)
    gates = callback_gate(callback, request_id, marker, "GET")
    write("permission-result.json", {"permission_callback_passed": gates["permission_callback_passed"], "http_status": positive["http_status"], "wordpress_error_code": error_code(positive)[0], "wordpress_error_message": error_code(positive)[1]})
    write("callback-proof.json", {"plugin": "contact-form-7", "plugin_version": (callback or {}).get("plugin_version"), "namespace": NAMESPACE, "route_pattern": ROUTE, "materialized_route": materialized.get("materialized"), "declared_methods": declared, "resolved_method": decision.get("resolved_method"), "callback": CALLBACK, "permission_callback": registration.get("permission_callback"), "request_id": request_id, "callback_reached": gates["real_callback_reached"], "expected_callback_identity_matched": gates["expected_callback_identity_matched"], "permission_callback_passed": gates["permission_callback_passed"]})
    write("parameter-proof.json", {"parameter_name": "search", "parameter_value": (callback or {}).get("parameter_value"), "marker": marker, "parameter_observed": gates["parameter_observed"], "marker_matched": gates["marker_matched"]})
    write("request-correlation.json", {"request_id": request_id, "callback_request_id": (callback or {}).get("request_id"), "request_id_correlated": gates["request_id_correlated"]})
    write("cf7-plugin-version.json", {"plugin": "contact-form-7", "version": (callback or {}).get("plugin_version"), "expected_version": "5.7.7", "matched": (callback or {}).get("plugin_version") == "5.7.7"})

    no_auth, no_auth_callback = replay(requests.Session(), config, f"{run_id}-no-auth", None)
    invalid_nonce, invalid_nonce_callback = replay(session, config, f"{run_id}-invalid-nonce", "invalidnonce")
    wrong_method, wrong_method_callback = replay(session, config, f"{run_id}-wrong-method", nonce, method="POST")
    actual_id = f"{run_id}-actual-id"
    wrong_id, wrong_id_callback = replay(session, config, f"{run_id}-expected-other-id", nonce, id_override=actual_id)
    denied_session, denied_login, denied_nonce = login(os.environ["PHASE11B_DENIED_USERNAME"], os.environ["PHASE11B_DENIED_PASSWORD"])
    denied, denied_callback = replay(denied_session, config, f"{run_id}-denied", denied_nonce)
    stale_id = request_id
    stale_callback = (RESULTS / "callbacks" / f"{stale_id}.json").exists()
    stale_failure_id = f"{run_id}-stale-failed"
    stale_failed, stale_failed_callback = replay(requests.Session(), config, stale_failure_id, None)
    negatives = {
        "no_auth_cookie": no_auth["http_status"] == 403 and no_auth_callback is not None and not bool(no_auth_callback.get("callback_reached")),
        "invalid_or_missing_nonce": invalid_nonce["http_status"] == 403 and invalid_nonce_callback is not None and not bool(invalid_nonce_callback.get("callback_reached")),
        "wrong_http_method": wrong_method_callback is not None and not bool(wrong_method_callback.get("callback_reached")),
        "wrong_request_id": wrong_id_callback is None or not callback_gate(wrong_id_callback, f"{run_id}-expected-other-id", marker, "GET")["request_id_correlated"],
        "stale_artifact": stale_callback and stale_failed_callback is not None and not bool(stale_failed_callback.get("callback_reached")),
        "insufficient_capability": denied_login["authenticated_session_created"] and denied["http_status"] == 403 and denied_callback is not None and not bool(denied_callback.get("callback_reached")),
        "correct_authentication": all(gates.values()),
    }
    diagnostics = {}
    for name, row, observed in (("no_auth", no_auth, no_auth_callback), ("invalid_nonce", invalid_nonce, invalid_nonce_callback), ("wrong_method", wrong_method, wrong_method_callback), ("denied", denied, denied_callback), ("stale_failed", stale_failed, stale_failed_callback)):
        code, message = error_code(row)
        diagnostics[name] = {"request_sent": True, "configured_method": row["configured_method"], "prepared_method": row["prepared_method"], "http_status": row["http_status"], "wordpress_error_code": code, "wordpress_error_message": message, "authenticated_cookie_present": row["authentication_cookie_present"], "rest_nonce_present": row["rest_nonce_present"], "permission_callback_passed": bool(observed and observed.get("permission_callback_passed")), "real_callback_reached": bool(observed and observed.get("callback_reached")), "parameter_observed": bool(observed and observed.get("parameter_observed")), "request_id_correlated": bool(observed and observed.get("request_id") == row["request_id"]), "blocker": code or "callback_not_executed"}
    write("negative-tests.json", {"tests": negatives, "passed": all(negatives.values()), "diagnostics": diagnostics})
    all_gates = {
        "route_registration_captured": registration.get("hookphuzz_route_capture_observed") is True,
        "real_plugin_identity_matched": registration.get("callback") == HOOK_CALLBACK,
        "plugin_version_matched": (callback or {}).get("plugin_version") == "5.7.7",
        "declared_method_captured": declared == ["GET"],
        "method_resolved_correctly": decision.get("resolved_method") == "GET",
        "route_materialized_correctly": materialized.get("materialized") == ROUTE,
        "generated_config_valid": bool(summary.get("generated")),
        "authenticated_session_created": login_result["authenticated_session_created"],
        **gates,
    }
    status = "PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_PASS" if all(all_gates.values()) and all(negatives.values()) else "PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_FAIL"
    write("phase11b-status.json", {"status": status, "run_id": run_id, "gates": all_gates, "negative_tests_passed": all(negatives.values())})
    report = ["# Phase 11B CF7 authenticated REST proof", "", "## Status", "", f"`{status}`", "", "## Gates", ""] + [f"- {key}: {str(value).lower()}" for key, value in all_gates.items()] + ["", "## Negative tests", ""] + [f"- {key}: {str(value).lower()}" for key, value in negatives.items()]
    (RESULTS / "investigation-summary.md").write_text("See `../investigation.md`. This run used the real local wp-login.php and core rest-nonce flow.\n", encoding="utf-8")
    (RESULTS / "final-report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    return 0 if status.endswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
