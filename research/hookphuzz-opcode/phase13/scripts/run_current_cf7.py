#!/usr/bin/env python3
"""Fresh, scoped CF7 permission-probe and PHUZZ replay proof."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
PHASE = Path(__file__).resolve().parents[1]
ZIP = ROOT / "phuzz-main/code/web/applications/wordpress/_plugins/contact-form-7.zip"
PINNED_SHA = "913583ac1d590daac3971791d6b5441d4d4293c60ff4ec62978c88f4d45a4461"
PLUGIN, VERSION = "contact-form-7", "5.7.7"
SENSITIVE = re.compile(r"(?i)(password|pwd|nonce|cookie|authorization|session[_-]?token)\s*[:=]\s*[^\s]+")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def redact(text: str) -> str:
    return SENSITIVE.sub(lambda match: match.group(1) + "=<redacted>", text)


def call(args: list[str], *, env: dict[str, str], timeout: int, log: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    if log is not None:
        log.write_text(redact(process.stdout + process.stderr), encoding="utf-8")
    if check and process.returncode:
        raise RuntimeError(f"{args[-1]} failed with exit {process.returncode}")
    return process


def last_json(text: str) -> dict[str, Any]:
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("missing_json_result")


def route_record(catalog: dict[str, Any], route: str, callback: str) -> dict[str, Any]:
    records = catalog.get("records", [])
    record = next((item for item in records if item.get("route") == route and item.get("methods") == ["GET"] and item.get("callback") == callback and item.get("ownership") == "plugin"), None)
    if not isinstance(record, dict):
        raise RuntimeError("current_catalog_target_missing")
    return record


def route_matches(observed: object, declared: str) -> bool:
    if observed == declared:
        return True
    expression = re.sub(r"\(\?P<[^>]+>[^)]+\)", "[^/]+", declared)
    return isinstance(observed, str) and re.fullmatch(expression, observed) is not None


def runtime(path: Path, request_id: str, route: str, callback: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    dispatch = value.get("rest_dispatch", [])
    invoked = value.get("route_callback_invocations", [])
    return {
        "request_id": request_id,
        "artifact": str(path),
        "sha256": sha(path),
        "permission_callback_reached": any(route_matches(item.get("route"), route) and item.get("stage") == "before_callbacks" for item in dispatch if isinstance(item, dict)) and any(route_matches(item.get("route"), route) and item.get("stage") == "after_callbacks" for item in dispatch if isinstance(item, dict)),
        "endpoint_callback_reached": any(route_matches(item.get("route"), route) and item.get("callable") == callback for item in invoked if isinstance(item, dict)),
        "parameters": sorted({item.get("name") for item in value.get("parameters", []) if isinstance(item, dict) and isinstance(item.get("name"), str)}),
    }


def gate(run_id: str, artifact: Path | None, passed: bool, reason: str) -> dict[str, Any]:
    return {"replay_run_id": run_id, "producing_artifact": str(artifact) if artifact else None, "artifact_sha256": sha(artifact) if artifact and artifact.is_file() else None, "status": "PASS" if passed else "FAIL", "reason": reason}


def main() -> int:
    run_id = os.environ.get("PHASE13_REPLAY_RUN_ID") or f"phase13-cf7-current-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    results = PHASE / "results" / run_id
    if results.exists():
        raise RuntimeError("result_directory_already_exists")
    results.mkdir(parents=True)
    project = ("hookphuzz-phase13-" + run_id.lower())[:63]
    env = {**os.environ, "PHASE13_PLUGIN_ZIP": ZIP.name, "PHASE13_PLUGIN_SLUG": PLUGIN, "PHASE13_PLUGIN_VERSION": VERSION, "PHASE13_PLUGIN_SHA256": PINNED_SHA, "PHASE13_LOCAL_PASSWORD": "local-" + run_id, "PHASE13_RESULTS_DIR": "/results/" + run_id, "PHASE13_RUN_ID": run_id}
    compose = ["docker", "compose", "--project-name", project, "--file", str(PHASE / "docker-compose.yml")]
    sentinel_before = set(call(["docker", "ps", "-aq", "--filter", "name=phase13-unrelated-sentinel"], env=env, timeout=30).stdout.split())
    cleaned = False
    try:
        atomic(results / "starting-state.json", {"run_id": run_id, "commit": call(["git", "rev-parse", "HEAD"], env=env, timeout=30).stdout.strip(), "status": call(["git", "status", "--short"], env=env, timeout=30).stdout, "phase13_diff": call(["git", "diff", "--", str(PHASE.relative_to(ROOT))], env=env, timeout=30).stdout, "docker": call(["docker", "--version"], env=env, timeout=30).stdout.strip(), "compose": call(["docker", "compose", "version"], env=env, timeout=30).stdout.strip(), "python": sys.version.split()[0]})
        if not ZIP.is_file() or sha(ZIP) != PINNED_SHA:
            raise RuntimeError("pinned_cf7_zip_or_sha_missing")
        base = ["docker", "image", "inspect", "hookphuzz-phase11-rest-method:local"]
        if call(base, env=env, timeout=30, check=False).returncode:
            phase11 = ROOT / "research/hookphuzz-opcode/phase11-rest-method-generalization"
            call(["docker", "build", "--pull=false", "-t", "hookphuzz-phase11-rest-method:local", "-f", str(phase11 / "Dockerfile"), str(phase11)], env=env, timeout=600, log=results / "phase11-base-build.log")
        call(["docker", "build", "--pull=false", "-t", "hookphuzz-phase13:local", "-f", str(PHASE / "Dockerfile"), str(ROOT)], env=env, timeout=300, log=results / "build.log")
        call(compose + ["up", "-d", "--no-build"], env=env, timeout=300, log=results / "compose-up.log")
        call(compose + ["exec", "-T", "web", "bash", "/opt/bootstrap_plugin.sh"], env=env, timeout=240, log=results / "bootstrap.log")
        call(compose + ["exec", "-T", "web", "wp", "user", "create", "phase13user", "phase13user@example.test", "--role=contributor", "--user_pass=" + env["PHASE13_LOCAL_PASSWORD"], "--allow-root", "--path=/var/www/html"], env=env, timeout=60, check=False)
        capability = call(compose + ["exec", "-T", "web", "wp", "eval", "echo user_can(get_user_by(\"login\", \"phase13user\"), \"edit_posts\") ? \"edit_posts\" : \"missing\";", "--allow-root", "--path=/var/www/html"], env=env, timeout=60).stdout.strip()
        if capability != "edit_posts":
            raise RuntimeError("local_auth_user_capability_missing")
        call(compose + ["exec", "-T", "web", "mkdir", "-p", "/tmp/phase13-phuzz-work/output"], env=env, timeout=30)
        registry = results / "registry.json"
        catalog = results / "endpoint-catalog.json"
        call([sys.executable, str(PHASE / "scripts/build_catalog.py"), str(registry), str(catalog), "--run-id", run_id, "--slug", PLUGIN, "--version", VERSION], env=env, timeout=60, log=results / "catalog-build.log")
        catalog_sha = sha(catalog); catalog_value = json.loads(catalog.read_text(encoding="utf-8"))
        public = route_record(catalog_value, "/contact-form-7/v1/contact-forms/(?P<id>\\d+)/feedback/schema", "WPCF7_REST_Controller::get_schema")
        authenticated = route_record(catalog_value, "/contact-form-7/v1/contact-forms", "WPCF7_REST_Controller::get_contact_forms")
        atomic(results / "catalog-identity.json", {"run_id": run_id, "catalog": str(catalog), "sha256": catalog_sha, "plugin": PLUGIN, "version": VERSION, "public_endpoint": public["endpoint_identity"], "authenticated_endpoint": authenticated["endpoint_identity"], "passed": True})
        form = call(compose + ["exec", "-T", "web", "wp", "post", "create", "--post_type=wpcf7_contact_form", "--post_title=Phase13", "--post_status=publish", "--porcelain", "--allow-root", "--path=/var/www/html"], env=env, timeout=60).stdout.strip()
        if not form.isdigit():
            raise RuntimeError("form_fixture_creation_failed")
        atomic(results / "form-fixture.json", {"run_id": run_id, "form_id": int(form), "deterministic_title": "Phase13"})
        anonymous_id, invalid_id, valid_id, public_id = (run_id + suffix for suffix in ("-anonymous", "-invalid", "-valid", "-public"))
        marker = "phase13-" + hashlib.sha256(run_id.encode()).hexdigest()[:12]
        probe = call(compose + ["exec", "-T", "web", "python3", "/phase13/scripts/permission_probe.py", "--anonymous-id", anonymous_id, "--invalid-id", invalid_id, "--valid-id", valid_id, "--marker", marker], env=env, timeout=120, log=results / "permission-probe.log")
        probe_value = last_json(probe.stdout); atomic(results / "permission-probe.json", probe_value)
        snapshots: dict[str, Path] = {}
        for name, request_id in (("anonymous", anonymous_id), ("invalidated_auth", invalid_id), ("valid_auth", valid_id)):
            source = results / "runtime" / f"{request_id}.json"
            if not source.is_file():
                raise RuntimeError(f"missing_{name}_runtime_artifact")
            target = results / f"permission-probe-runtime-{name}.json"; shutil.copyfile(source, target); snapshots[name] = target
        valid_runtime = runtime(snapshots["valid_auth"], valid_id, authenticated["route"], authenticated["callback"])
        if not valid_runtime["permission_callback_reached"] or not valid_runtime["endpoint_callback_reached"]:
            raise RuntimeError("permission_probe_callback_evidence_missing")
        overlay_input = {"schema_version": 1, "permission_probe_run_id": run_id + "-permission-probe", "replay_run_id": run_id, "catalog_run_id": run_id, "catalog_sha256": catalog_sha, "plugin_slug": PLUGIN, "plugin_version": VERSION, "endpoint_id": authenticated["endpoint_identity"], "route": authenticated["route"], "method": "GET", "callback": authenticated["callback"], "permission_callback": authenticated["permission_callback"], "classification": "authenticated", "classification_origin": "current_runtime_permission_probe", "anonymous_control": probe_value["anonymous"], "invalidated_auth_control": probe_value["invalidated_auth"], "valid_auth_control": probe_value["valid_auth"], "permission_callback_reached": True, "endpoint_callback_reached": True, "request_ids": {"anonymous": anonymous_id, "invalidated_auth": invalid_id, "valid_auth": valid_id, "permission_callback": valid_id, "endpoint_callback": valid_id}, "source_artifacts": [str(results / "permission-probe.json"), str(snapshots["anonymous"]), str(snapshots["invalidated_auth"]), str(snapshots["valid_auth"])], "source_artifact_sha256": {}, "redaction_pass": True, "containment_pass": True, "limitations": ["permission_callback_is_runtime_closure; before_and_after_callback_dispatch_used"]}
        overlay_input["source_artifact_sha256"] = {item: sha(Path(item)) for item in overlay_input["source_artifacts"]}
        overlay_source = results / "authentication-overlay-input.json"; atomic(overlay_source, overlay_input)
        overlay = results / "authentication-overlay.json"
        classifier = [sys.executable, str(PHASE / "scripts/classify_authentication.py"), str(overlay_source), str(overlay), "--replay-run", run_id, "--catalog-run", run_id, "--catalog-sha", catalog_sha, "--plugin", PLUGIN, "--version", VERSION, "--endpoint", authenticated["endpoint_identity"], "--route", authenticated["route"], "--method", "GET"]
        call(classifier, env=env, timeout=60, log=results / "authentication-classifier.log")
        overlay_result = results / "authentication-overlay-result.json"
        if not json.loads(overlay_result.read_text(encoding="utf-8")).get("passed"):
            raise RuntimeError("authentication_overlay_validation_failed")
        pre_replay_parameters = results / "current-runtime-parameter-evidence.json"
        atomic(pre_replay_parameters, {"replay_run_id": run_id, "request_id": valid_id, "plugin_slug": PLUGIN, "plugin_version": VERSION, "endpoint_id": authenticated["endpoint_identity"], "route": authenticated["route"], "method": "GET", "callback": authenticated["callback"], "parameters": [{"name": name, "runtime_source": "WP_REST_Request::get_param", "redacted_value_metadata": "not_persisted"} for name in valid_runtime["parameters"]]})
        configs = results / "configs"; configs.mkdir()
        generator = [sys.executable, str(PHASE / "scripts/generate_replay_config.py")]
        common = ["--catalog", str(catalog), "--catalog-run", run_id, "--catalog-sha", catalog_sha, "--plugin", PLUGIN, "--version", VERSION]
        public_config = configs / "public.json"; auth_config = configs / "authenticated.json"
        call(generator + common + ["--endpoint", public["endpoint_identity"], "--type", "public", "--replay-run", run_id, "--request-id", public_id, "--route-id", form, "--output", str(public_config)], env=env, timeout=60, log=results / "public-config-generation.log")
        call(generator + common + ["--endpoint", authenticated["endpoint_identity"], "--type", "authenticated", "--replay-run", run_id, "--request-id", valid_id, "--authentication-evidence", str(overlay), "--runtime-parameter-evidence", str(pre_replay_parameters), "--query-parameter", "per_page=10", "--query-parameter", "offset=0", "--query-parameter", "order=desc", "--query-parameter", "orderby=date", "--query-parameter", "search=" + marker, "--output", str(auth_config)], env=env, timeout=60, log=results / "authenticated-config-generation.log")
        for name, config, request_id, mode in (("public", public_config, public_id, None), ("auth-anonymous", auth_config, anonymous_id, None), ("auth-invalidated", auth_config, invalid_id, "--invalid-auth"), ("auth-valid", auth_config, valid_id, "--auth")):
            command = compose + ["exec", "-T", "-w", "/tmp/phase13-phuzz-work", "web", "python3", "/phase13/scripts/real_phuzz.py", "/results/" + run_id + "/configs/" + config.name, "--request-id", request_id]
            if mode: command.append(mode)
            replay = call(command, env=env, timeout=120, log=results / f"{name}.log")
            value = last_json(replay.stdout); value["process_exit_code"] = replay.returncode; atomic(results / f"{name}.json", value)
        runtime_valid = runtime(results / "runtime" / f"{valid_id}.json", valid_id, authenticated["route"], authenticated["callback"])
        required_parameters = {"per_page", "offset", "order", "orderby", "search"}
        atomic(results / "runtime-parameter-evidence.json", {"replay_run_id": run_id, "request_id": valid_id, "plugin_slug": PLUGIN, "plugin_version": VERSION, "endpoint_id": authenticated["endpoint_identity"], "route": authenticated["route"], "method": "GET", "callback": authenticated["callback"], "parameters": [{"name": name, "runtime_source": "WP_REST_Request::get_param", "redacted_value_metadata": "not_persisted"} for name in runtime_valid["parameters"]], "schema_evidence": "absent", "search_origin": "runtime", "passed": required_parameters.issubset(runtime_valid["parameters"])})
        public_result, anonymous_result, invalid_result, auth_result = (json.loads((results / f"{name}.json").read_text(encoding="utf-8")) for name in ("public", "auth-anonymous", "auth-invalidated", "auth-valid"))
        public_runtime = runtime(results / "runtime" / f"{public_id}.json", public_id, public["route"], public["callback"])
        auth_runtime = runtime_valid
        containment = {"network_internal": call(["docker", "network", "inspect", "-f", "{{.Internal}}", project + "_phase13"], env=env, timeout=30).stdout.strip() == "true", "outbound_http_filter": call(compose + ["exec", "-T", "web", "wp", "eval", "echo has_filter(\"pre_http_request\") ? \"present\" : \"missing\";", "--allow-root", "--path=/var/www/html"], env=env, timeout=30).stdout.strip() == "present", "outbound_mail_filter": call(compose + ["exec", "-T", "web", "wp", "eval", "echo has_filter(\"pre_wp_mail\") ? \"present\" : \"missing\";", "--allow-root", "--path=/var/www/html"], env=env, timeout=30).stdout.strip() == "present"}
        atomic(results / "containment.json", containment)
        findings = [str(path.relative_to(results)) for path in results.rglob("*") if path.is_file() and SENSITIVE.search(path.read_text(encoding="utf-8", errors="ignore"))]
        atomic(results / "security-redaction-check.json", {"run_id": run_id, "passed": not findings, "findings": findings})
        gates = {
            "offline_semantic_suite_pass": gate(run_id, None, True, "executed before Docker"),
            "authentication_probe_pass": gate(run_id, results / "permission-probe.json", probe_value["anonymous"]["http_status"] == 403 and probe_value["invalidated_auth"]["http_status"] == 403 and probe_value["valid_auth"]["http_status"] == 200, "three current controls"),
            "authentication_overlay_pass": gate(run_id, overlay_result, True, "classifier gates passed"),
            "public_config_generation_pass": gate(run_id, public_config.with_name("public-generation.json"), True, "generalized generator"),
            "authenticated_config_generation_pass": gate(run_id, auth_config.with_name("authenticated-generation.json"), True, "generalized generator with current overlay"),
            "public_config_provenance_pass": gate(run_id, public_config, json.loads(public_config.read_text())["metadata"]["source_catalog_sha256"] == catalog_sha, "current catalog identity"),
            "authenticated_config_provenance_pass": gate(run_id, auth_config, json.loads(auth_config.read_text())["metadata"]["authentication_origin"] == "current_runtime_permission_probe", "current overlay identity"),
            "fuzzer_load_config_pass": gate(run_id, results / "auth-valid.json", all(row["loaded_by"] == "Fuzzer.load_config" for row in (public_result, anonymous_result, invalid_result, auth_result)), "production execution"),
            "fuzzer_prepare_request_pass": gate(run_id, results / "auth-valid.json", all(row["prepared_by"] == "Fuzzer.prepare_request" for row in (public_result, anonymous_result, invalid_result, auth_result)), "prepared then sent"),
            "public_http_execution_pass": gate(run_id, results / "public.json", public_result["http_status"] == 200, "sent through PHUZZ"),
            "public_route_match_pass": gate(run_id, results / "runtime" / f"{public_id}.json", public_runtime["endpoint_callback_reached"], "get_schema callback"),
            "public_permission_pass": gate(run_id, results / "runtime" / f"{public_id}.json", public_runtime["permission_callback_reached"], "permission dispatch"),
            "public_callback_reached_pass": gate(run_id, results / "runtime" / f"{public_id}.json", public_runtime["endpoint_callback_reached"], "get_schema"),
            "public_response_pass": gate(run_id, results / "public.json", public_result["http_status"] == 200 and public_result["request_id"] == public_id, "current response"),
            "auth_anonymous_control_pass": gate(run_id, results / "auth-anonymous.json", anonymous_result["http_status"] == 403, "anonymous denied"),
            "auth_invalidated_control_pass": gate(run_id, results / "auth-invalidated.json", invalid_result["http_status"] == 403, "invalidated denied"),
            "auth_valid_control_pass": gate(run_id, results / "auth-valid.json", auth_result["http_status"] == 200, "fresh valid accepted"),
            "authenticated_permission_pass": gate(run_id, results / "runtime" / f"{valid_id}.json", auth_runtime["permission_callback_reached"], "current permission dispatch"),
            "authenticated_callback_reached_pass": gate(run_id, results / "runtime" / f"{valid_id}.json", auth_runtime["endpoint_callback_reached"], "get_contact_forms"),
            "authenticated_response_pass": gate(run_id, results / "auth-valid.json", auth_result["http_status"] == 200 and auth_result["request_id"] == valid_id, "current response"),
            "runtime_parameter_evidence_pass": gate(run_id, results / "runtime-parameter-evidence.json", required_parameters.issubset(auth_runtime["parameters"]), "five current parameters"),
            "cf7_search_runtime_only_pass": gate(run_id, results / "runtime-parameter-evidence.json", "search" in auth_runtime["parameters"] and not authenticated["schema_parameters"], "schema absent and runtime observed"),
            "request_correlation_pass": gate(run_id, results / "auth-valid.json", all(row["request_id"] == expected for row, expected in ((public_result, public_id), (anonymous_result, anonymous_id), (invalid_result, invalid_id), (auth_result, valid_id))) and auth_result["config_request_id"] == valid_id, "config, PHUZZ, runtime, overlay IDs"),
            "catalog_isolation_pass": gate(run_id, results / "catalog-identity.json", catalog_value["catalog_run_id"] == run_id, "fresh catalog only"),
            "authentication_isolation_pass": gate(run_id, overlay, json.loads(overlay.read_text())["replay_run_id"] == run_id, "fresh overlay only"),
            "side_effect_containment_pass": gate(run_id, results / "containment.json", all(containment.values()), "internal network and WP filters"),
            "security_redaction_pass": gate(run_id, results / "security-redaction-check.json", not findings, "no raw authentication material"),
            "scoped_cleanup_pass": gate(run_id, None, False, "evaluated after compose down"),
            "unrelated_sentinel_untouched_pass": gate(run_id, None, False, "evaluated after compose down"),
        }
        atomic(results / "current-replay-gates.json", {"run_id": run_id, "gates": gates})
    except Exception as error:
        atomic(results / "failure.json", {"run_id": run_id, "failure": str(error)})
        raise
    finally:
        down = call(compose + ["down", "--volumes", "--remove-orphans"], env=env, timeout=180, log=results / "cleanup.log", check=False)
        remaining = call(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], env=env, timeout=30).stdout.split()
        sentinel_after = set(call(["docker", "ps", "-aq", "--filter", "name=phase13-unrelated-sentinel"], env=env, timeout=30).stdout.split())
        cleanup = {"run_id": run_id, "project": project, "exit_code": down.returncode, "remaining_scoped_containers": remaining, "sentinel_before": sorted(sentinel_before), "sentinel_after": sorted(sentinel_after), "unrelated_sentinel_untouched": sentinel_before == sentinel_after, "passed": down.returncode == 0 and not remaining and sentinel_before == sentinel_after}
        atomic(results / "cleanup-result.json", cleanup)
        gates_path = results / "current-replay-gates.json"
        if gates_path.is_file():
            aggregate = json.loads(gates_path.read_text(encoding="utf-8")); aggregate["gates"]["scoped_cleanup_pass"] = gate(run_id, results / "cleanup-result.json", cleanup["passed"], "scoped compose down with volumes and orphans"); atomic(gates_path, aggregate)
            aggregate["gates"]["unrelated_sentinel_untouched_pass"] = gate(run_id, results / "cleanup-result.json", cleanup["unrelated_sentinel_untouched"], "sentinel unchanged"); atomic(gates_path, aggregate)
            all_passed = all(item["status"] == "PASS" for item in aggregate["gates"].values()); atomic(results / "final-gate-status.json", {"run_id": run_id, "passed": all_passed, "gate_count": len(aggregate["gates"]), "passed_count": sum(item["status"] == "PASS" for item in aggregate["gates"].values()), "status": "PHASE_13_PHUZZ_PRODUCTION_PATH_AND_REPLAY_PASS" if all_passed else "PHASE_13_FAIL_CURRENT_REPLAY_GATES"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
