#!/usr/bin/env python3
"""Validate one local Phase 13 CF7 replay run using only its own artifacts."""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def write(path: Path, value: object) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("results", type=Path); parser.add_argument("runtime", type=Path); parser.add_argument("catalog", type=Path); args = parser.parse_args()
    result = args.results; catalog = load(args.catalog); source_sha = hashlib.sha256(args.catalog.read_bytes()).hexdigest()
    expected = {"public": (200, "WPCF7_REST_Controller::get_schema"), "auth-negative": (403, None), "auth-invalid": (403, None), "auth-valid": (200, "WPCF7_REST_Controller::get_contact_forms")}
    evidence: dict[str, object] = {}; passed = True
    for name, (status, callback) in expected.items():
        replay = load(result / f"{name}.json"); request_id = replay.get("request_id"); runtime_path = args.runtime / f"{request_id}.json"
        runtime = load(runtime_path) if isinstance(request_id, str) and runtime_path.is_file() else {}
        dispatch = runtime.get("rest_dispatch") or []
        invoked = runtime.get("route_callback_invocations") or []
        observed = runtime.get("parameters") or []
        callback_reached = any(item.get("callable") == callback for item in invoked if isinstance(item, dict)) if callback else False
        row = {"request_id": request_id, "request_id_correlated": runtime.get("request_id") == request_id, "http_status": replay.get("http_status"), "expected_status": status, "expected_callback": callback, "callback_reached": callback_reached, "permission_dispatch_entered": any(item.get("stage") == "before_callbacks" for item in dispatch if isinstance(item, dict)), "permission_outcome": "passed" if replay.get("http_status") == 200 else "failed", "parameters": sorted({item.get("name") for item in observed if isinstance(item, dict) and isinstance(item.get("name"), str)}), "runtime_artifact_sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest() if runtime_path.is_file() else None}
        evidence[name] = row
        passed &= replay.get("process_exit_code") == 0 and replay.get("http_status") == status and replay.get("loaded_by") == "Fuzzer.load_config" and replay.get("prepared_by") == "Fuzzer.prepare_request" and replay.get("config_hash_preserved") is True and row["request_id_correlated"] and (callback is None or callback_reached)
    configs = [result / "configs" / "public.json", result / "configs" / "authenticated.json"]
    config_ok = all(load(path).get("metadata", {}).get("source_catalog_sha256") == source_sha for path in configs)
    sensitive = re.compile(r"(?i)(wordpress_logged_in_[^\s:=]+[=:][^\s]+|x-wp-nonce\s*[:=]\s*[^<\s]+|authorization\s*[:=]\s*bearer|password\s*[:=]\s*[^<\s]+)")
    findings = [str(path.relative_to(result)) for path in result.rglob("*") if path.is_file() and sensitive.search(path.read_text(encoding="utf-8", errors="ignore"))]
    gates = {"current_run_only": all(load(path).get("metadata", {}).get("replay_run_id") == result.name for path in configs), "catalog_sha_preserved": config_ok, "public_replay": evidence["public"]["callback_reached"] and evidence["public"]["http_status"] == 200, "authenticated_negative_controls": evidence["auth-negative"]["http_status"] == 403 and evidence["auth-invalid"]["http_status"] == 403, "authenticated_replay": evidence["auth-valid"]["callback_reached"] and evidence["auth-valid"]["http_status"] == 200 and "search" in evidence["auth-valid"]["parameters"], "loader_and_preparation": all(load(result / f"{name}.json").get("loaded_by") == "Fuzzer.load_config" and load(result / f"{name}.json").get("prepared_by") == "Fuzzer.prepare_request" for name in expected), "secrets_redacted": not findings}
    passed &= all(gates.values())
    write(result / "replay-evidence.json", {"run_id": result.name, "source_catalog_sha256": source_sha, "evidence": evidence, "gates": gates})
    write(result / "security-redaction-check.json", {"run_id": result.name, "passed": not findings, "findings": findings})
    write(result / "final-gate-status.json", {"run_id": result.name, "passed": bool(passed), "gates": gates})
    return 0 if passed else 1

if __name__ == "__main__": raise SystemExit(main())
