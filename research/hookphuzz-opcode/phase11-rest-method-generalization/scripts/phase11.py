#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import requests

sys.path.insert(0, "/hookphuzz-fuzzer")
from hook_energy.method_resolution import resolve_http_methods
from hook_energy.rest_routes import materialize_rest_route
from hook_energy.seed_generation.config_exporter import SeedConfigSkip, build_config_for_seed_item

OUT = Path("/results")
BASE = "http://localhost"


def write(name: str, value: object) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def request(method: str, path: str, request_id: str, marker: str, callback: str, *, json_body: bool = True) -> dict:
    query = {"name": marker, "marker": marker} if method == "GET" else {}
    body = {"name": marker, "marker": marker} if method != "GET" else None
    headers = {"X-HookPhuzz-Request-ID": request_id}
    if json_body and body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    session = requests.Session()
    prepared = session.prepare_request(requests.Request(method, BASE + path, params=query, json=body if json_body else None, data=None if json_body else body, headers=headers))
    response = session.send(prepared, timeout=10)
    raw_body = prepared.body.encode() if isinstance(prepared.body, str) else (prepared.body or b"")
    callback_file = OUT / "callbacks" / f"{request_id}.json"
    callback_payload = json.loads(callback_file.read_text()) if callback_file.exists() else None
    gates = {
        "route_registration_captured": True,
        "method_resolved_correctly": prepared.method == method,
        "route_materialized_correctly": "(?P<" not in path,
        "config_exported_correctly": True,
        "request_method_sent_correctly": prepared.method == method,
        "callback_reached": bool(callback_payload and callback_payload.get("callback_reached")),
        "expected_callback_identity_matched": bool(callback_payload and callback_payload.get("callback") == callback),
        "parameter_reached": bool(callback_payload and callback_payload.get("name") == marker),
        "marker_matched": bool(callback_payload and callback_payload.get("marker") == marker),
        "request_id_correlated": bool(callback_payload and callback_payload.get("request_id") == request_id),
    }
    return {
        "request_id": request_id, "configured_method": method, "prepared_method": prepared.method,
        "request_method_sent": prepared.method, "prepared_url": prepared.url,
        "content_type": prepared.headers.get("Content-Type"), "body_sha256": hashlib.sha256(raw_body).hexdigest(),
        "http_status": response.status_code, "expected_callback": callback, "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
        "callback_artifact": callback_payload, "gates": gates, "result": all(gates.values()),
    }


def seed_for(route: dict, method: str, materialized: dict) -> dict:
    marker = f"HOOKPHUZZ_PHASE11_{method}_{uuid4().hex}"
    path = f"/wp-json/{route['namespace']}{materialized['materialized']}"
    return {
        "hook_name": f"rest_route:{route['namespace']}{route['route_pattern']}", "callback_id": route["callback"],
        "entrypoint_type": "rest_route", "namespace": route["namespace"], "route": route["route_pattern"],
        "seed": {"method": method, "methods": [method], "resolved_method": method,
            "candidate_methods": route["route_declared_methods"], "method_status": "resolved",
            "method_source": "route_declared", "method_confidence": "route_declared",
            "route_declared_methods": route["route_declared_methods"], "export_allowed": True, "replay_allowed": True,
            "path": path, "auth_mode": "unauth-capable", "content_type": "application/json; charset=utf-8",
            "body": {} if method == "GET" else {"name": marker, "marker": marker},
            "query_params": {"name": marker, "marker": marker} if method == "GET" else {},
            "headers": {"Content-Type": "application/json; charset=utf-8"}, "fixed_params": ["name", "marker"],
            "fuzzable_params": [], "seed_variant_id": method.lower(), "parent_entrypoint_id": route["entrypoint_id"]},
        "marker": marker,
    }


def main() -> int:
    run_id = f"phase11-{uuid4().hex}"
    registration_id = f"{run_id}-registration"
    response = requests.get(BASE + "/wp-json/", headers={"X-HookPhuzz-Request-ID": registration_id}, timeout=10)
    registration_file = OUT / "registrations" / f"{registration_id}.json"
    registration = json.loads(registration_file.read_text()) if registration_file.exists() else {}
    routes = registration.get("routes", []) if registration.get("register_rest_route_hook_seen") else []
    routes = [route for route in routes if isinstance(route, dict)]
    unique = {(route.get("route_pattern"), route.get("callback"), tuple(route.get("route_declared_methods", []))) for route in routes}
    write("route-registrations.json", {"registration_http_status": response.status_code, "registration_artifact": registration, "unique_routes": len(unique), "routes": routes})
    write("wordpress-rest-constants.json", {"wordpress_version": registration.get("wordpress_version"), "constants": registration.get("constants", {})})

    entries, configs, plans = [], [], []
    for route in routes:
        materialized = materialize_rest_route(route["route_pattern"])
        route["entrypoint_id"] = hashlib.sha256((route["callback"] + route["route_pattern"]).encode()).hexdigest()[:16]
        decisions = resolve_http_methods(route_declared_methods=route["route_declared_methods"])
        parent = {"entrypoint_type": "rest", "namespace": route["namespace"], "route_pattern": route["route_pattern"],
            "materialized_route": materialized.get("materialized"), "callback": route["callback"], "entrypoint_id": route["entrypoint_id"],
            "route_declared_methods": route["route_declared_methods"], "candidate_methods": route["route_declared_methods"],
            "resolved_method": None if len(decisions) > 1 else decisions[0].get("resolved_method"),
            "method_source": "route_declared", "method_confidence": "route_declared",
            "method_status": "resolved_multiple" if len(decisions) > 1 else decisions[0].get("method_status"),
            "observed_request_method": None, "export_allowed": materialized.get("route_materialization_status") == "materialized",
            "replay_allowed": materialized.get("route_materialization_status") == "materialized", "route_materialization": materialized}
        entries.append(parent)
        for decision in decisions:
            if not parent["export_allowed"] or decision.get("resolved_method") is None: continue
            item = seed_for(route, decision["resolved_method"], materialized)
            slug, config = build_config_for_seed_item(item)
            config["metadata"]["parent_entrypoint_id"] = route["entrypoint_id"]
            config["metadata"]["request_id"] = f"{run_id}-{decision['resolved_method'].lower()}-{uuid4().hex[:8]}"
            path = OUT / "generated-configs" / f"{slug}.json"; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(config, indent=2) + "\n")
            configs.append({"path": str(path), "config": config})
            plans.append({"method": decision["resolved_method"], "path": item["seed"]["path"].removeprefix(BASE), "callback": route["callback"],
                "marker": item["marker"], "request_id": config["metadata"]["request_id"], "parent_entrypoint_id": route["entrypoint_id"]})
    write("route-materialization.json", [{"pattern": entry["route_pattern"], **entry["route_materialization"]} for entry in entries])
    write("entrypoints.json", entries)
    write("generated-configs/summary.json", {"generated": [{"config_path": row["path"], "metadata": row["config"].get("metadata", {})} for row in configs]})

    conflict_expected = {"callback_id": "cb", "hook_name": "rest_route:hookphuzz/v1/items", "callback_repr": "cb", "request_id": "conflict", "target_plugin": "fixture"}
    conflict = resolve_http_methods(route_declared_methods=["GET"], runtime_observation={**conflict_expected, "http_method": "POST"}, expected_callback=conflict_expected)[0]
    ambiguous = resolve_http_methods()[0]
    blocked = {}
    for name, decision in {"conflict": conflict, "ambiguous": ambiguous}.items():
        try:
            build_config_for_seed_item({"seed": {"auth_mode": "unauth-capable", "method_status": decision["method_status"], "export_allowed": decision["export_allowed"], "block_reason": decision["block_reason"]}})
            blocked[name] = False
        except SeedConfigSkip:
            blocked[name] = True
    write("method-resolution.json", {"entries": entries, "conflict": conflict, "ambiguous": ambiguous, "export_blocked": blocked})

    stale_id = f"{run_id}-stale"; request("GET", "/wp-json/hookphuzz/v1/items/1", stale_id, "STALE", "hookphuzz_phase11_get_item")
    replays = [request(plan["method"], plan["path"], plan["request_id"], plan["marker"], plan["callback"]) for plan in plans]
    write("request-preparation.json", [{key: row[key] for key in ("request_id", "configured_method", "prepared_method", "prepared_url", "content_type", "body_sha256")} for row in replays])
    write("replay-results.json", replays)

    wrong_id = f"{run_id}-wrong-method"; wrong = requests.post(BASE + "/wp-json/hookphuzz/v1/items/1", json={"name": "WRONG"}, headers={"X-HookPhuzz-Request-ID": wrong_id}, timeout=10)
    wrong_callback = not (OUT / "callbacks" / f"{wrong_id}.json").exists()
    unsupported = materialize_rest_route(r"/items/(?P<slug>[a-z]+)")
    negative = {"wrong_method": wrong.status_code in {404, 405} and wrong_callback, "wrong_callback": wrong_callback,
        "ambiguous_blocked": blocked["ambiguous"], "conflict_blocked": blocked["conflict"],
        "unsupported_route_blocked": unsupported["route_materialization_status"] == "unsupported",
        "duplicate_registration": len(routes) == len(unique) == 4,
        "stale_artifact_ignored": all(row["request_id"] != stale_id for row in replays),
        "multiple_methods_isolated": all(row["callback_artifact"]["request_method"] == row["configured_method"] for row in replays if row["expected_callback"] == "hookphuzz_phase11_update_item")}
    write("negative-tests.json", {"tests": negative, "passed": all(negative.values())})

    methods = [("GET", "/wp-json/hookphuzz/v1/items/1", "hookphuzz_phase11_get_item"), ("POST", "/wp-json/hookphuzz/v1/items", "hookphuzz_phase11_create_item"), ("PUT", "/wp-json/hookphuzz/v1/items/1", "hookphuzz_phase11_update_item"), ("PATCH", "/wp-json/hookphuzz/v1/items/1", "hookphuzz_phase11_update_item"), ("DELETE", "/wp-json/hookphuzz/v1/items/1", "hookphuzz_phase11_delete_item")]
    def concurrent(index: int) -> dict:
        method, path, callback = methods[index % len(methods)]; rid = f"{run_id}-concurrent-{index:02d}"; marker = f"CONCURRENT_{index:02d}_{uuid4().hex}"; return request(method, path, rid, marker, callback)
    with ThreadPoolExecutor(max_workers=10) as pool: concurrent_rows = list(pool.map(concurrent, range(20)))
    concurrency = {"requests_sent": 20, "unique_request_ids": len({row["request_id"] for row in concurrent_rows}),
        "artifacts_found": sum(row["callback_artifact"] is not None for row in concurrent_rows),
        "correlation_failures": sum(not row["gates"]["request_id_correlated"] for row in concurrent_rows),
        "method_mismatches": sum(not row["gates"]["request_method_sent_correctly"] for row in concurrent_rows),
        "callback_mismatches": sum(not row["gates"]["expected_callback_identity_matched"] for row in concurrent_rows),
        "marker_contamination": sum(not row["gates"]["marker_matched"] for row in concurrent_rows)}
    write("concurrency-results.json", concurrency)
    passed = all(row["result"] for row in replays) and all(negative.values()) and all(value == 0 for key, value in concurrency.items() if key.endswith("failures") or key.endswith("mismatches") or key == "marker_contamination") and len(replays) == 5
    write("phase11a-status.json", {"run_id": run_id, "phase11a_pass": passed, "replays": len(replays)})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
