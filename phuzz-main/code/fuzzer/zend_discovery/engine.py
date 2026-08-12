from __future__ import annotations

import hashlib
import json
import re
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .parameter_seeds import build_enriched_parameters
from .rest_runtime import normalize_rest_parameter_events


PASS = "PASS"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
SKIPPED = "SKIPPED"
BLOCKED_UNSAFE_AUTO_PROBE = "BLOCKED_UNSAFE_AUTO_PROBE"
BLOCKED_NEEDS_RECIPE = "BLOCKED_NEEDS_RECIPE"
READ_ACTION = re.compile(r"(?:get|list|fetch|search|load|view)", re.IGNORECASE)
PERSISTENCE_FORBIDDEN_KEY = re.compile(r"(?:authorization|cookie|password|secret|token|pass2)", re.IGNORECASE)


def canonical_identity(candidate: Mapping[str, Any]) -> dict[str, Any]:
    entrypoint_type = str(candidate.get("entrypoint_type") or candidate.get("kind") or "").lower()
    if entrypoint_type in {"ajax", "admin-post", "admin_post"}:
        dispatch_identity: dict[str, Any] = {
            "dispatcher": entrypoint_type,
            "action": str(candidate.get("action") or ""),
        }
    elif entrypoint_type == "rest":
        dispatch_identity = {
            "namespace": str(candidate.get("namespace") or ""),
            "route_pattern": str(candidate.get("route_pattern") or candidate.get("route") or ""),
            "endpoint_definition_index": candidate.get("endpoint_definition_index"),
            "materialized_route": str(candidate.get("materialized_route") or candidate.get("route") or ""),
        }
    else:
        dispatch_identity = {
            "path": str(candidate.get("path") or candidate.get("route") or ""),
            "fixed_selectors": candidate.get("fixed_selectors", {}),
        }
    return {
        "plugin_slug": str(candidate.get("plugin_slug") or ""),
        "entrypoint_type": entrypoint_type,
        "dispatch_identity": dispatch_identity,
        "callback_identity": str(candidate.get("callback_id") or ""),
        "resolved_method": _candidate_method(candidate),
        "auth_variant": _candidate_auth_variant(candidate, entrypoint_type),
    }


def canonical_identity_id(candidate: Mapping[str, Any]) -> str:
    encoded = json.dumps(canonical_identity(candidate), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def correlate_pass1_artifact(
    candidate: Mapping[str, Any],
    artifact: Mapping[str, Any],
    *,
    legacy_run_id: str,
    pass1_request_id: str,
    plugin_slug: str,
) -> dict[str, Any] | None:
    identity = canonical_identity(candidate)
    artifact_legacy_run_id = artifact.get("legacy_run_id", artifact.get("run_id"))
    artifact_identity_id = str(artifact.get("canonical_identity_id") or "")
    artifact_callback_id = str(artifact.get("callback_id") or "")
    artifact_auth_variant = str(artifact.get("auth_variant") or "")
    if (
        artifact_legacy_run_id != legacy_run_id
        or artifact.get("request_id") != pass1_request_id
        or artifact.get("compat_request_id_matches") is False
        or artifact.get("target_plugin") != plugin_slug
        or identity["plugin_slug"] != plugin_slug
        or (artifact_identity_id and artifact_identity_id != canonical_identity_id(candidate))
        or (artifact_callback_id and artifact_callback_id != identity["callback_identity"])
        or str(artifact.get("http_method") or "").upper() != identity["resolved_method"]
        or (artifact_auth_variant and artifact_auth_variant != identity["auth_variant"])
        or identity["auth_variant"] == "unresolved"
        or not _callback_executed(dict(artifact), identity["callback_identity"])
    ):
        return None
    return artifact if isinstance(artifact, dict) else dict(artifact)


def normalize_runtime_evidence(
    candidate: Mapping[str, Any],
    uopz_artifact: Mapping[str, Any],
    zend_artifact: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return only direct, value-free GET/POST evidence with complete Pass 1 correlation."""
    identity = canonical_identity(candidate)
    proof = correlate_pass1_artifact(
        candidate,
        uopz_artifact,
        legacy_run_id=str(candidate.get("legacy_run_id") or ""),
        pass1_request_id=str(candidate.get("pass1_request_id") or ""),
        plugin_slug=identity["plugin_slug"],
    )
    callback_map = _callback_map(registry)
    canonical_callback = str(callback_map.get(identity["callback_identity"]) or "")
    loading = zend_artifact.get("target_loading") if isinstance(zend_artifact.get("target_loading"), Mapping) else {}
    if (
        proof is None
        or registry.get("schema_version") != 1
        or not canonical_callback
        or str(zend_artifact.get("request_id") or "") != str(candidate.get("pass1_request_id") or "")
        or loading.get("load_status") not in {"loaded", "partially_loaded"}
        or int(loading.get("file_target_count") or 0) < 1
    ):
        return []
    zend_run_id = str(zend_artifact.get("run_id") or "")
    if zend_run_id and zend_run_id != str(candidate.get("legacy_run_id") or ""):
        return []
    zend_method = str(zend_artifact.get("request_method") or zend_artifact.get("method") or "").upper()
    if zend_method and zend_method != str(identity["resolved_method"]).upper():
        return []
    fixed = candidate.get("fixed_bootstrap") if isinstance(candidate.get("fixed_bootstrap"), Mapping) else {}
    if identity["entrypoint_type"] == "rest":
        return normalize_rest_parameter_events(
            candidate,
            zend_artifact,
            uopz_artifact=uopz_artifact,
            canonical_callback=canonical_callback,
            fixed_bootstrap=fixed,
        )
    summaries = zend_artifact.get("callback_summaries")
    if not isinstance(summaries, list):
        return []
    matched = [summary for summary in summaries if isinstance(summary, Mapping) and summary.get("callback") == canonical_callback]
    if len(matched) != 1:
        return []
    parameters = matched[0].get("unique_parameters")
    if not isinstance(parameters, list):
        return []
    normalized: list[dict[str, Any]] = []
    for parameter in parameters:
        if not isinstance(parameter, Mapping):
            continue
        source = str(parameter.get("source") or "").upper()
        path = parameter.get("path")
        try:
            helper_depth = int(parameter.get("helper_depth"))
            observed_count = int(parameter.get("observed_count"))
        except (TypeError, ValueError):
            continue
        if (
            source not in {"GET", "POST"}
            or not isinstance(path, list)
            or len(path) != 1
            or not isinstance(path[0], str)
            or not path[0]
            or helper_depth != 0
            or observed_count < 1
            or path[0] in fixed
        ):
            continue
        normalized.append(
            {
                "name": path[0],
                "path": [path[0]],
                "source": source,
                "location": "query" if source == "GET" else "form",
                "helper_depth": 0,
                "observed_count": observed_count,
                "evidence_kind": "zend_runtime",
                "fuzzable": True,
                "run_id": str(candidate.get("legacy_run_id") or ""),
                "request_id": str(candidate.get("pass1_request_id") or ""),
                "plugin_slug": identity["plugin_slug"],
                "callback_id": identity["callback_identity"],
                "canonical_callback": canonical_callback,
                "request_method": zend_method,
            }
        )
    return sorted(normalized, key=lambda item: (item["source"], item["name"]))


def prepare_callback_registry(registry: Mapping[str, Any], plugin_slug: str) -> dict[str, Any]:
    registrations: list[dict[str, str]] = []
    for callback_id, raw in _registered(dict(registry)).items():
        if not isinstance(raw, Mapping) or not _target_owned(dict(raw), plugin_slug):
            continue
        canonical = _canonical_php_callback(raw, callback_id)
        if not canonical:
            continue
        registrations.append(
            {
                "callback_id": str(raw.get("callback_id") or callback_id),
                "hook_name": str(raw.get("hook_name") or ""),
                "callback": str(raw.get("callback_repr") or canonical),
                "canonical_callback": canonical,
                "callback_type": _php_callable_type(raw, canonical),
                "wordpress_callback_type": str(raw.get("type") or raw.get("callback_type") or ""),
            }
        )
    callback_map = {row["callback_id"]: row["canonical_callback"] for row in registrations}
    return {
        "schema_version": 1,
        "plugin_slug": plugin_slug,
        "callback_map": callback_map,
        "registrations": registrations,
    }


def _canonical_php_callback(raw: Mapping[str, Any], callback_id: str) -> str:
    class_name = str(raw.get("class_name") or "").strip()
    method_name = str(raw.get("method_name") or "").strip()
    if class_name and method_name:
        return f"{class_name}::{method_name}"
    return str(
        raw.get("canonical_callback")
        or raw.get("callback_repr")
        or raw.get("callback_name")
        or raw.get("function_name")
        or callback_id
    ).strip()


def _php_callable_type(raw: Mapping[str, Any], canonical: str) -> str:
    if str(raw.get("class_name") or "") and str(raw.get("method_name") or ""):
        return "static_method" if bool(raw.get("is_static")) else "object_method"
    if "::" in canonical:
        return "static_method"
    return "function"


def _callback_map(registry: Mapping[str, Any]) -> dict[str, str]:
    direct = registry.get("callback_map")
    if isinstance(direct, Mapping):
        return {str(key): str(value) for key, value in direct.items() if str(key) and str(value)}
    rows = registry.get("registrations")
    if not isinstance(rows, list):
        return {}
    mapped: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        callback_id = str(row.get("callback_id") or "").strip()
        canonical = str(row.get("canonical_callback") or "").strip()
        if callback_id and canonical:
            mapped[callback_id] = canonical
    return mapped


def enrich_current_run(
    candidate: Mapping[str, Any],
    callback: Mapping[str, Any],
    artifact: Mapping[str, Any],
    extractor: Any,
) -> dict[str, Any]:
    identity = canonical_identity(candidate)
    legacy_run_id = str(candidate.get("legacy_run_id") or "")
    pass1_request_id = str(candidate.get("pass1_request_id") or "")
    proof = (
        correlate_pass1_artifact(
            candidate,
            artifact,
            legacy_run_id=legacy_run_id,
            pass1_request_id=pass1_request_id,
            plugin_slug=identity["plugin_slug"],
        )
        if legacy_run_id and pass1_request_id
        else None
    )
    if str(callback.get("callback_id") or "") != identity["callback_identity"]:
        return {
            **identity,
            "canonical_identity_id": canonical_identity_id(candidate),
            "legacy_run_id": legacy_run_id,
            "pass1_request_id": pass1_request_id,
            "parameters": [],
            "blocked_parameters": [],
            "probe_replay_allowed": False,
            "final_fuzz_export_allowed": False,
            "source_resolution_status": "unresolved",
        }
    parameters, blocked = build_enriched_parameters(
        candidate,
        callback,
        proof or {},
        extractor,
        valid_pass1_proof=proof is not None,
    )
    result = {
        **identity,
        "canonical_identity_id": canonical_identity_id(candidate),
        "legacy_run_id": legacy_run_id,
        "pass1_request_id": pass1_request_id,
        "parameters": parameters,
        "blocked_parameters": blocked,
        "probe_replay_allowed": proof is not None,
        "final_fuzz_export_allowed": any(item["fuzzable"] for item in parameters),
        "source_resolution_status": "resolved" if any(item["fuzzable"] for item in parameters) else "unresolved",
    }
    return result


def _candidate_method(candidate: Mapping[str, Any]) -> str:
    method = candidate.get("resolved_method") or candidate.get("method")
    if not method:
        methods = candidate.get("methods")
        method = methods[0] if isinstance(methods, list) and methods else ""
    return str(method).upper()


def _candidate_auth_variant(candidate: Mapping[str, Any], entrypoint_type: str) -> str:
    value = str(candidate.get("auth_variant") or candidate.get("auth_mode") or "").lower()
    if value in {"authenticated", "auth"}:
        return "authenticated"
    if value in {"unauthenticated", "nopriv", "public", "unauth-capable", "unauth_capable"}:
        return "unauthenticated"
    hook_name = str(candidate.get("hook_name") or "")
    if hook_name.startswith("wp_ajax_nopriv_") or entrypoint_type.endswith("nopriv"):
        return "unauthenticated"
    return "unresolved"


def read_plugin_metadata(plugin_zip: Path, plugin_slug: str) -> dict[str, str]:
    if plugin_zip.name != f"{plugin_slug}.zip":
        raise ValueError("PLUGIN_ZIP_SLUG_MISMATCH")
    if not zipfile.is_zipfile(plugin_zip):
        raise ValueError("PLUGIN_ZIP_INVALID")
    with zipfile.ZipFile(plugin_zip) as archive:
        php_files = [name for name in archive.namelist() if name.startswith(f"{plugin_slug}/") and name.endswith(".php")]
        main_file = next((name for name in php_files if Path(name).name == f"{plugin_slug}.php"), None)
        if main_file is None:
            raise ValueError("PLUGIN_MAIN_FILE_MISSING")
        text = archive.read(main_file).decode("utf-8", errors="replace")
    version = re.search(r"^\s*\*?\s*Version:\s*(.+?)\s*$", text, re.MULTILINE | re.IGNORECASE)
    if version is None:
        raise ValueError("PLUGIN_VERSION_MISSING")
    return {
        "slug": plugin_slug,
        "version": version.group(1).strip(),
        "main_file": main_file,
        "sha256": hashlib.sha256(plugin_zip.read_bytes()).hexdigest(),
    }


def _registered(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return registry.get("hook_coverage", registry.get("data", {})).get("registered_callbacks", {})


def _target_owned(entry: dict[str, Any], plugin_slug: str) -> bool:
    source = str(entry.get("source_file") or "").replace("\\", "/")
    return f"/wp-content/plugins/{plugin_slug}/" in source or f"/{plugin_slug}/" in source


def _ajax_action(hook_name: str) -> str | None:
    for prefix in ("wp_ajax_nopriv_", "wp_ajax_", "admin_post_nopriv_", "admin_post_"):
        if hook_name.startswith(prefix):
            return hook_name[len(prefix) :]
    return None


def build_catalog(registry: dict[str, Any], plugin_slug: str) -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    for callback_id, raw in _registered(registry).items():
        if not _target_owned(raw, plugin_slug):
            continue
        item = {"callback_id": raw.get("callback_id", callback_id), "callback": raw.get("callback_repr"), "source_file": raw.get("source_file"), "ownership": "target", "parameters": raw.get("input_params", [])}
        hook_name = str(raw.get("hook_name") or "")
        action = _ajax_action(hook_name)
        if raw.get("entrypoint_type") == "rest_route":
            namespace = str(raw.get("namespace") or "").strip("/")
            route = str(raw.get("route") or "").strip("/")
            item.update({"kind": "rest", "route": f"/wp-json/{namespace}/{route}".rstrip("/"), "methods": [str(method).upper() for method in raw.get("methods", [])], "hook_name": hook_name, "status": SKIPPED})
        elif action:
            item.update({"kind": "ajax", "action": action, "route": "/wp-admin/admin-ajax.php", "method": "POST", "hook_name": hook_name, "status": SKIPPED})
        else:
            continue
        catalog.append(item)
    return catalog


def select_auto_probes(catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for item in catalog:
        if item["kind"] == "rest":
            safe_methods = [method for method in item["methods"] if method in {"GET", "HEAD"}]
            if safe_methods:
                probe = dict(item)
                probe["method"] = safe_methods[0]
                probe["status"] = SKIPPED
                selected.append(probe)
            else:
                item["status"] = BLOCKED_UNSAFE_AUTO_PROBE
        elif item["hook_name"].startswith("wp_ajax_nopriv_") and READ_ACTION.search(item["action"]):
            item["status"] = SKIPPED
            selected.append(item)
        else:
            item["status"] = BLOCKED_UNSAFE_AUTO_PROBE
    return selected


def _callback_executed(artifact: dict[str, Any], callback_id: str) -> bool:
    callbacks = artifact.get("hook_coverage", {}).get("executed_callbacks", {})
    return callback_id in callbacks or any(value.get("callback_id") == callback_id for value in callbacks.values() if isinstance(value, dict))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def candidate_from_seed_item(
    seed_item: Mapping[str, Any],
    *,
    plugin_slug: str = "",
    legacy_run_id: str = "",
) -> dict[str, Any]:
    """Normalize one legacy seed item for the Task 1 canonical identity helper."""
    seed = seed_item.get("seed")
    seed = seed if isinstance(seed, Mapping) else {}
    raw_entrypoint_type = str(seed_item.get("entrypoint_type") or seed.get("entrypoint_type") or "").lower()
    body = seed.get("body") if isinstance(seed.get("body"), Mapping) else {}
    query = seed.get("query_params") if isinstance(seed.get("query_params"), Mapping) else {}
    hook_name = str(seed_item.get("hook_name") or "")
    entrypoint_type = _canonical_entrypoint_type(raw_entrypoint_type, hook_name)
    action = str(seed_item.get("action") or body.get("action") or query.get("action") or _ajax_action(hook_name) or "")
    method = str(seed.get("resolved_method") or seed.get("method") or seed_item.get("resolved_method") or seed_item.get("method") or "").upper()
    fixed_bootstrap: dict[str, str] = {}
    fixed_params = seed.get("fixed_params")
    if isinstance(fixed_params, list):
        fixed_bootstrap.update({str(name): "legacy_fixed_param" for name in fixed_params if str(name)})
    raw_bootstrap = seed_item.get("fixed_bootstrap")
    if isinstance(raw_bootstrap, Mapping):
        fixed_bootstrap.update({str(name): str(value) for name, value in raw_bootstrap.items() if str(name)})
    return {
        "plugin_slug": str(seed_item.get("plugin_slug") or plugin_slug),
        "entrypoint_type": entrypoint_type,
        "action": action,
        "namespace": str(seed_item.get("namespace") or ""),
        "route_pattern": str(seed_item.get("route_pattern") or seed_item.get("route") or seed.get("path") or ""),
        "endpoint_definition_index": seed_item.get("endpoint_definition_index"),
        "materialized_route": str(seed_item.get("materialized_route") or seed.get("path") or seed_item.get("route") or ""),
        "path": str(seed_item.get("path") or seed.get("path") or ""),
        "fixed_selectors": seed_item.get("fixed_selectors", {}),
        "callback_id": str(seed_item.get("callback_id") or ""),
        "method": method,
        "auth_mode": str(seed.get("auth_mode") or seed_item.get("auth_mode") or _entrypoint_auth_variant(raw_entrypoint_type)),
        "legacy_run_id": legacy_run_id,
        "pass1_request_id": str(seed_item.get("pass1_request_id") or seed.get("pass1_request_id") or ""),
        "fixed_bootstrap": fixed_bootstrap,
    }


def _canonical_entrypoint_type(raw_entrypoint_type: str, hook_name: str) -> str:
    if hook_name.startswith(("admin_post_nopriv_", "admin_post_")) or raw_entrypoint_type in {"admin-post", "admin_post"}:
        return "admin-post"
    if hook_name.startswith(("wp_ajax_nopriv_", "wp_ajax_")) or raw_entrypoint_type.startswith("ajax"):
        return "ajax"
    if raw_entrypoint_type in {"rest", "rest_route", "rest_api", "wp_rest", "wp_rest_route"}:
        return "rest"
    return raw_entrypoint_type


def _entrypoint_auth_variant(raw_entrypoint_type: str) -> str:
    if raw_entrypoint_type in {"ajax_authenticated", "admin_post_authenticated"}:
        return "authenticated"
    if raw_entrypoint_type in {"ajax_unauthenticated", "admin_post_unauthenticated"}:
        return "unauth-capable"
    return ""


def _fixed_bootstrap(raw_item: Mapping[str, Any]) -> list[dict[str, str]]:
    seed = raw_item.get("seed") if isinstance(raw_item.get("seed"), Mapping) else {}
    names = list(seed.get("fixed_params", [])) if isinstance(seed.get("fixed_params"), list) else []
    bootstrap = raw_item.get("fixed_bootstrap")
    if isinstance(bootstrap, Mapping):
        names.extend(bootstrap.keys())
    return [
        {"name": str(name), "provenance": "legacy_fixed_param"}
        for name in dict.fromkeys(names)
        if str(name) and not PERSISTENCE_FORBIDDEN_KEY.search(str(name))
    ]


def _sanitize_persisted(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_persisted(item)
            for key, item in value.items()
            if not PERSISTENCE_FORBIDDEN_KEY.search(str(key))
        }
    if isinstance(value, list):
        return [_sanitize_persisted(item) for item in value]
    return value


def _enriched_record(
    raw_item: Mapping[str, Any],
    candidate: Mapping[str, Any],
    runtime_registry: Mapping[str, Any],
    uopz_artifacts: list[Mapping[str, Any]],
    zend_artifacts: list[Mapping[str, Any]],
    plugin: Mapping[str, str],
) -> dict[str, Any]:
    identity = canonical_identity(candidate)
    identity_id = canonical_identity_id(candidate)
    canonical_callback = _callback_map(runtime_registry).get(identity["callback_identity"], "")
    proof = None
    proof_artifact: Mapping[str, Any] = {}
    for artifact in uopz_artifacts:
        matched = correlate_pass1_artifact(
            candidate,
            artifact,
            legacy_run_id=str(candidate["legacy_run_id"]),
            pass1_request_id=str(candidate["pass1_request_id"]),
            plugin_slug=str(candidate["plugin_slug"]),
        )
        if matched is not None:
            proof = matched
            proof_artifact = artifact
            break
    zend = next((item for item in zend_artifacts if str(item.get("request_id") or "") == str(candidate["pass1_request_id"])), {})
    parameters = normalize_runtime_evidence(candidate, proof_artifact, zend, runtime_registry)
    fuzzable_parameters = [
        {"name": str(row["name"]), "location": str(row["location"])}
        for row in parameters if row.get("fuzzable")
    ]
    fuzzable_params = [row["name"] for row in fuzzable_parameters]
    record: dict[str, Any] = {
        "canonical_identity": identity,
        "canonical_identity_id": identity_id,
        "legacy_run_id": candidate["legacy_run_id"],
        "pass1_request_id": candidate["pass1_request_id"],
        "plugin_slug": plugin["slug"],
        "plugin_sha256": plugin["sha256"],
        "method": identity["resolved_method"],
        "auth_variant": identity["auth_variant"],
        "entrypoint_type": identity["entrypoint_type"],
        "parameters": parameters,
        "provenance": {
            "pass1": {
                "legacy_run_id": candidate["legacy_run_id"],
                "pass1_request_id": candidate["pass1_request_id"],
                "canonical_identity_id": identity_id,
                "callback_id": identity["callback_identity"],
                "method": identity["resolved_method"],
                "auth_variant": identity["auth_variant"],
            }
        },
        "accepted_pass1_proof": proof is not None,
        "probe_replay_allowed": proof is not None,
        "final_fuzz_export_allowed": bool(proof is not None and fuzzable_params),
        "fuzzable_params": fuzzable_params,
        "seed_patch": {
            "canonical_identity": identity,
            "canonical_identity_id": identity_id,
            "method": identity["resolved_method"],
            "auth_variant": identity["auth_variant"],
            "entrypoint_type": identity["entrypoint_type"],
            "canonical_callback": canonical_callback,
            "fuzzable_parameters": fuzzable_parameters,
            "run_id": candidate["legacy_run_id"],
            "request_id": candidate["pass1_request_id"],
            "request_method": identity["resolved_method"],
            "method_confidence": "runtime_observed",
            "method_source": "runtime_observed",
            "fixed_bootstrap": _fixed_bootstrap(raw_item),
            "gates": {
                "accepted_pass1_proof": proof is not None,
                "probe_replay_allowed": proof is not None,
                "final_fuzz_export_allowed": bool(proof is not None and fuzzable_params),
            },
        },
    }
    return _sanitize_persisted(record)


def run_enrichment(
    plugin_zip: Path,
    plugin_slug: str,
    legacy_run_id: str,
    registry: dict[str, Any],
    raw_seed_report: Mapping[str, Any],
    pass1_artifacts: list[dict[str, Any]],
    output_root: Path,
    zend_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Write value-free Zend enrichment artifacts from offline Pass 1 evidence."""
    plugin = read_plugin_metadata(Path(plugin_zip), plugin_slug)
    raw_items = raw_seed_report.get("suggested_seeds", [])
    if not isinstance(raw_items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
    for raw_item in raw_items:
        if isinstance(raw_item, Mapping) and raw_item.get("plugin_slug") and raw_item["plugin_slug"] != plugin_slug:
            raise ValueError("RAW_CANDIDATE_PLUGIN_MISMATCH")
    output_dir = Path(output_root) / legacy_run_id
    if output_dir.exists():
        raise ValueError("RUN_OUTPUT_ALREADY_EXISTS")
    output_dir.mkdir(parents=True)
    seeds_dir = output_dir / "seeds"
    seeds_dir.mkdir()
    runtime_registry = (
        dict(registry)
        if registry.get("schema_version") == 1 and isinstance(registry.get("registrations"), list)
        else prepare_callback_registry(registry, plugin_slug)
    )
    artifacts = [artifact for artifact in pass1_artifacts if isinstance(artifact, Mapping)]
    zend_events = [artifact for artifact in zend_artifacts or [] if isinstance(artifact, Mapping)]
    enriched: list[dict[str, Any]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping):
            continue
        candidate = candidate_from_seed_item(raw_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
        record = _enriched_record(raw_item, candidate, runtime_registry, artifacts, zend_events, plugin)
        enriched.append(record)
        _write_json(seeds_dir / f"{record['canonical_identity_id']}--{record['method']}.json", record)
    catalog = [
        {
            "canonical_identity_id": row["canonical_identity_id"],
            "callback_id": row["canonical_identity"]["callback_identity"],
            "method": row["method"],
            "accepted_pass1_proof": row["accepted_pass1_proof"],
            "probe_replay_allowed": row["probe_replay_allowed"],
            "final_fuzz_export_allowed": row["final_fuzz_export_allowed"],
        }
        for row in enriched
    ]
    report = {"legacy_run_id": legacy_run_id, "callback_registry": runtime_registry, "enriched_seeds": enriched}
    summary = {
        "legacy_run_id": legacy_run_id,
        "plugin_slug": plugin_slug,
        "plugin_sha256": plugin["sha256"],
        "enriched_seed_count": len(enriched),
        "accepted_pass1_proof": sum(row["accepted_pass1_proof"] for row in enriched),
        "final_fuzz_export_allowed": sum(row["final_fuzz_export_allowed"] for row in enriched),
    }
    _write_json(output_dir / "zend_enriched_seeds.json", report)
    _write_json(output_dir / "zend-enrichment-summary.json", summary)
    _write_json(output_dir / "endpoint-catalog.json", catalog)
    return {**summary, "enriched_seeds": enriched}
