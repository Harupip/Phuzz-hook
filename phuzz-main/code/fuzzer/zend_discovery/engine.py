from __future__ import annotations

import hashlib
import json
import re
import tempfile
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from hook_energy.seed_generation.input_extractor import InputSignatureExtractor
from hook_energy.seed_generation.source_resolver import SourcePathResolver

from .parameter_seeds import build_enriched_parameters
from .source_materializer import materialize_plugin_source


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
    if (
        artifact_legacy_run_id != legacy_run_id
        or artifact.get("request_id") != pass1_request_id
        or artifact.get("target_plugin") != plugin_slug
        or identity["plugin_slug"] != plugin_slug
        or artifact.get("canonical_identity_id") != canonical_identity_id(candidate)
        or artifact.get("callback_id") != identity["callback_identity"]
        or str(artifact.get("http_method") or "").upper() != identity["resolved_method"]
        or artifact.get("auth_variant") != identity["auth_variant"]
        or identity["auth_variant"] == "unresolved"
        or not _callback_executed(dict(artifact), identity["callback_identity"])
    ):
        return None
    return artifact if isinstance(artifact, dict) else dict(artifact)


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
        "fixed_bootstrap": seed_item.get("fixed_bootstrap", {}),
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
    callback: Mapping[str, Any],
    artifacts: list[Mapping[str, Any]],
    extractor: InputSignatureExtractor,
    plugin: Mapping[str, str],
) -> dict[str, Any]:
    identity = canonical_identity(candidate)
    identity_id = canonical_identity_id(candidate)
    proof = next(
        (
            matched
            for artifact in artifacts
            if (matched := correlate_pass1_artifact(
                candidate,
                artifact,
                legacy_run_id=str(candidate["legacy_run_id"]),
                pass1_request_id=str(candidate["pass1_request_id"]),
                plugin_slug=str(candidate["plugin_slug"]),
            )) is not None
        ),
        None,
    )
    extracted = extractor.extract(dict(callback))
    source_resolution = extracted.get("source_resolution", {}) if isinstance(extracted, Mapping) else {}
    current = enrich_current_run(candidate, callback, proof or {}, extractor)
    parameters = [
        row for row in current["parameters"]
        if not PERSISTENCE_FORBIDDEN_KEY.search(str(row.get("name") or ""))
    ]
    blocked_parameters = [
        row for row in current["blocked_parameters"]
        if not PERSISTENCE_FORBIDDEN_KEY.search(str(row.get("name") or ""))
    ]
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
        "source_resolution": deepcopy(source_resolution),
        "source_resolution_status": current["source_resolution_status"],
        "parameters": parameters,
        "blocked_parameters": blocked_parameters,
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
        "probe_replay_allowed": bool(current["probe_replay_allowed"]),
        "final_fuzz_export_allowed": bool(current["final_fuzz_export_allowed"] and fuzzable_params),
        "fuzzable_params": fuzzable_params,
        "seed_patch": {
            "canonical_identity": identity,
            "canonical_identity_id": identity_id,
            "method": identity["resolved_method"],
            "auth_variant": identity["auth_variant"],
            "entrypoint_type": identity["entrypoint_type"],
            "fuzzable_parameters": fuzzable_parameters,
            "fixed_bootstrap": _fixed_bootstrap(raw_item),
            "gates": {
                "accepted_pass1_proof": proof is not None,
                "probe_replay_allowed": bool(current["probe_replay_allowed"]),
                "final_fuzz_export_allowed": bool(current["final_fuzz_export_allowed"] and fuzzable_params),
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
    callbacks = _registered(registry)
    artifacts = [artifact for artifact in pass1_artifacts if isinstance(artifact, Mapping)]
    enriched: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="zend-enrichment-") as source_dir:
        source_root = materialize_plugin_source(Path(plugin_zip), plugin_slug, Path(source_dir))
        extractor = InputSignatureExtractor(
            source_resolver=SourcePathResolver(
                container_source_root=f"/var/www/html/wp-content/plugins/{plugin_slug}",
                host_source_root=source_root,
                source_root=source_root,
            )
        )
        for raw_item in raw_items:
            if not isinstance(raw_item, Mapping):
                continue
            candidate = candidate_from_seed_item(raw_item, plugin_slug=plugin_slug, legacy_run_id=legacy_run_id)
            callback = callbacks.get(candidate["callback_id"], {"callback_id": candidate["callback_id"]})
            record = _enriched_record(raw_item, candidate, callback, artifacts, extractor, plugin)
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
    report = {"legacy_run_id": legacy_run_id, "enriched_seeds": enriched}
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
