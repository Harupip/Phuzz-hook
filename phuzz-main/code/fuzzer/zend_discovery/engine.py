from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from hook_energy.seed_generation.input_extractor import InputSignatureExtractor
    from hook_energy.seed_generation.source_resolver import SourcePathResolver
    from zend_discovery.parameter_seeds import build_parameter_seed
    from zend_discovery.source_materializer import materialize_plugin_source
else:
    from hook_energy.seed_generation.input_extractor import InputSignatureExtractor
    from hook_energy.seed_generation.source_resolver import SourcePathResolver

    from .parameter_seeds import build_parameter_seed
    from .source_materializer import materialize_plugin_source


PASS = "PASS"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
SKIPPED = "SKIPPED"
BLOCKED_UNSAFE_AUTO_PROBE = "BLOCKED_UNSAFE_AUTO_PROBE"
BLOCKED_NEEDS_RECIPE = "BLOCKED_NEEDS_RECIPE"
READ_ACTION = re.compile(r"(?:get|list|fetch|search|load|view)", re.IGNORECASE)
RECIPE_FIELDS = {"selector", "auth_mode", "fixed_fields", "seed_values"}
FORBIDDEN_RECIPE_FIELDS = re.compile(r"(?:secret|cookie|password|token|authorization)", re.IGNORECASE)


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
    for prefix in ("wp_ajax_nopriv_", "wp_ajax_"):
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


def correlate_artifact(endpoint: dict[str, Any], artifact: dict[str, Any], run_id: str, plugin_slug: str) -> dict[str, Any] | None:
    if artifact.get("run_id") != run_id or artifact.get("target_plugin") != plugin_slug:
        return None
    if str(artifact.get("http_method", "")).upper() != endpoint["method"]:
        return None
    target = str(artifact.get("http_target") or "")
    parsed = urlparse(target)
    if endpoint["kind"] == "ajax":
        if parsed.path != endpoint["route"] or parse_qs(parsed.query).get("action", [None])[-1] != endpoint["action"]:
            return None
    elif parsed.path != endpoint["route"]:
        return None
    if not artifact.get("request_id") or not _callback_executed(artifact, endpoint["callback_id"]):
        return None
    return artifact


def _validate_recipe(recipe_path: Path | None) -> dict[str, Any] | None:
    if recipe_path is None:
        return None
    value = json.loads(recipe_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) - RECIPE_FIELDS:
        raise ValueError("RECIPE_UNKNOWN_FIELD")
    if any(FORBIDDEN_RECIPE_FIELDS.search(str(key)) for key in value):
        raise ValueError("RECIPE_SECRET_FIELD")
    if "selector" in value and (not isinstance(value["selector"], dict) or set(value["selector"]) - {"callback_id", "action", "route", "method"}):
        raise ValueError("RECIPE_UNSAFE_SELECTOR")
    for key in ("fixed_fields", "seed_values"):
        if key in value and not isinstance(value[key], dict):
            raise ValueError("RECIPE_INVALID_FIELDS")
    return value


def _config_for(endpoint: dict[str, Any], seed: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any] | None:
    params = [entry["name"] for entry in seed["parameters"] if entry.get("fuzzable")]
    if not params:
        return None
    if endpoint["kind"] == "ajax":
        params = [entry["name"] for entry in seed["parameters"] if entry.get("fuzzable") and entry["location"] == "body"]
        if not params:
            return None
        return {"target": "http://web/wp-admin/admin-ajax.php", "methods": ["POST"], "body_params": {"data": [{"name": "action", "value": endpoint["action"]}] + [{"name": name, "value": "fuzz"} for name in params], "fixed": ["action"], "fuzz": params, "weight": 1}, "zend_proof": {"request_id": artifact["request_id"], "callback_id": endpoint["callback_id"]}}
    section = "query_params" if seed["method"] in {"GET", "HEAD"} else "body_params"
    location = "query" if section == "query_params" else "body"
    params = [entry["name"] for entry in seed["parameters"] if entry.get("fuzzable") and entry["location"] == location]
    if not params:
        return None
    return {"target": f"http://web{endpoint['route']}", "methods": [seed["method"]], section: {"data": [{"name": name, "value": "fuzz"} for name in params], "fixed": [], "fuzz": params, "weight": 1}, "zend_proof": {"request_id": artifact["request_id"], "callback_id": endpoint["callback_id"]}}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_runtime_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(artifact))
    params = value.get("request_params")
    if isinstance(params, dict):
        value["request_params"] = {
            f"{section}_names": sorted(str(name) for name in params.get(section, {}) if not FORBIDDEN_RECIPE_FIELDS.search(str(name)))
            for section in ("query_params", "body_params")
            if isinstance(params.get(section), dict)
        }
    return value


def build_probe_plan(registry: dict[str, Any], plugin_slug: str) -> list[dict[str, Any]]:
    return [
        {key: endpoint[key] for key in ("callback_id", "kind", "route", "method", "action") if key in endpoint}
        for endpoint in select_auto_probes(build_catalog(registry, plugin_slug))
    ]


def run_discovery(plugin_zip: Path, plugin_slug: str, run_id: str, registry: dict[str, Any], request_artifacts: list[dict[str, Any]], output_root: Path, recipe_path: Path | None = None) -> dict[str, Any]:
    output_dir = output_root / run_id
    if output_dir.exists():
        raise ValueError("RUN_OUTPUT_ALREADY_EXISTS")
    output_dir.mkdir(parents=True)
    (output_dir / "runtime").mkdir()
    (output_dir / "seeds").mkdir()
    (output_dir / "configs").mkdir()
    (output_dir / "replays").mkdir()
    try:
        plugin = read_plugin_metadata(plugin_zip, plugin_slug)
        integrity = PASS
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        summary = {"run_id": run_id, "plugin_slug": plugin_slug, "stages": {"integrity": FAILED, "catalog": SKIPPED, "recipe": SKIPPED, "replay": SKIPPED}, "error": str(error), "endpoints": []}
        _write_json(output_dir / "run-summary.json", summary)
        raise
    try:
        _validate_recipe(recipe_path)
        recipe_status = PASS if recipe_path else SKIPPED
    except (ValueError, json.JSONDecodeError) as error:
        catalog = build_catalog(registry, plugin_slug)
        for endpoint in catalog:
            endpoint["status"] = BLOCKED_NEEDS_RECIPE
        summary = {"run_id": run_id, "plugin": plugin, "plugin_slug": plugin_slug, "stages": {"integrity": integrity, "catalog": PASS, "recipe": FAILED, "replay": BLOCKED}, "error": str(error), "endpoints": catalog}
        _write_json(output_dir / "endpoint-catalog.json", catalog)
        _write_json(output_dir / "run-summary.json", summary)
        return summary
    catalog = build_catalog(registry, plugin_slug)
    probes = select_auto_probes(catalog)
    for artifact in request_artifacts:
        request_id = str(artifact.get("request_id") or "rejected")
        _write_json(output_dir / "runtime" / f"{request_id}.json", _safe_runtime_artifact(artifact))
    replays: list[dict[str, Any]] = []
    generated: list[dict[str, Any]] = []
    callbacks = _registered(registry)
    with tempfile.TemporaryDirectory(prefix="zend-discovery-") as source_dir:
        source_root = materialize_plugin_source(plugin_zip, plugin_slug, Path(source_dir))
        resolver = SourcePathResolver(
            container_source_root=f"/var/www/html/wp-content/plugins/{plugin_slug}",
            host_source_root=source_root,
            source_root=source_root,
        )
        extractor = InputSignatureExtractor(source_resolver=resolver)
        for endpoint in probes:
            proof = next((correlate_artifact(endpoint, artifact, run_id, plugin_slug) for artifact in request_artifacts if correlate_artifact(endpoint, artifact, run_id, plugin_slug)), None)
            original = next(item for item in catalog if item["callback_id"] == endpoint["callback_id"])
            if proof is None:
                original["status"] = BLOCKED_NEEDS_RECIPE
                original["blocking_reason"] = "runtime_proof_missing"
                continue
            callback = callbacks.get(endpoint["callback_id"], {"callback_id": endpoint["callback_id"]})
            seed = build_parameter_seed(endpoint, callback, proof, extractor)
            seed_path = output_dir / "seeds" / f"{endpoint['callback_id']}.json"
            _write_json(seed_path, seed)
            original["seed_path"] = str(seed_path.relative_to(output_dir))
            config = _config_for(endpoint, seed, proof)
            if config is None:
                original["status"] = BLOCKED_NEEDS_RECIPE
                original["blocking_reason"] = "no_fuzzable_parameter"
                continue
            original["status"] = PASS
            config_path = output_dir / "configs" / f"{endpoint['callback_id']}.json"
            _write_json(config_path, config)
            original["config_path"] = str(config_path.relative_to(output_dir))
            replay = {"callback_id": endpoint["callback_id"], "request_id": proof["request_id"], "status": PASS, "config": config_path.name}
            replays.append(replay)
            generated.append({
                "config_slug": f"../output/zend-discovery/{run_id}/configs/{endpoint['callback_id']}",
                "config_path": str(config_path),
                "hook_name": endpoint["hook_name"],
                "callback_id": endpoint["callback_id"],
                "entrypoint_type": endpoint["kind"],
            })
            _write_json(output_dir / "replays" / f"{endpoint['callback_id']}.json", replay)
    stages = {"integrity": integrity, "catalog": PASS, "recipe": recipe_status, "replay": PASS if replays else BLOCKED}
    summary = {"run_id": run_id, "plugin": plugin, "plugin_slug": plugin_slug, "stages": stages, "safe_endpoint_count": len(probes), "endpoints": catalog, "replays": replays}
    _write_json(output_dir / "endpoint-catalog.json", catalog)
    _write_json(output_dir / "generated_config_summary.json", {"generated": generated})
    _write_json(output_dir / "run-summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Zend discovery artifacts from correlated UOPZ request proof.")
    parser.add_argument("--plugin-zip", required=True, type=Path)
    parser.add_argument("--plugin-slug", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--request-artifact", action="append", default=[], type=Path)
    parser.add_argument("--output-root", default=Path(__file__).resolve().parents[1] / "output" / "zend-discovery", type=Path)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--write-probe-plan", type=Path)
    args = parser.parse_args(argv)
    registry = json.loads(args.registry.read_text(encoding="utf-8-sig"))
    artifacts = [json.loads(path.read_text(encoding="utf-8-sig")) for path in args.request_artifact]
    if args.write_probe_plan:
        _write_json(args.write_probe_plan, build_probe_plan(registry, args.plugin_slug))
        return 0
    try:
        summary = run_discovery(args.plugin_zip, args.plugin_slug, args.run_id, registry, artifacts, args.output_root, args.recipe)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(summary["stages"], sort_keys=True))
    return 0 if summary["stages"]["replay"] == PASS or summary["safe_endpoint_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
