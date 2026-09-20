"""Configuration selection and artifact helpers shared by both online modes."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from hook_energy.seed_generation.generated_config_runner import ZEND_ARTIFACTS_DIR
from seed_generation.config.config_exporter import SeedConfigSkip, build_config_for_seed_item

SUPPORTED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def validate_v0_config(
    config: Mapping[str, Any],
    *,
    require_fuzzing_ready: bool = True,
) -> tuple[bool, str]:
    """Validate the v0 shape, optionally requiring fuzz-ready parameters."""

    if not isinstance(config, Mapping):
        return False, "CONFIG_NOT_OBJECT"
    target = str(config.get("target") or "").strip()
    if not target.startswith(("http://", "https://")):
        return False, "MISSING_TARGET"
    methods = config.get("methods")
    if not isinstance(methods, list) or not methods:
        return False, "MISSING_METHOD"
    normalized_methods = {str(method).strip().upper() for method in methods if str(method).strip()}
    metadata = config.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    resolved_method = str(metadata.get("resolved_method") or "").strip().upper()
    if not resolved_method:
        if len(normalized_methods) == 1:
            resolved_method = next(iter(normalized_methods))
        else:
            return False, "MISSING_RESOLVED_METHOD"
    if resolved_method not in SUPPORTED_METHODS or resolved_method not in normalized_methods:
        return False, "INVALID_RESOLVED_METHOD"
    if not str(metadata.get("callback_repr") or metadata.get("callback_id") or "").strip():
        return False, "MISSING_CALLBACK"
    if require_fuzzing_ready and (
        str(config.get("config_type") or "").strip().lower() == "replay_only"
        or not _has_fuzzable_parameter(config)
    ):
        return False, "NOT_FUZZING_READY"
    return True, ""


def config_hash(config: Mapping[str, Any]) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _seed_matches_target(item: Mapping[str, Any], config: Mapping[str, Any]) -> bool:
    seed = item.get("seed")
    if not isinstance(seed, Mapping):
        return False
    seed_path = str(seed.get("path") or "").strip()
    target = str(config.get("target") or "").strip()
    if not seed_path or not target:
        return False
    parsed = urlsplit(target)
    target_paths = {parsed.path.rstrip("/") or "/"}
    rest_route = parse_qs(parsed.query).get("rest_route", [""])[0]
    if rest_route:
        target_paths.add(str(rest_route).rstrip("/") or "/")
    normalized_seed = seed_path.rstrip("/") or "/"
    if normalized_seed.startswith("/wp-json/"):
        normalized_seed = normalized_seed[len("/wp-json"):]
    return normalized_seed in target_paths


def _has_fuzzable_parameter(config: Mapping[str, Any]) -> bool:
    for placement in ("query_params", "body_params", "cookies"):
        section = config.get(placement)
        if isinstance(section, Mapping) and isinstance(section.get("fuzz"), list) and section["fuzz"]:
            return True
    return False


def _load_zend_artifact(name: str) -> Any:
    if Path(name).name != name:
        raise ValueError(f"Invalid Zend artifact name: {name}")
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "cat", f"{ZEND_ARTIFACTS_DIR}/{name}"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Could not read Zend artifact: {name}")
    return json.loads(result.stdout)


def _write_exclusive_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _decorate_config(config: dict[str, Any], item: Mapping[str, Any]) -> None:
    metadata = config.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
        config["metadata"] = metadata
    seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
    metadata.setdefault("callback_id", str(item.get("callback_id") or ""))
    metadata.setdefault("callback_repr", str(item.get("callback_repr") or item.get("callback_name") or ""))
    metadata.setdefault("hook_name", str(item.get("hook_name") or ""))
    metadata.setdefault("resolved_method", str(seed.get("resolved_method") or seed.get("method") or ""))


def select_v0(
    suggested_seeds: Path,
    bootstrap_config: Path | None = None,
    *,
    build_config_fn: Callable[..., Any] = build_config_for_seed_item,
) -> tuple[Mapping[str, Any], dict[str, Any]] | None:
    payload = json.loads(suggested_seeds.read_text(encoding="utf-8-sig"))
    suggestions = payload.get("suggested_seeds") if isinstance(payload, Mapping) else None
    if not isinstance(suggestions, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
    for item in suggestions:
        if not isinstance(item, Mapping):
            continue
        try:
            _, config = build_config_fn(item, target_base="http://web", rest_route_fallback=True)
        except SeedConfigSkip:
            continue
        _decorate_config(config, item)
        if _has_fuzzable_parameter(config) and str(config.get("config_type") or "").lower() == "replay_only":
            config["config_type"] = "fuzzing_ready"
        valid, _ = validate_v0_config(config)
        if valid:
            return item, config
    if bootstrap_config and bootstrap_config.exists():
        bootstrap = json.loads(bootstrap_config.read_text(encoding="utf-8-sig"))
        if isinstance(bootstrap, Mapping):
            for item in suggestions:
                if not isinstance(item, Mapping) or not _seed_matches_target(item, bootstrap):
                    continue
                config = copy.deepcopy(dict(bootstrap))
                _decorate_config(config, item)
                if not str(config.get("config_type") or "").strip():
                    config["config_type"] = "fuzzing_ready"
                valid, _ = validate_v0_config(config)
                if valid:
                    return item, config
    return None
