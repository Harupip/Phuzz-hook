from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class SeedConfigSkip(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def build_config_for_seed_item(
    seed_item: Mapping[str, Any],
    *,
    target_base: str = "http://web",
) -> tuple[str, dict[str, Any]]:
    seed = seed_item.get("seed")
    if not isinstance(seed, Mapping):
        raise SeedConfigSkip("missing_seed")

    auth_mode = str(seed.get("auth_mode", "")).strip()
    if auth_mode not in {"authenticated", "unauth-capable"}:
        raise SeedConfigSkip("unsupported_auth_mode")

    method = str(seed.get("method", "")).strip().upper()
    path = str(seed.get("path", "")).strip()
    body = seed.get("body")
    if not method or not path or not isinstance(body, Mapping):
        raise SeedConfigSkip("malformed_seed")

    config: dict[str, Any] = {
        "target": _join_target(target_base, path),
        "methods": [method],
        "print_timestamps": True,
    }

    fixed_params = _string_set(seed.get("fixed_params", []))
    fuzzable_params = _string_set(seed.get("fuzzable_params", []))

    sections = (
        ("body", "body_params"),
        ("query_params", "query_params"),
        ("headers", "headers"),
        ("cookies", "cookies"),
    )
    for seed_key, config_key in sections:
        values = seed.get(seed_key, {})
        if not isinstance(values, Mapping) or not values:
            continue

        config[config_key] = _build_param_section(
            values,
            fixed_params=fixed_params,
            fuzzable_params=fuzzable_params,
        )

    return _build_file_slug(seed_item), config


def export_seed_configs(
    seed_report: Mapping[str, Any],
    *,
    output_config_dir: str | Path,
    summary_path: str | Path | None = None,
    target_base: str = "http://web",
) -> dict[str, list[dict[str, str]]]:
    output_dir = Path(output_config_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, list[dict[str, str]]] = {"generated": [], "skipped": []}
    suggestions = seed_report.get("suggested_seeds", [])
    if not isinstance(suggestions, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")

    for item in suggestions:
        if not isinstance(item, Mapping):
            summary["skipped"].append({"hook_name": "", "callback_id": "", "reason": "malformed_item"})
            continue

        hook_name = str(item.get("hook_name", ""))
        callback_id = str(item.get("callback_id", ""))
        try:
            file_slug, config = build_config_for_seed_item(item, target_base=target_base)
        except SeedConfigSkip as exc:
            summary["skipped"].append(
                {"hook_name": hook_name, "callback_id": callback_id, "reason": exc.reason}
            )
            continue

        config_path = output_dir / f"{file_slug}.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        summary["generated"].append(
            {
                "config_slug": _build_config_slug(output_dir, file_slug),
                "hook_name": hook_name,
                "callback_id": callback_id,
            }
        )

    if summary_path is not None:
        Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
        Path(summary_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return summary


def _build_param_section(
    values: Mapping[str, Any],
    *,
    fixed_params: set[str],
    fuzzable_params: set[str],
) -> dict[str, Any]:
    fixed: list[str] = []
    fuzz: list[str] = []
    data: list[dict[str, str]] = []

    for name, value in values.items():
        param_name = str(name)
        data.append({"name": param_name, "value": str(value)})
        if param_name in fuzzable_params and param_name not in fixed_params:
            fuzz.append(param_name)
        else:
            fixed.append(param_name)

    return {"data": data, "fixed": fixed, "fuzz": fuzz, "weight": 1}


def _build_file_slug(seed_item: Mapping[str, Any]) -> str:
    hook_name = str(seed_item.get("hook_name", "hook")).strip() or "hook"
    callback_id = str(seed_item.get("callback_id", "callback")).strip() or "callback"
    return f"{_safe_slug(hook_name)}-{_safe_slug(callback_id)}"


def _build_config_slug(output_dir: Path, file_slug: str) -> str:
    parts = list(output_dir.parts)
    lowered = [part.lower() for part in parts]
    if "configs" in lowered:
        configs_index = len(lowered) - 1 - lowered[::-1].index("configs")
        slug_parts = parts[configs_index + 1 :] + [file_slug]
        return "/".join(slug_parts)
    return file_slug


def _join_target(target_base: str, path: str) -> str:
    return target_base.rstrip("/") + "/" + path.lstrip("/")


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return slug.strip("._-") or "item"


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value if str(item)}
