from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


GENERATED_BY = "hookphuzz_bootstrap_entry_discovery"


def build_config_for_candidate(candidate: Mapping[str, Any], *, target_base: str) -> tuple[str, dict[str, Any]]:
    if candidate.get("classification") != "direct_http":
        raise ValueError("candidate classification must be direct_http")

    http_template = candidate.get("http_template")
    if not isinstance(http_template, Mapping):
        raise ValueError("direct_http candidate must contain http_template")

    method = str(http_template.get("method", "")).strip().upper()
    path = str(http_template.get("path", "")).strip()
    if not method or not path:
        raise ValueError("http_template method and path are required")

    config: dict[str, Any] = {
        "target": _join_target(target_base, path),
        "methods": [method],
        "print_timestamps": True,
    }

    fuzz_count = 0
    for source_key, config_key in (
        ("headers", "headers"),
        ("query_params", "query_params"),
        ("body_params", "body_params"),
        ("cookies", "cookies"),
    ):
        values = _mapping_to_strings(http_template.get(source_key, {}))
        if not values:
            continue
        section, section_fuzz_count = _build_param_section(values, allow_fuzz=config_key in {"query_params", "body_params"})
        config[config_key] = section
        fuzz_count += section_fuzz_count

    if fuzz_count == 0:
        placeholder_section = "body_params" if method == "POST" else "query_params"
        values = _section_values(config.get(placeholder_section, {}))
        values["hookphuzz_probe"] = "fuzz"
        config[placeholder_section], _ = _build_param_section(values, allow_fuzz=True)

    config["metadata"] = {
        "candidate_id": _optional_string(candidate.get("candidate_id")),
        "hook_name": _optional_string(candidate.get("hook_name")),
        "callback_id": _optional_string(candidate.get("callback_id")),
        "callback_repr": _optional_string(candidate.get("callback_repr")),
        "entry_type": _optional_string(candidate.get("entry_type")),
        "generated_by": GENERATED_BY,
    }

    return _safe_slug(_optional_string(candidate.get("candidate_id")) or _optional_string(candidate.get("callback_id")) or "candidate"), config


def write_candidate_configs(
    direct_http_candidates_file: str | Path,
    *,
    output_dir: str | Path,
    target_base: str,
    pretty: bool = False,
) -> list[dict[str, Any]]:
    payload = json.loads(Path(direct_http_candidates_file).read_text(encoding="utf-8-sig"))
    candidates = payload.get("candidates", []) if isinstance(payload, Mapping) else []
    if not isinstance(candidates, list):
        candidates = []

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, Mapping) or candidate.get("classification") != "direct_http":
            continue
        slug, config = build_config_for_candidate(candidate, target_base=target_base)
        config_path = output_path / f"{slug}.json"
        config_path.write_text(
            json.dumps(config, indent=2 if pretty else None, ensure_ascii=False),
            encoding="utf-8",
        )
        written.append(
            {
                "candidate_id": _optional_string(candidate.get("candidate_id")) or slug,
                "hook_name": _optional_string(candidate.get("hook_name")),
                "entry_type": _optional_string(candidate.get("entry_type")),
                "path": config_path,
            }
        )
    return written


def _build_param_section(values: Mapping[str, str], *, allow_fuzz: bool) -> tuple[dict[str, Any], int]:
    data = [{"name": str(name), "value": str(value)} for name, value in values.items()]
    fixed: list[str] = []
    fuzz: list[str] = []
    for name in values:
        param_name = str(name)
        if allow_fuzz and param_name != "action":
            fuzz.append(param_name)
        else:
            fixed.append(param_name)
    return {"data": data, "fixed": fixed, "fuzz": fuzz, "weight": 1 if fuzz else 0}, len(fuzz)


def _section_values(section: Any) -> dict[str, str]:
    if not isinstance(section, Mapping):
        return {}
    values: dict[str, str] = {}
    data = section.get("data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, Mapping) and item.get("name") is not None:
                values[str(item["name"])] = str(item.get("value", ""))
    return values


def _mapping_to_strings(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _join_target(target_base: str, path: str) -> str:
    return target_base.rstrip("/") + "/" + path.lstrip("/")


def _optional_string(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return slug.strip("._-") or "candidate"
