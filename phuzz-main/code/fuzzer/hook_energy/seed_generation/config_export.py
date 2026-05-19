from __future__ import annotations

import re
from typing import Any

try:
    from .models import ImportedSeedRequest, ImportedSeedResult
except ImportError:
    from models import ImportedSeedRequest, ImportedSeedResult


PARAM_GROUPS = ("headers", "cookies", "query_params", "body_params")


def build_fast_seed_config(
    result: ImportedSeedResult,
    *,
    source_config: dict[str, Any],
    target_base: str = "http://web",
    seed_limit: int = 5,
) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    if result.authenticated_queue:
        warnings.append(
            f"Skipped {len(result.authenticated_queue)} authenticated seed(s); HOOK_FAST v1 does not run login flows."
        )

    seed_requests = [
        _seed_to_request(seed, source_config=source_config, target_base=target_base)
        for seed in result.unauthenticated_queue[: max(0, int(seed_limit))]
    ]

    if not seed_requests:
        warnings.append("No unauthenticated hook seeds were available; fast config falls back to the source PHUZZ config.")
        return dict(source_config), warnings

    fast_config = {
        "schema_version": "hook-fast-seed-config-v1",
        "print_timestamps": bool(source_config.get("print_timestamps", False)),
        "target_base": target_base.rstrip("/"),
        "seed_requests": seed_requests,
    }
    if "request_timeout" in source_config:
        fast_config["request_timeout"] = source_config["request_timeout"]
    return fast_config, warnings


def _seed_to_request(
    seed: ImportedSeedRequest,
    *,
    source_config: dict[str, Any],
    target_base: str,
) -> dict[str, Any]:
    fixed_params = {
        "headers": dict(seed.headers),
        "cookies": dict(seed.cookies),
        "query_params": dict(seed.query_params),
        "body_params": dict(seed.body),
    }
    if seed.content_type:
        fixed_params["headers"].setdefault("Content-Type", seed.content_type)

    fuzz_params, fuzz_weights = _extract_source_fuzz_params(source_config, fixed_params)
    if not any(fuzz_params[group] for group in PARAM_GROUPS):
        fuzz_params["body_params"]["hookphuzz_seed"] = "fuzz"
        fuzz_weights["body_params"] = 1

    return {
        "request_id": seed.request_id,
        "source": seed.source,
        "target": target_base.rstrip("/") + "/" + seed.path.lstrip("/"),
        "http_method": seed.http_method.upper(),
        "fixed_params": fixed_params,
        "fuzz_params": fuzz_params,
        "fuzz_weights": fuzz_weights,
        "metadata": seed.metadata,
    }


def _extract_source_fuzz_params(
    source_config: dict[str, Any],
    fixed_params: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, float]]:
    fuzz_params: dict[str, dict[str, Any]] = {group: {} for group in PARAM_GROUPS}
    fuzz_weights: dict[str, float] = {group: 0.25 for group in PARAM_GROUPS}

    for group in PARAM_GROUPS:
        group_config = source_config.get(group, {})
        if not isinstance(group_config, dict):
            continue
        if "weight" in group_config:
            fuzz_weights[group] = float(group_config["weight"])

        data = group_config.get("data", [])
        if not isinstance(data, list):
            continue

        fuzz_patterns = group_config.get("fuzz", [])
        if not fuzz_patterns:
            fuzz_patterns = [".*"]

        compiled_patterns = [re.compile(str(pattern)) for pattern in fuzz_patterns]
        fixed_names = set(fixed_params.get(group, {}).keys())
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name or name in fixed_names:
                continue
            if not any(pattern.match(name) for pattern in compiled_patterns):
                continue
            if "value" in item:
                fuzz_params[group][name] = item["value"]
            elif isinstance(item.get("seeds"), list) and item["seeds"]:
                fuzz_params[group][name] = item["seeds"][0]

    return fuzz_params, fuzz_weights
