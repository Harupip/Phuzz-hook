"""Canonical identity and request context for online-linked candidates."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from seed_generation.config.config_exporter import _fuzzable_params_for_section, _string_set

_CANDIDATE_CONTEXT_KEY_VERSION = 1


def _canonical_callback_name(value: Any) -> str:
    return re.sub(r"\s*(?:->|::)\s*", "::", str(value or "").strip())


def _candidate_slug(item: Mapping[str, Any], index: int) -> str:
    raw = str(item.get("hook_name") or item.get("callback_id") or "candidate")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-.") or "candidate"
    return f"{index:03d}-{slug}"


def _normalize_identity_route(value: Any) -> str:
    route = str(value or "").strip().replace("\\", "/")
    if not route:
        return ""
    route = "/" + route.lstrip("/")
    return route if route == "/" else route.rstrip("/")


def _candidate_identity(item: Mapping[str, Any], plugin_slug: str) -> str:
    """Build the sole online-linked identity from normalized candidate fields."""
    seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
    route = next((
        _normalize_identity_route(value)
        for value in (
            item.get("route"),
            item.get("rest_route"),
            seed.get("route"),
            seed.get("rest_route"),
            seed.get("materialized_route"),
            seed.get("path"),
        )
        if _normalize_identity_route(value)
    ), "")
    hook_name = str(item.get("hook_name") or "")
    entrypoint_type = str(seed.get("entrypoint_type") or item.get("entrypoint_type") or "")
    if not entrypoint_type:
        if hook_name.startswith("wp_ajax_nopriv_"):
            entrypoint_type = "ajax_unauthenticated"
        elif hook_name.startswith("wp_ajax_"):
            entrypoint_type = "ajax_authenticated"
        elif hook_name.startswith("admin_post_nopriv_"):
            entrypoint_type = "admin_post_unauthenticated"
        elif hook_name.startswith("admin_post_"):
            entrypoint_type = "admin_post_authenticated"
        elif hook_name.startswith("rest_route:"):
            entrypoint_type = "rest_route"
        elif hook_name in {"heartbeat_received", "heartbeat_nopriv_received"}:
            entrypoint_type = "heartbeat"
    method = str(
        seed.get("resolved_method")
        or seed.get("method")
        or item.get("resolved_method")
        or item.get("method")
        or ""
    ).upper()
    variant = str(seed.get("seed_variant_id") or item.get("seed_variant_id") or "")
    if not variant and method:
        variant = method.lower()
    return "|".join((
        plugin_slug,
        str(item.get("callback_id") or ""),
        entrypoint_type,
        hook_name,
        route,
        method,
        variant,
    ))


def _batch_candidate_identity(item: Mapping[str, Any], plugin_slug: str) -> str:
    return _candidate_identity(item, plugin_slug)


def _candidate_context_key(item: Mapping[str, Any], plugin_slug: str) -> str:
    """Fingerprint a request context without provenance or fuzzable values."""
    seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
    fixed = _string_set(seed.get("fixed_params", []))
    fuzzable = _string_set(seed.get("fuzzable_params", []))
    roles = [{"name": name, "role": "fixed"} for name in sorted(fixed)]
    roles.extend({"name": name, "role": "fuzzable"}
                 for name in sorted(fuzzable - fixed))
    scoped_normalized = {
        bucket: {
            name for name in _fuzzable_params_for_section(seed, fuzzable, config_key)
            if name not in fixed and "nonce" not in name.lower()
        }
        for bucket, config_key in (
            ("body", "body_params"), ("query_params", "query_params"),
            ("headers", "headers"), ("cookies", "cookies"),
        )
    }
    credential_normalized: dict[str, set[str]] = {}
    input_roles = {}
    input_params = seed.get("input_params", [])
    for parameter in input_params if isinstance(input_params, list) else []:
        if not isinstance(parameter, Mapping) or not parameter.get("name"):
            continue
        name = str(parameter["name"])
        source = str(parameter.get("source") or "").upper()
        location = str(parameter.get("location") or "").lower()
        role = str(parameter.get("role") or "")
        is_credential = any(token in role.lower() for token in ("nonce", "token"))
        role_row = {
            "name": name, "source": source, "location": location, "role": role,
            "fuzzable": parameter.get("fuzzable") if type(parameter.get("fuzzable")) is bool else None,
        }
        input_roles[json.dumps(role_row, sort_keys=True, separators=(",", ":"))] = role_row
        if not is_credential:
            continue
        bucket = (
            "query_params" if source == "GET" or location == "query" else
            "cookies" if source == "COOKIE" or location == "cookie" else
            "headers" if source in {"HEADER", "HEADERS"} or location == "header" else
            "json_params" if source in {"JSON", "JSON_BODY"} or location == "json" else
            "body" if source == "POST" or location in {"form", "body"} else None
        )
        if bucket is not None:
            credential_normalized.setdefault(bucket, set()).add(name)
    roles.extend(input_roles[key] for key in sorted(input_roles))

    def normalize(value: Any, bucket: str, *, top_level: bool = True) -> Any:
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                name = str(key)
                is_fuzzable = name in scoped_normalized.get(bucket, set())
                is_credential = name in credential_normalized.get(bucket, set())
                result[key] = ("<fuzzable>" if top_level and (is_fuzzable or is_credential)
                               else normalize(item, bucket, top_level=False))
            return result
        if isinstance(value, list):
            return [normalize(item, bucket, top_level=False) for item in value]
        return value

    descriptor = {
        "identity": _candidate_identity(item, plugin_slug),
        "path": seed.get("path"),
        "method": str(seed.get("resolved_method") or seed.get("method") or "").upper(),
        "content_type": seed.get("content_type"),
        "auth_mode": seed.get("auth_mode", item.get("auth_mode")),
        "request_buckets": {
            bucket: normalize(seed.get(bucket, {}), bucket)
            for bucket in ("query_params", "body", "json_params", "headers", "cookies")
        },
        "fixed_params": sorted(fixed),
        "fuzzable_params": sorted(fuzzable),
        "field_roles": roles,
    }
    encoded = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
