from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


VALID_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
AMBIGUOUS_HTTP_METHODS = ["GET", "POST"]

_REST_CONSTANTS = {
    "WP_REST_SERVER::READABLE": ["GET"],
    "WP_REST_SERVER::CREATABLE": ["POST"],
    "WP_REST_SERVER::EDITABLE": ["POST", "PUT", "PATCH"],
    "WP_REST_SERVER::DELETABLE": ["DELETE"],
    "WP_REST_SERVER::ALLMETHODS": ["GET", "POST", "PUT", "PATCH", "DELETE"],
}


def resolve_http_methods(
    *,
    input_params: Sequence[Mapping[str, Any]] = (),
    route_declared_methods: Any = None,
    runtime_observation: Mapping[str, Any] | None = None,
    expected_callback: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return one deterministic decision per runnable method, or one ambiguous decision."""
    route_methods = normalize_http_methods(route_declared_methods)
    observed = correlated_runtime_observation(runtime_observation, expected_callback)
    observed_method = observed["method"] if observed else None
    sources = sorted(
        {
            str(item.get("source", "")).strip().upper()
            for item in input_params
            if isinstance(item, Mapping) and str(item.get("source", "")).strip()
        }
    )

    if route_methods:
        evidence = {"route_declared_methods": route_methods}
        return [
            _resolved_decision(
                method,
                candidates=route_methods,
                confidence="route_declared",
                evidence=evidence,
                observed_method=observed_method,
                route_methods=route_methods,
            )
            for method in route_methods
        ]

    exact_methods = [method for method in ("GET", "POST") if method in sources]
    if exact_methods:
        evidence = {"parameter_sources": sources, "source_exact_methods": exact_methods}
        return [
            _resolved_decision(
                method,
                candidates=exact_methods,
                confidence="source_exact",
                evidence=evidence,
                observed_method=observed_method,
                route_methods=[],
            )
            for method in exact_methods
        ]

    if observed:
        evidence = {
            "parameter_sources": sources,
            "request_id": observed["request_id"],
            "callback_id": observed["callback_id"],
            "hook_name": observed["hook_name"],
            "target_plugin": observed["target_plugin"],
        }
        return [
            _resolved_decision(
                observed["method"],
                candidates=[observed["method"]],
                confidence="runtime_observed",
                evidence=evidence,
                observed_method=observed["method"],
                route_methods=[],
            )
        ]

    return [
        {
            "method": None,
            "resolved_method": None,
            "candidate_methods": list(AMBIGUOUS_HTTP_METHODS),
            "method_status": "ambiguous",
            "method_source": "ambiguous",
            "method_confidence": "ambiguous",
            "method_evidence": {
                "parameter_sources": sources,
                "reason": "no_correlated_runtime_or_declared_or_source_exact_method",
            },
            "observed_request_method": observed_method,
            "route_declared_methods": [],
            "seed_variant_id": "ambiguous",
        }
    ]


def normalize_http_methods(value: Any) -> list[str]:
    methods: list[str] = []

    def add(raw: Any) -> None:
        if isinstance(raw, Mapping):
            nested = raw.get("methods", raw.get("method"))
            if nested is not None:
                add(nested)
            else:
                for method, enabled in raw.items():
                    if enabled:
                        add(method)
            return
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            for item in raw:
                add(item)
            return
        for part in str(raw or "").replace("|", ",").split(","):
            token = part.strip().upper().lstrip("\\")
            expanded = _REST_CONSTANTS.get(token, [token])
            for method in expanded:
                if method in VALID_HTTP_METHODS and method not in methods:
                    methods.append(method)

    add(value)
    return methods


def correlated_runtime_observation(
    observation: Mapping[str, Any] | None,
    expected_callback: Mapping[str, Any] | None,
) -> dict[str, str] | None:
    if not isinstance(observation, Mapping) or not isinstance(expected_callback, Mapping):
        return None

    aliases = {
        "callback_id": ("callback_id",),
        "hook_name": ("hook_name", "fired_hook"),
        "callback_repr": ("callback_repr", "callback", "callback_name"),
    }
    normalized: dict[str, str] = {}
    for field, keys in aliases.items():
        expected = _first_string(expected_callback, keys)
        actual = _first_string(observation, keys)
        if not expected or not actual or expected != actual:
            return None
        normalized[field] = actual

    request_id = _first_string(observation, ("request_id",))
    method = _first_string(observation, ("observed_request_method", "observed_method", "http_method", "method")).upper()
    target_plugin = _first_string(observation, ("target_plugin", "plugin"))
    if not request_id or method not in VALID_HTTP_METHODS or not target_plugin:
        return None
    expected_request_id = _first_string(expected_callback, ("request_id",))
    expected_plugin = _first_string(expected_callback, ("target_plugin", "plugin"))
    if expected_request_id and expected_request_id != request_id:
        return None
    if expected_plugin and expected_plugin != target_plugin:
        return None
    return {
        **normalized,
        "request_id": request_id,
        "method": method,
        "target_plugin": target_plugin,
    }


def _resolved_decision(
    method: str,
    *,
    candidates: list[str],
    confidence: str,
    evidence: Mapping[str, Any],
    observed_method: str | None,
    route_methods: list[str],
) -> dict[str, Any]:
    return {
        "method": method,
        "resolved_method": method,
        "candidate_methods": list(candidates),
        "method_status": "resolved",
        "method_source": confidence,
        "method_confidence": confidence,
        "method_evidence": dict(evidence),
        "observed_request_method": observed_method,
        "route_declared_methods": list(route_methods),
        "seed_variant_id": method.lower(),
    }


def _first_string(value: Mapping[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        item = str(value.get(key, "")).strip()
        if item:
            return item
    return ""
