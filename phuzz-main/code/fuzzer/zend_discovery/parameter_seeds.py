from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


FORBIDDEN_PARAMETER_NAME = re.compile(
    r"(?:nonce|cookie|secret|password|token|authorization)", re.IGNORECASE
)
SAFE_METHODS = {"GET", "HEAD", "POST"}
ENRICHED_LOCATIONS = {"query", "form", "json"}


def build_enriched_parameters(
    candidate: Mapping[str, Any],
    callback: Mapping[str, Any],
    artifact: Mapping[str, Any],
    extractor: Any,
    *,
    valid_pass1_proof: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return value-free parameter provenance for a correlated Pass 1 request."""
    method = str(candidate.get("resolved_method") or candidate.get("method") or artifact.get("http_method") or "").upper()
    rows: dict[str, dict[str, Any]] = {}

    def add(
        name: Any,
        *,
        locations: set[str] | None = None,
        evidence: dict[str, Any],
        observed_value: Any = _MISSING,
        forced_block: str | None = None,
    ) -> None:
        name = str(name or "")
        if not name:
            return
        row = rows.setdefault(
            name,
            {
                "name": name,
                "_locations": set(),
                "evidence": [],
                "_observed_value": _MISSING,
                "_forced_block": None,
            },
        )
        if locations:
            row["_locations"].update(locations)
        if evidence not in row["evidence"]:
            row["evidence"].append(evidence)
        if observed_value is not _MISSING:
            row["_observed_value"] = observed_value
        if forced_block and row["_forced_block"] is None:
            row["_forced_block"] = forced_block

    extracted = extractor.extract(dict(callback))
    static_params = extracted.get("input_params", []) if isinstance(extracted, Mapping) else []
    for item in static_params if isinstance(static_params, list) else []:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name")
        source = str(item.get("source") or "").upper()
        if source in {"GET", "POST", "REQUEST", "COOKIE"}:
            direct_location = {"GET": "query", "POST": "form"}.get(source)
            locations = {direct_location} if direct_location and method == source else set()
            add(
                name,
                locations=locations,
                evidence={"kind": "zend_superglobal_read", "superglobal": f"$_{source}"},
                forced_block="security_field" if source == "COOKIE" else None,
            )
        elif source in {"REST_GET_PARAM", "GET_PARAM", "WP_REST_REQUEST_GET_PARAM"}:
            add(name, evidence={"kind": "rest_get_param_name_only"})
        elif source in {"HEADER", "HEADERS", "SELECTOR"}:
            add(name, evidence={"kind": "static_candidate"}, forced_block="auth_material")
        else:
            add(name, evidence={"kind": "static_candidate"})

    definitions = callback.get("argument_definitions", {})
    if isinstance(definitions, Mapping):
        for name in definitions:
            add(name, evidence={"kind": "rest_schema_declared"})

    bootstrap = candidate.get("fixed_bootstrap", {})
    if isinstance(bootstrap, Mapping):
        for name in bootstrap:
            add(name, evidence={"kind": "fixed_bootstrap"}, forced_block="fixed_bootstrap")

    for key, location, evidence_kind in (
        ("query_params", "query", "runtime_query_observed"),
        ("form_params", "form", "runtime_form_body_observed"),
        ("json_params", "json", "runtime_json_observed"),
    ):
        values = artifact.get("request_params", {})
        values = values.get(key, {}) if isinstance(values, Mapping) else {}
        if isinstance(values, Mapping):
            for name, value in values.items():
                add(name, locations={location}, evidence={"kind": evidence_kind}, observed_value=value)
    request_params = artifact.get("request_params", {})
    body_values = request_params.get("body_params", {}) if isinstance(request_params, Mapping) else {}
    if isinstance(body_values, Mapping):
        content_type = str(artifact.get("content_type") or artifact.get("request_content_type") or "").lower()
        if "json" in content_type:
            location, evidence_kind = "json", "runtime_json_observed"
        elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            location, evidence_kind = "form", "runtime_form_body_observed"
        else:
            location, evidence_kind = None, "runtime_form_body_observed"
        for name, value in body_values.items():
            add(name, locations={location} if location else set(), evidence={"kind": evidence_kind}, observed_value=value)

    parameters: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for row in rows.values():
        locations = row.pop("_locations")
        observed_value = row.pop("_observed_value")
        forced_block = row.pop("_forced_block")
        if _blocked_name(row["name"]):
            reason = "security_field"
        elif forced_block:
            reason = forced_block
        elif not valid_pass1_proof:
            reason = "pass1_proof_missing"
        elif len(locations) == 1:
            reason = None
        else:
            reason = "unresolved_location"
        location = next(iter(locations)) if len(locations) == 1 else "unknown"
        item: dict[str, Any] = {
            "name": row["name"],
            "location": location,
            "location_confidence": "runtime" if observed_value is not _MISSING and location != "unknown" else ("direct" if reason is None else "unresolved"),
            "evidence": row["evidence"],
            "blocked": reason is not None,
            "blocked_reason": reason,
            "fuzzable": bool(valid_pass1_proof and reason is None and location in ENRICHED_LOCATIONS),
            "redacted_value_metadata": {"observed": observed_value is not _MISSING, "redacted": observed_value is not _MISSING},
        }
        if observed_value is not _MISSING:
            item["safe_observed_type"] = _safe_observed_type(observed_value)
        parameters.append(item)
        if item["blocked"]:
            blocked.append(item)
    return parameters, blocked


_MISSING = object()


def _safe_observed_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    return "string"


def build_parameter_seed(
    endpoint: Mapping[str, Any],
    callback: Mapping[str, Any],
    artifact: Mapping[str, Any],
    extractor: Any,
) -> dict[str, Any]:
    extracted = extractor.extract(dict(callback))
    static_params = extracted.get("input_params", []) if isinstance(extracted, Mapping) else []
    method = _resolve_method(endpoint, artifact, static_params)
    observations = _observed_locations(artifact)
    parameters: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    index: dict[tuple[str, str], dict[str, Any]] = {}

    def add(name: str, location: str, evidence: str, *, fuzzable: bool = True) -> None:
        if not name or name == "action":
            return
        if _blocked_name(name):
            _block(blocked, name, "security_field", evidence)
            return
        if location == "cookie":
            _block(blocked, name, "cookie_field", evidence)
            return
        if location == "body_or_query":
            locations = observations.get(name, set())
            if len(locations) != 1:
                _block(blocked, name, "unresolved_location", evidence)
                return
            location = next(iter(locations))
        if method not in SAFE_METHODS:
            _block(blocked, name, "unsafe_method", evidence)
            return
        if endpoint.get("kind") == "rest" and method in {"GET", "HEAD"} and location != "query":
            _block(blocked, name, "method_location_conflict", evidence)
            return
        key = (name, location)
        existing = index.get(key)
        if existing is None:
            existing = {"name": name, "location": location, "fuzzable": fuzzable, "evidence": [evidence]}
            index[key] = existing
            parameters.append(existing)
        elif evidence not in existing["evidence"]:
            existing["evidence"].append(evidence)

    for item in static_params:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "")
        source = str(item.get("source") or "").upper()
        location = str(item.get("location") or _location_for_source(source))
        if item.get("role") == "security_nonce" or item.get("fuzzable") is False:
            _block(blocked, name, "security_field", f"static:{source or 'unknown'}")
            continue
        add(name, location, f"static:{source or 'unknown'}")

    for name, definition in _argument_definitions(callback).items():
        if _blocked_name(name):
            _block(blocked, name, "security_field", "rest_schema")
        elif method in {"GET", "HEAD"}:
            add(name, "query", "rest_schema")
        else:
            _block(blocked, name, "unresolved_location", "rest_schema")

    for name, locations in observations.items():
        for location in sorted(locations):
            add(name, location, f"runtime:{location}")

    return {
        "callback_id": str(endpoint.get("callback_id") or callback.get("callback_id") or ""),
        "method": method,
        "parameters": parameters,
        "blocked_parameters": blocked,
    }


def _resolve_method(endpoint: Mapping[str, Any], artifact: Mapping[str, Any], static_params: Any) -> str:
    declared = endpoint.get("method")
    if declared:
        return str(declared).upper()
    methods = endpoint.get("methods")
    if isinstance(methods, list) and methods:
        return str(methods[0]).upper()
    observed = artifact.get("http_method")
    if observed:
        return str(observed).upper()
    for item in static_params if isinstance(static_params, list) else []:
        if isinstance(item, Mapping) and str(item.get("source") or "").upper() == "POST":
            return "POST"
    return "GET"


def _argument_definitions(callback: Mapping[str, Any]) -> Mapping[str, Any]:
    definitions = callback.get("argument_definitions", {})
    return definitions if isinstance(definitions, Mapping) else {}


def _observed_locations(artifact: Mapping[str, Any]) -> dict[str, set[str]]:
    request_params = artifact.get("request_params", {})
    if not isinstance(request_params, Mapping):
        return {}
    observations: dict[str, set[str]] = {}
    for key, location in (("query_params", "query"), ("body_params", "body")):
        values = request_params.get(key, {})
        if isinstance(values, Mapping):
            for name in values:
                observations.setdefault(str(name), set()).add(location)
    cookies = request_params.get("cookies", [])
    if isinstance(cookies, Mapping):
        cookies = cookies.keys()
    if isinstance(cookies, list) or hasattr(cookies, "__iter__"):
        for name in cookies:
            observations.setdefault(str(name), set()).add("cookie")
    return observations


def _location_for_source(source: str) -> str:
    return {"GET": "query", "POST": "body", "REQUEST": "body_or_query", "COOKIE": "cookie"}.get(source, "body_or_query")


def _blocked_name(name: str) -> bool:
    return bool(FORBIDDEN_PARAMETER_NAME.search(name))


def _block(blocked: list[dict[str, Any]], name: str, reason: str, evidence: str) -> None:
    if not name or any(row["name"] == name for row in blocked):
        return
    blocked.append({"name": name, "reason": reason, "evidence": [evidence]})
