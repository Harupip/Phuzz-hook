from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .engine import candidate_from_seed_item, canonical_identity, canonical_identity_id


_DIRECT_SOURCES = {"GET", "POST"}
_REST_SOURCES = {"REST_QUERY", "REST_FORM", "REST_JSON", "REST_URL"}
_SOURCE_LOCATIONS = {
    "GET": "query",
    "POST": "form",
    "REST_QUERY": "query",
    "REST_FORM": "form",
    "REST_JSON": "json",
    "REST_URL": "path",
}
_SEED_SOURCES = {
    "query": "GET",
    "form": "POST",
    "json": "JSON",
    "path": "URL",
}


def canonical_runtime_parameter_identity(parameter: Mapping[str, Any]) -> tuple[str, tuple[str, ...]] | None:
    """Return the Phase 2 identity for one direct Zend runtime parameter."""
    evidence_kind = str(parameter.get("evidence_kind") or "")
    source = str(parameter.get("source") or "").upper()
    path = parameter.get("path")
    if (
        not (
            evidence_kind == "zend_runtime" and source in _DIRECT_SOURCES
            or evidence_kind == "zend_rest_runtime" and source in _REST_SOURCES
        )
        or not isinstance(path, list)
        or len(path) != 1
        or not isinstance(path[0], str)
        or not path[0]
        or parameter.get("helper_depth") != 0
        or int(parameter.get("observed_count") or 0) < 1
    ):
        return None
    return source, (path[0],)


def advance_convergence_state(
    known_parameters: list[Mapping[str, Any]],
    observed_parameters: list[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Accumulate only distinct parameters proven by Zend runtime evidence."""
    known: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    for parameter in known_parameters:
        identity = canonical_runtime_parameter_identity(parameter)
        if identity is not None:
            known.setdefault(identity, dict(parameter))

    new: list[dict[str, Any]] = []
    for parameter in observed_parameters:
        identity = canonical_runtime_parameter_identity(parameter)
        if identity is None or identity in known:
            continue
        normalized = dict(parameter)
        known[identity] = normalized
        new.append(normalized)

    parent_identities = _nested_runtime_parent_identities(known)
    for identity in parent_identities:
        known.pop(identity, None)
    new = [
        parameter
        for parameter in new
        if canonical_runtime_parameter_identity(parameter) not in parent_identities
    ]

    return {
        "known_parameters": list(known.values()),
        "new_parameters": new,
    }


def _nested_runtime_parent_identities(
    parameters: Mapping[tuple[str, tuple[str, ...]], Mapping[str, Any]],
) -> set[tuple[str, tuple[str, ...]]]:
    identities = list(parameters)
    return {
        identity
        for identity in identities
        if any(
            other_source == identity[0]
            and other_path[0].startswith(f"{identity[1][0]}[")
            for other_source, other_path in identities
        )
    }


def _accepted_patch(row: Mapping[str, Any], candidate: Mapping[str, Any]) -> Mapping[str, Any] | None:
    patch = row.get("seed_patch")
    identity = canonical_identity(candidate)
    identity_id = canonical_identity_id(candidate)
    if not isinstance(patch, Mapping):
        return None
    if (
        row.get("accepted_pass1_proof") is not True
        or row.get("final_fuzz_export_allowed") is not True
        or row.get("canonical_identity_id") != identity_id
        or row.get("canonical_identity") != identity
        or row.get("method") != identity["resolved_method"]
        or row.get("auth_variant") != identity["auth_variant"]
        or row.get("entrypoint_type") != identity["entrypoint_type"]
        or patch.get("canonical_identity") != identity
        or patch.get("canonical_identity_id") != identity_id
        or patch.get("method") != identity["resolved_method"]
        or patch.get("auth_variant") != identity["auth_variant"]
        or patch.get("entrypoint_type") != identity["entrypoint_type"]
        or not str(patch.get("canonical_callback") or "")
    ):
        return None
    parameters = patch.get("fuzzable_parameters")
    names = row.get("fuzzable_params")
    if not isinstance(parameters, list) or not isinstance(names, list):
        return None
    if not parameters or {str(name) for name in names if str(name)} != {
        str(item.get("name")) for item in parameters
        if isinstance(item, Mapping) and str(item.get("name")) and str(item.get("location"))
    }:
        return None
    row_parameters = row.get("parameters")
    if not isinstance(row_parameters, list) or {
        (str(item.get("name")), str(item.get("location")))
        for item in row_parameters
        if isinstance(item, Mapping) and item.get("fuzzable") is True
    } != {
        (str(item.get("name")), str(item.get("location")))
        for item in parameters if isinstance(item, Mapping)
    }:
        return None
    gates = patch.get("gates")
    if not isinstance(gates, Mapping) or gates.get("accepted_pass1_proof") is not True or gates.get("final_fuzz_export_allowed") is not True:
        return None
    return patch


def _apply_patch(
    raw_item: Mapping[str, Any],
    patch: Mapping[str, Any],
    *,
    for_replay: bool = False,
) -> dict[str, Any]:
    item = deepcopy(dict(raw_item))
    seed = item.get("seed")
    if not isinstance(seed, dict):
        return item
    method = str(patch["method"])
    seed["method"] = method
    seed["resolved_method"] = method
    seed["method_status"] = "resolved"
    seed["method_confidence"] = "runtime_observed"
    seed["method_source"] = "runtime_observed"
    seed["method_evidence"] = {
        "evidence_kind": "runtime_request",
        "run_id": str(patch.get("run_id") or ""),
        "request_id": str(patch.get("request_id") or ""),
        "request_method": str(patch.get("request_method") or method),
    }
    seed["zend_canonical_callback"] = str(patch.get("canonical_callback") or "")
    seed["export_allowed"] = True
    seed["replay_allowed"] = True
    seed.pop("block_reason", None)
    if for_replay:
        return item
    fuzzable_parameters = _effective_fuzzable_parameters(seed, patch["fuzzable_parameters"])
    seed["fuzzable_params"] = []
    seed["input_params"] = []
    body = seed.setdefault("body", {})
    query = seed.setdefault("query_params", {})
    headers = seed.setdefault("headers", {})
    if not isinstance(body, dict) or not isinstance(query, dict) or not isinstance(headers, dict):
        return item
    fixed_params = {str(name) for name in seed.get("fixed_params", [])}
    for parameter in fuzzable_parameters:
        name = str(parameter["name"])
        location = str(parameter["location"])
        target = query if location == "query" else body if location in {"form", "json"} else None
        if target is not None:
            for existing_name in list(target):
                if existing_name not in fixed_params and name.startswith(f"{existing_name}["):
                    target.pop(existing_name, None)
        if location == "query":
            query[name] = "FUZZ"
        elif location in {"form", "json"}:
            body[name] = "FUZZ"
            if location == "json":
                headers["Content-Type"] = "application/json"
        elif location != "path":
            continue
        seed["fuzzable_params"].append(name)
        seed["input_params"].append(
            {
                "name": name,
                "path": [name],
                "source": _SEED_SOURCES[location],
                "location": location,
                "fuzzable": True,
                "evidence_kind": str(parameter.get("evidence_kind") or "zend_runtime"),
            }
        )
    return item


def _effective_fuzzable_parameters(
    seed: Mapping[str, Any],
    runtime_parameters: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    input_params = seed.get("input_params")
    static_params = input_params if isinstance(input_params, list) else []
    effective: list[dict[str, Any]] = []
    for parameter in runtime_parameters:
        if not isinstance(parameter, Mapping):
            continue
        name = str(parameter.get("name") or "")
        location = str(parameter.get("location") or "")
        children = [
            {
                "name": str(item.get("name")),
                "location": location,
                "evidence_kind": str(parameter.get("evidence_kind") or "zend_runtime"),
            }
            for item in static_params
            if isinstance(item, Mapping)
            and item.get("fuzzable") is not False
            and str(item.get("name") or "").startswith(f"{name}[")
            and _input_param_location(item, location) == location
        ]
        effective.extend(children or [dict(parameter)])
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for parameter in effective:
        deduped.setdefault((str(parameter.get("name") or ""), str(parameter.get("location") or "")), parameter)
    return list(deduped.values())


def _input_param_location(item: Mapping[str, Any], default: str) -> str:
    location = str(item.get("location") or "").lower()
    if location in {"query", "form", "json"}:
        return location
    source = str(item.get("source") or "").upper()
    if source == "GET":
        return "query"
    if source == "POST":
        return "form"
    return default


def materialize_convergence_seeds(
    raw_report: Mapping[str, Any],
    *,
    plugin_slug: str,
    candidate_key: str,
    known_parameters: list[Mapping[str, Any]],
    for_replay: bool = False,
) -> dict[str, Any]:
    """Materialize one candidate from direct Zend runtime observations only.

    Convergence replays keep the raw request values so branch-dependent reads
    remain reachable; final materialization applies the fuzz markers.
    """
    raw_items = raw_report.get("suggested_seeds", [])
    if not isinstance(raw_items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")

    runtime_parameters: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    callback = ""
    for parameter in known_parameters:
        identity = canonical_runtime_parameter_identity(parameter)
        if identity is None or identity in runtime_parameters:
            continue
        runtime_parameters[identity] = dict(parameter)
        callback = callback or str(parameter.get("canonical_callback") or "")
    for identity in _nested_runtime_parent_identities(runtime_parameters):
        runtime_parameters.pop(identity, None)

    parameters: list[dict[str, Any]] = []
    for identity, parameter in runtime_parameters.items():
        location = _SOURCE_LOCATIONS[identity[0]]
        parameters.append(
            {
                "name": identity[1][0],
                "location": location,
                "evidence_kind": str(parameter.get("evidence_kind") or "zend_runtime"),
            }
        )
    if parameters and not callback:
        raise ValueError("Zend runtime parameters require a canonical callback")

    merged = deepcopy(dict(raw_report))
    materialized: list[dict[str, Any]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping):
            continue
        candidate = candidate_from_seed_item(raw_item, plugin_slug=plugin_slug)
        if canonical_identity_id(candidate) != candidate_key:
            continue
        identity = canonical_identity(candidate)
        materialized.append(
            _apply_patch(
                raw_item,
                {
                    "method": identity["resolved_method"],
                    "canonical_callback": callback,
                    "fuzzable_parameters": parameters,
                },
                for_replay=for_replay,
            ) if parameters else deepcopy(dict(raw_item))
        )
    if len(materialized) != 1:
        raise ValueError("Phase 2 convergence requires exactly one matching candidate")
    merged["suggested_seeds"] = materialized
    return merged


def merge_enriched_seeds(
    raw_report: Mapping[str, Any],
    enriched_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Build exportable legacy seeds only from validated, value-free Zend patches."""
    merged = deepcopy(dict(raw_report))
    raw_items = raw_report.get("suggested_seeds", [])
    enriched_items = enriched_report.get("enriched_seeds", [])
    if not isinstance(raw_items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
    default_plugin_slug = _default_plugin_slug(raw_report, enriched_items)
    accepted: list[dict[str, Any]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping):
            continue
        plugin_slug = str(raw_item.get("plugin_slug") or default_plugin_slug)
        candidate = candidate_from_seed_item(raw_item, plugin_slug=plugin_slug)
        patch = next(
            (
                value
                for row in enriched_items if isinstance(enriched_items, list) and isinstance(row, Mapping)
                if (value := _accepted_patch(row, candidate)) is not None
            ),
            None,
        )
        if patch is not None:
            accepted.append(_apply_patch(raw_item, patch))
    merged["suggested_seeds"] = accepted
    return merged


def _default_plugin_slug(raw_report: Mapping[str, Any], enriched_items: Any) -> str:
    plugin_slug = str(raw_report.get("plugin_slug") or "")
    if plugin_slug:
        return plugin_slug
    if not isinstance(enriched_items, list):
        return ""
    for row in enriched_items:
        if isinstance(row, Mapping):
            plugin_slug = str(row.get("plugin_slug") or "")
            if plugin_slug:
                return plugin_slug
    return ""
