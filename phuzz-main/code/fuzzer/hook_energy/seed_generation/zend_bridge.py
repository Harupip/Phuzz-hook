from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from zend_discovery.engine import candidate_from_seed_item, canonical_identity, canonical_identity_id


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


def _apply_patch(raw_item: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    item = deepcopy(dict(raw_item))
    seed = item.get("seed")
    if not isinstance(seed, dict):
        return item
    method = str(patch["method"])
    seed["method"] = method
    seed["resolved_method"] = method
    seed["method_status"] = "resolved"
    seed["method_confidence"] = "zend_pass1"
    seed["export_allowed"] = True
    seed["fuzzable_params"] = []
    body = seed.setdefault("body", {})
    query = seed.setdefault("query_params", {})
    if not isinstance(body, dict) or not isinstance(query, dict):
        return item
    for parameter in patch["fuzzable_parameters"]:
        name = str(parameter["name"])
        target = query if parameter["location"] == "query" else body
        target[name] = "FUZZ"
        seed["fuzzable_params"].append(name)
    return item


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
    plugin_slug = str(raw_report.get("plugin_slug") or "")
    accepted: list[dict[str, Any]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping):
            continue
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
