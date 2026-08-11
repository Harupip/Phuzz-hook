from __future__ import annotations

from copy import deepcopy
from collections.abc import Mapping
from typing import Any

from zend_discovery.engine import candidate_from_seed_item, canonical_identity_id


def merge_enriched_seeds(
    raw_report: Mapping[str, Any],
    enriched_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Return only legacy seeds backed by accepted, fuzzable Zend enrichment."""
    merged = deepcopy(dict(raw_report))
    raw_items = raw_report.get("suggested_seeds", [])
    enriched_items = enriched_report.get("enriched_seeds", [])
    if not isinstance(raw_items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
    allowed: dict[str, Mapping[str, Any]] = {}
    for item in enriched_items if isinstance(enriched_items, list) else []:
        if not isinstance(item, Mapping):
            continue
        fuzzable_params = item.get("fuzzable_params")
        seed_item = item.get("seed_item")
        identity_id = item.get("canonical_identity_id")
        if (
            item.get("accepted_pass1_proof") is True
            and item.get("final_fuzz_export_allowed") is True
            and isinstance(fuzzable_params, list)
            and any(str(name).strip() for name in fuzzable_params)
            and isinstance(seed_item, Mapping)
            and isinstance(identity_id, str)
        ):
            allowed[identity_id] = seed_item
    plugin_slug = str(raw_report.get("plugin_slug") or "")
    merged["suggested_seeds"] = [
        deepcopy(dict(allowed[canonical_identity_id(candidate_from_seed_item(item, plugin_slug=plugin_slug))]))
        for item in raw_items
        if isinstance(item, Mapping)
        and canonical_identity_id(candidate_from_seed_item(item, plugin_slug=plugin_slug)) in allowed
    ]
    return merged
