from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_LOCATIONS = {"query": "REST_QUERY", "form": "REST_FORM", "json": "REST_JSON"}
_FORBIDDEN_PARAMETER_NAME = re.compile(
    r"(?:nonce|cookie|secret|password|token|authorization)", re.IGNORECASE
)
_METHOD_LOCATIONS = {
    "GET": {"query"},
    "HEAD": {"query"},
    "POST": set(_LOCATIONS),
}


def normalize_rest_parameter_events(
    candidate: Mapping[str, Any],
    zend_artifact: Mapping[str, Any],
    *,
    canonical_callback: str,
    fixed_bootstrap: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Normalize only correlated, top-level REST transport observations."""
    method = str(candidate.get("resolved_method") or candidate.get("method") or "").upper()
    allowed_locations = _METHOD_LOCATIONS.get(method)
    events = zend_artifact.get("rest_parameter_events")
    if not canonical_callback or not allowed_locations or not isinstance(events, list):
        return []

    expected = {
        "callback": canonical_callback,
        "namespace": str(candidate.get("namespace") or ""),
        "route_pattern": str(candidate.get("route_pattern") or candidate.get("route") or ""),
        "endpoint_definition_index": candidate.get("endpoint_definition_index"),
        "materialized_route": str(candidate.get("materialized_route") or candidate.get("route") or ""),
        "method": method,
    }
    accepted_events: list[Mapping[str, Any]] = []
    locations_by_name: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    for event in events:
        if not isinstance(event, Mapping) or any(event.get(key) != value for key, value in expected.items()):
            continue
        name = event.get("name")
        location = str(event.get("location") or "")
        try:
            observed_count = int(event.get("observed_count") or 0)
        except (TypeError, ValueError):
            continue
        if (
            not isinstance(name, str)
            or not name
            or "[" in name
            or "]" in name
            or _FORBIDDEN_PARAMETER_NAME.search(name)
            or location not in allowed_locations
            or observed_count < 1
            or name in fixed_bootstrap
            or (name, location) in seen
        ):
            continue
        seen.add((name, location))
        accepted_events.append(event)
        locations_by_name.setdefault(name, set()).add(location)
    if any(len(locations) != 1 for locations in locations_by_name.values()):
        return []

    normalized: list[dict[str, Any]] = []
    for event in accepted_events:
        name = str(event["name"])
        location = str(event.get("location") or "")
        normalized.append(
            {
                "name": name,
                "path": [name],
                "source": _LOCATIONS[location],
                "location": location,
                "helper_depth": 0,
                "observed_count": int(event.get("observed_count") or 0),
                "evidence_kind": "zend_rest_runtime",
                "fuzzable": True,
                "run_id": str(candidate.get("legacy_run_id") or ""),
                "request_id": str(candidate.get("pass1_request_id") or ""),
                "plugin_slug": str(candidate.get("plugin_slug") or ""),
                "callback_id": str(candidate.get("callback_id") or ""),
                "canonical_callback": canonical_callback,
                "namespace": expected["namespace"],
                "route_pattern": expected["route_pattern"],
                "materialized_route": expected["materialized_route"],
                "endpoint_definition_index": expected["endpoint_definition_index"],
                "request_method": method,
            }
        )
    return sorted(normalized, key=lambda item: (item["location"], item["name"]))
