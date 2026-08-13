from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_LOCATIONS = {"query": "REST_QUERY", "form": "REST_FORM", "json": "REST_JSON"}
_BUCKET_LOCATIONS = {"GET": "query", "POST": "form", "JSON": "json"}
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
    uopz_artifact: Mapping[str, Any],
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
    transport_events: list[Mapping[str, Any]] = list(events)
    if method in {"GET", "HEAD"}:
        request_params = uopz_artifact.get("request_params")
        query_params = request_params.get("query_params") if isinstance(request_params, Mapping) else None
        uopz_events = uopz_artifact.get("rest_parameter_events")
        observed: dict[str, int] = {}
        duplicate_observation = False
        if isinstance(query_params, Mapping) and isinstance(uopz_events, list):
            for event in uopz_events:
                if not isinstance(event, Mapping) or event.get("accessor") != "WP_REST_Request::get_param":
                    continue
                name = event.get("name")
                if isinstance(name, str) and name in query_params:
                    if name in observed:
                        duplicate_observation = True
                        break
                    observed[name] = 1
        if duplicate_observation:
            return []
        transport_events.extend(
            {
                **expected,
                "name": name,
                "location": "query",
                "observed_count": count,
            }
            for name, count in observed.items()
        )

    accepted_events: list[Mapping[str, Any]] = []
    locations_by_name: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    for event in transport_events:
        if not isinstance(event, Mapping) or str(event.get("callback") or "") != canonical_callback:
            continue
        if any(key in event and event.get(key) != value for key, value in expected.items() if key != "callback"):
            continue
        if event.get("source") == "REST":
            bucket = str(event.get("bucket") or "").upper()
            name = event.get("parameter")
            location = _BUCKET_LOCATIONS.get(bucket, "")
            path = event.get("path")
            if isinstance(path, list) and path != [bucket, name]:
                continue
        else:
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
        accepted_events.append({**event, "name": name, "location": location})
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
