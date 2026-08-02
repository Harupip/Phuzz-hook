# Phase 12 normalized parameter contract

Schema version `1` is deterministic JSON: routes sort by namespace, route,
endpoint index, and method; parameters sort by name; object keys sort
lexicographically.  One record represents one route, endpoint definition,
method, and parameter.  Schemas are never merged across methods.

```json
{
  "schema_version": 1,
  "entrypoint_id": "stable callback identity",
  "namespace": "demo/v1",
  "route_pattern": "/items/(?P<id>\\d+)",
  "endpoint_definition_index": 0,
  "method": "POST",
  "parameter": {
    "name": "id",
    "location": "path",
    "location_candidates": [],
    "location_confidence": "route_pattern_exact",
    "type": "integer",
    "required": true,
    "default_present": false,
    "default": null,
    "enum": [],
    "description": null,
    "format": null,
    "minimum": null,
    "maximum": null,
    "min_length": null,
    "max_length": null,
    "pattern": null,
    "items": null,
    "properties": null,
    "validate_callback": null,
    "sanitize_callback": null,
    "schema_source": "route_declared",
    "schema_confidence": "exact",
    "runtime_observed": false,
    "runtime_readers": [],
    "value_origin": null,
    "raw_value": null,
    "observed_value": null,
    "transformed": null,
    "seed_status": null,
    "seed": null,
    "additional_seeds": [],
    "parameter_status": "resolved",
    "export_allowed": false,
    "evidence": []
  }
}
```

Absent route fields remain `null` or the explicit empty collection shown above;
they are not invented. `required` is `"unknown"` only for runtime-only
parameters. Location is `unknown` with `query`, `json`, and `form` candidates
for schema-only values, except a named route group is `path` with
`route_pattern_exact`. Runtime and replay evidence may elevate confidence to
`runtime_source_exact` and `replay_validated`. Conflicts preserve both values,
set `parameter_status` to `conflict`, and block export.
