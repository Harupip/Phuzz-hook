from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

from .models import NormalizedConfig, RequestIdentity


def _action_from_config(config: NormalizedConfig) -> str:
    occurrences = []
    for source in ("query_params", "body_params"):
        entry = config.parameters[source].get("action")
        if entry is not None:
            occurrences.append(entry)
    if len(occurrences) != 1:
        raise ValueError("missing_or_ambiguous_action")

    entry = occurrences[0]
    if "value" in entry:
        value = entry["value"]
        if isinstance(value, str) and value:
            return value
        raise ValueError("missing_or_ambiguous_action")
    seeds = entry.get("seeds")
    if not isinstance(seeds, list):
        raise ValueError("missing_or_ambiguous_action")
    unique = {seed for seed in seeds if isinstance(seed, str)}
    if len(unique) != 1 or len(unique) != len(seeds) or not next(iter(unique)):
        raise ValueError("missing_or_ambiguous_action")
    return next(iter(unique))


def _rest_fallback_endpoint(config: NormalizedConfig) -> str | None:
    entry = config.parameters["query_params"].get("rest_route")
    if not entry or entry.get("origin") != "target_query":
        return None
    route = entry.get("value")
    if not isinstance(route, str) or not route:
        return None
    parsed = urlsplit(config.target)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, f"rest_route={quote(route, safe='/')}", ""))


def request_identity(config: NormalizedConfig) -> RequestIdentity:
    if not isinstance(config, NormalizedConfig):
        raise ValueError("invalid_normalized_config")
    parsed = urlsplit(config.target)
    path = parsed.path
    if path.endswith("/wp-admin/admin-ajax.php"):
        return RequestIdentity("ajax", config.methods, config.target, _action_from_config(config))
    if path.endswith("/wp-admin/admin-post.php"):
        return RequestIdentity("admin_post", config.methods, config.target, _action_from_config(config))
    if path == "/wp-json" or path.startswith("/wp-json/"):
        return RequestIdentity("rest", config.methods, config.target, None)
    fallback_endpoint = _rest_fallback_endpoint(config)
    if fallback_endpoint is not None:
        return RequestIdentity("rest", config.methods, fallback_endpoint, None)
    return RequestIdentity("http", config.methods, config.target, None)

