"""Normalize request-linked Zend comparison events into PHUZZ mutations."""

import copy
import re
from collections.abc import Mapping


_SUPPORTED_OPCODES = {
    "IS_EQUAL",
    "IS_NOT_EQUAL",
    "IS_IDENTICAL",
    "IS_NOT_IDENTICAL",
    "SWITCH_STRING",
}
_SENSITIVE_PARAMETER = re.compile(
    r"(?:nonce|password|secret|token|authorization|auth)", re.IGNORECASE
)
_PLACEMENTS = {
    "GET": ("REST_QUERY", "query_params"),
    "POST": ("REST_FORM", "body_params"),
    "JSON": ("REST_JSON", "body_params"),
}


def _is_scalar(value):
    return isinstance(value, (str, int, float, bool))


def _parameter_name(path):
    if not isinstance(path, (list, tuple)) or not path:
        return None
    parts = list(path)
    if not all(isinstance(part, (str, int)) for part in parts):
        return None
    if isinstance(parts[0], str) and parts[0] in _PLACEMENTS:
        parts = parts[1:]
    if not parts or not all(isinstance(part, str) and part for part in parts):
        return None
    parameter = str(parts[0])
    for part in parts[1:]:
        parameter += "[{}]".format(part)
    return parameter


def _placement(source, path):
    if source in ("GET", "POST"):
        return source, "query_params" if source == "GET" else "body_params"
    if source in ("REST_QUERY", "REST_FORM", "REST_JSON"):
        placement = {
            "REST_QUERY": "query_params",
            "REST_FORM": "body_params",
            "REST_JSON": "body_params",
        }[source]
        return source, placement
    if source == "REST" and isinstance(path, (list, tuple)) and path:
        bucket = path[0]
        if bucket in _PLACEMENTS:
            return _PLACEMENTS[bucket]
    # REQUEST/COOKIE/REST_URL remain fail-closed until the existing runtime
    # transport correlation supplies a concrete fuzzable placement.
    return None, None


def _same_value(left, right):
    if left == right:
        return True
    if isinstance(left, str) and _is_scalar(right):
        return left == str(right)
    if isinstance(right, str) and _is_scalar(left):
        return str(left) == right
    return False


def normalize_comparison_events(artifact, fuzz_params):
    """Return deduplicated, parameter-specific hints from one Zend artifact."""

    if not isinstance(artifact, Mapping) or not isinstance(fuzz_params, Mapping):
        return []
    request_id = artifact.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return []
    raw_events = artifact.get("comparison_events")
    if not isinstance(raw_events, list):
        return []

    hints = []
    seen = set()
    for event in raw_events:
        if not isinstance(event, Mapping):
            continue
        opcode = event.get("opcode")
        if opcode not in _SUPPORTED_OPCODES:
            continue
        runtime_value = event.get("runtime_value")
        comparison_value = event.get("comparison_value")
        if not _is_scalar(runtime_value) or not _is_scalar(comparison_value):
            continue
        if _same_value(runtime_value, comparison_value):
            continue
        source = event.get("source")
        path = event.get("path")
        normalized_source, placement = _placement(source, path)
        if normalized_source is None or placement not in fuzz_params:
            continue
        parameter = _parameter_name(path)
        if parameter is None or _SENSITIVE_PARAMETER.search(parameter):
            continue
        placement_params = fuzz_params.get(placement)
        if not isinstance(placement_params, Mapping) or parameter not in placement_params:
            continue
        if not _same_value(placement_params[parameter], runtime_value):
            continue

        callback = event.get("callback")
        if callback is not None and not isinstance(callback, str):
            callback = None
        raw_path = list(path) if isinstance(path, (list, tuple)) else []
        dedupe_key = (
            request_id,
            callback,
            opcode,
            normalized_source,
            tuple(raw_path),
            repr(runtime_value),
            repr(comparison_value),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        hints.append(
            {
                "request_id": request_id,
                "callback": callback,
                "opcode": opcode,
                "source": normalized_source,
                "path": raw_path,
                "parameter": parameter,
                "placement": placement,
                "observed_value": runtime_value,
                "candidate_value": comparison_value,
                "reason": "cmplog",
                "mutation_source": "cmplog",
            }
        )
    return hints


def apply_cmplog_hint(fuzz_params, hint):
    """Apply one already-normalized hint without reading runtime artifacts."""

    if not isinstance(fuzz_params, Mapping) or not isinstance(hint, Mapping):
        return None
    placement = hint.get("placement")
    parameter = hint.get("parameter")
    candidate_value = hint.get("candidate_value")
    if placement not in fuzz_params or not isinstance(parameter, str) or not _is_scalar(candidate_value):
        return None
    placement_params = fuzz_params.get(placement)
    if not isinstance(placement_params, Mapping) or parameter not in placement_params:
        return None
    observed_value = hint.get("observed_value")
    if observed_value is not None and not _same_value(placement_params[parameter], observed_value):
        return None
    if _same_value(placement_params[parameter], candidate_value):
        return None
    updated = copy.deepcopy(fuzz_params)
    updated[placement][parameter] = candidate_value
    return {
        "fuzz_params": updated,
        "mutated_param_type": placement,
        "mutated_param_name": parameter,
        "mutation_source": "cmplog",
        "cmplog_hint": dict(hint),
    }
