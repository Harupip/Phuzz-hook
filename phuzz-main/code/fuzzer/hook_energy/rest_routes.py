from __future__ import annotations

import re
from typing import Any


_NAMED_GROUP = re.compile(r"\(\?P<(?P<name>[A-Za-z_][A-Za-z0-9_]*)>(?P<pattern>[^()]+)\)")


def materialize_rest_route(pattern: str) -> dict[str, Any]:
    """Materialize only bounded named numeric groups; block every other regex."""
    original = str(pattern or "").strip()
    if not original.startswith("/"):
        return _unsupported(original, "route_must_start_with_slash")

    substitutions: dict[str, dict[str, str]] = {}

    def replace(match: re.Match[str]) -> str:
        name, group_pattern = match.group("name"), match.group("pattern")
        if group_pattern != r"\d+":
            raise ValueError(f"unsupported_named_group:{name}")
        substitutions[name] = {"pattern": group_pattern, "value": "1", "reason": "smallest_positive_integer_for_\\d+"}
        return "1"

    try:
        materialized = _NAMED_GROUP.sub(replace, original)
    except ValueError as exc:
        return _unsupported(original, str(exc))
    if "(" in materialized or ")" in materialized or "[" in materialized or "]" in materialized:
        return _unsupported(original, "unsupported_route_regex")
    try:
        if not re.fullmatch(original, materialized):
            return _unsupported(original, "materialized_route_does_not_match_pattern")
    except re.error:
        return _unsupported(original, "invalid_route_regex")
    return {
        "route_materialization_status": "materialized",
        "pattern": original,
        "materialized": materialized,
        "substitutions": substitutions,
    }


def _unsupported(pattern: str, reason: str) -> dict[str, Any]:
    return {
        "route_materialization_status": "unsupported",
        "pattern": pattern,
        "materialized": None,
        "substitutions": {},
        "block_reason": reason,
    }
