from __future__ import annotations

import copy
import re
from dataclasses import replace
from typing import Any

from .models import CompareResult, ConfigError, Difference, DifferenceKind, NormalizedConfig, Status
from .normalizer import _freeze_typed, normalize_config, pointer_escape
from .policy import ComparisonPolicy


_DECLARATION_FIELDS = frozenset({"name", "value", "seeds"})


def _error_differences(errors: list[ConfigError]) -> list[Difference]:
    return [Difference(error.kind, error.path, reason=error.message) for error in errors]


def _with_side(errors: list[ConfigError], side: str) -> list[ConfigError]:
    return [replace(error, side=side) for error in errors]


def _path(source: str, name: str) -> str:
    return f"/{source}/{pointer_escape(name)}"


def _typed_equal(left: Any, right: Any) -> bool:
    return _freeze_typed(left) == _freeze_typed(right)


def _seed_set(value: list[Any]) -> set[tuple[Any, ...]]:
    return {_freeze_typed(seed) for seed in value}


def _compare_entry(source: str, name: str, expected: dict[str, Any], actual: dict[str, Any]) -> list[Difference]:
    base = _path(source, name)
    differences: list[Difference] = []

    for field_name, kind in (("value", DifferenceKind.VALUE_MISMATCH), ("seeds", DifferenceKind.SEED_MISMATCH)):
        expected_has = field_name in expected
        actual_has = field_name in actual
        if expected_has != actual_has:
            differences.append(
                Difference(
                    kind,
                    f"{base}/{field_name}",
                    expected=expected.get(field_name),
                    actual=actual.get(field_name),
                    reason="missing_field",
                )
            )
            continue
        if not expected_has:
            continue
        if field_name == "seeds":
            equal = _seed_set(expected[field_name]) == _seed_set(actual[field_name])
        else:
            equal = _typed_equal(expected[field_name], actual[field_name])
        if not equal:
            differences.append(
                Difference(kind, f"{base}/{field_name}", expected[field_name], actual[field_name])
            )

    for field_name in sorted((set(expected) | set(actual)) - _DECLARATION_FIELDS):
        expected_has = field_name in expected
        actual_has = field_name in actual
        field_path = f"{base}/{pointer_escape(field_name)}"
        if not expected_has or not actual_has:
            differences.append(
                Difference(
                    DifferenceKind.VALUE_MISMATCH,
                    field_path,
                    expected=expected.get(field_name),
                    actual=actual.get(field_name),
                    reason="missing_field" if not expected_has or not actual_has else None,
                )
            )
        elif not _typed_equal(expected[field_name], actual[field_name]):
            differences.append(Difference(DifferenceKind.VALUE_MISMATCH, field_path, expected[field_name], actual[field_name]))
    return differences


def _allowed_selector_pattern(pattern: str, extra_name: str, expected_names: set[str]) -> bool:
    if not (re.fullmatch(r"[A-Za-z0-9_]+", pattern) or pattern == re.escape(extra_name)):
        return False
    return not any(expected_name.startswith(pattern) for expected_name in expected_names)


def _filtered_actual_selectors(
    source: str,
    selectors: set[str] | frozenset[str],
    extra_names: set[str],
    expected_names: set[str],
) -> set[str]:
    filtered = set(selectors)
    for pattern in selectors:
        if any(_allowed_selector_pattern(pattern, name, expected_names) for name in extra_names):
            filtered.discard(pattern)
    return filtered


def _compare_parameters(expected: NormalizedConfig, actual: NormalizedConfig, policy: ComparisonPolicy) -> list[Difference]:
    differences: list[Difference] = []
    expected_names = set().union(*(set(values) for values in expected.parameters.values()))
    actual_names = set().union(*(set(values) for values in actual.parameters.values()))
    actual_only_names = actual_names - expected_names

    for name in sorted(expected_names | actual_names):
        expected_sources = [source for source in expected.parameters if name in expected.parameters[source]]
        actual_sources = [source for source in actual.parameters if name in actual.parameters[source]]
        if len(expected_sources) == len(actual_sources) == 1 and expected_sources[0] != actual_sources[0]:
            expected_source = expected_sources[0]
            actual_source = actual_sources[0]
            differences.append(
                Difference(
                    DifferenceKind.SOURCE_MISMATCH,
                    _path(expected_source, name),
                    expected={"source": expected_source, "entry": expected.parameters[expected_source][name]},
                    actual={"source": actual_source, "entry": actual.parameters[actual_source][name]},
                )
            )
            continue

        for source in sorted(set(expected_sources) | set(actual_sources)):
            expected_entry = expected.parameters[source].get(name)
            actual_entry = actual.parameters[source].get(name)
            if expected_entry is not None and actual_entry is not None:
                differences.extend(_compare_entry(source, name, expected_entry, actual_entry))
            elif expected_entry is not None:
                differences.append(Difference(DifferenceKind.MISSING_PARAMETER, _path(source, name), expected_entry, None))
            elif (source, name) not in policy.allowed_extra_parameters:
                differences.append(Difference(DifferenceKind.UNEXPECTED_PARAMETER, _path(source, name), None, actual_entry))
    return differences


def _compare_selectors(expected: NormalizedConfig, actual: NormalizedConfig, policy: ComparisonPolicy) -> list[Difference]:
    differences: list[Difference] = []
    expected_names = set().union(*(set(values) for values in expected.parameters.values()))
    for source in expected.selectors:
        actual_only_names = {
            name
            for name in actual.parameters[source]
            if name not in expected_names and (source, name) in policy.allowed_extra_parameters
        }
        for selector_kind in ("fixed", "fuzz"):
            expected_patterns = set(expected.selectors[source][selector_kind])
            actual_patterns = _filtered_actual_selectors(
                source,
                actual.selectors[source][selector_kind],
                actual_only_names,
                expected_names,
            )
            if expected_patterns != actual_patterns:
                differences.append(
                    Difference(
                        DifferenceKind.CLASSIFICATION_MISMATCH,
                        f"/{source}/{selector_kind}",
                        sorted(expected_patterns),
                        sorted(actual_patterns),
                    )
                )
    return differences


def _prune_ignored(value: Any, path: str, policy: ComparisonPolicy) -> Any:
    if path in policy.ignored_metadata_paths:
        return _MISSING
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            child_path = f"{path}/{pointer_escape(str(key))}" if path else f"/{pointer_escape(str(key))}"
            pruned = _prune_ignored(child, child_path, policy)
            if pruned is not _MISSING:
                result[str(key)] = pruned
        if path == "/metadata" and not result:
            return _MISSING
        return result
    return copy.deepcopy(value)


_MISSING = object()


def _compare_structural(expected: Any, actual: Any, path: str, policy: ComparisonPolicy) -> list[Difference]:
    if expected is _MISSING and actual is _MISSING:
        return []
    if expected is _MISSING or actual is _MISSING:
        return [
            Difference(
                DifferenceKind.VALUE_MISMATCH,
                path,
                expected=None if expected is _MISSING else expected,
                actual=None if actual is _MISSING else actual,
                reason="missing_field",
            )
        ]
    if isinstance(expected, dict) and isinstance(actual, dict):
        differences: list[Difference] = []
        for key in sorted(set(expected) | set(actual), key=str):
            child_path = f"{path}/{pointer_escape(str(key))}" if path else f"/{pointer_escape(str(key))}"
            differences.extend(
                _compare_structural(
                    expected.get(key, _MISSING),
                    actual.get(key, _MISSING),
                    child_path,
                    policy,
                )
            )
        return differences
    if not _typed_equal(expected, actual):
        return [Difference(DifferenceKind.VALUE_MISMATCH, path, expected, actual)]
    return []


def _sort_differences(differences: list[Difference]) -> list[Difference]:
    return sorted(differences, key=lambda item: (item.path, item.kind.value, repr(item.expected), repr(item.actual)))


def _compare_normalized(expected: NormalizedConfig, actual: NormalizedConfig, policy: ComparisonPolicy) -> CompareResult:
    differences: list[Difference] = []
    if expected.target != actual.target:
        differences.append(Difference(DifferenceKind.TARGET_MISMATCH, "/target", expected.target, actual.target))
    if expected.methods != actual.methods:
        differences.append(Difference(DifferenceKind.METHOD_MISMATCH, "/methods", list(expected.methods), list(actual.methods)))
    differences.extend(_compare_parameters(expected, actual, policy))
    differences.extend(_compare_selectors(expected, actual, policy))
    differences.extend(_compare_structural(expected.section_extras, actual.section_extras, "", policy))
    expected_extras = _prune_ignored(expected.extras, "", policy)
    actual_extras = _prune_ignored(actual.extras, "", policy)
    differences.extend(_compare_structural(expected_extras, actual_extras, "", policy))
    differences = _sort_differences(differences)
    return CompareResult(Status.MATCH if not differences else Status.MISMATCH, differences=differences)


def compare_configs(expected: dict, actual: dict, policy: ComparisonPolicy) -> CompareResult:
    expected_result = normalize_config(expected, policy)
    actual_result = normalize_config(actual, policy)
    errors = _with_side(expected_result.errors, "expected") + _with_side(actual_result.errors, "actual")
    if errors:
        return CompareResult(
            Status.INVALID,
            differences=_sort_differences(_error_differences(errors)),
            errors=errors,
        )
    return _compare_normalized(expected_result.config, actual_result.config, policy)
