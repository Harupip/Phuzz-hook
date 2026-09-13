from __future__ import annotations

import copy
from dataclasses import replace
from typing import Iterable

from .comparator import _compare_normalized, _error_differences, _sort_differences, _with_side
from .identity import request_identity
from .models import CompareResult, ConfigError, Difference, DifferenceKind, PreparedReferences, Status
from .normalizer import normalize_config
from .policy import ComparisonPolicy


def _identity_error(message: str, side: str, input_index: int) -> ConfigError:
    return ConfigError(
        kind=DifferenceKind.INVALID_CONFIG,
        path="",
        message=message,
        side=side,
        input_index=input_index,
    )


def prepare_references(reference_configs: Iterable[dict], policy: ComparisonPolicy) -> PreparedReferences:
    normalized_references = []
    index = {}
    reference_errors: list[ConfigError] = []
    policy_snapshot = copy.deepcopy(policy)
    for reference_index, config in enumerate(reference_configs):
        normalized_result = normalize_config(config, policy_snapshot)
        if normalized_result.errors:
            errors = [replace(error, side="reference", input_index=reference_index) for error in normalized_result.errors]
            normalized_references.append(None)
            reference_errors.extend(errors)
            continue
        normalized = normalized_result.config
        try:
            identity = request_identity(normalized)
        except ValueError as exc:
            normalized_references.append(normalized)
            reference_errors.append(_identity_error(str(exc), "reference", reference_index))
            continue
        normalized_references.append(normalized)
        index.setdefault(identity, []).append(reference_index)
    return PreparedReferences(policy_snapshot, normalized_references, index, reference_errors)


def _invalid_actual_result(
    errors: list[ConfigError],
    *,
    actual_index: int,
    reference_errors: list[ConfigError] | None = None,
) -> CompareResult:
    all_errors = list(reference_errors or []) + errors
    if reference_errors:
        all_errors.append(ConfigError(DifferenceKind.INVALID_CONFIG, "", "invalid_reference_set", "reference"))
    return CompareResult(
        Status.INVALID,
        differences=_sort_differences(_error_differences(all_errors)),
        errors=all_errors,
        actual_index=actual_index,
    )


def compare_many(generated_configs: Iterable[dict], references: PreparedReferences) -> list[CompareResult]:
    results: list[CompareResult] = []
    for actual_index, actual in enumerate(generated_configs):
        normalized_result = normalize_config(actual, references.policy)
        actual_errors = _with_side(normalized_result.errors, "actual")
        if references.reference_errors:
            results.append(
                _invalid_actual_result(
                    actual_errors,
                    actual_index=actual_index,
                    reference_errors=references.reference_errors,
                )
            )
            continue
        if actual_errors:
            results.append(_invalid_actual_result(actual_errors, actual_index=actual_index))
            continue
        normalized_actual = normalized_result.config
        try:
            identity = request_identity(normalized_actual)
        except ValueError as exc:
            results.append(_invalid_actual_result([_identity_error(str(exc), "actual", actual_index)], actual_index=actual_index))
            continue

        reference_indices = references.index.get(identity, [])
        if not reference_indices:
            results.append(CompareResult(Status.NO_REFERENCE, actual_index=actual_index, reference_indices=[]))
            continue
        if len(reference_indices) > 1:
            results.append(
                CompareResult(
                    Status.AMBIGUOUS,
                    actual_index=actual_index,
                    reference_indices=list(reference_indices),
                )
            )
            continue
        comparison = _compare_normalized(
            references.normalized_references[reference_indices[0]],
            normalized_actual,
            references.policy,
        )
        results.append(
            CompareResult(
                comparison.status,
                differences=comparison.differences,
                errors=comparison.errors,
                actual_index=actual_index,
                reference_indices=list(reference_indices),
            )
        )
    return results
