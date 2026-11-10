"""Pure pending runtime candidate helpers for the online-linked coordinator."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from online_linked.coordination.request_matching import _parameter_key, _safe_parameter_identity


def failed_batch_parameters(
    parent: Mapping[str, Any], proposed: Sequence[Mapping[str, Any]], *, versions: Sequence[Any],
) -> list[dict[str, Any]]:
    """Return fields of children whose baseline did not pass in this callback/method context.

    The parent keeps fuzzing after such a failure, so without this the next
    update would drop that batch instead of replaying it in the union.
    """
    method = str(parent.get("resolved_method") or "").upper()
    seen = {_parameter_key(parameter) for parameter in proposed if isinstance(parameter, Mapping)}
    carried: list[dict[str, Any]] = []
    for version in versions:
        if (
            not isinstance(version, Mapping) or version.get("version") == "v0"
            # A failed replay-guard child is a rejected probe, not a parent batch.
            or version.get("discovery_origin") == "replay_guard"
            or (version.get("replay_result") or {}).get("passed") is True
            or str(version.get("callback_id") or "") != str(parent.get("callback_id") or "")
            or str(version.get("resolved_method") or "").upper() != method
        ):
            continue
        for parameter in version.get("known_parameters") or []:
            if (
                isinstance(parameter, Mapping)
                and _parameter_key(parameter) not in seen
                and str(parameter.get("request_method") or method).upper() == method
            ):
                seen.add(_parameter_key(parameter))
                carried.append(dict(parameter))
    return carried


def pending_key(item: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    """Identity of one pending runtime candidate: field plus the request/run that observed it."""
    return (
        str(item.get("name") or ""),
        str(item.get("source") or "").upper(),
        str(item.get("location") or "").lower(),
        str(item.get("request_id") or ""),
        str(item.get("run_id") or ""),
    )


def append_pending_rows(
    pending: list[Any], groups: Sequence[Mapping[str, Any]], parent: Mapping[str, Any],
) -> None:
    """Append one pending row per new (field, request, run) in ``groups``, in place."""
    existing = {pending_key(item) for item in pending if isinstance(item, Mapping)}
    for group in groups:
        evidence = group.get("evidence") if isinstance(group.get("evidence"), Mapping) else {}
        request_id = str(evidence.get("request_id") or "")
        run_id = str(evidence.get("worker_run_id") or evidence.get("run_id") or "")
        for parameter in group.get("parameters", []):
            if not isinstance(parameter, Mapping):
                continue
            row = dict(_safe_parameter_identity(parameter))
            row.update({
                "parameter": copy.deepcopy(dict(parameter)),
                "evidence": copy.deepcopy(dict(evidence)),
                "parent_version": parent.get("version"),
                "config_path": parent.get("config_path"),
                "request_id": request_id,
                "run_id": run_id,
                "callback_id": str(parameter.get("callback_id") or parent.get("callback_id") or ""),
                "canonical_callback": str(
                    parameter.get("canonical_callback") or parent.get("canonical_callback") or ""
                ),
                "candidate_status": "pending_runtime_proposal",
            })
            key = (
                row["name"], row["source"], row["location"], row["request_id"], row["run_id"],
            )
            if key in existing:
                continue
            pending.append(row)
            existing.add(key)


def without_discarded(pending: list[Any], groups: Sequence[Mapping[str, Any]]) -> list[Any] | None:
    """Return ``pending`` without the rows named by ``groups``; None when nothing is discarded."""
    discard = set()
    for group in groups:
        evidence = group.get("evidence") if isinstance(group.get("evidence"), Mapping) else {}
        request_id = str(evidence.get("request_id") or "")
        run_id = str(evidence.get("worker_run_id") or evidence.get("run_id") or "")
        for parameter in group.get("parameters", []):
            if not isinstance(parameter, Mapping):
                continue
            identity = _safe_parameter_identity(parameter)
            discard.add((
                identity["name"], identity["source"], identity["location"], request_id, run_id,
            ))
    if not discard:
        return None
    return [
        item for item in pending
        if not isinstance(item, Mapping) or pending_key(item) not in discard
    ]


def fresh_runtime_candidates(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Collect the candidates observed by this result, in proposal order."""
    fresh_candidates = []
    for field in ("pending_probes", "new_parameters", "observed_parameters"):
        values = result.get(field)
        if isinstance(values, list):
            fresh_candidates.extend(item for item in values if isinstance(item, Mapping))
    return fresh_candidates
