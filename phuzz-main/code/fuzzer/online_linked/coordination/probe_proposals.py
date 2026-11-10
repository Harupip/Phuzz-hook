"""Pure grouping of accepted probe reads into proposals for the online-linked coordinator."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from online_linked.coordination.request_matching import (
    _coherent_evidence_key,
    _method_parameter_key,
    _parameter_key,
)


def add_accepted_records(
    records: list[dict[str, Any]],
    keys: set[tuple[str, tuple[str, str, str]]],
    parameters: Iterable[Any],
    evidence: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    """Append one record per new method-qualified parameter, updating ``records`` and ``keys``."""
    # Keyed by method too: a proof in one method context never covers another.
    for parameter in parameters:
        if not isinstance(parameter, Mapping):
            continue
        key = _method_parameter_key(parameter)
        if key in keys:
            continue
        keys.add(key)
        records.append({
            "parameter": dict(parameter),
            "evidence": evidence,
            "result": result,
        })


def drop_queue_row(
    queue: Sequence[Any],
    *,
    parent_version: Any,
    candidate: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> list[Any]:
    """Return the saved probe queue without the row for this parent, candidate and evidence."""
    return [row for row in queue
            if not (row.get("parent_version") == parent_version and
                    row.get("candidate") == candidate and row.get("evidence") == evidence)]


def group_accepted_records(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Group accepted records by coherent request evidence, largest parameter keys first."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        group_key = _coherent_evidence_key(record["evidence"])
        group = groups.setdefault(group_key, {
            "parameters": [], "evidence": record["evidence"], "result": record["result"],
        })
        group["parameters"].append(record["parameter"])
        group["result"] = record["result"]
    return sorted(
        groups.values(),
        key=lambda group: sorted(_parameter_key(p) for p in group["parameters"]),
        reverse=True,
    )


def probe_proposals(
    ordered_groups: list[dict[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return the proposals to try, a combined proposal first when reads span several groups."""
    # Separate reads justify trying a combined request, never publishing a
    # union directly. Admission checks each original evidence pair, then the
    # a single correlated callback baseline must pass before handoff.
    proposals = list(ordered_groups)
    if len(ordered_groups) > 1:
        proposals.insert(0, {
            "parameters": sorted(
                (record["parameter"] for record in records), key=_parameter_key,
            ),
            "evidence": ordered_groups[0]["evidence"],
            "result": ordered_groups[0]["result"],
            "parameter_evidence": {
                _parameter_key(record["parameter"]): record["evidence"]
                for record in records
            },
            "combined": True,
        })
    return proposals


def proposal_result(
    group: Mapping[str, Any],
    *,
    convergence: Mapping[str, Any],
    existing: list[dict[str, Any]],
    deferred: list[dict[str, Any]],
    evidence_origin: str,
    target_key: str,
) -> dict[str, Any]:
    """Build the convergence result that sends one proposal into admission."""
    chosen_parameters = [dict(item) for item in group["parameters"]]
    chosen_evidence = group["evidence"]
    final_result = dict(group["result"])
    final_result["new_parameters"] = chosen_parameters
    inherited = [] if convergence.get("_coherent_only") is True and not group.get("combined") else existing
    final_result["known_parameters"] = list({
        _parameter_key(p): p for p in sorted(inherited + chosen_parameters, key=_parameter_key)
    }.values())
    final_result.pop("pending_probes", None)
    final_result["deferred_probes"] = deferred
    final_result["parameter_evidence"] = group.get("parameter_evidence") or {
        _parameter_key(parameter): chosen_evidence for parameter in chosen_parameters
    }
    final_result["base_evidence"] = chosen_evidence
    final_result["candidate_key"] = str(convergence.get("candidate_key") or target_key)
    if isinstance(group["result"].get("method_transition_report"), Mapping):
        final_result["method_transition_report"] = group["result"]["method_transition_report"]
        final_result["candidate_key"] = group["result"]["candidate_key"]
        final_result["known_parameters"] = [
            dict(parameter) for parameter in group["result"].get("observed_parameters", [])
            if isinstance(parameter, Mapping) and parameter.get("fuzzable") is True
        ]
    final_result["_pending_group_dispatch"] = True
    final_result["evidence_origin"] = evidence_origin
    if group.get("combined") or convergence.get("_coherent_only") is True:
        # A probe's missing reads describe that individual request,
        # not the combined proposal which has yet to be sent.
        final_result["status"] = "CONTINUE"
        final_result["missing_parameters"] = []
    return final_result
