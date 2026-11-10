"""Pure classification of probe and replay results for the online-linked coordinator."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from online_linked.coordination.request_matching import _parameter_key
from online_linked.export import parameter_replay_failures


def ajax_branch_continuation(result: Mapping[str, Any], parent: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite an AJAX branch failure as CONTINUE with the accumulated parameter set."""
    # AJAX keeps the accumulated set: a known field this request did not
    # touch only describes its path (also for results saved before).
    observed = list({
        _parameter_key(parameter): dict(parameter)
        for parameter in [*(result.get("observed_parameters") or []), *(result.get("new_parameters") or [])]
        if isinstance(parameter, Mapping) and parameter.get("fuzzable") is True
    }.values())
    base = [
        dict(parameter) for parameter in (result.get("known_parameters") or parent.get("known_parameters") or [])
        if isinstance(parameter, Mapping)
    ]
    base_keys = {_parameter_key(parameter) for parameter in base}
    new = [
        dict(parameter) for parameter in (result.get("new_parameters") or [])
        if isinstance(parameter, Mapping) and parameter.get("fuzzable") is True
    ] or [parameter for parameter in observed if _parameter_key(parameter) not in base_keys]
    return {
        **result,
        "status": "CONTINUE",
        "new_parameters": new,
        "known_parameters": list({_parameter_key(p): p for p in [*base, *observed]}.values()),
        "unobserved_known_parameters": list(result.get("missing_parameters") or []),
        "missing_parameters": [],
    }


@dataclass(frozen=True)
class ProbeParameterMatch:
    matching: list[Any]
    trace_parameters: list[Any]
    pending_matching: list[Any]
    unexpected: list[dict[str, Any]]


def match_probe_parameters(
    probe: Mapping[str, Any], probe_parameters: Any, all_parameters: Sequence[Any], *, ajax: bool,
) -> ProbeParameterMatch:
    target_key = _parameter_key(probe)
    matching = [
        parameter for parameter in all_parameters
        if isinstance(parameter, Mapping)
        # A method probe proves POST only through a POST field, never GET reads.
        and (_parameter_key(parameter) == target_key if probe.get("method_probe") is not True
             else str(parameter.get("source") or "").upper() == "POST")
        and parameter.get("fuzzable") is True
    ]
    # The probe's target decides success; once it holds, every other
    # admitted access in the same AJAX trace joins the same proposal.
    trace_parameters = list({
        _parameter_key(parameter): parameter for parameter in all_parameters
        if isinstance(parameter, Mapping) and parameter.get("fuzzable") is True
    }.values()) if matching and ajax else matching
    pending_matching = [
        parameter for parameter in all_parameters
        if isinstance(parameter, Mapping)
        and (probe.get("method_probe") is True or _parameter_key(parameter) == target_key)
        and parameter.get("fuzzable") is not True
    ]
    unexpected = [
        dict(parameter) for parameter in probe_parameters
        if isinstance(parameter, Mapping) and _parameter_key(parameter) != target_key
    ] if isinstance(probe_parameters, list) else []
    return ProbeParameterMatch(matching, trace_parameters, pending_matching, unexpected)


@dataclass(frozen=True)
class ReplayVerdict:
    callback_passed: bool
    non_success_response: bool
    response_status: Any
    parameter_failures: list[dict[str, str]]
    transport_failed: bool

    @property
    def passed(self) -> bool:
        return self.callback_passed and not self.non_success_response


def replay_verdict(
    *,
    replay_row: Mapping[str, Any],
    sender_result: Mapping[str, Any],
    baseline: Mapping[str, Any] | None,
    verified_parameters: list[dict[str, str]],
    deadline_expired: bool,
    artifact_error: str,
) -> ReplayVerdict:
    replay_passed = bool(
        isinstance(replay_row, Mapping)
        and not deadline_expired
        and not artifact_error
        and replay_row.get("validation_status") == "callback_reached"
        and replay_row.get("process_status") not in {"failed", "runner_error", "window_elapsed"}
        and baseline is not None
    )
    request_payload = replay_row.get("request_payload")
    response = request_payload.get("response") if isinstance(request_payload, Mapping) else None
    response_status = sender_result.get("response_status")
    artifact_status = response.get("status_code") if isinstance(response, Mapping) else None
    if response_status is None and isinstance(response, Mapping):
        response_status = artifact_status
    parameter_failures: list[dict[str, str]] = []
    transport_failed = False
    if verified_parameters:
        # parameter_replay_v1: the HTTP status is diagnostic; the batch's Zend proof decides.
        transport_failed = bool(sender_result.get("error")) or (
            response_status is not None and artifact_status is not None
            and str(artifact_status) != str(response_status)
        )
        parameter_failures = (
            parameter_replay_failures(verified_parameters, baseline["request"], baseline["zend"])
            if baseline is not None else list(verified_parameters)
        )
        replay_passed = replay_passed and not transport_failed and not parameter_failures
        non_success_response = False
    else:
        try:
            non_success_response = (bool(sender_result.get("error")) or not 200 <= int(response_status) <= 299
                                    or int(artifact_status) != int(response_status))
        except (TypeError, ValueError):
            non_success_response = True
    return ReplayVerdict(
        callback_passed=replay_passed,
        non_success_response=non_success_response,
        response_status=response_status,
        parameter_failures=parameter_failures,
        transport_failed=transport_failed,
    )
