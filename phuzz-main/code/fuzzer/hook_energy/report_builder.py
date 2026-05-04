from __future__ import annotations

from .report_models import (
    CallbackRecord,
    ComparisonSummary,
    DecisionRecord,
    HookVisualizationReport,
    RequestRecord,
    RunMetadata,
    RunSummary,
)


def _decision_outcome_tags(coverage_id: str, exception_candidates: list[dict], vulnerability_candidates: dict) -> list[str]:
    tags = []
    if any(item.get("coverage_id") == coverage_id for item in exception_candidates):
        tags.append("exception_or_error")
    for vuln_name, items in vulnerability_candidates.items():
        if any(item.get("coverage_id") == coverage_id for item in items):
            tags.append(vuln_name)
    return tags


def build_single_run_report(loaded) -> HookVisualizationReport:
    decision_records = []
    priority_deltas = []
    energy_deltas = []

    exception_by_coverage = {item.get("coverage_id"): item for item in loaded.exception_candidates}

    for row in loaded.decisions:
        priority_delta = float(row.get("priority", 0.0)) - float(row.get("base_priority", 0.0))
        energy_delta = int(row.get("final_energy", 0)) - int(row.get("base_energy", 0))
        priority_deltas.append(priority_delta)
        energy_deltas.append(energy_delta)

        exception_row = exception_by_coverage.get(row.get("coverage_id"), {})
        decision_records.append(
            DecisionRecord(
                coverage_id=str(row.get("coverage_id", "")),
                hook_request_id=str(row.get("hook_request_id", "")),
                mutated_param_name=str(exception_row.get("mutated_param_name", "")),
                mutated_param_type=str(exception_row.get("mutated_param_type", "")),
                base_score=float(row.get("base_score", 0.0)),
                score=float(row.get("score", 0.0)),
                base_priority=float(row.get("base_priority", 0.0)),
                priority=float(row.get("priority", 0.0)),
                base_energy=int(row.get("base_energy", 0)),
                final_energy=int(row.get("final_energy", 0)),
                hook_energy=float(row.get("hook_energy", 0.0)),
                hook_energy_avg=float(row.get("hook_energy_avg", 0.0)),
                target=str(row.get("http_target", "")),
                method=str(row.get("http_method", "")),
                outcome_tags=_decision_outcome_tags(
                    str(row.get("coverage_id", "")),
                    loaded.exception_candidates,
                    loaded.vulnerability_candidates,
                ),
            )
        )

    callback_records = []
    request_records = []
    registered = {}
    callback_execution_totals = {}
    callback_request_totals = {}

    for request_id, payload in loaded.requests.items():
        hook_coverage = payload.get("hook_coverage", {})
        registered_callbacks = hook_coverage.get("registered_callbacks", {}) or {}
        executed_callbacks = hook_coverage.get("executed_callbacks", {}) or {}

        for callback_id, callback_payload in registered_callbacks.items():
            registered[callback_id] = callback_payload

        normalized_callbacks = []
        if isinstance(executed_callbacks, dict):
            for callback_id, callback_payload in executed_callbacks.items():
                executed_count = int(callback_payload.get("executed_count", 0))
                callback_execution_totals[callback_id] = callback_execution_totals.get(callback_id, 0) + executed_count
                callback_request_totals[callback_id] = callback_request_totals.get(callback_id, 0) + 1
                normalized_callbacks.append(callback_payload)

        request_records.append(
            RequestRecord(
                request_id=request_id,
                endpoint=str(payload.get("endpoint", "")),
                request_method=str(payload.get("request_method", "")),
                coverage_id=str(payload.get("request_params", {}).get("headers", {}).get("X-FUZZER-COVID", "")),
                request_time_ms=float(payload.get("request_time_ms", 0.0)),
                executed_callbacks=normalized_callbacks,
                rarity_contribution_summary=[
                    f"{item.get('hook_name', '')}:{item.get('callback_repr', '')}:{item.get('executed_count', 0)}"
                    for item in normalized_callbacks
                ],
            )
        )

    blindspot_ids = {
        str(item.get("callback_id", ""))
        for item in loaded.coverage_summary.get("blindspot_callbacks", [])
        if item.get("callback_id")
    }

    for callback_id, callback_payload in registered.items():
        executed_count = callback_execution_totals.get(callback_id, 0)
        request_count = callback_request_totals.get(callback_id, 0)
        callback_records.append(
            CallbackRecord(
                callback_id=callback_id,
                hook_name=str(callback_payload.get("hook_name", "")),
                callback_identity=str(callback_payload.get("callback_repr", "")),
                executed_count=executed_count,
                request_count=request_count,
                rarity_score_current=(1.0 / executed_count) if executed_count else 0.0,
                next_score_if_seen_again=(1.0 / (executed_count + 1)) if executed_count else 1.0,
                status="blindspot" if callback_id in blindspot_ids or executed_count == 0 else "executed",
            )
        )

    coverage_percent = str(loaded.coverage_summary.get("coverage_percent", "0")).rstrip("%")
    hook_values = [record.hook_energy for record in decision_records] or [0.0]
    summary = RunSummary(
        requests_total=len(loaded.requests),
        registered_callbacks_total=int(loaded.coverage_summary.get("registered_total", len(registered))),
        executed_callbacks_total=int(
            loaded.coverage_summary.get(
                "executed_total",
                sum(1 for item in callback_records if item.executed_count > 0),
            )
        ),
        blindspots_total=len(blindspot_ids),
        coverage_ratio=(float(coverage_percent) / 100.0) if coverage_percent else 0.0,
        exceptions_count=len(loaded.exception_candidates),
        vulnerability_counts={key: len(value) for key, value in loaded.vulnerability_candidates.items()},
        boosted_decisions_count=sum(1 for value in priority_deltas if value > 0),
        avg_hook_energy=sum(hook_values) / len(hook_values),
        max_hook_energy=max(hook_values),
        avg_priority_delta=sum(priority_deltas) / len(priority_deltas or [1]),
        max_priority_delta=max(priority_deltas or [0.0]),
        avg_energy_delta=sum(energy_deltas) / len(energy_deltas or [1]),
        max_energy_delta=max(energy_deltas or [0.0]),
    )

    callback_records.sort(key=lambda item: (0 if item.status == "executed" else 1, item.callback_id))

    return HookVisualizationReport(
        metadata=RunMetadata(
            label=str(loaded.metadata.get("label", "")),
            mode=str(loaded.metadata.get("mode", "")),
        ),
        summary=summary,
        decision_records=decision_records,
        callback_records=callback_records,
        request_records=request_records,
        warnings=list(loaded.warnings),
    )


def build_run_pair_comparison(baseline: HookVisualizationReport, hook: HookVisualizationReport) -> ComparisonSummary:
    baseline_callbacks = {item.callback_id for item in baseline.callback_records if item.executed_count > 0}
    hook_callbacks = {item.callback_id for item in hook.callback_records if item.executed_count > 0}

    metric_deltas = {
        "requests_total_delta": hook.summary.requests_total - baseline.summary.requests_total,
        "executed_callbacks_delta": hook.summary.executed_callbacks_total - baseline.summary.executed_callbacks_total,
        "blindspots_delta": hook.summary.blindspots_total - baseline.summary.blindspots_total,
        "coverage_ratio_delta": hook.summary.coverage_ratio - baseline.summary.coverage_ratio,
        "exceptions_delta": hook.summary.exceptions_count - baseline.summary.exceptions_count,
        "boosted_decisions_delta": hook.summary.boosted_decisions_count - baseline.summary.boosted_decisions_count,
    }
    outcome_deltas = {
        "exceptions_delta": hook.summary.exceptions_count - baseline.summary.exceptions_count,
        "xss_delta": hook.summary.vulnerability_counts.get("WebFuzzXSSVulnCheck", 0)
        - baseline.summary.vulnerability_counts.get("WebFuzzXSSVulnCheck", 0),
    }

    interpretation_flags = []
    if metric_deltas["executed_callbacks_delta"] > 0 and hook_callbacks - baseline_callbacks:
        interpretation_flags.append("hook improved rare callback exploration")
    if (
        metric_deltas["boosted_decisions_delta"] > 0
        and outcome_deltas["exceptions_delta"] <= 0
        and outcome_deltas["xss_delta"] <= 0
    ):
        interpretation_flags.append("hook increased boosts without outcome gains")
    if metric_deltas["executed_callbacks_delta"] <= 0 and hook.summary.avg_priority_delta > 0:
        interpretation_flags.append("hook mostly amplified repeated ajax traffic")

    return ComparisonSummary(
        baseline_label=baseline.metadata.label,
        hook_label=hook.metadata.label,
        metric_deltas=metric_deltas,
        callbacks_only_in_hook=sorted(hook_callbacks - baseline_callbacks),
        callbacks_only_in_baseline=sorted(baseline_callbacks - hook_callbacks),
        outcome_deltas=outcome_deltas,
        interpretation_flags=interpretation_flags,
    )
