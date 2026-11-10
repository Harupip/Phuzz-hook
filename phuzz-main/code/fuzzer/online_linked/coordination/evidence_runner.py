"""Runtime evidence reading and pending runtime candidates for the online-linked coordinator.

``EvidenceRunner`` holds no state of its own: every limit, dependency and piece of
campaign state stays on the coordinator and is read through ``self._host`` each
time it is needed, so overrides assigned on a built coordinator still apply.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from discovery.entrypoints.entrypoints import seed_template_for_callback
from discovery.entrypoints.method_resolution import resolve_http_methods
from online_linked.coordination.candidate_identity import _candidate_context_key, _candidate_identity
from online_linked.coordination.pending_candidates import (
    append_pending_rows,
    fresh_runtime_candidates,
    without_discarded,
)
from online_linked.coordination.request_matching import _runtime_candidate_key
from online_linked.coordination.runtime_discovery import foreign_callback, registered_child_callback
from online_linked.coordination.worker import CommandRunner
from online_linked.evidence import RuntimeBatchTimeout, correlate_runtime_pair
from online_linked.probe_sender import ParentInspectionError, ParentInspectionTimeout


class EvidenceHost(Protocol):
    """The coordinator members ``EvidenceRunner`` reads, writes or calls."""

    state: dict[str, Any]
    clock: Callable[[], float]
    max_seconds: int
    plugin_slug: str
    resume: bool
    run_command: CommandRunner
    runtime_batch_reader: Callable[..., dict[str, Any]]
    _active_container: str
    _active_version: str
    _deadline: float | None
    _gate_convergence: dict[str, Any] | None
    _gate_evidence: dict[str, Any] | None
    _gate_evidence_consumed: bool
    _failure: bool
    _reports: dict[str, dict[str, Any]]
    _seen_pairs: set[tuple[str, str]]

    def _record_event(self, event: Mapping[str, Any], *, checkpoint: bool = True) -> dict[str, Any]: ...
    def _write_state(self) -> None: ...
    def _version(self, name: str) -> dict[str, Any] | None: ...
    def _extend_progress_budget(self, kind: str, key: str) -> float: ...
    def _handle_convergence_result(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        result: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
    ) -> dict[str, Any] | None: ...
    def _observe_parent_exit(self, *, timeout: float | None = None) -> int | None: ...
    def _admission_complete(self, parameter: Any, evidence: Mapping[str, Any], parent: Mapping[str, Any]) -> bool: ...
    def _merge_runtime_registry(self, callback: Mapping[str, Any]) -> None: ...
    def _discover_runtime_candidates(
        self, evidence: Mapping[str, Any], *, deadline: float | None = None,
    ) -> list[dict[str, Any]]: ...


class EvidenceRunner:
    """Reads runtime evidence batches and reconciles pending runtime candidates."""

    __slots__ = ("_host",)

    def __init__(self, host: EvidenceHost) -> None:
        self._host = host

    def read_new_runtime_evidence(self, *, deadline: float | None = None) -> list[dict[str, Any]]:
        """Read one bounded batch, then apply host-side evidence admission."""

        version = self._host._version(self._host._active_version)
        if version is None:
            return []
        remaining = self._host.max_seconds if deadline is None else deadline - self._host.clock()
        if remaining <= 0:
            self.reject_runtime_batch(version, "BUDGET_EXPIRED")
            return []
        started_at = self._host.clock()
        try:
            batch = self._host.runtime_batch_reader(
                run_id=str(version.get("worker_run_id") or ""),
                plugin_slug=self._host.plugin_slug,
                timeout=remaining,
                run_command=self._host.run_command,
            )
        except Exception as exc:
            reason = "BUDGET_EXPIRED" if (
                isinstance(exc, RuntimeBatchTimeout)
                and deadline is not None and self._host.clock() >= deadline
            ) else "RUNTIME_BATCH_READ_FAILED"
            self.reject_runtime_batch(version, reason, detail=str(exc))
            return []
        if deadline is not None and self._host.clock() >= deadline:
            self.reject_runtime_batch(version, "BUDGET_EXPIRED")
            return []
        if not isinstance(batch, Mapping) or not isinstance(batch.get("pairs"), list):
            self.reject_runtime_batch(version, "RUNTIME_BATCH_INVALID_OUTPUT")
            return []

        stats = dict(batch.get("stats") or {}) if isinstance(batch.get("stats"), Mapping) else {}
        stats["paired_count"] = len(batch["pairs"])
        stats["transport_duration_seconds"] = round(max(0.0, self._host.clock() - started_at), 3)
        stats["version"] = str(version["version"])
        stats["worker_run_id"] = str(version.get("worker_run_id") or "")
        stats["remaining_budget"] = max(0.0, remaining)
        stats["last_attempt_complete"] = True
        self._host.state["evidence_scan"] = stats
        if int(stats.get("missing_zend") or 0) > 0:
            self._host._record_event({
                "kind": "EVIDENCE_SCAN", "status": "RETRY",
                "reason": "ZEND_ARTIFACT_MISSING",
                "version": version["version"],
                "worker_run_id": version.get("worker_run_id"),
                "missing_zend": int(stats["missing_zend"]),
            })
        if int(stats.get("invalid_payloads") or 0) > 0:
            self._host._record_event({
                "kind": "EVIDENCE_SCAN", "status": "REJECTED",
                "reason": "RUNTIME_BATCH_INVALID_PAYLOAD",
                "version": version["version"],
                "worker_run_id": version.get("worker_run_id"),
                "invalid_payloads": int(stats["invalid_payloads"]),
            })

        evidence: list[dict[str, Any]] = []
        for pair in batch["pairs"]:
            if deadline is not None and self._host.clock() >= deadline:
                self.reject_runtime_batch(version, "BUDGET_EXPIRED")
                return []
            if not isinstance(pair, Mapping):
                stats["invalid_payloads"] = int(stats.get("invalid_payloads") or 0) + 1
                stats["last_reason"] = "HOST_CORRELATION_REJECTED"
                continue
            runtime_evidence = correlate_runtime_pair(version, pair, plugin_slug=self._host.plugin_slug)
            if runtime_evidence is None:
                continue
            runtime_evidence["evidence_origin"] = "worker_poll"
            request_name = runtime_evidence["request_name"]
            request_payload = runtime_evidence["request"]
            request_id = runtime_evidence["request_id"]
            pair_key = (str(version["version"]), request_id)
            if pair_key in self._host._seen_pairs:
                continue
            if deadline is not None and self._host.clock() >= deadline:
                self.reject_runtime_batch(version, "BUDGET_EXPIRED")
                return []
            discovered = self._host._discover_runtime_candidates(runtime_evidence, deadline=deadline)
            foreign = foreign_callback(request_payload, version)
            if foreign is not None:
                explicit_callback, explicit_hook = foreign
                if any(
                    candidate.get("callback_id") == explicit_callback
                    or candidate.get("hook_name") == explicit_hook
                    for candidate in discovered
                ):
                    self._host._seen_pairs.add(pair_key)
                    continue
                self._host._record_event({
                    "kind": "ACTION_DISCOVERY",
                    "status": "REJECTED",
                    "reason": "ACTION_EXPANSION_NOT_IMPLEMENTED",
                    "version": version["version"],
                    "worker_run_id": version["worker_run_id"],
                    "request_id": request_id,
                    "callback_id": explicit_callback,
                    "hook_name": explicit_hook,
                })
                self._host._seen_pairs.add(pair_key)
                continue
            self._host._seen_pairs.add(pair_key)
            evidence.append(runtime_evidence)
        self._host._write_state()
        return evidence

    def reject_runtime_batch(
        self, version: Mapping[str, Any], reason: str, *, detail: str = "",
    ) -> None:
        budget_expired = reason == "BUDGET_EXPIRED"
        # Budget exhaustion stops observation, but does not revoke verified evidence.
        if budget_expired and self._host.state["terminal_status"] is not None:
            return
        version_record = self._host._version(str(version.get("version") or ""))
        if version_record is not None:
            if not budget_expired:
                version_record["status"] = "not_verified"
            version_record["terminal_reason"] = reason
        if not budget_expired:
            self._host._failure = True
        self._host.state["terminal_status"] = "BOUNDED_ONLINE_COMPLETE" if budget_expired else "NOT_VERIFIED"
        self._host.state["terminal_reason"] = reason
        self._host.state["evidence_scan"].update(last_attempt_complete=False, last_reason=reason)
        self._host._record_event({
            "kind": "EVIDENCE_SCAN", "status": "REJECTED", "reason": reason,
            "version": version.get("version"),
            "worker_run_id": version.get("worker_run_id"),
            **({"detail": detail} if detail else {}),
        })

    def consume_gate_evidence(self, version: Mapping[str, Any], *, deadline: float) -> None:
        if self._host._gate_evidence_consumed or self._host._gate_evidence is None or self._host._gate_convergence is None:
            return
        if not self._host._active_container:
            return
        remaining = deadline - self._host.clock()
        if remaining <= 0:
            self.reject_runtime_batch(version, "BUDGET_EXPIRED")
            return
        try:
            parent_exit_code = self._host._observe_parent_exit(timeout=remaining)
        except (ParentInspectionTimeout, ParentInspectionError) as exc:
            reason = "PARENT_CHECK_TIMEOUT" if isinstance(exc, ParentInspectionTimeout) else "PARENT_CHECK_ERROR"
            self.reject_runtime_batch(version, reason, detail=str(exc))
            return
        if parent_exit_code is not None:
            return
        if self._host.clock() >= deadline:
            self.reject_runtime_batch(version, "BUDGET_EXPIRED")
            return
        parent = self._host._version(str(version["version"]))
        if parent is None:
            return
        raw_report = self._host._reports.get(str(parent["version"]))
        if raw_report is None:
            self.reject_runtime_batch(version, "V0_PROVENANCE_NOT_VERIFIED")
            return
        self._host._gate_evidence["evidence_origin"] = "v0_gate"
        self._host._discover_runtime_candidates(self._host._gate_evidence, deadline=deadline)
        deadline = self._host._deadline or deadline
        if self._host.clock() < deadline:
            self._host._handle_convergence_result(
                parent=parent,
                evidence=self._host._gate_evidence,
                raw_report=raw_report,
                result=self._host._gate_convergence,
                seed=parent["seed_item"],
                deadline=deadline,
            )
        self._host._gate_evidence_consumed = True
        gate_meta = parent.get("gate_evidence")
        if isinstance(gate_meta, dict):
            gate_meta["consumed"] = True
        self._host._seen_pairs.add((str(parent["version"]), str(self._host._gate_evidence["request_id"])))
        self._host._write_state()

    def discover_runtime_candidates(
        self, evidence: Mapping[str, Any], *, deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        """Queue only runtime-registered HTTP callbacks with correlated parent metadata."""
        parent = self._host._version(self._host._active_version)
        request = evidence.get("request") if isinstance(evidence.get("request"), Mapping) else {}
        coverage = request.get("hook_coverage") if isinstance(request, Mapping) else {}
        registered = coverage.get("registered_callbacks") if isinstance(coverage, Mapping) else {}
        if parent is None or not isinstance(registered, Mapping):
            return []

        discovered: list[dict[str, Any]] = []
        parent_callback_id = str(parent.get("callback_id") or "")
        parent_hook_name = str(parent.get("hook_name") or "")
        request_id = str(evidence.get("request_id") or "")
        for fallback_id, raw_callback in registered.items():
            if deadline is not None and self._host.clock() >= deadline:
                break
            registered_child = registered_child_callback(
                fallback_id, raw_callback,
                parent_callback_id=parent_callback_id, parent_hook_name=parent_hook_name,
                request_id=request_id, plugin_slug=self._host.plugin_slug,
            )
            if registered_child is None:
                continue
            callback, callback_id, hook_name = registered_child

            seed_template = seed_template_for_callback(hook_name, callback)
            if seed_template is None:
                self._host._record_event({
                    "kind": "ACTION_DISCOVERY",
                    "status": "BLOCKED",
                    "reason": "ACTION_EXPANSION_SETUP_REQUIRED",
                    "version": parent["version"],
                    "worker_run_id": parent["worker_run_id"],
                    "request_id": request_id,
                    "callback_id": callback_id,
                    "hook_name": hook_name,
                })
                continue

            decisions = resolve_http_methods(
                route_declared_methods=callback.get("methods", callback.get("method")),
                runtime_observation=callback,
                expected_callback=callback,
            )
            for decision in decisions:
                if decision.get("method_status") != "resolved" or not decision.get("replay_allowed"):
                    self._host._record_event({
                        "kind": "ACTION_DISCOVERY",
                        "status": "BLOCKED",
                        "reason": "ACTION_EXPANSION_SETUP_REQUIRED",
                        "detail": decision.get("block_reason") or "HTTP method is not runtime-resolved",
                        "version": parent["version"],
                        "worker_run_id": parent["worker_run_id"],
                        "request_id": request_id,
                        "callback_id": callback_id,
                        "hook_name": hook_name,
                    })
                    continue
                seed = copy.deepcopy(seed_template)
                seed.update(decision)
                seed["seed_variant_id"] = str(decision.get("seed_variant_id") or "")
                entrypoint_type = str(seed.get("entrypoint_type") or callback.get("entrypoint_type") or "")
                candidate = {
                    "callback_id": callback_id,
                    "hook_name": hook_name,
                    "entrypoint_type": entrypoint_type,
                    "seed": seed,
                }
                identity = _candidate_identity(candidate, self._host.plugin_slug)
                context_key = _candidate_context_key(candidate, self._host.plugin_slug)
                if context_key in self._host.state["queued_candidate_context_keys"]:
                    continue
                child = {
                    "hook_name": hook_name,
                    "callback_id": callback_id,
                    "callback_repr": str(callback.get("callback_repr") or callback_id),
                    "seed": seed,
                    "identity": identity,
                    "context_key": context_key,
                    "lineage": {
                        "parent_version": parent["version"],
                        "parent_request_id": request_id,
                        "parent_callback_id": parent_callback_id,
                        "parent_hook_name": parent_hook_name,
                    },
                }
                self._host.state["candidate_queue"].append(child)
                if identity not in self._host.state["queued_candidate_ids"]:
                    self._host.state["queued_candidate_ids"].append(identity)
                self._host.state["queued_candidate_context_keys"].append(context_key)
                discovered.append(child)
                self._host._extend_progress_budget("runtime_callback", context_key)
                deadline = self._host._deadline if deadline is not None else None
                self._host._record_event({
                    "kind": "ACTION_DISCOVERY",
                    "status": "ACCEPTED",
                    "reason": "RUNTIME_REGISTERED_HTTP_CALLBACK",
                    "version": parent["version"],
                    "worker_run_id": parent["worker_run_id"],
                    "request_id": request_id,
                    "callback_id": callback_id,
                    "hook_name": hook_name,
                    "entrypoint_type": entrypoint_type,
                    "resolved_method": decision["resolved_method"],
                    "seed_variant_id": seed["seed_variant_id"],
                    "lineage": child["lineage"],
                })
                self._host._merge_runtime_registry(callback)
        return discovered

    def retain_pending_runtime_candidates(
        self, groups: Sequence[Mapping[str, Any]], parent: Mapping[str, Any],
    ) -> None:
        pending = self._host.state.setdefault("pending_runtime_candidates", [])
        if not isinstance(pending, list):
            pending = []
            self._host.state["pending_runtime_candidates"] = pending
        append_pending_rows(pending, groups, parent)
        if groups:
            self._host._write_state()

    def discard_pending_runtime_candidates(self, groups: Sequence[Mapping[str, Any]]) -> None:
        pending = self._host.state.get("pending_runtime_candidates")
        if not isinstance(pending, list):
            return
        kept = without_discarded(pending, groups)
        if kept is None:
            return
        self._host.state["pending_runtime_candidates"] = kept
        self._host._write_state()

    def reconcile_pending_runtime_candidates(
        self,
        parent: Mapping[str, Any],
        evidence: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        fresh_candidates = fresh_runtime_candidates(result)
        if self._host.resume and not result.get("runtime_block_reason"):
            fresh_keys = {
                _runtime_candidate_key(candidate) for candidate in fresh_candidates
                if self._host._admission_complete({**dict(candidate), "evidence_kind": "fresh_proposal"}, evidence, parent)
            }
            self._host.state["pending_probe_queue"] = [row for row in self._host.state.get("pending_probe_queue", [])
                if _runtime_candidate_key(row["candidate"]) not in fresh_keys]
        pending = self._host.state.get("pending_runtime_candidates")
        if not isinstance(pending, list) or not pending:
            return
        current_request_id = str(evidence.get("request_id") or "")
        current_run_id = str(evidence.get("worker_run_id") or evidence.get("run_id") or "")
        if not current_request_id and not current_run_id:
            return
        remaining = []
        changed = False
        for item in pending:
            if not isinstance(item, Mapping):
                continue
            previous_request_id = str(item.get("request_id") or "")
            previous_run_id = str(item.get("run_id") or "")
            same_context = (
                (not current_request_id or current_request_id == previous_request_id)
                and (not current_run_id or current_run_id == previous_run_id)
            )
            if same_context:
                remaining.append(item)
                continue
            key = _runtime_candidate_key(item)
            matched = next(
                (candidate for candidate in fresh_candidates
                 if _runtime_candidate_key(candidate) == key),
                None,
            )
            if self._host.resume and matched is None:
                # Saved evidence remains a proposal until observed in this run.
                remaining.append(item)
                continue
            self._host._record_event({
                "kind": "PENDING_RUNTIME_CANDIDATE",
                "status": "REQUEUED" if matched is not None else "RETIRED",
                "reason": "FRESH_CHILD_CONTEXT" if matched is not None else "NOT_REOBSERVED_ON_CHILD",
                "version": parent.get("version"),
                "parameter": key[0],
                "source": key[1],
                "location": key[2],
                "previous_request_id": previous_request_id,
                "previous_run_id": previous_run_id,
                "request_id": current_request_id,
                "run_id": current_run_id,
            })
            changed = True
        if changed:
            self._host.state["pending_runtime_candidates"] = remaining
            self._host._write_state()
