"""Probe execution for the online-linked coordinator.

``ProbeRunner`` holds no state of its own: every limit, dependency and piece of
campaign state stays on the coordinator and is read through ``self._host`` each
time it is needed, so overrides assigned on a built coordinator still apply.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from filesystem_paths import filesystem_path
from hook_energy.seed_generation.online_common import _write_exclusive_json
from online_linked.coordination.errors import OnlineLinkedError, ReplayArtifactError
from online_linked.coordination.probe_config import (
    load_correlated_probe_artifacts,
    probe_paths,
    probe_request_row,
    probe_runtime_metadata,
    select_probe_item,
)
from online_linked.coordination.probe_proposals import (
    add_accepted_records,
    drop_queue_row,
    group_accepted_records,
    probe_proposals,
    proposal_result,
)
from online_linked.coordination.probe_results import match_probe_parameters
from online_linked.coordination.request_matching import (
    _is_ajax,
    _method_parameter_key,
    _parameter_key,
    _request_id,
)
from online_linked.probe_sender import ParentInspectionError, ParentInspectionTimeout
from zend_discovery.engine import candidate_from_seed_item, canonical_identity_id


class ProbeHost(Protocol):
    """The coordinator members ``ProbeRunner`` reads, writes or calls."""

    MAX_PROBE_ATTEMPTS: int
    state: dict[str, Any]
    clock: Callable[[], float]
    sleeper: Callable[[float], None]
    run_dir: Path
    config_dir: Path
    config_root: Path
    plugin_slug: str
    legacy_run_id: str
    registry: dict[str, Any]
    runtime_cookie_probes: bool
    max_seconds: int
    probe_sender: Callable[..., dict[str, Any]]
    process_factory: Callable[..., Any]
    converge_fn: Callable[..., dict[str, Any]]
    export_configs_fn: Callable[..., dict[str, Any]]
    force_replay_only_fn: Callable[[dict[str, Any]], None]
    _active_container: str
    _active_version: str
    _failure: bool
    _target_key: str
    _sender_seconds: float
    _deadline: float | None
    _reports: dict[str, dict[str, Any]]
    _worker_started_at: dict[str, float]

    def _record_event(self, event: Mapping[str, Any], *, checkpoint: bool = True) -> dict[str, Any]: ...
    def _write_state(self) -> None: ...
    def _version(self, name: str) -> dict[str, Any] | None: ...
    def _candidate_deadline(self) -> float: ...
    def _extend_progress_budget(self, kind: str, key: str) -> float: ...
    def _gate_v0(self, version: dict[str, Any], config: Mapping[str, Any], *, deadline: float) -> bool: ...
    def _start_worker(
        self,
        version: dict[str, Any],
        *,
        deadline: float | None = None,
        priority_seed: Mapping[str, Any] | None = None,
    ) -> bool: ...
    def _stop_active_worker(self, reason: str) -> None: ...
    def _worker_exit_code(self, timeout: float | None = None) -> int | None: ...
    def _handle_worker_exit(self, worker_exit_code: int) -> None: ...
    def _observe_parent_exit(self, *, timeout: float | None = None) -> int | None: ...
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
    def _retain_pending_runtime_candidates(
        self,
        groups: Sequence[Mapping[str, Any]],
        parent: Mapping[str, Any],
    ) -> None: ...
    def _discard_pending_runtime_candidates(self, groups: Sequence[Mapping[str, Any]]) -> None: ...
    def _inherit_callback_identity(
        self,
        parameter: Mapping[str, Any],
        parent: Mapping[str, Any],
    ) -> dict[str, Any]: ...
    def _probe_context_key(
        self,
        parent: Mapping[str, Any],
        probe: Mapping[str, Any],
        evidence: Mapping[str, Any],
    ) -> str: ...
    def _probe_admission_complete(
        self,
        parameter: Mapping[str, Any],
        evidence: Mapping[str, Any],
        parent: Mapping[str, Any],
    ) -> bool: ...
    def _restore_request_values(
        self,
        config: dict[str, Any],
        evidence: Mapping[str, Any],
        parent: Mapping[str, Any],
        *,
        only_parameters: set[tuple[str, str, str]] | None = None,
    ) -> None: ...
    def _save_replay_artifacts(
        self,
        row: Mapping[str, Any],
        request_dir: Path,
        zend_dir: Path,
        *,
        strict_correlation: bool | None = None,
    ) -> None: ...
    @staticmethod
    def _sender_runner_row(
        base: Mapping[str, Any],
        result: Mapping[str, Any],
        run_id: str,
    ) -> dict[str, Any]: ...
    def _run_pending_probe(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        convergence: Mapping[str, Any],
        probe: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
    ) -> dict[str, Any] | None: ...
    def _run_pending_probe_once(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        convergence: Mapping[str, Any],
        probe: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
    ) -> dict[str, Any] | None: ...


class ProbeRunner:
    """Run probe replays for a coordinator, reading all state through the host."""

    __slots__ = ("_host",)

    def __init__(self, host: ProbeHost) -> None:
        self._host = host

    def drain_pending_probes(self) -> None:
        for pending in list(self._host.state.get("pending_probe_queue", [])):
            if self._host.clock() >= self._host._candidate_deadline() or self._host.state["terminal_status"] is not None or not self._host._active_container:
                break
            if pending not in self._host.state.get("pending_probe_queue", []):
                continue
            parent = self._host._version(pending["parent_version"])
            if parent is None or parent.get("seed_item") is None or parent["version"] not in self._host._reports:
                self._host._failure = True
                self._host.state.update(terminal_status="NOT_VERIFIED", terminal_reason="PENDING_PARENT_CONTEXT_MISSING")
                self._host._write_state()
                break
            if parent["version"] != self._host._active_version:
                self._host._stop_active_worker("RESUME_PENDING_PARENT")
                if self._host._active_container:
                    break
                self._host._active_version = parent["version"]
                candidate = candidate_from_seed_item(parent["seed_item"], plugin_slug=self._host.plugin_slug)
                variant = str(parent["seed_item"]["seed"].get("seed_variant_id") or "")
                self._host._target_key = canonical_identity_id(candidate) + (f"::{variant}" if variant else "")
                parent["previous_worker_run_id"] = parent.get("worker_run_id")
                parent.setdefault("readiness_history", []).append(copy.deepcopy(parent.get("readiness")))
                activation = len(parent["readiness_history"])
                parent["worker_run_id"] = f"{self._host.legacy_run_id}-{parent['version']}-resume-{self._host.state.get('resume_count', 0)}-activation-{activation}"
                parent_path = Path(parent.get("replay_config_path") or parent["config_path"])
                parent_config = json.loads(filesystem_path(parent_path).read_text(encoding="utf-8-sig"))
                if not self._host._gate_v0(parent, parent_config, deadline=self._host._deadline):
                    break
                if not self._host._start_worker(parent, deadline=self._host._deadline):
                    self._host.state.update(terminal_status="NOT_VERIFIED", terminal_reason="RESUME_PARENT_WORKER_START_FAILED")
                    break
            convergence = dict(pending["convergence"])
            # Saved requests are proposals, never accepted evidence.
            convergence.update(new_parameters=[], known_parameters=parent.get("known_parameters", []),
                               pending_probes=[pending["candidate"]])
            self._host._run_pending_probe(
                parent=parent, evidence=pending["evidence"], raw_report=self._host._reports[parent["version"]],
                convergence=convergence, probe=pending["candidate"], seed=parent["seed_item"],
                deadline=self._host._deadline,
            )
            if self._host.state["terminal_status"] is not None:
                break

    def run_light_sender(
        self,
        *,
        config_path: Path,
        request_id: str,
        run_id: str,
        hook_name: str,
        callback_id: str,
        method: str,
        auth_context: str,
        deadline: float | None,
        seed_variant_id: str = "",
        allow_error_responses: bool = False,
    ) -> dict[str, Any]:
        if not self._host._active_container:
            return {"status": "parent_container_missing", "error": "PARENT_CONTAINER_MISSING"}
        timeout = self._host.max_seconds
        if deadline is not None:
            timeout = min(30, max(0, deadline - self._host.clock()))
        if timeout <= 0:
            return {"status": "timeout", "error": "SENDER_BUDGET_EXPIRED"}
        config_slug = config_path.relative_to(self._host.config_root).with_suffix("").as_posix()
        started = self._host.clock()
        result = self._host.probe_sender(
            self._host._active_container,
            config_slug=config_slug,
            request_id=request_id,
            run_id=run_id,
            timeout_seconds=timeout,
            expected={
                "plugin_slug": self._host.plugin_slug,
                "hook_name": hook_name,
                "callback_id": callback_id,
                "method": method,
                "auth_context": auth_context,
                "seed_variant_id": seed_variant_id,
                "allow_error_responses": allow_error_responses,
            },
            process_factory=self._host.process_factory,
            parent_exit_code=self._host._worker_exit_code,
            clock=self._host.clock,
            sleeper=self._host.sleeper,
        )
        if (isinstance(result, Mapping)
                and (result.get("status") == "callback_reached" or result.get("callback_reached") is True)
                and (deadline is None or self._host.clock() < deadline)):
            self._host._sender_seconds = max(self._host._sender_seconds, self._host.clock() - started)
        return dict(result) if isinstance(result, Mapping) else {"status": "sender_invalid"}

    def recover_parent_after_failure(self, parent: Mapping[str, Any], deadline: float | None) -> bool:
        if self._host._active_container:
            return True
        if deadline is not None and self._host.clock() >= deadline:
            return False
        parent_record = self._host._version(str(parent["version"]))
        if parent_record is not None and self._host._start_worker(parent_record, deadline=deadline):
            self._host._active_version = str(parent_record["version"])
            return True
        self._host._failure = True
        self._host.state["terminal_status"] = "NOT_VERIFIED"
        self._host.state["terminal_reason"] = "PARENT_WORKER_RESTART_FAILED"
        self._host._write_state()
        return False

    def reject_child_attempt(
        self,
        parent: Mapping[str, Any],
        attempt: dict[str, Any],
        discovery: Mapping[str, Any],
        reason: str,
        deadline: float | None,
        *,
        detail: str = "",
    ) -> None:
        attempt.update(status="failed", reason=reason)
        if detail:
            attempt["error"] = detail
        self._host._record_event({
            **dict(discovery), "event_id": "", "status": "REJECTED", "reason": reason,
            **({"detail": detail} if detail else {}),
        })
        self.recover_parent_after_failure(parent, deadline)
        return None

    def run_pending_probe(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        convergence: Mapping[str, Any],
        probe: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
    ) -> dict[str, Any] | None:
        """Try pending candidates, prioritizing accepted evidence before a deadline.

        Calls without a deadline retain unlimited batching; bounded calls stop
        admitting optional probes once accepted evidence is available so the
        child handoff keeps the remaining budget.
        """
        pending = convergence.get("pending_probes")
        initial_candidates = pending if isinstance(pending, list) and pending else [probe]
        queue: list[dict[str, Any]] = []
        queued_keys: set[str] = set()

        def enqueue(
            candidate: Mapping[str, Any],
            candidate_convergence: Mapping[str, Any],
            candidate_evidence: Mapping[str, Any],
        ) -> None:
            if not isinstance(candidate, Mapping):
                return
            dedupe_key = self._host._probe_context_key(parent, candidate, candidate_evidence)
            if dedupe_key in queued_keys:
                return
            queued_keys.add(dedupe_key)
            queue.append({
                "candidate": copy.deepcopy(dict(candidate)),
                "convergence": copy.deepcopy(dict(candidate_convergence)),
                "evidence": copy.deepcopy(dict(candidate_evidence)),
            })
            saved_queue = self._host.state.setdefault("pending_probe_queue", [])
            if not any(row.get("dedupe_key") == dedupe_key for row in saved_queue):
                saved_queue.append({**copy.deepcopy(queue[-1]), "dedupe_key": dedupe_key,
                                    "parent_version": parent["version"]})

        for candidate in sorted(initial_candidates, key=_parameter_key):
            enqueue(candidate, convergence, evidence)
        self._host._write_state()
        probe_deadline = None
        if deadline is not None:
            self._host._candidate_deadline()
            started = self._host.clock()
            probe_deadline = started + max(0.0, (deadline - started) / 2)
        accepted = [
            self._host._inherit_callback_identity(item, parent) for item in convergence.get("new_parameters", [])
            if isinstance(item, Mapping)
        ] if isinstance(convergence.get("new_parameters"), list) else []
        accepted_keys: set[tuple[str, tuple[str, str, str]]] = set()
        accepted_records: list[dict[str, Any]] = []
        add_accepted_records(accepted_records, accepted_keys, accepted, evidence, convergence)
        deferred: list[dict[str, Any]] = []
        if accepted and probe_deadline is not None:
            deferred = [dict(item["candidate"]) for item in queue]
            queue = []
        index = 0
        while index < len(queue):
            queue_item = queue[index]
            candidate = queue_item["candidate"]
            candidate_convergence = queue_item["convergence"]
            candidate_evidence = queue_item["evidence"]
            if probe_deadline is not None:
                effective_deadline = probe_deadline
                if accepted_records:
                    effective_deadline = min(probe_deadline, deadline - 2 * self._host._sender_seconds)
                if self._host.clock() + self._host._sender_seconds >= effective_deadline:
                    deferred = [dict(item["candidate"]) for item in queue[index:]]
                    break
            index += 1
            if candidate.get("method_probe") is not True and _method_parameter_key(
                candidate, str(candidate.get("probe_method") or parent.get("resolved_method") or ""),
            ) in accepted_keys:
                # A saved per-field probe whose field an earlier trace already proved.
                self._host.state["pending_probe_queue"] = drop_queue_row(
                    self._host.state.get("pending_probe_queue", []), parent_version=parent["version"],
                    candidate=candidate, evidence=candidate_evidence,
                )
                self._host._record_event({
                    "kind": "PARAMETER_PROBE", "status": "SKIPPED", "reason": "ADMITTED_FROM_TRACE",
                    "version": parent["version"], "request_id": candidate.get("request_id"),
                    "candidate": dict(candidate),
                })
                continue
            outcome = self._host._run_pending_probe_once(
                parent=parent, evidence=candidate_evidence, raw_report=raw_report,
                convergence=candidate_convergence, probe=candidate,
                seed=seed, deadline=effective_deadline if probe_deadline is not None else None,
            )
            if deadline is not None and isinstance(outcome, Mapping) and outcome.get("status") == "accepted":
                deadline = max(deadline, self._host._candidate_deadline())
                probe_deadline = max(probe_deadline, deadline - 2 * self._host._sender_seconds)
            self._host.state["pending_probe_queue"] = drop_queue_row(
                self._host.state.get("pending_probe_queue", []), parent_version=parent["version"],
                candidate=candidate, evidence=candidate_evidence,
            )
            self._host._write_state()
            if not isinstance(outcome, Mapping) or outcome.get("status") != "accepted":
                if isinstance(outcome, Mapping) and outcome.get("status") == "pending":
                    pending_result = outcome.get("result")
                    pending_candidates = pending_result.get("pending_probes") if isinstance(pending_result, Mapping) else None
                    if isinstance(pending_candidates, list) and isinstance(pending_result, Mapping):
                        pending_evidence = outcome.get("evidence")
                        pending_evidence = (
                            pending_evidence if isinstance(pending_evidence, Mapping) else candidate_evidence
                        )
                        for item in pending_candidates:
                            enqueue(item, pending_result, pending_evidence)
                        self._host._write_state()
                if self._host.state.get("terminal_status") or (
                    not self._host._active_container and
                    (deadline is not None and self._host.clock() >= deadline)
                ):
                    break
                if probe_deadline is not None and self._host.clock() >= probe_deadline:
                    deferred = [dict(item["candidate"]) for item in queue[index:]]
                    break
                continue
            parameter = outcome.get("parameter")
            probe_evidence = outcome.get("evidence")
            if not isinstance(parameter, Mapping) or not isinstance(probe_evidence, Mapping):
                continue
            trace_parameters = outcome.get("parameters")
            if not isinstance(trace_parameters, list) or not trace_parameters:
                trace_parameters = [parameter]
            add_accepted_records(
                accepted_records, accepted_keys, trace_parameters, probe_evidence,
                outcome.get("result") if isinstance(outcome.get("result"), Mapping) else {},
            )
            probe_result = outcome.get("result")
            next_probes = probe_result.get("pending_probes") if isinstance(probe_result, Mapping) else None
            if isinstance(next_probes, list):
                for next_probe in next_probes:
                    enqueue(next_probe, probe_result, probe_evidence)
            request = probe_evidence.get("request") or {}
            status = (request.get("response") or {}).get("status_code")
            if deadline is not None and (status is None or 200 <= status < 300):
                deferred = [dict(item["candidate"]) for item in queue[index:]]
                break
        for candidate in deferred:
            self._host._record_event({
                "kind": "PARAMETER_PROBE",
                "status": "DEFERRED",
                "reason": "PROBE_BUDGET_RESERVED_FOR_CHILD",
                "version": parent["version"],
                "request_id": candidate.get("request_id") or evidence.get("request_id"),
                "candidate": candidate,
            }, checkpoint=False)
        if deferred:
            self._host._write_state()
        if not accepted_records:
            return None

        ordered_groups = group_accepted_records(accepted_records)
        self._host._retain_pending_runtime_candidates(ordered_groups, parent)
        proposals = probe_proposals(ordered_groups, accepted_records)

        existing = parent.get("known_parameters", [])
        existing = [dict(item) for item in existing if isinstance(item, Mapping)] if isinstance(existing, list) else []
        for group in proposals:
            # Consume only the proposal currently entering admission. If its
            # callback baseline fails, the remaining groups keep the parent
            # recoverable and are tried as separate coherent proposals.
            if not group.get("combined"):
                self._host._discard_pending_runtime_candidates([group])
            final_result = proposal_result(
                group, convergence=convergence, existing=existing, deferred=deferred,
                evidence_origin=str(evidence.get("evidence_origin") or "worker_poll"),
                target_key=self._host._target_key,
            )
            child = self._host._handle_convergence_result(
                parent=parent, evidence=group["evidence"], raw_report=raw_report,
                result=final_result, seed=seed, deadline=deadline,
            )
            if child is not None:
                if group.get("combined") and (child.get("replay_result") or {}).get("passed") is True:
                    self._host._discard_pending_runtime_candidates(ordered_groups)
                    self._host._write_state()
                return child
            if self._host.state.get("terminal_status") or not self._host._active_container:
                break
        return None

    def run_pending_probe_once(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        convergence: Mapping[str, Any],
        probe: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
    ) -> dict[str, Any] | None:
        """Replay one artifact-derived AJAX probe, then re-enter admission."""
        attempts = self._host.state.setdefault("probe_attempts", [])
        dedupe_key = self._host._probe_context_key(parent, probe, evidence)
        if any(item.get("dedupe_key") == dedupe_key for item in attempts if isinstance(item, Mapping)):
            self._host._record_event({
                "kind": "PARAMETER_PROBE", "status": "SKIPPED", "reason": "PROBE_ALREADY_ATTEMPTED",
                "version": parent["version"], "request_id": evidence.get("request_id"),
                "candidate": dict(probe), "dedupe_key": dedupe_key,
            })
            return {"status": "skipped"}
        if len(attempts) >= self._host.MAX_PROBE_ATTEMPTS:
            self._host._record_event({
                "kind": "PARAMETER_PROBE", "status": "REJECTED", "reason": "PROBE_BUDGET_EXHAUSTED",
                "version": parent["version"], "request_id": evidence.get("request_id"),
                "candidate": dict(probe),
            })
            return None
        probe_item = select_probe_item(convergence, probe)
        if probe_item is None:
            return self._finish_probe_failure(parent, evidence, None, "PROBE_CONFIG_MISSING", deadline)
        if deadline is not None and self._host.clock() >= deadline:
            return self._finish_probe_failure(parent, evidence, None, "PROBE_BUDGET_EXPIRED", deadline)

        probe_id = f"p{len(attempts) + 1}"
        probe_run_id = f"{parent['worker_run_id']}-probe-{probe_id}"
        evidence_origin = str(evidence.get("evidence_origin") or "worker_poll")
        remaining_budget = None if deadline is None else max(0.0, deadline - self._host.clock())
        first_probe_for_version = not any(
            isinstance(item, Mapping) and item.get("parent_version") == parent["version"]
            for item in attempts
        )
        first_probe_delay = None
        if first_probe_for_version:
            worker_started_at = self._host._worker_started_at.get(str(parent["version"]))
            if worker_started_at is not None:
                first_probe_delay = max(0.0, self._host.clock() - worker_started_at)
        paths = probe_paths(run_dir=self._host.run_dir, config_dir=self._host.config_dir,
                            version=str(parent["version"]), probe_id=probe_id)
        probe_root = paths.root
        generated_dir = paths.generated_dir
        generated_summary_path = paths.generated_summary
        attempt: dict[str, Any] = {
            "probe_id": probe_id, "parent_version": parent["version"],
            "request_id": evidence.get("request_id"), "status": "exporting",
            "candidate": dict(probe), "probe_run_id": probe_run_id, "dedupe_key": dedupe_key,
            "evidence_origin": evidence_origin,
            "remaining_budget_seconds": remaining_budget,
            "first_probe_delay_seconds": first_probe_delay,
            "_started_at": self._host.clock(),
        }
        attempts.append(attempt)
        self._host._write_state()
        try:
            filesystem_path(generated_dir).mkdir(parents=True, exist_ok=True)
            filesystem_path(generated_summary_path.parent).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_PREPARE_FAILED", deadline, detail=str(exc))
        try:
            generated = self._host.export_configs_fn(
                {"suggested_seeds": [dict(probe_item)]},
                output_config_dir=generated_dir,
                summary_path=generated_summary_path,
                target_base="http://web",
                replay_only=True,
                rest_route_fallback=True, compact_names=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_EXPORT_FAILED", deadline, detail=str(exc))
        rows = generated.get("generated") if isinstance(generated, Mapping) else None
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_EXPORT_FAILED", deadline)
        generated_path = Path(str(rows[0].get("config_path") or ""))
        if not filesystem_path(generated_path).is_file():
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_MISSING", deadline)
        try:
            probe_config = json.loads(filesystem_path(generated_path).read_text(encoding="utf-8-sig"))
            self._host._restore_request_values(probe_config, evidence, parent)
            probe_metadata = probe_config.setdefault("metadata", {})
            if not isinstance(probe_metadata, dict):
                raise OnlineLinkedError("PROBE_CONFIG_METADATA_INVALID")
            probe_metadata["zend_runtime_probe"] = probe_runtime_metadata(probe)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_INVALID", deadline, detail=str(exc))
        probe_config_path = paths.config
        probe_mirror_path = paths.config_mirror
        replay_path = paths.replay
        replay_mirror_path = paths.replay_mirror
        try:
            _write_exclusive_json(probe_config_path, probe_config)
            _write_exclusive_json(probe_mirror_path, probe_config)
            replay_config = copy.deepcopy(probe_config)
            self._host.force_replay_only_fn(replay_config)
            _write_exclusive_json(replay_path, replay_config)
            _write_exclusive_json(replay_mirror_path, replay_config)
        except (OSError, RuntimeError, ValueError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_WRITE_FAILED", deadline, detail=str(exc))
        attempt.update(config_path=str(probe_config_path), replay_config_path=str(replay_path), status="replaying")
        self._host._record_event({
            "kind": "PARAMETER_PROBE", "status": "PENDING", "reason": "ZEND_RUNTIME_CANDIDATE",
            "version": parent["version"], "worker_run_id": parent["worker_run_id"],
            "request_id": evidence.get("request_id"), "probe_id": probe_id,
            "probe_run_id": probe_run_id, "candidate": dict(probe),
            "evidence_origin": evidence_origin,
            "remaining_budget_seconds": attempt.get("remaining_budget_seconds"),
            "first_probe_delay_seconds": attempt.get("first_probe_delay_seconds"),
        })
        probe_row, probe_parent, method_transition = probe_request_row(
            probe_item, parent, replay_path=replay_path, config_root=self._host.config_root,
        )
        timeout = deadline - self._host.clock() if deadline is not None else self._host.max_seconds
        if timeout <= 0:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_BUDGET_EXPIRED", deadline)
        try:
            sender_result = self.run_light_sender(
                config_path=replay_path,
                request_id=_request_id(probe_run_id),
                run_id=probe_run_id,
                hook_name=probe_row["hook_name"],
                callback_id=probe_row["callback_id"],
                method=probe_row["resolved_method"],
                auth_context=str(parent.get("auth_context") or "authenticated"),
                seed_variant_id=probe_row["seed_variant_id"],
                allow_error_responses=True,
                deadline=deadline,
            )
        except Exception as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_REPLAY_FAILED", deadline, detail=str(exc))
        attempt["diagnostics"] = sender_result.get("diagnostics")
        if sender_result.get("status") == "parent_stopped":
            exit_code = sender_result.get("parent_exit_code")
            if isinstance(exit_code, int):
                self._host._handle_worker_exit(exit_code)
            return self._finish_probe_failure(
                parent, evidence, attempt, "PARENT_WORKER_EXITED_DURING_PROBE", deadline,
                detail=str(sender_result.get("error") or "parent worker exited"),
            )
        if sender_result.get("status") == "parent_container_missing":
            self._host._failure = True
            self._host._active_container = ""
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = "PARENT_CONTAINER_MISSING"
            return self._finish_probe_failure(
                parent, evidence, attempt, "PARENT_CONTAINER_MISSING", deadline,
                detail=str(sender_result.get("error") or "PARENT_CONTAINER_MISSING"),
            )
        if sender_result.get("status") in {"parent_check_timeout", "parent_check_error"}:
            reason = "PARENT_CHECK_TIMEOUT" if sender_result.get("status") == "parent_check_timeout" else "PARENT_CHECK_ERROR"
            return self._finish_probe_failure(
                parent, evidence, attempt, reason, deadline,
                detail=str(sender_result.get("error") or reason),
            )
        parent_timeout = None if deadline is None else deadline - self._host.clock()
        if parent_timeout is not None and parent_timeout <= 0:
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_BUDGET_EXPIRED", deadline,
            )
        try:
            parent_exit_code = self._host._observe_parent_exit(timeout=parent_timeout)
        except (ParentInspectionTimeout, ParentInspectionError) as exc:
            reason = "PARENT_CHECK_TIMEOUT" if isinstance(exc, ParentInspectionTimeout) else "PARENT_CHECK_ERROR"
            return self._finish_probe_failure(
                parent, evidence, attempt, reason, deadline, detail=str(exc),
            )
        if parent_exit_code is not None:
            return self._finish_probe_failure(
                parent, evidence, attempt, "PARENT_WORKER_EXITED_DURING_PROBE", deadline,
                detail="parent worker exited after sender completed",
            )
        attempt["timing"] = dict(sender_result.get("timing") or {})
        attempt["_verify_started_at"] = self._host.clock()
        replay_row = self._host._sender_runner_row(probe_row, sender_result, probe_run_id)
        probe_report = {
            "legacy_run_id": probe_run_id,
            "runs": [replay_row],
            "timing": dict(sender_result.get("timing") or {}),
        }
        if (
            replay_row.get("callback_reached") is not True
            or replay_row.get("validation_status") != "callback_reached"
            or replay_row.get("process_status") in {"failed", "runner_error", "window_elapsed"}
        ):
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_CALLBACK_NOT_REACHED", deadline,
                detail=str(sender_result.get("error") or "callback not reached"),
            )
        request_dir = probe_root / "request"
        zend_dir = probe_root / "zend"
        try:
            self._host._save_replay_artifacts(replay_row, request_dir, zend_dir)
            artifact_name = str(replay_row.get("matched_artifact") or "")
            request_path, probe_request, zend_path, probe_zend = load_correlated_probe_artifacts(
                request_dir, zend_dir, artifact_name, probe_run_id,
            )
        except ReplayArtifactError as exc:
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_ARTIFACT_CORRELATION_FAILED", deadline,
                detail=str(exc), extra={"artifact_stage": exc.stage},
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_ARTIFACT_CORRELATION_FAILED", deadline,
                detail=str(exc), extra={"artifact_stage": "id_correlation"},
            )

        probe_evidence = {
            "version": parent["version"], "worker_run_id": probe_run_id,
            "request_name": artifact_name, "request_id": request_path.stem,
            "request": dict(probe_request), "zend_name": zend_path.name, "zend": dict(probe_zend),
        }
        try:
            probe_result = self._host.converge_fn(
                raw_report={"suggested_seeds": [dict(probe_item)]},
                pass_run_summary={"legacy_run_id": probe_run_id, "runs": [{
                    **probe_row, "callback_reached": True, "matched_artifact": artifact_name,
                    "process_status": "replaying",
                }]},
                pass_artifacts_dir=request_dir, zend_events_dir=zend_dir, registry=self._host.registry,
                plugin_slug=self._host.plugin_slug, legacy_run_id=probe_run_id,
                known_state={"known_parameters": [] if method_transition else parent.get("known_parameters", [])}, candidate_key=None,
                runtime_cookie_probes=self._host.runtime_cookie_probes,
                # A guard first reached by a field probe on a field it did not send gets its own
                # probe. A method probe stays one batch: like the worker trace it is the first
                # request of its method, and only its POST fields may prove that method.
                probe_unsent_guards=probe.get("method_probe") is not True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONVERGENCE_FAILED", deadline, detail=str(exc))
        probe_parameters = probe_result.get("new_parameters") if isinstance(probe_result, Mapping) else None
        observed_parameters = probe_result.get("observed_parameters") if isinstance(probe_result, Mapping) else None
        all_probe_parameters = []
        if isinstance(probe_parameters, list):
            all_probe_parameters.extend(probe_parameters)
        if isinstance(observed_parameters, list):
            all_probe_parameters.extend(observed_parameters)
        if not all_probe_parameters:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_NO_CORRELATED_READ", deadline)
        match = match_probe_parameters(probe, probe_parameters, all_probe_parameters, ajax=_is_ajax(parent))
        matching, trace_parameters = match.matching, match.trace_parameters
        pending_matching, unexpected = match.pending_matching, match.unexpected
        if not matching and pending_matching:
            parameter = self._host._inherit_callback_identity(pending_matching[0], parent)
            return self._finish_probe_pending(
                parent, evidence, attempt, probe_evidence, probe_result, parameter,
            )
        if not matching:
            if unexpected:
                attempt["unexpected_parameters"] = unexpected
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_TARGET_MISMATCH", deadline,
                extra={"unexpected_parameters": unexpected},
            )
        matching_keys = {_parameter_key(parameter) for parameter in matching}
        admitted: list[dict[str, Any]] = []
        for candidate_parameter in trace_parameters:
            normalized = self._host._inherit_callback_identity(candidate_parameter, parent)
            if self._host._probe_admission_complete(normalized, probe_evidence, probe_parent):
                admitted.append(normalized)
        if not any(_parameter_key(parameter) in matching_keys for parameter in admitted):
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_PROVENANCE_INCOMPLETE", deadline,
                extra={"unexpected_parameters": unexpected},
            )
        unexpected = [
            parameter for parameter in unexpected
            if _parameter_key(parameter) not in {_parameter_key(item) for item in admitted}
        ]
        parameter = next(item for item in admitted if _parameter_key(item) in matching_keys)
        # Credit the verified reads before checkpointing or queuing more guards.
        for item in admitted:
            key = json.dumps([parent.get("callback_id"), _parameter_key(item)])
            self._host._extend_progress_budget("verified_parameter", key)
        if method_transition:
            probe_result = dict(probe_result)
            # Materialize the request just replayed, never its prospective probes.
            probe_result["method_transition_report"] = {"suggested_seeds": [copy.deepcopy(dict(probe_item))]}
        if unexpected:
            attempt["unexpected_parameters"] = unexpected
        attempt.update(status="accepted", probe_request_id=probe_evidence["request_id"])
        timing = dict(attempt.get("timing") or {})
        timing["verify"] = round(self._host.clock() - float(attempt.pop("_verify_started_at", self._host.clock())), 3)
        timing["total"] = round(self._host.clock() - float(attempt.pop("_started_at", self._host.clock())), 3)
        attempt["timing"] = timing
        self._host._record_event({
            "kind": "PARAMETER_PROBE", "status": "ACCEPTED", "reason": "CORRELATED_ZEND_READ",
            "version": parent["version"], "worker_run_id": probe_run_id,
            "request_id": probe_evidence["request_id"], "probe_id": probe_id,
            "hook_name": probe_row["hook_name"], "candidate": dict(probe), "parameter": dict(parameter),
            "parameters": [dict(item) for item in admitted],
            "timing": timing,
            "evidence_origin": attempt.get("evidence_origin"),
            "remaining_budget_seconds": attempt.get("remaining_budget_seconds"),
            "first_probe_delay_seconds": attempt.get("first_probe_delay_seconds"),
            **({"unexpected_parameters": unexpected} if unexpected else {}),
        })
        return {
            "status": "accepted",
            "parameter": dict(parameter),
            "parameters": [dict(item) for item in admitted],
            "evidence": probe_evidence,
            "result": probe_result,
        }

    def _finish_probe_pending(
        self,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        attempt: dict[str, Any],
        probe_evidence: Mapping[str, Any],
        probe_result: Mapping[str, Any],
        parameter: Mapping[str, Any],
    ) -> dict[str, Any]:
        attempt.update(status="pending", reason="CORRELATED_CANDIDATE_NOT_ADMITTED")
        attempt["probe_request_id"] = probe_evidence.get("request_id")
        timing = dict(attempt.get("timing") or {})
        timing["verify"] = round(self._host.clock() - float(attempt.pop("_verify_started_at", self._host.clock())), 3)
        timing["total"] = round(self._host.clock() - float(attempt.pop("_started_at", self._host.clock())), 3)
        attempt["timing"] = timing
        self._host._record_event({
            "kind": "PARAMETER_PROBE", "status": "PENDING",
            "reason": "CORRELATED_CANDIDATE_NOT_ADMITTED",
            "version": parent["version"], "worker_run_id": attempt.get("probe_run_id"),
            "request_id": probe_evidence.get("request_id") or evidence.get("request_id"),
            "probe_id": attempt.get("probe_id"), "candidate": dict(attempt.get("candidate") or {}),
            "parameter": dict(parameter), "timing": timing,
            "evidence_origin": attempt.get("evidence_origin"),
            "remaining_budget_seconds": attempt.get("remaining_budget_seconds"),
            "first_probe_delay_seconds": attempt.get("first_probe_delay_seconds"),
            "candidate_status": parameter.get("candidate_status"),
            "candidate_reason": parameter.get("candidate_reason"),
        })
        self._host._write_state()
        return {
            "status": "pending",
            "parameter": dict(parameter),
            "evidence": dict(probe_evidence),
            "result": dict(probe_result),
        }

    def _finish_probe_failure(
        self,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        attempt: dict[str, Any] | None,
        reason: str,
        deadline: float | None,
        *,
        detail: str = "",
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        timing: dict[str, Any] = {}
        if attempt is not None:
            attempt.update(status="failed", reason=reason)
            if detail:
                attempt["error"] = detail
            timing = dict(attempt.get("timing") or {})
            verify_started_at = attempt.pop("_verify_started_at", None)
            started_at = attempt.pop("_started_at", None)
            if verify_started_at is not None:
                timing["verify"] = round(self._host.clock() - float(verify_started_at), 3)
            if started_at is not None:
                timing["total"] = round(self._host.clock() - float(started_at), 3)
            attempt["timing"] = timing
        self._host._record_event({
            "kind": "PARAMETER_PROBE", "status": "REJECTED", "reason": reason,
            "version": parent["version"], "request_id": evidence.get("request_id"),
            "hook_name": parent.get("hook_name"),
            "probe_id": attempt.get("probe_id") if attempt else None,
            "probe_run_id": attempt.get("probe_run_id") if attempt else None,
            "parameter": (attempt.get("candidate") or {}).get("name") if attempt else None,
            "timing": timing,
            "evidence_origin": attempt.get("evidence_origin") if attempt else str(evidence.get("evidence_origin") or "worker_poll"),
            "remaining_budget_seconds": attempt.get("remaining_budget_seconds") if attempt else (
                None if deadline is None else max(0.0, deadline - self._host.clock())
            ),
            "first_probe_delay_seconds": attempt.get("first_probe_delay_seconds") if attempt else None,
            **(dict(extra) if isinstance(extra, Mapping) else {}),
            **({"detail": detail} if detail else {}),
        })
        self._host._write_state()
        return None
