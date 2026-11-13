"""Handoff and worker lifecycle for the online-linked coordinator."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from hook_energy.seed_generation.generated_config_runner import STOP_ON_VULN_EXIT_CODE
from online_linked.coordination.errors import ReplayArtifactError
from online_linked.coordination.gate_replay import load_gate_evidence
from online_linked.coordination.handoff_replay import handoff_replay_row, replay_failure_reason
from online_linked.coordination.priority_descriptor import (
    missing_verified_fields,
    priority_descriptor,
    priority_targets,
    verified_fields,
)
from online_linked.coordination.probe_results import replay_verdict
from online_linked.coordination.probe_runner import ProbeRunner
from online_linked.coordination.request_matching import _is_ajax, _request_id
from online_linked.coordination.worker import (
    CommandRunner,
    handoff_command,
    matching_pause_ack,
    parallel_node_id,
    remove_container,
    worker_container_name,
    worker_start_command,
)
from online_linked.export import (
    PARAMETER_REPLAY_POLICY,
    config_fields as _config_fields,
    config_fuzzable_fields as _config_fuzzable_fields,
)
from online_linked.probe_sender import ParentInspectionError, ParentInspectionTimeout
from zend_discovery.engine import candidate_from_seed_item, canonical_identity_id


class WorkerHost(Protocol):
    """Coordinator members the worker runner reads, writes or calls."""

    state: dict[str, Any]
    clock: Callable[[], float]
    sleeper: Callable[[float], None]
    run_command: CommandRunner
    config_root: Path
    run_dir: Path
    legacy_run_id: str
    plugin_slug: str
    service: str
    max_seconds: int
    priority_energy_mode: str
    _sender_seconds: float
    _deadline: float | None
    _reports: dict[str, dict[str, Any]]
    _replay_evidence: dict[str, dict[str, Any]]
    _replay_discovery_active: bool
    _worker_started_at: dict[str, float]
    _active_container: str
    _active_version: str
    _failure: bool
    _pause: dict[str, str] | None
    _target_key: str

    @property
    def _probes(self) -> ProbeRunner: ...

    def _record_event(self, event: Mapping[str, Any], *, checkpoint: bool = True) -> dict[str, Any]: ...
    def _write_state(self) -> None: ...
    def _version(self, name: str) -> dict[str, Any] | None: ...
    def _attach_finding_artifact(self, version: Mapping[str, Any] | None) -> None: ...
    def _sender_runner_row(
        self, base: Mapping[str, Any], result: Mapping[str, Any], run_id: str,
    ) -> dict[str, Any]: ...
    def _save_replay_artifacts(
        self, row: Mapping[str, Any], request_dir: Path, zend_dir: Path,
        *, strict_correlation: bool | None = None,
    ) -> None: ...
    def _baseline_identity_complete(
        self, request: Mapping[str, Any], zend: Mapping[str, Any], parent: Mapping[str, Any],
    ) -> bool: ...
    def _baseline_evidence(self, evidence: Mapping[str, Any], version: Mapping[str, Any]) -> dict[str, str]: ...
    def _parameter_replay_fields(
        self, parent: Mapping[str, Any], child: Mapping[str, Any], baseline: Mapping[str, Any] | None,
    ) -> list[dict[str, str]]: ...
    def config_hash(self, path: Path) -> str: ...
    def _discover_replay_guards(
        self, child: dict[str, Any], evidence: Mapping[str, Any], *, deadline: float | None,
        running_parent: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...
    def _worker_exit_code(self, timeout: float | None = None) -> int | None: ...
    def _observe_parent_exit(self, *, timeout: float | None = None) -> int | None: ...
    def _handle_worker_exit(self, worker_exit_code: int) -> None: ...
    def _priority_seed(
        self, parent: Mapping[str, Any], child: Mapping[str, Any], replay_result: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]: ...
    def _stop_worker(self, version: Mapping[str, Any], reason: str) -> bool: ...
    def _start_worker(
        self, version: dict[str, Any], *, deadline: float | None = None,
        priority_seed: Mapping[str, Any] | None = None,
    ) -> bool: ...
    def _stop_active_worker(self, reason: str) -> None: ...
    def _resume_parent(self) -> bool: ...


class WorkerRunner:
    __slots__ = ("_host",)

    def __init__(self, host: WorkerHost) -> None:
        self._host = host

    def handoff_to_next_worker(
        self,
        parent: Mapping[str, Any],
        child: dict[str, Any],
        merged_report: Mapping[str, Any],
        replay_path: Path,
        *,
        deadline: float | None = None,
    ) -> bool:
        """Replay/verify child in parent, then stop parent and start one worker."""

        if self._host._observe_parent_exit() is not None:
            child["worker_status"] = "not_started_parent_exited"
            child["terminal_reason"] = str(self._host.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
            self._host._write_state()
            return False
        version_name = str(child["version"])
        replay_dir = self._host.run_dir / "versions" / version_name / "replay"
        request_dir = replay_dir / "request"
        zend_dir = replay_dir / "zend"
        row = handoff_replay_row(child, replay_path, config_root=self._host.config_root)
        timeout = deadline - self._host.clock() if deadline is not None else self._host.max_seconds
        if timeout <= 0:
            child["worker_status"] = "not_started_budget_expired"
            child["terminal_reason"] = "BUDGET_EXPIRED"
            self._host._write_state()
            return False
        replay_run_id = f"{self._host.legacy_run_id}-{version_name}-replay"
        replay_started_at = self._host.clock()
        try:
            sender_result = self._host._probes.run_light_sender(
                config_path=replay_path,
                request_id=_request_id(replay_run_id),
                run_id=replay_run_id,
                hook_name=row["hook_name"],
                callback_id=row["callback_id"],
                method=row["resolved_method"],
                auth_context=str(child.get("auth_context") or "authenticated"),
                seed_variant_id=str(child.get("seed_variant_id") or ""),
                deadline=deadline,
            )
        except Exception as exc:
            sender_result = {"status": "sender_error", "error": str(exc)}
        if sender_result.get("status") == "parent_stopped":
            exit_code = sender_result.get("parent_exit_code")
            if isinstance(exit_code, int):
                self._host._handle_worker_exit(exit_code)
            child["worker_status"] = "not_started_parent_exited"
            child["terminal_reason"] = str(self._host.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
            self._host._write_state()
            return False
        if sender_result.get("status") == "parent_container_missing":
            self._host._failure = True
            self._host._active_container = ""
            child["worker_status"] = "not_started_parent_missing"
            child["terminal_reason"] = "PARENT_CONTAINER_MISSING"
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = "PARENT_CONTAINER_MISSING"
            self._host._write_state()
            return False
        if sender_result.get("status") in {"parent_check_timeout", "parent_check_error"}:
            reason = "PARENT_CHECK_TIMEOUT" if sender_result.get("status") == "parent_check_timeout" else "PARENT_CHECK_ERROR"
            self._host._failure = True
            child["worker_status"] = "not_started_parent_check_timeout"
            child["terminal_reason"] = reason
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = reason
            self._host._write_state()
            return False
        parent_timeout = None if deadline is None else deadline - self._host.clock()
        deadline_expired = parent_timeout is not None and parent_timeout <= 0
        # Budget exhaustion is not evidence that the HTTP callback failed.
        # Keep any received request/Zend artifacts, but do not admit a late gate.
        if not deadline_expired:
            try:
                parent_exit_code = self._host._observe_parent_exit(timeout=parent_timeout)
            except (ParentInspectionTimeout, ParentInspectionError) as exc:
                reason = "PARENT_CHECK_TIMEOUT" if isinstance(exc, ParentInspectionTimeout) else "PARENT_CHECK_ERROR"
                self._host._failure = True
                child["worker_status"] = "not_started_parent_check_timeout"
                child["terminal_reason"] = reason
                self._host.state["terminal_status"] = "NOT_VERIFIED"
                self._host.state["terminal_reason"] = reason
                self._host._write_state()
                return False
            if parent_exit_code is not None:
                child["worker_status"] = "not_started_parent_exited"
                child["terminal_reason"] = str(self._host.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                self._host._write_state()
                return False
        verify_started_at = self._host.clock()
        replay_row = self._host._sender_runner_row(row, sender_result, replay_run_id)
        replay_report = {
            "legacy_run_id": replay_run_id,
            "runs": [replay_row],
            "timing": dict(sender_result.get("timing") or {}),
        }
        artifact_error = ""
        artifact_stage = ""
        try:
            self._host._save_replay_artifacts(
                {**replay_row, "_strict_correlation": False}, request_dir, zend_dir,
            )
        except ReplayArtifactError as exc:
            artifact_error = str(exc)
            artifact_stage = exc.stage
        except (OSError, RuntimeError, ValueError) as exc:
            artifact_error = str(exc)
        baseline_version = {**child, "worker_run_id": replay_run_id}
        baseline = None
        try:
            baseline = load_gate_evidence(
                baseline_version, replay_row, request_dir, zend_dir, {},
                plugin_slug=self._host.plugin_slug,
            )
            if baseline is not None and not self._host._baseline_identity_complete(
                baseline["request"], baseline["zend"], baseline_version,
            ):
                baseline = None
        except (OSError, RuntimeError, ValueError):
            baseline = None
        deadline_expired = deadline is not None and self._host.clock() >= deadline
        verified_parameters = (
            self._host._parameter_replay_fields(parent, child, baseline)
            if child.get("evidence_origin", "worker_poll") == "worker_poll" else []
        )
        verdict = replay_verdict(
            replay_row=replay_row, sender_result=sender_result, baseline=baseline,
            verified_parameters=verified_parameters, deadline_expired=deadline_expired, artifact_error=artifact_error,
        )
        replay_passed, non_success_response = verdict.callback_passed, verdict.non_success_response
        response_status, parameter_failures = verdict.response_status, verdict.parameter_failures
        transport_failed = verdict.transport_failed
        replay_result = {
            "passed": verdict.passed,
            "guard_status": "unknown",
            "budget_expired": deadline_expired,
            "config_path": str(replay_path),
            "config_hash": self._host.config_hash(replay_path),
            "runner": replay_report,
            "verification_policy": PARAMETER_REPLAY_POLICY if verified_parameters else "callback_baseline_v1",
            "response_status": response_status,
        }
        if verified_parameters:
            replay_result["verified_parameters"] = verified_parameters
            if parameter_failures:
                replay_result["unverified_parameters"] = parameter_failures
            if transport_failed:
                replay_result["transport_error"] = True
        if replay_result["passed"]:
            replay_result["baseline_evidence"] = self._host._baseline_evidence(baseline, child)
        replay_result["timing"] = dict(sender_result.get("timing") or {})
        replay_result["timing"]["verify"] = round(self._host.clock() - verify_started_at, 3)
        replay_result["timing"]["total"] = round(self._host.clock() - replay_started_at, 3)
        replay_result["timing"].setdefault("handoff", 0.0)
        if artifact_error:
            replay_result["artifact_error"] = artifact_error
            if artifact_stage:
                replay_result["artifact_stage"] = artifact_stage
        child["replay_result"] = replay_result
        self._host.state.setdefault("replay_results", []).append(replay_result)

        def record_replay_event(status: str, reason: str) -> None:
            self._host._record_event({
                "kind": "CHILD_REPLAY", "status": status, "reason": reason,
                "hook_name": child.get("hook_name"), "version": version_name,
                "probe_id": None, "parameter": None, "timing": dict(replay_result["timing"]),
            })

        if replay_passed and non_success_response:
            child["status"] = "guard_unverified"
            child["worker_status"] = "not_started_guard_unverified"
            child["terminal_reason"] = "GUARD_SATISFACTION_UNKNOWN"
            if not self._host._replay_discovery_active:
                self._host.state.update(terminal_status="PARTIAL", terminal_reason="GUARD_SATISFACTION_UNKNOWN")
            record_replay_event("DEFERRED", "GUARD_SATISFACTION_UNKNOWN")
            self._host._write_state()
            return False

        if replay_passed:
            child["status"] = "replay_pass"
            child["terminal_reason"] = ""
            self._host._write_state()
            if self._host._replay_discovery_active:
                # The caller hands off once, after choosing among verified children.
                self._host._replay_evidence[version_name] = {**baseline, "evidence_origin": "child_replay"}
                return True
            if _is_ajax(child):
                target = self._host._discover_replay_guards(
                    child, {**baseline, "evidence_origin": "child_replay"}, deadline=deadline,
                    running_parent=parent,
                )
                if self._host.state.get("terminal_status") in {"NOT_VERIFIED", "VULN_FOUND"} or not self._host._active_container:
                    child["worker_status"] = "not_started_parent_exited"
                    child["terminal_reason"] = str(self._host.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                    record_replay_event("PASS", child["terminal_reason"])
                    self._host._write_state()
                    return False
                if deadline is not None and self._host._deadline is not None:
                    deadline = max(deadline, self._host._deadline)
                if target is not child:
                    # record_replay_event reads these names, so its events describe the target.
                    child, version_name = target, str(target["version"])
                    replay_result = child["replay_result"]
                    merged_report = self._host._reports.get(version_name, merged_report)
            if self._host._observe_parent_exit() is not None:
                child["worker_status"] = "not_started_parent_exited"
                child["terminal_reason"] = str(self._host.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                record_replay_event("PASS", "PARENT_WORKER_EXITED")
                self._host._write_state()
                return False
            handoff_started_at = self._host.clock()
            priority_seed, blocked = self._host._priority_seed(parent, child, replay_result)
            if blocked:
                # The config would drop a field the replay proved: keep the parent instead.
                replay_result["passed"] = False
                child.update(status="replay_failed", worker_status="not_started_replay_failed", terminal_reason=blocked)
                record_replay_event("REJECTED", blocked)
                self._host._write_state()
                return False
            if getattr(self._host, "_parallel_group", None) is not None:
                self._host._parallel.end_for_handoff(str(child["version"]))
            if not self._host._stop_worker(parent, "HANDOFF_TO_" + str(child["version"])):
                child["worker_status"] = "not_started_parent_stop_failed"
                child["terminal_reason"] = "WORKER_STOP_FAILED"
                replay_result["timing"]["handoff"] = round(self._host.clock() - handoff_started_at, 3)
                record_replay_event("PASS", "WORKER_STOP_FAILED")
                self._host._write_state()
                return False
            if self._host._start_worker(child, deadline=deadline, priority_seed=priority_seed):
                self._host._active_version = str(child["version"])
                if child.get("resolved_method") != parent.get("resolved_method"):
                    candidate = candidate_from_seed_item(merged_report["suggested_seeds"][0], plugin_slug=self._host.plugin_slug)
                    variant = str(merged_report["suggested_seeds"][0]["seed"].get("seed_variant_id") or "")
                    self._host._target_key = canonical_identity_id(candidate) + (f"::{variant}" if variant else "")
                replay_result["timing"]["handoff"] = round(self._host.clock() - handoff_started_at, 3)
                record_replay_event("PASS", (
                    "PARAMETER_REPLAY_VERIFIED" if replay_result["verification_policy"] == PARAMETER_REPLAY_POLICY
                    else "CALLBACK_BASELINE_VERIFIED"
                ))
                self._host._write_state()
                return True
            replay_result["timing"]["handoff"] = round(self._host.clock() - handoff_started_at, 3)
            if child["worker_status"] == "not_started_budget_expired":
                record_replay_event("PASS", "BUDGET_EXPIRED")
                self._host._write_state()
                return False
            child["terminal_reason"] = "WORKER_START_FAILED"
            self._host._failure = True
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = "CHILD_WORKER_START_FAILED"
            record_replay_event("PASS", "CHILD_WORKER_START_FAILED")
            self._host._write_state()
        else:
            child["status"] = "replay_failed"
            child["worker_status"] = "not_started_replay_failed"
            if deadline_expired:
                child["terminal_reason"] = "CANDIDATE_BUDGET_EXPIRED"
                self._host.state["terminal_status"] = "BOUNDED_ONLINE_COMPLETE"
                self._host.state["terminal_reason"] = "BUDGET_EXPIRED"
                record_replay_event("DEFERRED", "CANDIDATE_BUDGET_EXPIRED")
                self._host._write_state()
                return False
            child["terminal_reason"] = replay_failure_reason(
                artifact_error=artifact_error, replay_report=replay_report, replay_row=replay_row,
                replay_result=replay_result,
            )
            # A paused parent resumes its round (or fails loudly in _resume_parent).
            if not self._host._replay_discovery_active and self._host._pause is None:
                self._host._failure = True
                self._host.state["terminal_status"] = "NOT_VERIFIED"
                self._host.state["terminal_reason"] = "CHILD_REPLAY_FAILED"
            record_replay_event(
                "REJECTED",
                str(
                    replay_result.get("artifact_error")
                    or replay_row.get("validation_reason")
                    or "CALLBACK_BASELINE_NOT_VERIFIED"
                ),
            )
            self._host._write_state()
        return False

    def start_worker(
        self, version: dict[str, Any], *, deadline: float | None = None,
        priority_seed: Mapping[str, Any] | None = None,
    ) -> bool:
        if self._host._active_container:
            return False
        if deadline is not None and self._host.clock() >= deadline:
            version["worker_status"] = "not_started_budget_expired"
            version["terminal_reason"] = "BUDGET_EXPIRED"
            self._host._write_state()
            return False
        version_name = str(version["version"])
        config_path = Path(str(version["config_path"]))
        runtime_slug = config_path.relative_to(self._host.config_root).with_suffix("").as_posix()
        container_name = worker_container_name(self._host.legacy_run_id, version_name)
        worker_run_id = str(version.get("worker_run_id") or f"{self._host.legacy_run_id}-{version_name}")
        version["worker_run_id"] = worker_run_id
        handoff_key = f"{version_name}-{uuid.uuid4().hex}"
        version["handoff_key"] = handoff_key
        # The priority round belongs to the first activation of a verified config only.
        grant = priority_seed is not None and not version.get("priority_seed")
        command = worker_start_command(
            version, container_name=container_name, runtime_slug=runtime_slug, service=self._host.service,
            priority_seed=priority_seed if grant else None,
            fuzzer_node_id=parallel_node_id(version_name, 1) if getattr(self._host, "parallel", False) else None,
        )
        try:
            timeout = 30 if deadline is None else min(30, max(0.0, deadline - self._host.clock()))
            result = self._host.run_command(command, timeout=timeout, check=False, capture_output=True, text=True)
        except Exception as exc:
            version["worker_status"] = "start_failed"
            version["terminal_reason"] = f"WORKER_START_FAILED: {exc}"
            self._host._failure = True
            self._host._write_state()
            return False
        if int(getattr(result, "returncode", 1)) != 0:
            version["worker_status"] = "start_failed"
            version["terminal_reason"] = str(getattr(result, "stderr", "") or "WORKER_START_FAILED").strip()
            self._host._failure = True
            self._host._write_state()
            return False
        version["worker_status"] = "started"
        version["status"] = "replaying" if version.get("config_type") == "replay_only" else "fuzzing"
        if grant:
            version["priority_seed"] = dict(priority_seed)
        self._host._active_container = container_name
        self._host._worker_started_at[version_name] = self._host.clock()
        self._host.state["workers"].append({
            "version": version_name,
            "container_name": container_name,
            "run_id": worker_run_id,
            "status": "started",
            "command": command,
        })
        self._host._write_state()
        return True

    def priority_seed(
        self, parent: Mapping[str, Any], child: Mapping[str, Any], replay_result: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Reference the verified replay seed and its fuzzable new fields; never request values.

        Returns (descriptor, block_reason); a block reason stops the handoff.
        """
        if replay_result.get("verification_policy") != PARAMETER_REPLAY_POLICY:
            return None, None
        event = {"kind": "PRIORITY_SEED", "version": child.get("version")}
        verified = verified_fields(replay_result)

        try:
            child_path = Path(str(child["config_path"]))
            all_fields = _config_fields(child_path, fuzzable_only=False)
            # Only fields the running parent could not fuzz are new (nested selectors included).
            fuzzable = _config_fuzzable_fields(child_path) - _config_fuzzable_fields(Path(str(parent["config_path"])))
            replay_slug = Path(str(child["replay_config_path"])).relative_to(self._host.config_root).with_suffix("").as_posix()
        except (KeyError, OSError, ValueError, re.error) as exc:
            self._host._record_event({**event, "status": "REJECTED", "reason": "CONFIG_FIELDS_UNAVAILABLE", "detail": str(exc)})
            return None, "CONFIG_FIELDS_UNAVAILABLE"
        missing = missing_verified_fields(verified, all_fields)
        if missing:
            self._host._record_event({**event, "status": "REJECTED", "reason": "VERIFIED_FIELD_NOT_IN_CONFIG",
                                "fields": [list(field) for field in missing]})
            return None, "VERIFIED_FIELD_NOT_IN_CONFIG"
        # A verified field the updated config keeps fixed gets no priority attempts.
        targets = priority_targets(verified, fuzzable)
        if not targets:
            # The plan switches config only for a new fuzzable param: keep the parent.
            self._host._record_event({**event, "status": "REJECTED", "reason": "NO_NEW_FUZZABLE_TARGET"})
            return None, "NO_NEW_FUZZABLE_TARGET"
        ack = parent.get("pause_ack") if isinstance(parent.get("pause_ack"), Mapping) else {}
        attempt = next((row for row in reversed(self._host.state.get("attempts", []))
                        if row.get("version") == child.get("version")), {})
        descriptor = priority_descriptor(
            replay_slug=replay_slug, child=child, targets=targets, mode=self._host.priority_energy_mode,
            ack=ack, attempt=attempt, replay_result=replay_result,
        )
        self._host._record_event({
            **event, "status": "GRANTED", "reason": "PARAMETER_REPLAY_VERIFIED", "mode": descriptor["mode"],
            "discovery_request_id": attempt.get("request_id"), "pause_round_id": ack.get("round_id"),
            "allocated_energy": descriptor["allocated_energy"], "attempts_used": descriptor["attempts_used"],
            "targets": descriptor["targets"], "seed_phuzz_energy": descriptor.get("seed_phuzz_energy"),
        })
        return descriptor, None

    def pause_parent(self, parent: Mapping[str, Any], deadline: float | None, *, request_id: str = "") -> bool:
        """Ask the running worker to stop between requests and wait for its matching ACK."""
        key = str(parent.get("handoff_key") or "")
        run_id = str(parent.get("worker_run_id") or "")
        event = {"kind": "WORKER_PAUSE", "version": parent.get("version"), "worker_run_id": run_id}
        if not key or not self._host._active_container:
            self._host._record_event({**event, "status": "REJECTED", "reason": "PAUSE_UNAVAILABLE"})
            return False
        token = uuid.uuid4().hex
        self._host._pause = {"container": self._host._active_container, "key": key, "token": token}
        try:
            acknowledged = self.await_pause_ack(parent, event, key, token, run_id, deadline, request_id)
            if acknowledged and getattr(self._host, "_parallel_group", None) is not None:
                self._host._parallel.pause_nodes(deadline, request_id=request_id)
            return acknowledged
        except BaseException:
            self._host._resume_parent()
            raise

    def resume_parent(self) -> bool:
        """Release the pause only for the same worker container while it still runs."""
        if getattr(self._host, "_parallel_group", None) is not None:
            self._host._parallel.release_nodes()
        pause, self._host._pause = self._host._pause, None
        if pause is None or self._host._active_container != pause["container"]:
            return True
        try:
            running = self._host._worker_exit_code(timeout=10.0) is None
        except (ParentInspectionTimeout, ParentInspectionError):
            running = True  # unknown: the token-guarded release is harmless if the container is gone
        response = self._handoff("release", pause["key"], pause["token"], deadline=None) if running else None
        # {"released": false}: no request with this token is pending, so nothing is paused.
        released = response is not None
        version = self._host._version(self._host._active_version) or {}
        if released:
            reason = "PAUSE_RELEASED" if response.get("released") is True else "PAUSE_NOT_PENDING"
        else:
            reason = "PAUSE_RELEASE_FAILED" if running else "PAUSED_WORKER_NOT_RUNNING"
        self._host._record_event({
            "kind": "WORKER_PAUSE", "status": "RELEASED" if released else "REJECTED", "reason": reason,
            "version": version.get("version"), "worker_run_id": version.get("worker_run_id"),
        })
        if not released and running and self._host.state.get("terminal_status") is None:
            self._host._failure = True
            self._host.state.update(terminal_status="NOT_VERIFIED", terminal_reason="PAUSE_RELEASE_FAILED")
            self._host._write_state()
        return released

    def stop_active_worker(self, reason: str) -> None:
        version = self._host._version(self._host._active_version)
        if version is not None:
            self._host._stop_worker(version, reason)

    def stop_worker(self, version: Mapping[str, Any], reason: str) -> bool:
        container_name = self._host._active_container
        if not container_name:
            return True
        stopped, error = remove_container(
            container_name, clock=self._host.clock, sleeper=self._host.sleeper, run_command=self._host.run_command,
        )
        status = "stopped" if stopped else "stop_failed"
        for worker in reversed(self._host.state["workers"]):
            if worker.get("container_name") == container_name:
                worker["status"] = status
                worker["terminal_reason"] = reason
                if not stopped:
                    worker["stop_error"] = error
                break
        record = self._host._version(str(version["version"]))
        if record is not None:
            record["worker_status"] = "stopped" if status == "stopped" else status
            record["terminal_reason"] = reason
        if stopped:
            self._host._active_container = ""
        else:
            self._host._failure = True
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = "WORKER_STOP_FAILED"
        self._host._write_state()
        return stopped

    def handle_worker_exit(self, worker_exit_code: int) -> None:
        version = self._host._version(self._host._active_version)
        if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
            self._host._attach_finding_artifact(version)
            if version is not None:
                version["status"] = "vuln_found"
                version["terminal_reason"] = "VULN_FOUND"
            self._host.state["terminal_status"] = "VULN_FOUND"
            self._host.state["terminal_reason"] = "VULN_FOUND"
            self._host._stop_active_worker("VULN_FOUND")
        elif worker_exit_code != 0:
            self._host._failure = True
            if version is not None:
                version["status"] = "worker_failed"
                version["terminal_reason"] = f"WORKER_EXIT_CODE_{worker_exit_code}"
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = f"WORKER_EXIT_CODE_{worker_exit_code}"
            self._host._stop_active_worker("WORKER_FAILED")
        else:
            self._host._failure = True
            if version is not None:
                version["status"] = "worker_exited"
                version["worker_status"] = "exited"
                version["terminal_reason"] = "WORKER_EXITED"
            for worker in reversed(self._host.state["workers"]):
                if worker.get("container_name") == self._host._active_container:
                    worker["status"] = "exited"
                    worker["terminal_reason"] = "WORKER_EXITED"
                    break
            self._host.state["terminal_status"] = "NOT_VERIFIED"
            self._host.state["terminal_reason"] = "WORKER_EXITED"
            self._host._active_container = ""
        self._host._write_state()

    def observe_parent_exit(self, *, timeout: float | None = None) -> int | None:
        exit_code = self._host._worker_exit_code(timeout=timeout)
        if exit_code is not None:
            self._host._handle_worker_exit(exit_code)
        return exit_code

    def await_pause_ack(
        self, parent: Mapping[str, Any], event: Mapping[str, Any], key: str, token: str, run_id: str,
        deadline: float | None, request_id: str = "",
    ) -> bool:
        self._host._record_event({**event, "status": "REQUESTED", "reason": "PARAMETER_HANDOFF"})
        wait_until = (deadline - 2 * self._host._sender_seconds if deadline is not None
                      else self._host.clock() + self._host.max_seconds)
        reason = "PAUSE_REQUEST_FAILED"
        if self._handoff("request", key, token, run_id, *([request_id] if request_id else []),
                                 deadline=wait_until) is not None:
            reason = "PAUSE_ACK_TIMEOUT"
            while self._host.clock() < wait_until:
                ack = self._handoff("ack", key, deadline=wait_until)
                snapshot = matching_pause_ack(ack, token=token, run_id=run_id)
                if snapshot is not None:
                    record = self._host._version(str(parent.get("version"))) or {}
                    record["pause_ack"] = {**snapshot, "token": token, "acked_at": self._host.clock()}
                    self._host._record_event({**event, "status": "ACKNOWLEDGED", "reason": "PAUSE_ACK", **snapshot})
                    return True
                try:
                    exit_code = self._host._worker_exit_code(timeout=min(10.0, max(0.0, wait_until - self._host.clock())))
                except (ParentInspectionTimeout, ParentInspectionError):
                    exit_code = None
                if exit_code is not None:
                    reason = "PAUSE_WORKER_EXITED"
                    break
                self._host.sleeper(min(0.2, max(0.0, wait_until - self._host.clock())))
        self._host._record_event({**event, "status": "REJECTED", "reason": reason})
        self._host._resume_parent()
        return False

    def _handoff(self, *args: str, deadline: float | None) -> dict[str, Any] | None:
        return handoff_command(
            self._host._active_container, *args, deadline=deadline, clock=self._host.clock, run_command=self._host.run_command,
        )
