"""Online-linked coordinator for immutable, replay-gated PHUZZ workers."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from filesystem_paths import check_directory_io, filesystem_path
from hook_energy.seed_generation.generated_config_runner import (
    STOP_ON_VULN_EXIT_CODE,
    list_request_artifacts,
    list_zend_artifacts,
    load_request_artifact,
    run_generated_configs,
)
from online_linked.probe_sender import (
    ParentInspectionError,
    ParentInspectionTimeout,
    run_in_container,
)
from hook_energy.seed_generation.online_common import (
    _load_zend_artifact,
    _write_exclusive_json,
    _write_json,
    config_hash,
)
from online_linked.coordination.candidate_identity import (
    _CANDIDATE_CONTEXT_KEY_VERSION,
    _candidate_identity,
)
from online_linked.coordination.checkpoint import validate_resume_checkpoint
from online_linked.coordination.errors import OnlineLinkedError, ReplayArtifactError
from online_linked.coordination.evidence_runner import EvidenceRunner
from online_linked.coordination.gate_replay import load_gate_evidence
from online_linked.coordination.gate_runner import GateRunner
from online_linked.coordination.replay_artifacts import save_replay_artifacts
from online_linked.coordination.pending_candidates import failed_batch_parameters
from online_linked.coordination.probe_runner import ProbeRunner
from online_linked.coordination.probe_results import (
    ajax_branch_continuation,
    replay_verdict,
    sender_runner_row,
)
from online_linked.coordination.replay_request import restore_request_values
from online_linked.coordination.runtime_discovery import merge_registry_callback
from online_linked.coordination.version_record import new_version_record
from online_linked.coordination.request_matching import (
    _is_ajax,
    _parameter_key,
    _replace_fuzzable_values_with_placeholder,
    _request_id,
    _request_payload_hash,
    _safe_parameter_identity,
    admission_complete,
    baseline_evidence,
    baseline_identity_complete,
    config_request_key,
    inherit_callback_identity,
    parameter_replay_fields,
    probe_admission_complete,
    probe_context_key,
    published_config_with_same_request,
)
from online_linked.coordination.worker import (
    CommandRunner,
    handoff_command,
    remove_container,
    worker_exit_code,
    worker_start_command,
)
from online_linked.evidence import read_runtime_batch
from core.online_handoff import DEFAULT_PRIORITY_ENERGY_MODE, priority_energy_mode as _priority_energy_mode
from online_linked.export import (
    PARAMETER_REPLAY_POLICY, config_fields as _config_fields, config_fuzzable_fields as _config_fuzzable_fields,
)
from hook_energy.seed_generation.zend_runtime.bridge_cli import (
    converge_iteration,
    list_convergence_targets,
)
from seed_generation.config.config_exporter import (
    _force_replay_only,
    build_config_for_seed_item,
    export_seed_configs,
)
from seed_generation.convergence.convergence import materialize_convergence_seeds
from zend_discovery.engine import (
    candidate_from_seed_item, canonical_identity_id, resolve_request_transport,
)
ArtifactLister = Callable[[], set[str]]
ArtifactLoader = Callable[[str], Any]
ConvergeRunner = Callable[..., dict[str, Any]]
TargetLister = Callable[..., list[dict[str, Any]]]
MaterializeRunner = Callable[..., dict[str, Any]]
Exporter = Callable[..., dict[str, Any]]
ReplayRunner = Callable[..., dict[str, Any]]
ProbeSender = Callable[..., dict[str, Any]]
ConfigBuilder = Callable[..., tuple[str, dict[str, Any]]]
RuntimeBatchReader = Callable[..., dict[str, Any]]


def _budget_pair(name: str, initial: int, hard: int | None, default: int,
                 maximum: int | None = None) -> tuple[int, int]:
    hard = default if hard is None else hard
    for value in (initial, hard):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} budgets must be positive integers")
    if maximum is not None and initial > maximum:
        raise ValueError(f"initial {name} budget must not exceed {maximum}")
    if hard < initial:
        raise ValueError(f"hard {name} cap must cover initial budget")
    return initial, hard


class OnlineLinkedCoordinator:
    """Coordinate immutable online versions without changing worker configs."""

    MAX_PROBE_ATTEMPTS = 64

    def __init__(
        self,
        *,
        suggested_seeds: Path,
        bootstrap_config: Path | None = None,
        config_root: Path,
        output_root: Path,
        plugin_slug: str,
        legacy_run_id: str,
        max_seconds: int,
        max_versions: int,
        runtime_cookie_probes: bool = False,
        registry: Mapping[str, Any] | None = None,
        registry_path: Path | None = None,
        service: str = "fuzzer-wordpress-plugin",
        run_command: CommandRunner = subprocess.run,
        list_artifacts: ArtifactLister = list_request_artifacts,
        load_artifact: ArtifactLoader = load_request_artifact,
        load_finding_artifact: ArtifactLoader | None = None,
        list_zend_artifacts: ArtifactLister = list_zend_artifacts,
        load_zend_artifact: ArtifactLoader = _load_zend_artifact,
        runtime_batch_reader: RuntimeBatchReader = read_runtime_batch,
        build_config_fn: ConfigBuilder = build_config_for_seed_item,
        list_targets_fn: TargetLister = list_convergence_targets,
        converge_fn: ConvergeRunner = converge_iteration,
        materialize_fn: MaterializeRunner = materialize_convergence_seeds,
        export_configs_fn: Exporter = export_seed_configs,
        force_replay_only_fn: Callable[[dict[str, Any]], None] = _force_replay_only,
        replay_runner: ReplayRunner = run_generated_configs,
        probe_sender: ProbeSender = run_in_container,
        process_factory: Callable[..., Any] = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        campaign_deadline: float | None = None,
        campaign_dir: Path | None = None,
        hard_seconds: int | None = None,
        hard_versions: int | None = None,
        progress_callback: Callable[[str, str], float | None] | None = None,
        registry_checkpoint_callback: Callable[[Mapping[str, Any]], None] | None = None,
        resume: bool = False,
        priority_energy_mode: str = DEFAULT_PRIORITY_ENERGY_MODE,
    ) -> None:
        if type(max_seconds) is not int or type(max_versions) is not int:
            raise ValueError("initial candidate budgets must be positive integers")
        if max_seconds < 1:
            raise ValueError("candidate seconds must be a positive integer")
        if hard_seconds is not None:
            max_seconds, hard_seconds = _budget_pair("candidate seconds", max_seconds, hard_seconds,
                                                    max_seconds, max_seconds)
        max_versions, hard_versions = _budget_pair("versions", max_versions, hard_versions,
                                                   max(20, max_versions * 4), 20)
        self.suggested_seeds = Path(suggested_seeds)
        self.bootstrap_config = Path(bootstrap_config) if bootstrap_config else None
        self.config_root = Path(config_root)
        self.output_root = Path(output_root)
        self.plugin_slug = plugin_slug
        self.legacy_run_id = legacy_run_id
        self.max_seconds = max_seconds
        self._sender_seconds = 0.0
        # Set while a passed AJAX replay's guards are probed: children are only verified.
        self._replay_discovery_active = False
        self._replay_evidence: dict[str, dict[str, Any]] = {}
        # The acknowledged pause of the running worker during one handoff.
        self._pause: dict[str, str] | None = None
        self.max_versions = max_versions
        self.hard_seconds = hard_seconds
        self.hard_versions = hard_versions
        self.progress_callback = progress_callback
        self.registry_checkpoint_callback = registry_checkpoint_callback
        # Fixed by the batch checkpoint; the worker of each verified handoff receives it.
        self.priority_energy_mode = _priority_energy_mode(priority_energy_mode)
        self._deadline: float | None = None
        self._hard_deadline: float | None = None
        self._progress_keys: set[tuple[str, str]] = set()
        self.resume = resume
        self._budget_started_at: float | None = None
        self._elapsed_seconds = 0.0
        self.runtime_cookie_probes = bool(runtime_cookie_probes)
        self.service = service
        self.run_command = run_command
        self.list_artifacts = list_artifacts
        self.load_artifact = load_artifact
        self.load_finding_artifact = load_finding_artifact
        self.list_zend_artifacts = list_zend_artifacts
        self.load_zend_artifact = load_zend_artifact
        self.runtime_batch_reader = runtime_batch_reader
        self.build_config_fn = build_config_fn
        self.list_targets_fn = list_targets_fn
        self.converge_fn = converge_fn
        self.materialize_fn = materialize_fn
        self.export_configs_fn = export_configs_fn
        self.force_replay_only_fn = force_replay_only_fn
        self.replay_runner = replay_runner
        self.probe_sender = probe_sender
        self.process_factory = process_factory
        self.clock = clock
        self.sleeper = sleeper
        self.campaign_deadline = float(campaign_deadline) if campaign_deadline is not None else None
        # Avoid repeating long candidate run IDs in nested evidence/config paths.
        storage_id = hashlib.sha256(self.legacy_run_id.encode("utf-8")).hexdigest()[:16]
        evidence_root = Path(campaign_dir) / "campaigns" if campaign_dir is not None else self.output_root / "online-linked"
        self.run_dir = evidence_root / storage_id
        self.config_dir = self.config_root / "online-linked" / self.plugin_slug / storage_id
        if registry is not None:
            self.registry = dict(registry)
        elif registry_path is not None:
            self.registry = json.loads(filesystem_path(Path(registry_path)).read_text(encoding="utf-8-sig"))
        else:
            raise ValueError("online-linked requires a callback registry")
        self.registry_path = Path(registry_path) if registry_path is not None else None
        if not isinstance(self.registry, Mapping):
            raise ValueError("callback registry must be an object")
        self.state: dict[str, Any] = {
            "schema_version": 1,
            "context_key_version": _CANDIDATE_CONTEXT_KEY_VERSION,
            "mode": "online-linked",
            "budget_policy": "progress_idle_v1",
            "plugin_slug": plugin_slug,
            "legacy_run_id": legacy_run_id,
            "max_seconds": max_seconds,
            "max_versions": max_versions,
            "initial_max_versions": max_versions,
            "hard_seconds": self.hard_seconds,
            "hard_versions": self.hard_versions,
            "budget_progress": [],
            "runtime_cookie_probes": self.runtime_cookie_probes,
            "priority_energy_mode": self.priority_energy_mode,
            "campaign_deadline": self.campaign_deadline,
            "campaign_status": "running" if self.campaign_deadline is not None else None,
            "versions": [],
            "attempts": [],
            "probe_attempts": [],
            "pending_runtime_candidates": [],
            "candidate_queue": [],
            "queued_candidate_ids": [],
            "queued_candidate_context_keys": [],
            "events": [],
            "workers": [],
            "terminal_status": None,
            "terminal_reason": None,
            "evidence_scan": {},
        }
        self.state_path = self.run_dir / "state.json"
        self.events_path = self.run_dir / "events.jsonl"
        self._raw_report: dict[str, Any] | None = None
        self._reports: dict[str, dict[str, Any]] = {}
        self._targets: list[dict[str, Any]] = []
        self._target_key = ""
        self._active_version = ""
        self._active_container = ""
        self._worker_started_at: dict[str, float] = {}
        self._seen_pairs: set[tuple[str, str]] = set()
        self._gate_evidence: dict[str, Any] | None = None
        self._gate_convergence: dict[str, Any] | None = None
        self._gate_evidence_consumed = False
        self._failure = False

    def run(self) -> int:
        try:
            check_directory_io(self.run_dir)
            check_directory_io(self.config_dir)
        except OSError as exc:
            self.state.update(terminal_status="NOT_VERIFIED", terminal_reason=str(exc))
            print(str(exc), file=sys.stderr)
            try:
                self._write_state()
            except OSError:
                pass
            return 2
        resumed = self._load_checkpoint() if self.resume else None
        self._write_state()
        try:
            config_generation_started_at = self.clock()
            selected = None if resumed else self._select_v0()
            if resumed:
                version, config = resumed
                deadline = self._candidate_deadline()
                if self.clock() >= deadline:
                    self.state.update(terminal_status="PARTIAL", terminal_reason="RESUME_BUDGET_EXHAUSTED")
                    self._write_state()
                    return 0
            elif selected is None:
                self.state["terminal_status"] = "NOT_VERIFIED"
                self.state["terminal_reason"] = "V0_PREREQUISITE_GATE_FAILED"
                self._write_state()
                return 2
            if not resumed:
                item, config, target_key = selected
                config_path = self._write_config("v0", config)
                config_generation_seconds = round(max(0.0, self.clock() - config_generation_started_at), 3)
                version = self._new_version(
                    "v0", config, config_path, None, None, item,
                    config_generation_seconds=config_generation_seconds,
                )
                version["worker_run_id"] = f"{self.legacy_run_id}-v0"
                version["known_parameters"] = []
                self._reports["v0"] = copy.deepcopy(self._raw_report or {})
                self._target_key = target_key
                self._active_version = "v0"
                initial_identity = _candidate_identity(item, self.plugin_slug)
                if initial_identity not in self.state["queued_candidate_ids"]:
                    self.state["queued_candidate_ids"].append(initial_identity)
                deadline = self._candidate_deadline()
            if not self._gate_v0(version, config, deadline=deadline):
                self._mark_campaign_expired_if_needed()
                self._write_state()
                return 0 if self.state["terminal_status"] == "VULN_FOUND" else 2
            if not self._start_worker(version, deadline=deadline):
                self._mark_campaign_expired_if_needed()
                self.state["terminal_status"] = "NOT_VERIFIED"
                self.state["terminal_reason"] = version.get("terminal_reason") or "V0_WORKER_START_FAILED"
                self._write_state()
                return 1
            self._consume_gate_evidence(version, deadline=deadline)
            self._drain_pending_probes()
            if not self._active_container or self.state["terminal_status"] in {"VULN_FOUND", "NOT_VERIFIED"}:
                self._stop_active_worker(self.state["terminal_reason"] or "GATE_PROCESSING_STOPPED")
                self._mark_campaign_expired_if_needed()
                self._write_state()
                return 1 if self._failure else 0

            deadline = self._deadline or deadline
            while self.clock() < deadline:
                if self.state["terminal_status"] in {"PARTIAL", "NOT_VERIFIED", "VULN_FOUND"}:
                    break
                self._drain_pending_probes()
                deadline = self._candidate_deadline()
                if self.state["terminal_status"] is not None or not self._active_container or self.clock() >= deadline:
                    break
                worker_exit_code = self._observe_parent_exit(timeout=min(30.0, max(0.0, deadline - self.clock())))
                if worker_exit_code is not None:
                    if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
                        return 1 if self._failure else 0
                    return 1
                for evidence in self.read_new_runtime_evidence(deadline=deadline):
                    deadline = self._deadline or deadline
                    self.advance_online_version(evidence, deadline=deadline)
                    deadline = self._deadline or deadline
                    if self.state["terminal_status"] in {"PARTIAL", "NOT_VERIFIED", "VULN_FOUND"} or not self._active_container:
                        break
                deadline = self._deadline or deadline
                if self.state["terminal_status"] in {"PARTIAL", "NOT_VERIFIED", "VULN_FOUND"} or not self._active_container:
                    break
                worker_exit_code = self._worker_exit_code(timeout=min(30.0, max(0.0, deadline - self.clock())))
                if worker_exit_code is not None:
                    self._handle_worker_exit(worker_exit_code)
                    if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
                        return 1 if self._failure else 0
                    return 1
                remaining = deadline - self.clock()
                if remaining > 0:
                    self.sleeper(min(0.5, remaining))
            self._stop_active_worker(self.state["terminal_reason"] or "NO_NEW_PROGRESS")
            self._mark_campaign_expired_if_needed()
            if self.state["terminal_status"] is None:
                self.state["terminal_status"] = "BOUNDED_ONLINE_COMPLETE"
                self.state["terminal_reason"] = "NO_NEW_PROGRESS"
            if self.state["terminal_status"] == "BOUNDED_ONLINE_COMPLETE" and self._hard_deadline is not None and self.clock() >= self._hard_deadline:
                self.state.update(terminal_status="PARTIAL", terminal_reason="HARD_CANDIDATE_TIME_CAP")
            elif self.state["terminal_status"] == "BOUNDED_ONLINE_COMPLETE" and self.state.get("pending_runtime_candidates"):
                self.state["terminal_status"] = "PARTIAL"
            self._write_state()
            return 1 if self._failure else 0
        except Exception as exc:
            self._failure = True
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = f"ONLINE_LINKED_COORDINATOR_ERROR: {exc}"
            self._write_state()
            self._stop_active_worker("COORDINATOR_ERROR")
            return 1

    @property
    def _probes(self) -> ProbeRunner:
        # Built per use: tests create coordinators without __init__ and
        # replace dependencies on the instance after construction.
        return ProbeRunner(self)

    @property
    def _evidence_runner(self) -> EvidenceRunner:
        # Built per use, like _probes.
        return EvidenceRunner(self)

    @property
    def _gate_runner(self) -> GateRunner:
        # Built per use, like _probes.
        return GateRunner(self)

    def _drain_pending_probes(self) -> None:
        self._probes.drain_pending_probes()

    def _handle_worker_exit(self, worker_exit_code: int) -> None:
        version = self._version(self._active_version)
        if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
            self._attach_finding_artifact(version)
            if version is not None:
                version["status"] = "vuln_found"
                version["terminal_reason"] = "VULN_FOUND"
            self.state["terminal_status"] = "VULN_FOUND"
            self.state["terminal_reason"] = "VULN_FOUND"
            self._stop_active_worker("VULN_FOUND")
        elif worker_exit_code != 0:
            self._failure = True
            if version is not None:
                version["status"] = "worker_failed"
                version["terminal_reason"] = f"WORKER_EXIT_CODE_{worker_exit_code}"
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = f"WORKER_EXIT_CODE_{worker_exit_code}"
            self._stop_active_worker("WORKER_FAILED")
        else:
            self._failure = True
            if version is not None:
                version["status"] = "worker_exited"
                version["worker_status"] = "exited"
                version["terminal_reason"] = "WORKER_EXITED"
            for worker in reversed(self.state["workers"]):
                if worker.get("container_name") == self._active_container:
                    worker["status"] = "exited"
                    worker["terminal_reason"] = "WORKER_EXITED"
                    break
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "WORKER_EXITED"
            self._active_container = ""
        self._write_state()

    def _attach_finding_artifact(self, version: Mapping[str, Any] | None) -> None:
        if version is None or self.load_finding_artifact is None:
            return
        run_id = str(version.get("worker_run_id") or "").strip()
        if not run_id:
            return
        artifact_name = f"{run_id}.json"
        artifact_path = f"/shared-tmpfs/fuzzer-findings/{artifact_name}"
        try:
            finding = self.load_finding_artifact(artifact_name)
        except Exception as exc:
            version["finding_artifact_path"] = artifact_path
            version["finding_artifact_error"] = str(exc)
            return
        version["finding_artifact_path"] = artifact_path
        version["finding_artifact"] = finding
        for worker in reversed(self.state.get("workers", [])):
            if worker.get("run_id") == run_id:
                worker["finding_artifact_path"] = artifact_path
                worker["finding_artifact"] = finding
                break

    def _observe_parent_exit(self, *, timeout: float | None = None) -> int | None:
        exit_code = self._worker_exit_code(timeout=timeout)
        if exit_code is not None:
            self._handle_worker_exit(exit_code)
        return exit_code

    @staticmethod
    def _sender_runner_row(base: Mapping[str, Any], result: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        return sender_runner_row(base, result, run_id)

    def _candidate_deadline(self) -> float:
        if self._deadline is None:
            now = self.clock()
            self._budget_started_at = now
            self._hard_deadline = now + self.hard_seconds if self.hard_seconds is not None else None
            self._deadline = now + self.max_seconds
            if self.campaign_deadline is not None:
                self._deadline = min(self._deadline, self.campaign_deadline)
        return self._deadline

    def _extend_progress_budget(self, kind: str, key: str) -> float:
        """Credit semantic progress once; retries cannot buy more time."""
        deadline = self._candidate_deadline()
        identity = (kind, key)
        now = self.clock()
        if kind == "pending_verification" or identity in self._progress_keys or now >= deadline:
            return deadline
        if self.campaign_deadline is not None and now >= self.campaign_deadline:
            return deadline
        if self.progress_callback is not None:
            campaign_deadline = self.progress_callback(kind, key)
            if campaign_deadline is None:
                return deadline
            self.campaign_deadline = campaign_deadline
        self._progress_keys.add(identity)
        reserve = 2 * self._sender_seconds if kind == "verified_parameter" else 0.0
        self._deadline = max(deadline, now + self.max_seconds + reserve) if kind == "verified_parameter" else deadline
        if self._hard_deadline is not None:
            self._deadline = min(self._hard_deadline, self._deadline)
        if self.campaign_deadline is not None:
            self._deadline = min(self._deadline, self.campaign_deadline)
        self.max_versions = min(self.hard_versions, self.max_versions + 1)
        self.state["budget_progress"].append({"kind": kind, "key": key, "at": now,
            "previous_deadline": deadline, "deadline": self._deadline, "reserve_seconds": reserve})
        self.state.update(candidate_deadline=self._deadline, campaign_deadline=self.campaign_deadline,
                          max_versions=self.max_versions)
        return self._deadline

    def _mark_campaign_expired_if_needed(self) -> None:
        if self.campaign_deadline is not None and self.clock() >= self.campaign_deadline:
            self.state["campaign_status"] = "bounded"
            self.state["campaign_stop_reason"] = "CAMPAIGN_BUDGET_EXPIRED"

    def _gate_v0(self, version: dict[str, Any], config: Mapping[str, Any], *, deadline: float) -> bool:
        return self._gate_runner.gate_v0(version, config, deadline=deadline)

    def read_new_runtime_evidence(self, *, deadline: float | None = None) -> list[dict[str, Any]]:
        return self._evidence_runner.read_new_runtime_evidence(deadline=deadline)

    def _reject_runtime_batch(
        self, version: Mapping[str, Any], reason: str, *, detail: str = "",
    ) -> None:
        self._evidence_runner.reject_runtime_batch(version, reason, detail=detail)

    def _consume_gate_evidence(self, version: Mapping[str, Any], *, deadline: float) -> None:
        self._evidence_runner.consume_gate_evidence(version, deadline=deadline)

    def _discover_runtime_candidates(
        self, evidence: Mapping[str, Any], *, deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        return self._evidence_runner.discover_runtime_candidates(evidence, deadline=deadline)

    def _merge_runtime_registry(self, callback: Mapping[str, Any]) -> None:
        if not merge_registry_callback(self.registry, callback):
            return
        if self.registry_path is not None:
            if self.registry_checkpoint_callback is not None:
                self.registry_checkpoint_callback(self.registry)
            else:
                _write_json(self.registry_path, self.registry)

    def advance_online_version(self, evidence: Mapping[str, Any], *, deadline: float | None = None) -> dict[str, Any] | None:
        """Run existing convergence/export logic and prepare one child version."""

        parent = self._version(self._active_version)
        if parent is None:
            return None
        if deadline is not None and self.clock() >= deadline:
            return None
        raw_report = self._reports.get(str(parent["version"]))
        if raw_report is None:
            raise OnlineLinkedError("active worker has no seed report")
        request_name = str(evidence.get("request_name") or "")
        zend_name = str(evidence.get("zend_name") or "")
        if not request_name or not zend_name:
            raise OnlineLinkedError("runtime evidence pair is incomplete")
        observation_dir = self.run_dir / "versions" / str(parent["version"]) / "observation"
        request_dir = observation_dir / "request"
        zend_dir = observation_dir / "zend"
        self._copy_json(request_dir / request_name, evidence.get("request"))
        self._copy_json(zend_dir / zend_name, evidence.get("zend"))
        seed = parent.get("seed_item") if isinstance(parent.get("seed_item"), Mapping) else {}
        seed_variant_id = str((seed.get("seed") or {}).get("seed_variant_id") or "") if isinstance(seed.get("seed"), Mapping) else ""
        summary = {
            "legacy_run_id": parent["worker_run_id"],
            "runs": [{
                "config_slug": Path(parent["config_path"]).relative_to(self.config_root).with_suffix("").as_posix(),
                "hook_name": parent["hook_name"],
                "callback_id": parent["callback_id"],
                "seed_variant_id": seed_variant_id,
                "callback_reached": True,
                "matched_artifact": request_name,
                "resolved_method": parent["resolved_method"],
                "process_status": "fuzzing",
            }],
        }
        try:
            result = self.converge_fn(
                raw_report=raw_report,
                pass_run_summary=summary,
                pass_artifacts_dir=request_dir,
                zend_events_dir=zend_dir,
                registry=self.registry,
                plugin_slug=self.plugin_slug,
                legacy_run_id=str(parent["worker_run_id"]),
                known_state={"known_parameters": parent.get("known_parameters", [])},
                candidate_key=self._target_key,
                runtime_cookie_probes=self.runtime_cookie_probes,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self._record_event({
                "kind": "PARAMETER_DISCOVERY",
                "status": "REJECTED",
                "reason": "CORRELATION_OR_PROVENANCE_INCOMPLETE",
                "version": parent["version"],
                "request_id": evidence.get("request_id"),
                "detail": str(exc),
            })
            return None
        if deadline is not None and self.clock() >= deadline:
            self._record_event({
                "kind": "PARAMETER_DISCOVERY",
                "status": "REJECTED",
                "reason": "BUDGET_EXPIRED",
                "version": parent["version"],
                "request_id": evidence.get("request_id"),
            })
            return None
        return self._handle_convergence_result(
            parent=parent,
            evidence=evidence,
            raw_report=raw_report,
            result=result,
            seed=seed,
            deadline=deadline,
        )

    def _handle_convergence_result(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        result: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
    ) -> dict[str, Any] | None:
        """Admit accepted evidence, or service one pending runtime probe."""
        if result.get("_pending_group_dispatch") is not True:
            self._evidence_runner.reconcile_pending_runtime_candidates(parent, evidence, result)
        branch_failure = result.get("status") == "REPLAY_FAILED" or bool(result.get("missing_parameters"))
        if branch_failure and not result.get("runtime_block_reason") and _is_ajax(parent):
            result = ajax_branch_continuation(result, parent)
            branch_failure = False
        if branch_failure or result.get("runtime_block_reason"):
            self._record_event({
                "kind": "RUNTIME_OBSERVATION", "status": "REJECTED",
                "reason": result.get("runtime_block_reason") or result.get("status") or "MISSING_PARAMETERS",
                "missing_parameters": result.get("missing_parameters", []),
                "version": parent["version"], "request_id": evidence.get("request_id"),
            })
            # A missing field proves that this request is a different branch;
            # it must not erase a candidate observed in the current request.
            # Runtime-blocked/auth-invalid evidence remains fail-closed.
            if result.get("runtime_block_reason"):
                return None
            branch_parameters = [
                dict(parameter) for parameter in (result.get("observed_parameters") or [])
                if isinstance(parameter, Mapping) and parameter.get("fuzzable") is True
            ]
            if not branch_parameters:
                branch_parameters = [
                    dict(parameter) for parameter in (result.get("new_parameters") or [])
                    if isinstance(parameter, Mapping) and parameter.get("fuzzable") is True
                ]
            pending_probes = result.get("pending_probes")
            if not branch_parameters and not isinstance(pending_probes, list):
                return None
            result = dict(result)
            result["_coherent_only"] = True
            result["new_parameters"] = branch_parameters
            result["known_parameters"] = branch_parameters
            result["status"] = "CONTINUE"
            result["missing_parameters"] = []

        pending_probes = result.get("pending_probes")
        if isinstance(pending_probes, list) and pending_probes:
            return self._run_pending_probe(
                parent=parent,
                evidence=evidence,
                raw_report=raw_report,
                convergence=result,
                probe=pending_probes[0],
                seed=seed,
                deadline=deadline,
            )

        new_parameters = result.get("new_parameters")
        if not isinstance(new_parameters, list) or not new_parameters:
            status = str(result.get("runtime_candidate_status") or "no_raw_candidate")
            reason = {
                "no_raw_candidate": "NO_RAW_ZEND_CANDIDATE",
                "all_rejected": "ALL_ZEND_CANDIDATES_REJECTED",
            }.get(status, "NO_NEW_ZEND_PARAMETER")
            self._record_event({
                "kind": "RUNTIME_OBSERVATION",
                "status": "IGNORED",
                "reason": reason,
                "runtime_candidate_count": result.get("runtime_candidate_count", 0),
                "version": parent["version"],
                "request_id": evidence.get("request_id"),
            })
            return None
        new_parameters = [
            self._inherit_callback_identity(parameter, parent)
            if isinstance(parameter, Mapping) else parameter
            for parameter in new_parameters
        ]
        admission_parent = parent
        transition_report = result.get("method_transition_report")
        if isinstance(transition_report, Mapping):
            raw_report = transition_report
            transition_seed = raw_report["suggested_seeds"][0]["seed"]
            admission_parent = {**parent, "resolved_method": transition_seed["resolved_method"]}
        evidence_by_parameter = result.get("parameter_evidence")
        for parameter in new_parameters:
            parameter_evidence = evidence
            if isinstance(evidence_by_parameter, Mapping):
                candidate_evidence = evidence_by_parameter.get(_parameter_key(parameter))
                if isinstance(candidate_evidence, Mapping):
                    parameter_evidence = candidate_evidence
            try:
                helper_depth = int(parameter.get("helper_depth")) if isinstance(parameter, Mapping) else 0
            except (TypeError, ValueError):
                helper_depth = 0
            admitted = (
                self._probe_admission_complete(parameter, parameter_evidence, admission_parent)
                if helper_depth != 0
                else self._admission_complete(parameter, parameter_evidence, admission_parent)
            )
            if not admitted:
                self._record_event({
                    "kind": "PARAMETER_DISCOVERY",
                    "status": "REJECTED",
                    "reason": "CORRELATION_OR_PROVENANCE_INCOMPLETE",
                    "version": parent["version"],
                    "request_id": parameter_evidence.get("request_id"),
                    "parameter": dict(parameter) if isinstance(parameter, Mapping) else {},
                })
                return None
        for parameter in new_parameters:
            key = json.dumps([parent.get("callback_id"), _parameter_key(parameter)])
            renewed = self._extend_progress_budget("verified_parameter", key)
            if deadline is not None:
                deadline = max(deadline, renewed)
        if 1 + len(self.state["attempts"]) >= self.max_versions:
            self._retain_pending_runtime_candidates([
                {"parameters": new_parameters, "evidence": evidence}
            ], parent)
            reason = "HARD_VERSION_CAP" if self.max_versions >= self.hard_versions else "VERSION_BUDGET_EXPIRED"
            if self._replay_discovery_active:
                # The verified child still starts; its own run reaches the cap later.
                self._record_event({
                    "kind": "REPLAY_GUARD_DISCOVERY", "status": "DEFERRED", "reason": reason,
                    "version": parent["version"], "request_id": evidence.get("request_id"),
                    "parameters": [_safe_parameter_identity(p) for p in new_parameters if isinstance(p, Mapping)],
                })
            else:
                self.state.update(terminal_status="PARTIAL", terminal_reason=reason)
            self._write_state()
            return None
        discovery = {
            "kind": "PARAMETER_DISCOVERY",
            "status": "ACCEPTED",
            "reason": "ZEND_RUNTIME_PARAMETER",
            "version": parent["version"],
            "worker_run_id": parent["worker_run_id"],
            "plugin_slug": self.plugin_slug,
            "callback_id": parent["callback_id"],
            "resolved_method": parent["resolved_method"],
            "request_id": result.get("request_id") or evidence.get("request_id"),
            "evidence_run_id": str(evidence.get("worker_run_id") or evidence.get("run_id") or parent["worker_run_id"]),
            "parameters": [dict(parameter) for parameter in new_parameters],
        }
        if result.get("unobserved_known_parameters"):
            discovery["unobserved_known_parameters"] = [
                _safe_parameter_identity(parameter) for parameter in result["unobserved_known_parameters"]
                if isinstance(parameter, Mapping)
            ]
        proposed_parameters = [
            self._inherit_callback_identity(parameter, parent)
            if isinstance(parameter, Mapping) else parameter
            for parameter in (result.get("known_parameters") or [])
        ]
        carried = self._failed_batch_parameters(admission_parent, proposed_parameters) if _is_ajax(parent) else []
        if carried:
            proposed_parameters = [*carried, *proposed_parameters]
            discovery["carried_parameters"] = [_safe_parameter_identity(parameter) for parameter in carried]
        discovery = self._record_event(discovery)
        # A descendant verified inside this handoff runs under the outer pause.
        owns_pause = self._pause is None
        defer_reason = ""
        # Reserve one baseline send and one sender-sized handoff allowance.
        if deadline is not None and deadline - self.clock() < 2 * self._sender_seconds:
            defer_reason = "INSUFFICIENT_VERIFICATION_BUDGET"
        elif owns_pause and not self._pause_parent(parent, deadline, request_id=str(discovery.get("request_id") or "")):
            defer_reason = "PARENT_PAUSE_NOT_ACKNOWLEDGED"
        elif deadline is not None and deadline - self.clock() < 2 * self._sender_seconds:
            # The ACK wait spent the reserve: resume the parent and keep the batch.
            defer_reason = "INSUFFICIENT_VERIFICATION_BUDGET"
            if owns_pause:
                self._resume_parent()
        if defer_reason:
            self._retain_pending_runtime_candidates([
                {"parameters": [parameter], "evidence": (
                    evidence_by_parameter.get(_parameter_key(parameter), evidence)
                    if isinstance(evidence_by_parameter, Mapping) else evidence
                )} for parameter in new_parameters
            ], parent)
            self._record_event({**discovery, "event_id": "", "status": "DEFERRED", "reason": defer_reason})
            return None
        try:
            return self._build_and_hand_off_child(
                parent=parent, evidence=evidence, raw_report=raw_report, result=result, seed=seed,
                deadline=deadline, discovery=discovery, new_parameters=new_parameters,
                proposed_parameters=proposed_parameters, evidence_by_parameter=evidence_by_parameter,
                transition_report=transition_report,
            )
        finally:
            if owns_pause:
                self._resume_parent()

    def _build_and_hand_off_child(
        self,
        *,
        parent: dict[str, Any],
        evidence: Mapping[str, Any],
        raw_report: Mapping[str, Any],
        result: Mapping[str, Any],
        seed: Mapping[str, Any],
        deadline: float | None,
        discovery: Mapping[str, Any],
        new_parameters: list[Any],
        proposed_parameters: list[Any],
        evidence_by_parameter: Any,
        transition_report: Any,
    ) -> dict[str, Any] | None:
        """Materialize, export and replay one child while the parent is paused."""
        materialize_candidate_key = str(result.get("candidate_key") or self._target_key).split("::", 1)[0]
        try:
            materialized = self.materialize_fn(
                raw_report,
                plugin_slug=self.plugin_slug,
                candidate_key=materialize_candidate_key,
                known_parameters=proposed_parameters,
                for_replay=False,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self._record_event({**discovery, "event_id": "", "status": "REJECTED",
                                "reason": "CHILD_CONFIG_MATERIALIZATION_FAILED", "detail": str(exc)})
            self._probes.recover_parent_after_failure(parent, deadline)
            return None
        if deadline is not None and self.clock() >= deadline:
            self._record_event({
                "kind": "PARAMETER_DISCOVERY",
                "status": "REJECTED",
                "reason": "BUDGET_EXPIRED",
                "version": parent["version"],
                "request_id": evidence.get("request_id"),
            })
            return None
        next_version = f"v{1 + len(self.state['attempts'])}"
        attempt = {
            "version": next_version, "parent_version": parent["version"],
            "request_id": evidence.get("request_id"), "status": "exporting",
        }
        generated_dir = self.config_dir / "versions" / next_version / "exported"
        generated_summary_path = self.run_dir / "versions" / next_version / "generated_config_summary.json"
        failure_reason = "CHILD_CONFIG_EXPORT_FAILED"
        try:
            filesystem_path(generated_dir).mkdir(parents=True, exist_ok=True)
            filesystem_path(generated_summary_path.parent).mkdir(parents=True, exist_ok=True)
            generated = self.export_configs_fn(
                materialized, output_config_dir=generated_dir,
                summary_path=generated_summary_path, target_base="http://web",
                rest_route_fallback=True, compact_names=True,
            )
            rows = generated.get("generated") if isinstance(generated, Mapping) else None
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
                raise OnlineLinkedError("CHILD_CONFIG_EXPORT_FAILED")
            failure_reason = "CHILD_CONFIG_BUILD_FAILED"
            child_config = json.loads(filesystem_path(Path(rows[0]["config_path"])).read_text(encoding="utf-8-sig"))
            base_evidence = result.get("base_evidence") if isinstance(result.get("base_evidence"), Mapping) else evidence
            self._restore_request_values(child_config, base_evidence, parent)
            if isinstance(evidence_by_parameter, Mapping):
                for parameter in new_parameters:
                    parameter_evidence = evidence_by_parameter.get(_parameter_key(parameter))
                    if isinstance(parameter_evidence, Mapping):
                        self._restore_request_values(
                            child_config, parameter_evidence, parent,
                            only_parameters={_parameter_key(parameter)},
                        )
            duplicate_parameters = proposed_parameters if result.get("_pending_group_dispatch") is True else None
            if self._published_config_with_same_request(child_config, duplicate_parameters) is not None:
                self._record_event({**discovery, "event_id": "", "status": "IGNORED",
                                    "reason": "NO_SEMANTIC_PROGRESS"})
                return None
            self.state["attempts"].append(attempt)
            config_generation_started_at = self.clock()
            replay_config = copy.deepcopy(child_config)
            _replace_fuzzable_values_with_placeholder(child_config)
            child_path = self._write_config(next_version, child_config)
            child = self._new_version(
                next_version, child_config, child_path, parent, discovery["event_id"],
                materialized["suggested_seeds"][0] if isinstance(transition_report, Mapping) else seed,
                config_generation_seconds=round(max(0.0, self.clock() - config_generation_started_at), 3),
            )
            child["known_parameters"] = proposed_parameters
            child["discovery_payload_hash"] = _request_payload_hash(evidence.get("request"))
            # parameter_replay_v1 covers discovery while a worker fuzzes; descendants keep their batch's origin.
            child["evidence_origin"] = str(
                (parent.get("evidence_origin") if self._replay_discovery_active
                 else result.get("evidence_origin") or evidence.get("evidence_origin")) or "worker_poll"
            )
            if self._replay_discovery_active:
                child["discovery_origin"] = "replay_guard"
            self._reports[next_version] = copy.deepcopy(materialized)
            self.force_replay_only_fn(replay_config)
            replay_path = self._write_config(next_version, replay_config, replay=True)
            child["replay_config_path"] = str(replay_path)
            child["replay_config_hash"] = config_hash(replay_config)
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            return self._probes.reject_child_attempt(
                parent, attempt, discovery, failure_reason, deadline, detail=str(exc),
            )
        self._write_state()
        if deadline is not None and self.clock() >= deadline:
            child["status"] = "not_started_budget_expired"
            child["terminal_reason"] = "BUDGET_EXPIRED"
            attempt.update(status=child["status"], reason=child["terminal_reason"])
            self._write_state()
            return child
        self.handoff_to_next_worker(parent, child, materialized, replay_path, deadline=deadline)
        attempt.update(status=child["status"], reason=child["terminal_reason"])
        self._write_state()
        return child


    def _failed_batch_parameters(
        self, parent: Mapping[str, Any], proposed: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        return failed_batch_parameters(parent, proposed, versions=self.state.get("versions", []))

    def _retain_pending_runtime_candidates(
        self, groups: Sequence[Mapping[str, Any]], parent: Mapping[str, Any],
    ) -> None:
        self._evidence_runner.retain_pending_runtime_candidates(groups, parent)

    def _discard_pending_runtime_candidates(self, groups: Sequence[Mapping[str, Any]]) -> None:
        self._evidence_runner.discard_pending_runtime_candidates(groups)

    @staticmethod
    def _config_request_key(config: Mapping[str, Any]) -> str:
        return config_request_key(config)

    def _published_config_with_same_request(
        self, config: Mapping[str, Any], proposed_parameters: Sequence[Mapping[str, Any]] | None,
    ) -> dict[str, Any] | None:
        return published_config_with_same_request(config, proposed_parameters, versions=self.state.get("versions", []))


    def _baseline_identity_complete(
        self, request: Mapping[str, Any], zend: Mapping[str, Any], parent: Mapping[str, Any],
    ) -> bool:
        return baseline_identity_complete(request, zend, parent, plugin_slug=self.plugin_slug)

    def _parameter_replay_fields(
        self, parent: Mapping[str, Any], child: Mapping[str, Any], baseline: Mapping[str, Any] | None,
    ) -> list[dict[str, str]]:
        return parameter_replay_fields(parent, child, baseline, plugin_slug=self.plugin_slug, registry=self.registry)

    def _baseline_evidence(self, evidence: Mapping[str, Any], version: Mapping[str, Any]) -> dict[str, str]:
        return baseline_evidence(evidence, version, plugin_slug=self.plugin_slug)


    def _probe_context_key(
        self, parent: Mapping[str, Any], probe: Mapping[str, Any], evidence: Mapping[str, Any],
    ) -> str:
        return probe_context_key(parent, probe, evidence, plugin_slug=self.plugin_slug)

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
    ) -> dict[str, Any] | None:
        return self._probes.run_pending_probe(
            parent=parent, evidence=evidence, raw_report=raw_report, convergence=convergence,
            probe=probe, seed=seed, deadline=deadline,
        )

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
    ) -> dict[str, Any] | None:
        return self._probes.run_pending_probe_once(
            parent=parent, evidence=evidence, raw_report=raw_report, convergence=convergence,
            probe=probe, seed=seed, deadline=deadline,
        )

    def _restore_request_values(
        self, config: dict[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
        *, only_parameters: set[tuple[str, str, str]] | None = None,
    ) -> None:
        restore_request_values(config, evidence, parent, only_parameters=only_parameters)

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

        if self._observe_parent_exit() is not None:
            child["worker_status"] = "not_started_parent_exited"
            child["terminal_reason"] = str(self.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
            self._write_state()
            return False
        version_name = str(child["version"])
        replay_dir = self.run_dir / "versions" / version_name / "replay"
        request_dir = replay_dir / "request"
        zend_dir = replay_dir / "zend"
        row = {
            "config_slug": replay_path.relative_to(self.config_root).with_suffix("").as_posix(),
            "hook_name": child["hook_name"],
            "callback_id": child["callback_id"],
            "entrypoint_type": child["entrypoint_type"],
            "resolved_method": child["resolved_method"],
            "seed_variant_id": child.get("seed_variant_id", ""),
        }
        timeout = deadline - self.clock() if deadline is not None else self.max_seconds
        if timeout <= 0:
            child["worker_status"] = "not_started_budget_expired"
            child["terminal_reason"] = "BUDGET_EXPIRED"
            self._write_state()
            return False
        replay_run_id = f"{self.legacy_run_id}-{version_name}-replay"
        replay_started_at = self.clock()
        try:
            sender_result = self._probes.run_light_sender(
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
                self._handle_worker_exit(exit_code)
            child["worker_status"] = "not_started_parent_exited"
            child["terminal_reason"] = str(self.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
            self._write_state()
            return False
        if sender_result.get("status") == "parent_container_missing":
            self._failure = True
            self._active_container = ""
            child["worker_status"] = "not_started_parent_missing"
            child["terminal_reason"] = "PARENT_CONTAINER_MISSING"
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "PARENT_CONTAINER_MISSING"
            self._write_state()
            return False
        if sender_result.get("status") in {"parent_check_timeout", "parent_check_error"}:
            reason = "PARENT_CHECK_TIMEOUT" if sender_result.get("status") == "parent_check_timeout" else "PARENT_CHECK_ERROR"
            self._failure = True
            child["worker_status"] = "not_started_parent_check_timeout"
            child["terminal_reason"] = reason
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = reason
            self._write_state()
            return False
        parent_timeout = None if deadline is None else deadline - self.clock()
        deadline_expired = parent_timeout is not None and parent_timeout <= 0
        # Budget exhaustion is not evidence that the HTTP callback failed.
        # Keep any received request/Zend artifacts, but do not admit a late gate.
        if not deadline_expired:
            try:
                parent_exit_code = self._observe_parent_exit(timeout=parent_timeout)
            except (ParentInspectionTimeout, ParentInspectionError) as exc:
                reason = "PARENT_CHECK_TIMEOUT" if isinstance(exc, ParentInspectionTimeout) else "PARENT_CHECK_ERROR"
                self._failure = True
                child["worker_status"] = "not_started_parent_check_timeout"
                child["terminal_reason"] = reason
                self.state["terminal_status"] = "NOT_VERIFIED"
                self.state["terminal_reason"] = reason
                self._write_state()
                return False
            if parent_exit_code is not None:
                child["worker_status"] = "not_started_parent_exited"
                child["terminal_reason"] = str(self.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                self._write_state()
                return False
        verify_started_at = self.clock()
        replay_row = self._sender_runner_row(row, sender_result, replay_run_id)
        replay_report = {
            "legacy_run_id": replay_run_id,
            "runs": [replay_row],
            "timing": dict(sender_result.get("timing") or {}),
        }
        artifact_error = ""
        artifact_stage = ""
        try:
            self._save_replay_artifacts(
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
                plugin_slug=self.plugin_slug,
            )
            if baseline is not None and not self._baseline_identity_complete(
                baseline["request"], baseline["zend"], baseline_version,
            ):
                baseline = None
        except (OSError, RuntimeError, ValueError):
            baseline = None
        deadline_expired = deadline is not None and self.clock() >= deadline
        verified_parameters = (
            self._parameter_replay_fields(parent, child, baseline)
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
            "config_hash": self.config_hash(replay_path),
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
            replay_result["baseline_evidence"] = self._baseline_evidence(baseline, child)
        replay_result["timing"] = dict(sender_result.get("timing") or {})
        replay_result["timing"]["verify"] = round(self.clock() - verify_started_at, 3)
        replay_result["timing"]["total"] = round(self.clock() - replay_started_at, 3)
        replay_result["timing"].setdefault("handoff", 0.0)
        if artifact_error:
            replay_result["artifact_error"] = artifact_error
            if artifact_stage:
                replay_result["artifact_stage"] = artifact_stage
        child["replay_result"] = replay_result
        self.state.setdefault("replay_results", []).append(replay_result)

        def record_replay_event(status: str, reason: str) -> None:
            self._record_event({
                "kind": "CHILD_REPLAY", "status": status, "reason": reason,
                "hook_name": child.get("hook_name"), "version": version_name,
                "probe_id": None, "parameter": None, "timing": dict(replay_result["timing"]),
            })

        if replay_passed and non_success_response:
            child["status"] = "guard_unverified"
            child["worker_status"] = "not_started_guard_unverified"
            child["terminal_reason"] = "GUARD_SATISFACTION_UNKNOWN"
            if not self._replay_discovery_active:
                self.state.update(terminal_status="PARTIAL", terminal_reason="GUARD_SATISFACTION_UNKNOWN")
            record_replay_event("DEFERRED", "GUARD_SATISFACTION_UNKNOWN")
            self._write_state()
            return False

        if replay_passed:
            child["status"] = "replay_pass"
            child["terminal_reason"] = ""
            self._write_state()
            if self._replay_discovery_active:
                # The caller hands off once, after choosing among verified children.
                self._replay_evidence[version_name] = {**baseline, "evidence_origin": "child_replay"}
                return True
            if _is_ajax(child):
                target = self._discover_replay_guards(
                    child, {**baseline, "evidence_origin": "child_replay"}, deadline=deadline,
                    running_parent=parent,
                )
                if self.state.get("terminal_status") in {"NOT_VERIFIED", "VULN_FOUND"} or not self._active_container:
                    child["worker_status"] = "not_started_parent_exited"
                    child["terminal_reason"] = str(self.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                    record_replay_event("PASS", child["terminal_reason"])
                    self._write_state()
                    return False
                if deadline is not None and self._deadline is not None:
                    deadline = max(deadline, self._deadline)
                if target is not child:
                    # record_replay_event reads these names, so its events describe the target.
                    child, version_name = target, str(target["version"])
                    replay_result = child["replay_result"]
                    merged_report = self._reports.get(version_name, merged_report)
            if self._observe_parent_exit() is not None:
                child["worker_status"] = "not_started_parent_exited"
                child["terminal_reason"] = str(self.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                record_replay_event("PASS", "PARENT_WORKER_EXITED")
                self._write_state()
                return False
            handoff_started_at = self.clock()
            priority_seed, blocked = self._priority_seed(parent, child, replay_result)
            if blocked:
                # The config would drop a field the replay proved: keep the parent instead.
                replay_result["passed"] = False
                child.update(status="replay_failed", worker_status="not_started_replay_failed", terminal_reason=blocked)
                record_replay_event("REJECTED", blocked)
                self._write_state()
                return False
            if not self._stop_worker(parent, "HANDOFF_TO_" + str(child["version"])):
                child["worker_status"] = "not_started_parent_stop_failed"
                child["terminal_reason"] = "WORKER_STOP_FAILED"
                replay_result["timing"]["handoff"] = round(self.clock() - handoff_started_at, 3)
                record_replay_event("PASS", "WORKER_STOP_FAILED")
                self._write_state()
                return False
            if self._start_worker(child, deadline=deadline, priority_seed=priority_seed):
                self._active_version = str(child["version"])
                if child.get("resolved_method") != parent.get("resolved_method"):
                    candidate = candidate_from_seed_item(merged_report["suggested_seeds"][0], plugin_slug=self.plugin_slug)
                    variant = str(merged_report["suggested_seeds"][0]["seed"].get("seed_variant_id") or "")
                    self._target_key = canonical_identity_id(candidate) + (f"::{variant}" if variant else "")
                replay_result["timing"]["handoff"] = round(self.clock() - handoff_started_at, 3)
                record_replay_event("PASS", (
                    "PARAMETER_REPLAY_VERIFIED" if replay_result["verification_policy"] == PARAMETER_REPLAY_POLICY
                    else "CALLBACK_BASELINE_VERIFIED"
                ))
                self._write_state()
                return True
            replay_result["timing"]["handoff"] = round(self.clock() - handoff_started_at, 3)
            if child["worker_status"] == "not_started_budget_expired":
                record_replay_event("PASS", "BUDGET_EXPIRED")
                self._write_state()
                return False
            child["terminal_reason"] = "WORKER_START_FAILED"
            self._failure = True
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "CHILD_WORKER_START_FAILED"
            record_replay_event("PASS", "CHILD_WORKER_START_FAILED")
            self._write_state()
        else:
            child["status"] = "replay_failed"
            child["worker_status"] = "not_started_replay_failed"
            if deadline_expired:
                child["terminal_reason"] = "CANDIDATE_BUDGET_EXPIRED"
                self.state["terminal_status"] = "BOUNDED_ONLINE_COMPLETE"
                self.state["terminal_reason"] = "BUDGET_EXPIRED"
                record_replay_event("DEFERRED", "CANDIDATE_BUDGET_EXPIRED")
                self._write_state()
                return False
            if artifact_error:
                child["terminal_reason"] = "REPLAY_ARTIFACT_SAVE_FAILED"
            elif replay_report.get("error") or replay_row.get("process_status") in {"failed", "runner_error"}:
                child["terminal_reason"] = "REPLAY_PROCESS_FAILED"
            elif replay_row.get("validation_status") != "callback_reached":
                child["terminal_reason"] = str(replay_row.get("validation_reason") or "CALLBACK_NOT_REACHED")
            elif replay_result.get("transport_error"):
                child["terminal_reason"] = "REPLAY_TRANSPORT_NOT_VERIFIED"
            elif replay_result.get("unverified_parameters"):
                child["terminal_reason"] = "PARAMETER_REPLAY_NOT_VERIFIED"
            else:
                child["terminal_reason"] = "CALLBACK_BASELINE_NOT_VERIFIED"
            # A paused parent resumes its round (or fails loudly in _resume_parent).
            if not self._replay_discovery_active and self._pause is None:
                self._failure = True
                self.state["terminal_status"] = "NOT_VERIFIED"
                self.state["terminal_reason"] = "CHILD_REPLAY_FAILED"
            record_replay_event(
                "REJECTED",
                str(
                    replay_result.get("artifact_error")
                    or replay_row.get("validation_reason")
                    or "CALLBACK_BASELINE_NOT_VERIFIED"
                ),
            )
            self._write_state()
        return False

    def _discover_replay_guards(
        self, child: dict[str, Any], evidence: Mapping[str, Any], *, deadline: float | None,
        running_parent: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._gate_runner.discover_replay_guards(
            child, evidence, deadline=deadline, running_parent=running_parent,
        )

    def _select_v0(self) -> tuple[Mapping[str, Any], dict[str, Any], str] | None:
        return self._gate_runner.select_v0()

    def _new_version(
        self,
        name: str,
        config: Mapping[str, Any],
        config_path: Path,
        parent: Mapping[str, Any] | None,
        discovery_event: str | None,
        seed_item: Mapping[str, Any],
        *,
        config_generation_seconds: float | None = None,
    ) -> dict[str, Any]:
        record = new_version_record(
            name, config, config_path, parent, discovery_event, seed_item,
            plugin_slug=self.plugin_slug, config_generation_seconds=config_generation_seconds,
        )
        self.state["versions"].append(record)
        self._write_state()
        return record

    def _start_worker(
        self, version: dict[str, Any], *, deadline: float | None = None,
        priority_seed: Mapping[str, Any] | None = None,
    ) -> bool:
        if self._active_container:
            return False
        if deadline is not None and self.clock() >= deadline:
            version["worker_status"] = "not_started_budget_expired"
            version["terminal_reason"] = "BUDGET_EXPIRED"
            self._write_state()
            return False
        version_name = str(version["version"])
        config_path = Path(str(version["config_path"]))
        runtime_slug = config_path.relative_to(self.config_root).with_suffix("").as_posix()
        safe_run = re.sub(r"[^A-Za-z0-9_.-]+", "-", self.legacy_run_id).strip("-") or "online-linked"
        container_name = f"hookphuzz-online-linked-{safe_run}-{version_name}"
        worker_run_id = str(version.get("worker_run_id") or f"{self.legacy_run_id}-{version_name}")
        version["worker_run_id"] = worker_run_id
        handoff_key = f"{version_name}-{uuid.uuid4().hex}"
        version["handoff_key"] = handoff_key
        # The priority round belongs to the first activation of a verified config only.
        grant = priority_seed is not None and not version.get("priority_seed")
        command = worker_start_command(
            version, container_name=container_name, runtime_slug=runtime_slug, service=self.service,
            priority_seed=priority_seed if grant else None,
        )
        try:
            timeout = 30 if deadline is None else min(30, max(0.0, deadline - self.clock()))
            result = self.run_command(command, timeout=timeout, check=False, capture_output=True, text=True)
        except Exception as exc:
            version["worker_status"] = "start_failed"
            version["terminal_reason"] = f"WORKER_START_FAILED: {exc}"
            self._failure = True
            self._write_state()
            return False
        if int(getattr(result, "returncode", 1)) != 0:
            version["worker_status"] = "start_failed"
            version["terminal_reason"] = str(getattr(result, "stderr", "") or "WORKER_START_FAILED").strip()
            self._failure = True
            self._write_state()
            return False
        version["worker_status"] = "started"
        version["status"] = "replaying" if version.get("config_type") == "replay_only" else "fuzzing"
        if grant:
            version["priority_seed"] = dict(priority_seed)
        self._active_container = container_name
        self._worker_started_at[version_name] = self.clock()
        self.state["workers"].append({
            "version": version_name,
            "container_name": container_name,
            "run_id": worker_run_id,
            "status": "started",
            "command": command,
        })
        self._write_state()
        return True

    def _worker_exit_code(self, timeout: float | None = None) -> int | None:
        return worker_exit_code(self._active_container, timeout=timeout, run_command=self.run_command)

    def _priority_seed(
        self, parent: Mapping[str, Any], child: Mapping[str, Any], replay_result: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Reference the verified replay seed and its fuzzable new fields; never request values.

        Returns (descriptor, block_reason); a block reason stops the handoff.
        """
        if replay_result.get("verification_policy") != PARAMETER_REPLAY_POLICY:
            return None, None
        event = {"kind": "PRIORITY_SEED", "version": child.get("version")}
        verified = {
            (str(row.get("bucket") or ""), str(row.get("name") or ""))
            for row in replay_result.get("verified_parameters") or [] if isinstance(row, Mapping)
        }

        def covers(field: tuple[str, str], proven: tuple[str, str]) -> bool:
            # Zend proves the top-level key; the materializer may fuzz nested selectors under it.
            return field[0] == proven[0] and (field[1] == proven[1] or field[1].split("[", 1)[0] == proven[1])

        try:
            child_path = Path(str(child["config_path"]))
            all_fields = _config_fields(child_path, fuzzable_only=False)
            # Only fields the running parent could not fuzz are new (nested selectors included).
            fuzzable = _config_fuzzable_fields(child_path) - _config_fuzzable_fields(Path(str(parent["config_path"])))
            replay_slug = Path(str(child["replay_config_path"])).relative_to(self.config_root).with_suffix("").as_posix()
        except (KeyError, OSError, ValueError, re.error) as exc:
            self._record_event({**event, "status": "REJECTED", "reason": "CONFIG_FIELDS_UNAVAILABLE", "detail": str(exc)})
            return None, "CONFIG_FIELDS_UNAVAILABLE"
        missing = sorted(p for p in verified if not any(covers(f, p) for f in all_fields))
        if missing:
            self._record_event({**event, "status": "REJECTED", "reason": "VERIFIED_FIELD_NOT_IN_CONFIG",
                                "fields": [list(field) for field in missing]})
            return None, "VERIFIED_FIELD_NOT_IN_CONFIG"
        # A verified field the updated config keeps fixed gets no priority attempts.
        targets = sorted(f for f in fuzzable if any(covers(f, p) for p in verified))
        if not targets:
            # The plan switches config only for a new fuzzable param: keep the parent.
            self._record_event({**event, "status": "REJECTED", "reason": "NO_NEW_FUZZABLE_TARGET"})
            return None, "NO_NEW_FUZZABLE_TARGET"
        ack = parent.get("pause_ack") if isinstance(parent.get("pause_ack"), Mapping) else {}
        descriptor = {
            "replay_slug": replay_slug,
            "replay_hash": str(child.get("replay_config_hash") or ""),
            "targets": [list(target) for target in targets],
            "mode": self.priority_energy_mode,
            "allocated_energy": ack["allocated_energy"] if type(ack.get("allocated_energy")) is int else 0,
            "attempts_used": ack["attempts_used"] if type(ack.get("attempts_used")) is int else 0,
        }
        attempt = next((row for row in reversed(self.state.get("attempts", []))
                        if row.get("version") == child.get("version")), {})
        # The old worker's PHUZZ energy counts only for the very request this seed replays:
        # same request ID and the same sent input (a probe or the replay may have changed it).
        rows = (replay_result.get("runner") or {}).get("runs") or [{}]
        seed_payload = _request_payload_hash(rows[0].get("request_payload"))
        if (type(ack.get("seed_phuzz_energy")) is int and ack.get("request_id")
                and ack.get("request_id") == attempt.get("request_id")
                and seed_payload and seed_payload == child.get("discovery_payload_hash")):
            descriptor["seed_phuzz_energy"] = ack["seed_phuzz_energy"]
        self._record_event({
            **event, "status": "GRANTED", "reason": "PARAMETER_REPLAY_VERIFIED", "mode": descriptor["mode"],
            "discovery_request_id": attempt.get("request_id"), "pause_round_id": ack.get("round_id"),
            "allocated_energy": descriptor["allocated_energy"], "attempts_used": descriptor["attempts_used"],
            "targets": descriptor["targets"], "seed_phuzz_energy": descriptor.get("seed_phuzz_energy"),
        })
        return descriptor, None

    def _handoff_command(self, *args: str, deadline: float | None) -> dict[str, Any] | None:
        return handoff_command(
            self._active_container, *args, deadline=deadline, clock=self.clock, run_command=self.run_command,
        )

    def _pause_parent(self, parent: Mapping[str, Any], deadline: float | None, *, request_id: str = "") -> bool:
        """Ask the running worker to stop between requests and wait for its matching ACK."""
        key = str(parent.get("handoff_key") or "")
        run_id = str(parent.get("worker_run_id") or "")
        event = {"kind": "WORKER_PAUSE", "version": parent.get("version"), "worker_run_id": run_id}
        if not key or not self._active_container:
            self._record_event({**event, "status": "REJECTED", "reason": "PAUSE_UNAVAILABLE"})
            return False
        token = uuid.uuid4().hex
        self._pause = {"container": self._active_container, "key": key, "token": token}
        try:
            return self._await_pause_ack(parent, event, key, token, run_id, deadline, request_id)
        except BaseException:
            self._resume_parent()
            raise

    def _await_pause_ack(
        self, parent: Mapping[str, Any], event: Mapping[str, Any], key: str, token: str, run_id: str,
        deadline: float | None, request_id: str = "",
    ) -> bool:
        self._record_event({**event, "status": "REQUESTED", "reason": "PARAMETER_HANDOFF"})
        wait_until = (deadline - 2 * self._sender_seconds if deadline is not None
                      else self.clock() + self.max_seconds)
        reason = "PAUSE_REQUEST_FAILED"
        if self._handoff_command("request", key, token, run_id, *([request_id] if request_id else []),
                                 deadline=wait_until) is not None:
            reason = "PAUSE_ACK_TIMEOUT"
            while self.clock() < wait_until:
                ack = self._handoff_command("ack", key, deadline=wait_until)
                if ack and ack.get("token") == token and ack.get("worker_run_id") == run_id:
                    snapshot = {name: ack.get(name) for name in (
                        "round_id", "allocated_energy", "attempts_used", "request_id", "seed_phuzz_energy")}
                    record = self._version(str(parent.get("version"))) or {}
                    record["pause_ack"] = {**snapshot, "token": token, "acked_at": self.clock()}
                    self._record_event({**event, "status": "ACKNOWLEDGED", "reason": "PAUSE_ACK", **snapshot})
                    return True
                try:
                    exit_code = self._worker_exit_code(timeout=min(10.0, max(0.0, wait_until - self.clock())))
                except (ParentInspectionTimeout, ParentInspectionError):
                    exit_code = None
                if exit_code is not None:
                    reason = "PAUSE_WORKER_EXITED"
                    break
                self.sleeper(min(0.2, max(0.0, wait_until - self.clock())))
        self._record_event({**event, "status": "REJECTED", "reason": reason})
        self._resume_parent()
        return False

    def _resume_parent(self) -> bool:
        """Release the pause only for the same worker container while it still runs."""
        pause, self._pause = self._pause, None
        if pause is None or self._active_container != pause["container"]:
            return True
        try:
            running = self._worker_exit_code(timeout=10.0) is None
        except (ParentInspectionTimeout, ParentInspectionError):
            running = True  # unknown: the token-guarded release is harmless if the container is gone
        response = self._handoff_command("release", pause["key"], pause["token"], deadline=None) if running else None
        # {"released": false}: no request with this token is pending, so nothing is paused.
        released = response is not None
        version = self._version(self._active_version) or {}
        if released:
            reason = "PAUSE_RELEASED" if response.get("released") is True else "PAUSE_NOT_PENDING"
        else:
            reason = "PAUSE_RELEASE_FAILED" if running else "PAUSED_WORKER_NOT_RUNNING"
        self._record_event({
            "kind": "WORKER_PAUSE", "status": "RELEASED" if released else "REJECTED", "reason": reason,
            "version": version.get("version"), "worker_run_id": version.get("worker_run_id"),
        })
        if not released and running and self.state.get("terminal_status") is None:
            self._failure = True
            self.state.update(terminal_status="NOT_VERIFIED", terminal_reason="PAUSE_RELEASE_FAILED")
            self._write_state()
        return released

    def _stop_active_worker(self, reason: str) -> None:
        version = self._version(self._active_version)
        if version is not None:
            self._stop_worker(version, reason)

    def _stop_worker(self, version: Mapping[str, Any], reason: str) -> bool:
        container_name = self._active_container
        if not container_name:
            return True
        stopped, error = remove_container(
            container_name, clock=self.clock, sleeper=self.sleeper, run_command=self.run_command,
        )
        status = "stopped" if stopped else "stop_failed"
        for worker in reversed(self.state["workers"]):
            if worker.get("container_name") == container_name:
                worker["status"] = status
                worker["terminal_reason"] = reason
                if not stopped:
                    worker["stop_error"] = error
                break
        record = self._version(str(version["version"]))
        if record is not None:
            record["worker_status"] = "stopped" if status == "stopped" else status
            record["terminal_reason"] = reason
        if stopped:
            self._active_container = ""
        else:
            self._failure = True
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "WORKER_STOP_FAILED"
        self._write_state()
        return stopped

    def _save_replay_artifacts(
        self, row: Mapping[str, Any], request_dir: Path, zend_dir: Path,
        *, strict_correlation: bool | None = None,
    ) -> None:
        save_replay_artifacts(
            row, request_dir, zend_dir, strict_correlation=strict_correlation,
            load_request=lambda name: self.load_artifact(name),
            load_zend=lambda name: self.load_zend_artifact(name),
            list_zend=lambda: self.list_zend_artifacts(),
            write_json=self._copy_json,
        )

    def _write_config(self, version: str, config: Mapping[str, Any], *, replay: bool = False) -> Path:
        filename = f"{version}-replay.json" if replay else f"{version}-config.json"
        relative = Path("versions") / version / ("replay" if replay else "") / filename
        config_path = self.config_dir / relative
        _write_exclusive_json(config_path, config)
        mirror_path = self.run_dir / relative
        _write_exclusive_json(mirror_path, config)
        return config_path

    def _copy_json(self, path: Path, value: Any) -> None:
        if value is None:
            return
        _write_exclusive_json(path, value)

    def _record_event(self, event: Mapping[str, Any], *, checkpoint: bool = True) -> dict[str, Any]:
        item = dict(event)
        if not item.get("event_id"):
            encoded = json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))
            item["event_id"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
        if any(existing.get("event_id") == item["event_id"] for existing in self.state["events"]):
            return item
        self.state["events"].append(item)
        filesystem_path(self.events_path.parent).mkdir(parents=True, exist_ok=True)
        with filesystem_path(self.events_path).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        if checkpoint:
            self._write_state()
        return item

    def _write_state(self) -> None:
        if self.state.get("terminal_status") == "BOUNDED_ONLINE_COMPLETE":
            if self._hard_deadline is not None and self.clock() >= self._hard_deadline:
                self.state.update(terminal_status="PARTIAL", terminal_reason="HARD_CANDIDATE_TIME_CAP")
            elif self.state.get("pending_runtime_candidates") or self.state.get("pending_probe_queue"):
                self.state["terminal_status"] = "PARTIAL"
                if self.state.get("terminal_reason") != "NO_NEW_PROGRESS":
                    self.state["terminal_reason"] = "PENDING_RUNTIME_VERIFICATION"
        if self._budget_started_at is not None:
            now = self.clock()
            self.state["budget"] = {
                "elapsed_seconds": self._elapsed_seconds + max(0.0, now - self._budget_started_at),
                "remaining_seconds": max(0.0, self._deadline - now),
                "hard_remaining_seconds": max(0.0, self._hard_deadline - now) if self._hard_deadline is not None else None,
                "progress_keys": sorted(self._progress_keys),
                "saved_at": time.time(),
            }
        self.state["checkpoint"] = {
            "context_key_version": _CANDIDATE_CONTEXT_KEY_VERSION,
            "candidate_context_key": self.state.get("candidate_context_key"),
            "reports": self._reports, "raw_report": self._raw_report,
            "targets": self._targets, "target_key": self._target_key,
            "active_version": self._active_version, "sender_seconds": self._sender_seconds,
            "input_hash": hashlib.sha256(self.suggested_seeds.read_bytes()).hexdigest(),
        }
        _write_json(self.state_path, self.state)

    def _load_checkpoint(self) -> tuple[dict[str, Any], dict[str, Any]]:
        saved = json.loads(self.state_path.read_text(encoding="utf-8-sig"))
        validate_resume_checkpoint(saved, expected=self.state)
        checkpoint = saved.get("checkpoint", {})
        if checkpoint.get("input_hash") != hashlib.sha256(self.suggested_seeds.read_bytes()).hexdigest():
            raise ValueError("resume candidate input changed")
        budget = saved["budget"]
        for row in saved["versions"]:
            if self.config_hash(Path(row["config_path"])) != row["config_hash"]:
                raise ValueError("resume config hash changed")
            if row.get("replay_config_hash") and self.config_hash(Path(row["replay_config_path"])) != row["replay_config_hash"]:
                raise ValueError("resume replay config hash changed")
        version = next(row for row in saved["versions"] if row["version"] == checkpoint["active_version"])
        candidate_context_key = saved.get("candidate_context_key")
        if (not isinstance(candidate_context_key, str)
                or checkpoint.get("candidate_context_key") != candidate_context_key):
            raise ValueError("resume candidate request context changed")
        config_path = version.get("replay_config_path") or version["config_path"]
        config = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
        self.state = saved
        self.state.setdefault("resume_history", []).append({
            "terminal_status": saved.get("terminal_status"), "terminal_reason": saved.get("terminal_reason"),
            "budget": copy.deepcopy(budget),
        })
        self.state.update(terminal_status=None, terminal_reason=None,
                          resume_count=int(saved.get("resume_count", 0)) + 1)
        self._reports = checkpoint["reports"]
        self._raw_report = checkpoint["raw_report"]
        self._targets = checkpoint["targets"]
        self._target_key = checkpoint["target_key"]
        self._active_version = version["version"]
        self._active_container = ""
        self._sender_seconds = checkpoint["sender_seconds"]
        offline_seconds = max(0.0, time.time() - budget["saved_at"])
        self._elapsed_seconds = budget["elapsed_seconds"] + offline_seconds
        self._budget_started_at = self.clock()
        self._hard_deadline = None
        if self.hard_seconds is not None:
            self._hard_deadline = self._budget_started_at + min(
                max(0.0, budget["hard_remaining_seconds"] - offline_seconds),
                max(0.0, self.hard_seconds - self._elapsed_seconds))
        self._deadline = self._budget_started_at + max(0.0, budget["remaining_seconds"] - offline_seconds)
        if self._hard_deadline is not None:
            self._deadline = min(self._deadline, self._hard_deadline)
        if self.campaign_deadline is not None:
            self._deadline = min(self._deadline, self.campaign_deadline)
        self._progress_keys = {tuple(key) for key in budget["progress_keys"]}
        self.max_versions = saved["max_versions"]
        version["previous_worker_run_id"] = version.get("worker_run_id")
        version["worker_run_id"] = f"{self.legacy_run_id}-{version['version']}-resume-{self.state['resume_count']}"
        version.setdefault("readiness_history", []).append(copy.deepcopy(version.get("readiness")))
        for worker in saved["workers"]:
            if worker.get("version") == version["version"] and worker.get("status") == "started":
                self._active_container = worker["container_name"]
                if not self._stop_worker(version, "RESUME_REVALIDATION"):
                    raise ValueError("resume previous worker could not be stopped")
                break
        return version, config

    def _version(self, name: str) -> dict[str, Any] | None:
        return next((item for item in self.state["versions"] if item.get("version") == name), None)

    def config_hash(self, path: Path) -> str:
        return config_hash(json.loads(filesystem_path(Path(path)).read_text(encoding="utf-8")))

    def _admission_complete(self, parameter: Any, evidence: Mapping[str, Any], parent: Mapping[str, Any]) -> bool:
        return admission_complete(parameter, evidence, parent, plugin_slug=self.plugin_slug, registry=self.registry)

    def _inherit_callback_identity(
        self, parameter: Mapping[str, Any], parent: Mapping[str, Any],
    ) -> dict[str, Any]:
        return inherit_callback_identity(parameter, parent, plugin_slug=self.plugin_slug, registry=self.registry)

    def _probe_admission_complete(
        self, parameter: Mapping[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
    ) -> bool:
        return probe_admission_complete(
            parameter, evidence, parent, plugin_slug=self.plugin_slug, registry=self.registry,
            runtime_cookie_probes=self.runtime_cookie_probes, ajax=_is_ajax(parent),
        )


if __name__ == "__main__":
    from online_linked.coordination.campaign import main

    raise SystemExit(main())
