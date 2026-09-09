"""Online-linked coordinator for immutable, replay-gated PHUZZ workers."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

FUZZER_DIR = Path(__file__).resolve().parents[2]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.generated_config_runner import (
    STOP_ON_VULN_EXIT_CODE,
    list_request_artifacts,
    list_zend_artifacts,
    load_request_artifact,
    run_generated_configs,
)
from hook_energy.seed_generation.probe_sender import (
    ParentInspectionError,
    ParentInspectionTimeout,
    run_in_container,
)
from hook_energy.seed_generation.online_config_runner import (
    OnlineCoordinator,
    _load_zend_artifact,
    _write_exclusive_json,
    _write_json,
    config_hash,
    validate_v0_config,
)
from hook_energy.seed_generation.zend_runtime.bridge_cli import (
    converge_iteration,
    list_convergence_targets,
    verify_pass2_contract,
)
from seed_generation.config.config_exporter import (
    SeedConfigSkip,
    _force_replay_only,
    build_config_for_seed_item,
    export_seed_configs,
)
from seed_generation.convergence.convergence import materialize_convergence_seeds
from discovery.entrypoints.entrypoints import seed_template_for_callback
from discovery.entrypoints.method_resolution import resolve_http_methods
from zend_discovery.engine import runtime_parameter_is_accepted
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ArtifactLister = Callable[[], set[str]]
ArtifactLoader = Callable[[str], Any]
ConvergeRunner = Callable[..., dict[str, Any]]
TargetLister = Callable[..., list[dict[str, Any]]]
MaterializeRunner = Callable[..., dict[str, Any]]
Exporter = Callable[..., dict[str, Any]]
ReplayRunner = Callable[..., dict[str, Any]]
ProbeSender = Callable[..., dict[str, Any]]
Pass2Verifier = Callable[..., dict[str, int]]
ConfigBuilder = Callable[..., tuple[str, dict[str, Any]]]


def _parameter_key(parameter: Any) -> tuple[str, str, str]:
    if not isinstance(parameter, Mapping):
        return "", "", ""
    return (
        str(parameter.get("name") or ""),
        str(parameter.get("source") or "").upper(),
        str(parameter.get("location") or ""),
    )


class OnlineLinkedError(ValueError):
    """A coordinator transition cannot be completed safely."""


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
        registry: Mapping[str, Any] | None = None,
        registry_path: Path | None = None,
        service: str = "fuzzer-wordpress-plugin",
        run_command: CommandRunner = subprocess.run,
        list_artifacts: ArtifactLister = list_request_artifacts,
        load_artifact: ArtifactLoader = load_request_artifact,
        list_zend_artifacts: ArtifactLister = list_zend_artifacts,
        load_zend_artifact: ArtifactLoader = _load_zend_artifact,
        build_config_fn: ConfigBuilder = build_config_for_seed_item,
        list_targets_fn: TargetLister = list_convergence_targets,
        converge_fn: ConvergeRunner = converge_iteration,
        materialize_fn: MaterializeRunner = materialize_convergence_seeds,
        export_configs_fn: Exporter = export_seed_configs,
        force_replay_only_fn: Callable[[dict[str, Any]], None] = _force_replay_only,
        replay_runner: ReplayRunner = run_generated_configs,
        probe_sender: ProbeSender = run_in_container,
        process_factory: Callable[..., Any] = subprocess.Popen,
        verify_pass2_fn: Pass2Verifier = verify_pass2_contract,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        campaign_deadline: float | None = None,
    ) -> None:
        if not 1 <= max_seconds <= 120:
            raise ValueError("max_seconds must be between 1 and 120")
        if not 1 <= max_versions <= 20:
            raise ValueError("max_versions must be between 1 and 20")
        self.suggested_seeds = Path(suggested_seeds)
        self.bootstrap_config = Path(bootstrap_config) if bootstrap_config else None
        self.config_root = Path(config_root)
        self.output_root = Path(output_root)
        self.plugin_slug = plugin_slug
        self.legacy_run_id = legacy_run_id
        self.max_seconds = max_seconds
        self.max_versions = max_versions
        self.service = service
        self.run_command = run_command
        self.list_artifacts = list_artifacts
        self.load_artifact = load_artifact
        self.list_zend_artifacts = list_zend_artifacts
        self.load_zend_artifact = load_zend_artifact
        self.build_config_fn = build_config_fn
        self.list_targets_fn = list_targets_fn
        self.converge_fn = converge_fn
        self.materialize_fn = materialize_fn
        self.export_configs_fn = export_configs_fn
        self.force_replay_only_fn = force_replay_only_fn
        self.replay_runner = replay_runner
        self.probe_sender = probe_sender
        self.process_factory = process_factory
        self.verify_pass2_fn = verify_pass2_fn
        self.clock = clock
        self.sleeper = sleeper
        self.campaign_deadline = float(campaign_deadline) if campaign_deadline is not None else None
        # Keep nested evidence/config paths below Windows MAX_PATH for long run IDs.
        storage_id = hashlib.sha256(self.legacy_run_id.encode("utf-8")).hexdigest()[:16]
        self.run_dir = self.output_root / "online-linked" / storage_id
        self.config_dir = self.config_root / "online-linked" / self.plugin_slug / storage_id
        if registry is not None:
            self.registry = dict(registry)
        elif registry_path is not None:
            self.registry = json.loads(Path(registry_path).read_text(encoding="utf-8-sig"))
        else:
            raise ValueError("online-linked requires a callback registry")
        self.registry_path = Path(registry_path) if registry_path is not None else None
        if not isinstance(self.registry, Mapping):
            raise ValueError("callback registry must be an object")
        self.state: dict[str, Any] = {
            "schema_version": 1,
            "mode": "online-linked",
            "plugin_slug": plugin_slug,
            "legacy_run_id": legacy_run_id,
            "max_seconds": max_seconds,
            "max_versions": max_versions,
            "campaign_deadline": self.campaign_deadline,
            "campaign_status": "running" if self.campaign_deadline is not None else None,
            "versions": [],
            "attempts": [],
            "probe_attempts": [],
            "candidate_queue": [],
            "queued_candidate_ids": [],
            "events": [],
            "workers": [],
            "terminal_status": None,
            "terminal_reason": None,
        }
        self.state_path = self.run_dir / "state.json"
        self.events_path = self.run_dir / "events.jsonl"
        self._raw_report: dict[str, Any] | None = None
        self._reports: dict[str, dict[str, Any]] = {}
        self._targets: list[dict[str, Any]] = []
        self._target_key = ""
        self._active_version = ""
        self._active_container = ""
        self._seen_pairs: set[tuple[str, str]] = set()
        self._failure = False

    def run(self) -> int:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._write_state()
        try:
            selected = self._select_v0()
            if selected is None:
                self.state["terminal_status"] = "NOT_VERIFIED"
                self.state["terminal_reason"] = "V0_PREREQUISITE_GATE_FAILED"
                self._write_state()
                return 2
            item, config, target_key = selected
            config_path = self._write_config("v0", config)
            version = self._new_version("v0", config, config_path, None, None, item)
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

            while self.clock() < deadline:
                worker_exit_code = self._observe_parent_exit()
                if worker_exit_code is not None:
                    if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
                        return 1 if self._failure else 0
                    return 1
                for evidence in self.read_new_runtime_evidence(deadline=deadline):
                    self.advance_online_version(evidence, deadline=deadline)
                    if self.state["terminal_reason"] == "WORKER_STOP_FAILED" or not self._active_container:
                        break
                if self.state["terminal_reason"] == "WORKER_STOP_FAILED" or not self._active_container:
                    break
                worker_exit_code = self._worker_exit_code()
                if worker_exit_code is not None:
                    self._handle_worker_exit(worker_exit_code)
                    if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
                        return 1 if self._failure else 0
                    return 1
                remaining = deadline - self.clock()
                if remaining > 0:
                    self.sleeper(min(0.5, remaining))
            self._stop_active_worker("BUDGET_EXPIRED")
            self._mark_campaign_expired_if_needed()
            if self.state["terminal_status"] is None:
                self.state["terminal_status"] = "BOUNDED_ONLINE_COMPLETE"
                self.state["terminal_reason"] = "BUDGET_EXPIRED"
            self._write_state()
            return 1 if self._failure else 0
        except Exception as exc:
            self._failure = True
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = f"ONLINE_LINKED_COORDINATOR_ERROR: {exc}"
            self._write_state()
            self._stop_active_worker("COORDINATOR_ERROR")
            return 1

    def _handle_worker_exit(self, worker_exit_code: int) -> None:
        version = self._version(self._active_version)
        if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
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

    def _observe_parent_exit(self, *, timeout: float | None = None) -> int | None:
        exit_code = self._worker_exit_code(timeout=timeout)
        if exit_code is not None:
            self._handle_worker_exit(exit_code)
        return exit_code

    def _run_light_sender(
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
    ) -> dict[str, Any]:
        if not self._active_container:
            return {"status": "parent_container_missing", "error": "PARENT_CONTAINER_MISSING"}
        timeout = self.max_seconds
        if deadline is not None:
            timeout = min(30, max(0, deadline - self.clock()))
        if timeout <= 0:
            return {"status": "timeout", "error": "SENDER_BUDGET_EXPIRED"}
        config_slug = config_path.relative_to(self.config_root).with_suffix("").as_posix()
        result = self.probe_sender(
            self._active_container,
            config_slug=config_slug,
            request_id=request_id,
            run_id=run_id,
            timeout_seconds=timeout,
            expected={
                "plugin_slug": self.plugin_slug,
                "hook_name": hook_name,
                "callback_id": callback_id,
                "method": method,
                "auth_context": auth_context,
                "seed_variant_id": seed_variant_id,
            },
            process_factory=self.process_factory,
            parent_exit_code=self._worker_exit_code,
            clock=self.clock,
            sleeper=self.sleeper,
        )
        return dict(result) if isinstance(result, Mapping) else {"status": "sender_invalid"}

    @staticmethod
    def _sender_runner_row(base: Mapping[str, Any], result: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        reached = result.get("status") == "callback_reached" or result.get("callback_reached") is True
        status = "stopped_on_callback" if reached else (
            "window_elapsed" if result.get("status") == "timeout" else "failed"
        )
        row = {
            **dict(base),
            "legacy_run_id": run_id,
            "process_status": status,
            "callback_reached": reached,
            "validation_status": result.get("validation_status") or (
                "callback_reached" if reached else "registered_not_executed"
            ),
            "validation_reason": result.get("validation_reason") or result.get("error") or "",
            "matched_artifact": result.get("request_name"),
            "request_artifacts": [result["request_name"]] if result.get("request_name") else [],
            "zend_artifact": result.get("zend_name"),
            "request_payload": result.get("request"),
            "zend_payload": result.get("zend"),
            "timing": dict(result.get("timing") or {}),
        }
        return row

    def _candidate_deadline(self) -> float:
        candidate_deadline = self.clock() + self.max_seconds
        if self.campaign_deadline is not None:
            return min(candidate_deadline, self.campaign_deadline)
        return candidate_deadline

    def _mark_campaign_expired_if_needed(self) -> None:
        if self.campaign_deadline is not None and self.clock() >= self.campaign_deadline:
            self.state["campaign_status"] = "bounded"
            self.state["campaign_stop_reason"] = "CAMPAIGN_BUDGET_EXPIRED"

    def _gate_v0(self, version: dict[str, Any], config: Mapping[str, Any], *, deadline: float) -> bool:
        """Require a correlated replay before starting any v0 worker."""
        if deadline - self.clock() < 1:
            version["terminal_reason"] = "BUDGET_EXPIRED"
            return False
        replay = copy.deepcopy(dict(config))
        self.force_replay_only_fn(replay)
        path = self._write_config("v0", replay, replay=True)
        version["replay_config_path"] = str(path)
        seed = version["seed_item"].get("seed", {})
        row = {
            "config_slug": path.relative_to(self.config_root).with_suffix("").as_posix(),
            "hook_name": version["hook_name"], "callback_id": version["callback_id"],
            "resolved_method": version["resolved_method"], "entrypoint_type": version["entrypoint_type"],
            "seed_variant_id": str(seed.get("seed_variant_id") or ""),
        }
        reason = "V0_CALLBACK_NOT_REACHED"
        readiness: dict[str, Any] = {"passed": False}
        version["readiness"] = readiness
        try:
            if not self.registry.get("callback_map", {}).get(version["callback_id"]):
                raise OnlineLinkedError("V0_REGISTRY_MISSING")
            timeout = min(30, int(deadline - self.clock()))
            if timeout < 1:
                raise OnlineLinkedError("BUDGET_EXPIRED")
            report = self.replay_runner(
                [row], timeout_seconds=timeout, service=self.service,
                legacy_run_id=version["worker_run_id"], run_command=self.run_command,
                list_artifacts=self.list_artifacts, load_artifact=self.load_artifact,
                list_zend_artifacts=self.list_zend_artifacts, poll_interval_seconds=0, fuzzer_node_id=100,
                stop_on_callback=True,
            )
            readiness["runner"] = report
            rows = report.get("runs", [])
            result_row = rows[0] if len(rows) == 1 else {}
            if result_row.get("process_status") == "vuln_found":
                self.state.update(terminal_status="VULN_FOUND", terminal_reason="VULN_FOUND")
                return False
            if result_row.get("callback_reached") is not True or result_row.get("validation_status") != "callback_reached":
                raise OnlineLinkedError(reason)
            if result_row.get("process_status") in {"failed", "runner_error"}:
                raise OnlineLinkedError("V0_REPLAY_PROCESS_FAILED")
            request_dir = self.run_dir / "versions" / "v0" / "probe" / "request"
            zend_dir = request_dir.parent / "zend"
            self._save_replay_artifacts(result_row, request_dir, zend_dir)
            reason = "V0_PROVENANCE_NOT_VERIFIED"
            observation = self.converge_fn(
                raw_report=self._reports["v0"], pass_run_summary=report,
                pass_artifacts_dir=request_dir, zend_events_dir=zend_dir, registry=self.registry,
                plugin_slug=self.plugin_slug, legacy_run_id=version["worker_run_id"],
                known_state={"known_parameters": []}, candidate_key=self._target_key,
            )
            readiness["convergence"] = observation
            if observation.get("status") == "REPLAY_FAILED" or observation.get("runtime_block_reason") or observation.get("missing_parameters"):
                reason = str(observation.get("runtime_block_reason") or "V0_PROVENANCE_NOT_VERIFIED")
                self._record_event({"kind": "V0_READINESS", "status": "REJECTED", "reason": reason,
                                    "missing_parameters": observation.get("missing_parameters", [])})
                raise OnlineLinkedError(reason)
            if version["config_type"] == "fuzzing_ready":
                expected = copy.deepcopy(self._reports["v0"])
                expected["suggested_seeds"][0]["seed"]["zend_canonical_callback"] = version["canonical_callback"]
                verification = self.verify_pass2_fn(report, expected, zend_dir, pass2_artifacts_dir=request_dir)
                readiness["pass2_verification"] = verification
                if not verification.get("total") or verification.get("accepted") != verification["total"]:
                    raise OnlineLinkedError("V0_PASS2_NOT_VERIFIED")
            else:
                readiness["probe_only"] = True
            readiness["passed"] = True
            return True
        except (OSError, RuntimeError, ValueError) as exc:
            readiness.update(reason=str(exc), passed=False)
            self.state.update(terminal_status="NOT_VERIFIED", terminal_reason=str(exc) if isinstance(exc, OnlineLinkedError) else reason)
            return False

    def read_new_runtime_evidence(self, *, deadline: float | None = None) -> list[dict[str, Any]]:
        """Read exact-ID request/Zend pairs for the active worker."""

        version = self._version(self._active_version)
        if version is None:
            return []
        request_names = self.list_artifacts()
        evidence: list[dict[str, Any]] = []
        for request_name in sorted(request_names):
            if deadline is not None and self.clock() >= deadline:
                break
            if Path(request_name).name != request_name:
                continue
            request_payload = self.load_artifact(request_name)
            if not isinstance(request_payload, Mapping):
                continue
            request_id = str(request_payload.get("request_id") or "").strip()
            if not request_id or Path(request_name).stem != request_id:
                continue
            request_run_id = str(request_payload.get("legacy_run_id") or request_payload.get("run_id") or "").strip()
            if request_run_id != str(version.get("worker_run_id") or ""):
                continue
            if str(request_payload.get("target_plugin") or "").strip() != self.plugin_slug:
                continue
            zend_names = self.list_zend_artifacts()
            matches = [
                name for name in zend_names
                if Path(name).name == name and Path(name).stem == request_id
            ]
            if len(matches) != 1:
                continue
            zend_name = matches[0]
            pair_key = (str(version["version"]), request_id)
            if pair_key in self._seen_pairs:
                continue
            zend_payload = self.load_zend_artifact(zend_name)
            if not isinstance(zend_payload, Mapping):
                continue
            if str(zend_payload.get("request_id") or "") != request_id:
                continue
            zend_run_id = str(zend_payload.get("run_id") or zend_payload.get("legacy_run_id") or "").strip()
            if zend_run_id != str(version.get("worker_run_id") or ""):
                continue
            runtime_evidence = {
                "version": str(version["version"]),
                "worker_run_id": str(version["worker_run_id"]),
                "request_name": request_name,
                "request_id": request_id,
                "request": dict(request_payload),
                "zend_name": zend_name,
                "zend": dict(zend_payload),
            }
            if deadline is not None and self.clock() >= deadline:
                break
            discovered = self._discover_runtime_candidates(runtime_evidence, deadline=deadline)
            explicit_callback = str(request_payload.get("callback_id") or "").strip()
            explicit_hook = str(request_payload.get("hook_name") or "").strip()
            if (explicit_callback and explicit_callback != str(version.get("callback_id") or "")) or (
                explicit_hook and explicit_hook != str(version.get("hook_name") or "")
            ):
                if any(
                    candidate.get("callback_id") == explicit_callback
                    or candidate.get("hook_name") == explicit_hook
                    for candidate in discovered
                ):
                    self._seen_pairs.add(pair_key)
                    continue
                self._record_event({
                    "kind": "ACTION_DISCOVERY",
                    "status": "REJECTED",
                    "reason": "ACTION_EXPANSION_NOT_IMPLEMENTED",
                    "version": version["version"],
                    "worker_run_id": version["worker_run_id"],
                    "request_id": request_id,
                    "callback_id": explicit_callback,
                    "hook_name": explicit_hook,
                })
                self._seen_pairs.add((str(version["version"]), request_id))
                continue
            self._seen_pairs.add(pair_key)
            evidence.append(runtime_evidence)
        return evidence

    def _discover_runtime_candidates(
        self, evidence: Mapping[str, Any], *, deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        """Queue only runtime-registered HTTP callbacks with correlated parent metadata."""
        parent = self._version(self._active_version)
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
            if deadline is not None and self.clock() >= deadline:
                break
            if not isinstance(raw_callback, Mapping):
                continue
            callback = dict(raw_callback)
            callback_id = str(callback.get("callback_id") or fallback_id).strip()
            hook_name = str(callback.get("hook_name") or "").strip()
            if not callback_id or not hook_name or callback_id == parent_callback_id:
                continue
            if not callback.get("registered_inside_callback"):
                continue
            parent_callback = callback.get("parent_callback") if isinstance(callback.get("parent_callback"), Mapping) else {}
            parent_ids = {
                str(callback.get("parent_callback_id") or "").strip(),
                str(parent_callback.get("callback_id") or "").strip(),
            }
            parent_hooks = {
                str(callback.get("parent_hook_name") or "").strip(),
                str(parent_callback.get("hook_name") or "").strip(),
            }
            if parent_callback_id not in parent_ids and parent_hook_name not in parent_hooks:
                continue
            callback.setdefault("callback_id", callback_id)
            callback.setdefault("request_id", request_id)
            callback.setdefault("target_plugin", self.plugin_slug)

            seed_template = seed_template_for_callback(hook_name, callback)
            if seed_template is None:
                self._record_event({
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
                    self._record_event({
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
                identity = _candidate_identity({
                    "callback_id": callback_id,
                    "hook_name": hook_name,
                    "entrypoint_type": entrypoint_type,
                    "seed": seed,
                }, self.plugin_slug)
                if identity in self.state["queued_candidate_ids"]:
                    continue
                child = {
                    "hook_name": hook_name,
                    "callback_id": callback_id,
                    "callback_repr": str(callback.get("callback_repr") or callback_id),
                    "seed": seed,
                    "identity": identity,
                    "lineage": {
                        "parent_version": parent["version"],
                        "parent_request_id": request_id,
                        "parent_callback_id": parent_callback_id,
                        "parent_hook_name": parent_hook_name,
                    },
                }
                self.state["candidate_queue"].append(child)
                self.state["queued_candidate_ids"].append(identity)
                discovered.append(child)
                self._record_event({
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
                self._merge_runtime_registry(callback)
        return discovered

    def _merge_runtime_registry(self, callback: Mapping[str, Any]) -> None:
        callback_id = str(callback.get("callback_id") or "").strip()
        canonical = str(callback.get("callback_repr") or callback_id).strip()
        if not callback_id or not canonical:
            return
        callback_map = self.registry.setdefault("callback_map", {})
        if not isinstance(callback_map, dict):
            callback_map = {}
            self.registry["callback_map"] = callback_map
        callback_map[callback_id] = canonical
        registrations = self.registry.setdefault("registrations", [])
        if not isinstance(registrations, list):
            registrations = []
            self.registry["registrations"] = registrations
        if any(str(row.get("callback_id") or "") == callback_id for row in registrations if isinstance(row, Mapping)):
            return
        registrations.append({
            "callback_id": callback_id,
            "callback": canonical,
            "canonical_callback": canonical,
            "callback_type": "static_method" if "::" in canonical else "function",
        })
        if self.registry_path is not None:
            _write_json(self.registry_path, self.registry)

    def advance_online_version(self, evidence: Mapping[str, Any], *, deadline: float | None = None) -> dict[str, Any] | None:
        """Run existing convergence/export logic and prepare one child version."""

        parent = self._version(self._active_version)
        if parent is None:
            return None
        if deadline is not None and self.clock() >= deadline:
            return None
        if 1 + len(self.state["attempts"]) >= self.max_versions:
            self._record_event({
                "kind": "PARAMETER_DISCOVERY",
                "status": "REJECTED",
                "reason": "VERSION_LIMIT_REACHED",
                "version": parent["version"],
                "request_id": evidence.get("request_id"),
            })
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
        if result.get("status") == "REPLAY_FAILED" or result.get("missing_parameters") or result.get("runtime_block_reason"):
            self._record_event({
                "kind": "RUNTIME_OBSERVATION", "status": "REJECTED",
                "reason": result.get("runtime_block_reason") or result.get("status") or "MISSING_PARAMETERS",
                "missing_parameters": result.get("missing_parameters", []),
                "version": parent["version"], "request_id": evidence.get("request_id"),
            })
            return None

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
                self._probe_admission_complete(parameter, parameter_evidence, parent)
                if helper_depth != 0
                else self._admission_complete(parameter, parameter_evidence, parent)
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
            "parameters": [dict(parameter) for parameter in new_parameters],
        }
        discovery = self._record_event(discovery)
        proposed_parameters = list(result.get("known_parameters") or [])
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
            self._recover_parent_after_failure(parent, deadline)
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
        attempt = {"version": next_version, "parent_version": parent["version"],
                   "request_id": evidence.get("request_id"), "status": "exporting"}
        self.state["attempts"].append(attempt)
        self._write_state()
        generated_dir = self.config_dir / "versions" / next_version / "exported"
        generated_summary_path = self.run_dir / "versions" / next_version / "generated_config_summary.json"
        try:
            generated_dir.mkdir(parents=True, exist_ok=True)
            generated_summary_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return self._reject_child_attempt(
                parent, attempt, discovery, "CHILD_CONFIG_PREPARE_FAILED", deadline, detail=str(exc),
            )
        if deadline is not None and self.clock() >= deadline:
            attempt.update(status="failed", reason="BUDGET_EXPIRED")
            self._record_event({**discovery, "event_id": "", "status": "REJECTED", "reason": "BUDGET_EXPIRED"})
            return None
        child_failure_reason = "CHILD_CONFIG_EXPORT_FAILED"
        try:
            generated = self.export_configs_fn(
                materialized,
                output_config_dir=generated_dir,
                summary_path=generated_summary_path,
                target_base="http://web",
                rest_route_fallback=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            attempt["error"] = str(exc)
            generated = {}
        rows = generated.get("generated") if isinstance(generated, Mapping) else None
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
            return self._reject_child_attempt(parent, attempt, discovery, child_failure_reason, deadline)
        generated_path = Path(str(rows[0].get("config_path") or ""))
        if not generated_path.is_file():
            return self._reject_child_attempt(parent, attempt, discovery, "CHILD_CONFIG_MISSING", deadline)
        try:
            child_config = json.loads(generated_path.read_text(encoding="utf-8-sig"))
            base_evidence = result.get("base_evidence") if isinstance(result.get("base_evidence"), Mapping) else evidence
            self._restore_request_values(child_config, base_evidence, parent)
            if isinstance(evidence_by_parameter, Mapping):
                for parameter in new_parameters:
                    parameter_evidence = evidence_by_parameter.get(_parameter_key(parameter))
                    if isinstance(parameter_evidence, Mapping):
                        self._restore_request_values(
                            child_config,
                            parameter_evidence,
                            parent,
                            only_parameters={_parameter_key(parameter)},
                        )
            child_path = self._write_config(next_version, child_config)
            child = self._new_version(next_version, child_config, child_path, parent, discovery["event_id"], seed)
            child["known_parameters"] = proposed_parameters
            self._reports[next_version] = copy.deepcopy(materialized)
            replay_config = copy.deepcopy(child_config)
            self.force_replay_only_fn(replay_config)
            replay_path = self._write_config(next_version, replay_config, replay=True)
            child["replay_config_path"] = str(replay_path)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return self._reject_child_attempt(
                parent, attempt, discovery, "CHILD_CONFIG_BUILD_FAILED", deadline, detail=str(exc),
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

    def _probe_context_key(
        self, parent: Mapping[str, Any], probe: Mapping[str, Any], evidence: Mapping[str, Any],
    ) -> str:
        request = evidence.get("request")
        params = request.get("request_params") if isinstance(request, Mapping) else None
        params = params if isinstance(params, Mapping) else {}
        # Ignore request IDs and metadata; preserve input types and array order.
        inputs = {bucket: params.get(bucket, {}) for bucket in ("query_params", "body_params", "json_params")}
        input_hash = hashlib.sha256(
            json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return json.dumps([
            str(parent.get("version") or ""),
            str(parent.get("worker_run_id") or ""),
            str(parent.get("callback_id") or ""),
            str(parent.get("hook_name") or ""),
            str(parent.get("entrypoint_type") or ""),
            str(probe.get("name") or ""),
            str(probe.get("source") or "").upper(),
            str(probe.get("location") or ""),
            str(probe.get("callback_id") or parent.get("callback_id") or ""),
            str(probe.get("plugin_slug") or self.plugin_slug),
            str(probe.get("canonical_callback") or parent.get("canonical_callback") or ""),
            str(probe.get("request_method") or parent.get("resolved_method") or "").upper(),
            input_hash,
        ], separators=(",", ":"))

    def _recover_parent_after_failure(self, parent: Mapping[str, Any], deadline: float | None) -> bool:
        if self._active_container:
            return True
        if deadline is not None and self.clock() >= deadline:
            return False
        parent_record = self._version(str(parent["version"]))
        if parent_record is not None and self._start_worker(parent_record, deadline=deadline):
            self._active_version = str(parent_record["version"])
            return True
        self._failure = True
        self.state["terminal_status"] = "NOT_VERIFIED"
        self.state["terminal_reason"] = "PARENT_WORKER_RESTART_FAILED"
        self._write_state()
        return False

    def _reject_child_attempt(
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
        self._record_event({
            **dict(discovery), "event_id": "", "status": "REJECTED", "reason": reason,
            **({"detail": detail} if detail else {}),
        })
        self._recover_parent_after_failure(parent, deadline)
        return None

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
        """Try pending candidates, prioritizing accepted evidence before a deadline.

        Calls without a deadline retain unlimited batching; bounded calls stop
        admitting optional probes once accepted evidence is available so the
        child handoff keeps the remaining budget.
        """
        pending = convergence.get("pending_probes")
        candidates = pending if isinstance(pending, list) else [probe]
        accepted = [
            dict(item) for item in convergence.get("new_parameters", [])
            if isinstance(item, Mapping)
        ] if isinstance(convergence.get("new_parameters"), list) else []
        parameter_evidence: dict[tuple[str, str, str], Mapping[str, Any]] = {}
        for parameter in accepted:
            parameter_evidence[_parameter_key(parameter)] = evidence
        last_result: Mapping[str, Any] | None = convergence if accepted else None
        last_evidence: Mapping[str, Any] | None = evidence if accepted else None
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            if accepted and deadline is not None:
                # Admit proven evidence before spending the deadline on optional probes.
                break
            outcome = self._run_pending_probe_once(
                parent=parent, evidence=evidence, raw_report=raw_report,
                convergence=convergence, probe=candidate, seed=seed, deadline=deadline,
            )
            if not isinstance(outcome, Mapping) or outcome.get("status") != "accepted":
                if self.state.get("terminal_status") or (
                    not self._active_container and
                    (deadline is not None and self.clock() >= deadline)
                ):
                    break
                continue
            parameter = outcome.get("parameter")
            probe_evidence = outcome.get("evidence")
            if not isinstance(parameter, Mapping) or not isinstance(probe_evidence, Mapping):
                continue
            accepted.append(dict(parameter))
            parameter_evidence[_parameter_key(parameter)] = probe_evidence
            last_result = outcome.get("result") if isinstance(outcome.get("result"), Mapping) else None
            last_evidence = probe_evidence
        if not accepted or last_result is None or last_evidence is None:
            return None
        final_result = dict(last_result)
        final_result["new_parameters"] = accepted
        existing = parent.get("known_parameters", [])
        existing = [dict(item) for item in existing if isinstance(item, Mapping)] if isinstance(existing, list) else []
        final_result["known_parameters"] = existing + accepted
        final_result["pending_probes"] = []
        final_result["parameter_evidence"] = parameter_evidence
        final_result["base_evidence"] = evidence
        final_result["candidate_key"] = str(convergence.get("candidate_key") or self._target_key)
        return self._handle_convergence_result(
            parent=parent, evidence=last_evidence, raw_report=raw_report,
            result=final_result, seed=seed, deadline=deadline,
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
        """Replay one artifact-derived AJAX probe, then re-enter admission."""
        attempts = self.state.setdefault("probe_attempts", [])
        dedupe_key = self._probe_context_key(parent, probe, evidence)
        if any(item.get("dedupe_key") == dedupe_key for item in attempts if isinstance(item, Mapping)):
            self._record_event({
                "kind": "PARAMETER_PROBE", "status": "SKIPPED", "reason": "PROBE_ALREADY_ATTEMPTED",
                "version": parent["version"], "request_id": evidence.get("request_id"),
                "candidate": dict(probe), "dedupe_key": dedupe_key,
            })
            return {"status": "skipped"}
        if len(attempts) >= self.MAX_PROBE_ATTEMPTS:
            self._record_event({
                "kind": "PARAMETER_PROBE", "status": "REJECTED", "reason": "PROBE_BUDGET_EXHAUSTED",
                "version": parent["version"], "request_id": evidence.get("request_id"),
                "candidate": dict(probe),
            })
            return None
        merged_probe_report = convergence.get("merged_suggested_seeds")
        probe_items = merged_probe_report.get("suggested_seeds", []) if isinstance(merged_probe_report, Mapping) else []
        if not isinstance(probe_items, list):
            probe_items = []
        variant = str(probe.get("seed_variant_id") or "")
        probe_item = next(
            (item for item in probe_items if isinstance(item, Mapping)
             and str((item.get("seed") or {}).get("seed_variant_id") or "") == variant),
            None,
        )
        if probe_item is None and len(probe_items) == 1 and isinstance(probe_items[0], Mapping):
            probe_item = probe_items[0]
        if probe_item is None:
            return self._finish_probe_failure(parent, evidence, None, "PROBE_CONFIG_MISSING", deadline)
        if deadline is not None and self.clock() >= deadline:
            return self._finish_probe_failure(parent, evidence, None, "PROBE_BUDGET_EXPIRED", deadline)

        probe_id = f"p{len(attempts) + 1}"
        probe_run_id = f"{parent['worker_run_id']}-probe-{probe_id}"
        probe_root = self.run_dir / "versions" / str(parent["version"]) / "probe" / probe_id
        generated_dir = self.config_dir / "versions" / str(parent["version"]) / "probe" / probe_id / "exported"
        generated_summary_path = probe_root / "generated_config_summary.json"
        attempt: dict[str, Any] = {
            "probe_id": probe_id, "parent_version": parent["version"],
            "request_id": evidence.get("request_id"), "status": "exporting",
            "candidate": dict(probe), "probe_run_id": probe_run_id, "dedupe_key": dedupe_key,
            "_started_at": self.clock(),
        }
        attempts.append(attempt)
        self._write_state()
        try:
            generated_dir.mkdir(parents=True, exist_ok=True)
            generated_summary_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_PREPARE_FAILED", deadline, detail=str(exc))
        try:
            generated = self.export_configs_fn(
                {"suggested_seeds": [dict(probe_item)]},
                output_config_dir=generated_dir,
                summary_path=generated_summary_path,
                target_base="http://web",
                replay_only=True,
                rest_route_fallback=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_EXPORT_FAILED", deadline, detail=str(exc))
        rows = generated.get("generated") if isinstance(generated, Mapping) else None
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_EXPORT_FAILED", deadline)
        generated_path = Path(str(rows[0].get("config_path") or ""))
        if not generated_path.is_file():
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_MISSING", deadline)
        try:
            probe_config = json.loads(generated_path.read_text(encoding="utf-8-sig"))
            self._restore_request_values(probe_config, evidence, parent)
            probe_metadata = probe_config.setdefault("metadata", {})
            if not isinstance(probe_metadata, dict):
                raise OnlineLinkedError("PROBE_CONFIG_METADATA_INVALID")
            probe_metadata["zend_runtime_probe"] = {
                "parameter": str(probe.get("name") or ""),
                "source": str(probe.get("source") or "").upper(),
                "location": str(probe.get("location") or ""),
                "helper_depth": probe.get("helper_depth"),
                "value_origin": "generated_probe",
                "candidate_value_redacted": True,
                "candidate_request_id": probe.get("request_id"),
                "candidate_run_id": probe.get("run_id"),
            }
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_INVALID", deadline, detail=str(exc))
        probe_config_path = self.config_dir / "versions" / str(parent["version"]) / "probe" / probe_id / f"{probe_id}-config.json"
        probe_mirror_path = probe_root / f"{probe_id}-config.json"
        replay_path = self.config_dir / "versions" / str(parent["version"]) / "probe" / probe_id / f"{probe_id}-replay.json"
        replay_mirror_path = probe_root / f"{probe_id}-replay.json"
        try:
            _write_exclusive_json(probe_config_path, probe_config)
            _write_exclusive_json(probe_mirror_path, probe_config)
            replay_config = copy.deepcopy(probe_config)
            self.force_replay_only_fn(replay_config)
            _write_exclusive_json(replay_path, replay_config)
            _write_exclusive_json(replay_mirror_path, replay_config)
        except (OSError, RuntimeError, ValueError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONFIG_WRITE_FAILED", deadline, detail=str(exc))
        attempt.update(config_path=str(probe_config_path), replay_config_path=str(replay_path), status="replaying")
        self._record_event({
            "kind": "PARAMETER_PROBE", "status": "PENDING", "reason": "ZEND_RUNTIME_CANDIDATE",
            "version": parent["version"], "worker_run_id": parent["worker_run_id"],
            "request_id": evidence.get("request_id"), "probe_id": probe_id,
            "probe_run_id": probe_run_id, "candidate": dict(probe),
        })
        probe_seed = probe_item.get("seed") if isinstance(probe_item.get("seed"), Mapping) else {}
        probe_row = {
            "config_slug": replay_path.relative_to(self.config_root).with_suffix("").as_posix(),
            "hook_name": str(probe_item.get("hook_name") or parent["hook_name"]),
            "callback_id": str(probe_item.get("callback_id") or parent["callback_id"]),
            "entrypoint_type": str(probe_item.get("entrypoint_type") or parent["entrypoint_type"]),
            "resolved_method": str(probe_seed.get("resolved_method") or probe_seed.get("method") or parent["resolved_method"]),
            "seed_variant_id": str(probe_seed.get("seed_variant_id") or ""),
        }
        timeout = deadline - self.clock() if deadline is not None else self.max_seconds
        if timeout <= 0:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_BUDGET_EXPIRED", deadline)
        try:
            sender_result = self._run_light_sender(
                config_path=replay_path,
                request_id=f"{probe_run_id}-request",
                run_id=probe_run_id,
                hook_name=probe_row["hook_name"],
                callback_id=probe_row["callback_id"],
                method=probe_row["resolved_method"],
                auth_context=str(probe_config.get("metadata", {}).get("auth_context") or "authenticated"),
                seed_variant_id=probe_row["seed_variant_id"],
                deadline=deadline,
            )
        except Exception as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_REPLAY_FAILED", deadline, detail=str(exc))
        if sender_result.get("status") == "parent_stopped":
            exit_code = sender_result.get("parent_exit_code")
            if isinstance(exit_code, int):
                self._handle_worker_exit(exit_code)
            return self._finish_probe_failure(
                parent, evidence, attempt, "PARENT_WORKER_EXITED_DURING_PROBE", deadline,
                detail=str(sender_result.get("error") or "parent worker exited"),
            )
        if sender_result.get("status") == "parent_container_missing":
            self._failure = True
            self._active_container = ""
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "PARENT_CONTAINER_MISSING"
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
        parent_timeout = None if deadline is None else deadline - self.clock()
        if parent_timeout is not None and parent_timeout <= 0:
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_BUDGET_EXPIRED", deadline,
            )
        try:
            parent_exit_code = self._observe_parent_exit(timeout=parent_timeout)
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
        attempt["_verify_started_at"] = self.clock()
        replay_row = self._sender_runner_row(probe_row, sender_result, probe_run_id)
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
            self._save_replay_artifacts(replay_row, request_dir, zend_dir)
            artifact_name = str(replay_row.get("matched_artifact") or "")
            request_path = request_dir / artifact_name
            zend_paths = [path for path in zend_dir.glob("*.json") if path.stem == request_path.stem]
            if Path(artifact_name).name != artifact_name or not request_path.is_file() or len(zend_paths) != 1:
                raise OnlineLinkedError("PROBE_ARTIFACT_CORRELATION_FAILED")
            probe_request = json.loads(request_path.read_text(encoding="utf-8-sig"))
            probe_zend = json.loads(zend_paths[0].read_text(encoding="utf-8-sig"))
            if (
                not isinstance(probe_request, Mapping)
                or not isinstance(probe_zend, Mapping)
                or str(probe_request.get("request_id") or "") != request_path.stem
                or str(probe_zend.get("request_id") or "") != request_path.stem
                or str(probe_request.get("legacy_run_id") or probe_request.get("run_id") or "") != probe_run_id
                or str(probe_zend.get("run_id") or probe_zend.get("legacy_run_id") or "") != probe_run_id
            ):
                raise OnlineLinkedError("PROBE_ARTIFACT_CORRELATION_FAILED")
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_ARTIFACT_CORRELATION_FAILED", deadline, detail=str(exc))

        probe_evidence = {
            "version": parent["version"], "worker_run_id": probe_run_id,
            "request_name": artifact_name, "request_id": request_path.stem,
            "request": dict(probe_request), "zend_name": zend_paths[0].name, "zend": dict(probe_zend),
        }
        try:
            probe_result = self.converge_fn(
                raw_report={"suggested_seeds": [dict(probe_item)]},
                pass_run_summary={"legacy_run_id": probe_run_id, "runs": [{
                    **probe_row, "callback_reached": True, "matched_artifact": artifact_name,
                    "process_status": "replaying",
                }]},
                pass_artifacts_dir=request_dir, zend_events_dir=zend_dir, registry=self.registry,
                plugin_slug=self.plugin_slug, legacy_run_id=probe_run_id,
                known_state={"known_parameters": parent.get("known_parameters", [])}, candidate_key=None,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_CONVERGENCE_FAILED", deadline, detail=str(exc))
        probe_parameters = probe_result.get("new_parameters") if isinstance(probe_result, Mapping) else None
        if not isinstance(probe_parameters, list) or not probe_parameters:
            return self._finish_probe_failure(parent, evidence, attempt, "PROBE_NO_CORRELATED_READ", deadline)
        target_key = _parameter_key(probe)
        matching = [
            parameter for parameter in probe_parameters
            if isinstance(parameter, Mapping)
            and _parameter_key(parameter) == target_key
            and parameter.get("fuzzable") is True
        ]
        unexpected = [
            dict(parameter) for parameter in probe_parameters
            if isinstance(parameter, Mapping) and _parameter_key(parameter) != target_key
        ]
        if not matching:
            if unexpected:
                attempt["unexpected_parameters"] = unexpected
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_TARGET_MISMATCH", deadline,
                extra={"unexpected_parameters": unexpected},
            )
        parameter = matching[0]
        if not self._probe_admission_complete(parameter, probe_evidence, parent):
            return self._finish_probe_failure(
                parent, evidence, attempt, "PROBE_PROVENANCE_INCOMPLETE", deadline,
                extra={"unexpected_parameters": unexpected},
            )
        if unexpected:
            attempt["unexpected_parameters"] = unexpected
        attempt.update(status="accepted", probe_request_id=probe_evidence["request_id"])
        timing = dict(attempt.get("timing") or {})
        timing["verify"] = round(self.clock() - float(attempt.pop("_verify_started_at", self.clock())), 3)
        timing["total"] = round(self.clock() - float(attempt.pop("_started_at", self.clock())), 3)
        attempt["timing"] = timing
        self._record_event({
            "kind": "PARAMETER_PROBE", "status": "ACCEPTED", "reason": "CORRELATED_ZEND_READ",
            "version": parent["version"], "worker_run_id": probe_run_id,
            "request_id": probe_evidence["request_id"], "probe_id": probe_id,
            "hook_name": probe_row["hook_name"], "candidate": dict(probe), "parameter": dict(parameter),
            "timing": timing,
            **({"unexpected_parameters": unexpected} if unexpected else {}),
        })
        return {
            "status": "accepted",
            "parameter": dict(parameter),
            "evidence": probe_evidence,
            "result": probe_result,
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
                timing["verify"] = round(self.clock() - float(verify_started_at), 3)
            if started_at is not None:
                timing["total"] = round(self.clock() - float(started_at), 3)
            attempt["timing"] = timing
        self._record_event({
            "kind": "PARAMETER_PROBE", "status": "REJECTED", "reason": reason,
            "version": parent["version"], "request_id": evidence.get("request_id"),
            "hook_name": parent.get("hook_name"),
            "probe_id": attempt.get("probe_id") if attempt else None,
            "probe_run_id": attempt.get("probe_run_id") if attempt else None,
            "parameter": (attempt.get("candidate") or {}).get("name") if attempt else None,
            "timing": timing,
            **(dict(extra) if isinstance(extra, Mapping) else {}),
            **({"detail": detail} if detail else {}),
        })
        self._write_state()
        return None

    def _restore_request_values(
        self, config: dict[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
        *, only_parameters: set[tuple[str, str, str]] | None = None,
    ) -> None:
        """Seed child inputs from this correlated request, retaining fuzz selectors."""
        request = evidence.get("request") or {}
        if not isinstance(request, Mapping):
            raise OnlineLinkedError("UNSUPPORTED_REQUEST: expected an object")
        params = request.get("request_params")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            raise OnlineLinkedError("UNSUPPORTED_REQUEST_PARAMS: expected an object")
        parent_config = json.loads(Path(str(parent["config_path"])).read_text(encoding="utf-8-sig"))
        headers = config.get("headers", {}).get("data", [])
        is_json = any(
            str(row.get("name", "")).lower() == "content-type"
            and "json" in str(row.get("value", "")).lower() for row in headers
        )
        values = []
        section_identity = {
            "query_params": ("GET", "query"),
            "body_params": ("POST", "form"),
            "headers": ("HEADER", "header"),
            "cookies": ("COOKIE", "cookie"),
        }
        for section_name in ("query_params", "body_params", "headers", "cookies"):
            section = config.get(section_name)
            if not isinstance(section, dict):
                continue
            bucket = "json_params" if section_name == "body_params" and is_json else section_name
            observed, source_status, source_reason = self._request_bucket_values(params, bucket)
            parent_section = parent_config.get(section_name, {})
            if not isinstance(parent_section, Mapping):
                parent_section = {}
            fixed = parent_section.get("fixed", [])
            if not isinstance(fixed, list):
                raise OnlineLinkedError(f"UNSUPPORTED_CONFIG_BUCKET: {section_name}.fixed must be a list")
            for row in section.get("data", []):
                name = str(row["name"])
                transport, location = section_identity[section_name]
                if only_parameters is not None and (name, transport, location) not in only_parameters:
                    continue
                value = observed
                path = [name] if name in observed else [part for part in re.split(r"\[|\]", name) if part]
                found = True
                for part in path:
                    if isinstance(value, Mapping) and part in value:
                        value = value[part]
                    elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                        value = value[int(part)]
                    else:
                        found = False
                        break
                if found:
                    row["value"] = copy.deepcopy(value)
                    row.pop("seeds", None)
                if any(re.match(selector, name) for selector in fixed):
                    selector = re.escape(name)
                    if selector not in section.setdefault("fixed", []):
                        section["fixed"].append(selector)
                    section["fuzz"] = [item for item in section.get("fuzz", []) if item != selector]
                value_record = {
                    "name": name,
                    "bucket": bucket,
                    "request_id": evidence.get("request_id"),
                    "run_id": evidence.get("worker_run_id") or evidence.get("run_id") or parent["worker_run_id"],
                    "value_origin": "observed" if found else ("probe" if source_status == "observed" else source_status),
                }
                if not found:
                    value_record["reason"] = source_reason or "REQUEST_VALUE_MISSING"
                values.append(value_record)
        metadata = config.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            raise OnlineLinkedError("PROBE_CONFIG_METADATA_INVALID")
        previous = metadata.get("online_request_seed")
        previous_values = previous.get("values", []) if isinstance(previous, Mapping) else []
        records: dict[tuple[str, str], dict[str, Any]] = {}
        for value in previous_values if isinstance(previous_values, list) else []:
            if isinstance(value, Mapping):
                records[(str(value.get("bucket") or ""), str(value.get("name") or ""))] = dict(value)
        for value in values:
            records[(str(value.get("bucket") or ""), str(value.get("name") or ""))] = value
        request_ids = []
        if isinstance(previous, Mapping):
            request_ids.extend(str(item) for item in previous.get("evidence_request_ids", []) if str(item))
            if previous.get("request_id") and previous.get("request_id") != "multiple":
                request_ids.append(str(previous["request_id"]))
        request_id = str(evidence.get("request_id") or "")
        if request_id:
            request_ids.append(request_id)
        request_ids = list(dict.fromkeys(request_ids))
        metadata["online_request_seed"] = {
            "request_id": request_ids[0] if len(request_ids) == 1 else "multiple",
            "run_id": parent["worker_run_id"],
            "evidence_request_ids": request_ids,
            "values": list(records.values()),
        }

    @staticmethod
    def _request_bucket_values(
        params: Mapping[str, Any], bucket: str,
    ) -> tuple[Mapping[str, Any], str, str]:
        """Decode producer buckets without treating names or falsey values as data loss."""
        if bucket == "json_params":
            if "json_params" not in params:
                status = str(params.get("json_params_status") or "").strip().lower()
                if status in {"invalid", "error"}:
                    return {}, status, str(params.get("json_params_error") or f"JSON_PARAMS_{status.upper()}")
                return {}, "missing", "JSON_PARAMS_MISSING"
            status = str(params.get("json_params_status") or "decoded").strip().lower()
            if status in {"missing", "invalid", "error", "not_json"}:
                return {}, status, str(params.get("json_params_error") or f"JSON_PARAMS_{status.upper()}")
            observed = params.get("json_params")
            if isinstance(observed, Mapping):
                return observed, "empty" if not observed else "observed", ""
            json_type = str(params.get("json_params_type") or "").strip().lower()
            if not json_type:
                if isinstance(observed, list):
                    json_type = "array"
                elif observed is None:
                    json_type = "null"
                elif isinstance(observed, bool):
                    json_type = "boolean"
                elif isinstance(observed, (int, float)):
                    json_type = "number"
                elif isinstance(observed, str):
                    json_type = "string"
                else:
                    json_type = type(observed).__name__
            raise OnlineLinkedError(
                f"UNSUPPORTED_REQUEST_BUCKET: json_params must be an object (got {json_type})"
            )

        if bucket not in params:
            return {}, "missing", "REQUEST_BUCKET_MISSING"
        observed = params[bucket]
        if bucket in {"query_params", "body_params"} and observed == []:
            return {}, "empty", ""
        if bucket == "cookies" and isinstance(observed, list):
            if not all(isinstance(name, str) for name in observed):
                raise OnlineLinkedError("UNSUPPORTED_REQUEST_BUCKET: cookies must be a list of names")
            return {}, "names_only", "COOKIE_VALUES_NOT_EXPORTED"
        if not isinstance(observed, Mapping):
            raise OnlineLinkedError(f"UNSUPPORTED_REQUEST_BUCKET: {bucket} must be an object")
        return observed, "observed", ""

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
            sender_result = self._run_light_sender(
                config_path=replay_path,
                request_id=f"{replay_run_id}-request",
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
        if deadline_expired:
            sender_result = dict(sender_result)
            sender_result.update(
                status="timeout",
                callback_reached=False,
                validation_status="registered_not_executed",
                validation_reason="SENDER_TIMEOUT",
                error="SENDER_TIMEOUT",
            )
        else:
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
        try:
            self._save_replay_artifacts(replay_row, request_dir, zend_dir)
        except (OSError, RuntimeError, ValueError) as exc:
            artifact_error = str(exc)
        try:
            verification = self.verify_pass2_fn(
                replay_report,
                merged_report,
                zend_dir,
                pass2_artifacts_dir=request_dir,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            verification = {"accepted": 0, "total": 0, "error": str(exc)}
        replay_passed = bool(
            isinstance(replay_row, Mapping)
            and not artifact_error
            and replay_row.get("validation_status") == "callback_reached"
            and replay_row.get("process_status") not in {"failed", "runner_error", "window_elapsed"}
            and verification.get("accepted") == verification.get("total")
            and verification.get("total", 0) > 0
        )
        replay_result = {
            "passed": replay_passed,
            "config_path": str(replay_path),
            "config_hash": self.config_hash(replay_path),
            "runner": replay_report,
            "pass2_verification": verification,
        }
        replay_result["timing"] = dict(sender_result.get("timing") or {})
        replay_result["timing"]["verify"] = round(self.clock() - verify_started_at, 3)
        replay_result["timing"]["total"] = round(self.clock() - replay_started_at, 3)
        replay_result["timing"].setdefault("handoff", 0.0)
        if artifact_error:
            replay_result["artifact_error"] = artifact_error
        child["replay_result"] = replay_result
        self.state.setdefault("replay_results", []).append(replay_result)

        def record_replay_event(status: str, reason: str) -> None:
            self._record_event({
                "kind": "CHILD_REPLAY", "status": status, "reason": reason,
                "hook_name": child.get("hook_name"), "version": version_name,
                "probe_id": None, "parameter": None, "timing": dict(replay_result["timing"]),
            })

        if replay_passed:
            child["status"] = "replay_pass"
            child["terminal_reason"] = ""
            self._write_state()
            if self._observe_parent_exit() is not None:
                child["worker_status"] = "not_started_parent_exited"
                child["terminal_reason"] = str(self.state.get("terminal_reason") or "PARENT_WORKER_EXITED")
                record_replay_event("PASS", "PARENT_WORKER_EXITED")
                self._write_state()
                return False
            handoff_started_at = self.clock()
            if not self._stop_worker(parent, "HANDOFF_TO_" + str(child["version"])):
                child["worker_status"] = "not_started_parent_stop_failed"
                child["terminal_reason"] = "WORKER_STOP_FAILED"
                replay_result["timing"]["handoff"] = round(self.clock() - handoff_started_at, 3)
                record_replay_event("PASS", "WORKER_STOP_FAILED")
                self._write_state()
                return False
            if self._start_worker(child, deadline=deadline):
                self._active_version = str(child["version"])
                replay_result["timing"]["handoff"] = round(self.clock() - handoff_started_at, 3)
                record_replay_event("PASS", "PASS2_VERIFIED")
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
            if artifact_error:
                child["terminal_reason"] = "REPLAY_ARTIFACT_SAVE_FAILED"
            elif replay_report.get("error") or replay_row.get("process_status") in {"failed", "runner_error"}:
                child["terminal_reason"] = "REPLAY_PROCESS_FAILED"
            elif replay_row.get("validation_status") != "callback_reached":
                child["terminal_reason"] = str(replay_row.get("validation_reason") or "CALLBACK_NOT_REACHED")
            else:
                child["terminal_reason"] = "PASS2_VERIFICATION_FAILED"
            self._failure = True
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "CHILD_REPLAY_FAILED"
            record_replay_event(
                "REJECTED",
                str(
                    replay_result.get("artifact_error")
                    or replay_row.get("validation_reason")
                    or "PASS2_VERIFICATION_FAILED"
                ),
            )
            self._write_state()
        return False

    def _select_v0(self) -> tuple[Mapping[str, Any], dict[str, Any], str] | None:
        payload = json.loads(self.suggested_seeds.read_text(encoding="utf-8-sig"))
        if not isinstance(payload, Mapping) or not isinstance(payload.get("suggested_seeds"), list):
            raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
        self._raw_report = copy.deepcopy(dict(payload))
        selected: tuple[Mapping[str, Any], dict[str, Any]] | None = None
        for item in payload["suggested_seeds"]:
            if not isinstance(item, Mapping):
                continue
            try:
                _, config = self.build_config_fn(item, target_base="http://web", rest_route_fallback=True)
            except SeedConfigSkip:
                try:
                    _, config = self.build_config_fn(
                        item,
                        target_base="http://web",
                        replay_only=True,
                        rest_route_fallback=True,
                    )
                except SeedConfigSkip:
                    continue
            valid, _ = validate_v0_config(config, require_fuzzing_ready=False)
            if valid:
                selected = (item, config)
                break
        if selected is None:
            if self.bootstrap_config is None or not self.bootstrap_config.is_file():
                return None
            legacy_selector = OnlineCoordinator(
                suggested_seeds=self.suggested_seeds,
                bootstrap_config=self.bootstrap_config,
                config_root=self.config_root,
                output_root=self.output_root,
                plugin_slug=self.plugin_slug,
                legacy_run_id=f"{self.legacy_run_id}-v0",
                max_seconds=self.max_seconds,
                max_versions=self.max_versions,
            )
            selected = legacy_selector._select_v0()
            if selected is None:
                return None
        self._targets = self.list_targets_fn(
            self._raw_report,
            plugin_slug=self.plugin_slug,
            legacy_run_id=f"{self.legacy_run_id}-v0",
        )
        item = selected[0]
        matches = [
            target for target in self._targets
            if str(target.get("hook_name") or "") == str(item.get("hook_name") or "")
            and str(target.get("callback_id") or "") == str(item.get("callback_id") or "")
            and str(target.get("method") or "").upper() == str(selected[1].get("metadata", {}).get("resolved_method") or "").upper()
        ]
        if len(matches) != 1:
            return None
        return selected[0], selected[1], str(matches[0].get("candidate_key") or "")

    def _new_version(
        self,
        name: str,
        config: Mapping[str, Any],
        config_path: Path,
        parent: Mapping[str, Any] | None,
        discovery_event: str | None,
        seed_item: Mapping[str, Any],
    ) -> dict[str, Any]:
        metadata = config.get("metadata") if isinstance(config.get("metadata"), Mapping) else {}
        record = {
            "version": name,
            "parent_version": parent.get("version") if isinstance(parent, Mapping) else None,
            "parent_config": parent.get("config_path") if isinstance(parent, Mapping) else None,
            "config_path": str(config_path),
            "config_type": str(config.get("config_type") or "").strip().lower(),
            "config_hash": config_hash(config),
            "discovery_event": discovery_event,
            "replay_result": None,
            "replay_config_path": None,
            "worker_status": "pending",
            "status": "pending",
            "terminal_reason": "",
            "hook_name": str(metadata.get("hook_name") or seed_item.get("hook_name") or ""),
            "callback_id": str(metadata.get("callback_id") or seed_item.get("callback_id") or ""),
            "canonical_callback": str(metadata.get("callback_repr") or seed_item.get("callback_repr") or ""),
            "entrypoint_type": str(config.get("entrypoint_type") or ""),
            "resolved_method": str(metadata.get("resolved_method") or ""),
            "auth_context": str(metadata.get("auth_context") or "authenticated"),
            "seed_variant_id": str(metadata.get("seed_variant_id") or (seed_item.get("seed") or {}).get("seed_variant_id") or ""),
            "seed_item": copy.deepcopy(dict(seed_item)),
        }
        self.state["versions"].append(record)
        self._write_state()
        return record

    def _start_worker(self, version: dict[str, Any], *, deadline: float | None = None) -> bool:
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
        command = [
            "docker", "compose", "run", "-d", "--no-deps", "--name", container_name,
            "-e", f"FUZZER_CONFIG={runtime_slug}",
            "-e", f"FUZZER_NODE_ID={1 + int(version_name[1:])}",
            "-e", f"HOOKPHUZZ_LEGACY_RUN_ID={worker_run_id}",
            "-e", "HOOKPHUZZ_CMPLOG=1",
            self.service,
        ]
        try:
            result = self.run_command(command, timeout=30, check=False, capture_output=True, text=True)
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
        self._active_container = container_name
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
        """Return a stopped worker exit code while ignoring a running/unknown worker."""

        if not self._active_container:
            return None
        inspect_timeout = 30 if timeout is None else max(0, timeout)
        if inspect_timeout <= 0:
            return None
        try:
            result = self.run_command(
                ["docker", "inspect", "-f", "{{if .State.Running}}running{{else}}{{.State.ExitCode}}{{end}}", self._active_container],
                timeout=inspect_timeout,
                check=False,
                capture_output=True,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            if timeout is not None:
                raise ParentInspectionTimeout("PARENT_INSPECT_TIMEOUT") from exc
            return None
        except Exception as exc:
            if timeout is not None:
                raise ParentInspectionError("PARENT_INSPECT_FAILED") from exc
            return None
        if int(getattr(result, "returncode", 1)) != 0:
            return None
        state = str(getattr(result, "stdout", "") or "").strip().lower()
        if state == "running":
            return None
        try:
            return int(state)
        except (TypeError, ValueError):
            return None

    def _stop_active_worker(self, reason: str) -> None:
        version = self._version(self._active_version)
        if version is not None:
            self._stop_worker(version, reason)

    def _stop_worker(self, version: Mapping[str, Any], reason: str) -> bool:
        container_name = self._active_container
        if not container_name:
            return True
        stop_deadline = self.clock() + 30
        try:
            result = self.run_command(
                ["docker", "rm", "-f", container_name],
                timeout=30,
                check=False,
                capture_output=True,
                text=True,
            )
            stopped = int(getattr(result, "returncode", 1)) == 0
            error = str(getattr(result, "stderr", "") or "WORKER_STOP_FAILED").strip() if not stopped else ""
            if not stopped and "removal of container" in error and "is already in progress" in error:
                # Do not reuse the name until Docker confirms removal has finished.
                while True:
                    remaining = stop_deadline - self.clock()
                    if remaining <= 0:
                        break
                    inspection = self.run_command(
                        ["docker", "container", "inspect", "--format", "{{.State.Status}}", container_name],
                        timeout=remaining, check=False, capture_output=True, text=True,
                    )
                    if int(getattr(inspection, "returncode", 1)) != 0:
                        detail = str(getattr(inspection, "stderr", "") or "").strip()
                        stopped = detail in {
                            f"Error: No such container: {container_name}",
                            f"Error response from daemon: No such container: {container_name}",
                        }
                        if not stopped:
                            error = detail or error
                        break
                    self.sleeper(min(0.5, max(0, stop_deadline - self.clock())))
        except Exception as exc:
            stopped = False
            error = str(exc)
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

    def _save_replay_artifacts(self, row: Mapping[str, Any], request_dir: Path, zend_dir: Path) -> None:
        names = set()
        matched = str(row.get("matched_artifact") or "")
        if matched:
            names.add(matched)
        names.update(str(name) for name in row.get("request_artifacts", []) if str(name))
        for name in names:
            if Path(name).name != name:
                continue
            payload = row.get("request_payload") if name == matched else None
            if payload is None:
                payload = self.load_artifact(name)
            self._copy_json(request_dir / name, payload)
            zend_name = str(row.get("zend_artifact") or "") if name == matched else ""
            if zend_name and Path(zend_name).name == zend_name:
                self._copy_json(zend_dir / zend_name, row.get("zend_payload"))
            else:
                zend_names = self.list_zend_artifacts()
                exact = [candidate for candidate in zend_names if Path(candidate).name == candidate and Path(candidate).stem == Path(name).stem]
                if len(exact) == 1:
                    self._copy_json(zend_dir / exact[0], self.load_zend_artifact(exact[0]))

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

    def _record_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(event)
        if not item.get("event_id"):
            encoded = json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))
            item["event_id"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
        if any(existing.get("event_id") == item["event_id"] for existing in self.state["events"]):
            return item
        self.state["events"].append(item)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        self._write_state()
        return item

    def _write_state(self) -> None:
        _write_json(self.state_path, self.state)

    def _version(self, name: str) -> dict[str, Any] | None:
        return next((item for item in self.state["versions"] if item.get("version") == name), None)

    def config_hash(self, path: Path) -> str:
        return config_hash(json.loads(Path(path).read_text(encoding="utf-8")))

    def _admission_complete(self, parameter: Any, evidence: Mapping[str, Any], parent: Mapping[str, Any]) -> bool:
        if not isinstance(parameter, Mapping):
            return False
        required = (
            parameter.get("name"),
            parameter.get("source"),
            parameter.get("location"),
            parameter.get("evidence_kind"),
            parameter.get("request_id"),
            parameter.get("run_id"),
            parameter.get("plugin_slug"),
            parameter.get("canonical_callback"),
            parameter.get("request_method"),
        )
        evidence_run_id = str(
            evidence.get("worker_run_id")
            or evidence.get("run_id")
            or parent.get("worker_run_id")
            or ""
        )
        return (
            all(str(value or "").strip() for value in required)
            and str(parameter.get("request_id")) == str(evidence.get("request_id"))
            and str(parameter.get("run_id")) == evidence_run_id
            and str(parameter.get("plugin_slug")) == self.plugin_slug
            and str(parameter.get("request_method")).upper() == str(parent.get("resolved_method") or "").upper()
            and _canonical_callback_name(parameter.get("canonical_callback"))
            == _canonical_callback_name(parent.get("canonical_callback"))
        )

    def _probe_admission_complete(
        self, parameter: Mapping[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
    ) -> bool:
        if not self._admission_complete(parameter, evidence, parent):
            return False
        request = evidence.get("request")
        zend = evidence.get("zend")
        source = str(parameter.get("source") or "").upper()
        location = str(parameter.get("location") or "")
        request_method = str(parent.get("resolved_method") or "").upper()
        artifact_method = str(
            (request.get("http_method") if isinstance(request, Mapping) else "")
            or (request.get("method") if isinstance(request, Mapping) else "")
            or (zend.get("request_method") if isinstance(zend, Mapping) else "")
            or (zend.get("method") if isinstance(zend, Mapping) else "")
            or request_method
        ).upper()
        return (
            isinstance(request, Mapping)
            and isinstance(zend, Mapping)
            and request.get("target_plugin") == self.plugin_slug
            and (source, location) in {("GET", "query"), ("POST", "form")}
            and artifact_method == request_method
            and runtime_parameter_is_accepted(
                parameter,
                request,
                zend,
                canonical_callback=_canonical_callback_name(parent.get("canonical_callback")),
                request_method=str(parent.get("resolved_method") or ""),
            )
        )


def _canonical_callback_name(value: Any) -> str:
    return re.sub(r"\s*(?:->|::)\s*", "::", str(value or "").strip())


def _candidate_slug(item: Mapping[str, Any], index: int) -> str:
    raw = str(item.get("hook_name") or item.get("callback_id") or "candidate")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-.") or "candidate"
    return f"{index:03d}-{slug}"


def _normalize_identity_route(value: Any) -> str:
    route = str(value or "").strip().replace("\\", "/")
    if not route:
        return ""
    route = "/" + route.lstrip("/")
    return route if route == "/" else route.rstrip("/")


def _candidate_identity(item: Mapping[str, Any], plugin_slug: str) -> str:
    """Build the sole online-linked identity from normalized candidate fields."""
    seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
    route = next((
        _normalize_identity_route(value)
        for value in (
            item.get("route"),
            item.get("rest_route"),
            seed.get("route"),
            seed.get("rest_route"),
            seed.get("materialized_route"),
            seed.get("path"),
        )
        if _normalize_identity_route(value)
    ), "")
    hook_name = str(item.get("hook_name") or "")
    entrypoint_type = str(seed.get("entrypoint_type") or item.get("entrypoint_type") or "")
    if not entrypoint_type:
        if hook_name.startswith("wp_ajax_nopriv_"):
            entrypoint_type = "ajax_unauthenticated"
        elif hook_name.startswith("wp_ajax_"):
            entrypoint_type = "ajax_authenticated"
        elif hook_name.startswith("admin_post_nopriv_"):
            entrypoint_type = "admin_post_unauthenticated"
        elif hook_name.startswith("admin_post_"):
            entrypoint_type = "admin_post_authenticated"
        elif hook_name.startswith("rest_route:"):
            entrypoint_type = "rest_route"
        elif hook_name in {"heartbeat_received", "heartbeat_nopriv_received"}:
            entrypoint_type = "heartbeat"
    method = str(
        seed.get("resolved_method")
        or seed.get("method")
        or item.get("resolved_method")
        or item.get("method")
        or ""
    ).upper()
    variant = str(seed.get("seed_variant_id") or item.get("seed_variant_id") or "")
    if not variant and method:
        variant = method.lower()
    return "|".join((
        plugin_slug,
        str(item.get("callback_id") or ""),
        entrypoint_type,
        hook_name,
        route,
        method,
        variant,
    ))


def _batch_candidate_identity(item: Mapping[str, Any], plugin_slug: str) -> str:
    return _candidate_identity(item, plugin_slug)


def _sync_callback_registry_to_web(registry_path: Path) -> None:
    """Reload callback targets in the running web container before child replay."""
    result = subprocess.run(
        ["docker", "compose", "ps", "-q", "web"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    container_id = str(result.stdout or "").strip()
    if result.returncode != 0 or not container_id:
        raise RuntimeError("CALLBACK_REGISTRY_REFRESH_FAILED: web container is unavailable")
    result = subprocess.run(
        ["docker", "cp", str(registry_path), f"{container_id}:/shared/hookphuzz-callback-registry.json"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = str(result.stderr or "").strip()
        raise RuntimeError(f"CALLBACK_REGISTRY_REFRESH_FAILED: {detail or 'docker cp failed'}")


def run_online_linked(args: argparse.Namespace) -> int:
    suggested_path = Path(args.suggested_seeds)
    payload = json.loads(suggested_path.read_text(encoding="utf-8-sig"))
    items = payload.get("suggested_seeds") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")

    batch_dir = Path(args.output_root) / "online-linked" / args.legacy_run_id
    candidate_input_dir = batch_dir / "candidates"
    candidate_input_dir.mkdir(parents=True, exist_ok=True)
    max_candidates = int(getattr(args, "max_candidates", max(1, len(items) + 16)))
    campaign_seconds = int(getattr(args, "campaign_seconds", max(60, args.max_seconds * max_candidates)))
    if max_candidates < 1 or campaign_seconds < 1:
        raise ValueError("online-linked candidate and campaign budgets must be positive")
    registry_source = Path(args.callback_registry)
    batch_registry = batch_dir / "callback-registry.json"
    batch_registry.write_text(registry_source.read_text(encoding="utf-8-sig"), encoding="utf-8")
    batch_state: dict[str, Any] = {
        "schema_version": 1,
        "mode": "online-linked-batch",
        "plugin_slug": args.plugin_slug,
        "legacy_run_id": args.legacy_run_id,
        "max_seconds_per_candidate": args.max_seconds,
        "max_versions_per_candidate": args.max_versions,
        "max_candidates": max_candidates,
        "campaign_seconds": campaign_seconds,
        "campaign_status": "running",
        "candidates": [],
        "expansion_events": [],
    }
    failed = False
    queue: list[tuple[int, Mapping[str, Any], str]] = []
    queued_ids: set[str] = set()
    for index, raw_item in enumerate(items, start=1):
        if not isinstance(raw_item, Mapping):
            continue
        identity = _batch_candidate_identity(raw_item, args.plugin_slug)
        if identity in queued_ids:
            continue
        queued_ids.add(identity)
        queue.append((index, dict(raw_item), "initial"))
    campaign_deadline = time.monotonic() + campaign_seconds
    next_index = len(queue) + 1
    while queue:
        if len(batch_state["candidates"]) >= max_candidates:
            batch_state["campaign_status"] = "CANDIDATE_BUDGET_EXPIRED"
            batch_state["expansion_events"].append({"reason": "CANDIDATE_BUDGET_EXPIRED"})
            break
        if time.monotonic() >= campaign_deadline:
            batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
            batch_state["expansion_events"].append({"reason": "CAMPAIGN_BUDGET_EXPIRED"})
            break
        index, raw_item, source = queue.pop(0)
        slug = _candidate_slug(raw_item, index)
        candidate_run_id = f"{args.legacy_run_id}-candidate-{slug}"
        candidate_input = candidate_input_dir / f"{slug}.json"
        candidate_input.write_text(
            json.dumps({**payload, "suggested_seeds": [dict(raw_item)]}, indent=2) + "\n",
            encoding="utf-8",
        )
        candidate_record = {
            "index": index,
            "hook_name": str(raw_item.get("hook_name") or ""),
            "callback_id": str(raw_item.get("callback_id") or ""),
            "run_id": candidate_run_id,
            "identity": _batch_candidate_identity(raw_item, args.plugin_slug),
            "source": source,
        }
        if isinstance(raw_item.get("lineage"), Mapping):
            candidate_record["lineage"] = dict(raw_item["lineage"])
        try:
            coordinator = OnlineLinkedCoordinator(
                suggested_seeds=candidate_input,
                bootstrap_config=Path(args.bootstrap_config) if args.bootstrap_config else None,
                config_root=Path(args.config_root),
                output_root=Path(args.output_root),
                plugin_slug=args.plugin_slug,
                legacy_run_id=candidate_run_id,
                max_seconds=args.max_seconds,
                max_versions=args.max_versions,
                registry_path=batch_registry,
                service=args.service,
                campaign_deadline=campaign_deadline,
            )
            result = coordinator.run()
            failed = failed or result != 0
            candidate_record.update({
                "exit_code": result,
                "state_path": str(coordinator.state_path),
                "terminal_status": coordinator.state.get("terminal_status"),
                "terminal_reason": coordinator.state.get("terminal_reason"),
                "versions": len(coordinator.state.get("versions", [])),
            })
            for child in coordinator.state.get("candidate_queue", []):
                if not isinstance(child, Mapping):
                    continue
                child_identity = _batch_candidate_identity(child, args.plugin_slug)
                if child_identity in queued_ids:
                    continue
                if time.monotonic() >= campaign_deadline:
                    batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
                    batch_state["expansion_events"].append({
                        "reason": "CAMPAIGN_BUDGET_EXPIRED",
                        "identity": child_identity,
                        "lineage": dict(child.get("lineage") or {}),
                    })
                    break
                if len(batch_state["candidates"]) + len(queue) >= max_candidates:
                    batch_state["expansion_events"].append({
                        "reason": "CANDIDATE_BUDGET_EXPIRED",
                        "identity": child_identity,
                        "lineage": dict(child.get("lineage") or {}),
                    })
                    continue
                if bool(getattr(args, "sync_registry", False)):
                    try:
                        _sync_callback_registry_to_web(batch_registry)
                    except (OSError, RuntimeError, ValueError) as exc:
                        batch_state["expansion_events"].append({
                            "reason": "CALLBACK_REGISTRY_REFRESH_FAILED",
                            "identity": child_identity,
                            "detail": str(exc),
                            "lineage": dict(child.get("lineage") or {}),
                        })
                        failed = True
                        batch_state["campaign_status"] = "NOT_VERIFIED"
                        continue
                    if time.monotonic() >= campaign_deadline:
                        batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
                        batch_state["expansion_events"].append({
                            "reason": "CAMPAIGN_BUDGET_EXPIRED",
                            "identity": child_identity,
                            "lineage": dict(child.get("lineage") or {}),
                        })
                        break
                queued_ids.add(child_identity)
                queue.append((next_index, dict(child), "runtime_registration"))
                next_index += 1
        except (OSError, ValueError) as exc:
            failed = True
            candidate_record.update({
                "exit_code": 2,
                "state_path": "",
                "terminal_status": "NOT_VERIFIED",
                "terminal_reason": f"CANDIDATE_SETUP_FAILED: {exc}",
                "versions": 0,
            })
        batch_state["candidates"].append(candidate_record)

    if batch_state["campaign_status"] == "running" and time.monotonic() >= campaign_deadline:
        batch_state["campaign_status"] = "CAMPAIGN_BUDGET_EXPIRED"
        batch_state["expansion_events"].append({"reason": "CAMPAIGN_BUDGET_EXPIRED"})
    if batch_state["campaign_status"] == "running":
        batch_state["campaign_status"] = "complete"

    batch_state_path = batch_dir / "batch-state.json"
    _write_json(batch_state_path, batch_state)
    print(f"Online-linked batch state: {batch_state_path}")
    print(f"Online-linked candidates: {len(batch_state['candidates'])}")
    print(
        "Online-linked terminal statuses: "
        + json.dumps(
            {
                status: sum(row.get("terminal_status") == status for row in batch_state["candidates"])
                for status in sorted({str(row.get("terminal_status") or "") for row in batch_state["candidates"]})
            },
            sort_keys=True,
        )
    )
    return 1 if failed else 0


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run online-linked Zend expansion with immutable workers.")
    parser.add_argument("--suggested-seeds", required=True)
    parser.add_argument("--bootstrap-config", default="")
    parser.add_argument("--config-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--plugin-slug", required=True)
    parser.add_argument("--legacy-run-id", required=True)
    parser.add_argument("--callback-registry", required=True)
    parser.add_argument("--max-seconds", type=int, choices=range(1, 121), default=120)
    parser.add_argument("--max-versions", type=int, choices=range(1, 21), default=2)
    parser.add_argument("--max-candidates", type=int, choices=range(1, 129), default=32)
    parser.add_argument("--campaign-seconds", type=int, choices=range(1, 86401), default=3600)
    parser.add_argument("--sync-registry", action="store_true")
    parser.add_argument("--service", default="fuzzer-wordpress-plugin")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        return run_online_linked(args)
    except (OSError, ValueError) as exc:
        print(f"Online-linked failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
