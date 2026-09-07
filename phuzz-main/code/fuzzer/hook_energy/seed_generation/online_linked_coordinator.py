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
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ArtifactLister = Callable[[], set[str]]
ArtifactLoader = Callable[[str], Any]
ConvergeRunner = Callable[..., dict[str, Any]]
TargetLister = Callable[..., list[dict[str, Any]]]
MaterializeRunner = Callable[..., dict[str, Any]]
Exporter = Callable[..., dict[str, Any]]
ReplayRunner = Callable[..., dict[str, Any]]
Pass2Verifier = Callable[..., dict[str, int]]
ConfigBuilder = Callable[..., tuple[str, dict[str, Any]]]


class OnlineLinkedError(ValueError):
    """A coordinator transition cannot be completed safely."""


class OnlineLinkedCoordinator:
    """Coordinate immutable online versions without changing worker configs."""

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
                for evidence in self.read_new_runtime_evidence(deadline=deadline):
                    self.advance_online_version(evidence, deadline=deadline)
                    if self.state["terminal_reason"] == "WORKER_STOP_FAILED" or not self._active_container:
                        break
                if self.state["terminal_reason"] == "WORKER_STOP_FAILED" or not self._active_container:
                    break
                worker_exit_code = self._worker_exit_code()
                if worker_exit_code is not None:
                    version = self._version(self._active_version)
                    if worker_exit_code == STOP_ON_VULN_EXIT_CODE:
                        if version is not None:
                            version["status"] = "vuln_found"
                            version["terminal_reason"] = "VULN_FOUND"
                        self.state["terminal_status"] = "VULN_FOUND"
                        self.state["terminal_reason"] = "VULN_FOUND"
                        self._stop_active_worker("VULN_FOUND")
                        self._write_state()
                        return 1 if self._failure else 0
                    if worker_exit_code != 0:
                        self._failure = True
                        if version is not None:
                            version["status"] = "worker_failed"
                            version["terminal_reason"] = f"WORKER_EXIT_CODE_{worker_exit_code}"
                        self.state["terminal_status"] = "NOT_VERIFIED"
                        self.state["terminal_reason"] = f"WORKER_EXIT_CODE_{worker_exit_code}"
                        self._stop_active_worker("WORKER_FAILED")
                        self._write_state()
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
        if result.get("status") == "REPLAY_FAILED" or result.get("missing_parameters") or result.get("runtime_block_reason"):
            self._record_event({
                "kind": "RUNTIME_OBSERVATION", "status": "REJECTED",
                "reason": result.get("runtime_block_reason") or result.get("status") or "MISSING_PARAMETERS",
                "missing_parameters": result.get("missing_parameters", []),
                "version": parent["version"], "request_id": evidence.get("request_id"),
            })
            return None
        new_parameters = result.get("new_parameters") if isinstance(result, Mapping) else None
        if not isinstance(new_parameters, list) or not new_parameters:
            self._record_event({
                "kind": "RUNTIME_OBSERVATION",
                "status": "IGNORED",
                "reason": "NO_NEW_ZEND_PARAMETER",
                "version": parent["version"],
                "request_id": evidence.get("request_id"),
            })
            return None
        for parameter in new_parameters:
            if not self._admission_complete(parameter, evidence, parent):
                self._record_event({
                    "kind": "PARAMETER_DISCOVERY",
                    "status": "REJECTED",
                    "reason": "CORRELATION_OR_PROVENANCE_INCOMPLETE",
                    "version": parent["version"],
                    "request_id": evidence.get("request_id"),
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
        materialized = self.materialize_fn(
            raw_report,
            plugin_slug=self.plugin_slug,
            candidate_key=materialize_candidate_key,
            known_parameters=proposed_parameters,
            for_replay=False,
        )
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
        generated_dir.mkdir(parents=True, exist_ok=True)
        generated_summary_path.parent.mkdir(parents=True, exist_ok=True)
        if deadline is not None and self.clock() >= deadline:
            attempt.update(status="failed", reason="BUDGET_EXPIRED")
            self._record_event({**discovery, "event_id": "", "status": "REJECTED", "reason": "BUDGET_EXPIRED"})
            return None
        try:
            generated = self.export_configs_fn(
                materialized,
                output_config_dir=generated_dir,
                summary_path=generated_summary_path,
                target_base="http://web",
                rest_route_fallback=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            generated = {}
            attempt["error"] = str(exc)
        rows = generated.get("generated") if isinstance(generated, Mapping) else None
        if not isinstance(rows, list) or len(rows) != 1:
            attempt.update(status="failed", reason="CHILD_CONFIG_EXPORT_FAILED")
            self._record_event({**discovery, "event_id": "", "status": "REJECTED", "reason": "CHILD_CONFIG_EXPORT_FAILED"})
            return None
        generated_path = Path(str(rows[0].get("config_path") or ""))
        if not generated_path.is_file():
            attempt.update(status="failed", reason="CHILD_CONFIG_MISSING")
            self._record_event({**discovery, "event_id": "", "status": "REJECTED", "reason": "CHILD_CONFIG_MISSING"})
            return None
        child_config = json.loads(generated_path.read_text(encoding="utf-8-sig"))
        self._restore_request_values(child_config, evidence, parent)
        child_path = self._write_config(next_version, child_config)
        child = self._new_version(next_version, child_config, child_path, parent, discovery["event_id"], seed)
        child["known_parameters"] = proposed_parameters
        self._reports[next_version] = copy.deepcopy(materialized)
        replay_config = copy.deepcopy(child_config)
        self.force_replay_only_fn(replay_config)
        replay_path = self._write_config(next_version, replay_config, replay=True)
        child["replay_config_path"] = str(replay_path)
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

    def _restore_request_values(
        self, config: dict[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
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
        for section_name in ("query_params", "body_params", "headers", "cookies"):
            section = config.get(section_name)
            if not isinstance(section, dict):
                continue
            bucket = "json_params" if section_name == "body_params" and is_json else section_name
            observed, source, source_reason = self._request_bucket_values(params, bucket)
            parent_section = parent_config.get(section_name, {})
            if not isinstance(parent_section, Mapping):
                parent_section = {}
            fixed = parent_section.get("fixed", [])
            if not isinstance(fixed, list):
                raise OnlineLinkedError(f"UNSUPPORTED_CONFIG_BUCKET: {section_name}.fixed must be a list")
            for row in section.get("data", []):
                name = str(row["name"])
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
                    "value_origin": "observed" if found else ("probe" if source == "observed" else source),
                }
                if not found:
                    value_record["reason"] = source_reason or "REQUEST_VALUE_MISSING"
                values.append(value_record)
        config.setdefault("metadata", {})["online_request_seed"] = {
            "request_id": evidence["request_id"], "run_id": parent["worker_run_id"],
            "values": values,
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
        """Stop parent, replay/verify child, then start exactly one active worker."""

        if not self._stop_worker(parent, "HANDOFF_TO_" + str(child["version"])):
            child["worker_status"] = "not_started_parent_stop_failed"
            child["terminal_reason"] = "WORKER_STOP_FAILED"
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
        timeout = self.max_seconds
        if deadline is not None:
            timeout = min(30, int(deadline - self.clock()))
            if timeout < 1:
                child["worker_status"] = "not_started_budget_expired"
                child["terminal_reason"] = "BUDGET_EXPIRED"
                self._write_state()
                return False
        replay_run_id = f"{self.legacy_run_id}-{version_name}-replay"
        try:
            replay_report = self.replay_runner(
                [row],
                timeout_seconds=timeout,
                service=self.service,
                legacy_run_id=replay_run_id,
                run_command=self.run_command,
                list_artifacts=self.list_artifacts,
                load_artifact=self.load_artifact,
                list_zend_artifacts=self.list_zend_artifacts,
                poll_interval_seconds=0,
                fuzzer_node_id=100 + int(version_name[1:]),
                stop_on_callback=True,
            )
        except Exception as exc:
            replay_report = {"error": str(exc), "runs": []}
        replay_rows = replay_report.get("runs") if isinstance(replay_report, Mapping) else None
        replay_row = replay_rows[0] if isinstance(replay_rows, list) and replay_rows else {}
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
            and replay_row.get("process_status") not in {"failed", "runner_error"}
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
        if artifact_error:
            replay_result["artifact_error"] = artifact_error
        child["replay_result"] = replay_result
        self.state.setdefault("replay_results", []).append(replay_result)
        if replay_passed:
            child["status"] = "replay_pass"
            child["terminal_reason"] = ""
            self._write_state()
            if self._start_worker(child, deadline=deadline):
                self._active_version = str(child["version"])
                return True
            if child["worker_status"] == "not_started_budget_expired":
                return False
            child["terminal_reason"] = "WORKER_START_FAILED"
            self._failure = True
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "CHILD_WORKER_START_FAILED"
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
            self._write_state()
        parent_record = self._version(str(parent["version"]))
        if parent_record is not None and self._start_worker(parent_record, deadline=deadline):
            self._active_version = str(parent_record["version"])
        elif parent_record is None or parent_record["worker_status"] != "not_started_budget_expired":
            self.state["terminal_status"] = "NOT_VERIFIED"
            self.state["terminal_reason"] = "PARENT_WORKER_RESTART_FAILED"
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

    def _worker_exit_code(self) -> int | None:
        """Return a stopped worker exit code while ignoring a running/unknown worker."""

        if not self._active_container:
            return None
        try:
            result = self.run_command(
                ["docker", "inspect", "-f", "{{if .State.Running}}running{{else}}{{.State.ExitCode}}{{end}}", self._active_container],
                timeout=30,
                check=False,
                capture_output=True,
                text=True,
            )
        except Exception:
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
            payload = self.load_artifact(name)
            self._copy_json(request_dir / name, payload)
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
        return (
            all(str(value or "").strip() for value in required)
            and str(parameter.get("request_id")) == str(evidence.get("request_id"))
            and str(parameter.get("run_id")) == str(parent.get("worker_run_id"))
            and str(parameter.get("plugin_slug")) == self.plugin_slug
            and str(parameter.get("request_method")).upper() == str(parent.get("resolved_method") or "").upper()
            and _canonical_callback_name(parameter.get("canonical_callback"))
            == _canonical_callback_name(parent.get("canonical_callback"))
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
    parser.add_argument("--max-seconds", type=int, choices=range(1, 121), default=60)
    parser.add_argument("--max-versions", type=int, choices=range(1, 21), default=2)
    parser.add_argument("--max-candidates", type=int, choices=range(1, 129), default=32)
    parser.add_argument("--campaign-seconds", type=int, choices=range(1, 86401), default=600)
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
