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
    ) -> None:
        if not 1 <= max_seconds <= 60:
            raise ValueError("max_seconds must be between 1 and 60")
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
        # Keep nested evidence/config paths below Windows MAX_PATH for long run IDs.
        storage_id = hashlib.sha256(self.legacy_run_id.encode("utf-8")).hexdigest()[:16]
        self.run_dir = self.output_root / "online-linked" / storage_id
        self.config_dir = self.config_root / "online-linked" / storage_id
        if registry is not None:
            self.registry = dict(registry)
        elif registry_path is not None:
            self.registry = json.loads(Path(registry_path).read_text(encoding="utf-8-sig"))
        else:
            raise ValueError("online-linked requires a callback registry")
        if not isinstance(self.registry, Mapping):
            raise ValueError("callback registry must be an object")
        self.state: dict[str, Any] = {
            "schema_version": 1,
            "mode": "online-linked",
            "plugin_slug": plugin_slug,
            "legacy_run_id": legacy_run_id,
            "max_seconds": max_seconds,
            "max_versions": max_versions,
            "versions": [],
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
            if not self._start_worker(version):
                self.state["terminal_status"] = "NOT_VERIFIED"
                self.state["terminal_reason"] = "V0_WORKER_START_FAILED"
                self._write_state()
                return 1

            deadline = self.clock() + self.max_seconds
            while self.clock() < deadline:
                for evidence in self.read_new_runtime_evidence():
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

    def read_new_runtime_evidence(self) -> list[dict[str, Any]]:
        """Read exact-ID request/Zend pairs for the active worker."""

        version = self._version(self._active_version)
        if version is None:
            return []
        request_names = self.list_artifacts()
        evidence: list[dict[str, Any]] = []
        for request_name in sorted(request_names):
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
            explicit_callback = str(request_payload.get("callback_id") or "").strip()
            explicit_hook = str(request_payload.get("hook_name") or "").strip()
            if (explicit_callback and explicit_callback != str(version.get("callback_id") or "")) or (
                explicit_hook and explicit_hook != str(version.get("hook_name") or "")
            ):
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
            evidence.append({
                "version": str(version["version"]),
                "worker_run_id": str(version["worker_run_id"]),
                "request_name": request_name,
                "request_id": request_id,
                "request": dict(request_payload),
                "zend_name": zend_name,
                "zend": dict(zend_payload),
            })
        return evidence

    def advance_online_version(self, evidence: Mapping[str, Any], *, deadline: float | None = None) -> dict[str, Any] | None:
        """Run existing convergence/export logic and prepare one child version."""

        parent = self._version(self._active_version)
        if parent is None:
            return None
        if deadline is not None and self.clock() >= deadline:
            return None
        if len(self.state["versions"]) >= self.max_versions:
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
        parent["known_parameters"] = list(result.get("known_parameters") or [])
        materialize_candidate_key = str(result.get("candidate_key") or self._target_key).split("::", 1)[0]
        materialized = self.materialize_fn(
            raw_report,
            plugin_slug=self.plugin_slug,
            candidate_key=materialize_candidate_key,
            known_parameters=parent["known_parameters"],
            for_replay=False,
        )
        next_version = f"v{len(self.state['versions'])}"
        generated_dir = self.config_dir / "versions" / next_version / "exported"
        generated_summary_path = self.run_dir / "versions" / next_version / "generated_config_summary.json"
        generated_dir.mkdir(parents=True, exist_ok=True)
        generated_summary_path.parent.mkdir(parents=True, exist_ok=True)
        generated = self.export_configs_fn(
            materialized,
            output_config_dir=generated_dir,
            summary_path=generated_summary_path,
            target_base="http://web",
            rest_route_fallback=True,
        )
        rows = generated.get("generated") if isinstance(generated, Mapping) else None
        if not isinstance(rows, list) or len(rows) != 1:
            self._record_event({**discovery, "status": "REJECTED", "reason": "CHILD_CONFIG_EXPORT_FAILED"})
            return None
        generated_path = Path(str(rows[0].get("config_path") or ""))
        if not generated_path.is_file():
            self._record_event({**discovery, "status": "REJECTED", "reason": "CHILD_CONFIG_MISSING"})
            return None
        child_config = json.loads(generated_path.read_text(encoding="utf-8-sig"))
        child_path = self._write_config(next_version, child_config)
        child = self._new_version(next_version, child_config, child_path, parent, discovery["event_id"], seed)
        child["known_parameters"] = list(parent["known_parameters"])
        self._reports[next_version] = copy.deepcopy(materialized)
        replay_config = copy.deepcopy(child_config)
        self.force_replay_only_fn(replay_config)
        replay_path = self._write_config(next_version, replay_config, replay=True)
        child["replay_config_path"] = str(replay_path)
        self._write_state()
        self.handoff_to_next_worker(parent, child, materialized, replay_path, deadline=deadline)
        return child

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
        relative = Path("versions") / version / ("replay" if replay else "") / "config.json"
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
            and str(parameter.get("canonical_callback")) == str(parent.get("canonical_callback"))
        )


def _candidate_slug(item: Mapping[str, Any], index: int) -> str:
    raw = str(item.get("hook_name") or item.get("callback_id") or "candidate")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-.") or "candidate"
    return f"{index:03d}-{slug}"


def run_online_linked(args: argparse.Namespace) -> int:
    suggested_path = Path(args.suggested_seeds)
    payload = json.loads(suggested_path.read_text(encoding="utf-8-sig"))
    items = payload.get("suggested_seeds") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")

    batch_dir = Path(args.output_root) / "online-linked" / args.legacy_run_id
    candidate_input_dir = batch_dir / "candidates"
    candidate_input_dir.mkdir(parents=True, exist_ok=True)
    batch_state: dict[str, Any] = {
        "schema_version": 1,
        "mode": "online-linked-batch",
        "plugin_slug": args.plugin_slug,
        "legacy_run_id": args.legacy_run_id,
        "max_seconds_per_candidate": args.max_seconds,
        "max_versions_per_candidate": args.max_versions,
        "candidates": [],
    }
    failed = False
    for index, raw_item in enumerate(items, start=1):
        if not isinstance(raw_item, Mapping):
            continue
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
        }
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
                registry_path=Path(args.callback_registry),
                service=args.service,
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
    parser.add_argument("--max-seconds", type=int, choices=range(1, 61), default=60)
    parser.add_argument("--max-versions", type=int, choices=range(1, 21), default=2)
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
