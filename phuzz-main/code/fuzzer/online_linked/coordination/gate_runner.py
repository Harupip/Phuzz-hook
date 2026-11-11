"""Gate v0, replay guard discovery and v0 selection for the online-linked coordinator.

``GateRunner`` holds no state of its own: every dependency and piece of campaign
state stays on the coordinator and is read through ``self._host`` each time it is
needed, so overrides assigned on a built coordinator still apply.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from filesystem_paths import filesystem_path
from hook_energy.seed_generation.online_common import config_hash, select_v0, validate_v0_config
from online_linked.coordination.candidate_identity import _candidate_context_key, _candidate_identity
from online_linked.coordination.errors import OnlineLinkedError
from online_linked.coordination.gate_replay import (
    gate_replay_name,
    gate_replay_row,
    guard_replay_summary,
    load_gate_evidence,
    unsent_guard_probes,
)
from online_linked.coordination.request_matching import _parameter_key, _safe_parameter_identity
from online_linked.coordination.worker import CommandRunner
from online_linked.export import PARAMETER_REPLAY_POLICY, parameter_replay_failures
from seed_generation.config.config_exporter import SeedConfigSkip


class GateHost(Protocol):
    """The coordinator members ``GateRunner`` reads, writes or calls."""

    state: dict[str, Any]
    clock: Callable[[], float]
    resume: bool
    registry: dict[str, Any]
    service: str
    run_command: CommandRunner
    list_artifacts: Callable[[], set[str]]
    load_artifact: Callable[[str], Any]
    list_zend_artifacts: Callable[[], set[str]]
    replay_runner: Callable[..., dict[str, Any]]
    force_replay_only_fn: Callable[[dict[str, Any]], None]
    converge_fn: Callable[..., dict[str, Any]]
    build_config_fn: Callable[..., tuple[str, dict[str, Any]]]
    list_targets_fn: Callable[..., list[dict[str, Any]]]
    config_root: Path
    run_dir: Path
    plugin_slug: str
    legacy_run_id: str
    runtime_cookie_probes: bool
    suggested_seeds: Path
    bootstrap_config: Path | None
    _reports: dict[str, dict[str, Any]]
    _target_key: str
    _active_container: str
    _replay_evidence: dict[str, dict[str, Any]]
    _gate_evidence: dict[str, Any] | None
    _gate_convergence: dict[str, Any] | None
    _replay_discovery_active: bool
    _raw_report: dict[str, Any] | None
    _targets: list[dict[str, Any]]

    def _record_event(self, event: Mapping[str, Any], *, checkpoint: bool = True) -> dict[str, Any]: ...
    def _write_config(self, version: str, config: Mapping[str, Any], *, replay: bool = False) -> Path: ...
    def _save_replay_artifacts(
        self,
        row: Mapping[str, Any],
        request_dir: Path,
        zend_dir: Path,
        *,
        strict_correlation: bool | None = None,
    ) -> None: ...
    def _baseline_identity_complete(
        self, request: Mapping[str, Any], zend: Mapping[str, Any], parent: Mapping[str, Any],
    ) -> bool: ...
    def _baseline_evidence(self, evidence: Mapping[str, Any], version: Mapping[str, Any]) -> dict[str, str]: ...
    def _parameter_replay_fields(
        self, parent: Mapping[str, Any], child: Mapping[str, Any], baseline: Mapping[str, Any] | None,
    ) -> list[dict[str, str]]: ...
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


class GateRunner:
    __slots__ = ("_host",)

    def __init__(self, host: GateHost) -> None:
        self._host = host

    def gate_v0(self, version: dict[str, Any], config: Mapping[str, Any], *, deadline: float) -> bool:
        """Require a correlated replay before starting any v0 worker."""
        if deadline - self._host.clock() < 1:
            version["terminal_reason"] = "BUDGET_EXPIRED"
            return False
        replay = copy.deepcopy(dict(config))
        self._host.force_replay_only_fn(replay)
        gate_name, reactivation = gate_replay_name(
            version, resume=self._host.resume, resume_count=self._host.state.get("resume_count", 0),
        )
        path = self._host._write_config(gate_name, replay, replay=True)
        # A child's handoff replay is the proof the exporter rechecks: store reactivations apart.
        child_proof = version.get("replay_result") if str(version.get("version")) != "v0" else None
        child_proof = child_proof if isinstance(child_proof, Mapping) else None
        if child_proof is None:
            version["replay_config_path"] = str(path)
            version["replay_config_hash"] = config_hash(replay)
        parameter_policy = bool(child_proof) and child_proof.get("verification_policy") == PARAMETER_REPLAY_POLICY
        row = gate_replay_row(version, path, config_root=self._host.config_root)
        reason = "V0_CALLBACK_NOT_REACHED"
        readiness: dict[str, Any] = {
            "passed": False, "verification_policy": "callback_baseline_v1",
            "config_path": str(path), "config_hash": config_hash(replay),
        }
        version["readiness"] = readiness
        try:
            if not self._host.registry.get("callback_map", {}).get(version["callback_id"]):
                raise OnlineLinkedError("V0_REGISTRY_MISSING")
            timeout = min(30, int(deadline - self._host.clock()))
            if timeout < 1:
                raise OnlineLinkedError("BUDGET_EXPIRED")
            report = self._host.replay_runner(
                [row], timeout_seconds=timeout, service=self._host.service,
                legacy_run_id=version["worker_run_id"], run_command=self._host.run_command,
                list_artifacts=self._host.list_artifacts, load_artifact=self._host.load_artifact,
                list_zend_artifacts=self._host.list_zend_artifacts, poll_interval_seconds=0, fuzzer_node_id=100,
                stop_on_callback=True,
            )
            readiness["runner"] = report
            rows = report.get("runs", [])
            result_row = rows[0] if len(rows) == 1 else {}
            if result_row.get("process_status") == "vuln_found":
                self._host.state.update(terminal_status="VULN_FOUND", terminal_reason="VULN_FOUND")
                return False
            if result_row.get("callback_reached") is not True or result_row.get("validation_status") != "callback_reached":
                raise OnlineLinkedError(reason)
            if result_row.get("process_status") in {"failed", "runner_error"}:
                raise OnlineLinkedError("V0_REPLAY_PROCESS_FAILED")
            probe_dir = gate_name + "-probe" if reactivation else "probe"
            request_dir = self._host.run_dir / "versions" / str(version["version"]) / probe_dir / "request"
            zend_dir = request_dir.parent / "zend"
            self._host._save_replay_artifacts(
                {**result_row, "_strict_correlation": False}, request_dir, zend_dir,
            )
            reason = "V0_PROVENANCE_NOT_VERIFIED"
            observation = self._host.converge_fn(
                raw_report=self._host._reports[str(version["version"])], pass_run_summary=report,
                pass_artifacts_dir=request_dir, zend_events_dir=zend_dir, registry=self._host.registry,
                plugin_slug=self._host.plugin_slug, legacy_run_id=version["worker_run_id"],
                known_state={"known_parameters": version.get("known_parameters", [])}, candidate_key=self._host._target_key,
                runtime_cookie_probes=self._host.runtime_cookie_probes,
            )
            readiness["convergence"] = observation
            if observation.get("runtime_block_reason") or (observation.get("status") == "REPLAY_FAILED" and not observation.get("missing_parameters")):
                reason = str(observation.get("runtime_block_reason") or "V0_PROVENANCE_NOT_VERIFIED")
                self._host._record_event({"kind": "V0_READINESS", "status": "REJECTED", "reason": reason,
                                    "missing_parameters": observation.get("missing_parameters", [])})
                raise OnlineLinkedError(reason)
            if version["config_type"] != "fuzzing_ready":
                readiness["probe_only"] = True
            gate_evidence = load_gate_evidence(
                version, result_row, request_dir, zend_dir, observation,
                plugin_slug=self._host.plugin_slug,
            )
            if gate_evidence is None or not self._host._baseline_identity_complete(
                gate_evidence["request"], gate_evidence["zend"], version,
            ):
                raise OnlineLinkedError("V0_PROVENANCE_NOT_VERIFIED")
            self._host._gate_evidence = gate_evidence
            self._host._gate_convergence = copy.deepcopy(dict(observation))
            version["gate_evidence"] = {
                "origin": "v0_gate",
                "request_id": gate_evidence["request_id"],
                "request_name": gate_evidence["request_name"],
                "zend_name": gate_evidence["zend_name"],
                "consumed": False,
            }
            response = gate_evidence["request"].get("response")
            status = response.get("status_code") if isinstance(response, Mapping) else None
            if parameter_policy:
                # Same policy as the handoff that admitted this config: status is diagnostic.
                fields = list(child_proof.get("verified_parameters") or [])
                missing = parameter_replay_failures(fields, gate_evidence["request"], gate_evidence["zend"])
                readiness.update(verification_policy=PARAMETER_REPLAY_POLICY, verified_parameters=fields,
                                 response_status=status)
                if not fields or missing:
                    readiness.update(reason="PARAMETER_REPLAY_NOT_VERIFIED", unverified_parameters=missing)
                    self._host.state.update(terminal_status="PARTIAL", terminal_reason="PARAMETER_REPLAY_NOT_VERIFIED")
                    return False
            elif version["config_type"] == "fuzzing_ready":
                try:
                    guard_unknown = not (200 <= int(status) < 300 or int(status) == 302)
                except (TypeError, ValueError):
                    guard_unknown = True
                if guard_unknown:
                    readiness.update(guard_status="unknown", reason="GUARD_SATISFACTION_UNKNOWN")
                    self._host.state.update(terminal_status="PARTIAL", terminal_reason="GUARD_SATISFACTION_UNKNOWN")
                    return False
            if self._host.clock() >= deadline:
                raise OnlineLinkedError("BUDGET_EXPIRED")
            readiness["baseline_evidence"] = self._host._baseline_evidence(gate_evidence, version)
            readiness["passed"] = True
            return True
        except (OSError, RuntimeError, ValueError) as exc:
            readiness.update(reason=str(exc), passed=False)
            self._host.state.update(terminal_status="NOT_VERIFIED", terminal_reason=str(exc) if isinstance(exc, OnlineLinkedError) else reason)
            return False

    def discover_replay_guards(
        self, child: dict[str, Any], evidence: Mapping[str, Any], *, deadline: float | None,
        running_parent: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Probe guards that a passed AJAX replay hit on fields it never sent.

        The running parent sends each probe and child baseline. A descendant replaces
        ``child`` only after its own callback baseline passes; every round adds one
        version, so the loop is bounded by the version and probe caps.
        """
        current = child
        while not (deadline is not None and self._host.clock() >= deadline):
            if self._host.state.get("terminal_status") or not self._host._active_container:
                break
            version_name = str(current["version"])
            raw_report = self._host._reports.get(version_name)
            if raw_report is None or not current.get("replay_config_path"):
                break
            replay_run_id = str(evidence["worker_run_id"])
            replay_dir = self._host.run_dir / "versions" / version_name / "replay"
            try:
                result = self._host.converge_fn(
                    raw_report=raw_report,
                    pass_run_summary=guard_replay_summary(
                        current, evidence, config_root=self._host.config_root, replay_run_id=replay_run_id,
                    ),
                    pass_artifacts_dir=replay_dir / "request",
                    zend_events_dir=replay_dir / "zend",
                    registry=self._host.registry,
                    plugin_slug=self._host.plugin_slug,
                    legacy_run_id=replay_run_id,
                    known_state={"known_parameters": current.get("known_parameters", [])},
                    candidate_key=None,
                    runtime_cookie_probes=self._host.runtime_cookie_probes,
                    probe_unsent_guards=True,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                self._host._record_event({
                    "kind": "REPLAY_GUARD_DISCOVERY", "status": "REJECTED",
                    "reason": "CORRELATION_OR_PROVENANCE_INCOMPLETE", "version": version_name,
                    "request_id": evidence.get("request_id"), "detail": str(exc),
                })
                break
            probes = unsent_guard_probes(result)
            if not probes:
                break
            self._host._record_event({
                "kind": "REPLAY_GUARD_DISCOVERY", "status": "PENDING", "reason": "UNSENT_GUARD",
                "version": version_name, "worker_run_id": replay_run_id,
                "request_id": evidence.get("request_id"),
                "parameters": [_safe_parameter_identity(row) for row in probes],
            })
            convergence = {
                **result, "new_parameters": [], "pending_probes": probes,
                "known_parameters": current.get("known_parameters", []),
            }
            self._host._replay_discovery_active = True
            try:
                next_child = self._host._run_pending_probe(
                    parent={**current, "worker_run_id": replay_run_id}, evidence=evidence,
                    raw_report=raw_report, convergence=convergence, probe=probes[0],
                    seed=current.get("seed_item") or {}, deadline=deadline,
                )
            finally:
                self._host._replay_discovery_active = False
            next_evidence = self._host._replay_evidence.pop(str((next_child or {}).get("version") or ""), None)
            if (
                next_child is None or next_evidence is None
                or (next_child.get("replay_result") or {}).get("passed") is not True
            ):
                break
            if running_parent is not None and not self.descendant_proves_batch(running_parent, next_child):
                break  # keep the verified ancestor as the handoff target
            current["worker_status"] = "not_started_superseded"
            current["terminal_reason"] = f"SUPERSEDED_BY_{next_child['version']}"
            covered = {
                _parameter_key(parameter) for parameter in next_child.get("known_parameters") or []
                if isinstance(parameter, Mapping)
            }
            superseded = {
                str(version.get("version")) for version in self._host.state["versions"]
                if version.get("worker_status") == "not_started_superseded"
            }
            queue = self._host.state.get("pending_probe_queue", [])
            for row in [row for row in queue if row.get("parent_version") in superseded
                        and _parameter_key(row.get("candidate") or {}) in covered]:
                # Otherwise a later drain would stop the descendant to restart this version.
                queue.remove(row)
                self._host._record_event({
                    "kind": "PARAMETER_PROBE", "status": "SKIPPED", "reason": "ADMITTED_FROM_TRACE",
                    "version": row.get("parent_version"), "request_id": (row.get("candidate") or {}).get("request_id"),
                    "candidate": dict(row.get("candidate") or {}),
                })
            self._host._record_event({
                "kind": "CHILD_REPLAY", "status": "PASS", "reason": current["terminal_reason"],
                "hook_name": current.get("hook_name"), "version": version_name,
                "probe_id": None, "parameter": None,
                "timing": dict((current.get("replay_result") or {}).get("timing") or {}),
            })
            current, evidence = next_child, next_evidence
        return current

    def descendant_proves_batch(self, running_parent: Mapping[str, Any], descendant: dict[str, Any]) -> bool:
        """The worker gets the last descendant: its own replay must prove every field new over the parent."""
        replay_result = descendant["replay_result"]
        if descendant.get("evidence_origin", "worker_poll") != "worker_poll":
            return True
        rows = (replay_result.get("runner") or {}).get("runs") or [{}]
        proof = {"request": rows[0].get("request_payload") or {}, "zend": rows[0].get("zend_payload") or {}}
        batch = self._host._parameter_replay_fields(running_parent, descendant, proof)
        if not batch:
            return True
        replay_result.update(verification_policy=PARAMETER_REPLAY_POLICY, verified_parameters=batch)
        missing = parameter_replay_failures(batch, proof["request"], proof["zend"])
        if not missing:
            return True
        replay_result.update(passed=False, unverified_parameters=missing)
        descendant.update(status="replay_failed", worker_status="not_started_replay_failed",
                          terminal_reason="PARAMETER_REPLAY_NOT_VERIFIED")
        self._host._record_event({
            "kind": "CHILD_REPLAY", "status": "REJECTED", "reason": "PARAMETER_REPLAY_NOT_VERIFIED",
            "hook_name": descendant.get("hook_name"), "version": descendant.get("version"),
            "probe_id": None, "parameter": None, "timing": dict(replay_result.get("timing") or {}),
        })
        return False

    def select_v0(self) -> tuple[Mapping[str, Any], dict[str, Any], str] | None:
        payload = json.loads(filesystem_path(self._host.suggested_seeds).read_text(encoding="utf-8-sig"))
        if not isinstance(payload, Mapping) or not isinstance(payload.get("suggested_seeds"), list):
            raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
        self._host._raw_report = copy.deepcopy(dict(payload))
        selected: tuple[Mapping[str, Any], dict[str, Any]] | None = None
        for item in payload["suggested_seeds"]:
            if not isinstance(item, Mapping):
                continue
            try:
                _, config = self._host.build_config_fn(item, target_base="http://web", rest_route_fallback=True)
            except SeedConfigSkip:
                try:
                    _, config = self._host.build_config_fn(
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
            if self._host.bootstrap_config is None or not filesystem_path(self._host.bootstrap_config).is_file():
                return None
            selected = select_v0(self._host.suggested_seeds, self._host.bootstrap_config)
            if selected is None:
                return None
        self._host._targets = self._host.list_targets_fn(
            self._host._raw_report,
            plugin_slug=self._host.plugin_slug,
            legacy_run_id=f"{self._host.legacy_run_id}-v0",
        )
        item = selected[0]
        matches = [
            target for target in self._host._targets
            if str(target.get("hook_name") or "") == str(item.get("hook_name") or "")
            and str(target.get("callback_id") or "") == str(item.get("callback_id") or "")
            and str(target.get("method") or "").upper() == str(selected[1].get("metadata", {}).get("resolved_method") or "").upper()
        ]
        if len(matches) != 1:
            return None
        context_key = _candidate_context_key(item, self._host.plugin_slug)
        self._host.state["candidate_context_key"] = context_key
        if context_key not in self._host.state["queued_candidate_context_keys"]:
            self._host.state["queued_candidate_context_keys"].append(context_key)
        identity = _candidate_identity(item, self._host.plugin_slug)
        if identity not in self._host.state["queued_candidate_ids"]:
            self._host.state["queued_candidate_ids"].append(identity)
        return selected[0], selected[1], str(matches[0].get("candidate_key") or "")
