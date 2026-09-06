"""Bounded, opt-in Zend discovery coordinator for immutable online workers."""

from __future__ import annotations

import argparse
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
from urllib.parse import parse_qs, urlsplit

FUZZER_DIR = Path(__file__).resolve().parents[2]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from fuzz_guidance.cmplog.hints import normalize_comparison_events
from hook_energy.seed_generation.generated_config_runner import (
    list_request_artifacts,
    list_zend_artifacts,
    load_request_artifact,
    run_generated_configs,
)
from seed_generation.config.config_exporter import SeedConfigSkip, build_config_for_seed_item


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ArtifactLister = Callable[[], set[str]]
ArtifactLoader = Callable[[str], Any]
ReplayRunner = Callable[..., dict[str, Any]]

REQUESTS_DIR = "/shared-tmpfs/hook-coverage/requests"
ZEND_ARTIFACTS_DIR = "/shared/opcode-events"
SUPPORTED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
VERSION_STATUSES = {"pending", "replaying", "replay_pass", "replay_failed", "fuzzing"}
SENSITIVE_PARAMETER = re.compile(r"(?:nonce|password|secret|token|authorization|auth|cookie)", re.IGNORECASE)
REST_BUCKETS = {"URL", "GET", "POST", "JSON"}
REST_PLACEMENTS = {
    "GET": "query_params",
    "POST": "body_params",
    "JSON": "body_params",
    "URL": "url_params",
}
DIRECT_PLACEMENTS = {
    "GET": "query_params",
    "POST": "body_params",
    "COOKIE": "cookies",
}
_MISSING = object()


class OnlineConfigError(ValueError):
    """A discovered parameter cannot be represented safely by the worker."""


def validate_v0_config(
    config: Mapping[str, Any],
    *,
    require_fuzzing_ready: bool = True,
) -> tuple[bool, str]:
    """Validate the v0 shape, optionally requiring fuzz-ready parameters."""

    if not isinstance(config, Mapping):
        return False, "CONFIG_NOT_OBJECT"
    target = str(config.get("target") or "").strip()
    if not target.startswith(("http://", "https://")):
        return False, "MISSING_TARGET"
    methods = config.get("methods")
    if not isinstance(methods, list) or not methods:
        return False, "MISSING_METHOD"
    normalized_methods = {str(method).strip().upper() for method in methods if str(method).strip()}
    metadata = config.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    resolved_method = str(metadata.get("resolved_method") or "").strip().upper()
    if not resolved_method:
        if len(normalized_methods) == 1:
            resolved_method = next(iter(normalized_methods))
        else:
            return False, "MISSING_RESOLVED_METHOD"
    if resolved_method not in SUPPORTED_METHODS or resolved_method not in normalized_methods:
        return False, "INVALID_RESOLVED_METHOD"
    if not str(metadata.get("callback_repr") or metadata.get("callback_id") or "").strip():
        return False, "MISSING_CALLBACK"
    if require_fuzzing_ready and (
        str(config.get("config_type") or "").strip().lower() == "replay_only"
        or not _has_fuzzable_parameter(config)
    ):
        return False, "NOT_FUZZING_READY"
    return True, ""


def config_hash(config: Mapping[str, Any]) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def parameter_identity(parameter: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(parameter.get("source") or "").upper(),
        str(parameter.get("placement") or ""),
        str(parameter.get("name") or ""),
    )


def classify_runtime_parameter_events(
    artifact: Mapping[str, Any],
    active_config: Mapping[str, Any],
    active_version: str,
) -> list[dict[str, Any]]:
    """Turn one correlated Zend artifact into accepted/rejected discovery events."""

    if not isinstance(artifact, Mapping) or not isinstance(active_config, Mapping):
        return [_rejected_event(active_version, "ARTIFACT_NOT_OBJECT", "")]

    metadata = active_config.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    expected_callbacks = {
        str(metadata.get("callback_repr") or "").strip(),
        str(metadata.get("callback_id") or "").strip(),
    }
    expected_callbacks.discard("")
    callbacks = _artifact_callbacks(artifact)
    events: list[dict[str, Any]] = []
    for callback in sorted(callbacks - expected_callbacks):
        events.append(
            _rejected_event(
                active_version,
                "ACTION_EXPANSION_NOT_IMPLEMENTED",
                callback,
                kind="ACTION_DISCOVERY",
            )
        )
    if not callbacks.intersection(expected_callbacks):
        events.append(_rejected_event(active_version, "CALLBACK_EVIDENCE_MISMATCH", ""))
        return events

    expected_method = str(metadata.get("resolved_method") or "").strip().upper()
    observed_method = str(
        artifact.get("request_method") or artifact.get("http_method") or artifact.get("method") or ""
    ).strip().upper()
    if not expected_method:
        methods = active_config.get("methods")
        if isinstance(methods, list) and len(methods) == 1:
            expected_method = str(methods[0]).strip().upper()
    if not observed_method:
        events.append(_rejected_event(active_version, "METHOD_EVIDENCE_MISSING", ""))
        return events
    if expected_method and observed_method != expected_method:
        events.append(_rejected_event(active_version, "METHOD_EVIDENCE_MISMATCH", ""))
        return events

    raw_parameters = _artifact_parameters(artifact, expected_callbacks)
    if not raw_parameters:
        return events
    seen: set[tuple[str, str, str]] = set()
    existing = _config_parameter_identities(active_config)
    for raw in raw_parameters:
        normalized, reason = _normalize_runtime_parameter(raw, artifact, observed_method)
        if normalized is None:
            events.append(_rejected_event(active_version, reason, str(raw.get("name") or "")))
            continue
        identity = parameter_identity(normalized)
        if identity in seen:
            continue
        seen.add(identity)
        if identity in existing:
            events.append(
                _event(
                    active_version,
                    "PARAMETER_ALREADY_PRESENT",
                    "IGNORED",
                    parameter=normalized,
                )
            )
            continue
        events.append(_event(active_version, "PARAMETER_DISCOVERY", "ACCEPTED", parameter=normalized))
    return events


def classify_cmplog_events(
    artifact: Mapping[str, Any],
    active_config: Mapping[str, Any],
    active_version: str,
) -> list[dict[str, Any]]:
    """Record CmpLog mutations for parameters already present in the active config."""

    hints = normalize_comparison_events(artifact, _config_fuzz_parameters(active_config))
    return [
        _event(
            active_version,
            "CMPLOG_VALUE",
            "OBSERVED",
            kind="CMPLOG_VALUE",
            parameter={
                "name": hint["parameter"],
                "source": hint["source"],
                "placement": hint["placement"],
                "path": hint.get("path", []),
            },
            candidate_value=hint["candidate_value"],
            hint=hint,
        )
        for hint in hints
    ]


def build_child_config(parent_config: Mapping[str, Any], parameter_event: Mapping[str, Any]) -> dict[str, Any]:
    """Add one worker-representable parameter without mutating the parent."""

    if parameter_event.get("status") != "ACCEPTED":
        raise OnlineConfigError("PARAMETER_EVENT_NOT_ACCEPTED")
    parameter = parameter_event.get("parameter")
    if not isinstance(parameter, Mapping):
        raise OnlineConfigError("PARAMETER_MISSING")
    if parameter.get("materializable") is False:
        source = str(parameter.get("source") or "").upper()
        if source in {"REST_JSON", "REST_URL"}:
            raise OnlineConfigError(f"{source}_CONFIG_PLACEMENT_UNSUPPORTED")
    placement = str(parameter.get("placement") or "")
    if placement not in {"query_params", "body_params", "cookies"}:
        if str(parameter.get("source") or "").upper() in {"REST_JSON", "REST_URL"}:
            raise OnlineConfigError(f"REST_{str(parameter.get('source')).upper().split('_', 1)[-1]}_CONFIG_PLACEMENT_UNSUPPORTED")
        raise OnlineConfigError("PARAMETER_PLACEMENT_UNSUPPORTED")
    name = str(parameter.get("name") or "").strip()
    if not name or "[" in name or "]" in name or SENSITIVE_PARAMETER.search(name):
        raise OnlineConfigError("PARAMETER_NOT_SAFE_TO_FUZZ")
    child = copy.deepcopy(dict(parent_config))
    section = child.setdefault(placement, {"data": [], "fixed": [], "fuzz": [], "weight": 1})
    if not isinstance(section, dict):
        raise OnlineConfigError("PARAMETER_SECTION_MALFORMED")
    data = section.setdefault("data", [])
    if not isinstance(data, list):
        raise OnlineConfigError("PARAMETER_DATA_MALFORMED")
    if any(isinstance(item, Mapping) and str(item.get("name") or "") == name for item in data):
        raise OnlineConfigError("PARAMETER_ALREADY_PRESENT")
    data.append({"name": name, "value": parameter.get("value", "")})
    fixed = section.setdefault("fixed", [])
    fuzz = section.setdefault("fuzz", [])
    if not isinstance(fixed, list) or not isinstance(fuzz, list):
        raise OnlineConfigError("PARAMETER_SELECTOR_MALFORMED")
    section["fixed"] = [item for item in fixed if str(item) != name]
    if name not in fuzz:
        fuzz.append(name)
    child["config_type"] = "fuzzing_ready"
    metadata = child.setdefault("metadata", {})
    if isinstance(metadata, dict):
        metadata["fuzzing_ready"] = True
    return child


def build_replay_config(child_config: Mapping[str, Any], observed_values: Mapping[str, Any]) -> dict[str, Any]:
    """Make a separate fixed-value config used only for replay confirmation."""

    replay = copy.deepcopy(dict(child_config))
    for placement in ("query_params", "body_params", "cookies", "headers"):
        section = replay.get(placement)
        if not isinstance(section, dict):
            continue
        data = section.get("data")
        if not isinstance(data, list):
            data = []
            section["data"] = data
        values = observed_values.get(placement, {}) if isinstance(observed_values, Mapping) else {}
        values = values if isinstance(values, Mapping) else {}
        names: list[str] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            if name in values:
                item["value"] = values[name]
            names.append(name)
        section["fixed"] = names
        section["fuzz"] = []
    replay["config_type"] = "replay_only"
    metadata = replay.setdefault("metadata", {})
    if isinstance(metadata, dict):
        metadata["fuzzing_ready"] = False
        metadata["generated_reason"] = "online_replay_only"
    return replay


def _seed_matches_target(item: Mapping[str, Any], config: Mapping[str, Any]) -> bool:
    seed = item.get("seed")
    if not isinstance(seed, Mapping):
        return False
    seed_path = str(seed.get("path") or "").strip()
    target = str(config.get("target") or "").strip()
    if not seed_path or not target:
        return False
    parsed = urlsplit(target)
    target_paths = {parsed.path.rstrip("/") or "/"}
    rest_route = parse_qs(parsed.query).get("rest_route", [""])[0]
    if rest_route:
        target_paths.add(str(rest_route).rstrip("/") or "/")
    normalized_seed = seed_path.rstrip("/") or "/"
    if normalized_seed.startswith("/wp-json/"):
        normalized_seed = normalized_seed[len("/wp-json"):]
    return normalized_seed in target_paths


class OnlineCoordinator:
    """Coordinate bounded immutable workers with injectable local test seams."""

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
        service: str = "fuzzer-wordpress-plugin",
        run_command: CommandRunner = subprocess.run,
        list_artifacts: ArtifactLister = list_request_artifacts,
        load_artifact: ArtifactLoader = load_request_artifact,
        list_zend: ArtifactLister = list_zend_artifacts,
        load_zend: ArtifactLoader | None = None,
        replay_runner: ReplayRunner = run_generated_configs,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_seconds <= 0 or max_seconds > 60:
            raise ValueError("max_seconds must be between 1 and 60")
        if max_versions <= 0 or max_versions > 20:
            raise ValueError("max_versions must be between 1 and 20")
        self.suggested_seeds = Path(suggested_seeds)
        self.bootstrap_config = Path(bootstrap_config) if bootstrap_config else None
        self.config_root = Path(config_root)
        self.output_root = Path(output_root)
        self.plugin_slug = plugin_slug
        self.legacy_run_id = legacy_run_id or f"online-{uuid.uuid4().hex}"
        self.max_seconds = max_seconds
        self.max_versions = max_versions
        self.service = service
        self.run_command = run_command
        self.list_artifacts = list_artifacts
        self.load_artifact = load_artifact
        self.list_zend = list_zend
        self.load_zend = load_zend or _load_zend_artifact
        self.replay_runner = replay_runner
        self.clock = clock
        self.sleeper = sleeper
        self.run_dir = self.output_root / "online" / self.legacy_run_id
        self.config_dir = self.config_root / "online" / self.legacy_run_id
        artifact_key = hashlib.sha256(self.legacy_run_id.encode("utf-8")).hexdigest()[:12]
        self.artifact_dir = self.output_root.parent / "online-artifacts" / artifact_key
        self.lineage_path = self.run_dir / "lineage.json"
        self.lineage: dict[str, Any] = {
            "schema_version": 1,
            "mode": "online",
            "plugin_slug": self.plugin_slug,
            "legacy_run_id": self.legacy_run_id,
            "max_seconds": self.max_seconds,
            "max_versions": self.max_versions,
            "artifact_root": str(self.artifact_dir),
            "versions": [],
            "discovery_events": [],
            "replay_results": [],
            "workers": [],
            "artifact_copy_errors": [],
        }
        self._created_containers: list[str] = []
        self._seen_event_ids: set[str] = set()
        self._pending_requests: dict[str, dict[str, Any]] = {}
        self._active_version = ""

    def run(self) -> int:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._write_lineage()
        try:
            selected = self._select_v0()
            if selected is None:
                self.lineage["terminal_status"] = "NOT_VERIFIED"
                self.lineage["terminal_reason"] = "V0_PREREQUISITE_GATE_FAILED"
                self._write_lineage()
                return 2
            item, config = selected
            config_path = self._write_config("v0", config)
            version = self._new_version("v0", config, config_path, None, None)
            self._active_version = "v0"
            if not self._start_worker(version):
                self.lineage["terminal_status"] = "NOT_VERIFIED"
                self.lineage["terminal_reason"] = "V0_WORKER_START_FAILED"
                self._write_lineage()
                return 1
            deadline = self.clock() + self.max_seconds
            self._poll_until(deadline)
            self._stop_created_workers("BUDGET_EXPIRED")
            if self.lineage.get("terminal_status") is None:
                self.lineage["terminal_status"] = "BOUNDED_ONLINE_COMPLETE"
                self.lineage["terminal_reason"] = "BUDGET_EXPIRED"
            self._write_lineage()
            return 1 if self._has_replay_or_process_failure() else 0
        except Exception as exc:
            self.lineage["terminal_status"] = "NOT_VERIFIED"
            self.lineage["terminal_reason"] = f"ONLINE_COORDINATOR_ERROR: {exc}"
            self._write_lineage()
            self._stop_created_workers("COORDINATOR_ERROR")
            return 1

    def _select_v0(self) -> tuple[Mapping[str, Any], dict[str, Any]] | None:
        payload = json.loads(self.suggested_seeds.read_text(encoding="utf-8-sig"))
        suggestions = payload.get("suggested_seeds") if isinstance(payload, Mapping) else None
        if not isinstance(suggestions, list):
            raise ValueError("suggested_seeds.json must contain a suggested_seeds array")
        for item in suggestions:
            if not isinstance(item, Mapping):
                continue
            try:
                _, config = build_config_for_seed_item(item, target_base="http://web", rest_route_fallback=True)
            except SeedConfigSkip:
                continue
            self._decorate_config(config, item)
            if _has_fuzzable_parameter(config) and str(config.get("config_type") or "").lower() == "replay_only":
                config["config_type"] = "fuzzing_ready"
            valid, _ = validate_v0_config(config)
            if valid:
                return item, config
        if self.bootstrap_config and self.bootstrap_config.exists():
            bootstrap = json.loads(self.bootstrap_config.read_text(encoding="utf-8-sig"))
            if isinstance(bootstrap, Mapping):
                for item in suggestions:
                    if not isinstance(item, Mapping) or not _seed_matches_target(item, bootstrap):
                        continue
                    config = copy.deepcopy(dict(bootstrap))
                    self._decorate_config(config, item)
                    if not str(config.get("config_type") or "").strip():
                        config["config_type"] = "fuzzing_ready"
                    valid, _ = validate_v0_config(config)
                    if valid:
                        return item, config
        return None

    @staticmethod
    def _decorate_config(config: dict[str, Any], item: Mapping[str, Any]) -> None:
        metadata = config.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            config["metadata"] = metadata
        seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
        metadata.setdefault("callback_id", str(item.get("callback_id") or ""))
        metadata.setdefault("callback_repr", str(item.get("callback_repr") or item.get("callback_name") or ""))
        metadata.setdefault("hook_name", str(item.get("hook_name") or ""))
        metadata.setdefault("resolved_method", str(seed.get("resolved_method") or seed.get("method") or ""))

    def _write_config(self, version: str, config: Mapping[str, Any], *, replay: bool = False) -> Path:
        directory = self.config_dir / "replay" if replay else self.config_dir
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{version}.json"
        _write_exclusive_json(path, config)
        return path

    def _new_version(
        self,
        version: str,
        config: Mapping[str, Any],
        config_path: Path,
        parent_config: str | None,
        discovery_event: str | None,
    ) -> dict[str, Any]:
        record = {
            "version": version,
            "config_path": str(config_path),
            "config_type": str(config.get("config_type") or "").strip().lower(),
            "parent_config": parent_config,
            "discovery_event": discovery_event,
            "replay_result": None,
            "worker_status": "pending",
            "status": "pending",
            "config_hash": config_hash(config),
            "terminal_reason": "",
        }
        self.lineage["versions"].append(record)
        self._write_lineage()
        return record

    def _start_worker(self, version: dict[str, Any]) -> bool:
        version_name = str(version["version"])
        if len(self._created_containers) >= self.max_versions:
            version["worker_status"] = "not_started_version_limit"
            version["terminal_reason"] = "VERSION_LIMIT_REACHED"
            self._write_lineage()
            return False
        config_path = Path(str(version["config_path"]))
        runtime_slug = config_path.relative_to(self.config_root).with_suffix("").as_posix()
        container_name = _container_name(self.legacy_run_id, version_name)
        worker_run_id = f"{self.legacy_run_id}-{version_name}"
        fuzzer_node_id = str(int(version_name[1:]) + 1)
        command = [
            "docker",
            "compose",
            "run",
            "-d",
            "--no-deps",
            "--name",
            container_name,
            "-e",
            f"FUZZER_CONFIG={runtime_slug}",
            "-e",
            f"FUZZER_NODE_ID={fuzzer_node_id}",
        ]
        if worker_run_id:
            command += ["-e", f"HOOKPHUZZ_LEGACY_RUN_ID={worker_run_id}"]
        command.append(self.service)
        try:
            result = self.run_command(command, timeout=30, check=False, capture_output=True, text=True)
        except Exception as exc:
            version["worker_status"] = "start_failed"
            version["terminal_reason"] = f"WORKER_START_FAILED: {exc}"
            self.lineage["workers"].append({"version": version_name, "container_name": container_name, "run_id": worker_run_id, "status": "start_failed", "command": command, "error": str(exc)})
            self._write_lineage()
            return False
        if int(getattr(result, "returncode", 1)) != 0:
            error = str(getattr(result, "stderr", "") or getattr(result, "stdout", "") or "docker compose run failed").strip()
            version["worker_status"] = "start_failed"
            version["terminal_reason"] = f"WORKER_START_FAILED: {error}"
            self.lineage["workers"].append({"version": version_name, "container_name": container_name, "run_id": worker_run_id, "status": "start_failed", "command": command, "error": error})
            self._write_lineage()
            return False
        version["worker_status"] = "started"
        version["status"] = "replaying" if version.get("config_type") == "replay_only" else "fuzzing"
        self.lineage["workers"].append({"version": version_name, "container_name": container_name, "run_id": worker_run_id, "status": "started", "command": command})
        self._created_containers.append(container_name)
        self._write_lineage()
        return True

    def _poll_until(self, deadline: float) -> None:
        while self.clock() < deadline:
            try:
                request_names = self.list_artifacts()
                for name in sorted(request_names - set(self._pending_requests)):
                    try:
                        payload = self.load_artifact(name)
                    except Exception as exc:
                        self._record_event(_rejected_event(self._active_version, f"REQUEST_ARTIFACT_READ_FAILED: {exc}", name))
                        continue
                    if isinstance(payload, Mapping):
                        self._pending_requests[name] = dict(payload)
                zend_names = self.list_zend()
                for request_name, request_payload in list(self._pending_requests.items()):
                    zend_name = _matching_artifact_name(request_name, request_payload, zend_names)
                    if not zend_name:
                        continue
                    try:
                        zend_payload = self.load_zend(zend_name)
                    except Exception as exc:
                        self._record_event(_rejected_event(self._active_version, f"ZEND_ARTIFACT_READ_FAILED: {exc}", zend_name))
                        continue
                    self._process_artifact_pair(request_name, request_payload, zend_name, zend_payload, deadline)
                    del self._pending_requests[request_name]
            except Exception as exc:
                self.lineage.setdefault("poll_errors", []).append(str(exc))
                self._write_lineage()
            remaining = deadline - self.clock()
            if remaining > 0:
                self.sleeper(min(0.5, remaining))

    def _process_artifact_pair(
        self,
        request_name: str,
        request_payload: Mapping[str, Any],
        zend_name: str,
        zend_payload: Any,
        deadline: float | None = None,
    ) -> None:
        if not isinstance(zend_payload, Mapping):
            return
        artifact = dict(request_payload)
        artifact.update(zend_payload)
        if "request_params" not in artifact and isinstance(request_payload.get("request_params"), Mapping):
            artifact["request_params"] = request_payload["request_params"]
        version = self._version(self._active_version)
        if version is None:
            return
        for kind, name, payload in (
            ("request", request_name, request_payload),
            ("zend", zend_name, zend_payload),
        ):
            try:
                self._copy_artifact(self._active_version, kind, name, payload)
            except OSError as exc:
                self.lineage["artifact_copy_errors"].append({
                    "version": self._active_version,
                    "kind": kind,
                    "name": name,
                    "reason": str(exc),
                })
        self._write_lineage()
        for event in classify_cmplog_events(artifact, self._config_for_version(version), self._active_version):
            self._record_event(event)
        for event in classify_runtime_parameter_events(artifact, self._config_for_version(version), self._active_version):
            if event.get("status") == "ACCEPTED":
                self._expand_parameter(version, event, deadline)
            else:
                self._record_event(event)

    def _expand_parameter(self, parent: Mapping[str, Any], event: Mapping[str, Any], deadline: float | None = None) -> None:
        if len(self.lineage["versions"]) >= self.max_versions:
            rejected = dict(event)
            rejected.pop("event_id", None)
            rejected["status"] = "REJECTED"
            rejected["reason"] = "VERSION_LIMIT_REACHED"
            self._record_event(rejected)
            return
        if deadline is not None and deadline - self.clock() < 1:
            rejected = dict(event)
            rejected.pop("event_id", None)
            rejected["status"] = "REJECTED"
            rejected["reason"] = "BUDGET_EXPIRED"
            self._record_event(rejected)
            return
        try:
            parent_config = self._config_for_version(parent)
            child_config = build_child_config(parent_config, event)
        except OnlineConfigError as exc:
            rejected = dict(event)
            rejected.pop("event_id", None)
            rejected["status"] = "REJECTED"
            rejected["reason"] = str(exc)
            self._record_event(rejected)
            return
        self._record_event(event)
        next_version = f"v{len(self.lineage['versions'])}"
        child_path = self._write_config(next_version, child_config)
        child = self._new_version(next_version, child_config, child_path, str(parent["config_path"]), str(event["event_id"]))
        replay_config = build_replay_config(child_config, _observed_values(event))
        replay_path = self._write_config(next_version, replay_config, replay=True)
        row = {
            "config_slug": f"online/{self.legacy_run_id}/replay/{next_version}",
            "config_path": str(replay_path),
            "hook_name": str(child_config.get("metadata", {}).get("hook_name") or ""),
            "callback_id": str(child_config.get("metadata", {}).get("callback_id") or ""),
            "entrypoint_type": str(child_config.get("entrypoint_type") or ""),
            "resolved_method": child_config.get("metadata", {}).get("resolved_method"),
        }
        remaining = self.max_seconds if deadline is None else max(1, int(deadline - self.clock()))
        timeout = max(1, min(30, remaining))
        replay_run_id = f"{self.legacy_run_id}-replay-{next_version}"
        try:
            report = self.replay_runner(
                [row],
                timeout_seconds=timeout,
                service=self.service,
                legacy_run_id=replay_run_id,
                run_command=self.run_command,
                list_artifacts=self.list_artifacts,
                load_artifact=self.load_artifact,
                list_zend_artifacts=self.list_zend,
                poll_interval_seconds=0,
                fuzzer_node_id=100 + int(next_version[1:]),
            )
        except Exception as exc:
            report = {"error": str(exc), "runs": []}
        replay_row = report.get("runs", [{}])[0] if isinstance(report, Mapping) and isinstance(report.get("runs"), list) else {}
        passed = bool(
            isinstance(replay_row, Mapping)
            and replay_row.get("validation_status") == "callback_reached"
            and replay_row.get("process_status") not in {"failed", "runner_error"}
        )
        replay_result = {
            "version": next_version,
            "config_path": str(replay_path),
            "config_hash": config_hash(replay_config),
            "passed": passed,
            "runner": report,
        }
        child["replay_result"] = replay_result
        self.lineage["replay_results"].append(replay_result)
        if passed:
            child["status"] = "replay_pass"
            child["terminal_reason"] = ""
            self._write_lineage()
            if self._start_worker(child):
                self._active_version = next_version
            else:
                child["terminal_reason"] = "WORKER_START_FAILED"
                self._write_lineage()
        else:
            child["status"] = "replay_failed"
            child["worker_status"] = "not_started_replay_failed"
            child["terminal_reason"] = str(replay_row.get("validation_reason") or "REPLAY_FAILED")
            self._write_lineage()

    def _copy_artifact(self, version: str, kind: str, name: str, payload: Any) -> None:
        safe_name = Path(name).name
        if not safe_name:
            return
        directory = self.artifact_dir / version / kind
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / safe_name
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _record_event(self, event: Mapping[str, Any]) -> None:
        event_id = str(event.get("event_id") or _event_id(event))
        if event_id in self._seen_event_ids:
            return
        item = dict(event)
        item["event_id"] = event_id
        self._seen_event_ids.add(event_id)
        self.lineage["discovery_events"].append(item)
        self._write_lineage()

    def _version(self, name: str) -> dict[str, Any] | None:
        return next((item for item in self.lineage["versions"] if item.get("version") == name), None)

    def _config_for_version(self, version: Mapping[str, Any]) -> dict[str, Any]:
        return json.loads(Path(str(version["config_path"])).read_text(encoding="utf-8"))

    def _write_lineage(self) -> None:
        _write_json(self.lineage_path, self.lineage)

    def _stop_created_workers(self, reason: str) -> None:
        for container_name in self._created_containers:
            result = self.run_command(
                ["docker", "rm", "-f", container_name],
                timeout=30,
                check=False,
                capture_output=True,
                text=True,
            )
            status = "stopped" if int(getattr(result, "returncode", 1)) == 0 else "stop_failed"
            for worker in self.lineage["workers"]:
                if worker.get("container_name") == container_name:
                    worker["status"] = "stopped_by_budget" if status == "stopped" else status
                    worker["terminal_reason"] = reason
            for version in self.lineage["versions"]:
                if version.get("worker_status") == "started":
                    version["worker_status"] = "stopped_by_budget" if status == "stopped" else status
                    version["terminal_reason"] = reason
        self._write_lineage()

    def _has_replay_or_process_failure(self) -> bool:
        return any(version.get("status") == "replay_failed" for version in self.lineage["versions"])


def run_online_discovery(args: argparse.Namespace) -> int:
    coordinator = OnlineCoordinator(
        suggested_seeds=Path(args.suggested_seeds),
        bootstrap_config=Path(args.bootstrap_config) if args.bootstrap_config else None,
        config_root=Path(args.config_root),
        output_root=Path(args.output_root),
        plugin_slug=args.plugin_slug,
        legacy_run_id=args.legacy_run_id,
        max_seconds=args.max_seconds,
        max_versions=args.max_versions,
        service=args.service,
    )
    result = coordinator.run()
    print(f"Online lineage: {coordinator.lineage_path}")
    print(f"Online versions: {len(coordinator.lineage['versions'])}")
    print(f"Online terminal status: {coordinator.lineage.get('terminal_status', 'NOT_VERIFIED')}")
    return result


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded online Zend discovery with immutable workers.")
    parser.add_argument("--suggested-seeds", required=True)
    parser.add_argument("--bootstrap-config", default="")
    parser.add_argument("--config-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--plugin-slug", required=True)
    parser.add_argument("--legacy-run-id", default="")
    parser.add_argument("--max-seconds", type=int, choices=range(1, 61), default=60)
    parser.add_argument("--max-versions", type=int, choices=range(1, 21), default=2)
    parser.add_argument("--service", default="fuzzer-wordpress-plugin")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        return run_online_discovery(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Online discovery failed: {exc}", file=sys.stderr)
        return 2


def _has_fuzzable_parameter(config: Mapping[str, Any]) -> bool:
    for placement in ("query_params", "body_params", "cookies"):
        section = config.get(placement)
        if isinstance(section, Mapping) and isinstance(section.get("fuzz"), list) and section["fuzz"]:
            return True
    return False


def _config_fuzz_parameters(config: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for placement in ("query_params", "body_params", "cookies"):
        section = config.get(placement)
        if not isinstance(section, Mapping):
            continue
        fuzz_names = {str(name) for name in section.get("fuzz", []) if str(name)}
        values = {
            str(item.get("name")): item.get("value")
            for item in section.get("data", [])
            if isinstance(item, Mapping) and str(item.get("name")) in fuzz_names
        }
        result[placement] = values
    return result


def _config_parameter_identities(config: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    identities: set[tuple[str, str, str]] = set()
    source_by_placement = {"query_params": "GET", "body_params": "POST", "cookies": "COOKIE"}
    for placement, source in source_by_placement.items():
        section = config.get(placement)
        if not isinstance(section, Mapping):
            continue
        for item in section.get("data", []):
            if isinstance(item, Mapping) and str(item.get("name") or ""):
                identities.add((source, placement, str(item["name"])))
                if placement == "query_params":
                    identities.add(("REST_GET", placement, str(item["name"])))
                elif placement == "body_params":
                    identities.add(("REST_POST", placement, str(item["name"])))
    return identities


def _artifact_callbacks(artifact: Mapping[str, Any]) -> set[str]:
    callbacks: set[str] = set()
    summaries = artifact.get("callback_summaries")
    if isinstance(summaries, list):
        for summary in summaries:
            if isinstance(summary, Mapping):
                for key in ("callback", "callback_id", "callback_repr"):
                    value = str(summary.get(key) or "").strip()
                    if value:
                        callbacks.add(value)
    rest_events = artifact.get("rest_parameter_events")
    if isinstance(rest_events, list):
        for event in rest_events:
            if isinstance(event, Mapping):
                for key in ("callback", "callback_id", "callback_repr"):
                    value = str(event.get(key) or "").strip()
                    if value:
                        callbacks.add(value)
    hook_coverage = artifact.get("hook_coverage")
    if isinstance(hook_coverage, Mapping):
        executed = hook_coverage.get("executed_callbacks")
        if isinstance(executed, Mapping):
            callbacks.update(str(key) for key in executed if str(key))
            for value in executed.values():
                if isinstance(value, Mapping):
                    for key in ("callback_id", "callback", "callback_repr"):
                        item = str(value.get(key) or "").strip()
                        if item:
                            callbacks.add(item)
    return callbacks


def _artifact_parameters(artifact: Mapping[str, Any], expected_callbacks: set[str]) -> list[Mapping[str, Any]]:
    parameters: list[Mapping[str, Any]] = []
    summaries = artifact.get("callback_summaries")
    if isinstance(summaries, list):
        for summary in summaries:
            if not isinstance(summary, Mapping):
                continue
            callback = str(summary.get("callback") or summary.get("callback_id") or "").strip()
            if callback not in expected_callbacks:
                continue
            values = summary.get("unique_parameters")
            if isinstance(values, list):
                parameters.extend(item for item in values if isinstance(item, Mapping))
    values = artifact.get("rest_parameter_events")
    if isinstance(values, list):
        for item in values:
            if not isinstance(item, Mapping):
                continue
            callback = str(item.get("callback") or item.get("callback_id") or "").strip()
            if not callback or callback in expected_callbacks:
                parameters.append(item)
    return parameters


def _normalize_runtime_parameter(raw: Mapping[str, Any], artifact: Mapping[str, Any], method: str) -> tuple[dict[str, Any] | None, str]:
    try:
        observed_count = int(raw.get("observed_count") or 0)
    except (TypeError, ValueError):
        return None, "PROVENANCE_INVALID"
    if observed_count < 1 or int(raw.get("helper_depth") or 0) != 0:
        return None, "PROVENANCE_INVALID"
    source_raw = str(raw.get("source") or "").strip()
    source = source_raw.upper().replace("$", "")
    if source.startswith("_"):
        source = source[1:]
    accessor = str(raw.get("accessor") or "")
    bucket = str(raw.get("bucket") or "").strip().upper()
    path = raw.get("path")
    is_rest = source in {"REST", "WP_REST_REQUEST", "REST_GET_PARAM", "REST_REQUEST"} or "WP_REST_REQUEST" in accessor.upper() or bucket in REST_BUCKETS
    if is_rest:
        if "WP_REST_REQUEST" not in accessor.upper() and source not in {"REST", "REST_GET_PARAM", "REST_REQUEST"}:
            return None, "REST_PROVENANCE_MISSING"
        if not bucket and isinstance(path, (list, tuple)) and path:
            bucket = str(path[0] or "").strip().upper()
        if bucket not in REST_BUCKETS:
            return None, "REST_BUCKET_UNSUPPORTED"
        name = str(raw.get("name") or raw.get("parameter") or "").strip()
        if isinstance(path, (list, tuple)):
            parts = [str(item).strip() for item in path]
            if parts and parts[0].upper() == bucket:
                parts = parts[1:]
            if len(parts) != 1:
                return None, "NESTED_PARAMETER_UNSUPPORTED"
            if name and name != parts[0]:
                return None, "PROVENANCE_NAME_MISMATCH"
            name = parts[0]
        if not name:
            return None, "PROVENANCE_MISSING"
        location = REST_PLACEMENTS[bucket]
        value = _observed_value(raw, artifact, location, bucket=bucket, name=name)
        if value is _MISSING or not _is_scalar(value):
            return None, "OBSERVED_VALUE_MISSING"
        if SENSITIVE_PARAMETER.search(name):
            return None, "SECURITY_SENSITIVE_PARAMETER"
        return {
            "name": name,
            "source": f"REST_{bucket}",
            "placement": location,
            "location": {"GET": "query", "POST": "form", "JSON": "json", "URL": "path"}[bucket],
            "path": [bucket, name],
            "value": value,
            "observed_count": observed_count,
            "evidence_kind": "zend_rest_runtime",
            "materializable": bucket in {"GET", "POST"},
        }, ""

    if not source_raw:
        return None, "PROVENANCE_MISSING"
    if source not in {"GET", "POST", "REQUEST", "COOKIE"}:
        return None, "PROVENANCE_UNSUPPORTED"
    name = str(raw.get("name") or raw.get("parameter") or "").strip()
    if isinstance(path, (list, tuple)):
        parts = [str(item).strip() for item in path if str(item).strip()]
        if parts and parts[0].upper() == source:
            parts = parts[1:]
        if len(parts) != 1:
            return None, "NESTED_PARAMETER_UNSUPPORTED"
        if name and name != parts[0]:
            return None, "PROVENANCE_NAME_MISMATCH"
        name = parts[0]
    if not name or not source_raw:
        return None, "PROVENANCE_MISSING"
    placement = DIRECT_PLACEMENTS.get(source)
    if source == "REQUEST":
        candidates = []
        for candidate_placement in ("query_params", "body_params"):
            value = _transport_value(artifact, candidate_placement, name)
            if value is not _MISSING:
                candidates.append((candidate_placement, value))
        if len(candidates) != 1:
            return None, "REQUEST_PROVENANCE_AMBIGUOUS" if candidates else "REQUEST_PROVENANCE_MISSING"
        placement, transport_value = candidates[0]
    else:
        transport_value = _transport_value(artifact, placement, name)
    value = _observed_value(raw, artifact, placement, fallback=transport_value)
    if value is _MISSING or not _is_scalar(value):
        return None, "OBSERVED_VALUE_MISSING"
    if SENSITIVE_PARAMETER.search(name):
        return None, "SECURITY_SENSITIVE_PARAMETER"
    return {
        "name": name,
        "source": source_raw,
        "placement": placement,
        "location": {"query_params": "query", "body_params": "form", "cookies": "cookie"}[placement],
        "path": [name],
        "value": value,
        "observed_count": observed_count,
        "evidence_kind": "zend_runtime",
        "materializable": True,
    }, ""


def _observed_value(raw: Mapping[str, Any], artifact: Mapping[str, Any], placement: str, *, bucket: str = "", name: str = "", fallback: Any = _MISSING) -> Any:
    for key in ("observed_value", "runtime_value", "value"):
        if key in raw and _is_scalar(raw[key]):
            return raw[key]
    if fallback is not _MISSING:
        return fallback
    return _transport_value(artifact, placement, name, bucket=bucket)


def _transport_value(artifact: Mapping[str, Any], placement: str, name: str, *, bucket: str = "") -> Any:
    request_params = artifact.get("request_params")
    if not isinstance(request_params, Mapping):
        return _MISSING
    keys = {
        "query_params": ("query_params", "query", "GET"),
        "body_params": ("body_params", "body", "POST", "JSON", "json_params", "json"),
        "cookies": ("cookies", "cookie", "COOKIE"),
        "url_params": ("url_params", "url", "URL", "path"),
    }.get(placement, ())
    if bucket == "JSON":
        keys = ("JSON", "json", "json_params", "body_params", "body")
    if bucket == "URL":
        keys = ("URL", "url", "url_params", "path")
    for key in keys:
        values = request_params.get(key)
        if isinstance(values, Mapping) and name in values:
            return values[name]
    return _MISSING


def _event(
    version: str,
    reason: str,
    status: str,
    *,
    parameter: Mapping[str, Any] | None = None,
    kind: str = "PARAMETER_DISCOVERY",
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {"version": version, "kind": kind, "status": status, "reason": reason}
    if parameter is not None:
        item["parameter"] = dict(parameter)
    item.update(extra)
    item["event_id"] = _event_id(item)
    return item


def _rejected_event(version: str, reason: str, name: str, *, kind: str = "PARAMETER_DISCOVERY") -> dict[str, Any]:
    return _event(version, reason, "REJECTED", parameter={"name": name} if name else None, kind=kind)


def _event_id(event: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key != "event_id"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")).hexdigest()[:20]


def _observed_values(event: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    parameter = event.get("parameter")
    if not isinstance(parameter, Mapping):
        return {}
    placement = str(parameter.get("placement") or "")
    name = str(parameter.get("name") or "")
    if not placement or not name:
        return {}
    return {placement: {name: parameter.get("value", "")}}


def _container_name(run_id: str, version: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id).strip("-") or "online"
    return f"hookphuzz-online-{safe}-{version}"


def _matching_artifact_name(request_name: str, request_payload: Mapping[str, Any], zend_names: set[str]) -> str | None:
    if request_name in zend_names:
        return request_name
    request_id = str(request_payload.get("request_id") or "").strip()
    candidates = {Path(request_name).stem, request_id}
    for name in sorted(zend_names):
        if Path(name).stem in candidates or any(token and token in Path(name).stem for token in candidates):
            return name
    return None


def _load_zend_artifact(name: str) -> Any:
    if Path(name).name != name:
        raise ValueError(f"Invalid Zend artifact name: {name}")
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "cat", f"{ZEND_ARTIFACTS_DIR}/{name}"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Could not read Zend artifact: {name}")
    return json.loads(result.stdout)


def _write_exclusive_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


if __name__ == "__main__":
    raise SystemExit(main())
