"""Opt-in parallel phase: extra PHUZZ nodes on the active version after the quiet window.

Node 1 is the coordinator's existing worker; this runner owns nodes 2..N only.
Nodes differ from node 1 by environment alone (run id, handoff key, node id),
so the fuzzer itself is unchanged and all nodes share one candidate queue.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from hook_energy.seed_generation.generated_config_runner import STOP_ON_VULN_EXIT_CODE
from online_linked.coordination.worker import (
    CommandRunner,
    container_running,
    handoff_command,
    matching_pause_ack,
    parallel_node_id,
    parallel_node_name,
    remove_container,
    worker_exit_code,
    worker_start_command,
)

# Docker start-up wait for the extra nodes; it never counts toward parallel_seconds.
NODE_START_WAIT_SECONDS = 30.0
# Pause ACK wait for nodes 2..N (bounded by node 1's wait). A node answers between
# requests, so this covers a request timeout; one stuck node must not burn the phase.
NODE_PAUSE_WAIT_SECONDS = 30.0


class ParallelHost(Protocol):
    state: dict[str, Any]
    clock: Callable[[], float]
    sleeper: Callable[[float], None]
    run_command: CommandRunner
    config_root: Path
    service: str
    max_seconds: int
    _sender_seconds: float
    parallel: bool
    parallel_nodes: int
    parallel_seconds: int
    campaign_deadline: float | None
    _active_container: str
    _active_version: str
    _deadline: float | None
    _parallel_group: dict[str, Any] | None

    def _record_event(self, event: Mapping[str, Any], *, checkpoint: bool = True) -> dict[str, Any]: ...
    def _write_state(self) -> None: ...
    def _version(self, name: str) -> dict[str, Any] | None: ...
    def _attach_finding_artifact(self, version: Mapping[str, Any] | None, *, run_id: str | None = None) -> None: ...
    def _stop_active_worker(self, reason: str) -> None: ...


class ParallelRunner:
    __slots__ = ("_host",)

    def __init__(self, host: ParallelHost) -> None:
        self._host = host

    @property
    def _group(self) -> dict[str, Any] | None:
        return getattr(self._host, "_parallel_group", None)

    def active(self) -> bool:
        return self._group is not None

    def deadline(self) -> float | None:
        group = self._group
        return None if group is None else float(group["deadline"])

    def run_ids(self) -> list[str]:
        version = self._host._version(self._host._active_version) or {}
        run_ids = [str(version.get("worker_run_id") or "")]
        group = self._group
        if group is not None:
            run_ids.extend(str(node["worker_run_id"]) for node in group["nodes"])
        return run_ids

    def owns_run_id(self, run_id: str) -> bool:
        group = self._group
        return group is not None and any(node["worker_run_id"] == run_id for node in group["nodes"])

    def can_start(self) -> bool:
        """Parallel runs once per version, when the quiet window ends with the worker still healthy."""
        host = self._host
        if not getattr(host, "parallel", False) or host.parallel_nodes < 2 or host.parallel_seconds < 1:
            return False
        if self.active() or not host._active_container or getattr(host, "_pause", None) is not None:
            return False
        status, reason = host.state.get("terminal_status"), host.state.get("terminal_reason")
        # An evidence read that crossed the quiet deadline is the same quiet end, not a failure.
        if status is not None and not (status == "BOUNDED_ONLINE_COMPLETE" and reason == "BUDGET_EXPIRED"):
            return False
        if host.campaign_deadline is not None and host.clock() >= host.campaign_deadline:
            return False
        version = host._version(host._active_version)
        return version is not None and "parallel" not in version

    def start(self, version: dict[str, Any]) -> bool:
        host = self._host
        if not host._active_container:
            return False
        host.state.update(terminal_status=None, terminal_reason=None)
        version_name = str(version["version"])
        base_container = host._active_container
        base_run_id = str(version["worker_run_id"])
        runtime_slug = Path(str(version["config_path"])).relative_to(host.config_root).with_suffix("").as_posix()
        nodes: list[dict[str, Any]] = [{
            "node_index": 1, "container_name": base_container, "worker_run_id": base_run_id,
            "started": True, "exit_code": None, "stop_reason": None,
        }]
        version["parallel"] = {
            "started_at": host.clock(), "all_running_at": None, "deadline": None,
            "requested_nodes": host.parallel_nodes, "nodes": nodes, "ended_at": None, "end_reason": None,
        }
        started: list[dict[str, Any]] = []
        # Tracked before the first start: any interruption from here on is cleaned up by stop_nodes.
        host._parallel_group = {"version": version_name, "nodes": started, "deadline": None,
                                "discovery_deadline": None}
        for node_index in range(2, host.parallel_nodes + 1):
            if host.campaign_deadline is not None and host.clock() >= host.campaign_deadline:
                break
            node = {
                "node_index": node_index,
                "container_name": parallel_node_name(base_container, node_index),
                "worker_run_id": parallel_node_name(base_run_id, node_index),
                "handoff_key": f"{version_name}-n{node_index}-{uuid.uuid4().hex}",
                "started": False, "exit_code": None, "stop_reason": None,
            }
            nodes.append(node)
            # In the group before `compose run`: an interrupted start may still create the container.
            started.append(node)
            command = worker_start_command(
                {**version, "worker_run_id": node["worker_run_id"], "handoff_key": node["handoff_key"]},
                container_name=node["container_name"], runtime_slug=runtime_slug, service=host.service,
                priority_seed=None, fuzzer_node_id=parallel_node_id(version_name, node_index),
            )
            error = ""
            try:
                result = host.run_command(command, timeout=self._bounded(30.0), check=False,
                                          capture_output=True, text=True)
                if int(getattr(result, "returncode", 1)) != 0:
                    error = str(getattr(result, "stderr", "") or "WORKER_START_FAILED").strip()
            except Exception as exc:
                error = f"WORKER_START_FAILED: {exc}"
            if error:
                # A timed-out `compose run -d` may still have created the container.
                started.remove(node)
                self._remove(node, "START_FAILED")
                node["start_error"] = error
                self._event("PARALLEL_NODE_START_FAILED", "REJECTED", "WORKER_START_FAILED", version, node,
                            detail=error)
                continue
            node["started"] = True

        wait_until = host.clock() + NODE_START_WAIT_SECONDS
        if host.campaign_deadline is not None:
            wait_until = min(wait_until, host.campaign_deadline)
        pending = list(started)
        while pending and host.clock() < wait_until:
            pending = [
                node for node in pending
                if not container_running(node["container_name"], run_command=host.run_command,
                                         timeout=min(10.0, max(0.0, wait_until - host.clock())))
            ]
            if pending:
                host.sleeper(min(0.5, max(0.0, wait_until - host.clock())))
        for node in pending:
            started.remove(node)
            node["started"] = False
            self._remove(node, "NOT_RUNNING")
            self._event("PARALLEL_NODE_START_FAILED", "REJECTED", "NODE_NOT_RUNNING", version, node)

        all_running_at = host.clock()
        deadline = all_running_at + host.parallel_seconds
        if host.campaign_deadline is not None:
            deadline = min(deadline, host.campaign_deadline)
        version["parallel"].update(all_running_at=all_running_at, deadline=deadline)
        host._parallel_group["deadline"] = deadline
        # The parallel deadline replaces the quiet window while the group runs.
        host._deadline = deadline
        host._record_event({
            "kind": "PARALLEL_START", "status": "STARTED", "reason": "QUIET_WINDOW_EXPIRED",
            "version": version_name, "requested_nodes": host.parallel_nodes, "running_nodes": 1 + len(started),
            "all_running_at": all_running_at, "deadline": deadline,
        })
        host._write_state()
        return True

    def poll_exits(self) -> int | None:
        """Drop exited nodes; a vulnerability exit from any node ends the callback."""
        group = self._group
        if group is None:
            return None
        host = self._host
        version = host._version(group["version"])
        for node in list(group["nodes"]):
            code = worker_exit_code(node["container_name"], timeout=None, run_command=host.run_command)
            if code is None:
                continue
            node["exit_code"] = code
            group["nodes"].remove(node)
            self._event("PARALLEL_NODE_EXIT", "EXITED", f"EXIT_CODE_{code}", version, node, exit_code=code)
            if code == STOP_ON_VULN_EXIT_CODE:
                host._attach_finding_artifact(version, run_id=node["worker_run_id"])
                if version is not None:
                    version["status"] = "vuln_found"
                    version["terminal_reason"] = "VULN_FOUND"
                host.state.update(terminal_status="VULN_FOUND", terminal_reason="VULN_FOUND")
                self._remove(node, "VULN_FOUND")
                host._stop_active_worker("VULN_FOUND")
                host._write_state()
                return code
            self._remove(node, f"EXIT_CODE_{code}")
            host._write_state()
        return None

    def pause_nodes(self, deadline: float | None, *, request_id: str = "") -> None:
        """Pause every extra node like node 1; a node without a matching ACK is removed."""
        group = self._group
        if group is None:
            return
        host = self._host
        version = host._version(group["version"])
        wait_until = (deadline - 2 * host._sender_seconds if deadline is not None
                      else host.clock() + host.max_seconds)
        wait_until = min(wait_until, host.clock() + NODE_PAUSE_WAIT_SECONDS)
        paused: dict[str, str] = group.setdefault("paused", {})
        pending: dict[str, tuple[dict[str, Any], str]] = {}
        for node in group["nodes"]:
            token = uuid.uuid4().hex
            if self._handoff(node, "request", node["handoff_key"], token, node["worker_run_id"],
                             *([request_id] if request_id else []), deadline=wait_until) is not None:
                pending[node["container_name"]] = (node, token)
        while pending and host.clock() < wait_until:
            for name, (node, token) in list(pending.items()):
                ack = self._handoff(node, "ack", node["handoff_key"], deadline=wait_until)
                if matching_pause_ack(ack, token=token, run_id=node["worker_run_id"]) is not None:
                    paused[name] = token
                    del pending[name]
            if pending:
                host.sleeper(min(0.2, max(0.0, wait_until - host.clock())))
        for node in [node for node in group["nodes"] if node["container_name"] not in paused]:
            # Replay must stay clean: a node we cannot pause does not keep fuzzing.
            group["nodes"].remove(node)
            removed = self._remove(node, "PAUSE_NOT_ACKNOWLEDGED")
            self._event("PARALLEL_PAUSE", "REJECTED", "NODE_REMOVED" if removed else "NODE_REMOVE_FAILED",
                        version, node)
        if paused:
            host._record_event({
                "kind": "PARALLEL_PAUSE", "status": "ACKNOWLEDGED", "reason": "PAUSE_ACK",
                "version": group["version"], "request_id": request_id, "paused_nodes": len(paused),
                "at": host.clock(),
            })
        host._write_state()

    def release_nodes(self) -> None:
        group = self._group
        if group is None:
            return
        paused = group.pop("paused", {}) or {}
        for node in group["nodes"]:
            token = paused.get(node["container_name"])
            if token is not None:
                self._handoff(node, "release", node["handoff_key"], token, deadline=None)

    def end_for_handoff(self, child_version: str) -> bool:
        """A verified parameter ends Parallel: discovery restarts on the child's config."""
        group = self._group
        if group is None:
            return True
        host = self._host
        discovery = group.get("discovery_deadline")
        if discovery is None:
            discovery = host.clock() + host.max_seconds
            if host.campaign_deadline is not None:
                discovery = min(discovery, host.campaign_deadline)
        stopped = self.stop_nodes("HANDOFF_TO_" + child_version)
        host._deadline = discovery
        host.state["candidate_deadline"] = discovery
        return stopped

    def stop_nodes(self, reason: str) -> bool:
        """Remove nodes 2..N and close the group; node 1 is the caller's to stop."""
        group = self._group
        if group is None:
            return True
        host = self._host
        stopped = all([self._remove(node, reason) for node in list(group["nodes"])])
        host._parallel_group = None
        version = host._version(group["version"])
        if version is not None and isinstance(version.get("parallel"), dict):
            for node in version["parallel"]["nodes"]:
                if node["node_index"] == 1 and node["stop_reason"] is None:
                    node["stop_reason"] = reason
            version["parallel"].update(ended_at=host.clock(), end_reason=reason)
        host._record_event({
            "kind": "PARALLEL_END", "status": "ENDED" if stopped else "REJECTED",
            "reason": reason if stopped else "NODE_STOP_FAILED", "version": group["version"],
            "end_reason": reason,
        })
        host._write_state()
        return stopped

    def remove_leftover_nodes(self, version: Mapping[str, Any], reason: str) -> None:
        """Remove nodes a killed coordinator left running; resume never restores the group."""
        parallel = version.get("parallel")
        if not isinstance(parallel, dict):
            return
        for node in parallel.get("nodes", []):
            if node.get("node_index", 1) >= 2 and node.get("started") and node.get("stop_reason") is None:
                self._remove(node, reason)
        if parallel.get("ended_at") is None:
            parallel.update(ended_at=self._host.clock(), end_reason=reason)

    def _remove(self, node: dict[str, Any], reason: str) -> bool:
        stopped, error = remove_container(
            node["container_name"], clock=self._host.clock, sleeper=self._host.sleeper,
            run_command=self._host.run_command,
        )
        node["stop_reason"] = reason
        if not stopped:
            node["stop_error"] = error
        return stopped

    def _handoff(self, node: Mapping[str, Any], *args: str, deadline: float | None) -> dict[str, Any] | None:
        return handoff_command(node["container_name"], *args, deadline=deadline,
                               clock=self._host.clock, run_command=self._host.run_command)

    def _bounded(self, seconds: float) -> float:
        campaign = self._host.campaign_deadline
        return seconds if campaign is None else min(seconds, max(0.0, campaign - self._host.clock()))

    def _event(self, kind: str, status: str, reason: str, version: Mapping[str, Any] | None,
               node: Mapping[str, Any], **extra: Any) -> None:
        self._host._record_event({
            "kind": kind, "status": status, "reason": reason,
            "version": (version or {}).get("version"), "node_index": node["node_index"],
            "container_name": node["container_name"], "worker_run_id": node["worker_run_id"], **extra,
        })
