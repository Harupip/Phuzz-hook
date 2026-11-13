"""Docker operations for online-linked workers."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Mapping
from typing import Any

from online_linked.probe_sender import ParentInspectionError, ParentInspectionTimeout

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def worker_container_name(legacy_run_id: str, version_name: str) -> str:
    safe_run = re.sub(r"[^A-Za-z0-9_.-]+", "-", legacy_run_id).strip("-") or "online-linked"
    return f"hookphuzz-online-linked-{safe_run}-{version_name}"


def matching_pause_ack(
    ack: Mapping[str, Any] | None, *, token: str, run_id: str,
) -> dict[str, Any] | None:
    if not ack or ack.get("token") != token or ack.get("worker_run_id") != run_id:
        return None
    return {name: ack.get(name) for name in (
        "round_id", "allocated_energy", "attempts_used", "request_id", "seed_phuzz_energy")}


MAX_PARALLEL_NODES = 50  # FUZZER_NODE_ID 100 is reserved for gate replay.


def parallel_node_id(version_name: str, node_index: int) -> int:
    if node_index < 1 or node_index > MAX_PARALLEL_NODES:
        raise ValueError(f"parallel node index out of range: {node_index}")
    return 1 + int(version_name[1:]) * 100 + (node_index - 1)


def parallel_node_name(base: str, node_index: int) -> str:
    return base if node_index == 1 else f"{base}-n{node_index}"


def container_running(container_name: str, *, timeout: float, run_command: CommandRunner) -> bool:
    if not container_name or timeout <= 0:
        return False
    try:
        result = run_command(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            timeout=timeout, check=False, capture_output=True, text=True,
        )
    except Exception:
        return False
    return (int(getattr(result, "returncode", 1)) == 0
            and str(getattr(result, "stdout", "") or "").strip().lower() == "true")


def worker_start_command(
    version: Mapping[str, Any], *, container_name: str, runtime_slug: str, service: str,
    priority_seed: Mapping[str, Any] | None, fuzzer_node_id: int | None = None,
) -> list[str]:
    version_name = str(version["version"])
    worker_run_id = str(version["worker_run_id"])
    handoff_key = str(version["handoff_key"])
    node_id = 1 + int(version_name[1:]) if fuzzer_node_id is None else fuzzer_node_id
    command = [
        "docker", "compose", "run", "-d", "--no-deps", "--name", container_name,
        "-e", f"FUZZER_CONFIG={runtime_slug}",
        "-e", f"FUZZER_NODE_ID={node_id}",
        "-e", f"HOOKPHUZZ_LEGACY_RUN_ID={worker_run_id}",
        "-e", f"HOOKPHUZZ_FINDING_ARTIFACT=/shared-tmpfs/fuzzer-findings/{worker_run_id}.json",
        "-e", "HOOKPHUZZ_CMPLOG=1",
        "-e", f"HOOKPHUZZ_HANDOFF_KEY={handoff_key}",
        # Immutable config → own candidate sync folder; older selectors never load these files.
        "-e", f"HOOKPHUZZ_SYNC_NAMESPACE={str(version.get('config_hash') or '')[:16] or version_name}",
    ]
    if priority_seed is not None:
        command.extend(["-e", "HOOKPHUZZ_PRIORITY_SEED=" + json.dumps(dict(priority_seed), sort_keys=True,
                                                                        separators=(",", ":"))])
    command.append(service)
    return command


def worker_exit_code(
    container_name: str, *, timeout: float | None, run_command: CommandRunner,
) -> int | None:
    """Return a stopped worker exit code while ignoring a running/unknown worker."""

    if not container_name:
        return None
    inspect_timeout = 30 if timeout is None else max(0, timeout)
    if inspect_timeout <= 0:
        return None
    try:
        result = run_command(
            ["docker", "inspect", "-f", "{{if .State.Running}}running{{else}}{{.State.ExitCode}}{{end}}", container_name],
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
        if timeout is not None:
            raise ParentInspectionError("PARENT_INSPECT_FAILED")
        return None
    state = str(getattr(result, "stdout", "") or "").strip().lower()
    if state == "running":
        return None
    try:
        return int(state)
    except (TypeError, ValueError) as exc:
        if timeout is not None:
            raise ParentInspectionError("PARENT_INSPECT_FAILED") from exc
        return None


def handoff_command(
    container_name: str, *args: str, deadline: float | None,
    clock: Callable[[], float], run_command: CommandRunner,
) -> dict[str, Any] | None:
    """Run one pause-protocol operation inside the active worker container."""
    timeout = 10.0 if deadline is None else min(10.0, max(0.0, deadline - clock()))
    if timeout <= 0 or not container_name:
        return None
    try:
        result = run_command(
            ["docker", "exec", container_name, "python", "-m", "core.online_handoff", *args],
            timeout=timeout, check=False, capture_output=True, text=True,
        )
        payload = json.loads(str(getattr(result, "stdout", "") or "null"))
    except Exception:
        return None
    if int(getattr(result, "returncode", 1)) != 0:
        return None
    return payload if isinstance(payload, dict) else None


def remove_container(
    container_name: str, *, clock: Callable[[], float],
    sleeper: Callable[[float], None], run_command: CommandRunner,
) -> tuple[bool, str]:
    stop_deadline = clock() + 30
    try:
        result = run_command(
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
                remaining = stop_deadline - clock()
                if remaining <= 0:
                    break
                inspection = run_command(
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
                sleeper(min(0.5, max(0, stop_deadline - clock())))
    except Exception as exc:
        stopped = False
        error = str(exc)
    return stopped, error
