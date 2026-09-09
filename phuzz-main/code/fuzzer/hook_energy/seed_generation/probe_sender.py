from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import requests

from hook_energy.seed_generation.generated_config_runner import (
    REQUESTS_DIR,
    ZEND_ARTIFACTS_DIR,
    read_correlated_artifact_pair,
)
from seed_generation.verification.seed_validator import evaluate_artifact_payloads
try:
    from fuzzer import prepare_request_from_config
except ImportError:
    from fuzzer.fuzzer import prepare_request_from_config


class ParentInspectionTimeout(RuntimeError):
    """Parent status could not be inspected within the sender deadline."""


class ParentInspectionError(RuntimeError):
    """Parent status inspection failed without proving an exit state."""


def run_in_container(
    container_name: str,
    *,
    config_slug: str,
    request_id: str,
    run_id: str,
    timeout_seconds: float,
    expected: Mapping[str, Any],
    process_factory: Callable[..., Any] = subprocess.Popen,
    parent_exit_code: Callable[[float], int | None] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    config_path = Path(config_slug)
    if config_path.is_absolute() or ".." in config_path.parts:
        raise ValueError("config_slug must be relative")
    command = [
        "docker", "exec",
        "-e", f"HOOKPHUZZ_LEGACY_RUN_ID={run_id}",
        container_name,
        "python", "/app/fuzzer.py", "--online-linked-probe",
        "--config-path", f"/app/configs/{config_path.as_posix()}.json",
        "--request-id", str(request_id),
        "--run-id", str(run_id),
        "--timeout-seconds", str(timeout_seconds),
        "--plugin-slug", str(expected.get("plugin_slug") or ""),
        "--hook-name", str(expected.get("hook_name") or ""),
        "--callback-id", str(expected.get("callback_id") or ""),
        "--method", str(expected.get("method") or ""),
        "--auth-context", str(expected.get("auth_context") or "authenticated"),
    ]
    started_at = clock()
    process = process_factory(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout_chunks: list[str | bytes] = []
    stderr_chunks: list[str | bytes] = []
    readers = _start_pipe_readers(process, stdout_chunks, stderr_chunks)

    def finish_output() -> tuple[str, str]:
        _finish_pipe_readers(process, readers)
        return _chunks_to_text(stdout_chunks), _chunks_to_text(stderr_chunks)

    def timeout_result(error: str = "SENDER_TIMEOUT") -> dict[str, Any]:
        _terminate_sender(process)
        finish_output()
        return {
            "status": "timeout",
            "error": error,
            "timing": {"total": round(clock() - started_at, 3)},
        }

    deadline = started_at + timeout_seconds
    next_parent_check = started_at
    while True:
        now = clock()
        remaining = deadline - now
        if remaining <= 0:
            return timeout_result()
        if parent_exit_code is not None and now >= next_parent_check:
            try:
                exit_code = parent_exit_code(remaining)
            except (ParentInspectionTimeout, subprocess.TimeoutExpired) as exc:
                if clock() >= deadline:
                    return timeout_result()
                _terminate_sender(process)
                finish_output()
                return {
                    "status": "parent_check_timeout",
                    "error": str(exc) or "PARENT_INSPECT_TIMEOUT",
                    "timing": {"total": round(clock() - started_at, 3)},
                }
            except ParentInspectionError as exc:
                _terminate_sender(process)
                finish_output()
                return {
                    "status": "parent_check_error",
                    "error": str(exc) or "PARENT_INSPECT_FAILED",
                    "timing": {"total": round(clock() - started_at, 3)},
                }
            if clock() >= deadline:
                return timeout_result()
            if exit_code is not None:
                _terminate_sender(process)
                finish_output()
                return {
                    "status": "parent_stopped",
                    "parent_exit_code": exit_code,
                    "error": "PARENT_WORKER_EXITED_DURING_SENDER",
                    "timing": {"total": round(clock() - started_at, 3)},
                }
            next_parent_check = clock() + 0.25
        return_code = process.poll()
        if return_code is not None:
            stdout, stderr = finish_output()
            if clock() >= deadline:
                return timeout_result()
            payload = _decode_sender_result(stdout)
            if payload is not None:
                payload.setdefault("timing", {})["exec"] = round(clock() - started_at, 3)
                return payload
            stderr_text = str(stderr or "").lower()
            parent_unavailable = any(
                marker in stderr_text
                for marker in ("no such container", "is not running", "cannot exec in a stopped container")
            )
            return {
                "status": "parent_container_missing" if parent_unavailable else "container_exec_failed",
                "return_code": return_code,
                "error": (
                    "PARENT_CONTAINER_MISSING"
                    if parent_unavailable
                    else str(stderr or "SENDER_OUTPUT_INVALID").strip()
                ),
                "timing": {"total": round(clock() - started_at, 3)},
            }
        remaining = deadline - clock()
        if remaining <= 0:
            return timeout_result()
        sleeper(min(0.05, remaining))


def _start_pipe_readers(
    process: Any,
    stdout_chunks: list[str | bytes],
    stderr_chunks: list[str | bytes],
) -> list[threading.Thread]:
    readers = []
    for stream, chunks in (
        (getattr(process, "stdout", None), stdout_chunks),
        (getattr(process, "stderr", None), stderr_chunks),
    ):
        if not callable(getattr(stream, "read", None)):
            continue
        reader = threading.Thread(target=_read_pipe, args=(stream, chunks), daemon=True)
        reader.start()
        readers.append(reader)
    return readers


def _read_pipe(stream: Any, chunks: list[str | bytes]) -> None:
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            chunks.append(chunk)
    except (OSError, ValueError):
        return


def _finish_pipe_readers(process: Any, readers: list[threading.Thread]) -> None:
    for reader in readers:
        reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        for name in ("stdout", "stderr"):
            stream = getattr(process, name, None)
            close = getattr(stream, "close", None)
            if callable(close):
                close()
        for reader in readers:
            reader.join(timeout=1)
    for name in ("stdout", "stderr"):
        stream = getattr(process, name, None)
        close = getattr(stream, "close", None)
        if callable(close):
            close()


def _chunks_to_text(chunks: list[str | bytes]) -> str:
    if not chunks:
        return ""
    if isinstance(chunks[0], bytes):
        return b"".join(
            chunk if isinstance(chunk, bytes) else str(chunk).encode() for chunk in chunks
        ).decode("utf-8", errors="replace")
    return "".join(str(chunk) for chunk in chunks)


def _decode_sender_result(stdout: str | bytes | None) -> dict[str, Any] | None:
    text = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else str(stdout or "")
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            return value
    return None


def _terminate_sender(process: Any) -> None:
    terminate = getattr(process, "terminate", None)
    if callable(terminate):
        terminate()
    wait = getattr(process, "wait", None)
    if callable(wait):
        try:
            wait(timeout=1)
        except (subprocess.TimeoutExpired, TypeError, OSError):
            kill = getattr(process, "kill", None)
            if callable(kill):
                try:
                    kill()
                except OSError:
                    pass
            try:
                wait(timeout=1)
            except (subprocess.TimeoutExpired, TypeError, OSError):
                pass


def send_and_wait(
    config_path: Path,
    *,
    request_id: str,
    run_id: str,
    timeout_seconds: float,
    expected: Mapping[str, Any],
    session_factory: Callable[[], Any] = requests.Session,
    request_dir: Path = Path(REQUESTS_DIR),
    zend_dir: Path = Path(ZEND_ARTIFACTS_DIR),
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    started_at = clock()
    deadline = started_at + timeout_seconds
    try:
        config = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
        prepared = prepare_request_from_config(config, request_id=request_id, run_id=run_id)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        finished_at = clock()
        return _result(
            "prepare_error", run_id, request_id, started_at, started_at, finished_at,
            None, finished_at, None, finished_at, None, str(exc),
        )
    http_started_at = clock()
    response_status = None
    http_error = ""
    try:
        remaining = deadline - clock()
        if remaining <= 0:
            finished_at = clock()
            return _result(
                "timeout", run_id, request_id, started_at, http_started_at, finished_at,
                None, finished_at, None, finished_at, None, "HTTP_BUDGET_EXPIRED",
            )
        with session_factory() as session:
            response = session.send(prepared, timeout=remaining, allow_redirects=False)
            response_status = getattr(response, "status_code", None)
    except Exception as exc:
        http_error = str(exc)
    http_finished_at = clock()
    if http_error:
        return _result(
            "http_error", run_id, request_id, started_at, http_started_at, http_finished_at,
            None, http_finished_at, None, http_finished_at, response_status, http_error,
        )

    pair = None
    wait_started_at = clock()
    while clock() < deadline:
        pair = read_correlated_artifact_pair(
            request_dir,
            zend_dir,
            request_id=request_id,
            run_id=run_id,
            expected=expected,
        )
        if pair is not None:
            break
        remaining = deadline - clock()
        if remaining > 0:
            sleeper(min(0.05, remaining))
    wait_finished_at = clock()
    if pair is None:
        return _result(
            "timeout", run_id, request_id, started_at, http_started_at, http_finished_at,
            wait_started_at, wait_finished_at, None, wait_finished_at, response_status,
            "CORRELATED_ARTIFACT_TIMEOUT",
        )

    verify_started_at = clock()
    candidate = {
        "hook_name": str(expected.get("hook_name") or ""),
        "callback_id": str(expected.get("callback_id") or ""),
    }
    validation = evaluate_artifact_payloads(candidate, [pair["request"]])
    finished_at = clock()
    result = _result(
        "artifacts_collected",
        run_id,
        request_id,
        started_at,
        http_started_at,
        http_finished_at,
        wait_started_at,
        wait_finished_at,
        verify_started_at,
        finished_at,
        response_status,
        "",
    )
    result.update({
        "request_name": pair["request_name"],
        "request": pair["request"],
        "zend_name": pair["zend_name"],
        "zend": pair["zend"],
        "callback_reached": bool(validation["expected_callback_reached"]),
        "validation_status": validation["status"],
        "validation_reason": validation["reason"],
    })
    result["status"] = "callback_reached" if result["callback_reached"] else "request_completed"
    return result


def _result(
    status,
    run_id,
    request_id,
    started_at,
    http_started_at,
    http_finished_at,
    wait_started_at,
    wait_finished_at,
    verify_started_at,
    finished_at,
    response_status,
    error,
):
    return {
        "status": status,
        "run_id": run_id,
        "request_id": request_id,
        "response_status": response_status,
        "error": error,
        "timing": {
            "send_http": round(http_finished_at - http_started_at, 3),
            "wait_artifacts": round(
                wait_finished_at - wait_started_at, 3
            ) if wait_started_at is not None else 0.0,
            "verify": round(
                finished_at - verify_started_at, 3
            ) if verify_started_at is not None else 0.0,
            "total": round(finished_at - started_at, 3),
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Send one online-linked request in an existing fuzzer container.")
    parser.add_argument("--config-path", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--plugin-slug", required=True)
    parser.add_argument("--hook-name", required=True)
    parser.add_argument("--callback-id", required=True)
    parser.add_argument("--method", required=True)
    parser.add_argument("--auth-context", required=True)
    args = parser.parse_args(argv)
    try:
        result = send_and_wait(
            Path(args.config_path),
            request_id=args.request_id,
            run_id=args.run_id,
            timeout_seconds=args.timeout_seconds,
            expected={
                "plugin_slug": args.plugin_slug,
                "hook_name": args.hook_name,
                "callback_id": args.callback_id,
                "method": args.method,
                "auth_context": args.auth_context,
            },
        )
    except Exception as exc:
        result = {"status": "sender_error", "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
