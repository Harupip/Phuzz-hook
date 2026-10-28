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

from filesystem_paths import filesystem_path
from hook_energy.seed_generation.generated_config_runner import (
    REQUESTS_DIR,
    ZEND_ARTIFACTS_DIR,
    read_correlated_artifact_pair,
)
from seed_generation.verification.seed_validator import (
    diagnostic_callback_reached, evaluate_artifact_payloads, has_callback_execution_evidence,
    http_diagnostics, response_details,
)
try:
    from fuzzer import _prepare_request
except ImportError:
    from fuzzer.fuzzer import _prepare_request


def _config_request_params(config):
    params = {bucket: {} for bucket in ('headers', 'cookies', 'query_params', 'body_params')}
    for bucket in params:
        section = config.get(bucket) or {}
        if not isinstance(section, dict):
            raise ValueError(f'Config parsing error: invalid {bucket}')
        for item in section.get('data', []):
            if not isinstance(item, dict) or not item.get('name'):
                raise ValueError(f'Config parsing error: invalid {bucket} data')
            if 'value' in item:
                value = item['value']
            elif item.get('seeds'):
                value = item['seeds'][0]
            else:
                raise ValueError(f"Neither seeds nor value for param {item['name']}")
            params[bucket][item['name']] = value
    return params


def prepare_request_from_config(config, *, request_id, run_id):
    params = _config_request_params(config)
    metadata = config.get('metadata') or {}
    methods = config.get('methods') or []
    http_method = str(metadata.get('resolved_method') or (methods[0] if methods else '')).upper()
    return _prepare_request(
        config,
        base_url=config['target'],
        http_method=http_method,
        fuzz_params={bucket: {} for bucket in params},
        fixed_params=params,
        request_id=str(request_id),
        run_id=str(run_id),
        force_run_id=True,
    )

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
        "python", "-m", "online_linked.probe_sender",
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
    if expected.get("allow_error_responses") is True:
        command.append("--allow-error-responses")
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
        config = json.loads(filesystem_path(Path(config_path)).read_text(encoding="utf-8-sig"))
        prepared = prepare_request_from_config(config, request_id=request_id, run_id=run_id)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        finished_at = clock()
        result = _result(
            "prepare_error", run_id, request_id, started_at, started_at, finished_at,
            None, finished_at, None, finished_at, None, str(exc),
        )
        result["diagnostics"] = http_diagnostics(transport_outcome="not_sent", transport_error=str(exc))
        result["diagnostics"]["config_validation"]["preparation"] = "failed"
        return result
    http_started_at = clock()
    response_status = None
    response_location = None
    response_info = {"status_code": None, "headers": {}, "body": None}
    transport_outcome = "not_observed"
    transport_error = None
    http_error = ""
    try:
        remaining = deadline - clock()
        if remaining <= 0:
            finished_at = clock()
            result = _result(
                "timeout", run_id, request_id, started_at, http_started_at, finished_at,
                None, finished_at, None, finished_at, None, "HTTP_BUDGET_EXPIRED",
            )
            result["diagnostics"] = http_diagnostics(transport_outcome="not_sent", transport_error="HTTP_BUDGET_EXPIRED")
            result["diagnostics"]["config_validation"]["preparation"] = "succeeded"
            return result
        with session_factory() as session:
            response = session.send(prepared, timeout=remaining, allow_redirects=False)
            response_status = getattr(response, "status_code", None)
            response_info = response_details(response)
            response_location = response_info["headers"].get("Location")
            transport_outcome = "response_received"
    except Exception as exc:
        http_error = str(exc)
        transport_error = http_error or type(exc).__name__
        transport_outcome = "timeout" if isinstance(exc, (TimeoutError, requests.Timeout)) else "error"
    http_finished_at = clock()
    pair = None
    correlation = {"outcome": "not_checked"}
    wait_started_at = clock()
    while clock() < deadline:
        pair = read_correlated_artifact_pair(
            request_dir,
            zend_dir,
            request_id=request_id,
            run_id=run_id,
            expected=expected,
            diagnostics=correlation,
        )
        if pair is not None:
            break
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleeper(min(0.05, remaining))
    wait_finished_at = clock()
    if pair is None:
        request_evidence = correlation.pop("request_evidence", None)
        artifact_response = request_evidence.get("response") if isinstance(request_evidence, Mapping) else None
        request_conflicts = [
            {"artifact": "request", "field": field, "expected": str(run_id).strip(),
             "actual": str(request_evidence[field]).strip()}
            for field in ("run_id", "legacy_run_id")
            if isinstance(request_evidence, Mapping) and request_evidence.get(field)
            and str(request_evidence[field]).strip() != str(run_id).strip()
        ]
        if request_conflicts:
            correlation["identity_conflicts"] = request_conflicts
        correlation["timed_out"] = wait_finished_at >= deadline
        result = _result(
            "http_error" if http_error else "timeout", run_id, request_id, started_at, http_started_at, http_finished_at,
            wait_started_at, wait_finished_at, None, wait_finished_at, response_status,
            http_error or "CORRELATED_ARTIFACT_TIMEOUT", response_location,
        )
        result["diagnostics"] = http_diagnostics(
            **response_info, target_url=str(getattr(prepared, "url", "") or ""),
            callback_reached=diagnostic_callback_reached(expected, request_evidence)
            if isinstance(request_evidence, Mapping) and not request_conflicts else None,
            transport_outcome=transport_outcome, transport_error=transport_error, correlation=correlation,
            artifact_status_code=artifact_response.get("status_code") if isinstance(artifact_response, Mapping) else None,
            php_errors=request_evidence.get("errors")
            if isinstance(request_evidence, Mapping) and not request_conflicts else None,
        )
        if request_evidence:
            result["diagnostics"]["callback"]["evidence_source"] = (
                "conflicting_request_identity" if request_conflicts else "request_artifact"
            )
        result["diagnostics"]["config_validation"]["preparation"] = "succeeded"
        return result

    verify_started_at = clock()
    candidate = {
        "hook_name": str(expected.get("hook_name") or ""),
        "callback_id": str(expected.get("callback_id") or ""),
    }
    validation = evaluate_artifact_payloads(candidate, [pair["request"]])
    coverage = pair["request"].get("hook_coverage")
    executed = coverage.get("executed_callbacks") if isinstance(coverage, Mapping) else None
    if isinstance(executed, list):
        executed = {str(index): entry for index, entry in enumerate(executed)}
    if candidate["hook_name"] and candidate["callback_id"] and isinstance(executed, Mapping):
        entries = [entry for key, entry in executed.items() if isinstance(entry, Mapping)
                   and candidate["callback_id"] in {str(key), str(entry.get("callback_id") or "")}]
        hooks = [{entry.get("hook_name"), entry.get("fired_hook")} for entry in entries
                 if entry.get("hook_name") or entry.get("fired_hook")]
        if hooks and all(candidate["hook_name"] not in names for names in hooks):
            validation.update(expected_callback_reached=False, status="not_observed",
                              reason="Expected callback executed on a different hook")
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
        http_error,
        response_location,
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
    request_response = pair["request"].get("response")
    request_identity_conflict = any(
        item.get("artifact") == "request" for item in correlation.get("identity_conflicts", [])
    )
    result["diagnostics"] = http_diagnostics(
        **response_info, target_url=str(getattr(prepared, "url", "") or ""),
        callback_reached=result["callback_reached"] if candidate["callback_id"] and not request_identity_conflict
        and has_callback_execution_evidence(pair["request"]) else None,
        transport_outcome=transport_outcome,
        transport_error=transport_error, correlation=correlation, validation_status=validation["status"],
        artifact_status_code=request_response.get("status_code") if isinstance(request_response, Mapping) else None,
        php_errors=pair["request"].get("errors") if not request_identity_conflict else None,
    )
    result["diagnostics"]["callback"]["evidence_source"] = (
        "conflicting_request_identity" if request_identity_conflict else "correlated_artifact_pair"
    )
    result["diagnostics"]["config_validation"]["preparation"] = "succeeded"
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
    response_location=None,
):
    return {
        "status": status,
        "run_id": run_id,
        "request_id": request_id,
        "response_status": response_status,
        "response_location": response_location,
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
    parser.add_argument("--allow-error-responses", action="store_true")
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
                "allow_error_responses": args.allow_error_responses,
            },
        )
    except Exception as exc:
        result = {"status": "sender_error", "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
