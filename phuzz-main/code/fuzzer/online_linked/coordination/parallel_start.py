"""Keep a receipt for a parallel Compose launch even if its coordinator exits."""

import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from online_linked.coordination.launch_guard import launch_ended, open_guard
except ImportError:  # run by path as the detached launcher
    from launch_guard import launch_ended, open_guard

# The launcher kills Compose after this. The guard, not this timeout, proves the launch ended.
LAUNCH_TIMEOUT_SECONDS = 120.0
# Written into `.started` by launchers that hold a launch_guard; 39ec0808 launchers left it empty.
GUARDED_CLAIM = "launch_guard_v1"


def _present(path: Path) -> bool:
    try:
        path.stat()
    except FileNotFoundError:
        return False
    return True


def settle_parallel_start(receipt: Path) -> bool:
    # Publish cancellation before checking whether the launcher has claimed the attempt.
    receipt.with_suffix(".cancelled").touch()
    started = receipt.with_suffix(".started")
    if not _present(started) or _present(receipt):
        return True
    if started.read_text(encoding="utf-8", errors="replace") != GUARDED_CLAIM:
        # A launcher without an OS guard (or one still writing its claim): absence proves nothing.
        raise ValueError("PARALLEL_START_LEGACY_UNCONFIRMED")
    # No receipt: the launcher is still running, or died; only a dead process tree is settled.
    return launch_ended(receipt)


def clear_parallel_start(receipt: Path) -> None:
    """Drop a settled launch's files; call only once its container removal is confirmed."""
    started = receipt.with_suffix(".started")
    # `.started` alone does not mean the launcher has read `.cancelled` yet. Keep the marker until a
    # receipt (written after that check) or a dead guarded tree proves the launcher can no longer act.
    if not _present(receipt):
        if not _present(started) or started.read_text(encoding="utf-8", errors="replace") != GUARDED_CLAIM:
            return
        if not launch_ended(receipt):
            return
    for suffix in (".json", ".started", ".cancelled", ".stderr", ".lock"):
        receipt.with_suffix(suffix).unlink(missing_ok=True)


def _claim(receipt: Path) -> bool:
    with receipt.with_suffix(".started").open("x", encoding="utf-8") as claim:
        claim.write(GUARDED_CLAIM)
    return not _present(receipt.with_suffix(".cancelled"))


def _write_receipt(receipt: Path, returncode: int, stderr: str) -> None:
    receipt.write_text(json.dumps({"returncode": returncode, "stderr": stderr}), encoding="utf-8")


def _run(receipt, command, run_command, **kwargs):
    """In-process launch for injected runners (tests); there is no process tree to guard."""
    if not _claim(receipt):
        result = subprocess.CompletedProcess(command, 1, "", "PARALLEL_START_CANCELLED")
    else:
        try:
            result = run_command(command, check=False, capture_output=True, text=True, **kwargs)
        except FileNotFoundError as exc:
            result = subprocess.CompletedProcess(command, 1, "", str(exc))
        except subprocess.TimeoutExpired:
            result = subprocess.CompletedProcess(command, -1, "", "PARALLEL_START_TIMEOUT")
    if 0 <= result.returncode < 128:
        _write_receipt(receipt, result.returncode, result.stderr)
    return result


def _launch(receipt: Path, command: list[str], timeout: float) -> None:
    """Detached launcher: a receipt is written only once the guard proves Compose's tree is gone."""
    try:
        guard = open_guard(receipt)
    except OSError as exc:
        # Nothing was claimed or started, so this receipt is final.
        _write_receipt(receipt, 1, f"PARALLEL_START_GUARD_FAILED: {exc}")
        return
    try:
        if not _claim(receipt):
            _write_receipt(receipt, 1, "PARALLEL_START_CANCELLED")
            return
        stderr_path = receipt.with_suffix(".stderr")
        # A file, not a pipe: a straggler holding the pipe open must not block the launcher.
        with stderr_path.open("w", encoding="utf-8") as stderr_file:
            try:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=stderr_file, **guard.spawn_kwargs())
            except OSError as exc:
                _write_receipt(receipt, 1, str(exc))
                return
        guard.spawned()
        try:
            returncode = process.wait(timeout=timeout)
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            returncode, stderr = -1, "PARALLEL_START_TIMEOUT"
        if guard.tree_ended(process):
            _write_receipt(receipt, returncode, stderr)
        # Otherwise exit without a receipt: settlement then waits on the guard itself.
    finally:
        guard.close()


def run_parallel_start(receipt, command, *, timeout, run_command, launch_timeout=LAUNCH_TIMEOUT_SECONDS):
    if run_command is not subprocess.run:
        return _run(receipt, command, run_command, timeout=timeout)
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), str(receipt), str(launch_timeout), *command],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    # A coordinator timeout must leave the launcher alive to record Compose's outcome.
    process.wait(timeout=timeout)
    try:
        payload = json.loads(receipt.read_text(encoding="utf-8"))
    except FileNotFoundError:
        # The launcher could not prove the tree ended; settle_parallel_start waits for it.
        return subprocess.CompletedProcess(command, 1, "", "PARALLEL_START_UNCONFIRMED")
    return subprocess.CompletedProcess(command, **payload)


if __name__ == "__main__":
    _launch(Path(sys.argv[1]), sys.argv[3:], float(sys.argv[2]))
