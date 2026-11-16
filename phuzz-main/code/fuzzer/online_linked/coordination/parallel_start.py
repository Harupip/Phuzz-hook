"""Keep a receipt for a parallel Compose launch even if its coordinator exits."""

import json
import os
import subprocess
import sys
from pathlib import Path


def _present(path: Path) -> bool:
    try:
        path.stat()
    except FileNotFoundError:
        return False
    return True


def settle_parallel_start(receipt: Path) -> bool:
    # Publish cancellation before checking whether the launcher has claimed the attempt.
    receipt.with_suffix(".cancelled").touch()
    return not _present(receipt.with_suffix(".started")) or _present(receipt)


def _run(receipt, command, run_command, **kwargs):
    receipt.with_suffix(".started").touch(exist_ok=False)
    if _present(receipt.with_suffix(".cancelled")):
        result = subprocess.CompletedProcess(command, 1, "", "PARALLEL_START_CANCELLED")
    else:
        try:
            result = run_command(command, check=False, capture_output=True, text=True, **kwargs)
        except FileNotFoundError as exc:
            result = subprocess.CompletedProcess(command, 1, "", str(exc))
    # A signal exit can leave the Compose plugin running after the CLI exits.
    if 0 <= result.returncode < 128:
        receipt.write_text(json.dumps({"returncode": result.returncode, "stderr": result.stderr}), encoding="utf-8")
    return result


def run_parallel_start(receipt, command, *, timeout, run_command):
    if run_command is not subprocess.run:
        return _run(receipt, command, run_command, timeout=timeout)
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), str(receipt), *command],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    # A coordinator timeout must leave the launcher alive to record Compose's outcome.
    process.wait(timeout=timeout)
    return subprocess.CompletedProcess(command, **json.loads(receipt.read_text(encoding="utf-8")))


if __name__ == "__main__":
    _run(Path(sys.argv[1]), sys.argv[2:], subprocess.run)
