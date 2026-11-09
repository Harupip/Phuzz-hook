"""Pause/ACK files shared by the online-linked coordinator and one worker run.

The worker reads ``<root>/<key>/pause.json`` at request boundaries and answers
with ``paused.json``; the coordinator writes and releases the request through
``docker exec ... python -m core.online_handoff``. Stdlib only: the worker
container imports this module from the mounted fuzzer directory, and the
shared runtime must not import online_linked (test_online_linked_package).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Sequence

HANDOFF_ROOT = Path("/shared-tmpfs/online-linked-handoff")
PAUSE_FILE = "pause.json"
ACK_FILE = "paused.json"
_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_sleep = time.sleep
PRIORITY_ENERGY_MODES = ("seed-plus-bonus", "carryover")
DEFAULT_PRIORITY_ENERGY_MODE = PRIORITY_ENERGY_MODES[0]


def priority_energy_mode(value: Any) -> str:
    """Validate HOOKPHUZZ_PRIORITY_ENERGY_MODE; empty means the default."""
    mode = str(value or "").strip() or DEFAULT_PRIORITY_ENERGY_MODE
    if mode not in PRIORITY_ENERGY_MODES:
        raise ValueError(f"HOOKPHUZZ_PRIORITY_ENERGY_MODE must be one of {PRIORITY_ENERGY_MODES}, got {mode!r}")
    return mode


def priority_energy(mode: str, *, seed_energy: int, target_count: int, allocated_energy: int, attempts_used: int) -> int:
    """Attempts of the priority round: PHUZZ(seed) + one per target, or what the old round had left."""
    if priority_energy_mode(mode) == "carryover":
        return max(1, allocated_energy - attempts_used)
    return seed_energy + target_count


def config_hash(config: Any) -> str:
    """Same canonical hash as hook_energy.seed_generation.online_common.config_hash (stdlib only)."""
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def control_dir(key: str, root: Path | None = None) -> Path:
    if not _KEY.match(str(key)) or key in {".", ".."}:
        raise ValueError("HOOKPHUZZ_HANDOFF_KEY is invalid")
    return Path(root if root is not None else HANDOFF_ROOT) / key


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temp, path)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def request_pause(
    key: str, token: str, worker_run_id: str, *, request_id: str = "", root: Path | None = None,
) -> None:
    """``request_id`` names the request whose trace opened the branch; the ACK carries its energy."""
    request = {"token": token, "worker_run_id": worker_run_id}
    if request_id:
        request["request_id"] = request_id
    _write_atomic(control_dir(key, root) / PAUSE_FILE, request)


def read_ack(key: str, *, root: Path | None = None) -> dict[str, Any] | None:
    return _read(control_dir(key, root) / ACK_FILE)


def write_ack(key: str, ack: dict[str, Any], *, root: Path | None = None) -> None:
    _write_atomic(control_dir(key, root) / ACK_FILE, ack)


def release(key: str, token: str, *, root: Path | None = None) -> bool:
    """Remove the request (and its ACK) only when it still carries ``token``."""
    directory = control_dir(key, root)
    request = _read(directory / PAUSE_FILE)
    if request is None or request.get("token") != token:
        return False
    for name in (ACK_FILE, PAUSE_FILE):
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            pass
    return True


class PauseGate:
    """Worker side: block between requests while a matching pause is pending."""

    def __init__(
        self, key: str, worker_run_id: str, *, root: Path | None = None, poll_seconds: float = 0.2,
        energy_for: Callable[[str], int | None] | None = None,
    ) -> None:
        self.key = key
        self.worker_run_id = worker_run_id
        self.root = root
        self.poll_seconds = poll_seconds
        # PHUZZ energy of a request this worker sent and scored, by request ID.
        self.energy_for = energy_for
        control_dir(key, root)

    @classmethod
    def from_env(cls, energy_for: Callable[[str], int | None] | None = None) -> "PauseGate | None":
        key = os.environ.get("HOOKPHUZZ_HANDOFF_KEY", "")
        return cls(key, os.environ.get("HOOKPHUZZ_LEGACY_RUN_ID", ""), energy_for=energy_for) if key else None

    def _pending(self) -> dict[str, Any] | None:
        request = _read(control_dir(self.key, self.root) / PAUSE_FILE)
        if request is None or request.get("worker_run_id") != self.worker_run_id or not request.get("token"):
            return None
        return request

    def wait_if_paused(self, *, round_id: int, allocated_energy: int, attempts_used: int) -> bool:
        """Return True after a pause was acknowledged and then released."""
        paused = False
        request = self._pending()
        while request is not None:
            paused = True
            ack = {
                "token": request["token"], "worker_run_id": self.worker_run_id, "round_id": round_id,
                "allocated_energy": allocated_energy, "attempts_used": attempts_used,
            }
            request_id = str(request.get("request_id") or "")
            energy = self.energy_for(request_id) if request_id and self.energy_for else None
            if type(energy) is int:
                ack.update(request_id=request_id, seed_phuzz_energy=energy)
            write_ack(self.key, ack, root=self.root)
            while True:
                _sleep(self.poll_seconds)
                current = self._pending()
                if current is None or current.get("token") != request["token"]:
                    break
            request = current
        return paused


def main(argv: Sequence[str] | None = None, *, root: Path | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["request"] and len(args) in {4, 5}:
        request_pause(args[1], args[2], args[3], request_id=args[4] if len(args) == 5 else "", root=root)
        print(json.dumps({"requested": True}))
    elif args[:1] == ["ack"] and len(args) == 2:
        print(json.dumps(read_ack(args[1], root=root)))
    elif args[:1] == ["release"] and len(args) == 3:
        print(json.dumps({"released": release(args[1], args[2], root=root)}))
    else:
        print(json.dumps({"error": "usage: request KEY TOKEN RUN_ID [REQUEST_ID] | ack KEY | release KEY TOKEN"}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
