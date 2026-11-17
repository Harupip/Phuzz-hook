"""Prove that a parallel launch's whole process tree has ended.

A Compose launch is done only when no process it started can still create the
container. Elapsed time cannot prove that (sleep, a hung daemon, an orphaned
Compose plugin), so the launcher holds an OS-level guard instead:

- Windows: the launcher joins a named Job Object with KILL_ON_JOB_CLOSE. Every
  process Compose starts joins the job; when the launcher exits, Windows kills
  them all. The launch has ended once the job has no live process.
- POSIX: Compose runs in its own process group and inherits an flock'd file.
  The launch has ended once nothing holds the lock.

parallel_start only uses `open_guard` (launcher side) and `launch_ended`
(coordinator side); replacing this mechanism means replacing this module.
"""

import os
import time
from pathlib import Path

# Stragglers get this long to exit after Compose returns, before the launcher gives up on a receipt.
TREE_EXIT_WAIT_SECONDS = 5.0


def open_guard(receipt: Path):
    """Launcher side: take the guard before claiming the launch."""
    return _WindowsGuard(receipt) if os.name == "nt" else _PosixGuard(receipt)


def launch_ended(receipt: Path) -> bool:
    """Coordinator side: True only when no process of this launch is alive."""
    return _windows_job_ended(receipt) if os.name == "nt" else _lock_free(_lock_path(receipt))


def _wait(condition) -> bool:
    deadline = time.monotonic() + TREE_EXIT_WAIT_SECONDS
    while not condition():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)
    return True


# --- POSIX: process group + inherited flock -------------------------------------------------

def _lock_path(receipt: Path) -> Path:
    return receipt.with_suffix(".lock")


def _lock_free(path: Path) -> bool:
    import fcntl

    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)  # closing also releases a lock taken here
    return True


class _PosixGuard:
    def __init__(self, receipt: Path):
        import fcntl

        self._lock = _lock_path(receipt)
        self._fd = os.open(self._lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._fd, fcntl.LOCK_EX)

    def spawn_kwargs(self) -> dict:
        # Compose and its children share this lock until the last of them exits.
        return {"pass_fds": (self._fd,), "start_new_session": True}

    def spawned(self) -> None:
        os.close(self._fd)
        self._fd = None

    def tree_ended(self, process) -> bool:
        import signal

        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        # A child that left the group still holds the lock, so this stays False for it.
        return _wait(lambda: _lock_free(self._lock))

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


# --- Windows: named Job Object with KILL_ON_JOB_CLOSE ---------------------------------------

_JOB_OBJECT_QUERY = 0x0004
_JOB_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_BASIC_ACCOUNTING = 1
_EXTENDED_LIMIT = 9
_ERROR_FILE_NOT_FOUND = 2
_ERROR_ALREADY_EXISTS = 183


def _job_name(receipt: Path) -> str:
    return "Local\\hookphuzz-" + receipt.stem


def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD,
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32


def _job_structs():
    import ctypes
    from ctypes import wintypes

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimit), ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class Accounting(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    return ExtendedLimit, Accounting


def _active_processes(kernel32, job) -> int:
    import ctypes

    _, accounting_type = _job_structs()
    accounting = accounting_type()
    if not kernel32.QueryInformationJobObject(
            job, _BASIC_ACCOUNTING, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(accounting.ActiveProcesses)


def _windows_job_ended(receipt: Path) -> bool:
    import ctypes

    kernel32 = _kernel32()
    job = kernel32.OpenJobObjectW(_JOB_OBJECT_QUERY, False, _job_name(receipt))
    if not job:
        error = ctypes.get_last_error()
        if error == _ERROR_FILE_NOT_FOUND:
            return True  # the job is gone with its last process
        raise ctypes.WinError(error)
    try:
        return _active_processes(kernel32, job) == 0
    finally:
        kernel32.CloseHandle(job)


class _WindowsGuard:
    def __init__(self, receipt: Path):
        import ctypes

        kernel32 = _kernel32()
        job = kernel32.CreateJobObjectW(None, _job_name(receipt))
        error = ctypes.get_last_error()
        if not job:
            raise ctypes.WinError(error)
        if error == _ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(job)
            raise OSError(f"launch job already exists: {_job_name(receipt)}")
        extended_type, _ = _job_structs()
        limits = extended_type()
        limits.BasicLimitInformation.LimitFlags = _JOB_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, _EXTENDED_LIMIT, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        # Joining before spawning puts every Compose descendant in the job, with no start-up race.
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            raise ctypes.WinError(ctypes.get_last_error())
        self._kernel32 = kernel32
        self._job = job

    def spawn_kwargs(self) -> dict:
        return {}

    def spawned(self) -> None:
        pass

    def tree_ended(self, process) -> bool:
        # Only this launcher left. Stragglers are killed when it exits, and launch_ended sees that.
        return _wait(lambda: _active_processes(self._kernel32, self._job) == 1)

    def close(self) -> None:
        # Keep the handle until exit: closing it would kill this launcher with its job.
        pass
