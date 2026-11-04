from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    exit_code: int | None
    timed_out: bool
    log_too_big: bool
    rss_exceeded: bool
    duration_sec: float
    peak_rss_mb: float
    log_path: Path

    @property
    def ok(self) -> bool:
        return (
            self.exit_code == 0
            and not self.timed_out
            and not self.log_too_big
            and not self.rss_exceeded
        )


def _rss_mb(pid: int) -> float | None:
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) / 1024.0
        except OSError:
            return None
    elif sys.platform == "win32":
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            return None
        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return counters.WorkingSetSize / (1024.0 * 1024.0)
        finally:
            kernel32.CloseHandle(handle)
    return None


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def run_command(
    cmd: list[str],
    cwd: Path,
    log_path: Path,
    timeout: int,
    max_log_mb: float,
    max_rss_mb: int,
) -> RunResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    max_log_bytes = int(max_log_mb * 1024 * 1024)
    peak_rss = 0.0

    kwargs = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    with log_path.open("wb") as log:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                **kwargs,
            )
        except OSError as exc:
            log.write(f"failed to start command: {exc}\n".encode("utf-8", "replace"))
            log.flush()
            return RunResult(None, False, False, False, 0.0, 0.0, log_path)
        timed_out = False
        log_too_big = False
        rss_exceeded = False
        while proc.poll() is None:
            elapsed = time.monotonic() - started
            rss = _rss_mb(proc.pid)
            if rss:
                peak_rss = max(peak_rss, rss)
                if max_rss_mb and rss > max_rss_mb:
                    rss_exceeded = True
                    _kill_tree(proc)
                    break
            if timeout and elapsed > timeout:
                timed_out = True
                _kill_tree(proc)
                break
            try:
                if max_log_bytes and log_path.stat().st_size > max_log_bytes:
                    log_too_big = True
                    _kill_tree(proc)
                    break
            except OSError:
                pass
            time.sleep(0.1)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.wait(timeout=5)

    return RunResult(
        exit_code=proc.returncode,
        timed_out=timed_out,
        log_too_big=log_too_big,
        rss_exceeded=rss_exceeded,
        duration_sec=round(time.monotonic() - started, 2),
        peak_rss_mb=round(peak_rss, 1),
        log_path=log_path,
    )


def tail_text(path: Path, limit: int = 4000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", "replace")

