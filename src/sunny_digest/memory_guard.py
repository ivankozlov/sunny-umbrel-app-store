"""Small, fail-closed process-memory protections for the guardian.

This protects the process boundary and one DEK-sized buffer.  It deliberately
does not claim that Python objects or Argon2's workspace are locked in RAM.
"""
from __future__ import annotations

import ctypes
import mmap
import os
import platform as _platform
import resource
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


class MemoryGuardError(RuntimeError):
    """The host cannot provide a mandatory guardian memory protection."""


PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3
MADV_DONTDUMP = 16


@dataclass(frozen=True)
class MemoryDiagnostics:
    core_soft: int
    core_hard: int
    dumpable: Optional[bool]
    swap_limited: Optional[bool]


def _prctl(option: int, arg: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(option, arg, 0, 0, 0)
    if result == -1:
        raise OSError(ctypes.get_errno(), "prctl failed")
    return result


def _cgroup_path(root: Path) -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            return root / parts[2].lstrip("/")
    raise MemoryGuardError("cgroup v2 path is unavailable")


def _cgroup_v1_path(root: Path) -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and "memory" in parts[1].split(","):
            return root / parts[2].lstrip("/")
    raise MemoryGuardError("cgroup v1 memory path is unavailable")


def _read_limit(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise MemoryGuardError("cgroup swap limit is unavailable") from exc


def _verify_swap_limit(root: Path, path: Optional[Path] = None) -> bool:
    """Prove a cgroup swap ban; unknown cgroup layouts fail closed."""
    if (root / "cgroup.controllers").exists():
        target = path or _cgroup_path(root)
        if _read_limit(target / "memory.swap.max") != "0":
            raise MemoryGuardError("cgroup v2 permits swap")
        return True
    # cgroup v1 can prove no swap only where memsw is exactly the RAM limit.
    target = path or _cgroup_v1_path(root)
    memory = _read_limit(target / "memory.limit_in_bytes")
    memsw = _read_limit(target / "memory.memsw.limit_in_bytes")
    # v1 represents "unlimited" by a very large page-rounded integer. Equal
    # unlimited values do not prove a ban on swap.
    if (not memory.isdecimal() or not 0 < int(memory) < 2**60
            or memsw != memory):
        raise MemoryGuardError("cgroup v1 cannot prove a zero swap allowance")
    return True


def verify_process(
    *,
    system: Optional[str] = None,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    cgroup_path: Optional[Path] = None,
    prctl: Callable[[int, int], int] = _prctl,
) -> MemoryDiagnostics:
    """Verify protections already requested by :func:`protect_process`."""
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    if soft != 0 or hard != 0:
        raise MemoryGuardError("core dump limit is not zero")
    current_system = system or _platform.system()
    if current_system != "Linux":
        raise MemoryGuardError("guardian memory protections require Linux")
    try:
        dumpable = prctl(PR_GET_DUMPABLE, 0)
    except OSError as exc:
        raise MemoryGuardError("cannot verify process dumpability") from exc
    if dumpable != 0:
        raise MemoryGuardError("process remains dumpable")
    return MemoryDiagnostics(0, 0, False, _verify_swap_limit(cgroup_root, cgroup_path))


def protect_process(
    *,
    system: Optional[str] = None,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    cgroup_path: Optional[Path] = None,
    prctl: Callable[[int, int], int] = _prctl,
) -> MemoryDiagnostics:
    """Disable core dumps, disable Linux dumpability, then verify cgroup swap."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as exc:
        raise MemoryGuardError("cannot disable core dumps") from exc
    current_system = system or _platform.system()
    if current_system != "Linux":
        raise MemoryGuardError("guardian memory protections require Linux")
    try:
        prctl(PR_SET_DUMPABLE, 0)
    except OSError as exc:
        raise MemoryGuardError("cannot disable process dumpability") from exc
    return verify_process(
        system=current_system, cgroup_root=cgroup_root, cgroup_path=cgroup_path, prctl=prctl)


class LockedBuffer:
    """A bounded mmap buffer whose page is mlock'ed and marked DONTDUMP on Linux."""

    def __init__(self, value: bytes, *, require_lock: bool = True) -> None:
        if not isinstance(value, bytes) or not value or len(value) > mmap.PAGESIZE:
            raise ValueError("LockedBuffer requires 1..PAGE_SIZE bytes")
        self._size = len(value)
        self._mapping = mmap.mmap(-1, mmap.PAGESIZE, access=mmap.ACCESS_WRITE)
        self._mapping[:self._size] = value
        self._closed = False
        if _platform.system() == "Linux":
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.mlock(ctypes.c_void_p(address), mmap.PAGESIZE) != 0:
                self.close()
                if require_lock:
                    raise MemoryGuardError("mlock failed")
            elif libc.madvise(ctypes.c_void_p(address), mmap.PAGESIZE, MADV_DONTDUMP) != 0:
                self.close()
                if require_lock:
                    raise MemoryGuardError("MADV_DONTDUMP failed")
        elif require_lock:
            self.close()
            raise MemoryGuardError("LockedBuffer requires Linux")

    def read(self) -> bytes:
        if self._closed:
            raise MemoryGuardError("locked buffer is closed")
        return self._mapping[:self._size]

    def close(self) -> None:
        if self._closed:
            return
        self._mapping[:] = b"\0" * mmap.PAGESIZE
        if _platform.system() == "Linux":
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
            ctypes.CDLL(None, use_errno=True).munlock(ctypes.c_void_p(address), mmap.PAGESIZE)
        self._mapping.close()
        self._closed = True


def verify_native_parent() -> None:
    """exec resets dumpability; native children require a file core handler.

    Core size zero is inherited across exec, but Linux ignores it for piped
    handlers. Refuse that host configuration rather than claiming PR_SET_DUMPABLE
    survives exec into OpenSSH or the statically linked Mihomo binary.
    """
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise MemoryGuardError("native child core limits are not zero")
    pattern = Path("/proc/sys/kernel/core_pattern").read_text(encoding="ascii").strip()
    if not pattern or pattern.startswith("|"):
        raise MemoryGuardError("native child core handler is not supported")
    verify_process()


def verify_native_child(pid: int) -> None:
    limits = Path(f"/proc/{pid}/limits").read_text(encoding="ascii")
    row = next((line.split() for line in limits.splitlines()
                if line.startswith("Max core file size")), None)
    if row is None or row[4:6] != ["0", "0"]:
        raise MemoryGuardError("native child did not inherit zero core limits")
