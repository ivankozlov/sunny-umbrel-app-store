"""Short-lived OpenSSH input files, confined to a role's private tmpfs."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


def require_private_tmpfs(directory: Path) -> None:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("private scratch ownership is invalid")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("private scratch requires Linux tmpfs")
    # fstatfs' first native long is f_type; use a larger aligned buffer than
    # either Linux struct layout, without assuming its architecture-specific tail.
    values = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if libc.fstatfs(fd, ctypes.byref(values)) != 0 or values[0] != 0x01021994:
            raise RuntimeError("private scratch is not tmpfs")
    finally:
        os.close(fd)


@contextmanager
def secret_files(directory: Path, values: dict[str, bytes]):
    from .memory_guard import verify_native_parent
    verify_native_parent()
    require_private_tmpfs(directory)
    work = Path(tempfile.mkdtemp(prefix="secret-", dir=directory))
    try:
        files = {}
        for name, data in values.items():
            if name not in {"identity", "known_hosts"} or not isinstance(data, bytes):
                raise ValueError("secret scratch input is invalid")
            path = work / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            files[name] = path
        yield files
    finally:
        # Exact names only; an unexpected file causes refusal, never recursive deletion.
        for name in ("identity", "known_hosts"):
            (work / name).unlink(missing_ok=True)
        work.rmdir()


def clean_secret_scratch(directory: Path) -> None:
    require_private_tmpfs(directory)
    for child in directory.iterdir():
        allowed = ({"identity", "known_hosts"} if child.name.startswith("secret-")
                   else {"config.yaml", "cache.db", "cache.db-shm", "cache.db-wal"}
                   if child.name.startswith("sunny-mihomo-") else None)
        if allowed is None:
            continue
        if child.is_symlink() or not child.is_dir() or child.stat().st_uid != os.getuid():
            raise RuntimeError("private scratch remnant is invalid")
        entries = tuple(child.iterdir())
        if any(p.name not in allowed or p.is_symlink() or not p.is_file() or p.stat().st_uid != os.getuid()
               for p in entries):
            raise RuntimeError("private scratch remnant is invalid")
        for entry in entries:
            entry.unlink()
        child.rmdir()


def generate_encrypted_ed25519(paths, private_name: str, public_name: str,
                               comment: str) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    from .storage import atomic_write_bytes
    private = Ed25519PrivateKey.generate()
    secret = private.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    public = private.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    public += b" " + comment.encode("ascii")
    blob = base64.b64decode(public.split()[1], validate=True)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    atomic_write_bytes(getattr(paths, private_name), secret)
    atomic_write_bytes(getattr(paths, public_name), public + b"\n")
    return public.decode("ascii"), fingerprint


def validate_encrypted_keypair(paths, private_name: str, public_name: str) -> None:
    from cryptography.hazmat.primitives.serialization import (
        load_ssh_private_key, Encoding, PublicFormat,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = load_ssh_private_key(getattr(paths, private_name).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("vault SSH key algorithm is invalid")
    expected = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    fields = getattr(paths, public_name).read_bytes().strip().split()
    if len(fields) < 2 or b" ".join(fields[:2]) != expected:
        raise ValueError("vault SSH keypair mismatch")
