from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_fd = os.open(
        path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    fd = None
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=str(path.parent))
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        fd = None
        os.replace(temporary, path)
        temporary = None
        # The file fsync above does not make the directory entry durable.
        # ACK-before-pending-delete and credential reset rely on this ordering.
        os.fsync(directory_fd)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temporary is not None:
            try:
                os.unlink(temporary)
                os.fsync(directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory_fd)


def atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value) + b"\n", mode)


def read_json(path: Path, max_bytes: int = 128 * 1024) -> Dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("JSON file exceeds size limit")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory_fd = os.open(
        path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        # Deletion is not durable until the parent directory is synced.
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def unlink_atomic_material(paths: Iterable[Path]) -> None:
    """Remove canonical files and only their mkstemp crash remnants.

    ``atomic_write_bytes`` uses ``.<name>.<random>`` in the same directory.
    A power loss can leave one of those files behind, so a credential reset
    must remove the exact prefixes as well as the canonical names.  Prefixes
    are derived from an explicit allowlist; unrelated dotfiles are untouched.
    """
    canonical = tuple(paths)
    for path in canonical:
        safe_unlink(path)
    by_parent: Dict[Path, set[str]] = {}
    for path in canonical:
        by_parent.setdefault(path.parent, set()).add(f".{path.name}.")
    for parent, prefixes in by_parent.items():
        try:
            candidates = tuple(parent.iterdir())
        except FileNotFoundError:
            continue
        for candidate in candidates:
            if any(candidate.name.startswith(prefix) for prefix in prefixes):
                safe_unlink(candidate)


@dataclass(frozen=True)
class Paths:
    config_dir: Path
    private_dir: Path
    runtime_dir: Path
    ipc_socket: Path

    @classmethod
    def from_env(cls) -> "Paths":
        config = Path(os.environ.get("SUNNY_CONFIG_DIR", "/data/config"))
        private = Path(os.environ.get("SUNNY_PRIVATE_DIR", "/data/private"))
        runtime = Path(os.environ.get("SUNNY_RUNTIME_DIR", "/data/runtime"))
        socket = Path(os.environ.get("SUNNY_IPC_SOCKET", str(runtime / "control.sock")))
        return cls(config, private, runtime, socket)

    def ensure(self) -> None:
        for directory in (self.config_dir, self.private_dir, self.runtime_dir):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)

    @property
    def settings(self) -> Path:
        return self.config_dir / "settings.json"

    @property
    def known_hosts(self) -> Path:
        return self.config_dir / "known_hosts"

    @property
    def pending(self) -> Path:
        return self.config_dir / "pending-upload.json"

    @property
    def acknowledged(self) -> Path:
        return self.config_dir / "acknowledged.json"

    @property
    def monitor_pending(self) -> Path:
        return self.config_dir / "pending-monitor-upload.json"

    @property
    def watch_state(self) -> Path:
        return self.config_dir / "watch-state.json"

    @property
    def revocation_warning(self) -> Path:
        return self.config_dir / "revocation-warning.json"

    @property
    def telegram_session_outstanding(self) -> Path:
        return self.config_dir / "telegram-session-outstanding.json"

    @property
    def credentials(self) -> Path:
        return self.private_dir / "credentials.json"

    @property
    def telegram_session(self) -> Path:
        return self.private_dir / "telegram.session.txt"

    @property
    def setup_state(self) -> Path:
        return self.private_dir / "setup-state.json"

    @property
    def dialog_candidates(self) -> Path:
        return self.private_dir / "dialog-candidates.json"

    @property
    def chat_locked(self) -> Path:
        return self.private_dir / "chat-locked"

    @property
    def upload_key(self) -> Path:
        return self.private_dir / "upload-ed25519"

    @property
    def upload_public_key(self) -> Path:
        return self.private_dir / "upload-ed25519.pub"

    @property
    def vpn_dir(self) -> Path:
        return self.private_dir / "mihomo"

    @property
    def vpn_active_node(self) -> Path:
        return self.vpn_dir / "active-node.json"

    @property
    def status(self) -> Path:
        return self.runtime_dir / "status.json"

    @property
    def heartbeat(self) -> Path:
        return self.runtime_dir / "heartbeat"

    def reset_files(self) -> tuple[Path, ...]:
        return (
            self.settings,
            self.known_hosts,
            self.pending,
            self.acknowledged,
            self.monitor_pending,
            self.watch_state,
            self.credentials,
            self.telegram_session,
            self.setup_state,
            self.dialog_candidates,
            self.chat_locked,
            self.upload_key,
            self.upload_public_key,
            self.vpn_active_node,
        )

    def remove_empty_vpn_dir(self) -> None:
        """Remove only the known VPN directory, and only when it is empty."""
        try:
            self.vpn_dir.rmdir()
        except (FileNotFoundError, OSError):
            return
