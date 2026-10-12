"""Encrypted records behind the existing, receipt-tested state machine.

Only guardian constructs these paths. Secret records have deliberately no OS
path: passing one to ssh/open/os.replace fails rather than creating plaintext.
Config checkpoints retain their existing fsync and receipt ordering.
"""
from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any

from .storage import Paths


RECORD_NAMES = {
    "settings": "settings.json", "chat_display": "chat-display.json",
    "digest_style": "digest-style.json", "known_hosts": "known_hosts",
    "credentials": "credentials.json", "telegram_session": "telegram.session.txt",
    "setup_state": "setup-state.json", "dialog_candidates": "dialog-candidates.json",
    "chat_locked": "chat-locked", "upload_key": "upload-ed25519",
    "upload_public_key": "upload-ed25519.pub", "openrouter_key": "openrouter-ed25519",
    "openrouter_public_key": "openrouter-ed25519.pub",
    "vpn_active_node": "mihomo/active-node.json", "vpn_node_origin": "mihomo/node-origin.json",
}


class VaultRecord:
    def __init__(self, vault: Any, name: str):
        self.vault, self.name = vault, name

    def exists(self) -> bool:
        return self.name in self.vault.snapshot["records"]

    def read_bytes(self) -> bytes:
        try:
            return base64.b64decode(self.vault.snapshot["records"][self.name], validate=True)
        except KeyError:
            raise FileNotFoundError("encrypted record is absent") from None

    def read_text(self, encoding: str = "utf-8") -> str:
        return self.read_bytes().decode(encoding)

    def open(self, mode: str):
        if mode != "rb":
            raise ValueError("encrypted record only supports bounded binary reads")
        return io.BytesIO(self.read_bytes())

    def write(self, data: bytes) -> None:
        snapshot = self.vault.snapshot
        snapshot["records"][self.name] = base64.b64encode(data).decode("ascii")
        if self.name == "settings.json":
            settings = json.loads(data)
            if settings.get("source_id"):
                snapshot["source_id"] = settings["source_id"]
        self.vault.update(snapshot)

    def unlink(self) -> None:
        snapshot = self.vault.snapshot
        if self.name not in snapshot["records"]:
            raise FileNotFoundError("encrypted record is absent")
        del snapshot["records"][self.name]
        self.vault.update(snapshot)

    def __fspath__(self):
        raise TypeError("encrypted records have no filesystem path")


class VaultPaths:
    def __init__(self, persistent: Paths, vault: Any, scratch: Path):
        self.persistent, self.vault = persistent, vault
        self.private_dir = self.runtime_dir = scratch
        self.config_dir = persistent.config_dir
        self.ipc_socket = persistent.ipc_socket

    def __getattr__(self, name: str):
        if name in RECORD_NAMES:
            return VaultRecord(self.vault, RECORD_NAMES[name])
        return getattr(self.persistent, name)

    @property
    def status(self):
        return self.scratch / "status.json"

    @property
    def heartbeat(self):
        return self.scratch / "heartbeat"

    @property
    def scratch(self):
        return self.runtime_dir

    def ensure(self) -> None:
        # The host layout is prepared separately; clients never chmod it.
        if not self.config_dir.is_dir() or not self.persistent.private_dir.is_dir():
            raise RuntimeError("guardian data layout is missing")
        self.scratch.mkdir(mode=0o700, parents=True, exist_ok=True)

    def reset_files(self):
        encrypted = tuple(getattr(self, name) for name in RECORD_NAMES)
        persistent = tuple(path for path in self.persistent.reset_files()
                           if path not in {getattr(self.persistent, n) for n in RECORD_NAMES})
        return encrypted + persistent

    def remove_empty_vpn_dir(self) -> None:
        pass
