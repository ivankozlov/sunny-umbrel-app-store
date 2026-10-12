"""Explicit, crash-resumable conversion; inventory is read-only by default.

Guardian calls apply only after the console-bootstrap/WebAuthn ceremony, and
resume only after verification using the candidate's canonical passkeys.
No runtime path falls back to plaintext files.
"""
from __future__ import annotations

import base64
import os
import stat
import uuid

from .storage import atomic_write_json, read_json, safe_unlink, unlink_atomic_material
from .vault_storage import RECORD_NAMES


MIGRATION_SCHEMA = "sunny.personal-chats.security-migration.v1"
MANIFEST_SCHEMA = "sunny.personal-chats.vault-manifest.v1"


def legacy_inventory(paths):
    result = []
    for name, record in RECORD_NAMES.items():
        path = getattr(paths, name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > 512 * 1024):
            raise RuntimeError("legacy artifact ownership or type is invalid")
        result.append({"record": record, "size": info.st_size,
                       "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid})
    return result


def write_manifest(paths, vault):
    snapshot = vault.snapshot
    # Browser hints only. Every signature is verified again against decrypted
    # canonical records; changing this public file grants no authorization.
    atomic_write_json(paths.private_dir / "vault-manifest.json", {
        "schema": MANIFEST_SCHEMA, "vault_id": vault.vault_id,
        "security_epoch": snapshot["security_epoch"],
        "policy_revision": snapshot["policy_revision"],
        "passkeys": snapshot["passkeys"],
    })


class VaultMigration:
    def __init__(self, paths, vault, *, barrier=lambda _: None, validator=lambda: None):
        self.paths, self.vault, self.barrier = paths, vault, barrier
        self.marker = paths.config_dir / "security-migration.json"
        self.validator = validator

    def inventory(self):
        return {"legacy": legacy_inventory(self.paths),
                "vault_exists": self.vault.path.exists(), "migration_pending": self.marker.exists()}

    def _mark(self, phase):
        atomic_write_json(self.marker, {"schema": MIGRATION_SCHEMA, "phase": phase})
        self.barrier(phase)

    def apply(self, passphrase, passkeys):
        if self.vault.path.exists():
            raise RuntimeError("existing vault requires authenticated migration resume")
        inventory = legacy_inventory(self.paths)
        self._mark("started")
        records = {}
        for name, record in RECORD_NAMES.items():
            path = getattr(self.paths, name)
            if any(row["record"] == record for row in inventory):
                with path.open("rb") as stream:
                    raw = stream.read(512 * 1024 + 1)
                if len(raw) > 512 * 1024:
                    raise RuntimeError("legacy artifact exceeds migration limit")
                records[record] = base64.b64encode(raw).decode("ascii")
        source = str(uuid.uuid4())
        if "settings.json" in records:
            settings = read_json(self.paths.settings)
            source = settings.get("source_id") or source
        snapshot = {"source_id": source, "security_epoch": 0, "policy_revision": 0,
                    "records": records, "passkeys": passkeys}
        try:
            self.vault.initialize(passphrase, snapshot)
            write_manifest(self.paths, self.vault)
            self.barrier("encrypted")
            # Prove that the committed encrypted snapshot is readable, without
            # retaining a second writer or using the in-memory snapshot as proof.
            expected = self.vault.snapshot
            self.vault.close()
            if self.vault.unlock(passphrase) != expected:
                raise RuntimeError("migration verification failed")
            self._finish()
        except BaseException:
            self.vault.close()
            raise

    def resume(self):
        # Caller has unlocked and verified the passkey against this vault.
        if self.marker.exists():
            value = read_json(self.marker, max_bytes=1024)
            if (set(value) != {"schema", "phase"} or value["schema"] != MIGRATION_SCHEMA
                    or value["phase"] not in {"started", "committed", "cleaned"}):
                raise RuntimeError("migration marker is invalid")
        self._finish()

    def _finish(self):
        self.validator()
        write_manifest(self.paths, self.vault)
        self._mark("committed")
        unlink_atomic_material(tuple(getattr(self.paths, name) for name in RECORD_NAMES))
        self.paths.remove_empty_vpn_dir()
        self.barrier("plaintext_removed")
        if legacy_inventory(self.paths):
            raise RuntimeError("legacy artifacts remain")
        self._mark("cleaned")
        safe_unlink(self.marker)
        self.barrier("ready")
