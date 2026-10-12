"""Authenticated, single-writer encrypted vault snapshots.

The whole snapshot is intentionally small.  A valid older whole-file copy is
not detected here; rollback detection belongs to the remote policy protocol.
"""
from __future__ import annotations

import base64
import copy
import fcntl
import json
import os
import secrets
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .memory_guard import LockedBuffer, MemoryGuardError, protect_process
from .storage import atomic_write_bytes, canonical_json_bytes


class VaultError(RuntimeError):
    """Stable public error that never includes secret values."""


class VaultLockedError(VaultError):
    pass


class VaultFormatError(VaultError):
    pass


class VaultAuthenticationError(VaultError):
    pass


SCHEMA = 1
PURPOSE = "sunny-personal-chats-vault"
KDF = {"name": "argon2id", "memory_kib": 65536, "iterations": 3, "lanes": 4, "length": 32}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_RECORD_BYTES = 512 * 1024
MAX_RECORDS = 64
RECORD_NAMES = frozenset({
    "settings.json", "chat-display.json", "digest-style.json", "known_hosts",
    "credentials.json", "telegram.session.txt", "setup-state.json",
    "dialog-candidates.json", "chat-locked", "upload-ed25519",
    "upload-ed25519.pub", "openrouter-ed25519", "openrouter-ed25519.pub",
    "mihomo/active-node.json", "mihomo/node-origin.json",
})


def _fernet_key(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw)


def _passphrase_bytes(value: str | bytes) -> bytearray:
    if not isinstance(value, (str, bytes)):
        raise VaultFormatError("passphrase has an invalid type")
    return bytearray(value.encode("utf-8") if isinstance(value, str) else value)


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


class Vault:
    def __init__(
        self,
        path: Path,
        *,
        source_id: Optional[str] = None,
        allowed_record_names: Iterable[str] = RECORD_NAMES,
        validator: Optional[Callable[[Mapping[str, Any]], None]] = None,
        memory_preflight: Callable[[], Any] = protect_process,
        buffer_factory: Callable[[bytes], LockedBuffer] = LockedBuffer,
    ) -> None:
        if source_id is not None and (not isinstance(source_id, str) or not source_id or len(source_id) > 256):
            raise ValueError("source_id must be a bounded nonempty string or None")
        names = frozenset(allowed_record_names)
        if any(not isinstance(name, str) or not name or len(name) > 128 for name in names):
            raise ValueError("record names must be bounded nonempty strings")
        self.path = Path(path)
        self.source_id = source_id
        self.allowed_record_names = names
        self._validator = validator
        self._memory_preflight = memory_preflight
        self._buffer_factory = buffer_factory
        self._dek: Optional[LockedBuffer] = None
        self._snapshot: Optional[dict[str, Any]] = None
        self._vault_id: Optional[str] = None
        self._lock_fd: Optional[int] = None

    @property
    def snapshot(self) -> dict[str, Any]:
        if self._snapshot is None:
            raise VaultLockedError("vault is locked")
        return copy.deepcopy(self._snapshot)

    @property
    def vault_id(self) -> str:
        """Authenticated vault identity, available only after a successful unlock."""
        self._require_unlocked()
        return self._vault_id

    def initialize(self, passphrase: str | bytes, snapshot: Mapping[str, Any]) -> "Vault":
        try:
            self._acquire_writer()
            # Check after acquiring the lock: another guardian may have won a
            # create race after the caller's earlier filesystem observation.
            if self.path.exists():
                raise VaultError("vault already exists")
            self._memory_preflight()
            checked = self._validate_snapshot(snapshot)
            self._vault_id = secrets.token_urlsafe(24)
            self._set_dek(secrets.token_bytes(32))
            self._snapshot = checked
            self._write(passphrase)
            return self
        except BaseException:
            self.close()
            raise

    def unlock(self, passphrase: str | bytes) -> dict[str, Any]:
        if self._snapshot is not None:
            return self.snapshot
        try:
            self._acquire_writer()
            self._memory_preflight()
            envelope = self._read_envelope()
            vault_id = envelope["vault_id"]
            kdf = envelope["kdf"]
            salt = self._decode(kdf["salt"], "kdf salt", exact=16)
            phrase = _passphrase_bytes(passphrase)
            try:
                kek = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(bytes(phrase))
                wrap = self._decrypt(Fernet(_fernet_key(kek)), envelope["wrapped_dek"], "wrapped key")
            finally:
                _wipe(phrase)
            wrapped = self._json_object(wrap, "wrapped key")
            if set(wrapped) != {"auth", "dek"}:
                raise VaultAuthenticationError("vault authentication data is invalid")
            self._check_wrap_auth(wrapped["auth"], vault_id)
            dek = self._decode(wrapped["dek"], "data key", exact=32)
            plaintext = self._decrypt(Fernet(_fernet_key(dek)), envelope["ciphertext"], "ciphertext")
            body = self._json_object(plaintext, "snapshot")
            self._check_snapshot_auth(body.pop("auth", None), vault_id, body)
            snapshot = self._validate_snapshot(body)
            self._vault_id = vault_id
            self._set_dek(dek)
            self._snapshot = snapshot
            return self.snapshot
        except (VaultError, MemoryGuardError):
            self.close()
            raise
        except Exception:
            self.close()
            raise VaultAuthenticationError("vault cannot be unlocked") from None

    def update(self, snapshot: Mapping[str, Any]) -> None:
        self._require_unlocked()
        self._snapshot = self._validate_snapshot(snapshot)
        try:
            self._write_with_dek()
        except BaseException:
            # A failed directory fsync can follow a successful replace. The
            # disk's committed state is then unknown: never continue from RAM.
            self.close()
            raise

    def change_passphrase(self, new_passphrase: str | bytes) -> None:
        self._require_unlocked()
        previous = self._dek
        replacement = self._new_buffer(secrets.token_bytes(32))
        self._dek = replacement
        try:
            self._write(new_passphrase)
        except BaseException:
            # The new wrapper may already be on disk. Restoring the old DEK
            # would make a later update undecryptable with either passphrase.
            self.close()
            previous.close()
            raise
        previous.close()

    def close(self) -> None:
        if self._dek is not None:
            self._dek.close()
        self._dek = None
        self._snapshot = None
        self._vault_id = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
        self._lock_fd = None

    def _require_unlocked(self) -> None:
        if self._snapshot is None or self._dek is None or self._vault_id is None:
            raise VaultLockedError("vault is locked")

    def _acquire_writer(self) -> None:
        if self._lock_fd is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path.with_name(self.path.name + ".lock"),
                     os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            import stat
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise VaultError("vault lock ownership or type is invalid")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise VaultError("vault writer is unavailable") from exc
        except BaseException:
            os.close(fd)
            raise
        self._lock_fd = fd

    def _set_dek(self, value: bytes) -> None:
        if self._dek is not None:
            self._dek.close()
        self._dek = self._new_buffer(value)

    def _new_buffer(self, value: bytes) -> LockedBuffer:
        try:
            return self._buffer_factory(value)
        except MemoryGuardError as exc:
            raise VaultError("data key memory protection failed") from exc

    def _write(self, passphrase: str | bytes) -> None:
        self._require_unlocked()
        phrase = _passphrase_bytes(passphrase)
        salt = secrets.token_bytes(16)
        try:
            kek = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(bytes(phrase))
            wrapped = Fernet(_fernet_key(kek)).encrypt(canonical_json_bytes({
                "auth": self._wrap_auth(), "dek": base64.b64encode(self._dek.read()).decode("ascii")}))
        finally:
            _wipe(phrase)
        self._write_envelope(salt, wrapped)

    def _write_with_dek(self) -> None:
        # Preserve the existing passphrase wrapper; update only the snapshot ciphertext.
        envelope = self._read_envelope()
        self._write_envelope(self._decode(envelope["kdf"]["salt"], "kdf salt", exact=16),
                             envelope["wrapped_dek"].encode("ascii"))

    def _write_envelope(self, salt: bytes, wrapped: bytes) -> None:
        self._require_unlocked()
        body = copy.deepcopy(self._snapshot)
        body["auth"] = self._snapshot_auth()
        ciphertext = Fernet(_fernet_key(self._dek.read())).encrypt(canonical_json_bytes(body))
        envelope = {"schema": SCHEMA, "vault_id": self._vault_id,
                    "kdf": {**KDF, "salt": base64.b64encode(salt).decode("ascii")},
                    "wrapped_dek": wrapped.decode("ascii"), "ciphertext": ciphertext.decode("ascii")}
        encoded = canonical_json_bytes(envelope) + b"\n"
        if len(encoded) > MAX_FILE_BYTES:
            raise VaultFormatError("encrypted vault exceeds size limit")
        atomic_write_bytes(self.path, encoded, 0o600)

    def _read_envelope(self) -> dict[str, Any]:
        try:
            import stat
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise VaultFormatError("vault ownership or type is invalid")
                raw = stream.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise VaultFormatError("vault cannot be read") from exc
        if not raw or len(raw) > MAX_FILE_BYTES:
            raise VaultFormatError("vault has an invalid size")
        return self._validate_envelope(self._json_object(raw, "vault"))

    @staticmethod
    def _json_object(raw: bytes, name: str) -> dict[str, Any]:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise VaultFormatError(f"{name} contains duplicate fields")
                result[key] = value
            return result
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError(f"{name} is malformed") from exc
        if not isinstance(value, dict):
            raise VaultFormatError(f"{name} must be an object")
        return value

    def _validate_envelope(self, value: dict[str, Any]) -> dict[str, Any]:
        if set(value) != {"schema", "vault_id", "kdf", "wrapped_dek", "ciphertext"}:
            raise VaultFormatError("vault envelope fields are invalid")
        if type(value["schema"]) is not int or value["schema"] != SCHEMA or not isinstance(value["vault_id"], str) or not value["vault_id"]:
            raise VaultFormatError("vault envelope identity is invalid")
        if not isinstance(value["kdf"], dict) or set(value["kdf"]) != set(KDF) | {"salt"}:
            raise VaultFormatError("vault KDF fields are invalid")
        if any(type(value["kdf"].get(key)) is not type(expected) or value["kdf"].get(key) != expected
               for key, expected in KDF.items()):
            raise VaultFormatError("vault KDF profile is not allowed")
        self._decode(value["kdf"].get("salt"), "kdf salt", exact=16)
        for key in ("wrapped_dek", "ciphertext"):
            if not isinstance(value[key], str) or len(value[key]) > MAX_FILE_BYTES:
                raise VaultFormatError("vault ciphertext is invalid")
        return value

    def _wrap_auth(self) -> dict[str, Any]:
        return {"purpose": PURPOSE, "schema": SCHEMA, "vault_id": self._vault_id}

    def _snapshot_auth(self) -> dict[str, Any]:
        return {**self._wrap_auth(), "source_id": self._snapshot["source_id"],
                "security_epoch": self._snapshot["security_epoch"]}

    def _check_wrap_auth(self, value: Any, vault_id: str) -> None:
        if value != {"purpose": PURPOSE, "schema": SCHEMA, "vault_id": vault_id}:
            raise VaultAuthenticationError("vault authentication data is invalid")

    def _check_snapshot_auth(self, value: Any, vault_id: str, snapshot: Mapping[str, Any]) -> None:
        expected = {"purpose": PURPOSE, "schema": SCHEMA, "vault_id": vault_id,
                    "source_id": snapshot.get("source_id"), "security_epoch": snapshot.get("security_epoch")}
        if value != expected or not isinstance(snapshot.get("source_id"), str) or not snapshot.get("source_id"):
            raise VaultAuthenticationError("vault authentication data is invalid")

    @staticmethod
    def _decrypt(fernet: Fernet, token: Any, name: str) -> bytes:
        if not isinstance(token, str):
            raise VaultFormatError(f"{name} is invalid")
        try:
            return fernet.decrypt(token.encode("ascii"))
        except (InvalidToken, UnicodeEncodeError) as exc:
            raise VaultAuthenticationError("vault authentication failed") from exc

    @staticmethod
    def _decode(value: Any, name: str, *, exact: Optional[int] = None) -> bytes:
        if not isinstance(value, str):
            raise VaultFormatError(f"{name} is invalid")
        try:
            decoded = base64.b64decode(value.encode("ascii"), validate=True)
        except Exception as exc:
            raise VaultFormatError(f"{name} is invalid") from exc
        if (exact is not None and len(decoded) != exact) or len(decoded) > MAX_RECORD_BYTES:
            raise VaultFormatError(f"{name} has an invalid size")
        return decoded

    def _validate_snapshot(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != {"source_id", "security_epoch", "policy_revision", "records", "passkeys"}:
            raise VaultFormatError("snapshot fields are invalid")
        if (not isinstance(value["source_id"], str) or not value["source_id"] or len(value["source_id"]) > 256
                or self.source_id is not None and value["source_id"] != self.source_id
                or type(value["security_epoch"]) is not int or value["security_epoch"] < 0
                or type(value["policy_revision"]) is not int or value["policy_revision"] < 0):
            raise VaultFormatError("snapshot identity is invalid")
        records = value["records"]
        if not isinstance(records, Mapping) or len(records) > MAX_RECORDS or set(records) - self.allowed_record_names:
            raise VaultFormatError("snapshot records are invalid")
        clean_records: dict[str, str] = {}
        for name, encoded in records.items():
            if not isinstance(name, str) or name not in self.allowed_record_names:
                raise VaultFormatError("snapshot record name is invalid")
            self._decode(encoded, "snapshot record")
            clean_records[name] = encoded
        if not isinstance(value["passkeys"], dict):
            raise VaultFormatError("snapshot passkeys are invalid")
        clean = {"source_id": value["source_id"], "security_epoch": value["security_epoch"],
                 "policy_revision": value["policy_revision"], "records": clean_records,
                 "passkeys": copy.deepcopy(value["passkeys"])}
        try:
            if len(canonical_json_bytes(clean)) > MAX_FILE_BYTES:
                raise VaultFormatError("snapshot is too large")
            if self._validator is not None:
                self._validator(copy.deepcopy(clean))
        except VaultError:
            raise
        except Exception as exc:
            raise VaultFormatError("snapshot domain validation failed") from exc
        return clean
