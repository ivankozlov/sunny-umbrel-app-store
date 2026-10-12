from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from sunny_digest.memory_guard import LockedBuffer, MemoryGuardError
from sunny_digest.storage import canonical_json_bytes
from sunny_digest.vault import Vault, VaultAuthenticationError, VaultError, VaultFormatError, VaultLockedError, _fernet_key


def sample() -> dict:
    return {"source_id": "source-1", "security_epoch": 7, "policy_revision": 3,
            "records": {"telegram_session": base64.b64encode(b"SYNTHETIC-CANARY").decode()}, "passkeys": {}}


class TestVault(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.json"
        self.kwargs = {"source_id": "source-1", "allowed_record_names": {"telegram_session"}, "memory_preflight": lambda: None,
                       "buffer_factory": lambda value: LockedBuffer(value, require_lock=False)}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_round_trip_wrong_phrase_and_no_plaintext_disk(self) -> None:
        vault = Vault(self.path, **self.kwargs).initialize("correct", sample())
        vault.close()
        unlocked = Vault(self.path, **self.kwargs)
        self.assertEqual(unlocked.unlock("correct"), sample())
        unlocked.close()
        self.assertNotIn(b"SYNTHETIC-CANARY", self.path.read_bytes())
        with self.assertRaises(VaultAuthenticationError):
            Vault(self.path, **self.kwargs).unlock("wrong")

    def test_tamper_and_kdf_bounds_fail_before_decrypt(self) -> None:
        vault = Vault(self.path, **self.kwargs).initialize("correct", sample())
        vault.close()
        raw = json.loads(self.path.read_text())
        raw["kdf"]["memory_kib"] = 1
        self.path.write_text(json.dumps(raw))
        with self.assertRaises(VaultFormatError):
            Vault(self.path, **self.kwargs).unlock("correct")

    def test_schema_numbers_reject_bool_and_unlock_failure_releases_writer(self) -> None:
        vault = Vault(self.path, **self.kwargs).initialize("correct", sample())
        vault.close()
        raw = json.loads(self.path.read_text())
        raw["kdf"]["iterations"] = True
        self.path.write_text(json.dumps(raw))
        rejected = Vault(self.path, **self.kwargs)
        with self.assertRaises(VaultFormatError):
            rejected.unlock("correct")
        self.assertIsNone(rejected._lock_fd)

    def test_initialize_failure_releases_writer_and_key(self) -> None:
        with patch("sunny_digest.vault.atomic_write_bytes", side_effect=OSError("synthetic interruption")):
            failed = Vault(self.path, **self.kwargs)
            with self.assertRaises(OSError):
                failed.initialize("correct", sample())
        self.assertIsNone(failed._lock_fd)
        self.assertIsNone(failed._dek)
        Vault(self.path, **self.kwargs).initialize("correct", sample()).close()

    def test_authentication_binds_source_and_envelope_id(self) -> None:
        vault = Vault(self.path, **self.kwargs).initialize("correct", sample())
        vault.close()
        raw = json.loads(self.path.read_text())
        raw["vault_id"] = "substituted"
        self.path.write_text(json.dumps(raw))
        with self.assertRaises(VaultAuthenticationError):
            Vault(self.path, **self.kwargs).unlock("correct")
        with self.assertRaises(VaultAuthenticationError):
            Vault(self.path, source_id="other", allowed_record_names={"telegram_session"}, memory_preflight=lambda: None).unlock("correct")

    def test_authenticated_snapshot_rejects_purpose_and_schema_substitution(self) -> None:
        for field, bad_value in (("purpose", "other"), ("schema", 99)):
            path = self.path.with_name(f"{field}.json")
            vault = Vault(path, **self.kwargs).initialize("correct", sample())
            raw = json.loads(path.read_text())
            body = sample()
            body["auth"] = {"purpose": "sunny-personal-chats-vault", "schema": 1,
                            "vault_id": raw["vault_id"], "source_id": "source-1", "security_epoch": 7}
            body["auth"][field] = bad_value
            raw["ciphertext"] = Fernet(_fernet_key(vault._dek.read())).encrypt(canonical_json_bytes(body)).decode()
            path.write_text(json.dumps(raw))
            vault.close()
            with self.assertRaises(VaultAuthenticationError):
                Vault(path, **self.kwargs).unlock("correct")

    def test_passphrase_change_uses_new_dek(self) -> None:
        vault = Vault(self.path, **self.kwargs).initialize("old", sample())
        old_dek = vault._dek.read()
        first = json.loads(self.path.read_text())["ciphertext"]
        vault.change_passphrase("new")
        second = json.loads(self.path.read_text())["ciphertext"]
        self.assertNotEqual(first, second)
        self.assertNotEqual(vault._dek.read(), old_dek)
        vault.close()
        with self.assertRaises(VaultAuthenticationError):
            Vault(self.path, **self.kwargs).unlock("old")
        self.assertEqual(Vault(self.path, **self.kwargs).unlock("new"), sample())

    def test_writer_lock_and_update_are_atomic(self) -> None:
        first = Vault(self.path, **self.kwargs).initialize("correct", sample())
        with self.assertRaises(VaultError):
            Vault(self.path, **self.kwargs).unlock("correct")
        changed = sample(); changed["policy_revision"] = 4
        first.update(changed)
        self.assertEqual(json.loads(self.path.read_text())["schema"], 1)
        first.close()
        self.assertEqual(Vault(self.path, **self.kwargs).unlock("correct")["policy_revision"], 4)

    def test_failed_atomic_update_leaves_previous_snapshot_unlockable(self) -> None:
        vault = Vault(self.path, **self.kwargs).initialize("correct", sample())
        before = self.path.read_bytes()
        changed = sample(); changed["policy_revision"] = 4
        with patch("sunny_digest.vault.atomic_write_bytes", side_effect=OSError("synthetic interruption")):
            with self.assertRaises(OSError):
                vault.update(changed)
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(VaultLockedError):
            _ = vault.snapshot
        self.assertEqual(vault.unlock("correct")["policy_revision"], 3)

    def test_rotation_failure_after_replace_never_reuses_previous_dek(self) -> None:
        from sunny_digest.storage import atomic_write_bytes
        vault = Vault(self.path, **self.kwargs).initialize("old", sample())
        def replaced_then_failed(path, data, mode):
            atomic_write_bytes(path, data, mode)
            raise OSError("synthetic directory fsync failure")
        with patch("sunny_digest.vault.atomic_write_bytes", side_effect=replaced_then_failed):
            with self.assertRaises(OSError):
                vault.change_passphrase("new")
        with self.assertRaises(VaultLockedError):
            vault.update(sample())
        with self.assertRaises(VaultAuthenticationError):
            vault.unlock("old")
        self.assertEqual(vault.unlock("new"), sample())
        vault.close()

    def test_encrypted_size_limit_cannot_commit_an_unreadable_snapshot(self) -> None:
        large = sample()
        large["records"] = {str(i): base64.b64encode(b"x" * n).decode()
                            for i, n in enumerate((512 * 1024, 512 * 1024, 256 * 1024))}
        kwargs = {**self.kwargs, "allowed_record_names": {"0", "1", "2"}}
        vault = Vault(self.path, **kwargs)
        with self.assertRaises(VaultFormatError):
            vault.initialize("correct", large)
        self.assertFalse(self.path.exists())

    def test_reader_rejects_symlink_and_group_readable_file(self) -> None:
        Vault(self.path, **self.kwargs).initialize("correct", sample()).close()
        self.path.chmod(0o640)
        with self.assertRaises(VaultFormatError):
            Vault(self.path, **self.kwargs).unlock("correct")
        self.path.chmod(0o600)
        link = self.path.with_name("link.json")
        link.symlink_to(self.path)
        with self.assertRaises(VaultFormatError):
            Vault(link, **self.kwargs).unlock("correct")

    def test_rejects_unowned_record(self) -> None:
        bad = sample(); bad["records"]["other"] = base64.b64encode(b"x").decode()
        with self.assertRaises(VaultFormatError):
            Vault(self.path, **self.kwargs).initialize("correct", bad)

    def test_memory_preflight_aborts_before_reading_ciphertext(self) -> None:
        original = Vault(self.path, **self.kwargs).initialize("correct", sample())
        original.close()
        candidate = Vault(self.path, source_id="source-1", allowed_record_names={"telegram_session"},
                          memory_preflight=lambda: (_ for _ in ()).throw(MemoryGuardError("synthetic")),
                          buffer_factory=lambda value: LockedBuffer(value, require_lock=False))
        with patch.object(candidate, "_read_envelope") as read_envelope:
            with self.assertRaises(MemoryGuardError):
                candidate.unlock("correct")
        read_envelope.assert_not_called()
        self.assertIsNone(candidate._lock_fd)

    def test_vault_id_is_unavailable_locked_and_public_after_unlock(self) -> None:
        vault = Vault(self.path, **self.kwargs)
        with self.assertRaises(VaultError):
            _ = vault.vault_id
        initialized = vault.initialize("correct", sample())
        self.assertTrue(initialized.vault_id)
