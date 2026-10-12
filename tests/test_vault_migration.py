from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sunny_digest.memory_guard import LockedBuffer
from sunny_digest.migrate_vault import VaultMigration
from sunny_digest.storage import Paths, atomic_write_json
from sunny_digest.vault import Vault, VaultLockedError


class TestVaultMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = Paths(
            self.root / "config", self.root / "private", self.root / "runtime", self.root / "runtime/control.sock"
        )
        self.paths.ensure()
        atomic_write_json(self.paths.settings, {"source_id": "source-a"})
        self.paths.credentials.write_bytes(b"SYNTHETIC-CANARY")
        self.paths.credentials.chmod(0o600)
        self.paths.pending.write_bytes(b"checkpoint-pending")
        self.paths.acknowledged.write_bytes(b"checkpoint-acknowledged")
        self.vault = self._vault()

    def tearDown(self):
        self.tmp.cleanup()

    def _vault(self) -> Vault:
        return Vault(
            self.paths.private_dir / "vault.json",
            memory_preflight=lambda: None,
            buffer_factory=lambda value: LockedBuffer(value, require_lock=False),
        )

    def _passkeys(self) -> dict[str, dict[str, object]]:
        return {
            "Y3JlZGVudGlhbA": {
                "credential_id": "Y3JlZGVudGlhbA",
                "public_key": "synthetic-public-key",
                "sign_count": 7,
                "user_handle": "synthetic-user",
                "name": "Synthetic passkey",
            }
        }

    def test_apply_crosses_all_barriers_and_leaves_only_encrypted_canary(self):
        phases = []
        migration = VaultMigration(self.paths, self.vault, barrier=phases.append)
        migration.apply("phrase", self._passkeys())
        self.assertEqual(phases, ["started", "encrypted", "committed", "plaintext_removed", "cleaned", "ready"])
        self.assertFalse(self.paths.credentials.exists())
        self.assertFalse(migration.marker.exists())
        self.assertEqual(self.vault.snapshot["source_id"], "source-a")
        self.assertEqual(self.vault.snapshot["passkeys"], self._passkeys())
        self.assertEqual(self.paths.pending.read_bytes(), b"checkpoint-pending")
        self.assertEqual(self.paths.acknowledged.read_bytes(), b"checkpoint-acknowledged")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SYNTHETIC-CANARY", path.read_bytes(), path)

    def test_resume_after_encrypted_and_cleanup_barriers_preserves_snapshot(self):
        for failed_phase in ("encrypted", "committed", "plaintext_removed", "cleaned"):
            with self.subTest(failed_phase=failed_phase):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    paths = Paths(root / "config", root / "private", root / "runtime", root / "runtime/control.sock")
                    paths.ensure()
                    atomic_write_json(paths.settings, {"source_id": "source-resume"})
                    paths.credentials.write_bytes(b"RESUME-CANARY")
                    paths.credentials.chmod(0o600)
                    paths.pending.write_bytes(b"pending-before-resume")
                    paths.acknowledged.write_bytes(b"ack-before-resume")
                    vault = Vault(
                        paths.private_dir / "vault.json",
                        memory_preflight=lambda: None,
                        buffer_factory=lambda value: LockedBuffer(value, require_lock=False),
                    )

                    def fail_at(phase: str) -> None:
                        if phase == failed_phase:
                            raise RuntimeError(f"fail at {phase}")

                    migration = VaultMigration(paths, vault, barrier=fail_at)
                    with self.assertRaisesRegex(RuntimeError, f"fail at {failed_phase}"):
                        migration.apply("phrase", self._passkeys())
                    vault.close()

                    resumed_vault = Vault(
                        paths.private_dir / "vault.json",
                        memory_preflight=lambda: None,
                        buffer_factory=lambda value: LockedBuffer(value, require_lock=False),
                    )
                    resumed_vault.unlock("phrase")
                    resumed = VaultMigration(paths, resumed_vault)
                    resumed.resume()

                    self.assertFalse(paths.credentials.exists())
                    self.assertFalse(resumed.marker.exists())
                    self.assertEqual(resumed_vault.snapshot["source_id"], "source-resume")
                    self.assertEqual(resumed_vault.snapshot["passkeys"], self._passkeys())
                    self.assertEqual(paths.pending.read_bytes(), b"pending-before-resume")
                    self.assertEqual(paths.acknowledged.read_bytes(), b"ack-before-resume")

    def test_started_barrier_does_not_bypass_missing_encrypted_vault(self):
        migration = VaultMigration(
            self.paths,
            self.vault,
            barrier=lambda phase: (_ for _ in ()).throw(RuntimeError("stop before vault"))
            if phase == "started"
            else None,
        )
        with self.assertRaisesRegex(RuntimeError, "stop before vault"):
            migration.apply("phrase", self._passkeys())
        self.assertTrue(self.paths.credentials.exists())
        self.assertTrue(migration.marker.exists())
        with self.assertRaises(VaultLockedError):
            migration.resume()
        self.assertTrue(self.paths.credentials.exists())
        self.assertTrue(migration.marker.exists())

    def test_precleanup_validator_rejection_retains_plaintext_and_marker(self):
        migration = VaultMigration(self.paths, self.vault, validator=lambda: (_ for _ in ()).throw(RuntimeError("reject")))
        with self.assertRaisesRegex(RuntimeError, "reject"):
            migration.apply("phrase", {})
        self.assertTrue(self.paths.credentials.exists())
        self.assertTrue(migration.marker.exists())

    def test_inventory_is_readonly_and_missing_vault_does_not_clear_warning(self):
        self.paths.telegram_session_outstanding.write_text("warning")
        migration = VaultMigration(self.paths, self.vault)
        before = self.paths.credentials.read_bytes()
        self.assertTrue(migration.inventory()["legacy"])
        self.assertEqual(self.paths.credentials.read_bytes(), before)
        self.assertTrue(self.paths.telegram_session_outstanding.exists())

    def test_stale_exact_temp_removed_but_unknown_file_survives(self):
        temp = self.paths.credentials.with_name(".credentials.json.tmp")
        write = self.paths.credentials.with_name(".credentials.json.write")
        temp.write_bytes(b"old")
        write.write_bytes(b"old")
        unknown = self.paths.private_dir / ".unrelated"
        unknown.write_bytes(b"keep")
        migration = VaultMigration(self.paths, self.vault)
        migration.apply("phrase", self._passkeys())
        self.assertFalse(temp.exists())
        self.assertFalse(write.exists())
        self.assertTrue(unknown.exists())
