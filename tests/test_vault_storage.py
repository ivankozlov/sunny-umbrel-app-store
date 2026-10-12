from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from sunny_digest.storage import Paths
from sunny_digest.vault_storage import RECORD_NAMES, VaultPaths


class FakeVault:
    def __init__(self):
        self.snapshot = {"source_id": "source", "security_epoch": 0, "policy_revision": 0,
                         "records": {}, "passkeys": {}}

    def update(self, value):
        self.snapshot = value


class TestVaultStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.paths = Paths(root / "config", root / "private", root / "runtime", root / "runtime/control.sock")
        self.paths.ensure()
        self.vault = FakeVault()
        self.vpaths = VaultPaths(self.paths, self.vault, root / "scratch")

    def tearDown(self):
        self.tmp.cleanup()

    def test_records_have_no_os_path_and_only_mutate_encrypted_snapshot(self):
        record = self.vpaths.credentials
        with self.assertRaises(TypeError):
            record.__fspath__()
        record.write(b"SYNTHETIC-CANARY")
        self.assertEqual(record.read_bytes(), b"SYNTHETIC-CANARY")
        self.assertFalse(self.paths.credentials.exists())
        self.assertEqual(list(self.paths.private_dir.iterdir()), [])

    def test_reset_files_clear_every_vault_record_but_keep_new_passkeys(self):
        self.vault.snapshot["records"] = {name: base64.b64encode(name.encode()).decode() for name in RECORD_NAMES.values()}
        self.vault.snapshot["passkeys"] = {"credential": {"name": "new"}}
        for record in self.vpaths.reset_files():
            try:
                record.unlink()
            except FileNotFoundError:
                pass
        self.assertEqual(self.vault.snapshot["records"], {})
        self.assertEqual(self.vault.snapshot["passkeys"], {"credential": {"name": "new"}})
