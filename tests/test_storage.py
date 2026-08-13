from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunny_digest.storage import Paths, atomic_write_bytes, safe_unlink


class StorageDurabilityTests(unittest.TestCase):
    def _recording_fsync(self):
        real_fsync = os.fsync
        modes = []

        def recording(fd):
            modes.append(stat.S_IFMT(os.fstat(fd).st_mode))
            return real_fsync(fd)

        return modes, recording

    def test_atomic_replace_syncs_file_then_parent_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            modes, recording = self._recording_fsync()
            with patch("sunny_digest.storage.os.fsync", side_effect=recording):
                atomic_write_bytes(path, b"durable\n")

            self.assertEqual(path.read_bytes(), b"durable\n")
            self.assertIn(stat.S_IFREG, modes)
            self.assertEqual(modes[-1], stat.S_IFDIR)

    def test_unlink_syncs_parent_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "credential"
            path.write_bytes(b"secret")
            modes, recording = self._recording_fsync()
            with patch("sunny_digest.storage.os.fsync", side_effect=recording):
                safe_unlink(path)

            self.assertFalse(path.exists())
            self.assertEqual(modes, [stat.S_IFDIR])

    def test_reset_allowlist_contains_only_exact_vpn_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(
                root / "config", root / "private", root / "runtime",
                root / "runtime" / "control.sock",
            )
            self.assertEqual(
                paths.vpn_active_node,
                root / "private" / "mihomo" / "active-node.json",
            )
            self.assertIn(paths.vpn_active_node, paths.reset_files())

            paths.vpn_dir.mkdir(parents=True)
            unrelated = paths.vpn_dir / "unrelated"
            unrelated.write_text("keep", encoding="utf-8")
            paths.remove_empty_vpn_dir()
            self.assertTrue(unrelated.exists())
            unrelated.unlink()
            paths.remove_empty_vpn_dir()
            self.assertFalse(paths.vpn_dir.exists())


if __name__ == "__main__":
    unittest.main()
