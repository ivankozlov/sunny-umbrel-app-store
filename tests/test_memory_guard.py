from __future__ import annotations

import platform
import resource
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunny_digest.memory_guard import (
    PR_GET_DUMPABLE, PR_SET_DUMPABLE, LockedBuffer, MemoryGuardError,
    protect_process, verify_process, verify_native_parent, verify_native_child,
)


class TestMemoryGuard(unittest.TestCase):
    def test_linux_guard_sets_and_verifies_all_required_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch("sunny_digest.memory_guard.resource.getrlimit", return_value=(0, 0)), patch("sunny_digest.memory_guard.resource.setrlimit") as setlimit:
            root = Path(directory); (root / "cgroup.controllers").write_text("memory")
            child = root / "unit"; child.mkdir(); (child / "memory.swap.max").write_text("0")
            calls = []
            def prctl(op, value=0):
                calls.append((op, value)); return 0
            diag = protect_process(system="Linux", cgroup_root=root, cgroup_path=child, prctl=prctl)
        setlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))
        self.assertFalse(diag.dumpable); self.assertTrue(diag.swap_limited)
        self.assertIn((PR_SET_DUMPABLE, 0), calls); self.assertIn((PR_GET_DUMPABLE, 0), calls)

    def test_refuses_dumpable_or_swap_permitted_process(self) -> None:
        with patch("sunny_digest.memory_guard.resource.getrlimit", return_value=(0, 0)):
            with self.assertRaises(MemoryGuardError):
                verify_process(system="Linux", cgroup_root=Path("/not-present"), prctl=lambda *_: 1)
        with tempfile.TemporaryDirectory() as directory, patch("sunny_digest.memory_guard.resource.getrlimit", return_value=(0, 0)):
            root = Path(directory); (root / "cgroup.controllers").write_text("memory")
            child = root / "unit"; child.mkdir(); (child / "memory.swap.max").write_text("max")
            with self.assertRaises(MemoryGuardError):
                verify_process(system="Linux", cgroup_root=root, cgroup_path=child, prctl=lambda *_: 0)

    def test_native_children_require_file_core_handler_and_inherited_zero_limits(self):
        with patch("sunny_digest.memory_guard.resource.getrlimit", return_value=(0, 0)), \
                patch("sunny_digest.memory_guard.verify_process") as verify, \
                patch("sunny_digest.memory_guard.Path.read_text", return_value="core\n"):
            verify_native_parent()
            verify.assert_called_once()
        for pattern in ("", "|/usr/bin/core-handler %p"):
            with patch("sunny_digest.memory_guard.resource.getrlimit", return_value=(0, 0)), \
                    patch("sunny_digest.memory_guard.Path.read_text", return_value=pattern):
                with self.assertRaises(MemoryGuardError): verify_native_parent()
        with patch("sunny_digest.memory_guard.Path.read_text", return_value="Max core file size        0                    0                    bytes\n"):
            verify_native_child(123)
        with patch("sunny_digest.memory_guard.Path.read_text", return_value="Max core file size        unlimited            unlimited            bytes\n"):
            with self.assertRaises(MemoryGuardError): verify_native_child(123)

    def test_v1_requires_provable_equal_memsw_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch("sunny_digest.memory_guard.resource.getrlimit", return_value=(0, 0)):
            root = Path(directory); child = root / "unit"; child.mkdir()
            (child / "memory.limit_in_bytes").write_text("536870912")
            (child / "memory.memsw.limit_in_bytes").write_text("536870912")
            self.assertTrue(verify_process(system="Linux", cgroup_root=root, cgroup_path=child, prctl=lambda *_: 0).swap_limited)
            (child / "memory.memsw.limit_in_bytes").write_text("1073741824")
            with self.assertRaises(MemoryGuardError):
                verify_process(system="Linux", cgroup_root=root, cgroup_path=child, prctl=lambda *_: 0)

            for limit in ("0", "9223372036854771712", "max"):
                with self.subTest(limit=limit):
                    (child / "memory.limit_in_bytes").write_text(limit)
                    (child / "memory.memsw.limit_in_bytes").write_text(limit)
                    with self.assertRaises(MemoryGuardError):
                        verify_process(system="Linux", cgroup_root=root, cgroup_path=child, prctl=lambda *_: 0)

    def test_non_linux_fails_closed_after_core_limit(self) -> None:
        with patch("sunny_digest.memory_guard.resource.setrlimit"):
            with self.assertRaises(MemoryGuardError):
                protect_process(system="Darwin")

    @unittest.skipUnless(platform.system() == "Linux", "real mlock is Linux-only")
    def test_locked_buffer_real_linux_path_and_zeroization_contract(self) -> None:
        buffer = LockedBuffer(b"synthetic-key")
        self.assertEqual(buffer.read(), b"synthetic-key")
        buffer.close()
        with self.assertRaises(MemoryGuardError):
            buffer.read()
