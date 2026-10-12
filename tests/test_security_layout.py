from __future__ import annotations

import sys
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import prepare_security_layout as layout  # noqa: E402


class TestSecurityLayout(unittest.TestCase):
    def test_fixed_path_and_explicit_apply_are_required(self):
        self.assertEqual(layout.prepare(apply=False, root=Path("/tmp/not-sunny")), 2)
        self.assertEqual(layout.APP_DATA_DIR, Path("/home/umbrel/umbrel/app-data/sunny-personal-digest"))

    def test_layout_names_are_bounded_and_role_specific(self):
        self.assertEqual([str(path) for path, *_ in layout.DIRECTORIES], [
            "data/config", "data/private", "data/runtime", "data/runtime/ipc",
            "data/runtime/ipc/jobs", "data/runtime/ipc/admin",
        ])
        self.assertEqual(layout.DIRECTORIES[-2][1:], (1000, 1001, 0o2750))
        self.assertEqual(layout.DIRECTORIES[-1][1:], (1000, 1002, 0o2750))

    def test_apply_creates_only_known_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sunny"
            root.mkdir()
            (root / "data").mkdir()
            with (
                patch.object(layout, "APP_DATA_DIR", root),
                patch.object(layout.os, "geteuid", return_value=0),
                patch.object(layout.os, "chown") as chown,
            ):
                self.assertEqual(layout.prepare(apply=True, root=layout.APP_DATA_DIR), 0)
            self.assertEqual(chown.call_count, len(layout.DIRECTORIES))
            self.assertEqual({path for path, *_ in layout.DIRECTORIES},
                             {path.relative_to(root) for path in root.rglob("*") if path.is_dir()} - {Path("data")})

    def test_apply_requires_root_and_dry_run_has_no_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sunny"
            root.mkdir()
            (root / "data").mkdir()
            with patch.object(layout, "APP_DATA_DIR", root), patch.object(layout.os, "geteuid", return_value=501):
                self.assertEqual(layout.prepare(apply=True, root=layout.APP_DATA_DIR), 1)
            self.assertEqual(list((root / "data").iterdir()), [])
            with (
                patch.object(layout, "APP_DATA_DIR", root),
                patch.object(layout.os, "mkdir") as mkdir,
                patch.object(layout.os, "chown") as chown,
                patch.object(layout.os, "chmod") as chmod,
            ):
                self.assertEqual(layout.prepare(apply=False, root=layout.APP_DATA_DIR), 0)
            mkdir.assert_not_called()
            chown.assert_not_called()
            chmod.assert_not_called()

    def test_refuses_symlink_ancestor_even_when_leaf_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sunny"
            root.mkdir()
            target = Path(directory) / "elsewhere"
            target.mkdir()
            (target / "config").mkdir()
            (root / "data").symlink_to(target, target_is_directory=True)
            with patch.object(layout, "APP_DATA_DIR", root):
                self.assertEqual(layout.prepare(apply=False, root=layout.APP_DATA_DIR), 1)

    def test_invalid_later_directory_prevents_any_apply_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sunny"
            root.mkdir()
            data = root / "data"
            data.mkdir()
            private = data / "private"
            private.mkdir(mode=0o700)
            # UID/GID 1000:1000 is valid in the native probe. Make the
            # negative fixture's mode explicitly wrong on every platform.
            private.chmod(0o750)
            with (
                patch.object(layout, "APP_DATA_DIR", root),
                patch.object(layout.os, "geteuid", return_value=0),
                patch.object(layout, "_state", side_effect=lambda path: (
                    1000, 1000, stat.S_IMODE(path.stat().st_mode))),
                patch.object(layout.os, "chown") as chown,
            ):
                self.assertEqual(layout.prepare(apply=True, root=layout.APP_DATA_DIR), 1)
            self.assertFalse((data / "config").exists())
            chown.assert_not_called()
