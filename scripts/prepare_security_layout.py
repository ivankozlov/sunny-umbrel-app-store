#!/usr/bin/env python3
"""Prepare only the known Personal Chats role directories on an Umbrel host."""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


APP_DATA_DIR = Path("/home/umbrel/umbrel/app-data/sunny-personal-digest")
DIRECTORIES = (
    (Path("data/config"), 1000, 1000, 0o700),
    (Path("data/private"), 1000, 1000, 0o700),
    (Path("data/runtime"), 1000, 1000, 0o700),
    (Path("data/runtime/ipc"), 1000, 1000, 0o700),
    (Path("data/runtime/ipc/jobs"), 1000, 1001, 0o2750),
    (Path("data/runtime/ipc/admin"), 1000, 1002, 0o2750),
)


def _state(path: Path) -> tuple[int, int, int]:
    info = path.stat()
    return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)


def _symlink_ancestor(root: Path, path: Path) -> Path | None:
    """Return a symlink in the controlled path, including a non-leaf parent."""
    current = root
    if current.is_symlink():
        return current
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return current
    return None


def prepare(*, apply: bool, root: Path = APP_DATA_DIR) -> int:
    if root != APP_DATA_DIR:
        print("refusing a non-canonical APP_DATA_DIR", file=sys.stderr)
        return 2
    if apply and os.geteuid() != 0:
        print("refusing --apply without root", file=sys.stderr)
        return 1
    if root.is_symlink() or not root.is_dir():
        print(f"refusing missing or non-directory APP_DATA_DIR: {root}", file=sys.stderr)
        return 1
    missing = []
    known = {root / relative for relative, *_ in DIRECTORIES}
    for relative, uid, gid, mode in DIRECTORIES:
        path = root / relative
        symlink = _symlink_ancestor(root, path)
        if symlink is not None:
            print(f"refusing symlink: {symlink}", file=sys.stderr)
            return 1
        if path.exists():
            if not path.is_dir():
                print(f"refusing non-directory: {path}", file=sys.stderr)
                return 1
            if _state(path) != (uid, gid, mode):
                print(f"refusing existing directory with unexpected owner/mode: {path}", file=sys.stderr)
                return 1
        else:
            parent = path.parent
            if not parent.is_dir() and parent not in known:
                print(f"refusing missing or symlink parent: {parent}", file=sys.stderr)
                return 1
            missing.append((path, uid, gid, mode))
    for path, uid, gid, mode in missing:
        print(("create" if apply else "would create") + f" {path} uid={uid} gid={gid} mode={mode:04o}")
    if not apply:
        return 0
    for path, uid, gid, mode in missing:
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare the fixed Sunny security directory layout")
    parser.add_argument("--apply", action="store_true", help="create missing known directories")
    args = parser.parse_args()
    return prepare(apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
