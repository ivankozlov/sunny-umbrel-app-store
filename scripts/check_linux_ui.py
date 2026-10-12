#!/usr/bin/env python3
"""Existing UI gate on the exact candidate sources, in a synthetic browser overlay."""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import zlib

TOOL_PACKAGES = {"pip", "setuptools", "wheel"}
UI_PACKAGES = {"playwright": "1.58.0", "pyee": "13.0.1", "greenlet": "3.5.6", "typing-extensions": "4.16.0", "pillow": "12.3.0"}


def packages():
    from importlib.metadata import distributions
    result = {}
    for dist in distributions():
        name = dist.metadata['Name'].lower().replace('_', '-')
        if name in TOOL_PACKAGES:
            continue
        row = {"version": dist.version, "location": str(dist.locate_file('').resolve())}
        if name in result and result[name] != row:
            raise RuntimeError("duplicate/shadowed production distribution")
        result[name] = row
    return result


def verify_packages(baseline, current):
    if not baseline or any(current.get(name) != row for name, row in baseline.items()):
        raise RuntimeError("UI overlay changed/shadowed production dependencies")
    if set(current)-set(baseline) != set(UI_PACKAGES)-set(baseline):
        raise RuntimeError("unexpected UI dependency inventory")
    if any(current[name]['version'] != version for name, version in UI_PACKAGES.items()):
        raise RuntimeError("UI dependency version differs")


def verify_screenshots(root):
    from PIL import Image
    expected = {'locked.png', 'configure.png', 'restart-recovered.png'}
    if {p.name for p in root.iterdir()} != expected:
        raise RuntimeError("UI screenshot inventory missing/extra")
    for name in expected:
        path = root/name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("UI screenshot type differs")
        blob = path.read_bytes()
        ending = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', zlib.crc32(b'IEND'))
        if len(blob) < 1024 or not blob.endswith(ending):
            raise RuntimeError("UI screenshot is empty/invalid")
        try:
            with Image.open(io.BytesIO(blob)) as picture:
                if picture.format != 'PNG':
                    raise ValueError('expected PNG')
                picture.verify()
            with Image.open(io.BytesIO(blob)) as picture:
                picture.load()
        except (OSError, SyntaxError, ValueError) as error:
            raise RuntimeError("UI screenshot is empty/invalid") from error
        path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True, type=Path)
    parser.add_argument('--out-dir', required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.context/'scripts'))
    from check_linux_crypto import verify_image
    verify_image(args.context)
    verify_packages(json.loads(Path('/ui/base-packages.json').read_text()), packages())
    print('UI OVERLAY PRODUCTION DEPENDENCIES: PASS')
    spec = importlib.util.spec_from_file_location('frozen_security_ui', args.context/'scripts/check_security_ui.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    args.out_dir.mkdir(mode=0o700, exist_ok=True)
    asyncio.run(asyncio.wait_for(gate.gate(None, args.out_dir), timeout=90))
    verify_screenshots(args.out_dir)
    print('UI SCREENSHOTS: PASS count=3')
    print('LINUX UI CASE EXIT: 0')


if __name__ == '__main__':
    main()
