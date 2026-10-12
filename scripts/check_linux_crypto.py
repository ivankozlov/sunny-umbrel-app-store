#!/usr/bin/env python3
"""Offline checks of the actual candidate image; all vault data is synthetic."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import platform
import resource
import sys
import tempfile
import time
import unittest


def verify_image(context: Path) -> tuple[dict, Path]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("this stage requires native Linux amd64")
    import sunny_digest
    from sunny_digest.memory_guard import _cgroup_path, protect_process, verify_native_parent
    from sunny_digest.secret_files import require_private_tmpfs
    from sunny_digest.version import APP_VERSION, COLLECTOR_VERSION

    if Path(sunny_digest.__file__).resolve().parent != Path("/app/src/sunny_digest"):
        raise RuntimeError("package is not imported from the production image")
    if (APP_VERSION, COLLECTOR_VERSION) != ("0.3.0", "0.2.1"):
        raise RuntimeError("image version differs")
    manifest = json.loads((context / "probe-manifest.json").read_text())
    files = manifest["files"]
    expected = {name[4:]: value for name, value in files.items() if name.startswith("src/")}
    actual = {str(p.relative_to("/app/src")): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in Path("/app/src").rglob("*") if p.is_file()}
    if not expected or actual != expected:
        raise RuntimeError("image source differs from the frozen context")
    if hashlib.sha256(Path("/app/requirements.txt").read_bytes()).hexdigest() != files["requirements.txt"]:
        raise RuntimeError("image requirements differ from the frozen context")
    status = dict(row.split(":", 1) for row in Path("/proc/self/status").read_text().splitlines() if ":" in row)
    for key, value in {"Uid": ["1000"] * 4, "Gid": ["1000"] * 4,
                       "NoNewPrivs": ["1"], "Seccomp": ["2"]}.items():
        if status[key].split() != value:
            raise RuntimeError("actual process isolation differs")
    if int(status["CapEff"].strip(), 16) != 0:
        raise RuntimeError("process capabilities are not empty")
    roots = [row.split()[5].split(",") for row in Path("/proc/self/mountinfo").read_text().splitlines()
             if row.split()[4] == "/"]
    if len(roots) != 1 or "ro" not in roots[0]:
        raise RuntimeError("root filesystem is not read-only")
    if {p.name for p in Path("/sys/class/net").iterdir()} != {"lo"}:
        raise RuntimeError("container network is not isolated")
    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").is_file():
        raise RuntimeError("this stage requires cgroup v2")
    cgroup = _cgroup_path(root)
    if (cgroup / "memory.max").read_text().strip() != "536870912":
        raise RuntimeError("actual RAM limit differs from 512 MiB")
    protect_process()
    verify_native_parent()
    require_private_tmpfs(Path("/run/guardian-private"))
    print("CANDIDATE IMAGE / MEMORY: PASS (exact source, UID 1000, network none, RAM 512 MiB, zero swap/core)")
    return manifest, cgroup


def offline_tests(context: Path, manifest: dict) -> None:
    # Import sunny_digest before discovery: test helper sys.path edits must not
    # redirect the package away from the actual image's /app/src.
    # Shared helpers use tests.*; discovery alone adds only /probe/tests.
    sys.path.insert(0, str(context))
    suite = unittest.defaultTestLoader.discover(str(context / "tests"))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if (not result.wasSuccessful() or result.testsRun != manifest["unittest_count"]
            or result.skipped or result.expectedFailures or result.unexpectedSuccesses):
        raise RuntimeError("offline suite failed, skipped tests or ran a different count")
    for name, module in tuple(sys.modules.items()):
        if name.startswith("sunny_digest.") and getattr(module, "__file__", None):
            if not Path(module.__file__).resolve().is_relative_to("/app/src/sunny_digest"):
                raise RuntimeError("offline suite imported a package copy outside the image")
    print("CANDIDATE OFFLINE TESTS: PASS count=" + str(result.testsRun))


def native_vault(cgroup: Path) -> None:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from sunny_digest.vault import KDF, Vault, VaultAuthenticationError, VaultLockedError

    if KDF != {"name": "argon2id", "memory_kib": 65536, "iterations": 3, "lanes": 4, "length": 32}:
        raise RuntimeError("production Argon2 profile differs")
    def locked_kib():
        values = [int(row.split()[1]) for row in Path("/proc/self/status").read_text().splitlines()
                  if row.startswith("VmLck:")]
        if len(values) != 1:
            raise RuntimeError("locked-page metric is unavailable")
        return values[0]
    baseline = locked_kib()
    durations = []
    for _ in range(3):
        start = time.perf_counter()
        value = Argon2id(salt=b"synthetic-salt-00", length=KDF["length"],
                        iterations=KDF["iterations"], lanes=KDF["lanes"],
                        memory_cost=KDF["memory_kib"]).derive(b"synthetic-benchmark-phrase")
        if len(value) != 32:
            raise RuntimeError("Argon2 result size differs")
        durations.append(round((time.perf_counter() - start) * 1000, 2))
    canary = b"SYNTHETIC-NATIVE-VAULT-CANARY"
    snapshot = {"source_id": "synthetic-linux-acceptance", "security_epoch": 1,
                "policy_revision": 1, "records": {
                    "telegram.session.txt": base64.b64encode(canary).decode()}, "passkeys": {}}
    with tempfile.TemporaryDirectory(prefix="sunny-vault-probe-", dir="/run/guardian-private") as directory:
        path = Path(directory) / "vault.json"
        vault = Vault(path)
        try:
            vault.initialize("synthetic-correct-phrase", snapshot)
            locked = locked_kib()
            if locked - baseline < 4:
                raise RuntimeError("native vault did not lock its data key page")
        finally:
            vault.close()
        if canary in path.read_bytes():
            raise RuntimeError("vault persisted plaintext")
        vault = Vault(path)
        try:
            if vault.unlock("synthetic-correct-phrase") != snapshot:
                raise RuntimeError("native vault round trip differs")
        finally:
            vault.close()
        vault = Vault(path)
        try:
            try:
                vault.unlock("synthetic-wrong-phrase")
            except VaultAuthenticationError:
                pass
            else:
                raise RuntimeError("vault accepted the wrong phrase")
            try:
                vault.snapshot
            except VaultLockedError:
                pass
            else:
                raise RuntimeError("failed unlock left vault open")
        finally:
            vault.close()
    if locked_kib() != baseline:
        raise RuntimeError("native vault did not release its locked page")
    print("VAULT LOCKED PAGE: before_kib=" + str(baseline) + " open_kib=" + str(locked)
          + " closed_kib=" + str(locked_kib()))
    print("ARGON2ID: profile=64MiB/3/4 samples_ms=" + json.dumps(durations))
    print("MEMORY: process_peak_rss_kib=" + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
          + " cgroup_peak_bytes=" + (cgroup / "memory.peak").read_text().strip())
    print("NATIVE VAULT: PASS (production guards, encrypted tmpfs, round trip, wrong phrase, closed key buffer)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("units", "vault"))
    parser.add_argument("--context", type=Path, required=True)
    args = parser.parse_args()
    manifest, cgroup = verify_image(args.context)
    if args.mode == "units":
        offline_tests(args.context, manifest)
    else:
        native_vault(cgroup)
    print("CANDIDATE CASE EXIT: 0 mode=" + args.mode)


if __name__ == "__main__":
    main()
