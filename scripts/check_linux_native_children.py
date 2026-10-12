#!/usr/bin/env python3
"""Native child lifetime probe. Synthetic inputs; loopback only, no remote SSH."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import tempfile
from types import SimpleNamespace


def audit_process(status: str, limits: str, uid: int, parent: int | None = None) -> None:
    fields = dict(row.split(":", 1) for row in status.splitlines() if ":" in row)
    if (fields.get("Uid", "").split() != [str(uid)] * 4
            or fields.get("Gid", "").split() != [str(uid)] * 4
            or fields.get("NoNewPrivs", "").strip() != "1"
            or fields.get("Seccomp", "").strip() != "2"
            or any(int(fields.get(key, "1").strip(), 16) for key in ("CapEff", "CapPrm", "CapBnd"))
            or (parent is not None and fields.get("PPid", "").strip() != str(parent))):
        raise RuntimeError("native process protections differ")
    rows = [row.split()[-3:] for row in limits.splitlines() if row.startswith("Max core file size")]
    if rows != [["0", "0", "bytes"]]:
        raise RuntimeError("native core limits are not zero")


def audit_image(manifest: dict, source: Path, requirements: Path) -> None:
    expected = {name[4:]: digest for name, digest in manifest["files"].items() if name.startswith("src/")}
    actual = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in source.rglob("*") if path.is_file()}
    if not expected or actual != expected:
        raise RuntimeError("native probe imported a different image source")
    if hashlib.sha256(requirements.read_bytes()).hexdigest() != manifest["files"]["requirements.txt"]:
        raise RuntimeError("native image requirements differ")


def verify_environment(manifest: Path, uid: int, scratch: Path) -> None:
    import sunny_digest
    from sunny_digest.memory_guard import _cgroup_path, protect_process, verify_native_parent
    from sunny_digest.secret_files import require_private_tmpfs
    from sunny_digest.version import APP_VERSION, COLLECTOR_VERSION

    if (platform.system() != "Linux" or platform.machine() != "x86_64"
            or uid not in (1000, 1001) or os.getuid() != uid
            or Path(sunny_digest.__file__).resolve().parent != Path("/app/src/sunny_digest")
            or (APP_VERSION, COLLECTOR_VERSION) != ("0.3.0", "0.2.1")):
        raise RuntimeError("native image/platform/role differs")
    audit_image(json.loads(manifest.read_text()), Path("/app/src"), Path("/app/requirements.txt"))
    audit_process(Path("/proc/self/status").read_text(), Path("/proc/self/limits").read_text(), uid)
    roots = [row.split()[5].split(",") for row in Path("/proc/self/mountinfo").read_text().splitlines()
             if row.split()[4] == "/"]
    if len(roots) != 1 or "ro" not in roots[0]:
        raise RuntimeError("native probe root filesystem differs")
    if {path.name for path in Path("/sys/class/net").iterdir()} != {"lo"}:
        raise RuntimeError("native probe network is not isolated")
    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").is_file():
        raise RuntimeError("native probe requires cgroup v2")
    group = _cgroup_path(root)
    if {name: (group/name).read_text().strip() for name in ("memory.max", "memory.swap.max", "pids.max")} != {
            "memory.max": "536870912", "memory.swap.max": "0", "pids.max": "96"}:
        raise RuntimeError("native probe cgroup limits differ")
    protect_process()
    verify_native_parent()
    require_private_tmpfs(scratch)
    print(f"NATIVE IMAGE / MEMORY: PASS uid={uid}", flush=True)


def child_pids() -> list[int]:
    return [int(value) for value in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()]


def audit_child(pid: int, comm: str, uid: int) -> None:
    root = Path("/proc") / str(pid)
    if (pid <= 1 or root.joinpath("comm").read_text().strip() != comm
            or pid not in child_pids()):
        raise RuntimeError("observed native child identity differs")
    audit_process((root/"status").read_text(), (root/"limits").read_text(), uid, os.getpid())


def audit_reaped(pid: int) -> None:
    if Path(f"/proc/{pid}").exists():
        raise RuntimeError("native child survives cleanup")
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return
    raise RuntimeError("native child was not reaped by its supervisor")


def audit_scratch(scratch: Path, expected: set[str]) -> None:
    if {path.name for path in scratch.iterdir()} != expected:
        raise RuntimeError("native secret scratch remnants differ")


async def expect_cancelled(task: asyncio.Task) -> None:
    try:
        await asyncio.wait_for(task, timeout=10)
    except asyncio.CancelledError:
        return
    raise RuntimeError("native operation did not acknowledge cancellation")


async def ssh_probe(scratch: Path, uid: int) -> None:
    """Use real production adapters/supervisors; a TCP sink holds SSH before auth."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from sunny_digest.secret_files import secret_files
    from sunny_digest.openrouter_tunnel import OpenRouterTunnel
    from sunny_digest.ssh_transport import SSHTransport
    from sunny_digest.storage import Paths
    from sunny_digest.vault import Vault
    from sunny_digest.vault_storage import VaultPaths

    identity = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    baseline = {path.name for path in scratch.iterdir()}
    accepted = asyncio.Event()
    writers = set()

    def connected(_reader, writer):
        writers.add(writer)
        accepted.set()

    server = await asyncio.start_server(connected, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    task = None
    vault = None
    try:
        if uid == 1000:
            import base64
            # Actual encrypted-record adapter; no fake path and no plaintext fallback.
            vault = Vault(scratch/"synthetic-vault.json")
            vault.initialize("synthetic-native-phrase", {
                "source_id": "synthetic-native", "security_epoch": 1, "policy_revision": 1,
                "records": {"upload-ed25519": base64.b64encode(identity).decode(), "known_hosts": ""},
                "passkeys": {}})
            paths = VaultPaths(Paths(scratch, scratch, scratch, scratch/"unused.sock"), vault, scratch)
            revoked = asyncio.Event()
            transport = SSHTransport(paths, {"host": "127.0.0.1", "port": port, "user": "synthetic"})
            task = asyncio.create_task(transport._exchange("status-v2", b"{}\n", revoked))
            pid = await observe_ssh(task, accepted, scratch, uid)
            revoked.set()
            await expect_cancelled(task)
            audit_reaped(pid)
            audit_scratch(scratch, baseline | {"synthetic-vault.json", "synthetic-vault.json.lock"})
            print("NATIVE RECEIVER SSH: PASS (core zero, revocation, reaped, scratch removed)", flush=True)
        else:
            with secret_files(scratch, {"identity": identity, "known_hosts": b""}) as files:
                tunnel = OpenRouterTunnel(SimpleNamespace(openrouter_key=files["identity"],
                    known_hosts=files["known_hosts"], guarded_native=True),
                    {"host": "127.0.0.1", "port": port})
                task = asyncio.create_task(tunnel.start())
                try:
                    pid = await observe_ssh(task, accepted, scratch, uid)
                    task.cancel()
                    await expect_cancelled(task)
                    audit_reaped(pid)
                    if tunnel._process is not None:
                        raise RuntimeError("native tunnel retained its child")
                finally:
                    # Observation can fail while SSH still uses these files.
                    # Join and stop inside their scope, also on cancellation.
                    try:
                        if not task.done():
                            task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    finally:
                        await tunnel.stop()
            audit_scratch(scratch, baseline)
            print("NATIVE MODEL SSH: PASS (core zero, cancelled start, reaped, scratch removed)", flush=True)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if vault is not None:
            vault.close()
        server.close()
        # Python 3.12 waits for accepted connections as well as the listener.
        # Close the sink's streams first; the SSH client is already reaped.
        for writer in writers:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
        await server.wait_closed()


async def observe_ssh(task, accepted, scratch, uid) -> int:
    async def observed():
        while not accepted.is_set() or not child_pids():
            if task.done():
                task.result()
                raise RuntimeError("native SSH completed before observation")
            await asyncio.sleep(0.02)
        pids = child_pids()
        if len(pids) != 1:
            raise RuntimeError("unexpected native child set")
        pid = pids[0]
        audit_child(pid, "ssh", uid)
        secret_dirs = [path for path in scratch.iterdir() if path.name.startswith("secret-")]
        if len(secret_dirs) != 1 or secret_dirs[0].stat().st_mode & 0o077:
            raise RuntimeError("native SSH scratch directory differs")
        entries = list(secret_dirs[0].iterdir())
        if {path.name for path in entries} != {"identity", "known_hosts"} or any(
                not path.is_file() or path.is_symlink() or path.stat().st_uid != uid
                or stat.S_IMODE(path.stat().st_mode) != 0o600 for path in entries):
            raise RuntimeError("native SSH scratch files differ")
        return pid
    return await asyncio.wait_for(observed(), timeout=10)


async def mihomo_probe(scratch: Path) -> None:
    from sunny_digest.mihomo import MihomoRuntime
    # A syntactically valid node. Network=none and no SOCKS CONNECT is sent.
    node = {"type": "vless", "server": "1.1.1.1", "port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001", "network": "tcp", "tls": True,
        "servername": "example.net", "client-fingerprint": "chrome", "flow": "xtls-rprx-vision",
        "reality-opts": {"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": ""}}
    baseline = {path.name for path in scratch.iterdir()}
    runtime = MihomoRuntime(scratch, runtime_parent=scratch, require_memory_guards=True)
    try:
        await asyncio.wait_for(runtime.start(node), timeout=25)
        runtime.ensure_alive()
        pid = runtime._process.pid
        audit_child(pid, "mihomo", 1000)
        if runtime.paths.config.stat().st_mode & 0o077:
            raise RuntimeError("native Mihomo config permissions differ")
        await runtime.stop()
        audit_reaped(pid)
        audit_scratch(scratch, baseline)
        if runtime._process is not None or runtime.paths is not None or runtime.ready:
            raise RuntimeError("native Mihomo retained runtime state")
        print("NATIVE MIHOMO: PASS (SOCKS handshake, core zero, stopped, reaped, scratch removed)", flush=True)
    finally:
        await runtime.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uid", type=int, choices=(1000, 1001), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    scratch = Path("/run/native-private")
    verify_environment(args.manifest, args.uid, scratch)
    with tempfile.TemporaryDirectory(prefix="native-", dir=scratch) as directory:
        async def run():
            if args.uid == 1000:
                await mihomo_probe(Path(directory))
            await ssh_probe(Path(directory), args.uid)
        asyncio.run(run())
    audit_scratch(scratch, set())
    print(f"NATIVE CHILD CASE EXIT: 0 uid={args.uid}", flush=True)


if __name__ == "__main__":
    main()
