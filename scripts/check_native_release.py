#!/usr/bin/env python3
"""Native Docker release gate on an ephemeral CI runner; synthetic data only.

The host and Docker daemon must match the requested architecture. The existing
amd64 owner probes remain frozen; this runner reuses their exercised case bodies,
with an explicit native architecture audit before any case or fixture input.
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MACHINES = {"amd64": "x86_64", "arm64": "aarch64"}
CONTEXT_LINKS = {"CLAUDE.md": "AGENTS.md"}
CASES = (("units", 1000, 300), ("vault", 1000, 90),
         ("native", 1000, 120), ("native", 1001, 120),
         ("active", 1000, 900), ("migration", 1000, 900))


def require_architecture(architecture):
    if platform.system() != "Linux" or platform.machine() != MACHINES[architecture]:
        raise RuntimeError("native Linux architecture differs")


def command(*args, timeout=30):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=True).stdout


def freeze(source, output):
    """Only tracked public code and build inputs; no checkout-wide mount."""
    names = command("git", "-C", str(source), "ls-files", "-z", "--",
                    "src", "tests", "scripts", "Dockerfile", ".dockerignore",
                    "requirements.txt", "LICENSE", "LICENSES", "THIRD_PARTY_NOTICES.md",
                    "requirements.in", "README.md", "SECURITY.md", "AGENTS.md",
                    "CLAUDE.md", "umbrel-app-store.yml", ".github/workflows",
                    "sunny-personal-digest/docker-compose.yml",
                    "sunny-personal-digest/umbrel-app.yml",
                    "sunny-personal-digest/icon.svg").split("\0")
    names = [name for name in names if name]
    required = {"Dockerfile", ".dockerignore", "requirements.txt",
                "sunny-personal-digest/docker-compose.yml",
                "scripts/check_native_release.py", "scripts/check_linux_crypto.py",
                "scripts/check_linux_native_children.py", "scripts/check_linux_security_state.py",
                "scripts/check_linux_lifecycle.py", "scripts/check_paired_ui.py",
                "scripts/check_security_ui.py", "scripts/check_linux_ui.py"}
    if not required <= set(names) or not any(name.startswith("src/") for name in names):
        raise RuntimeError("native gate source inventory is incomplete")
    output.mkdir(mode=0o755)
    hashes = {}
    links = {}
    for name in names:
        path = source / name
        if path.is_symlink():
            if CONTEXT_LINKS.get(name) != str(path.readlink()):
                raise RuntimeError("unsafe native gate input")
            target = output / name
            target.symlink_to("AGENTS.md")
            links[name] = str(path.readlink())
            continue
        if (any(parent.is_symlink() for parent in path.parents if parent != source.parent)
                or not path.is_file() or any(
                part in {"secrets", "credentials", "data", "__pycache__"}
                or part.startswith(".env") for part in Path(name).parts)
                or (name.startswith(("src/", "tests/", "scripts/"))
                    and path.suffix not in {".py", ".js"})):
            raise RuntimeError("unsafe native gate input")
        blob = path.read_bytes()
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        target.write_bytes(blob)
        target.chmod(0o644)
        hashes[name] = hashlib.sha256(blob).hexdigest()
    manifest = {"format": 1, "source_commit": command("git", "-C", str(source),
                "rev-parse", "HEAD").strip(), "unittest_count": 523,
                "files": hashes, "links": links}
    (output / "probe-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    (output / "probe-manifest.json").chmod(0o644)
    return manifest


def audit_context(context):
    if context.is_symlink() or not context.is_dir():
        raise RuntimeError("native gate context root differs")
    manifest = json.loads((context / "probe-manifest.json").read_text())
    entries = list(context.rglob("*"))
    links = manifest.get("links", {})
    if (not manifest["files"] or context.is_symlink()
            or links != CONTEXT_LINKS
            or any((p.is_symlink() and str(p.relative_to(context)) not in links)
                   or not (p.is_file() or p.is_dir() or p.is_symlink()) for p in entries)
            or {str(p.relative_to(context)) for p in entries if p.is_file() and not p.is_symlink()}
            != set(manifest["files"]) | {"probe-manifest.json"}
            or {str(p.relative_to(context)): str(p.readlink()) for p in entries if p.is_symlink()}
            != links
            or any(not (context / target).is_file() or (context / target).is_symlink()
                   for target in links.values())
            or any(hashlib.sha256((context / name).read_bytes()).hexdigest() != digest
                   for name, digest in manifest["files"].items())):
        raise RuntimeError("native gate context changed")
    return manifest


def require_case_result(mode, uid, result):
    blob = result.stdout + result.stderr
    marker = f"NATIVE RELEASE CASE EXIT: 0 mode={mode} uid={uid}"
    if result.returncode != 0 or blob.splitlines().count(marker) != 1:
        raise RuntimeError("native case failed or completion marker missing")


def audit_native(context, architecture, uid, *, bridge=False):
    require_architecture(architecture)
    import sunny_digest
    from sunny_digest.memory_guard import _cgroup_path, protect_process, verify_native_parent
    from sunny_digest.secret_files import require_private_tmpfs
    from sunny_digest.version import APP_VERSION, COLLECTOR_VERSION
    from check_linux_native_children import audit_image, audit_process
    manifest = audit_context(context)
    if (os.getuid() != uid or uid not in (1000, 1001)
            or Path(sunny_digest.__file__).resolve().parent != Path("/app/src/sunny_digest")
            or (APP_VERSION, COLLECTOR_VERSION) != ("0.3.0", "0.2.1")):
        raise RuntimeError("production image/role differs")
    audit_image(manifest, Path("/app/src"), Path("/app/requirements.txt"))
    audit_process(Path("/proc/self/status").read_text(), Path("/proc/self/limits").read_text(), uid)
    roots = [row.split()[5].split(",") for row in Path("/proc/self/mountinfo").read_text().splitlines()
             if row.split()[4] == "/"]
    if (len(roots) != 1 or "ro" not in roots[0]
            or {p.name for p in Path("/sys/class/net").iterdir()}
            != ({"lo", "eth0"} if bridge else {"lo"})):
        raise RuntimeError("native rootfs/network differs")
    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").is_file():
        raise RuntimeError("native gate requires cgroup v2")
    group = _cgroup_path(root)
    if {name: (group / name).read_text().strip()
            for name in ("memory.max", "memory.swap.max", "pids.max")} != {
            "memory.max": "536870912", "memory.swap.max": "0", "pids.max": "96"}:
        raise RuntimeError("native cgroup limits differ")
    protect_process()
    verify_native_parent()
    require_private_tmpfs(Path("/run/guardian-private"))
    print(f"NATIVE RELEASE ENVIRONMENT: PASS architecture={architecture} uid={uid}", flush=True)
    return manifest, group


def load_ui(context, *, browser=False):
    path = context / "scripts/check_security_ui.py"
    spec = importlib.util.spec_from_file_location("native_release_ui", path)
    gate = importlib.util.module_from_spec(spec)
    if browser:
        spec.loader.exec_module(gate)
    else:
        # The base image has no browser library. Remove only its unused test-host
        # import; keep the fixture, real handler/verifier and every assertion body.
        tree = ast.parse(path.read_text(), filename=str(path))
        imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "playwright.async_api"]
        if (len(imports) != 1 or [(alias.name, alias.asname) for alias in imports[0].names]
                != [("async_playwright", None)]):
            raise RuntimeError("frozen browser import boundary differs")
        tree.body.remove(imports[0])
        exec(compile(tree, str(path), "exec"), gate.__dict__)
    return gate


def container_case(args):
    sys.path.insert(0, str(args.context / "scripts"))
    manifest, group = audit_native(args.context, args.architecture, args.uid, bridge=args.mode == "serve")
    scratch = Path("/run/guardian-private")
    if args.mode == "units":
        from check_linux_crypto import offline_tests
        offline_tests(args.context, manifest)
    elif args.mode == "vault":
        from check_linux_crypto import native_vault
        native_vault(group)
    elif args.mode == "native":
        from check_linux_native_children import mihomo_probe, ssh_probe, audit_scratch
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            async def run():
                if args.uid == 1000:
                    await mihomo_probe(Path(directory))
                await ssh_probe(Path(directory), args.uid)
            asyncio.run(run())
        audit_scratch(scratch, set())
    elif args.mode == "active":
        from check_linux_security_state import active_case
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            asyncio.run(active_case(Path(directory)))
    elif args.mode == "migration":
        from check_linux_security_state import PHASES, migration_case
        def crash(stage, phase):
            result = subprocess.run([sys.executable, "-B", __file__, "crash",
                "--context=" + str(args.context), "--architecture=" + args.architecture,
                "--uid=1000", "--root=" + str(stage), "--phase=" + phase],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45)
            if result.returncode != 75 or result.stdout.splitlines().count("MIGRATION CRASH BARRIER: " + phase) != 1:
                raise RuntimeError("native migration crash barrier differs")
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            for phase in PHASES:
                stage = Path(directory) / phase
                stage.mkdir(mode=0o700)
                asyncio.run(migration_case(stage, phase, crash))
    elif args.mode == "crash":
        from check_linux_security_state import PHASES, crash_child
        if (args.root is None or args.phase not in PHASES
                or not args.root.resolve().is_relative_to(scratch)):
            raise RuntimeError("native crash scope differs")
        asyncio.run(crash_child(args.root, args.phase))
        raise RuntimeError("migration crash child did not exit")
    elif args.mode == "serve":
        from check_paired_ui import fixture_server, NATIVE_LINE
        access = json.loads(Path("/probe-access/access.json").read_text())
        server = fixture_server(load_ui(args.context), access, ("0.0.0.0", 8080), guard=NATIVE_LINE)
        server.timeout = 1
        # The parent bounds this temporary fixture; no daemon or restart policy.
        try:
            server.serve_forever()
        finally:
            server.server_close()
        raise RuntimeError("native UI fixture stopped unexpectedly")
    print(f"NATIVE RELEASE CASE EXIT: 0 mode={args.mode} uid={args.uid}", flush=True)


def ui_client(context, port, access, output):
    """Verified loopback TLS to native HTTP; frozen browser assertions unchanged."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from check_paired_ui import Backend, browser_gate, NATIVE_LINE
    from check_linux_ui import verify_screenshots
    gate = load_ui(context, browser=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic native CI loopback")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .sign(key, hashes.SHA256()))
    with tempfile.TemporaryDirectory() as directory:
        cert_path, key_path = Path(directory) / "cert.bin", Path(directory) / "key.bin"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        cert_path.chmod(0o600); key_path.chmod(0o600)
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def forward(self):
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 512 * 1024:
                    self.send_error(413); return
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.request(self.command, self.path, self.rfile.read(size), dict(self.headers))
                    response = connection.getresponse()
                    body = response.read(512 * 1024 + 1)
                    if len(body) > 512 * 1024:
                        self.send_error(502); return
                    self.send_response(response.status)
                    for header, value in response.getheaders():
                        if header.lower() not in {"connection", "transfer-encoding", "server", "date"}:
                            self.send_header(header, value)
                    self.end_headers(); self.wfile.write(body)
                finally:
                    connection.close()
            do_GET = do_POST = forward
        server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        backend = Backend("127.0.0.1", server.server_address[1], access,
                          tls=ssl.create_default_context(cafile=str(cert_path)))
        try:
            if backend.control("snapshot")["guard"] != NATIVE_LINE:
                raise RuntimeError("native UI receipt missing")
            output.mkdir(mode=0o700)
            asyncio.run(browser_gate(gate, backend, None, output))
            verify_screenshots(output)
            backend.control("finish", {"result": "pass"})
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=10)
    print("NATIVE RELEASE UI: PASS (sandbox, verified TLS, native handler, 3 decoded PNGs)", flush=True)


class DockerGate:
    def __init__(self, image, scope):
        self.image, self.scope, self.containers, self.network = image, scope, [], None

    def create(self, context, mode, uid, *, access=None):
        name = f"{self.scope}-{mode}-{uid}"
        args = ["docker", "create", "--name", name, "--label", "sunny.native-release=" + self.scope,
                "--user", f"{uid}:{uid}", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                "--init", "--memory=512m", "--memory-swap=512m", "--pids-limit=96", "--ulimit=core=0:0",
                "--ulimit=memlock=8388608:8388608", "--log-driver=none", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
                "--tmpfs", f"/run/guardian-private:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid={uid},gid={uid}",
                "--mount", f"type=bind,source={context},target=/probe,readonly"]
        if access:
            args += ["--network", self.network, "-p", "127.0.0.1::8080", "--mount",
                     f"type=bind,source={access},target=/probe-access,readonly"]
        else:
            args += ["--network=none"]
        args += ["--entrypoint=python", self.image, "-B", "/probe/scripts/check_native_release.py", mode,
                 "--context=/probe", "--architecture=" + self.architecture, "--uid=" + str(uid)]
        # Inventory the unique label even if create times out after creating it.
        cid = command(*args).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise RuntimeError("created container ID differs")
        self.containers.append(cid)
        return cid

    def cleanup(self):
        ids = command("docker", "ps", "--all", "--quiet", "--no-trunc", "--filter",
                      "label=sunny.native-release=" + self.scope).splitlines()
        for cid in set(ids) | set(self.containers):
            rows = json.loads(command("docker", "inspect", cid))
            if (len(rows) != 1 or rows[0]["Id"] != cid or rows[0]["Image"] != self.image
                    or rows[0]["Config"]["Labels"].get("sunny.native-release") != self.scope
                    or not rows[0]["Name"].startswith("/" + self.scope + "-")):
                raise RuntimeError("refusing cleanup of an unowned container")
            command("docker", "rm", "-f", cid)
        if command("docker", "ps", "--all", "--quiet", "--filter", "label=sunny.native-release=" + self.scope).strip():
            raise RuntimeError("native containers remain")
        for cid in self.containers:
            probe = subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, timeout=30)
            if probe.returncode == 0 or "No such object" not in probe.stderr:
                raise RuntimeError("saved native container ID remains or cannot be checked")
        networks = command("docker", "network", "ls", "--quiet", "--no-trunc", "--filter",
                           "label=sunny.native-release=" + self.scope).splitlines()
        if self.network and networks != [self.network]:
            raise RuntimeError("saved native network identity differs")
        if len(networks) > 1:
            raise RuntimeError("unexpected extra native network")
        for network in networks:
            rows = json.loads(command("docker", "network", "inspect", network))
            if (len(rows) != 1 or rows[0]["Id"] != network or rows[0]["Name"] != self.scope
                    or rows[0]["Labels"].get("sunny.native-release") != self.scope or rows[0]["Containers"]):
                raise RuntimeError("refusing cleanup of an unowned network")
            command("docker", "network", "rm", network)
            probe = subprocess.run(["docker", "network", "inspect", network], capture_output=True, text=True, timeout=30)
            if probe.returncode == 0 or "not found" not in probe.stderr.lower():
                raise RuntimeError("saved native network remains or cannot be checked")
        if command("docker", "network", "ls", "--quiet", "--filter", "label=sunny.native-release=" + self.scope).strip():
            raise RuntimeError("native network remains")
        print("NATIVE RELEASE CLEANUP: PASS (saved IDs and unique labels absent)", flush=True)


def host_gate(args):
    require_architecture(args.architecture)
    info = json.loads(command("docker", "info", "--format", "{{json .}}"))
    images = json.loads(command("docker", "image", "inspect", args.image))
    if (info["OSType"] != "linux" or info["Architecture"] not in (args.architecture, MACHINES[args.architecture])
            or str(info["CgroupVersion"]) != "2" or len(images) != 1
            or images[0]["Os"] != "linux" or images[0]["Architecture"] != args.architecture
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", images[0]["Id"])):
        raise RuntimeError("native daemon/image architecture or cgroup differs")
    image = images[0]["Id"]
    scope = "sunny-native-release-" + uuid.uuid4().hex[:12]
    args.out_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix=scope + "-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        context = root / "context"
        manifest = freeze(Path(__file__).resolve().parent.parent, context)
        (args.out_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        gate = DockerGate(image, scope)
        gate.architecture = args.architecture
        try:
            for mode, uid, deadline in CASES:
                cid = gate.create(context, mode, uid)
                result = subprocess.run(["docker", "start", "--attach", cid], stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, timeout=deadline)
                blob = result.stdout + result.stderr
                (args.out_dir / f"{mode}-{uid}.log").write_text(blob)
                (args.out_dir / f"{mode}-{uid}.exit").write_text(str(result.returncode) + "\n")
                print(blob, end="", flush=True)
                require_case_result(mode, uid, result)
            access_dir = root / "access"
            access_dir.mkdir(mode=0o755)
            access = {"password": secrets.token_urlsafe(32), "control": secrets.token_urlsafe(32)}
            # Random test-only values. Read access is confined to this temporary CI fixture.
            (access_dir / "access.json").write_text(json.dumps(access))
            (access_dir / "access.json").chmod(0o644)
            gate.network = command("docker", "network", "create", "--label", "sunny.native-release=" + scope,
                "--opt", "com.docker.network.bridge.enable_ip_masquerade=false", scope).strip()
            if not re.fullmatch(r"[0-9a-f]{64}", gate.network):
                raise RuntimeError("native network ID differs")
            cid = gate.create(context, "serve", 1000, access=access_dir)
            command("docker", "start", cid)
            ports = json.loads(command("docker", "inspect", cid))[0]["NetworkSettings"]["Ports"]["8080/tcp"]
            if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
                raise RuntimeError("native UI port is not private loopback")
            port = int(ports[0]["HostPort"])
            # Wait for HTTP, with no state change or form replay.
            import time
            until = time.monotonic() + 30
            while True:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    connection.request("GET", "/")
                    if connection.getresponse().status == 401:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                if time.monotonic() >= until:
                    raise RuntimeError("native UI server did not become ready")
                time.sleep(0.2)
            ui_client(context, port, access, args.out_dir / "screenshots")
            audit_context(context)
        finally:
            gate.cleanup()
    print(f"NATIVE RELEASE GATE EXIT: 0 architecture={args.architecture} image={image}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("host", "units", "vault", "native", "active", "migration", "crash", "serve"))
    parser.add_argument("--architecture", required=True, choices=tuple(MACHINES))
    parser.add_argument("--image")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--context", type=Path, default=Path("/probe"))
    parser.add_argument("--uid", type=int, choices=(1000, 1001), default=1000)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--phase")
    args = parser.parse_args()
    if args.mode == "host":
        if not args.image or not args.out_dir:
            parser.error("host requires --image and --out-dir")
        host_gate(args)
    else:
        container_case(args)


if __name__ == "__main__":
    main()
