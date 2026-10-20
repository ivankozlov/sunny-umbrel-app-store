#!/usr/bin/env python3
"""The frozen synthetic UI gate with its HTTP backend on the native candidate.

Chromium runs on the Mac, with its sandbox enabled. The native server uses the
unchanged production handler, JS and WebAuthn verifier; it never starts Chromium.
The fixture control API is test-only, authenticated separately, and exposes no
working app data. This file is outside the frozen production build allowlist.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import platform
import re
import secrets
import ssl
import sys
import threading
import time
import types

MANIFEST = "6eb6887f6adf56a076aea82339fd42746c1b5beddab1cfd872663aea53c49b37"
NATIVE_LINE = "PAIRED NATIVE IMAGE / MEMORY / PACKAGES: PASS"
CONTROL = "/__paired/"
LIMIT = 512 * 1024


def frozen_context(root):
    paths = list(root.rglob("*"))
    if root.is_symlink() or any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in paths):
        raise ValueError("unsafe frozen context")
    blob = (root / "probe-manifest.json").read_bytes()
    if hashlib.sha256(blob).hexdigest() != MANIFEST:
        raise ValueError("frozen manifest differs")
    files = json.loads(blob)["files"]
    if not files or {str(p.relative_to(root)) for p in paths if p.is_file()} != set(files) | {"probe-manifest.json"}:
        raise ValueError("frozen context inventory differs")
    if any(hashlib.sha256((root / name).read_bytes()).hexdigest() != digest for name, digest in files.items()):
        raise ValueError("frozen source differs")
    return files


def load_gate(context):
    frozen_context(context)
    spec = importlib.util.spec_from_file_location("frozen_security_ui", context / "scripts/check_security_ui.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def access_file(path):
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_mode & 0o7777 != 0o600 or info.st_uid != __import__("os").getuid():
        raise ValueError("synthetic access file identity differs")
    value = json.loads(path.read_text())
    if (set(value) != {"password", "control"} or value["password"] == value["control"]
            or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", v) for v in value.values())):
        raise ValueError("synthetic access fields differ")
    return value


def native_guard(context):
    """The bridge is the explicit server transport delta; memory guards stay real."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("native Linux amd64 required")
    import sunny_digest
    from sunny_digest.memory_guard import _cgroup_path, protect_process, verify_native_parent
    from sunny_digest.secret_files import require_private_tmpfs
    from sunny_digest.version import APP_VERSION, COLLECTOR_VERSION
    files = frozen_context(context)
    if (Path(sunny_digest.__file__).resolve().parent != Path("/app/src/sunny_digest")
            or (APP_VERSION, COLLECTOR_VERSION) != ("0.3.0", "0.2.1")):
        raise RuntimeError("production package/version differs")
    expected = {name[4:]: digest for name, digest in files.items() if name.startswith("src/")}
    actual = {str(p.relative_to("/app/src")): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in Path("/app/src").rglob("*") if p.is_file()}
    if not expected or actual != expected or hashlib.sha256(Path("/app/requirements.txt").read_bytes()).hexdigest() != files["requirements.txt"]:
        raise RuntimeError("production source/requirements differs")
    status = dict(row.split(":", 1) for row in Path("/proc/self/status").read_text().splitlines() if ":" in row)
    for key, value in {"Uid": ["1000"] * 4, "Gid": ["1000"] * 4, "NoNewPrivs": ["1"], "Seccomp": ["2"]}.items():
        if status[key].split() != value:
            raise RuntimeError("actual process isolation differs")
    roots = [row.split()[5].split(",") for row in Path("/proc/self/mountinfo").read_text().splitlines() if row.split()[4] == "/"]
    if (int(status["CapEff"].strip(), 16) != 0 or len(roots) != 1 or "ro" not in roots[0]
            or {p.name for p in Path("/sys/class/net").iterdir()} != {"lo", "eth0"}):
        raise RuntimeError("capabilities/rootfs/server interfaces differ")
    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").is_file() or (_cgroup_path(root) / "memory.max").read_text().strip() != "536870912":
        raise RuntimeError("actual cgroup/RAM differs")
    protect_process()
    verify_native_parent()
    require_private_tmpfs(Path("/run/guardian-private"))
    sys.path.insert(0, "/ui")
    from check_linux_ui import packages, verify_packages
    verify_packages(json.loads(Path("/ui/base-packages.json").read_text()), packages())
    return NATIVE_LINE


def snapshot(fixture, guard, result):
    calls = []
    for command, data in fixture.calls:
        # Preserve exactly the fields asserted by the frozen browser gate.
        value = None
        if command == "operation_begin":
            payload = data["payload"]
            value = {"operation": data["operation"], "payload": {
                key: payload[key] for key in ("telegram_api_id", "openrouter_model", "chat_ids") if key in payload}}
        calls.append([command, value])
    return {"guard": guard, "state": fixture.state, "phase": fixture.phase,
            "token": fixture.token, "credentials": {key: {"name": value["name"]} for key, value in fixture.credentials.items()},
            "calls": calls, "result": result}


def verify_finish(fixture):
    operations = [data["operation"] for command, data in fixture.calls if command == "operation_begin"]
    if (fixture.state != "locked" or fixture.phase != "configured" or operations != ["unlock", "configure", "select_chats", "passkey_add", "lock"]
            or {row["name"] for row in fixture.credentials.values()} != {"Main synthetic passkey", "Backup synthetic passkey"}
            or len(fixture.credentials) != 2 or fixture.unavailable_reads != 0):
        raise ValueError("native UI sequence incomplete")


def fixture_server(gate, access, address, *, guard, prefix=""):
    mutex = threading.RLock()

    class Fixture(gate.PolicyFixture):
        def request(self, command, data=None):
            with mutex:
                return super().request(command, data)

    class Handler(gate.SecureHandler):
        def native_path(self):
            if not prefix:
                return True
            if self.path == prefix:
                self.path = "/"
                return True
            if self.path.startswith(prefix + "/"):
                self.path = self.path[len(prefix):]
                return True
            return False

        def control_auth(self):
            return self._basic() and secrets.compare_digest(self.headers.get("X-Sunny-Probe-Control", ""), access["control"])

        def control_result(self, value):
            body = json.dumps(value, ensure_ascii=False).encode()
            self._headers(200, "application/json; charset=utf-8", len(body))
            self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            if not self.native_path():
                return self._deny()
            if not self.path.startswith(CONTROL):
                return super().do_GET()
            if self.path != CONTROL + "snapshot" or not self.control_auth():
                return self._deny()
            with mutex:
                self.control_result(snapshot(self.server.ipc, guard, self.server.result))

        def do_POST(self):
            if not self.native_path():
                return self._deny()
            if not self.path.startswith(CONTROL):
                return super().do_POST()
            if not self.control_auth():
                return self._deny()
            try:
                with mutex:
                    value = self._json()
                    if self.path == CONTROL + "dialogs" and value == {"phase": "dialogs_listed"}:
                        if self.server.ipc.state != "unlocked" or self.server.ipc.phase != "configured" or self.server.dialogs_used:
                            raise ValueError("fixture phase is not ready")
                        self.server.ipc.phase = "dialogs_listed"
                        self.server.dialogs_used = True
                    elif self.path == CONTROL + "finish" and value in ({"result": "pass"}, {"result": "fail"}):
                        if self.server.result is not None:
                            raise ValueError("fixture already finished")
                        if value["result"] == "pass":
                            verify_finish(self.server.ipc)
                        self.server.result = value["result"]
                    else:
                        raise ValueError("unknown fixture control")
                    self.control_result({"ok": True})
            except Exception:
                self._deny()

    server = gate.SecureAppServer(address, Handler, ipc=Fixture(), username="sunny", password=access["password"])
    server.result, server.dialogs_used = None, False
    return server


class Backend:
    def __init__(self, host, port, access, *, tls=None):
        self.host, self.port, self.access = host, port, access
        self.tls = tls or ssl.create_default_context()
        if self.tls.verify_mode != ssl.CERT_REQUIRED or not self.tls.check_hostname:
            raise ValueError("verified HTTPS is required")

    def headers(self, original, *, control=False):
        values = {key: value for key, value in original.items() if key.lower() not in {"host", "authorization", "x-sunny-probe-control"}}
        values["Host"] = self.host + ":" + str(self.port)
        values["Authorization"] = "Basic " + base64.b64encode(("sunny:" + self.access["password"]).encode()).decode()
        if control:
            values["X-Sunny-Probe-Control"] = self.access["control"]
        return values

    def control(self, action, value=None):
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=10, context=self.tls)
        try:
            body = json.dumps(value).encode() if value is not None else None
            connection.request("POST" if body else "GET", CONTROL + action, body, self.headers({"Content-Type": "application/json"}, control=True))
            response = connection.getresponse()
            blob = response.read(LIMIT + 1)
            if response.status != 200 or len(blob) > LIMIT:
                raise RuntimeError("fixture control refused/oversized")
            return json.loads(blob)
        finally:
            connection.close()

    def connection(self, host, port, timeout):
        if (host, port, timeout) != ("127.0.0.1", 0, 10):
            raise ValueError("frozen HTTP boundary differs")
        backend = self

        class Connection:
            def __init__(self):
                self.inner = http.client.HTTPSConnection(backend.host, backend.port, timeout=timeout, context=backend.tls)

            def request(self, method, path, body=None, headers=None):
                if (method, path) not in {("GET", "/"), ("GET", "/security.js"), ("POST", "/api")}:
                    raise ValueError("unexpected browser request")
                self.inner.request(method, path, body, backend.headers(headers or {}))

            def getresponse(self):
                return self.inner.getresponse()

            def close(self):
                self.inner.close()

        return Connection()


def paired_ui_host(value):
    if not value:
        raise RuntimeError("explicit paired UI host required")
    return value


async def browser_gate(gate, backend, browser, output):
    if sys.flags.optimize:
        raise RuntimeError("the frozen UI assertions must be enabled")
    class Fixture:
        def __getattr__(self, name):
            if name not in {"state", "credentials", "token", "calls", "phase"}:
                raise AttributeError(name)
            return backend.control("snapshot")[name]

        def __setattr__(self, name, value):
            if (name, value) != ("phase", "dialogs_listed"):
                raise ValueError("unexpected fixture assignment")
            backend.control("dialogs", {"phase": value})

    class Server:
        server_address = ("127.0.0.1", 0)

        def __init__(self, address, handler, *, ipc, username, password):
            if address != self.server_address or not isinstance(ipc, Fixture) or username != "sunny" or password != "synthetic-app-password":
                raise ValueError("frozen server boundary differs")

        def serve_forever(self): pass
        def shutdown(self): pass
        def server_close(self): pass

    # Copy only this function's global namespace. Do not edit the frozen file,
    # monkeypatch stdlib HTTP globally, or replace any browser assertions.
    namespace = dict(gate.gate.__globals__, PolicyFixture=Fixture, SecureAppServer=Server,
                     http=types.SimpleNamespace(client=types.SimpleNamespace(HTTPConnection=backend.connection)))
    paired = types.FunctionType(gate.gate.__code__, namespace, gate.gate.__name__)
    await asyncio.wait_for(paired(browser, output), timeout=180)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--access", type=Path, required=True)
    parser.add_argument("--browser")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--prefix")
    parser.add_argument("--host")
    args = parser.parse_args()
    access = access_file(args.access)
    if args.mode == "server":
        if not args.prefix or not re.fullmatch(r"/sunny-paired-ui\.[A-Za-z0-9]{6}", args.prefix):
            raise ValueError("unique native proxy prefix required")
        guard = native_guard(args.context)
        gate = load_gate(args.context)
        server = fixture_server(gate, access, ("0.0.0.0", 8080), guard=guard, prefix=args.prefix)
        server.timeout = 1
        deadline = time.monotonic() + 1200
        try:
            while time.monotonic() < deadline:
                server.handle_request()
        finally:
            server.server_close()
        raise SystemExit(1)
    if platform.system() != "Darwin" or not args.out_dir or not args.browser:
        raise RuntimeError("explicit Mac browser/output required")
    from check_linux_ui import verify_screenshots
    backend = Backend(paired_ui_host(args.host), 9444, access)
    if backend.control("snapshot")["guard"] != NATIVE_LINE:
        raise RuntimeError("native backend receipt missing")
    args.out_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        asyncio.run(browser_gate(load_gate(args.context), backend, args.browser, args.out_dir))
        verify_screenshots(args.out_dir)
        backend.control("finish", {"result": "pass"})
    except BaseException:
        try: backend.control("finish", {"result": "fail"})
        except Exception: pass
        raise
    print("PAIRED MAC UI CHECK EXIT: 0 (native backend; 3 decoded screenshots)")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("PAIRED UI STOP: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
