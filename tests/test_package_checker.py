from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_package  # noqa: E402
import check_native_release  # noqa: E402
from check_package import (  # noqa: E402
    APP,
    ROOT,
    host_code_errors,
    private_markers,
    private_marker_errors,
    role_layout_errors,
    telegram_client_guard,
    telegram_probe_guard,
)


class TestBugPackageHostCode20261018(unittest.TestCase):
    """18.10.2026: the owner's post-start hook must survive Store Updates.

    umbreld runs app hooks as root and an Update copies hooks/, exports.sh,
    *.template and torrc from the Store template over app-data.
    """

    def package(self, tmp, build):
        app = Path(tmp) / "sunny-personal-digest"
        (app / "data/config").mkdir(parents=True)
        (app / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        build(app)
        return app

    def test_actual_package_has_no_host_code(self):
        self.assertEqual(host_code_errors(APP), [])

    def test_clean_synthetic_package_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(host_code_errors(self.package(tmp, lambda app: None)), [])

    def test_refuses_each_path_umbreld_runs_or_copies(self):
        cases = {
            "empty hooks directory": lambda app: (app / "hooks").mkdir(),
            "post-start hook": lambda app: ((app / "hooks").mkdir(), (app / "hooks/post-start").write_text("#!/bin/sh\n")),
            "hooks as a file": lambda app: (app / "hooks").write_text(""),
            "hooks as a symlink": lambda app: (app / "hooks").symlink_to(app / "data"),
            "dangling hooks symlink": lambda app: (app / "hooks").symlink_to(app / "missing"),
            "exports.sh": lambda app: (app / "exports.sh").write_text("export X=1\n"),
            "torrc": lambda app: (app / "torrc").write_text(""),
            "top-level template": lambda app: (app / "settings.yml.template").write_text("x\n"),
            "nested template": lambda app: (app / "data/config/app.conf.template").write_text("x\n"),
        }
        for name, build in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                self.assertTrue(host_code_errors(self.package(tmp, build)))

    def test_checker_main_refuses_a_package_with_a_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
            app = root / "sunny-personal-digest"
            (app / "hooks").mkdir()
            (app / "hooks/post-start").write_text("#!/bin/sh\n")
            errors = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), mock.patch.object(check_package, "APP", app), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(errors):
                self.assertEqual(check_package.main(), 1)
            self.assertEqual(errors.getvalue(), "ERROR: hooks in the package directory runs or lands on the Umbrel host as root\n")

    def test_checker_main_refuses_template_path_without_disclosing_marker(self):
        marker = "vpn." + "synthetic" + ".internal"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "tests"))
            (root / "sunny-personal-digest" / (marker + ".template")).write_text("x\n", encoding="utf-8")
            errors = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), \
                    mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                    mock.patch.dict("os.environ", {}, clear=True), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(errors):
                self.assertEqual(check_package.main(), 1)
            self.assertEqual(errors.getvalue(), "ERROR: *.template files are rendered on the host and copied on Update\n")
            self.assertNotIn(marker, errors.getvalue())


class TestBugPackagePrivateMarkers20261019(unittest.TestCase):
    """The public package must not carry deployment routing identifiers."""

    def test_clean_package_accepts_configured_private_markers(self):
        markers = (
            "synthetic-tailnet-" + "6ae9" + "." + "ts" + "." + "net",
            ".".join(("10", "43", "18", "9")),
            "vpn." + "synthetic" + ".internal",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("public package\n", encoding="utf-8")
            self.assertEqual(private_marker_errors(root, markers), [])

    def test_rejects_tailnet_private_ip_and_vpn_domain_markers(self):
        markers = (
            "synthetic-tailnet-" + "6ae9" + "." + "ts" + "." + "net",
            ".".join(("10", "43", "18", "9")),
            "vpn." + "synthetic" + ".internal",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, marker in enumerate(markers):
                path = root / f"marker-{index}.txt"
                path.write_text(marker, encoding="utf-8")
                expected = ["possible private marker in package"]
                if index == 0:
                    expected.insert(0, "possible tailnet hostname in package")
                self.assertEqual(private_marker_errors(root, markers), expected)
                path.unlink()

    def test_checker_main_rejects_a_configured_private_marker(self):
        marker = "vpn." + "synthetic" + ".internal"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "tests"))
            (root / "synthetic-private-marker").write_text(marker, encoding="utf-8")
            errors = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), \
                    mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                    mock.patch.dict("os.environ", {"SUNNY_PACKAGE_PRIVATE_MARKERS": marker}, clear=True), \
                    mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(errors):
                self.assertEqual(check_package.main(), 1)
            self.assertEqual(errors.getvalue(), "ERROR: possible private marker in package\n")

    def test_checker_main_accepts_clean_package_without_private_marker_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "tests"))
            output = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), \
                    mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                    mock.patch.dict("os.environ", {}, clear=True), \
                    mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(output):
                self.assertEqual(check_package.main(), 0)
            self.assertEqual(output.getvalue(), "")

    def test_checker_main_rejects_tailnet_hostname_without_private_marker_input(self):
        hostname = "synthetic-tailnet-" + "6ae9" + "." + "ts" + "." + "net"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "tests"))
            (root / "synthetic-tailnet-host").write_text(hostname, encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), \
                    mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                    mock.patch.dict("os.environ", {}, clear=True), \
                    mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(output):
                self.assertEqual(check_package.main(), 1)
            self.assertEqual(output.getvalue(), "ERROR: possible tailnet hostname in package\n")

    def test_release_refuses_missing_empty_or_unreadable_private_marker_input(self):
        cases = (
            ("missing", {}),
            ("empty", {"SUNNY_PACKAGE_PRIVATE_MARKERS": "\n  \n"}),
            ("bom", {"SUNNY_PACKAGE_PRIVATE_MARKERS": "\ufeff"}),
            ("control", {"SUNNY_PACKAGE_PRIVATE_MARKERS": "vpn.synthetic.internal\x01"}),
            ("control_c1", {"SUNNY_PACKAGE_PRIVATE_MARKERS": "vpn.synthetic.internal\u0081"}),
            ("format", {"SUNNY_PACKAGE_PRIVATE_MARKERS": "vpn.synthetic.internal\u200b"}),
            ("unreadable", {"SUNNY_PACKAGE_PRIVATE_MARKERS_FILE": "/missing/private-markers"}),
        )
        for name, env in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "umbrel"
                shutil.copytree(ROOT, root, symlinks=True,
                                ignore=shutil.ignore_patterns("__pycache__", "tests"))
                output = io.StringIO()
                with mock.patch.object(check_package, "ROOT", root), \
                        mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                        mock.patch.dict("os.environ", env, clear=True), \
                        mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                        mock.patch.object(sys, "argv", ["check_package.py", "--release"]), contextlib.redirect_stderr(output):
                    self.assertEqual(check_package.main(), 1)
                expected = {
                    "unreadable": "private marker input is unreadable",
                    "control": "private marker input contains control characters",
                    "control_c1": "private marker input contains control characters",
                    "format": "private marker input contains control characters",
                }.get(name, "release requires nonempty private marker input")
                self.assertIn("ERROR: " + expected + "\n", output.getvalue())

    def test_external_marker_file_normalizes_bom_and_allows_release_input(self):
        marker = "vpn." + "synthetic" + ".internal"
        with tempfile.TemporaryDirectory() as tmp:
            marker_file = Path(tmp) / "markers"
            marker_file.write_text("\ufeff" + marker + "\n", encoding="utf-8")
            with mock.patch.dict("os.environ", {
                "SUNNY_PACKAGE_PRIVATE_MARKERS_FILE": str(marker_file),
            }, clear=True):
                self.assertIn(marker, private_markers(require_deployment=True))

    def test_release_refuses_empty_bom_or_invalid_external_marker_file(self):
        cases = (("empty", b""), ("bom", "\ufeff".encode()), ("invalid", b"\xff"))
        for name, contents in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "umbrel"
                shutil.copytree(ROOT, root, symlinks=True,
                                ignore=shutil.ignore_patterns("__pycache__", "tests"))
                marker_file = Path(tmp) / "markers"
                marker_file.write_bytes(contents)
                output = io.StringIO()
                with mock.patch.object(check_package, "ROOT", root), \
                        mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                        mock.patch.dict("os.environ", {
                            "SUNNY_PACKAGE_PRIVATE_MARKERS_FILE": str(marker_file),
                        }, clear=True), \
                        mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                        mock.patch.object(sys, "argv", ["check_package.py", "--release"]), contextlib.redirect_stderr(output):
                    self.assertEqual(check_package.main(), 1)
                expected = "private marker input is unreadable" if name == "invalid" else "release requires nonempty private marker input"
                self.assertIn("ERROR: " + expected + "\n", output.getvalue())

    def test_checker_main_rejects_marker_in_binary_body_or_path_without_disclosure(self):
        marker = "vpn." + "synthetic" + ".internal"
        hostname = "synthetic-tailnet-" + "6ae9" + "." + "ts" + "." + "net"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "tests"))
            (root / "notes.txt").write_bytes(hostname.encode() + b"\xff")
            (root / (marker + ".png")).write_bytes(b"public package\n")
            (root / (marker + ".pyc")).write_bytes(b"public package\n")
            (root / marker).mkdir()
            output = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), \
                    mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                    mock.patch.dict("os.environ", {"SUNNY_PACKAGE_PRIVATE_MARKERS": marker}, clear=True), \
                    mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(output):
                self.assertEqual(check_package.main(), 1)
            self.assertIn("ERROR: possible tailnet hostname in package\n", output.getvalue())
            self.assertIn("ERROR: possible private marker in package\n", output.getvalue())
            self.assertNotIn(hostname, output.getvalue())
            self.assertNotIn(marker, output.getvalue())

    def test_release_with_clean_external_marker_file_reaches_release_gates(self):
        marker = "vpn." + "synthetic" + ".internal"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "umbrel"
            shutil.copytree(ROOT, root, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "tests"))
            marker_file = Path(tmp) / "markers"
            marker_file.write_text(marker + "\n", encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(check_package, "ROOT", root), \
                    mock.patch.object(check_package, "APP", root / "sunny-personal-digest"), \
                    mock.patch.dict("os.environ", {
                        "SUNNY_PACKAGE_PRIVATE_MARKERS_FILE": str(marker_file),
                    }, clear=True), \
                    mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(sys, "argv", ["check_package.py", "--release"]), contextlib.redirect_stderr(output):
                expected = 1 if "disabled: true" in (
                    root / "sunny-personal-digest" / "umbrel-app.yml"
                ).read_text(encoding="utf-8") else 0
                self.assertEqual(check_package.main(), expected)
            self.assertNotIn("private marker input", output.getvalue())
            if expected:
                self.assertIn("ERROR: release manifest must be enabled\n", output.getvalue())
            else:
                self.assertEqual(output.getvalue(), "")


class TestBugNativePackageFixture20261020(unittest.TestCase):
    """Native probe must carry every public package input used by its tests."""

    def test_freeze_keeps_a_complete_package_checker_context(self):
        tracked = []
        explicit = {
            ".dockerignore", "Dockerfile", "requirements.txt", "requirements.in",
            "LICENSE", "THIRD_PARTY_NOTICES.md", "README.md", "SECURITY.md",
            "AGENTS.md", "CLAUDE.md", "umbrel-app-store.yml",
            "sunny-personal-digest/docker-compose.yml",
            "sunny-personal-digest/umbrel-app.yml",
            "sunny-personal-digest/icon.svg",
        }
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT).as_posix()
            included = relative in explicit or relative.startswith(
                ("src/", "tests/", "scripts/", "LICENSES/", ".github/workflows/"))
            if (relative.startswith(("src/", "tests/", "scripts/"))
                    and path.suffix not in {".py", ".js"}):
                included = False
            if (path.is_file() or path.is_symlink()) and included:
                tracked.append(relative)

        def git_inventory(*args, **kwargs):
            if args[-1] == "HEAD":
                return "synthetic-native-fixture\n"
            self.assertIn("ls-files", args)
            pathspecs = args[args.index("--") + 1:]
            selected = [
                name for name in tracked
                if any(name == pattern or name.startswith(pattern + "/") for pattern in pathspecs)
            ]
            return "\0".join(selected) + "\0"

        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp) / "probe"
            # /probe in the native image has no Git checkout or Git binary.
            # Mock only its source inventory and HEAD; freeze/audit still read
            # the real public files into a separate frozen context.
            with mock.patch.object(check_native_release, "command", side_effect=git_inventory):
                manifest = check_native_release.freeze(ROOT, context)
            self.assertEqual(manifest["unittest_count"], 523)
            check_native_release.audit_context(context)
            self.assertTrue((context / "CLAUDE.md").is_symlink())
            self.assertEqual((context / "CLAUDE.md").readlink(), Path("AGENTS.md"))
            output = io.StringIO()
            with mock.patch.object(check_package, "ROOT", context), \
                    mock.patch.object(check_package, "APP", context / "sunny-personal-digest"), \
                    mock.patch.object(check_package.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(sys, "argv", ["check_package.py"]), contextlib.redirect_stderr(output):
                self.assertEqual(check_package.main(), 0)
            self.assertEqual(output.getvalue(), "")
            manifest_path = context / "probe-manifest.json"
            tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
            tampered["links"] = {"CLAUDE.md": "README.md"}
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            (context / "CLAUDE.md").unlink()
            (context / "CLAUDE.md").symlink_to("README.md")
            with self.assertRaisesRegex(RuntimeError, "native gate context changed"):
                check_native_release.audit_context(context)


class TestPackageRoleLayoutGuard(unittest.TestCase):
    def setUp(self):
        self.compose = (ROOT / "sunny-personal-digest/docker-compose.yml").read_text(encoding="utf-8")

    def test_rejects_role_layout_weakening(self):
        mutations = (
            ("${APP_DATA_DIR}/data/runtime/ipc/jobs:/data/ipc:ro", "${APP_DATA_DIR}/data/private:/vault:ro"),
            ("${APP_DATA_DIR}/data/runtime/ipc/admin:/data/ipc:ro", "${APP_DATA_DIR}/data/runtime/ipc/admin:/data/ipc"),
            ("memswap_limit: 512m", "memswap_limit: 1024m"),
            ('user: "1001:1001"', 'user: "1000:1000"'),
            ("mode=0700,uid=1001,gid=1001", "mode=0777,uid=1001,gid=1001"),
            ("  guardian:\n", "  rogue:\n    image: example\n  guardian:\n"),
            ('user: "1001:1001"', 'user: "1001:1001"\n    user: "0:0"'),
            ('user: "1001:1001"', 'user: "1001:1001"\n    pid: service:guardian'),
            ('user: "1001:1001"', 'user: "1001:1001"\n    ipc: service:guardian'),
            ('user: "1001:1001"', 'user: "1001:1001"\n    network_mode: service:guardian'),
            ('user: "1001:1001"', 'user: "1001:1001"\n    <<: *unsafe_defaults'),
            ('user: "1001:1001"', 'user: "1001:1001"\n    entrypoint: /bin/sh'),
            ('        hard: 0', '        hard: 0\n        hard: -1'),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertTrue(role_layout_errors(self.compose.replace(before, after, 1)))

    def test_accepts_the_actual_candidate(self):
        self.assertEqual(role_layout_errors(self.compose), [])


class TestPackageTelegramProxyGuard(unittest.TestCase):
    def test_accepts_required_proxy_forwarded_with_app_version(self):
        source = """
class TelethonGateway:
    def __init__(self, api_id, api_hash, proxy):
        self.proxy = proxy

    def _client(self, session_text):
        return TelegramClient(proxy=self.proxy, app_version=APP_VERSION)
"""
        self.assertEqual(
            telegram_client_guard(source),
            (True, True, True),
        )

    def test_rejects_optional_proxy_even_when_forwarded(self):
        source = """
class TelethonGateway:
    def __init__(self, api_id, api_hash, proxy=None):
        self.proxy = proxy

    def _client(self, session_text):
        return TelegramClient(proxy=self.proxy, app_version=APP_VERSION)
"""
        self.assertEqual(
            telegram_client_guard(source),
            (False, True, True),
        )

    def test_accepts_required_keyword_only_proxy(self):
        source = """
class TelethonGateway:
    def __init__(self, api_id, api_hash, *, proxy):
        self.proxy = proxy

    def _client(self, session_text):
        return TelegramClient(proxy=self.proxy, app_version=APP_VERSION)
"""
        self.assertEqual(
            telegram_client_guard(source),
            (True, True, True),
        )

    def test_rejects_direct_client_and_wire_version_as_app_version(self):
        source = """
class TelethonGateway:
    def __init__(self, api_id, api_hash, proxy):
        self.proxy = proxy

    def _client(self, session_text):
        return TelegramClient(app_version=COLLECTOR_VERSION)
"""
        self.assertEqual(
            telegram_client_guard(source),
            (True, False, False),
        )

    def test_rejects_mixed_proxy_and_direct_client_calls(self):
        source = """
class TelethonGateway:
    def __init__(self, api_id, api_hash, proxy):
        self.proxy = proxy

    def _client(self, session_text, direct=False):
        if direct:
            return TelegramClient(app_version=APP_VERSION)
        return TelegramClient(proxy=self.proxy, app_version=APP_VERSION)
"""
        self.assertEqual(
            telegram_client_guard(source),
            (True, False, True),
        )

    def test_rejects_gateway_without_any_client_call(self):
        source = """
class TelethonGateway:
    def __init__(self, api_id, api_hash, proxy):
        self.proxy = proxy

    def _client(self, session_text):
        return object()
"""
        self.assertEqual(
            telegram_client_guard(source),
            (True, False, False),
        )


class TestPackageTelegramProbeGuard(unittest.TestCase):
    def setUp(self):
        self.parent = """
async def probe_telegram_session(request):
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "sunny_digest.telegram_probe_worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    process.stdin.write(request)
"""
        self.worker = """
async def _probe(value):
    gateway = TelethonGateway(
        value["api_id"], value["api_hash"], {
            "proxy_type": "socks5",
            "addr": MIHOMO_SOCKS_HOST,
            "port": MIHOMO_SOCKS_PORT,
            "rdns": True,
        },
    )
    return await gateway.probe_authorization(value["session"])

def main():
    raw = sys.stdin.buffer.read(16385)
"""
        self.gateway = """
class TelethonGateway:
    async def probe_authorization(self, session_text):
        client = self._client(session_text)
        try:
            await client.connect()
            return bool(await client.is_user_authorized())
        finally:
            await _disconnect_client(client)
"""
        self.mihomo = """
MIHOMO_SOCKS_HOST = "127.0.0.1"
MIHOMO_SOCKS_PORT = 7891
"""

    def guard(self, *, parent=None, worker=None, gateway=None, mihomo=None):
        return telegram_probe_guard(
            self.parent if parent is None else parent,
            self.worker if worker is None else worker,
            self.gateway if gateway is None else gateway,
            self.mihomo if mihomo is None else mihomo,
        )

    def test_accepts_exact_stdin_worker_and_authorization_only_probe(self):
        self.assertTrue(all(self.guard().values()))

    def test_current_probe_sources_pass(self):
        sources = (
            ROOT / "src/sunny_digest/telegram_probe.py",
            ROOT / "src/sunny_digest/telegram_probe_worker.py",
            ROOT / "src/sunny_digest/telegram_gateway.py",
            ROOT / "src/sunny_digest/mihomo.py",
        )
        self.assertTrue(all(telegram_probe_guard(
            *(path.read_text(encoding="utf-8") for path in sources)
        ).values()))

    def test_rejects_secrets_in_worker_argv(self):
        parent = self.parent.replace(
            '"sunny_digest.telegram_probe_worker",',
            '"sunny_digest.telegram_probe_worker", session_text,',
        )
        self.assertFalse(self.guard(parent=parent)["stdin_only_secrets"])

    def test_rejects_secrets_in_worker_environment(self):
        parent = self.parent.replace(
            "stdin=asyncio.subprocess.PIPE,",
            'env={"TELEGRAM_SESSION": session_text},\n        stdin=asyncio.subprocess.PIPE,',
        )
        self.assertFalse(self.guard(parent=parent)["stdin_only_secrets"])

    def test_rejects_secret_file_transport(self):
        parent = self.parent + '\nopen("/tmp/session", "wb").write(request)\n'
        self.assertFalse(self.guard(parent=parent)["stdin_only_secrets"])

    def test_rejects_non_loopback_socks(self):
        mihomo = self.mihomo.replace('"127.0.0.1"', '"0.0.0.0"')
        self.assertFalse(self.guard(mihomo=mihomo)["fixed_loopback_socks"])

    def test_rejects_direct_fallback(self):
        worker = self.worker.replace(
            "return await gateway.probe_authorization",
            'fallback = "DIRECT"\n    return await gateway.probe_authorization',
        )
        self.assertFalse(self.guard(worker=worker)["no_thread_or_direct"])

    def test_rejects_direct_telegram_client_helper(self):
        worker = self.worker + "\ndef bypass():\n    return TelegramClient(session)\n"
        facts = self.guard(worker=worker)
        self.assertFalse(facts["fixed_loopback_socks"])
        self.assertFalse(facts["no_thread_or_direct"])

    def test_rejects_message_api_in_authorization_probe(self):
        gateway = self.gateway.replace(
            "await client.connect()",
            "await client.connect()\n            await client.get_messages(limit=1)",
        )
        self.assertFalse(self.guard(gateway=gateway)["authorization_only"])

    def test_rejects_message_api_hidden_in_worker(self):
        worker = self.worker + "\nasync def inspect(client):\n    return await client.iter_dialogs()\n"
        self.assertFalse(self.guard(worker=worker)["authorization_only"])

    def test_rejects_asyncio_to_thread(self):
        parent = self.parent + "\nawait asyncio.to_thread(run_probe)\n"
        self.assertFalse(self.guard(parent=parent)["no_thread_or_direct"])

if __name__ == "__main__":
    unittest.main()
