from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_package import (  # noqa: E402
    ROOT,
    telegram_client_guard,
    telegram_probe_guard,
)


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
