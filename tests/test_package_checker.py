from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_package import telegram_client_guard  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
