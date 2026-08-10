from __future__ import annotations

import base64
import http.client
import re
import threading
import unittest
from urllib.parse import urlencode

from sunny_digest.web import AppServer, Handler, _layout, render_status


def status(phase="fresh"):
    value = {
        "phase": phase,
        "configured": phase != "fresh",
        "chat_locked": phase == "chat_locked",
        "consent_active": phase not in ("fresh", "unavailable"),
        "pending_upload": False,
        "source_id": None,
        "chat_id": None,
        "chat_title": None,
        "initial_message_id": None,
        "upload_public_key": None,
        "upload_key_fingerprint": None,
        "model": None,
        "upload_target": None,
        "consent_expires_at": None,
        "phone_masked": None,
        "dialogs": [],
        "last_result": None,
        "last_error_type": None,
        "revocation_required": False,
    }
    if phase == "chat_locked":
        value.update({
            "source_id": "12345678-1234-4678-9234-567812345678",
            "chat_id": -100123,
            "chat_title": "Pilot group",
            "initial_message_id": 10,
            "upload_public_key": "ssh-ed25519 AAAApublic",
            "upload_key_fingerprint": "SHA256:public",
            "model": "anthropic/example",
            "upload_target": "root@receiver.example:22",
            "consent_expires_at": "2026-08-05T00:00:00Z",
        })
    return value


class FakeIPC:
    def __init__(self, phase="fresh"):
        self.value = status(phase)
        self.calls = []

    def request(self, command, data=None):
        self.calls.append((command, data))
        return dict(self.value)


class WebTests(unittest.TestCase):
    def setUp(self):
        self.ipc = FakeIPC()
        self.server = AppServer(
            ("127.0.0.1", 0), Handler, ipc=self.ipc,
            username="sunny", password="app-password",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        credentials = base64.b64encode(b"sunny:app-password").decode("ascii")
        self.auth = {"Authorization": f"Basic {credentials}"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path="/", *, headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            raw = response.read()
            return response, raw
        finally:
            connection.close()

    def test_health_is_generic_but_ui_requires_second_auth(self):
        health, body = self.request("GET", "/healthz")
        self.assertEqual(health.status, 200)
        self.assertEqual(body, b"ok\n")
        denied, _ = self.request("GET")
        self.assertEqual(denied.status, 401)
        accepted, page = self.request("GET", headers=self.auth)
        self.assertEqual(accepted.status, 200)
        self.assertIn(b"Sunny Personal Digest", page)
        self.assertEqual(self.ipc.calls, [("status", None)])

    def test_setup_secrets_are_not_reflected_and_root_login_is_fixed(self):
        response, page = self.request("GET", headers=self.auth)
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        token = re.search(rb'name="csrf" value="([0-9a-f]{64})"', page).group(1).decode()
        form = {
            "csrf": token,
            "action": "configure",
            "telegram_api_id": "12345",
            "telegram_api_hash": "a-secret-api-hash",
            "openrouter_api_key": "a-secret-openrouter-key",
            "openrouter_model": "anthropic/example",
            "upload_host": "receiver.example",
            "upload_port": "22",
            "known_host": "receiver.example ssh-ed25519 AAAAsecret-host-key",
            "consent_expires_at": "2026-08-05T00:00:00Z",
        }
        headers = dict(self.auth)
        headers.update({
            "Cookie": cookie,
            "Content-Type": "application/x-www-form-urlencoded",
        })
        result, rendered = self.request(
            "POST", headers=headers, body=urlencode(form).encode("utf-8"))
        self.assertEqual(result.status, 200)
        self.assertNotIn(b"a-secret-api-hash", rendered)
        self.assertNotIn(b"a-secret-openrouter-key", rendered)
        self.assertNotIn(b"AAAAsecret-host-key", rendered)
        command, data = self.ipc.calls[-1]
        self.assertEqual(command, "configure")
        self.assertEqual(data["upload_user"], "root")

    def test_csrf_is_required(self):
        headers = dict(self.auth)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        response, page = self.request(
            "POST", headers=headers,
            body=urlencode({"csrf": "0" * 64, "action": "run_now"}).encode())
        self.assertEqual(response.status, 200)
        self.assertIn("Операция не выполнена".encode(), page)
        self.assertNotIn(("run_now", None), self.ipc.calls)

    def test_reset_is_visible_in_every_phase_and_renewal_is_explicit(self):
        for phase in ("fresh", "configured", "code_sent", "password_required",
                      "authenticated", "dialogs_listed", "chat_locked", "unavailable"):
            with self.subTest(phase=phase):
                body = _layout(render_status(status(phase), "a" * 64), "a" * 64).decode()
                self.assertIn('name="action" value="reset"', body)
                self.assertIn('name="confirm_reset"', body)
        locked = render_status(status("chat_locked"), "a" * 64)
        self.assertIn('name="action" value="renew_consent"', locked)
        self.assertIn('name="confirm_renew"', locked)

    def test_unconfirmed_logout_blocks_setup_and_requires_explicit_manual_ack(self):
        warning = status("fresh")
        warning["revocation_required"] = True
        warning["last_error_type"] = "TelegramLogoutUnconfirmed"
        body = render_status(warning, "a" * 64)
        self.assertIn("Telegram logout не подтверждён", body)
        self.assertIn("Settings → Devices", body)
        self.assertIn('name="action" value="ack_manual_revocation"', body)
        self.assertIn('name="confirm_manual_revocation"', body)
        self.assertNotIn("Telegram API ID", body)

    def test_expired_prelock_consent_hides_chat_read_actions(self):
        for phase, forbidden in (
                ("configured", 'name="action" value="send_code"'),
                ("code_sent", 'name="action" value="submit_code"'),
                ("password_required", 'name="action" value="submit_password"'),
                ("authenticated", 'name="action" value="list_dialogs"'),
                ("dialogs_listed", 'name="action" value="select_chat"')):
            with self.subTest(phase=phase):
                value = status(phase)
                value["consent_active"] = False
                body = render_status(value, "a" * 64)
                self.assertIn("Согласие истекло", body)
                self.assertIn("factory reset", body)
                self.assertNotIn(forbidden, body)

    def test_active_prelock_consent_keeps_each_setup_action_visible(self):
        for phase, action in (
                ("configured", "send_code"),
                ("code_sent", "submit_code"),
                ("password_required", "submit_password"),
                ("authenticated", "list_dialogs"),
                ("dialogs_listed", "select_chat")):
            with self.subTest(phase=phase):
                body = render_status(status(phase), "a" * 64)
                self.assertIn(f'name="action" value="{action}"', body)


if __name__ == "__main__":
    unittest.main()
