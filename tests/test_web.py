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
        "pending_digest_upload": False,
        "pending_monitor_upload": False,
        "source_id": None,
        "chats": [],
        "monitoring_phase": "not_selected",
        "activation_required": False,
        "monitoring_active": False,
        "upload_public_key": None,
        "upload_key_fingerprint": None,
        "model": None,
        "upload_target": None,
        "consent_expires_at": None,
        "phone_masked": None,
        "dialogs": [],
        "selection_id": None,
        "last_result": None,
        "last_error_type": None,
        "revocation_required": False,
        "failed_chat_count": 0,
    }
    if phase == "chat_locked":
        value.update({
            "source_id": "12345678-1234-4678-9234-567812345678",
            "chats": [
                {"chat_id": -100124, "title": "Pilot A", "kind": "channel"},
                {"chat_id": -100123, "title": "Pilot B", "kind": "channel"},
            ],
            "monitoring_phase": "activation_required",
            "activation_required": True,
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
        self.assertIn(b"Sunny Personal Chats", page)
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
            "confirm_data_scope": "yes",
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
                      "authenticated", "resolving_links", "dialogs_listed",
                      "chat_locked", "unavailable"):
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
                ("authenticated", 'name="action" value="resolve_chat_links"'),
                ("resolving_links", 'name="action" value="resolve_chat_links"'),
                ("dialogs_listed", 'name="action" value="select_chats"')):
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
                ("authenticated", "resolve_chat_links"),
                ("dialogs_listed", "select_chats")):
            with self.subTest(phase=phase):
                body = render_status(status(phase), "a" * 64)
                self.assertIn(f'name="action" value="{action}"', body)

    def test_message_links_then_multiselect_and_explicit_activation(self):
        self.ipc.value = status("authenticated")
        response, page = self.request("GET", headers=self.auth)
        self.assertIn(b'name="chat_links"', page)
        self.assertNotIn(b'name="chat_id"', page)
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        token = re.search(
            rb'name="csrf" value="([0-9a-f]{64})"', page).group(1).decode()
        headers = dict(self.auth)
        headers.update({"Cookie": cookie,
                        "Content-Type": "application/x-www-form-urlencoded"})
        body = urlencode({
            "csrf": token,
            "action": "resolve_chat_links",
            "chat_links": (
                " https://t.me/c/124/10 \n\n"
                "https://t.me/public_group/20\n"
            ),
        }).encode()
        result, rendered = self.request("POST", headers=headers, body=body)
        self.assertEqual(result.status, 200)
        self.assertNotIn(b"https://t.me/c/124/10", rendered)
        self.assertNotIn(b"https://t.me/public_group/20", rendered)
        self.assertEqual(self.ipc.calls[-1], (
            "resolve_chat_links",
            ["https://t.me/c/124/10", "https://t.me/public_group/20"],
        ))

        listed = status("dialogs_listed")
        listed["selection_id"] = "22345678-1234-4678-9234-567812345678"
        listed["dialogs"] = [
            {"chat_id": -100124, "title": "A", "kind": "channel"},
            {"chat_id": -100123, "title": "B", "kind": "channel"},
        ]
        self.ipc.value = listed
        response, page = self.request("GET", headers=self.auth)
        self.assertEqual(page.count(b'name="chat_id"'), 2)
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        token = re.search(rb'name="csrf" value="([0-9a-f]{64})"', page).group(1).decode()
        headers = dict(self.auth)
        headers.update({"Cookie": cookie,
                        "Content-Type": "application/x-www-form-urlencoded"})
        form = [
            ("csrf", token), ("action", "select_chats"),
            ("selection_id", listed["selection_id"]),
            ("chat_id", "-100124"), ("chat_id", "-100123"),
            ("confirm_lock", "yes"),
        ]
        result, _ = self.request(
            "POST", headers=headers, body=urlencode(form).encode())
        self.assertEqual(result.status, 200)
        self.assertEqual(self.ipc.calls[-1], ("select_chats", {
            "selection_id": listed["selection_id"],
            "chat_ids": ["-100124", "-100123"],
        }))

        locked = status("chat_locked")
        self.ipc.value = locked
        response, page = self.request("GET", headers=self.auth)
        self.assertIn(b'name="action" value="activate_monitoring"', page)
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        token = re.search(rb'name="csrf" value="([0-9a-f]{64})"', page).group(1).decode()
        headers["Cookie"] = cookie
        body = urlencode({
            "csrf": token, "action": "activate_monitoring",
            "confirm_activation": "yes",
        }).encode()
        self.request("POST", headers=headers, body=body)
        self.assertEqual(self.ipc.calls[-1], ("activate_monitoring", None))

    def test_message_link_count_is_bounded_before_ipc(self):
        self.ipc.value = status("authenticated")
        response, page = self.request("GET", headers=self.auth)
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        token = re.search(
            rb'name="csrf" value="([0-9a-f]{64})"', page).group(1).decode()
        headers = dict(self.auth)
        headers.update({"Cookie": cookie,
                        "Content-Type": "application/x-www-form-urlencoded"})
        before = list(self.ipc.calls)
        body = urlencode({
            "csrf": token,
            "action": "resolve_chat_links",
            "chat_links": "\n".join(
                f"https://t.me/group_{index}/1" for index in range(17)),
        }).encode()
        result, page = self.request("POST", headers=headers, body=body)
        self.assertEqual(result.status, 200)
        self.assertIn("Проверьте ссылки".encode(), page)
        self.assertEqual(self.ipc.calls, before + [("status", None)])

    def test_ui_discloses_exact_data_scope_and_first_activation_effect(self):
        fresh = render_status(status("fresh"), "a" * 64)
        self.assertIn("ZDR OpenRouter", fresh)
        self.assertIn("фрагментом до 300 UTF-16", fresh)
        self.assertIn("помечать просмотренные сообщения", fresh)
        authenticated = render_status(status("authenticated"), "a" * 64)
        self.assertIn("включая последние сообщения", authenticated)
        self.assertIn("не сохраняет ссылки или полученные тексты", authenticated)
        interrupted = render_status(status("resolving_links"), "a" * 64)
        self.assertIn("Повторный запрос заблокирован", interrupted)
        locked = render_status(status("chat_locked"), "a" * 64)
        self.assertIn("Старые mentions не будут отправлены", locked)
        self.assertIn("durable baseline ACK", locked)


if __name__ == "__main__":
    unittest.main()
