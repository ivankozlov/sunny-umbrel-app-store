from __future__ import annotations

import base64
import http.client
import json
import re
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sunny_digest.secure_web import SecureAppServer, SecureHandler, _content
from sunny_digest.web import IPCClient


def status(*, view=False):
    return {
        "security_state": "uninitialized", "trusted_origin": "https://admin.example.test",
        "trusted_origin_configured": True, "phase": "secured", "configured": False,
        "view_authorized": view, "revocation_required": False,
        "view_token": "must-never-reach-a-page",
        "private_marker": "only-with-a-view" if view else None,
    }


class FakeIPC:
    def __init__(self):
        self.calls = []

    def request(self, command, data=None):
        self.calls.append((command, data))
        if command == "status":
            return status(view=bool(data))
        if command == "operation_begin":
            return {"challenge_id": "challenge", "public_key": {"challenge": "AA", "rpId": "example.test"}}
        if command == "operation_finish":
            return {**status(view=True), "view_token": "a" * 43}
        raise RuntimeError("unexpected IPC request")


class SecureWebTests(unittest.TestCase):
    def setUp(self):
        self.ipc = FakeIPC()
        self.server = SecureAppServer(("127.0.0.1", 0), SecureHandler, ipc=self.ipc,
                                      username="sunny", password="app-password")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.auth = {"Authorization": "Basic " + base64.b64encode(b"sunny:app-password").decode()}

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def request(self, method, path="/", *, headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response, response.read()
        finally:
            connection.close()

    def csrf_headers(self):
        response, page = self.request("GET", headers=self.auth)
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        csrf = re.search(rb'data-csrf="([0-9a-f]{64})"', page).group(1).decode()
        headers = dict(self.auth)
        headers.update({"Cookie": cookie, "Origin": "https://admin.example.test",
                        "Content-Type": "application/json", "X-Sunny-CSRF": csrf})
        return headers, page

    def test_page_has_strict_cookie_csp_and_self_hosted_script(self):
        response, page = self.request("GET", headers=self.auth)
        self.assertEqual(response.status, 200)
        self.assertIn(b'src="/security.js"', page)
        self.assertNotIn(b"must-never-reach-a-page", page)
        self.assertIn("Secure; HttpOnly; SameSite=Strict", response.getheader("Set-Cookie"))
        csp = response.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        script, source = self.request("GET", "/security.js", headers=self.auth)
        self.assertEqual(script.status, 200)
        self.assertIn(b"navigator.credentials.get", source)
        self.assertNotIn(b"eval(", source)

    def test_mutation_requires_basic_exact_origin_and_csrf(self):
        payload = json.dumps({"command": "operation_begin", "data": {"operation": "lock", "payload": {}}}).encode()
        denied, _ = self.request("POST", "/api", headers={**self.auth, "Content-Type": "application/json"}, body=payload)
        self.assertEqual(denied.status, 403)
        headers, _ = self.csrf_headers()
        wrong = dict(headers); wrong["Origin"] = "https://evil.example.test"
        denied, _ = self.request("POST", "/api", headers=wrong, body=payload)
        self.assertEqual(denied.status, 403)
        headers["X-Sunny-CSRF"] = "0" * 64
        denied, _ = self.request("POST", "/api", headers=headers, body=payload)
        self.assertEqual(denied.status, 403)

    def test_operation_begin_is_bounded_and_bare_commands_are_unavailable(self):
        headers, _ = self.csrf_headers()
        bare = json.dumps({"command": "configure", "data": {}}).encode()
        denied, _ = self.request("POST", "/api", headers=headers, body=bare)
        self.assertEqual(denied.status, 403)
        begin = json.dumps({"command": "operation_begin", "data": {"operation": "lock", "payload": {}}}).encode()
        accepted, result = self.request("POST", "/api", headers=headers, body=begin)
        self.assertEqual(accepted.status, 200)
        self.assertEqual(json.loads(result)["challenge_id"], "challenge")
        duplicate = b'{"command":"operation_begin","command":"operation_begin","data":{}}'
        denied, _ = self.request("POST", "/api", headers=headers, body=duplicate)
        self.assertEqual(denied.status, 403)
        denied, _ = self.request("POST", "/api", headers=headers, body=b'{"command":"run_now","data":{"value":NaN}}')
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.getheader("Connection"), "close")

    def test_finish_sets_http_only_view_lease_but_never_reflects_token(self):
        headers, _ = self.csrf_headers()
        finish = {"command": "operation_finish", "data": {"challenge_id": "challenge", "credential": {}}}
        response, body = self.request("POST", "/api", headers=headers, body=json.dumps(finish).encode())
        self.assertEqual(response.status, 200)
        self.assertIn("sunny_secure_view=", response.getheader("Set-Cookie"))
        self.assertNotIn(b"a" * 43, body)

    def test_legacy_actions_are_explicitly_mapped_in_self_hosted_asset(self):
        source = Path(__file__).parent.parent / "src/sunny_digest/security.js"
        with open(source, encoding="utf-8") as stream:
            asset = stream.read()
        for action in ("configure", "send_code", "resolve_chat_links", "select_chats",
                       "activate_monitoring", "renew_consent", "extend_chats", "replace_vpn",
                       "reset", "ack_manual_revocation", "run_now"):
            self.assertIn(f'action === "{action}"', asset)
        self.assertIn("completePasskeyAdd", asset)
        self.assertIn("registration_finish", asset)
        self.assertIn("navigator.credentials.create", asset)
        self.assertNotIn("localStorage", asset)

    def test_locked_and_bootstrap_states_have_the_expected_limited_forms(self):
        base = status()
        base.update(security_state="migration_blocked", configured=False)
        bootstrap = _content(base, "a" * 64)
        self.assertIn('id="bootstrap-form"', bootstrap)
        self.assertNotIn('data-operation="migration_resume"', bootstrap)
        base.update(security_state="unlock_pending", configured=True)
        locked = _content(base, "a" * 64)
        self.assertIn('data-operation="unlock"', locked)
        self.assertNotIn('name="action" value="configure"', locked)
        self.assertNotIn("Collector недоступен", locked)

    def test_configure_model_is_fixed_and_only_view_authorized_status_has_settings(self):
        base = status(view=True)
        base.update(security_state="unlocked", phase="fresh")
        page = _content(base, "a" * 64)
        self.assertIn('name="openrouter_model" value="anthropic/claude-opus-5.5" readonly', page)
        self.assertIn("Упоминания отдельно не отправляются.", page)
        self.assertIn("даже если дайджест не удалось доставить", page)
        self.assertIn("Guardian хранит только очищенный VLESS/REALITY", page)
        self.assertNotIn("durably отправлять в Sunny native mention", page)
        base["view_authorized"] = False
        self.assertNotIn('name="action" value="configure"', _content(base, "a" * 64))

    def test_invalid_csrf_cookie_is_not_reflected(self):
        invalid = "<bad-cookie>"
        response, page = self.request("GET", headers={**self.auth, "Cookie": f"sunny_secure_csrf={invalid}"})
        self.assertEqual(response.status, 200)
        self.assertNotIn(invalid.encode(), page)
        self.assertRegex(response.getheader("Set-Cookie"), r"sunny_secure_csrf=[0-9a-f]{64};")


class TestBugGuardianRestart20261009(unittest.TestCase):
    """A signed lock's restart gap must not claim that the fixed Origin is missing."""

    def setUp(self):
        self.ipc = FakeIPC()
        self.scratch = tempfile.TemporaryDirectory()
        self.server = SecureAppServer(("127.0.0.1", 0), SecureHandler, ipc=self.ipc,
                                      username="sunny", password="app-password")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.auth = {"Authorization": "Basic " + base64.b64encode(b"sunny:app-password").decode()}

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.scratch.cleanup()

    def request(self, method, path="/", *, headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response, response.read()
        finally:
            connection.close()

    def missing_socket(self):
        self.server.ipc = IPCClient(str(Path(self.scratch.name) / "admin.sock"))

    def test_restart_gap_serves_no_forms_and_refreshes_only_the_same_page(self):
        self.missing_socket()
        denied, _ = self.request("GET")
        self.assertEqual(denied.status, 401)
        self.assertIsNone(denied.getheader("Refresh"))
        response, body = self.request("GET", headers=self.auth)
        self.assertEqual(response.status, 503)
        self.assertIn("Сервис временно недоступен", body.decode())
        self.assertNotIn(b"Trusted HTTPS origin is not configured", body)
        self.assertNotIn(b"<form", body)
        self.assertIsNone(response.getheader("Set-Cookie"))
        self.assertEqual(response.getheader("Retry-After"), "2")
        self.assertEqual(response.getheader("Refresh"), "2; url=/")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertIn("script-src 'self'", response.getheader("Content-Security-Policy"))
        self.server.ipc = self.ipc
        locked = status(); locked.update(security_state="locked", configured=True)
        with patch.object(self.ipc, "request", return_value=locked):
            recovered, page = self.request("GET", headers=self.auth)
        self.assertEqual(recovered.status, 200)
        self.assertIn('data-operation="unlock"', page.decode())
        self.assertIsNone(recovered.getheader("Refresh"))

    def test_missing_or_invalid_origin_still_refuses_without_retry(self):
        for origin in (None, "http://admin.example.test", "https://admin.example.test/path"):
            with self.subTest(origin=origin):
                value = status(); value["trusted_origin"] = origin
                with patch.object(self.ipc, "request", return_value=value):
                    response, body = self.request("GET", headers=self.auth)
                self.assertEqual(response.status, 503)
                self.assertIn(b"Trusted HTTPS origin is not configured", body)
                self.assertNotIn(b"<form", body)
                self.assertIsNone(response.getheader("Refresh"))
                self.assertIsNone(response.getheader("Retry-After"))

    def test_render_failure_does_not_claim_missing_origin_or_reflect_details(self):
        with patch("sunny_digest.secure_web._content", side_effect=RuntimeError("private-detail")):
            response, body = self.request("GET", headers=self.auth)
        self.assertEqual(response.status, 503)
        self.assertIn("Не удалось открыть интерфейс", body.decode())
        self.assertNotIn(b"private-detail", body)
        self.assertNotIn(b"Trusted HTTPS origin is not configured", body)
        self.assertIsNone(response.getheader("Refresh"))
        self.assertIsNone(response.getheader("Retry-After"))

    def test_post_during_restart_is_denied_without_automatic_replay(self):
        body = json.dumps({"command": "operation_begin", "data": {"operation": "lock", "payload": {}}}).encode()
        ready, page = self.request("GET", headers=self.auth)
        self.assertEqual(ready.status, 200)
        cookie = ready.getheader("Set-Cookie").split(";", 1)[0]
        csrf = re.search(rb'data-csrf="([0-9a-f]{64})"', page).group(1).decode()
        headers = {**self.auth, "Content-Type": "application/json",
                   "Origin": "https://admin.example.test", "Cookie": cookie,
                   "X-Sunny-CSRF": csrf}
        accepted, _ = self.request("POST", "/api", headers=headers, body=body)
        self.assertEqual(accepted.status, 200)
        self.assertEqual(self.ipc.calls[-1], ("operation_begin",
                         {"operation": "lock", "payload": {}}))
        self.ipc.calls.clear()
        self.missing_socket()
        # Observe the actual disconnected client, so a cached-Origin fallback
        # attempting the mutation cannot hide behind the same final HTTP 403.
        with patch.object(self.server.ipc, "request", wraps=self.server.ipc.request) as ipc_request:
            response, result = self.request("POST", "/api", headers=headers, body=body)
        ipc_request.assert_called_once_with("status")
        self.assertEqual(response.status, 403)
        self.assertEqual(response.getheader("Connection"), "close")
        self.assertEqual(result, b"Request denied\n")
        self.assertIsNone(response.getheader("Refresh"))
        self.assertIsNone(response.getheader("Retry-After"))
        self.assertEqual(self.ipc.calls, [])
        self.server.ipc = self.ipc
        recovered, _ = self.request("GET", headers=self.auth)
        self.assertEqual(recovered.status, 200)
        self.assertEqual(self.ipc.calls, [("status", None)])


if __name__ == "__main__":
    unittest.main()
