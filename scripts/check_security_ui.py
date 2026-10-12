#!/usr/bin/env python3
"""Offline browser regression gate, using only synthetic WebAuthn credentials.

The production HTTP handler and JS run against a small in-memory policy fixture.
CDP's virtual authenticator produces actual assertions verified by py_webauthn.
This does not attest the owner's authenticator, TLS deployment or Linux guards.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import http.client
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

from sunny_digest.authn import WebAuthnAuthorizer
from sunny_digest.secure_web import SecureAppServer, SecureHandler
from sunny_digest.settings import validate_configure


ORIGIN = "https://admin.example.test"
VIEW = "synthetic_view_lease_" + "a" * 32


class PolicyFixture:
    def __init__(self):
        self.auth = WebAuthnAuthorizer(trusted_origin=ORIGIN, rp_id="example.test")
        self.token = self.auth.create_bootstrap()
        self.credentials = {}
        self.state = "uninitialized"
        self.phase = "fresh"
        self.calls = []
        self.unavailable_reads = 0
        self.identity = {"vault_id": "synthetic-vault", "security_epoch": 0, "policy_revision": 0}

    def status(self, data=None):
        view = bool(data and data.get("view_token") == VIEW and self.state == "unlocked")
        result = {"security_state": self.state, "trusted_origin": ORIGIN,
                  "configured": self.state != "uninitialized", "view_authorized": view,
                  "phase": self.phase if view else "secured", "consent_active": True}
        if view:
            result["passkeys"] = [{"credential_id": key, "name": row["name"]}
                                 for key, row in self.credentials.items()]
        if view and self.phase == "dialogs_listed":
            result.update(selection_id="synthetic-selection", dialogs=[
                {"chat_id": -1000000000123, "title": "Первый тестовый чат"},
                {"chat_id": -1000000000124, "title": "Второй тестовый чат"}])
        return result

    def request(self, command, data=None):
        self.calls.append((command, copy.deepcopy(data)))
        if command == "status":
            if self.unavailable_reads:
                self.unavailable_reads -= 1
                raise ConnectionRefusedError("synthetic guardian restart gap")
            return self.status(data)
        if command == "bootstrap_begin":
            return self.auth.begin_bootstrap_registration(
                vault_id=self.identity["vault_id"], credentials={}, bootstrap_token=data["token"])
        if command == "registration_finish":
            record = self.auth.finish_registration(
                challenge_id=data["challenge_id"], credential=data["credential"],
                credentials=self.credentials, name=data["name"])
            bootstrap = not self.credentials
            self.credentials[record["credential_id"]] = record
            self.state = "locked" if bootstrap else "unlocked"
            return self.status() if bootstrap else {**self.status({"view_token": VIEW}), "view_token": VIEW}
        if command == "operation_begin":
            if data["operation"] == "configure":
                validate_configure(data["payload"], datetime.now(timezone.utc))
            return self.auth.begin_operation(operation=data["operation"],
                normalized_payload=data["payload"], credential_index=self.credentials, **self.identity)
        if command == "operation_finish":
            grant = self.auth.verify_operation(challenge_id=data["challenge_id"],
                credential=data["credential"], credentials=self.credentials, **self.identity)
            if grant.operation == "passkey_add":
                return {"registration": self.auth.begin_passkey_add(
                    authorization=grant, credentials=self.credentials)}
            if grant.operation == "unlock":
                self.state = "unlocked"
            elif grant.operation == "lock":
                self.state = "locked"
                self.unavailable_reads = 1
                return self.status()
            elif grant.operation == "configure":
                self.phase = "configured"
            elif grant.operation == "select_chats":
                self.phase = "configured"
            return {**self.status({"view_token": VIEW}), "view_token": VIEW}
        raise ValueError("unsupported fixture command")


async def gate(browser_path, output):
    fixture = PolicyFixture()
    server = SecureAppServer(("127.0.0.1", 0), SecureHandler, ipc=fixture,
                             username="sunny", password="synthetic-app-password")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    failures, errors, restart_pages = [], [], []
    port = server.server_address[1]
    def exchange(request):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request(request.method, urlsplit(request.url).path,
                               body=request.post_data_buffer, headers=request.headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                executable_path=browser_path, headless=True, chromium_sandbox=True)
            context = await browser.new_context(extra_http_headers={
                "Authorization": "Basic " + base64.b64encode(b"sunny:synthetic-app-password").decode()})
            session = None
            authenticator = None
            async def new_authenticator():
                result = await session.send("WebAuthn.addVirtualAuthenticator", {"options": {
                    "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                    "hasUserVerification": True, "isUserVerified": True,
                    "automaticPresenceSimulation": True}})
                return result["authenticatorId"]
            async def route(handler):
                nonlocal authenticator
                request = handler.request
                parsed = urlsplit(request.url)
                # Every browser request is intercepted. No live internet is used.
                if parsed.hostname not in {"admin.example.test", "wrong.example.test"} or parsed.path not in {"/", "/security.js", "/api"}:
                    failures.append("unexpected browser request")
                    await handler.abort()
                    return
                code, headers, body = await asyncio.to_thread(exchange, request)
                if (code == 503 and request.method == "GET" and parsed.path == "/"
                        and fixture.state == "locked" and not restart_pages
                        and "Сервис временно недоступен" in body.decode("utf-8")):
                    assert headers.get("Refresh") == "2; url=/"
                    assert headers.get("Retry-After") == "2"
                    assert b"<form" not in body
                    restart_pages.append(code)
                elif code >= 400:
                    failures.append(f"HTTP {code} {parsed.path}")
                if parsed.path == "/api" and code == 200 and "registration" in json.loads(body):
                    # The backup credential belongs to a different device. The
                    # first authenticator proves the add operation before this
                    # test switches to the new authenticator for registration.
                    await session.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
                    authenticator = await new_authenticator()
                await handler.fulfill(status=code, headers=headers, body=body)
            await context.route("**/*", route)
            page = await context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("requestfailed", lambda request: failures.append("browser request failed"))
            session = await context.new_cdp_session(page)
            await session.send("WebAuthn.enable")
            authenticator = await new_authenticator()
            await page.goto(ORIGIN)
            form = page.locator("#bootstrap-form")
            await form.locator('[name="bootstrap_token"]').fill(fixture.token)
            await form.locator('[name="passphrase"]').fill("synthetic passphrase long enough")
            await form.locator('[name="name"]').fill("Main synthetic passkey")
            async with page.expect_navigation(): await form.locator("button").click()
            assert fixture.state == "locked" and len(fixture.credentials) == 1
            assert await page.locator('[name="action"][value="configure"]').count() == 0
            if output: await page.screenshot(path=str(output / "locked.png"), full_page=True)
            form = page.locator('form[data-operation="unlock"]')
            await form.locator("xpath=..").evaluate("element => element.open = true")
            await form.locator('[name="passphrase"]').fill("synthetic passphrase long enough")
            async with page.expect_navigation(): await form.locator("button").click()
            assert fixture.state == "unlocked"
            form = page.locator('form:has(input[value="configure"])')
            kind = b"ssh-ed25519"
            blob = len(kind).to_bytes(4, "big") + kind + (32).to_bytes(4, "big") + b"x" * 32
            values = {"telegram_api_id": "12345", "telegram_api_hash": "a" * 32,
                      "vpn_subscription_url": "https://subscription.example/synthetic",
                      "openrouter_api_key": "synthetic-openrouter-key",
                      "upload_host": "receiver.example", "upload_port": "22",
                      "known_host": "receiver.example ssh-ed25519 " + base64.b64encode(blob).decode(),
                      "consent_expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}
            for name, value in values.items(): await form.locator(f'[name="{name}"]').fill(value)
            await form.locator('[name="confirm_data_scope"]').check()
            if output: await page.screenshot(path=str(output / "configure.png"), full_page=True)
            async with page.expect_navigation(): await form.locator("button").click()
            payload = next(data["payload"] for command, data in fixture.calls
                           if command == "operation_begin" and data["operation"] == "configure")
            assert payload["telegram_api_id"] == "12345"
            assert payload["openrouter_model"] == "anthropic/claude-opus-5.5"
            fixture.phase = "dialogs_listed"
            await page.reload()
            form = page.locator('form:has(input[value="select_chats"])')
            await form.locator('[name="chat_id"]').nth(0).check()
            await form.locator('[name="chat_id"]').nth(1).check()
            await form.locator('[name="confirm_lock"]').check()
            async with page.expect_navigation(): await form.locator("button").click()
            payload = next(data["payload"] for command, data in fixture.calls
                           if command == "operation_begin" and data["operation"] == "select_chats")
            assert payload["chat_ids"] == ["-1000000000123", "-1000000000124"]
            form = page.locator('form[data-operation="passkey_add"]')
            await form.locator("xpath=..").evaluate("element => element.open = true")
            await form.locator('[name="name"]').fill("Backup synthetic passkey")
            async with page.expect_navigation(): await form.locator("button").click()
            assert len(fixture.credentials) == 2
            assert {row["name"] for row in fixture.credentials.values()} == {"Main synthetic passkey", "Backup synthetic passkey"}
            form = page.locator('form[data-operation="lock"]')
            await form.locator("xpath=..").evaluate("element => element.open = true")
            async with page.expect_navigation(): await form.locator("button").click()
            # The browser's fixed relative Refresh must recover without another
            # click, signed mutation or access to a credential form during downtime.
            await page.locator('form[data-operation="unlock"]').wait_for(state="attached", timeout=10000)
            assert await page.get_by_role("heading", name="Vault заблокирован").is_visible()
            assert fixture.state == "locked" and restart_pages == [503]
            assert sum(command == "operation_begin" and data["operation"] == "lock"
                       for command, data in fixture.calls) == 1
            assert await page.locator('[name="action"][value="configure"]').count() == 0
            if output: await page.screenshot(path=str(output / "restart-recovered.png"), full_page=True)
            await page.goto("https://wrong.example.test")
            assert await page.locator("#security-error").is_visible()
            assert await page.locator("button:enabled").count() == 0
            await page.set_viewport_size({"width": 390, "height": 844})
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert not failures, failures
            assert not errors, errors
            await browser.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    print("Security UI: bootstrap, unlock, configure, selection, backup passkey and lock/restart recovery passed; one expected restart HTTP 503; wrong origin disabled; no external requests or JavaScript errors.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", help="optional cached Chromium headless-shell path")
    parser.add_argument("--out-dir", type=Path, help="optional synthetic screenshots directory")
    args = parser.parse_args()
    if args.out_dir: args.out_dir.mkdir(parents=True, exist_ok=True)
    asyncio.run(gate(args.browser, args.out_dir))
