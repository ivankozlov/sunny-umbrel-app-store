from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from sunny_digest.authn import AuthorizationError, WebAuthnAuthorizer
from sunny_digest.guardian import Guardian
from sunny_digest.memory_guard import LockedBuffer
from sunny_digest.migrate_vault import write_manifest
from sunny_digest.models import DialogCandidate, PeerSpec
from sunny_digest.storage import Paths
from sunny_digest.vault import Vault, VaultFormatError
from sunny_digest.guardian_engine import Collector
from sunny_digest.storage import read_json


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)
PEERS = [PeerSpec("channel", 124, 91), PeerSpec("channel", 123, 92)]
CHAT_IDS = [peer.telegram_chat_id() for peer in PEERS]
VPN_NODE = {
    "type": "vless", "server": "1.1.1.1", "port": 443,
    "uuid": "11111111-2222-4333-8444-555555555555", "network": "tcp",
    "tls": True, "servername": "cdn.example", "client-fingerprint": "chrome",
    "reality-opts": {"public-key": "E" * 43, "short-id": "1a2b3c4d"},
    "flow": "xtls-rprx-vision", "udp": False,
}


def known_host_blob():
    kind = b"ssh-ed25519"
    return base64.b64encode(len(kind).to_bytes(4, "big") + kind +
                            (32).to_bytes(4, "big") + b"x" * 32).decode("ascii")


def configure_payload(subscription_url):
    return {
        "telegram_api_id": "12345", "telegram_api_hash": "a" * 32,
        "vpn_subscription_url": subscription_url,
        "openrouter_api_key": "sk-or-canary-openrouter-key",
        "openrouter_model": "anthropic/claude-opus-5.5",
        "upload_host": "receiver.example", "upload_port": "22", "upload_user": "root",
        "known_host": f"receiver.example ssh-ed25519 {known_host_blob()}",
        "consent_expires_at": "2026-08-05T00:00:00Z",
    }


class Clock:
    def __init__(self): self.value = 1000.0
    def __call__(self): return self.value


def client_data(kind, nonce):
    return json.dumps({"type": kind, "challenge": nonce, "origin": "https://admin.example.test", "crossOrigin": False}, separators=(",", ":")).encode()


def registration(nonce, key, credential_id=b"guardian-key"):
    public = key.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")})
    auth_data = hashlib.sha256(b"example.test").digest() + b"\x45" + b"\0" * 4 + b"\0" * 16 + len(credential_id).to_bytes(2, "big") + credential_id + cose
    return {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key", "response": {"clientDataJSON": b64(client_data("webauthn.create", nonce)), "attestationObject": b64(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data}))}}


def assertion(nonce, key, credential_id=b"guardian-key", count=0):
    data = client_data("webauthn.get", nonce)
    auth_data = hashlib.sha256(b"example.test").digest() + b"\x05" + count.to_bytes(4, "big")
    signature = key.sign(auth_data + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
    return {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key", "response": {"clientDataJSON": b64(data), "authenticatorData": b64(auth_data), "signature": b64(signature), "userHandle": None}}


def valid_string_session():
    """Offline Telethon session accepted by the production unlock validator."""
    from telethon.crypto import AuthKey
    from telethon.sessions import StringSession

    session = StringSession()
    session.set_dc(2, "149.154.167.51", 443)
    session.auth_key = AuthKey(data=b"x" * 256)
    return session.save()


class FakeGateway:
    def __init__(self, _paths):
        self.dialogs = [
            DialogCandidate(chat_id, title, peer)
            for chat_id, title, peer in zip(CHAT_IDS, ("Первый чат", "Второй чат"), PEERS)
        ]
        self.send_code_calls = 0
        self.logout_calls = 0

    async def resolve_message_links(self, _session, links):
        if len(links) != len(self.dialogs):
            raise AssertionError("unexpected Telegram links")
        return self.dialogs


class SetupGateway(FakeGateway):
    async def send_code(self, _session, _phone):
        self.send_code_calls += 1
        return valid_string_session(), "phone-code-hash"

    async def submit_code(self, _session, _phone, _code, _phone_code_hash):
        return valid_string_session(), False

    async def logout(self, _session):
        self.logout_calls += 1
        # A real reset must preserve this durable warning until the owner has
        # explicitly revoked the remote Telegram device.
        return False


class FakeVPNRuntime:
    def __init__(self, _private_dir):
        self.ready = False
        self.starts = []
        self.stop_calls = 0

    async def start(self, node):
        self.starts.append(copy.deepcopy(node))
        self.ready = True

    def ensure_alive(self):
        if not self.ready:
            raise RuntimeError("VPN is not ready")

    async def stop(self):
        self.stop_calls += 1
        self.ready = False


class FakeTunnel:
    def __init__(self, *_args): pass
    async def start(self): pass
    def ensure_alive(self): pass
    async def stop(self): pass


class Engine:
    def __init__(self, paths, *, monotonic, **kwargs):
        self.paths = paths
        self.clock, self.calls, self.revoked = monotonic, [], asyncio.Event()
        self._generated_at = lambda gate, received: None
        self._fresh_gate = lambda: None
        self._run_morning_pass = lambda: None
    async def public_status(self): return {"phase": "configured", "configured": True}
    async def close(self): self.calls.append("close")
    async def revoke_and_reset(self): self.calls.append("reset"); return {}
    def _write_revocation_warning(self):
        writer = object.__new__(Collector)
        writer.paths, writer.clock = self.paths, lambda: NOW
        writer._write_revocation_warning()
    def trigger_run(self): self.calls.append("run_now"); return True
    async def run_once(self): self.calls.append("run")


class GuardianTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.paths = Paths(root / "config", root / "private", root / "runtime", root / "runtime" / "admin.sock")
        for path in (self.paths.config_dir, self.paths.private_dir, self.paths.runtime_dir): path.mkdir(mode=0o700)
        self.scratch = root / "scratch"; self.scratch.mkdir(mode=0o700)
        self.clock = Clock()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = WebAuthnAuthorizer(trusted_origin="https://admin.example.test", rp_id="example.test", clock=self.clock)

    def tearDown(self): self.tmp.cleanup()

    def guardian(self, engine_factory=Engine):
        def vault_factory(path, **kwargs):
            return Vault(path, **kwargs, memory_preflight=lambda: None,
                         buffer_factory=lambda value: LockedBuffer(value, require_lock=False))
        return Guardian(self.paths, scratch=self.scratch, authorizer=self.auth,
                        memory_preflight=lambda: None, vault_factory=vault_factory,
                        engine_factory=engine_factory, monotonic=self.clock)

    async def bootstrap(self, guardian):
        token = self.auth.create_bootstrap()
        begin = await guardian.bootstrap_begin({"token": token})
        await guardian.registration_finish({"challenge_id": begin["challenge_id"], "credential": registration(begin["public_key"]["challenge"], self.key), "name": "Main", "passphrase": "a" * 20})

    async def unlock(self, guardian, phrase="a" * 20):
        begin = await guardian.begin({"operation": "unlock", "payload": {}})
        return await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], self.key), "passphrase": phrase})

    def test_bootstrap_locked_restart_and_unlock_are_cryptographic(self):
        async def run():
            guardian = self.guardian()
            self.assertEqual(guardian.security_state(), "uninitialized")
            await self.bootstrap(guardian)
            self.assertEqual(guardian.security_state(), "locked")
            self.assertIsNone(guardian.engine)
            restarted = self.guardian()
            self.assertEqual(restarted.security_state(), "locked")
            # KDF/Fernet failure is intentionally distinct from an assertion refusal.
            with self.assertRaises(Exception):
                await self.unlock(restarted, "wrong" * 5)
            self.assertIsNone(restarted.engine)
            self.clock.value += 3
            await self.unlock(restarted)
            self.assertEqual(restarted.security_state(), "unlocked")
            self.assertIsInstance(restarted.engine, Engine)
        asyncio.run(run())

    def test_unlock_pending_replay_expiry_and_manifest_hint_do_not_authorize(self):
        async def run():
            guardian = self.guardian(); await self.bootstrap(guardian)
            begin = await guardian.begin({"operation": "unlock", "payload": {}})
            self.assertEqual(guardian.security_state(), "unlock_pending")
            with self.assertRaises(AuthorizationError):
                await guardian.begin({"operation": "unlock", "payload": {}})
            manifest = self.paths.private_dir / "vault-manifest.json"
            value = json.loads(manifest.read_text())
            value["passkeys"][b64(b"guardian-key")]["public_key"] = b64(b"forged-public-key")
            manifest.write_text(json.dumps(value))
            forged = ec.generate_private_key(ec.SECP256R1())
            with self.assertRaises(AuthorizationError):
                await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], forged), "passphrase": "a" * 20})
            self.assertIsNone(guardian.engine)
            write_manifest(self.paths, guardian.vault) if guardian.vault._snapshot is not None else None
            # A consumed challenge cannot be replayed, even after restoring a valid hint.
            with self.assertRaises(AuthorizationError):
                await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], self.key), "passphrase": "a" * 20})
            self.clock.value += 121
            with self.assertRaises(AuthorizationError):
                await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], self.key), "passphrase": "a" * 20})
        asyncio.run(run())

    def test_stale_epoch_refuses_a_freshly_signed_mutation(self):
        async def run():
            guardian = self.guardian(); await self.bootstrap(guardian); await self.unlock(guardian)
            begin = await guardian.begin({"operation": "view_status", "payload": {}})
            snapshot = guardian.vault.snapshot; snapshot["security_epoch"] += 1; guardian.vault.update(snapshot)
            with self.assertRaises(AuthorizationError):
                await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], self.key)})
        asyncio.run(run())

    def test_view_lease_and_lock_close_the_actual_vault_buffer(self):
        async def run():
            guardian = self.guardian(); await self.bootstrap(guardian); result = await self.unlock(guardian)
            token = result["view_token"]
            self.assertTrue((await guardian.status(token))["view_authorized"])
            self.clock.value += 901
            self.assertFalse((await guardian.status(token))["view_authorized"])
            begin = await guardian.begin({"operation": "lock", "payload": {}})
            await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], self.key)})
            self.assertEqual(guardian.security_state(), "locked")
            self.assertIsNone(guardian.engine)
            self.assertTrue(guardian.exit_requested.is_set())
        asyncio.run(run())

    def test_protected_reset_is_payload_bound_and_run_now_only_wakes(self):
        async def run():
            guardian = self.guardian(); await self.bootstrap(guardian); await self.unlock(guardian)
            begin = await guardian.begin({"operation": "revoke_and_reset", "payload": {}})
            with self.assertRaises(AuthorizationError):
                await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(b64(b"other"), self.key)})
            self.assertFalse(guardian.exit_requested.is_set())
            begin = await guardian.begin({"operation": "revoke_and_reset", "payload": {}})
            await guardian.finish({"challenge_id": begin["challenge_id"], "credential": assertion(begin["public_key"]["challenge"], self.key)})
            self.assertIn("reset", guardian.engine.calls)
            guardian.trigger_run()
            self.assertTrue(guardian._wakeup.is_set())
        asyncio.run(run())

    def test_last_passkey_refusal_preserves_signed_view_and_unlock_after_restart(self):
        """Replace the redundant owner UI deletion trial with the real signed policy path."""
        async def run():
            guardian = self.guardian()
            restarted = None
            credential_id = b64(b"guardian-key")
            try:
                await self.bootstrap(guardian)
                initial = await self.unlock(guardian)
                self.assertEqual(set(guardian.vault.snapshot["passkeys"]), {credential_id})
                before = guardian.vault.snapshot
                with self.assertRaisesRegex(ValueError, "last or unknown passkey"):
                    await guardian.begin({"operation": "passkey_remove",
                                          "payload": {"value": credential_id}})
                self.assertEqual(guardian.vault.snapshot, before)
                self.assertEqual(guardian.security_state(), "unlocked")
                self.assertEqual(set(guardian.vault.snapshot["passkeys"]), {credential_id})
                self.assertTrue((await guardian.status(initial["view_token"]))["view_authorized"])
                # The canonical vault validator also refuses an empty key set
                # independently of the earlier UI/ceremony admission guard.
                empty = guardian.vault.snapshot
                empty["passkeys"] = {}
                with self.assertRaises(VaultFormatError):
                    guardian.vault.update(empty)
                self.assertEqual(guardian.vault.snapshot, before)
                begin = await guardian.begin({"operation": "view_status", "payload": {}})
                view = await guardian.finish({
                    "challenge_id": begin["challenge_id"],
                    "credential": assertion(begin["public_key"]["challenge"], self.key),
                })
                self.assertTrue(view["view_authorized"])
                self.assertEqual([row["credential_id"] for row in view["passkeys"]], [credential_id])
                begin = await guardian.begin({"operation": "lock", "payload": {}})
                await guardian.finish({
                    "challenge_id": begin["challenge_id"],
                    "credential": assertion(begin["public_key"]["challenge"], self.key),
                })
                self.assertEqual(guardian.security_state(), "locked")
                self.assertIsNone(guardian.vault._snapshot)
                self.auth = WebAuthnAuthorizer(trusted_origin="https://admin.example.test",
                                               rp_id="example.test", clock=self.clock)
                restarted = self.guardian()
                self.assertEqual(restarted.security_state(), "locked")
                self.clock.value += 3
                result = await self.unlock(restarted)
                self.assertEqual(result["security_state"], "unlocked")
                self.assertEqual(set(restarted.vault.snapshot["passkeys"]), {credential_id})
                self.assertEqual([row["credential_id"] for row in result["passkeys"]], [credential_id])
            finally:
                await guardian.close()
                if restarted is not None:
                    await restarted.close()
        asyncio.run(run())

    def test_real_collector_setup_then_reset_keeps_only_encrypted_canonical_records(self):
        """Configure through reset uses VaultPaths; no setup secret reaches disk plaintext."""
        async def run():
            runtimes, gateways = [], []

            async def subscription(_url):
                return [dict(VPN_NODE)]

            def engine_factory(paths, **_unused):
                runtime = FakeVPNRuntime(paths.private_dir)
                gateway = SetupGateway(paths)
                runtimes.append(runtime)
                gateways.append(gateway)

                async def digest(*_args):
                    return "digest"

                return Collector(
                    paths,
                    gateway_factory=lambda *_: gateway,
                    digest_function=digest,
                    tunnel_factory=FakeTunnel,
                    transport_factory=lambda *_: None,
                    subscription_fetcher=subscription,
                    vpn_runtime_factory=lambda _private: runtime,
                    clock=lambda: NOW,
                    monotonic=self.clock,
                )

            def vault_factory(path, **kwargs):
                return Vault(path, **kwargs, memory_preflight=lambda: None,
                             buffer_factory=lambda value: LockedBuffer(value, require_lock=False))

            guardian = Guardian(
                self.paths, scratch=self.scratch, authorizer=self.auth,
                memory_preflight=lambda: None, vault_factory=vault_factory,
                engine_factory=engine_factory, monotonic=self.clock)
            await self.bootstrap(guardian)
            await self.unlock(guardian)

            async def authorize(operation, payload):
                begin = await guardian.begin({"operation": operation, "payload": payload})
                return await guardian.finish({
                    "challenge_id": begin["challenge_id"],
                    "credential": assertion(begin["public_key"]["challenge"], self.key),
                })

            payload = configure_payload(
                "https://subscription.example/vless?token=canary-vpn-token")
            payload.update({
                "openrouter_model": "anthropic/claude-opus-5.5",
                "openrouter_api_key": "sk-or-canary-openrouter-key",
                "known_host": f"receiver.example ssh-ed25519 {known_host_blob()}",
            })
            await authorize("configure", payload)
            engine = guardian.engine
            self.assertIsInstance(engine, Collector)
            self.assertEqual((await engine.send_code("+15551234567"))["phase"], "code_sent")
            self.assertEqual((await engine.submit_code("12345"))["phase"], "authenticated")
            listed = await engine.resolve_chat_links([
                "https://t.me/one/1", "https://t.me/two/1",
            ])
            self.assertEqual(listed["phase"], "dialogs_listed")
            selection = read_json(engine.paths.dialog_candidates, max_bytes=16 * 1024)
            await authorize("select_chats", {
                "selection_id": selection["selection_id"], "chat_ids": CHAT_IDS,
            })
            self.assertTrue(read_json(engine.paths.settings, max_bytes=16 * 1024)["chat_locked"])
            self.assertGreaterEqual(len(guardian.vault.snapshot["records"]), 7)

            persisted = b"".join(
                path.read_bytes() for path in self.paths.config_dir.parent.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(b"canary-vpn-token", persisted)
            self.assertNotIn(b"canary-openrouter-key", persisted)

            # The second Guardian process decrypts and validates the real
            # canonical settings/session/keypair before it may install a Collector.
            guardian.vault.close()
            guardian = Guardian(
                self.paths, scratch=self.scratch, authorizer=self.auth,
                memory_preflight=lambda: None, vault_factory=vault_factory,
                engine_factory=engine_factory, monotonic=self.clock)
            await self.unlock(guardian)
            self.assertTrue(read_json(guardian.engine.paths.settings, max_bytes=16 * 1024)["chat_locked"])
            self.assertGreaterEqual(len(guardian.vault.snapshot["records"]), 7)

            reset = await authorize("revoke_and_reset", {})
            self.assertTrue(reset["revocation_required"])
            self.assertEqual(reset["last_error_type"], "TelegramLogoutUnconfirmed")
            self.assertEqual(guardian.vault.snapshot["records"], {})
            self.assertIn(b64(b"guardian-key"), guardian.vault.snapshot["passkeys"])
            self.assertEqual(gateways[-1].logout_calls, 1)
            self.assertGreaterEqual(runtimes[-1].stop_calls, 1)

            guardian.vault.close()
            restarted = Guardian(
                self.paths, scratch=self.scratch, authorizer=self.auth,
                memory_preflight=lambda: None, vault_factory=vault_factory,
                engine_factory=engine_factory, monotonic=self.clock)
            result = await self.unlock(restarted)
            self.assertTrue(result["revocation_required"])
            self.assertEqual(restarted.vault.snapshot["records"], {})
        asyncio.run(run())

    def test_reset_intent_survives_failure_or_cancellation_before_cleanup(self):
        """A verified reset cannot be forgotten at its first asynchronous wait."""
        def engine_factory(paths, **_unused):
            return Collector(paths, clock=lambda: NOW, monotonic=self.clock,
                             vpn_runtime_factory=FakeVPNRuntime)

        async def run(target, failure):
            guardian = self.guardian(engine_factory)
            if not guardian.vault.path.exists():
                await self.bootstrap(guardian)
            await self.unlock(guardian)
            self.assertFalse(self.paths.revocation_warning.exists())
            begin = await guardian.begin({"operation": "revoke_and_reset", "payload": {}})
            victim = guardian.jobs if target == "cancel" else guardian.engine

            async def interrupted():
                # The real writer has atomically persisted and fsynced the marker
                # before either cancellation or native cleanup can suspend reset.
                self.assertTrue(self.paths.revocation_warning.exists())
                raise failure

            restarted = None
            try:
                with patch.object(victim, target, AsyncMock(side_effect=interrupted)):
                    with self.assertRaises(type(failure)):
                        await guardian.finish({
                            "challenge_id": begin["challenge_id"],
                            "credential": assertion(begin["public_key"]["challenge"], self.key),
                        })
                guardian.vault.close()
                restarted = self.guardian(engine_factory)
                self.clock.value += 3
                status = await self.unlock(restarted)
                self.assertTrue(status["revocation_required"])
                with self.assertRaises(RuntimeError):
                    restarted.engine._require_no_revocation_warning()
            finally:
                guardian.vault.close()
                if restarted is not None:
                    await restarted.close()
                self.paths.revocation_warning.unlink(missing_ok=True)

        for target, failure in (("cancel", RuntimeError("injected cleanup failure")),
                                ("cancel", asyncio.CancelledError()),
                                ("close", RuntimeError("injected close failure"))):
            with self.subTest(target=target, failure=type(failure).__name__):
                asyncio.run(run(target, failure))


if __name__ == "__main__":
    unittest.main()
