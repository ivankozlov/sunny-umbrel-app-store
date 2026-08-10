from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sunny_digest.collector import Collector
from sunny_digest.contracts import build_upload, canonical_upload_bytes
from sunny_digest.models import (
    DialogCandidate,
    FetchResult,
    PeerSpec,
    SelectedMessage,
)
from sunny_digest.settings import CREDENTIALS_SCHEMA, SETTINGS_SCHEMA, load_settings
from sunny_digest.storage import Paths, atomic_write_bytes, atomic_write_json, read_json


NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)
SOURCE_ID = "12345678-1234-4678-9234-567812345678"
CHAT_ID = -1_000_000_100_123
PEER = PeerSpec("channel", 100123, 998877)


def fake_known_host_key() -> str:
    key_type = b"ssh-ed25519"
    blob = len(key_type).to_bytes(4, "big") + key_type + (32).to_bytes(
        4, "big") + b"x" * 32
    return __import__("base64").b64encode(blob).decode("ascii")


def make_paths(root: Path) -> Paths:
    return Paths(root / "config", root / "private", root / "runtime",
                 root / "runtime" / "control.sock")


def gate(*, due: bool = True, day: str = "2026-08-04", sequence: int = 1,
         previous=None, cursor: int = 10):
    day_prefix = day
    return {
        "schema": "sunny.personal-digest-gate.v1",
        "ok": True,
        "due": due,
        "reason": "due" if due else "before_window",
        "server_time": f"{day_prefix}T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "digest_date": day,
        "prepare_not_before": f"{day_prefix}T03:00:00+03:00",
        "accept_until": f"{day_prefix}T04:45:00+03:00",
        "next_sequence": sequence,
        "previous_sha256": previous,
        "from_message_id_exclusive": cursor,
        "max_upload_bytes": 32768,
    }


def seed_locked(paths: Paths, *, source_id: str = SOURCE_ID, initial: int = 10):
    paths.ensure()
    atomic_write_json(paths.settings, {
        "schema": SETTINGS_SCHEMA,
        "phase": "chat_locked",
        "chat_locked": True,
        "openrouter_model": "anthropic/example",
        "upload": {"host": "receiver.example", "port": 22, "user": "root"},
        "consent": {
            "scope": "one-exact-chat-text-and-captions",
            "granted_at": "2026-08-04T00:00:00Z",
            "expires_at": "2026-08-05T00:00:00Z",
        },
        "source_id": source_id,
        "chat_id": CHAT_ID,
        "chat_title": "Pilot group",
        "peer": PEER.as_dict(),
        "initial_message_id": initial,
        "upload_public_key": "ssh-ed25519 AAAAtest source",
        "upload_key_fingerprint": "SHA256:test",
    })
    atomic_write_json(paths.credentials, {
        "schema": CREDENTIALS_SCHEMA,
        "telegram_api_id": 12345,
        "telegram_api_hash": "a" * 32,
        "openrouter_api_key": "sk-or-test-secret",
    })
    atomic_write_bytes(paths.telegram_session, b"string-session", 0o600)
    atomic_write_json(paths.telegram_session_outstanding, {
        "schema": "sunny.personal-digest-session-outstanding.v1",
        "outstanding": True,
        "created_at": "2026-08-04T00:00:00Z",
    })
    atomic_write_bytes(paths.chat_locked, b"locked\n", 0o600)


async def configure_unlocked(collector: Collector, paths: Paths, phase: str):
    known = "receiver.example ssh-ed25519 " + fake_known_host_key()
    await collector.configure({
        "telegram_api_id": "12345",
        "telegram_api_hash": "a" * 32,
        "openrouter_api_key": "sk-or-test-secret",
        "openrouter_model": "anthropic/example",
        "upload_host": "receiver.example",
        "upload_port": "22",
        "upload_user": "root",
        "known_host": known,
        "consent_expires_at": "2026-08-05T00:00:00Z",
    })
    settings = read_json(paths.settings)
    settings["phase"] = phase
    atomic_write_json(paths.settings, settings)
    atomic_write_bytes(paths.telegram_session, b"string-session", 0o600)
    if phase == "dialogs_listed":
        atomic_write_json(paths.dialog_candidates, {
            "dialogs": [DialogCandidate(CHAT_ID, "Pilot group", PEER).as_private_dict()],
        })


class FakeGateway:
    def __init__(self):
        self.dialogs = [DialogCandidate(CHAT_ID, "Pilot group", PEER)]
        self.fetch_result = FetchResult(11, [
            SelectedMessage(11, 7, NOW, "Message text"),
        ])
        self.fetch_calls = 0
        self.fetch_starts = []
        self.fetch_not_before = []
        self.logout_calls = 0
        self.bootstrap_value = 10
        self.bootstrap_calls = []

    async def send_code(self, _session, _phone):
        return "pending-string-session", "phone-code-hash"

    async def list_dialogs(self, _session):
        return self.dialogs

    async def bootstrap_cursor(self, _session, peer, now):
        if peer != PEER:
            raise AssertionError("wrong peer")
        self.bootstrap_calls.append(now)
        return self.bootstrap_value

    async def fetch(self, _session, peer, expected_chat_id, start, _cutoff,
                    not_before_at=None):
        self.fetch_calls += 1
        self.fetch_starts.append(start)
        self.fetch_not_before.append(not_before_at)
        if peer != PEER or expected_chat_id != CHAT_ID or start != 10:
            raise AssertionError("runtime escaped selected peer/cursor")
        return self.fetch_result

    async def logout(self, _session):
        self.logout_calls += 1
        return True


class FakeTransport:
    def __init__(self, gate_value):
        self.gate_value = gate_value
        self.gate_calls = 0
        self.uploads = []

    async def gate(self, source_id, chat_id, revoked):
        self.gate_calls += 1
        if source_id != SOURCE_ID or chat_id != CHAT_ID or revoked.is_set():
            raise AssertionError("invalid gate binding")
        return dict(self.gate_value)

    async def upload(self, raw, revoked):
        if revoked.is_set():
            raise asyncio.CancelledError
        self.uploads.append(raw)
        return {"ok": True}


class FinalPendingAcquireLock(asyncio.Lock):
    def __init__(self):
        super().__init__()
        self.calls = 0
        self.final_waiting = asyncio.Event()
        self.allow_final = asyncio.Event()

    async def acquire(self):
        self.calls += 1
        if self.calls == 6:
            self.final_waiting.set()
            await self.allow_final.wait()
        return await super().acquire()


class CollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_gate_not_due_prevents_telegram_and_openrouter(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            transport = FakeTransport(gate(due=False))
            digest_calls = []

            async def digest(*args):
                digest_calls.append(args)
                return "must not happen"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "not_due")
            self.assertEqual(gateway.fetch_calls, 0)
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.uploads, [])

    async def test_public_status_contains_no_credentials_or_exact_peer_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            collector = Collector(paths, clock=lambda: NOW)
            public = await collector.public_status()
            serialized = json.dumps(public, sort_keys=True)
            for forbidden in (
                "telegram_api_hash", "openrouter_api_key", "access_hash",
                "known_hosts", "string-session", "sk-or-test-secret",
            ):
                self.assertNotIn(forbidden, serialized)

    async def test_initial_gate_cursor_must_equal_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, initial=10)
            gateway = FakeGateway()
            transport = FakeTransport(gate(due=False, cursor=9))
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "error")
            self.assertEqual(result["last_error_type"], "RuntimeError")
            self.assertEqual(gateway.fetch_calls, 0)

    async def test_media_only_cursor_upload_skips_openrouter(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            gateway.fetch_result = FetchResult(14, [])
            transport = FakeTransport(gate())
            digest_calls = []

            async def digest(*args):
                digest_calls.append(args)
                return "unexpected"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "uploaded")
            self.assertEqual(digest_calls, [])
            payload = json.loads(transport.uploads[0])
            self.assertTrue(payload["empty"])
            self.assertEqual(payload["message_count"], 0)
            self.assertEqual(payload["digest"], "")
            self.assertEqual(payload["through_message_id"], 14)

    async def test_stale_unaccepted_pending_rolls_into_new_due_day(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            old = build_upload(
                source_id=SOURCE_ID, gate=gate(day="2026-08-03"), chat_id=CHAT_ID,
                through_message_id=11, message_count=1, digest="Вчера",
                model="anthropic/example",
                generated_at=datetime(2026, 8, 3, 0, 31, tzinfo=timezone.utc),
            )
            old_bytes = canonical_upload_bytes(old)
            atomic_write_bytes(paths.pending, old_bytes, 0o600)
            gateway = FakeGateway()
            transport = FakeTransport(gate(day="2026-08-04"))

            async def digest(*_args):
                return "Сегодня"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "uploaded")
            self.assertEqual(len(transport.uploads), 1)
            self.assertNotEqual(transport.uploads[0], old_bytes)
            self.assertEqual(json.loads(transport.uploads[0])["digest_date"], "2026-08-04")
            self.assertFalse(paths.pending.exists())
            self.assertEqual(gateway.bootstrap_calls, [NOW])

    async def test_unaccepted_pending_rebuilds_on_same_day_timezone_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            old_gate = gate()
            old_gate["timezone"] = "Europe/Istanbul"
            old = build_upload(
                source_id=SOURCE_ID, gate=old_gate, chat_id=CHAT_ID,
                through_message_id=11, message_count=1, digest="Old timezone",
                model="anthropic/example", generated_at=NOW + timedelta(minutes=1),
            )
            old_bytes = canonical_upload_bytes(old)
            atomic_write_bytes(paths.pending, old_bytes, 0o600)
            changed_gate = gate()
            changed_gate["timezone"] = "Asia/Baghdad"
            gateway = FakeGateway()
            transport = FakeTransport(changed_gate)

            async def digest(*_args):
                return "New timezone"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "uploaded")
            payload = json.loads(transport.uploads[0])
            self.assertEqual(payload["timezone"], "Asia/Baghdad")
            self.assertNotEqual(transport.uploads[0], old_bytes)

    async def test_revoke_interleaving_cannot_recreate_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            transport = FakeTransport(gate())

            async def digest(*_args):
                return "Digest"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            controlled = FinalPendingAcquireLock()
            collector.state_lock = controlled
            run_task = asyncio.create_task(collector.run_once())
            await asyncio.wait_for(controlled.final_waiting.wait(), timeout=2)
            reset_task = asyncio.create_task(collector.revoke_and_reset())
            while not collector.revoked.is_set():
                await asyncio.sleep(0)
            reset_result = await asyncio.wait_for(reset_task, timeout=2)
            controlled.allow_final.set()
            run_result = await asyncio.wait_for(run_task, timeout=2)
            self.assertEqual(reset_result["last_result"], "reset")
            self.assertEqual(run_result["last_result"], "revoked")
            self.assertFalse(paths.pending.exists())
            self.assertEqual(transport.uploads, [])

    async def test_setup_source_is_canonical_uuid_and_chat_is_permanently_locked(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            gateway = FakeGateway()

            async def keygen(_paths, source_id):
                uuid.UUID(source_id)
                return "ssh-ed25519 AAAAtest source", "SHA256:test"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                keygen_function=keygen, clock=lambda: NOW,
            )
            known = "receiver.example ssh-ed25519 " + fake_known_host_key()
            await collector.configure({
                "telegram_api_id": "12345",
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "sk-or-test-secret",
                "openrouter_model": "anthropic/example",
                "upload_host": "receiver.example",
                "upload_port": "22",
                "upload_user": "root",
                "known_host": known,
                "consent_expires_at": "2026-08-05T00:00:00Z",
            })
            settings = read_json(paths.settings)
            settings["phase"] = "authenticated"
            atomic_write_json(paths.settings, settings)
            atomic_write_bytes(paths.telegram_session, b"string-session", 0o600)
            await collector.list_dialogs()
            locked = await collector.select_chat(CHAT_ID)
            self.assertEqual(str(uuid.UUID(locked["source_id"])), locked["source_id"])
            self.assertNotIn("sunny-", locked["source_id"])
            self.assertEqual(locked["initial_message_id"], 0)
            self.assertEqual(gateway.bootstrap_calls, [])
            with self.assertRaises(RuntimeError):
                await collector.list_dialogs()
            with self.assertRaises(RuntimeError):
                await collector.configure({})

    async def test_telegram_authorization_is_prearmed_before_network_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            gateway = FakeGateway()

            async def failed_send_code(_session, _phone):
                raise RuntimeError("ambiguous Telegram authorization failure")

            gateway.send_code = failed_send_code
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            known = "receiver.example ssh-ed25519 " + fake_known_host_key()
            await collector.configure({
                "telegram_api_id": "12345",
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "sk-or-test-secret",
                "openrouter_model": "anthropic/example",
                "upload_host": "receiver.example",
                "upload_port": "22",
                "upload_user": "root",
                "known_host": known,
                "consent_expires_at": "2026-08-05T00:00:00Z",
            })
            with self.assertRaises(RuntimeError):
                await collector.send_code("+15555550123")
            self.assertTrue(paths.telegram_session_outstanding.exists())

    async def test_positive_private_dialog_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            gateway = FakeGateway()
            gateway.dialogs = [DialogCandidate(
                123, "Private user", PeerSpec("channel", 123, 9))]
            collector = Collector(paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            await configure_unlocked(collector, paths, "authenticated")
            with self.assertRaises(ValueError):
                await collector.list_dialogs()

    async def test_orphaned_partial_setup_can_always_be_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA,
                "telegram_api_id": 12345,
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "sk-or-test-secret",
            })
            atomic_write_bytes(paths.telegram_session, b"orphan-session", 0o600)
            atomic_write_bytes(paths.dialog_candidates, b'{"dialogs":[]}\n', 0o600)
            atomic_write_bytes(paths.upload_key, b"orphan-private-key", 0o600)
            gateway = FakeGateway()
            collector = Collector(paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            self.assertEqual((await collector.public_status())["phase"], "fresh")
            result = await collector.revoke_and_reset()
            self.assertEqual(result["last_result"], "reset")
            self.assertEqual(gateway.logout_calls, 1)
            for path in paths.reset_files():
                self.assertFalse(path.exists(), str(path))

    async def test_consent_renewal_is_narrow_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            transport = FakeTransport(gate())

            async def digest(*_args):
                return "Renewed digest"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            before = load_settings(paths)
            renewed = await collector.renew_consent("2026-08-06T00:00:00Z")
            after = load_settings(paths)
            self.assertTrue(renewed["consent_active"])
            for immutable in ("source_id", "chat_id", "peer", "openrouter_model", "upload"):
                self.assertEqual(after[immutable], before[immutable])
            self.assertEqual(after["consent"]["expires_at"], "2026-08-06T00:00:00Z")
            for invalid in ("2026-08-04T01:29:59Z", "2026-11-03T00:00:01Z"):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        await collector.renew_consent(invalid)

    async def test_expired_consent_blocks_fetch_until_renewed(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            settings = read_json(paths.settings)
            settings["consent"]["granted_at"] = "2026-08-03T00:00:00Z"
            settings["consent"]["expires_at"] = "2026-08-03T23:59:59Z"
            atomic_write_json(paths.settings, settings)
            gateway = FakeGateway()
            transport = FakeTransport(gate())

            async def digest(*_args):
                return "Digest"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            blocked = await collector.run_once()
            self.assertEqual(blocked["last_result"], "error")
            self.assertEqual(gateway.fetch_calls, 0)
            self.assertEqual(transport.gate_calls, 0)
            await collector.renew_consent("2026-08-05T00:00:00Z")
            allowed = await collector.run_once()
            self.assertEqual(allowed["last_result"], "uploaded")
            self.assertEqual(gateway.fetch_calls, 1)
            self.assertEqual(len(transport.uploads), 1)

    async def test_consent_expiring_during_gate_blocks_telegram_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            current = [NOW]

            class ExpiringTransport(FakeTransport):
                async def gate(self, source_id, chat_id, revoked):
                    result = await super().gate(source_id, chat_id, revoked)
                    current[0] = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
                    return result

            transport = ExpiringTransport(gate())
            digest_calls = []

            async def digest(*args):
                digest_calls.append(args)
                return "must not happen"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport,
                clock=lambda: current[0],
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "revoked")
            self.assertEqual(gateway.fetch_calls, 0)
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.uploads, [])

    async def test_receiver_clock_blocks_read_when_local_clock_is_behind(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            expired_gate = gate(day="2026-08-05")
            transport = FakeTransport(expired_gate)
            digest_calls = []

            async def digest(*args):
                digest_calls.append(args)
                return "must not happen"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport,
                # Umbrel still believes consent is active until the next day.
                clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "revoked")
            self.assertEqual(transport.gate_calls, 1)
            self.assertEqual(gateway.bootstrap_calls, [])
            self.assertEqual(gateway.fetch_calls, 0)
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.uploads, [])

    async def test_generated_at_uses_receiver_clock_domain_across_local_skew(self):
        cases = (
            (timedelta(minutes=-5), "2026-08-04T00:31:00Z"),
            (timedelta(minutes=5), "2026-08-04T00:31:00Z"),
        )
        for skew, expected in cases:
            with self.subTest(skew=skew), tempfile.TemporaryDirectory() as temporary:
                paths = make_paths(Path(temporary))
                seed_locked(paths)
                gateway = FakeGateway()
                transport = FakeTransport(gate())
                monotonic_values = iter((
                    100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0,
                    160.0, 160.0, 160.0, 160.0,
                ))

                async def digest(*_args):
                    return "Digest"

                collector = Collector(
                    paths, gateway_factory=lambda *_: gateway,
                    digest_function=digest,
                    transport_factory=lambda *_: transport,
                    clock=lambda: NOW + skew,
                    monotonic=lambda: next(monotonic_values),
                )
                result = await collector.run_once()
                self.assertEqual(result["last_result"], "uploaded")
                self.assertEqual(json.loads(transport.uploads[0])["generated_at"], expected)

    async def test_invalid_model_output_never_persists_and_is_rate_limited(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            transport = FakeTransport(gate())
            digest_calls = 0

            async def invalid_digest(*_args):
                nonlocal digest_calls
                digest_calls += 1
                raise RuntimeError("oversized model output")

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=invalid_digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            first = await collector.run_once()
            second = await collector.run_once()
            self.assertEqual(first["last_result"], "error")
            self.assertEqual(second["last_result"], "cooldown")
            self.assertEqual(digest_calls, 1)
            self.assertEqual(gateway.fetch_calls, 1)
            self.assertFalse(paths.pending.exists())
            self.assertEqual(transport.uploads, [])

    async def test_factory_reset_removes_atomic_crash_files_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            crash_files = []
            for path in paths.reset_files():
                crash = path.parent / f".{path.name}.power-loss"
                crash.write_text("secret remnant", encoding="utf-8")
                crash_files.append(crash)
            marker_crash = paths.config_dir / (
                f".{paths.telegram_session_outstanding.name}.power-loss")
            marker_crash.write_text("non-secret marker remnant", encoding="utf-8")
            crash_files.append(marker_crash)
            unrelated = paths.private_dir / ".unrelated"
            unrelated.write_text("keep", encoding="utf-8")
            collector = Collector(
                paths, gateway_factory=lambda *_: FakeGateway(), clock=lambda: NOW)
            result = await collector.revoke_and_reset()
            self.assertFalse(result["revocation_required"])
            for path in (*paths.reset_files(), *crash_files):
                self.assertFalse(path.exists(), str(path))
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")

    async def test_failed_logout_blocks_new_setup_until_manual_acknowledgement(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()

            async def failed_logout(_session):
                gateway.logout_calls += 1
                return False

            gateway.logout = failed_logout
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            reset = await collector.revoke_and_reset()
            self.assertTrue(reset["revocation_required"])
            self.assertEqual(reset["last_error_type"], "TelegramLogoutUnconfirmed")
            self.assertTrue(paths.revocation_warning.exists())
            restarted = Collector(paths, clock=lambda: NOW)
            self.assertTrue((await restarted.public_status())["revocation_required"])
            with self.assertRaises(RuntimeError):
                await restarted.configure({})
            acknowledged = await restarted.acknowledge_manual_revocation()
            self.assertFalse(acknowledged["revocation_required"])
            self.assertFalse(paths.revocation_warning.exists())
            self.assertFalse(paths.telegram_session_outstanding.exists())

    async def test_cancelled_logout_remains_fail_closed_after_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()

            async def cancelled_logout(_session):
                gateway.logout_calls += 1
                raise asyncio.CancelledError

            gateway.logout = cancelled_logout
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            with self.assertRaises(asyncio.CancelledError):
                await collector.revoke_and_reset()

            self.assertFalse(paths.telegram_session.exists())
            self.assertTrue(paths.telegram_session_outstanding.exists())
            self.assertTrue(paths.revocation_warning.exists())
            restarted = Collector(paths, clock=lambda: NOW)
            status = await restarted.public_status()
            self.assertEqual(status["phase"], "fresh")
            self.assertTrue(status["revocation_required"])
            with self.assertRaises(RuntimeError):
                await restarted.configure({})

    async def test_cancelled_reset_is_durable_before_waiting_for_hung_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            collector = Collector(paths, clock=lambda: NOW)
            cancellation_started = asyncio.Event()

            async def hung_cancellation():
                cancellation_started.set()
                await asyncio.Event().wait()

            collector._cancel_active_operations = hung_cancellation
            reset_task = asyncio.create_task(collector.revoke_and_reset())
            await asyncio.wait_for(cancellation_started.wait(), timeout=2)
            reset_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await reset_task

            self.assertTrue(paths.telegram_session.exists())
            self.assertTrue(paths.revocation_warning.exists())
            restarted = Collector(paths, clock=lambda: NOW)
            status = await restarted.public_status()
            self.assertEqual(status["phase"], "fresh")
            self.assertTrue(status["revocation_required"])
            with self.assertRaises(RuntimeError):
                await restarted.configure({})

    async def test_config_only_backup_restore_requires_manual_device_revocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            # Simulate Umbrel restore: config metadata is backed up, while the
            # entire private directory and runtime state are excluded.
            for candidate in tuple(paths.private_dir.iterdir()):
                candidate.unlink()
            for candidate in tuple(paths.runtime_dir.iterdir()):
                candidate.unlink()

            restored = Collector(paths, clock=lambda: NOW)
            status = await restored.public_status()
            self.assertEqual(status["phase"], "fresh")
            self.assertTrue(status["revocation_required"])
            self.assertIsNone(status["source_id"])

            acknowledged = await restored.acknowledge_manual_revocation()
            self.assertEqual(acknowledged["phase"], "fresh")
            self.assertFalse(acknowledged["revocation_required"])
            self.assertFalse(paths.settings.exists())
            self.assertFalse(paths.telegram_session_outstanding.exists())

    async def test_reset_overtakes_hung_setup_network_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            started = asyncio.Event()
            cancelled = asyncio.Event()
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            await configure_unlocked(collector, paths, "authenticated")

            async def hung_dialogs(_session):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

            gateway.list_dialogs = hung_dialogs
            setup_task = asyncio.create_task(collector.list_dialogs())
            await asyncio.wait_for(started.wait(), timeout=2)
            reset = await asyncio.wait_for(collector.revoke_and_reset(), timeout=2)
            await asyncio.gather(setup_task, return_exceptions=True)
            self.assertTrue(cancelled.is_set())
            self.assertEqual(reset["last_result"], "reset")
            self.assertFalse(paths.credentials.exists())

    async def test_reset_cancels_and_waits_for_hung_runtime_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            started = asyncio.Event()
            cancelled = asyncio.Event()
            gateway = FakeGateway()

            async def hung_fetch(*_args, **_kwargs):
                gateway.fetch_calls += 1
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

            gateway.fetch = hung_fetch
            transport = FakeTransport(gate())
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                transport_factory=lambda *_: transport, clock=lambda: NOW)
            run_task = asyncio.create_task(collector.run_once())
            await asyncio.wait_for(started.wait(), timeout=2)
            reset = await asyncio.wait_for(collector.revoke_and_reset(), timeout=2)
            run = await asyncio.wait_for(run_task, timeout=2)
            self.assertTrue(cancelled.is_set())
            self.assertEqual(run["last_result"], "revoked")
            self.assertEqual(reset["last_result"], "reset")
            self.assertFalse(paths.pending.exists())

    async def test_receiver_clock_rejects_consent_more_than_ninety_days_ahead(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            settings = read_json(paths.settings)
            settings["consent"]["granted_at"] = (
                NOW + timedelta(seconds=1)
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
            settings["consent"]["expires_at"] = (
                NOW + timedelta(days=90, seconds=1)
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
            atomic_write_json(paths.settings, settings)
            gateway = FakeGateway()
            transport = FakeTransport(gate())
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                transport_factory=lambda *_: transport,
                # A fast Umbrel clock still sees the locally configured consent
                # as active; the authenticated receiver clock must reject it.
                clock=lambda: NOW + timedelta(days=1),
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "revoked")
            self.assertEqual(transport.gate_calls, 1)
            self.assertEqual(gateway.fetch_calls, 0)

    async def test_local_ack_checkpoint_rejects_receiver_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway()
            first_transport = FakeTransport(gate())

            async def digest(*_args):
                return "Digest"

            first = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: first_transport, clock=lambda: NOW)
            self.assertEqual((await first.run_once())["last_result"], "uploaded")
            checkpoint = read_json(paths.acknowledged)
            self.assertEqual(checkpoint["sequence"], 1)

            rollback_gateway = FakeGateway()
            rollback = Collector(
                paths, gateway_factory=lambda *_: rollback_gateway,
                digest_function=digest,
                transport_factory=lambda *_: FakeTransport(gate()), clock=lambda: NOW)
            result = await rollback.run_once()
            self.assertEqual(result["last_result"], "error")
            self.assertEqual(result["last_error_type"], "RuntimeError")
            self.assertEqual(rollback_gateway.fetch_calls, 0)

    async def test_lost_ack_reconciliation_persists_local_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            payload = build_upload(
                source_id=SOURCE_ID, gate=gate(), chat_id=CHAT_ID,
                through_message_id=11, message_count=1, digest="Digest",
                model="anthropic/example", generated_at=NOW,
            )
            atomic_write_bytes(paths.pending, canonical_upload_bytes(payload), 0o600)
            accepted_gate = gate(
                due=False, sequence=2, previous=payload["content_sha256"], cursor=11)
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                transport_factory=lambda *_: FakeTransport(accepted_gate),
                clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "reconciled")
            self.assertFalse(paths.pending.exists())
            checkpoint = read_json(paths.acknowledged)
            self.assertEqual(checkpoint["sequence"], 1)
            self.assertEqual(checkpoint["content_sha256"], payload["content_sha256"])
            self.assertEqual(gateway.fetch_calls, 0)


class TestBugSetupConsent20260810(unittest.IsolatedAsyncioTestCase):
    """Expired consent must not permit Telegram setup reads or a chat lock."""

    async def test_expired_consent_blocks_dialog_listing_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            current = [NOW]
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: current[0])
            await configure_unlocked(collector, paths, "authenticated")
            current[0] = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
            calls = []
            original = gateway.list_dialogs

            async def tracked_list_dialogs(session):
                calls.append(session)
                return await original(session)

            gateway.list_dialogs = tracked_list_dialogs
            with self.assertRaisesRegex(RuntimeError, "consent is expired"):
                await collector.list_dialogs()
            self.assertEqual(calls, [])
            self.assertFalse(paths.dialog_candidates.exists())
            self.assertEqual(load_settings(paths)["phase"], "authenticated")

    async def test_consent_expiring_during_dialog_listing_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            current = [NOW]
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: current[0])
            await configure_unlocked(collector, paths, "authenticated")

            async def expiring_list_dialogs(_session):
                current[0] = NOW + timedelta(days=1)
                return gateway.dialogs

            gateway.list_dialogs = expiring_list_dialogs
            with self.assertRaisesRegex(RuntimeError, "consent is expired"):
                await collector.list_dialogs()
            self.assertFalse(paths.dialog_candidates.exists())
            self.assertEqual(load_settings(paths)["phase"], "authenticated")

    async def test_expired_consent_blocks_selection_before_external_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            current = [NOW]
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: current[0])
            await configure_unlocked(collector, paths, "dialogs_listed")
            current[0] = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
            keygen_calls = []

            async def keygen(*args):
                keygen_calls.append(args)
                return "ssh-ed25519 AAAAtest source", "SHA256:test"

            collector.keygen_function = keygen
            with self.assertRaisesRegex(RuntimeError, "consent is expired"):
                await collector.select_chat(CHAT_ID)
            self.assertEqual(gateway.bootstrap_calls, [])
            self.assertEqual(keygen_calls, [])
            self.assertFalse(paths.chat_locked.exists())
            self.assertEqual(load_settings(paths)["phase"], "dialogs_listed")

    async def test_consent_expiring_during_keygen_never_commits_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            current = [NOW]
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: current[0])
            await configure_unlocked(collector, paths, "dialogs_listed")

            async def keygen(key_paths, _source_id):
                atomic_write_bytes(key_paths.upload_key, b"private", 0o600)
                atomic_write_bytes(key_paths.upload_public_key, b"public", 0o600)
                current[0] = NOW + timedelta(days=1)
                return "ssh-ed25519 AAAAtest source", "SHA256:test"

            collector.keygen_function = keygen
            with self.assertRaisesRegex(RuntimeError, "consent is expired"):
                await collector.select_chat(CHAT_ID)
            self.assertFalse(paths.chat_locked.exists())
            self.assertFalse(paths.upload_key.exists())
            self.assertFalse(paths.upload_public_key.exists())
            self.assertEqual(load_settings(paths)["phase"], "dialogs_listed")
            self.assertTrue(paths.dialog_candidates.exists())

    async def test_monotonic_deadline_blocks_frozen_setup_clock(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            current = [NOW]
            monotonic = [100.0]
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                clock=lambda: current[0], monotonic=lambda: monotonic[0])
            known = "receiver.example ssh-ed25519 " + fake_known_host_key()
            await collector.configure({
                "telegram_api_id": "12345",
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "sk-or-test-secret",
                "openrouter_model": "anthropic/example",
                "upload_host": "receiver.example",
                "upload_port": "22",
                "upload_user": "root",
                "known_host": known,
                "consent_expires_at": "2026-08-05T00:00:00Z",
            })
            settings = read_json(paths.settings)
            settings["phase"] = "authenticated"
            atomic_write_json(paths.settings, settings)
            atomic_write_bytes(paths.telegram_session, b"string-session", 0o600)
            current[0] = NOW + timedelta(minutes=30)
            monotonic[0] += 3600
            with self.assertRaisesRegex(RuntimeError, "setup consent is expired"):
                await collector.list_dialogs()
            self.assertFalse(paths.dialog_candidates.exists())

    async def test_restart_before_chat_lock_expires_setup_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            known = "receiver.example ssh-ed25519 " + fake_known_host_key()
            await collector.configure({
                "telegram_api_id": "12345",
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "sk-or-test-secret",
                "openrouter_model": "anthropic/example",
                "upload_host": "receiver.example",
                "upload_port": "22",
                "upload_user": "root",
                "known_host": known,
                "consent_expires_at": "2026-08-05T00:00:00Z",
            })
            settings = read_json(paths.settings)
            settings["phase"] = "dialogs_listed"
            atomic_write_json(paths.settings, settings)
            atomic_write_bytes(paths.telegram_session, b"string-session", 0o600)
            atomic_write_json(paths.dialog_candidates, {
                "dialogs": [DialogCandidate(
                    CHAT_ID, "Pilot group", PEER).as_private_dict()],
            })
            restarted = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            status = await restarted.public_status()
            self.assertFalse(status["consent_active"])
            self.assertEqual(status["dialogs"], [])
            with self.assertRaisesRegex(RuntimeError, "setup consent is expired"):
                await restarted.select_chat(CHAT_ID)
            self.assertTrue(paths.dialog_candidates.exists())

    async def test_expired_code_result_keeps_session_available_for_logout(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            current = [NOW]
            gateway = FakeGateway()
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: current[0])
            await configure_unlocked(collector, paths, "code_sent")
            atomic_write_json(paths.setup_state, {
                "phone": "+15555550123",
                "phone_masked": "+***0123",
                "phone_code_hash": "phone-code-hash",
            })
            atomic_write_json(paths.telegram_session_outstanding, {
                "schema": "sunny.personal-digest-session-outstanding.v1",
                "outstanding": True,
                "created_at": "2026-08-04T00:00:00Z",
            })

            async def expiring_submit_code(*_args):
                current[0] = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
                return "authorized-session", False

            gateway.submit_code = expiring_submit_code
            with self.assertRaisesRegex(RuntimeError, "setup consent is expired"):
                await collector.submit_code("12345")
            self.assertEqual(
                paths.telegram_session.read_text(encoding="ascii"),
                "authorized-session",
            )
            self.assertEqual(load_settings(paths)["phase"], "code_sent")
            self.assertTrue(paths.telegram_session_outstanding.exists())


class TestBugFirstRunLookback20260810(unittest.IsolatedAsyncioTestCase):
    """The first due run is limited by trusted receiver time, not setup time."""

    async def test_first_fetch_clamps_setup_cursor_to_trusted_due_lookback(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, initial=10)
            gateway = FakeGateway()
            gateway.bootstrap_value = 100
            gateway.fetch_result = FetchResult(101, [
                SelectedMessage(101, 7, NOW, "Message text"),
            ])

            async def fetch(_session, peer, expected_chat_id, start, cutoff,
                            not_before_at=None):
                gateway.fetch_calls += 1
                gateway.fetch_starts.append(start)
                gateway.fetch_not_before.append(not_before_at)
                self.assertEqual(peer, PEER)
                self.assertEqual(expected_chat_id, CHAT_ID)
                self.assertEqual(start, 100)
                self.assertEqual(cutoff, NOW)
                self.assertEqual(not_before_at, NOW - timedelta(hours=72))
                return gateway.fetch_result

            gateway.fetch = fetch
            transport = FakeTransport(gate(cursor=10))

            async def digest(*_args):
                return "Digest"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport,
                clock=lambda: NOW + timedelta(hours=5),
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "uploaded")
            self.assertEqual(gateway.bootstrap_calls, [NOW])
            payload = json.loads(transport.uploads[0])
            self.assertEqual(payload["from_message_id_exclusive"], 10)
            self.assertEqual(payload["through_message_id"], 101)
            self.assertEqual(payload["message_count"], 1)

    async def test_empty_first_fetch_advances_to_trusted_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, initial=10)
            gateway = FakeGateway()
            gateway.bootstrap_value = 100
            gateway.fetch_result = FetchResult(100, [])
            digest_calls = []
            transport = FakeTransport(gate(cursor=10))

            async def digest(*args):
                digest_calls.append(args)
                return "must not happen"

            async def fetch(_session, _peer, _chat_id, start, _cutoff,
                            not_before_at=None):
                gateway.fetch_calls += 1
                self.assertEqual(start, 100)
                self.assertEqual(not_before_at, NOW - timedelta(hours=72))
                return gateway.fetch_result

            gateway.fetch = fetch
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "uploaded")
            self.assertEqual(digest_calls, [])
            payload = json.loads(transport.uploads[0])
            self.assertEqual(payload["from_message_id_exclusive"], 10)
            self.assertEqual(payload["through_message_id"], 100)
            self.assertTrue(payload["empty"])

    async def test_consent_expiring_during_trusted_bootstrap_blocks_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, initial=10)
            current = [NOW]
            gateway = FakeGateway()

            async def expiring_bootstrap(_session, peer, cutoff):
                gateway.bootstrap_calls.append(cutoff)
                self.assertEqual(peer, PEER)
                current[0] = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
                return 100

            gateway.bootstrap_cursor = expiring_bootstrap
            digest_calls = []
            transport = FakeTransport(gate(cursor=10))

            async def digest(*args):
                digest_calls.append(args)
                return "must not happen"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport, clock=lambda: current[0],
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "revoked")
            self.assertEqual(gateway.bootstrap_calls, [NOW])
            self.assertEqual(gateway.fetch_calls, 0)
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.uploads, [])

    async def test_later_sequence_does_not_reapply_first_fetch_lookback(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, initial=10)
            acknowledged = build_upload(
                source_id=SOURCE_ID, gate=gate(cursor=10), chat_id=CHAT_ID,
                through_message_id=110, message_count=1, digest="Earlier",
                model="anthropic/example", generated_at=NOW,
            )
            atomic_write_json(paths.acknowledged, {
                "schema": "sunny.personal-digest-acknowledged.v1",
                "source_id": SOURCE_ID,
                "chat_id": CHAT_ID,
                "sequence": 1,
                "content_sha256": acknowledged["content_sha256"],
                "through_message_id": 110,
                "digest_date": "2026-08-03",
            })
            gateway = FakeGateway()

            async def fetch(_session, _peer, _chat_id, start, _cutoff,
                            not_before_at=None):
                gateway.fetch_calls += 1
                gateway.fetch_starts.append(start)
                gateway.fetch_not_before.append(not_before_at)
                self.assertEqual(start, 110)
                self.assertIsNone(not_before_at)
                return FetchResult(111, [SelectedMessage(111, 7, NOW, "Message")])

            gateway.fetch = fetch
            next_gate = gate(
                day="2026-08-04", sequence=2,
                previous=acknowledged["content_sha256"], cursor=110,
            )
            transport = FakeTransport(next_gate)

            async def digest(*_args):
                return "Digest"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                digest_function=digest,
                transport_factory=lambda *_: transport,
                clock=lambda: NOW,
            )
            result = await collector.run_once()
            self.assertEqual(result["last_result"], "uploaded")
            self.assertEqual(gateway.bootstrap_calls, [])
            self.assertEqual(gateway.fetch_starts, [110])


if __name__ == "__main__":
    unittest.main()
