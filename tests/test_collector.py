from __future__ import annotations

import asyncio
import copy
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sunny_digest.collector import Collector, WATCH_STATE_SCHEMA
from sunny_digest.contracts import (
    canonical_digest_bytes,
    canonical_monitor_bytes,
    mention_event_id,
)
from sunny_digest.models import (
    DialogCandidate,
    FetchResult,
    MentionEvent,
    MentionScanResult,
    PeerSpec,
    SelectedMessage,
)
from sunny_digest.settings import CONSENT_SCOPE, CREDENTIALS_SCHEMA, SETTINGS_SCHEMA
from sunny_digest.storage import Paths, atomic_write_bytes, atomic_write_json, read_json


NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)
SOURCE_ID = "12345678-1234-4678-9234-567812345678"
PEERS = [PeerSpec("channel", 124, 91), PeerSpec("channel", 123, 92)]
CHAT_IDS = [peer.telegram_chat_id() for peer in PEERS]
TITLES = ["Первый чат", "Второй чат"]
BASELINE_TOPS = {CHAT_IDS[0]: 10, CHAT_IDS[1]: 20}
BASELINE_HASH = "b" * 64


def make_paths(root: Path) -> Paths:
    return Paths(root / "config", root / "private", root / "runtime",
                 root / "runtime" / "control.sock")


def locked_chats():
    return [
        {"chat_id": chat_id, "title": title, "peer": peer.as_dict(),
         "initial_message_id": 0}
        for chat_id, title, peer in zip(CHAT_IDS, TITLES, PEERS)
    ]


def initial_watch_state(phase="activation_requested"):
    if phase == "activation_requested":
        sequence, digest_hash = 0, None
        monitor = {chat_id: 0 for chat_id in CHAT_IDS}
        local = {chat_id: 0 for chat_id in CHAT_IDS}
    else:
        sequence, digest_hash = 1, BASELINE_HASH
        monitor = dict(BASELINE_TOPS)
        local = dict(BASELINE_TOPS)
    return {
        "schema": WATCH_STATE_SCHEMA,
        "source_id": SOURCE_ID,
        "phase": phase,
        "monitor_sequence": sequence,
        "monitor_content_sha256": digest_hash,
        "monitor_cursors": [
            {"chat_id": chat_id, "through_message_id": monitor[chat_id]}
            for chat_id in CHAT_IDS
        ],
        "chats": [
            {"chat_id": chat_id,
             "scan_through_message_id": local[chat_id],
             "read_pending_through_message_id": local[chat_id],
             "read_acked_through_message_id": local[chat_id]}
            for chat_id in CHAT_IDS
        ],
    }


def seed_locked(paths: Paths, *, watch_phase: str | None = None):
    paths.ensure()
    atomic_write_json(paths.settings, {
        "schema": SETTINGS_SCHEMA,
        "phase": "chat_locked",
        "chat_locked": True,
        "openrouter_model": "anthropic/example",
        "upload": {"host": "receiver.example", "port": 22, "user": "root"},
        "consent": {
            "scope": CONSENT_SCOPE,
            "granted_at": "2026-08-04T00:00:00Z",
            "expires_at": "2026-08-05T00:00:00Z",
        },
        "source_id": SOURCE_ID,
        "chats": locked_chats(),
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
        "schema": "sunny.personal-chats.session-outstanding.v2",
        "outstanding": True,
        "created_at": "2026-08-04T00:00:00Z",
    })
    atomic_write_bytes(paths.chat_locked, b"locked\n", 0o600)
    if watch_phase is not None:
        atomic_write_json(paths.watch_state, initial_watch_state(watch_phase))


def gate(*, baseline_required=False, monitor_sequence=2,
         monitor_previous=BASELINE_HASH, monitor_cursors=None,
         digest_due=False, digest_sequence=1, digest_previous=None,
         digest_cursors=None):
    monitor_cursors = monitor_cursors or (
        {chat_id: 0 for chat_id in CHAT_IDS}
        if baseline_required else dict(BASELINE_TOPS)
    )
    digest_cursors = digest_cursors or {chat_id: 0 for chat_id in CHAT_IDS}
    return {
        "schema": "sunny.personal-chats.status-gate.v2",
        "ok": True,
        "server_time": "2026-08-04T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "monitor": {
            "baseline_required": baseline_required,
            "next_sequence": 1 if baseline_required else monitor_sequence,
            "previous_sha256": None if baseline_required else monitor_previous,
            "cursors": [
                {"chat_id": chat_id,
                 "through_message_id": monitor_cursors[chat_id]}
                for chat_id in CHAT_IDS
            ],
            "max_upload_bytes": 32768,
        },
        "digest": {
            "due": digest_due,
            "reason": "due" if digest_due else "before_window",
            "digest_date": "2026-08-04",
            "prepare_not_before": "2026-08-04T03:00:00+03:00",
            "accept_until": "2026-08-04T04:45:00+03:00",
            "next_sequence": digest_sequence,
            "previous_sha256": digest_previous,
            "cursors": [
                {"chat_id": chat_id,
                 "through_message_id": digest_cursors[chat_id]}
                for chat_id in CHAT_IDS
            ],
            "max_upload_bytes": 32768,
        },
    }


class FakeTransport:
    def __init__(self, paths: Paths, gate_value, trace=None):
        self.paths = paths
        self.value = copy.deepcopy(gate_value)
        self.trace = trace if trace is not None else []
        self.gate_calls = 0
        self.monitor_uploads = []
        self.digest_uploads = []
        self.lose_monitor_ack = False
        self.lose_digest_ack = False

    async def gate(self, source_id, chat_ids, revoked):
        self.trace.append("status")
        self.gate_calls += 1
        if source_id != SOURCE_ID or chat_ids != CHAT_IDS or revoked.is_set():
            raise AssertionError("invalid status binding")
        return copy.deepcopy(self.value)

    async def upload_monitor(self, raw, revoked):
        self.trace.append("monitor_upload")
        self.assert_pending_monitor_before_upload()
        payload = json.loads(raw)
        self.monitor_uploads.append(payload)
        cursors = {row["chat_id"]: row["through_message_id"]
                   for row in self.value["monitor"]["cursors"]}
        for row in payload["ranges"]:
            cursors[row["chat_id"]] = row["through_message_id"]
        self.value["monitor"].update({
            "baseline_required": False,
            "next_sequence": payload["sequence"] + 1,
            "previous_sha256": payload["content_sha256"],
            "cursors": [
                {"chat_id": chat_id, "through_message_id": cursors[chat_id]}
                for chat_id in CHAT_IDS
            ],
        })
        if self.lose_monitor_ack:
            self.lose_monitor_ack = False
            raise RuntimeError("lost monitor ACK")
        return {"ok": True}

    def assert_pending_monitor_before_upload(self):
        if not self.paths.monitor_pending.exists():
            raise AssertionError("monitor bytes were not fsynced before upload")

    async def upload_digest(self, raw, revoked):
        self.trace.append("digest_upload")
        if not self.paths.pending.exists():
            raise AssertionError("digest bytes were not fsynced before upload")
        payload = json.loads(raw)
        self.digest_uploads.append(payload)
        self.value["digest"].update({
            "due": False,
            "next_sequence": payload["sequence"] + 1,
            "previous_sha256": payload["content_sha256"],
            "cursors": [
                {"chat_id": row["chat_id"],
                 "through_message_id": row["through_message_id"]}
                for row in payload["chat_ranges"]
            ],
        })
        if self.lose_digest_ack:
            self.lose_digest_ack = False
            raise RuntimeError("lost digest ACK")
        return {"ok": True}


class FakeGateway:
    def __init__(self, paths: Paths, trace=None):
        self.paths = paths
        self.trace = trace if trace is not None else []
        self.tops = dict(BASELINE_TOPS)
        self.scans = {
            chat_id: MentionScanResult(self.tops[chat_id], [])
            for chat_id in CHAT_IDS
        }
        self.scan_failures = []
        self.read_failures = []
        self.snapshot_calls = 0
        self.aggregate_scan_calls = 0
        self.read_batches = []
        self.bootstrap_calls = []
        self.bootstrap = {chat_id: 0 for chat_id in CHAT_IDS}
        self.fetch_calls = []
        self.fetches = {
            chat_id: FetchResult(1, [SelectedMessage(1, 7, NOW, f"text-{chat_id}")])
            for chat_id in CHAT_IDS
        }
        self.dialogs = [
            DialogCandidate(chat_id, title, peer)
            for chat_id, title, peer in zip(CHAT_IDS, TITLES, PEERS)
        ]
        self.logout_calls = 0

    async def list_dialogs(self, _session):
        return self.dialogs

    async def snapshot_tops(self, _session, selected):
        self.trace.append("snapshot")
        self.snapshot_calls += 1
        self.assert_exact_selected(selected)
        return dict(self.tops)

    def assert_exact_selected(self, selected):
        if [row[0] for row in selected] != CHAT_IDS:
            raise AssertionError("collector escaped locked chat set")

    async def snapshot_and_scan_mentions(self, _session, source_id, selected):
        self.trace.append("scan_batch")
        self.aggregate_scan_calls += 1
        if source_id != SOURCE_ID or [row[0] for row in selected] != CHAT_IDS:
            raise AssertionError("invalid aggregate scan binding")
        available = {}
        starts = {row[0]: row[3] for row in selected}
        for chat_id in CHAT_IDS:
            if chat_id in self.scan_failures:
                continue
            configured = self.scans[chat_id]
            start = starts[chat_id]
            available[chat_id] = MentionScanResult(
                max(start, configured.through_message_id),
                [event for event in configured.events if event.message_id > start],
            )
        return dict(self.tops), available, list(self.scan_failures)

    async def acknowledge_reads(self, _session, targets):
        self.trace.append("read_batch")
        self.read_batches.append(targets)
        succeeded = [row[0] for row in targets if row[0] not in self.read_failures]
        return succeeded, list(self.read_failures)

    async def bootstrap_cursor(self, _session, peer, cutoff):
        chat_id = peer.telegram_chat_id()
        self.bootstrap_calls.append((chat_id, cutoff))
        return self.bootstrap[chat_id]

    async def fetch(self, _session, peer, chat_id, start, cutoff,
                    not_before_at=None, max_prompt_bytes=None, chat_title=None):
        if peer.telegram_chat_id() != chat_id:
            raise AssertionError("wrong daily peer")
        self.fetch_calls.append({
            "chat_id": chat_id, "start": start, "cutoff": cutoff,
            "not_before": not_before_at, "budget": max_prompt_bytes,
            "title": chat_title,
        })
        result = self.fetches[chat_id]
        if isinstance(result, BaseException):
            raise result
        return result

    async def logout(self, _session):
        self.logout_calls += 1
        return True


def mention(chat_index: int, message_id: int) -> MentionEvent:
    chat_id = CHAT_IDS[chat_index]
    return MentionEvent(
        event_id=mention_event_id(SOURCE_ID, chat_id, message_id),
        chat_id=chat_id,
        message_id=message_id,
        sent_at=NOW,
        chat_title=TITLES[chat_index],
        sender="Иван",
        snippet="@ivan проверь",
        link=f"https://t.me/c/{PEERS[chat_index].peer_id}/{message_id}",
    )


def collector_for(paths, gateway, transport, digest_calls=None):
    digest_calls = digest_calls if digest_calls is not None else []

    async def digest(chats, model, key, revoked):
        digest_calls.append((chats, model, key, revoked.is_set()))
        return "Общий дайджест"

    return Collector(
        paths,
        gateway_factory=lambda *_: gateway,
        digest_function=digest,
        transport_factory=lambda *_: transport,
        clock=lambda: NOW,
    )


class CollectorV2Tests(unittest.IsolatedAsyncioTestCase):
    async def test_run_before_explicit_activation_never_contacts_receiver_or_telegram(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths)
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate())
            result = await collector_for(paths, gateway, transport).run_once()
            self.assertEqual(result["last_result"], "activation_required")
            self.assertEqual(transport.gate_calls, 0)
            self.assertEqual(gateway.snapshot_calls, 0)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            self.assertEqual(gateway.read_batches, [])

    async def test_select_chats_is_sorted_immutable_and_reads_no_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA, "phase": "dialogs_listed",
                "chat_locked": False, "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {"scope": CONSENT_SCOPE,
                            "granted_at": "2026-08-04T00:00:00Z",
                            "expires_at": "2026-08-05T00:00:00Z"},
            })
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA, "telegram_api_id": 1,
                "telegram_api_hash": "a" * 32, "openrouter_api_key": "secret-key-123456",
            })
            atomic_write_bytes(paths.telegram_session, b"session")
            gateway = FakeGateway(paths)
            atomic_write_json(paths.dialog_candidates, {
                "dialogs": [row.as_private_dict() for row in reversed(gateway.dialogs)],
            })

            async def keygen(_paths, source_id):
                uuid.UUID(source_id)
                return "ssh-ed25519 AAAAtest source", "SHA256:test"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                keygen_function=keygen, clock=lambda: NOW)
            collector._setup_deadline_mono = collector.monotonic() + 3600
            status = await collector.select_chats(list(reversed(CHAT_IDS)))
            self.assertEqual([row["chat_id"] for row in status["chats"]], CHAT_IDS)
            settings = read_json(paths.settings)
            self.assertEqual([row["initial_message_id"] for row in settings["chats"]], [0, 0])
            self.assertFalse(paths.watch_state.exists())
            self.assertEqual(gateway.snapshot_calls, 0)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            with self.assertRaises(RuntimeError):
                await collector.select_chats(CHAT_IDS)

            collector.trigger_run = lambda: True
            activated = await collector.activate_monitoring()
            self.assertEqual(activated["monitoring_phase"], "activation_requested")
            self.assertEqual(read_json(paths.watch_state)["phase"], "activation_requested")

    async def test_baseline_upload_is_durable_before_receiver_ack_and_read_batch(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="activation_requested")
            trace = []
            gateway = FakeGateway(paths, trace)
            transport = FakeTransport(paths, gate(baseline_required=True), trace)

            original_assert = transport.assert_pending_monitor_before_upload
            def assert_baseline_order():
                original_assert()
                self.assertEqual(read_json(paths.watch_state)["phase"],
                                 "activation_requested")
            transport.assert_pending_monitor_before_upload = assert_baseline_order

            result = await collector_for(paths, gateway, transport).run_once()
            self.assertEqual(result["last_result"], "watched_not_due")
            self.assertEqual(transport.monitor_uploads[0]["kind"], "baseline")
            self.assertEqual(trace[:4], ["status", "snapshot", "monitor_upload", "read_batch"])
            self.assertFalse(paths.monitor_pending.exists())
            state = read_json(paths.watch_state)
            self.assertEqual(state["phase"], "active")
            self.assertTrue(all(row["read_acked_through_message_id"]
                                == row["scan_through_message_id"]
                                for row in state["chats"]))

    async def test_activation_completes_baseline_reads_then_digest_in_same_tick(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="activation_requested")
            trace = []
            gateway = FakeGateway(paths, trace)
            transport = FakeTransport(
                paths, gate(baseline_required=True, digest_due=True), trace)
            digest_calls = []

            result = await collector_for(
                paths, gateway, transport, digest_calls).run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(read_json(paths.watch_state)["phase"], "active")
            self.assertEqual(len(gateway.read_batches), 1)
            self.assertEqual(len(digest_calls), 1)
            self.assertEqual(len(transport.digest_uploads), 1)
            self.assertEqual(
                trace,
                ["status", "snapshot", "monitor_upload", "read_batch",
                 "status", "digest_upload"],
            )

    async def test_partial_baseline_read_retries_only_failed_peer_then_allows_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="activation_requested")
            gateway = FakeGateway(paths)
            gateway.read_failures = [CHAT_IDS[0]]
            transport = FakeTransport(
                paths, gate(baseline_required=True, digest_due=True))
            digest_calls = []
            collector = collector_for(paths, gateway, transport, digest_calls)

            first = await collector.run_once()

            self.assertEqual(first["last_result"], "baseline_read_pending")
            self.assertEqual(read_json(paths.watch_state)["phase"],
                             "baseline_read_pending")
            self.assertEqual(gateway.snapshot_calls, 1)
            self.assertEqual(len(transport.monitor_uploads), 1)
            self.assertEqual(transport.digest_uploads, [])
            self.assertEqual(digest_calls, [])

            gateway.read_failures = []
            second = await collector.run_once()

            self.assertEqual(second["last_result"], "uploaded_digest")
            self.assertEqual(read_json(paths.watch_state)["phase"], "active")
            self.assertEqual(gateway.snapshot_calls, 1)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            self.assertEqual(len(transport.monitor_uploads), 1)
            self.assertEqual(
                [row[0] for row in gateway.read_batches[1]], [CHAT_IDS[0]])
            self.assertEqual(len(digest_calls), 1)
            self.assertEqual(len(transport.digest_uploads), 1)

    async def test_lost_baseline_ack_reconciles_before_first_read_without_reupload(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="activation_requested")
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate(baseline_required=True))
            transport.lose_monitor_ack = True
            collector = collector_for(paths, gateway, transport)
            first = await collector.run_once()
            self.assertEqual(first["last_result"], "error")
            self.assertTrue(paths.monitor_pending.exists())
            self.assertEqual(gateway.read_batches, [])
            self.assertEqual(read_json(paths.watch_state)["phase"], "activation_requested")

            second = await collector.run_once()
            self.assertEqual(second["last_result"], "watched_not_due")
            self.assertEqual(len(transport.monitor_uploads), 1)
            self.assertFalse(paths.monitor_pending.exists())
            self.assertEqual(read_json(paths.watch_state)["phase"], "active")
            self.assertEqual(len(gateway.read_batches), 1)

    async def test_fsynced_watch_state_with_stale_monitor_pending_reconciles(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="activation_requested")
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate(baseline_required=True))
            collector = collector_for(paths, gateway, transport)
            self.assertEqual((await collector.run_once())["last_result"],
                             "watched_not_due")
            payload = transport.monitor_uploads[0]
            checkpoint = read_json(paths.watch_state)
            atomic_write_bytes(
                paths.monitor_pending, canonical_monitor_bytes(payload), 0o600)

            recovered = await collector.run_once()

            self.assertEqual(recovered["last_result"], "watched_not_due")
            self.assertFalse(paths.monitor_pending.exists())
            self.assertEqual(read_json(paths.watch_state), checkpoint)
            self.assertEqual(gateway.snapshot_calls, 1)
            self.assertEqual(len(transport.monitor_uploads), 1)

    async def test_no_mentions_advance_only_local_cursor_before_read_ack(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.tops = {CHAT_IDS[0]: 12, CHAT_IDS[1]: 23}
            gateway.scans = {
                CHAT_IDS[0]: MentionScanResult(12, []),
                CHAT_IDS[1]: MentionScanResult(23, []),
            }
            transport = FakeTransport(paths, gate())
            result = await collector_for(paths, gateway, transport).run_once()
            self.assertEqual(result["last_result"], "watched_not_due")
            self.assertEqual(transport.monitor_uploads, [])
            state = read_json(paths.watch_state)
            self.assertEqual([row["scan_through_message_id"] for row in state["chats"]],
                             [12, 23])
            self.assertEqual([row["read_acked_through_message_id"] for row in state["chats"]],
                             [12, 23])
            self.assertEqual(
                [row["through_message_id"] for row in state["monitor_cursors"]],
                [10, 20],
            )
            self.assertEqual(len(gateway.read_batches), 1)

    async def test_mention_ack_precedes_read_and_remote_range_includes_local_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            state = read_json(paths.watch_state)
            state["chats"][0].update({
                "scan_through_message_id": 15,
                "read_pending_through_message_id": 15,
                "read_acked_through_message_id": 15,
            })
            atomic_write_json(paths.watch_state, state)
            trace = []
            gateway = FakeGateway(paths, trace)
            gateway.tops[CHAT_IDS[0]] = 16
            gateway.scans[CHAT_IDS[0]] = MentionScanResult(16, [mention(0, 16)])
            transport = FakeTransport(paths, gate(), trace)
            result = await collector_for(paths, gateway, transport).run_once()
            self.assertEqual(result["last_result"], "watched_not_due")
            payload = transport.monitor_uploads[0]
            self.assertEqual(payload["kind"], "mentions")
            self.assertEqual(payload["ranges"][0]["from_message_id_exclusive"], 10)
            self.assertEqual(payload["ranges"][0]["through_message_id"], 16)
            self.assertEqual(payload["events"][0]["event_id"],
                             mention_event_id(SOURCE_ID, CHAT_IDS[0], 16))
            self.assertLess(trace.index("monitor_upload"), trace.index("read_batch"))

    async def test_lost_mention_ack_never_reads_until_next_status_reconciles(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.tops[CHAT_IDS[0]] = 11
            gateway.scans[CHAT_IDS[0]] = MentionScanResult(11, [mention(0, 11)])
            transport = FakeTransport(paths, gate())
            transport.lose_monitor_ack = True
            collector = collector_for(paths, gateway, transport)
            self.assertEqual((await collector.run_once())["last_result"], "error")
            self.assertTrue(paths.monitor_pending.exists())
            self.assertEqual(gateway.read_batches, [])
            self.assertEqual(read_json(paths.watch_state)["chats"][0][
                "scan_through_message_id"], 10)
            self.assertEqual((await collector.run_once())["last_result"], "watched_not_due")
            self.assertEqual(len(transport.monitor_uploads), 1)
            self.assertFalse(paths.monitor_pending.exists())
            self.assertGreaterEqual(len(gateway.read_batches), 1)

    async def test_receiver_monitor_rollback_blocks_all_telegram_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            rollback = gate(monitor_sequence=1, monitor_previous=None)
            rollback["monitor"]["baseline_required"] = True
            rollback["monitor"]["cursors"] = [
                {"chat_id": chat_id, "through_message_id": 0} for chat_id in CHAT_IDS]
            transport = FakeTransport(paths, rollback)
            result = await collector_for(paths, gateway, transport).run_once()
            self.assertEqual(result["last_result"], "error")
            self.assertEqual(gateway.snapshot_calls, 0)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            self.assertEqual(gateway.read_batches, [])

    async def test_broken_first_peer_does_not_advance_it_or_block_good_second(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.scan_failures = [CHAT_IDS[0]]
            gateway.tops[CHAT_IDS[1]] = 25
            gateway.scans[CHAT_IDS[1]] = MentionScanResult(25, [])
            result = await collector_for(
                paths, gateway, FakeTransport(paths, gate())).run_once()
            self.assertEqual(result["last_result"], "watched_not_due")
            self.assertEqual(result["failed_chat_count"], 1)
            state = read_json(paths.watch_state)
            self.assertEqual(state["chats"][0]["scan_through_message_id"], 10)
            self.assertEqual(state["chats"][1]["scan_through_message_id"], 25)
            self.assertEqual([row[0] for row in gateway.read_batches[0]], [CHAT_IDS[1]])

    async def test_read_failure_is_redacted_and_other_chat_checkpoint_commits(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.tops = {CHAT_IDS[0]: 11, CHAT_IDS[1]: 21}
            gateway.scans = {
                CHAT_IDS[0]: MentionScanResult(11, []),
                CHAT_IDS[1]: MentionScanResult(21, []),
            }
            gateway.read_failures = [CHAT_IDS[0]]
            result = await collector_for(
                paths, gateway, FakeTransport(paths, gate())).run_once()
            self.assertEqual(result["failed_chat_count"], 1)
            state = read_json(paths.watch_state)
            self.assertEqual(state["chats"][0]["read_acked_through_message_id"], 10)
            self.assertEqual(state["chats"][0]["read_pending_through_message_id"], 11)
            self.assertEqual(state["chats"][1]["read_acked_through_message_id"], 21)

    async def test_active_retry_batches_old_and_new_read_acks_after_one_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            state = read_json(paths.watch_state)
            state["chats"][0].update({
                "scan_through_message_id": 11,
                "read_pending_through_message_id": 11,
                "read_acked_through_message_id": 10,
            })
            atomic_write_json(paths.watch_state, state)
            gateway = FakeGateway(paths)
            gateway.scans = {
                CHAT_IDS[0]: MentionScanResult(12, []),
                CHAT_IDS[1]: MentionScanResult(21, []),
            }

            result = await collector_for(
                paths, gateway, FakeTransport(paths, gate())).run_once()

            self.assertEqual(result["last_result"], "watched_not_due")
            self.assertEqual(gateway.aggregate_scan_calls, 1)
            self.assertEqual(len(gateway.read_batches), 1)
            self.assertEqual(
                [(row[0], row[2]) for row in gateway.read_batches[0]],
                [(CHAT_IDS[0], 12), (CHAT_IDS[1], 21)],
            )

    async def test_first_daily_digest_uses_independent_zero_cursors_and_one_llm_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.bootstrap = {CHAT_IDS[0]: 100, CHAT_IDS[1]: 200}
            gateway.fetches = {
                CHAT_IDS[0]: FetchResult(101, [SelectedMessage(101, 7, NOW, "A")]),
                CHAT_IDS[1]: FetchResult(202, [SelectedMessage(201, 8, NOW, "B")]),
            }
            transport = FakeTransport(paths, gate(digest_due=True))
            digest_calls = []
            result = await collector_for(
                paths, gateway, transport, digest_calls).run_once()
            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(len(digest_calls), 1)
            self.assertEqual([chat.title for chat in digest_calls[0][0]], TITLES)
            self.assertEqual(len(transport.digest_uploads), 1)
            payload = transport.digest_uploads[0]
            self.assertEqual(
                [row["from_message_id_exclusive"] for row in payload["chat_ranges"]],
                [0, 0],
            )
            self.assertEqual(
                [call["start"] for call in gateway.fetch_calls], [100, 200])
            self.assertTrue(all(call["not_before"] == NOW - timedelta(hours=72)
                                for call in gateway.fetch_calls))
            watch = read_json(paths.watch_state)
            self.assertEqual(
                [row["through_message_id"] for row in watch["monitor_cursors"]],
                [10, 20],
            )

    async def test_any_daily_peer_error_aborts_whole_daily_upload(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.fetches[CHAT_IDS[1]] = RuntimeError("peer unavailable")
            transport = FakeTransport(paths, gate(digest_due=True))
            digest_calls = []
            result = await collector_for(
                paths, gateway, transport, digest_calls).run_once()
            self.assertEqual(result["last_result"], "error")
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.digest_uploads, [])
            self.assertFalse(paths.acknowledged.exists())

    async def test_crash_after_digest_checkpoint_before_pending_unlink_recovers(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate(digest_due=True))
            collector = collector_for(paths, gateway, transport)
            self.assertEqual((await collector.run_once())["last_result"],
                             "uploaded_digest")
            payload = transport.digest_uploads[0]
            atomic_write_bytes(paths.pending, canonical_digest_bytes(payload), 0o600)

            recovered = await collector.run_once()

            self.assertEqual(recovered["last_result"], "watched_not_due")
            self.assertFalse(paths.pending.exists())
            self.assertEqual(read_json(paths.acknowledged)["content_sha256"],
                             payload["content_sha256"])

    async def test_lost_digest_receipt_reconciles_without_reupload_or_refetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate(digest_due=True))
            transport.lose_digest_ack = True
            digest_calls = []
            collector = collector_for(paths, gateway, transport, digest_calls)

            first = await collector.run_once()

            self.assertEqual(first["last_result"], "error")
            self.assertTrue(paths.pending.exists())
            self.assertEqual(len(transport.digest_uploads), 1)
            self.assertEqual(len(gateway.fetch_calls), len(CHAT_IDS))
            self.assertEqual(len(digest_calls), 1)
            payload = transport.digest_uploads[0]

            recovered = await collector.run_once()

            self.assertEqual(recovered["last_result"], "watched_not_due")
            self.assertFalse(paths.pending.exists())
            self.assertEqual(len(transport.digest_uploads), 1)
            self.assertEqual(len(gateway.fetch_calls), len(CHAT_IDS))
            self.assertEqual(len(digest_calls), 1)
            self.assertEqual(read_json(paths.acknowledged)["content_sha256"],
                             payload["content_sha256"])

    async def test_public_status_hides_peer_hashes_snippets_and_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            public = await Collector(paths, clock=lambda: NOW).public_status()
            serialized = json.dumps(public, ensure_ascii=False, sort_keys=True)
            for forbidden in (
                    "access_hash", "openrouter_api_key", "telegram_api_hash",
                    "string-session", "snippet", "sk-or-test-secret"):
                self.assertNotIn(forbidden, serialized)
            self.assertEqual([row["chat_id"] for row in public["chats"]], CHAT_IDS)

    async def test_factory_reset_removes_both_pending_domains_and_watch_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            atomic_write_bytes(paths.pending, b"digest")
            atomic_write_bytes(paths.monitor_pending, b"monitor")
            gateway = FakeGateway(paths)
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway, clock=lambda: NOW)
            result = await collector.revoke_and_reset()
            self.assertEqual(result["last_result"], "reset")
            self.assertEqual(gateway.logout_calls, 1)
            for path in paths.reset_files():
                self.assertFalse(path.exists(), str(path))


if __name__ == "__main__":
    unittest.main()
