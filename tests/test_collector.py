from __future__ import annotations

import asyncio
import copy
import json
import tempfile
import unittest
import uuid
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import sunny_digest.collector as collector_module
from sunny_digest.collector import (
    Collector,
    DIALOG_CANDIDATES_SCHEMA,
    RECENT_RUNS_LIMIT,
    VPNMigrationRequiredError,
    WATCH_STATE_SCHEMA,
)
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
from sunny_digest.settings import (
    CONSENT_SCOPE,
    CREDENTIALS_SCHEMA,
    SETTINGS_SCHEMA,
    load_credentials,
)
from sunny_digest.contracts import supergroup_link_prefix
from sunny_digest.prompting import DIGEST_SKIP_NOTE_HEAD, DIGEST_TRUNCATION_NOTE
from sunny_digest.storage import (
    Paths,
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    read_json,
)


NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)
SOURCE_ID = "12345678-1234-4678-9234-567812345678"
SELECTION_ID = "22345678-1234-4678-9234-567812345678"
PEERS = [PeerSpec("channel", 124, 91), PeerSpec("channel", 123, 92)]
CHAT_IDS = [peer.telegram_chat_id() for peer in PEERS]
TITLES = ["Первый чат", "Второй чат"]
BASELINE_TOPS = {CHAT_IDS[0]: 10, CHAT_IDS[1]: 20}
BASELINE_HASH = "b" * 64
VPN_NODE = {
    "type": "vless",
    "server": "1.1.1.1",
    "port": 443,
    "uuid": "11111111-2222-4333-8444-555555555555",
    "network": "tcp",
    "tls": True,
    "servername": "cdn.example",
    "client-fingerprint": "chrome",
    "reality-opts": {"public-key": "E" * 43, "short-id": "1a2b3c4d"},
    "flow": "xtls-rprx-vision",
    "udp": False,
}


def known_host_blob():
    key_type = b"ssh-ed25519"
    blob = len(key_type).to_bytes(4, "big") + key_type + (32).to_bytes(
        4, "big") + b"x" * 32
    return base64.b64encode(blob).decode("ascii")


def configure_payload(subscription_url):
    return {
        "telegram_api_id": "12345",
        "telegram_api_hash": "a" * 32,
        "vpn_subscription_url": subscription_url,
        "openrouter_api_key": "sk-or-test-secret",
        "openrouter_model": "anthropic/example",
        "upload_host": "receiver.example",
        "upload_port": "22",
        "upload_user": "root",
        "known_host": f"receiver.example ssh-ed25519 {known_host_blob()}",
        "consent_expires_at": "2026-08-05T00:00:00Z",
    }


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
    atomic_write_json(paths.vpn_active_node, VPN_NODE)
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
                for chat_id in monitor_cursors
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
                for chat_id in digest_cursors
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
        # Набор чатов расширяем: после расширения приложение законно шлёт
        # больше идентификаторов, чем было при установке.
        self.expected_chat_ids = list(CHAT_IDS)

    async def gate(self, source_id, chat_ids, revoked):
        self.trace.append("status")
        self.gate_calls += 1
        if (source_id != SOURCE_ID or chat_ids != self.expected_chat_ids
                or revoked.is_set()):
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
        self.boundary_calls = []
        self.boundary = {chat_id: 0 for chat_id in CHAT_IDS}
        self.fetch_calls = []
        self.fetches = {
            chat_id: FetchResult(1, [SelectedMessage(1, 7, NOW, f"text-{chat_id}")])
            for chat_id in CHAT_IDS
        }
        self.dialogs = [
            DialogCandidate(chat_id, title, peer)
            for chat_id, title, peer in zip(CHAT_IDS, TITLES, PEERS)
        ]
        self.resolve_calls = []
        self.expected_chat_ids = list(CHAT_IDS)
        self.send_code_calls = 0
        self.logout_calls = 0

    async def send_code(self, _session, _phone):
        self.send_code_calls += 1
        return "new-session", "phone-code-hash"

    async def resolve_message_links(self, _session, links):
        self.resolve_calls.append(list(links))
        return self.dialogs

    async def snapshot_tops(self, _session, selected):
        self.trace.append("snapshot")
        self.snapshot_calls += 1
        self.assert_exact_selected(selected)
        return dict(self.tops)

    def assert_exact_selected(self, selected):
        # Сторож ловит выход ЗА набор. Подмножество законно: extension
        # baseline снимает срез только по добавленным чатам, а не по всем.
        chosen = [row[0] for row in selected]
        if (not set(chosen) <= set(self.expected_chat_ids)
                or chosen != sorted(chosen, key=self.expected_chat_ids.index)
                or len(set(chosen)) != len(chosen)):
            raise AssertionError("collector escaped locked chat set")

    async def snapshot_and_scan_mentions(self, _session, source_id, selected):
        self.trace.append("scan_batch")
        self.aggregate_scan_calls += 1
        if (source_id != SOURCE_ID
                or [row[0] for row in selected] != self.expected_chat_ids):
            raise AssertionError("invalid aggregate scan binding")
        available = {}
        starts = {row[0]: row[3] for row in selected}
        for chat_id in self.expected_chat_ids:
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

    async def boundary_cursor(self, _session, peer, not_before):
        chat_id = peer.telegram_chat_id()
        self.boundary_calls.append((chat_id, not_before))
        return self.boundary[chat_id]

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


class FakeVPNRuntime:
    def __init__(self, _private_dir, trace=None):
        self.ready = False
        self.trace = trace if trace is not None else []
        self.starts = []
        self.stop_calls = 0
        self.start_error = None
        self.stop_error = None

    async def start(self, node):
        self.trace.append("vpn_start")
        self.starts.append(copy.deepcopy(node))
        if self.start_error is not None:
            raise self.start_error
        self.ready = True

    def ensure_alive(self):
        if not self.ready:
            raise RuntimeError("VPN is not ready")

    async def stop(self):
        self.trace.append("vpn_stop")
        self.stop_calls += 1
        self.ready = False
        if self.stop_error is not None:
            raise self.stop_error


class BlockingVPNRuntime(FakeVPNRuntime):
    def __init__(self, private_dir):
        super().__init__(private_dir)
        self.start_entered = asyncio.Event()
        self.allow_start = asyncio.Event()

    async def start(self, node):
        self.trace.append("vpn_start")
        self.starts.append(copy.deepcopy(node))
        self.start_entered.set()
        await self.allow_start.wait()
        self.ready = True


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


class FakeTunnel:
    """Фейк ssh-туннеля: тесты не поднимают настоящий ssh.

    Считает start/stop, чтобы регресс мог проверить, что канал закрывается
    даже при провале запроса."""

    instances = []

    def __init__(self, paths, upload):
        self.paths = paths
        self.upload = upload
        self.started = 0
        self.stopped = 0
        self.alive = True
        FakeTunnel.instances.append(self)

    async def start(self):
        self.started += 1

    def ensure_alive(self):
        if not self.alive:
            from sunny_digest.openrouter_tunnel import TunnelUnavailableError
            raise TunnelUnavailableError("tunnel died")

    async def stop(self):
        self.stopped += 1


def collector_for(paths, gateway, transport, digest_calls=None, runtime=None):
    digest_calls = digest_calls if digest_calls is not None else []

    async def digest(chats, model, key, revoked):
        digest_calls.append((chats, model, key, revoked.is_set()))
        return "Общий дайджест"

    async def fake_openrouter_keygen(paths_, source_id):
        # реальный ssh-keygen в 27 прогонах не нужен и делает тесты медленными
        paths_.openrouter_key.write_text("private", encoding="ascii")
        paths_.openrouter_public_key.write_text(
            f"ssh-ed25519 AAAAtest {source_id}@sunny-openrouter", encoding="ascii")
        return "ssh-ed25519 AAAAtest", "SHA256:test"

    runtime = runtime or FakeVPNRuntime(paths.private_dir)
    return Collector(
        paths,
        gateway_factory=lambda *_: gateway,
        digest_function=digest,
        transport_factory=lambda *_: transport,
        tunnel_factory=FakeTunnel,
        openrouter_keygen_function=fake_openrouter_keygen,
        vpn_runtime_factory=lambda _private: runtime,
        clock=lambda: NOW,
    )


def seed_vpn_repair_protected_files(paths: Paths):
    atomic_write_bytes(paths.known_hosts, b"receiver.example ssh-ed25519 test\n")
    atomic_write_bytes(paths.upload_key, b"private-upload-key")
    atomic_write_bytes(paths.upload_public_key, b"public-upload-key\n")
    atomic_write_bytes(paths.pending, b'{"pending":"digest"}\n')
    atomic_write_bytes(paths.monitor_pending, b'{"pending":"monitor"}\n')
    atomic_write_bytes(paths.acknowledged, b'{"acknowledged":true}\n')


def vpn_repair_protected_snapshot(paths: Paths):
    return {
        path: path.read_bytes()
        for path in (
            paths.settings,
            paths.credentials,
            paths.telegram_session,
            paths.telegram_session_outstanding,
            paths.chat_locked,
            paths.watch_state,
            paths.known_hosts,
            paths.upload_key,
            paths.upload_public_key,
            paths.pending,
            paths.monitor_pending,
            paths.acknowledged,
        )
    }


class TestBugLiveVPNRepair20260814(unittest.IsolatedAsyncioTestCase):
    """A locally-ready VLESS node reset Telegram before any locked peer access."""

    async def test_live_vpn_repair_commits_only_authorized_candidate_without_state_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = make_paths(root)
            seed_locked(paths, watch_phase="active")
            seed_vpn_repair_protected_files(paths)
            before = vpn_repair_protected_snapshot(paths)
            bad = copy.deepcopy(VPN_NODE)
            bad["server"] = "2.2.2.2"
            good = copy.deepcopy(VPN_NODE)
            good["server"] = "3.3.3.3"
            secret_url = "https://subscription.example/client?token=repair-secret"
            fetched = []

            async def fetch(source):
                fetched.append(source)
                return [copy.deepcopy(VPN_NODE), bad, good]

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            probe_calls = []
            probe_results = [TimeoutError(), True]

            async def probe(api_id, api_hash, session, revoked):
                probe_calls.append((api_id, api_hash, session, revoked.is_set()))
                result = probe_results.pop(0)
                if isinstance(result, BaseException):
                    raise result
                return result

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )

            queued = await collector.replace_vpn(secret_url)
            self.assertEqual(queued["last_result"], "vpn_repairing")
            task = collector._vpn_repair_task
            self.assertIsNotNone(task)
            await task

            self.assertEqual(fetched, [secret_url])
            self.assertEqual(runtime.starts, [bad, good])
            self.assertEqual(probe_calls, [
                (12345, "a" * 32, "string-session", False),
                (12345, "a" * 32, "string-session", False),
            ])
            self.assertEqual(read_json(paths.vpn_active_node), good)
            for path, raw in before.items():
                self.assertEqual(path.read_bytes(), raw, path)
            persisted = b"".join(
                path.read_bytes() for path in root.rglob("*") if path.is_file()
            )
            self.assertNotIn(secret_url.encode(), persisted)
            status = await collector.public_status()
            self.assertEqual(status["last_result"], "vpn_repaired")
            self.assertIsNone(status["last_error_type"])
            self.assertFalse(status["vpn_repairing"])

    async def test_failed_live_vpn_repair_restores_old_runtime_and_exact_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            seed_vpn_repair_protected_files(paths)
            old_node_bytes = paths.vpn_active_node.read_bytes()
            protected = vpn_repair_protected_snapshot(paths)
            secret_url = (
                "https://subscription.example/client?token=failed-repair-secret")
            first = copy.deepcopy(VPN_NODE)
            first["server"] = "2.2.2.2"
            second = copy.deepcopy(VPN_NODE)
            second["server"] = "3.3.3.3"

            async def fetch(_source):
                return [first, second]

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            probe_results = [TimeoutError(), ConnectionError()]

            async def probe(_api_id, _api_hash, _session, _revoked):
                result = probe_results.pop(0)
                if isinstance(result, BaseException):
                    raise result
                return result

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )

            await collector.replace_vpn(secret_url)
            task = collector._vpn_repair_task
            self.assertIsNotNone(task)
            await task

            self.assertEqual(runtime.starts, [first, second, VPN_NODE])
            self.assertEqual(paths.vpn_active_node.read_bytes(), old_node_bytes)
            for path, raw in protected.items():
                self.assertEqual(path.read_bytes(), raw, path)
            status = await collector.public_status()
            self.assertEqual(status["last_result"], "vpn_repair_failed")
            self.assertEqual(status["last_error_type"], "VPNRepairFailed")
            self.assertFalse(status["vpn_repairing"])
            persisted = b"".join(
                path.read_bytes()
                for path in Path(temporary).rglob("*") if path.is_file()
            )
            self.assertNotIn(secret_url.encode(), persisted)

    async def test_repair_waits_for_active_run_before_stopping_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                return True

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.run_lock.acquire()
            try:
                await collector.replace_vpn(
                    "https://subscription.example/locked-run")
                task = collector._vpn_repair_task
                self.assertIsNotNone(task)
                for _ in range(10):
                    await asyncio.sleep(0)
                    if collector._vpn_repair_state == "waiting_for_run":
                        break
                self.assertEqual(collector._vpn_repair_state, "waiting_for_run")
                self.assertEqual(runtime.stop_calls, 0)
                self.assertEqual(runtime.starts, [])
            finally:
                collector.run_lock.release()
            await task
            self.assertEqual(runtime.starts, [candidate])

    async def test_duplicate_repair_is_rejected_without_replacing_first_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            fetch_entered = asyncio.Event()
            allow_fetch = asyncio.Event()
            fetched = []

            async def fetch(source):
                fetched.append(source)
                fetch_entered.set()
                await allow_fetch.wait()
                return [VPN_NODE]

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda private: FakeVPNRuntime(private),
                subscription_fetcher=fetch,
                clock=lambda: NOW,
            )
            first = "https://subscription.example/first?token=first-secret"
            second = "https://subscription.example/second?token=second-secret"
            await collector.replace_vpn(first)
            task = collector._vpn_repair_task
            await fetch_entered.wait()
            with self.assertRaises(RuntimeError):
                await collector.replace_vpn(second)
            self.assertEqual(fetched, [first])
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            persisted = b"".join(
                path.read_bytes()
                for path in Path(temporary).rglob("*") if path.is_file()
            )
            self.assertNotIn(first.encode(), persisted)
            self.assertNotIn(second.encode(), persisted)

    async def test_reset_during_probe_stops_candidate_without_restarting_old(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"
            probe_entered = asyncio.Event()

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                probe_entered.set()
                await asyncio.Event().wait()

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/reset?token=reset-secret")
            repair = collector._vpn_repair_task
            await probe_entered.wait()
            # Remove the session only to isolate the repair cleanup from the
            # reset logout path, which legitimately restarts the persisted old node.
            paths.telegram_session.unlink()
            paths.telegram_session_outstanding.unlink()
            await collector.revoke_and_reset()
            await asyncio.gather(repair, return_exceptions=True)
            self.assertEqual(runtime.starts, [candidate])
            self.assertFalse(runtime.ready)
            for path in paths.reset_files():
                self.assertFalse(path.exists(), path)

    async def test_reset_during_probe_lets_only_logout_path_restart_old_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"
            probe_entered = asyncio.Event()

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                probe_entered.set()
                await asyncio.Event().wait()

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            gateway = FakeGateway(paths)
            collector = Collector(
                paths,
                gateway_factory=lambda *_args: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/reset-with-logout")
            repair = collector._vpn_repair_task
            await probe_entered.wait()
            result = await collector.revoke_and_reset()
            await asyncio.gather(repair, return_exceptions=True)
            self.assertEqual(runtime.starts, [candidate, VPN_NODE])
            self.assertEqual(gateway.logout_calls, 1)
            self.assertFalse(runtime.ready)
            self.assertFalse(result["revocation_required"])
            for path in paths.reset_files():
                self.assertFalse(path.exists(), path)

    async def test_close_during_probe_does_not_restart_old_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"
            probe_entered = asyncio.Event()

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                probe_entered.set()
                await asyncio.Event().wait()

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/close-during-probe")
            repair = collector._vpn_repair_task
            await probe_entered.wait()
            await collector.close()
            await asyncio.gather(repair, return_exceptions=True)
            self.assertEqual(runtime.starts, [candidate])
            self.assertFalse(runtime.ready)

    async def test_partial_candidate_commit_failure_restores_exact_old_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            old_bytes = paths.vpn_active_node.read_bytes()
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                return True

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            real_write = collector_module.atomic_write_json
            failed = False

            def fail_after_replace(path, value, mode=0o600):
                nonlocal failed
                real_write(path, value, mode)
                if path == paths.vpn_active_node and value == candidate and not failed:
                    failed = True
                    raise OSError("simulated directory fsync failure")

            with patch.object(
                collector_module, "atomic_write_json", side_effect=fail_after_replace,
            ):
                await collector.replace_vpn(
                    "https://subscription.example/write-failure")
                task = collector._vpn_repair_task
                await task
            self.assertEqual(paths.vpn_active_node.read_bytes(), old_bytes)
            self.assertEqual(runtime.starts, [candidate, VPN_NODE])
            status = await collector.public_status()
            self.assertEqual(status["last_error_type"], "VPNRepairFailed")

    async def test_rollback_start_failure_keeps_old_canonical_and_reports_unready(self):
        class RollbackFailRuntime(FakeVPNRuntime):
            async def start(self, node):
                self.trace.append("vpn_start")
                self.starts.append(copy.deepcopy(node))
                if node == VPN_NODE:
                    self.ready = False
                    raise RuntimeError("old route cannot start")
                self.ready = True

        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            old_bytes = paths.vpn_active_node.read_bytes()
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                raise TimeoutError

            runtime = RollbackFailRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/rollback-failure")
            task = collector._vpn_repair_task
            await task
            self.assertEqual(paths.vpn_active_node.read_bytes(), old_bytes)
            self.assertFalse(runtime.ready)
            status = await collector.public_status()
            self.assertEqual(status["last_error_type"], "VPNRollbackError")
            self.assertFalse(status["vpn_ready"])

    async def test_unauthorized_session_stops_candidate_search(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidates = []
            for server in ("2.2.2.2", "3.3.3.3"):
                node = copy.deepcopy(VPN_NODE)
                node["server"] = server
                candidates.append(node)

            async def fetch(_source):
                return candidates

            async def probe(*_args):
                return False

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/unauthorized")
            task = collector._vpn_repair_task
            await task
            self.assertEqual(runtime.starts, [candidates[0], VPN_NODE])
            status = await collector.public_status()
            self.assertEqual(
                status["last_error_type"], "TelegramSessionUnauthorized")

    async def test_candidate_that_dies_after_authorization_is_not_committed(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidates = []
            for server in ("2.2.2.2", "3.3.3.3"):
                node = copy.deepcopy(VPN_NODE)
                node["server"] = server
                candidates.append(node)

            async def fetch(_source):
                return candidates

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            probe_calls = 0

            async def probe(*_args):
                nonlocal probe_calls
                probe_calls += 1
                if probe_calls == 1:
                    runtime.ready = False
                return True

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/died-after-auth")
            task = collector._vpn_repair_task
            await task
            self.assertEqual(runtime.starts, candidates)
            self.assertEqual(read_json(paths.vpn_active_node), candidates[1])

    async def test_total_timeout_before_run_lock_never_touches_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"

            async def fetch(_source):
                return [candidate]

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                clock=lambda: NOW,
            )
            await collector.run_lock.acquire()
            try:
                with patch.object(
                    collector_module, "VPN_REPAIR_RUN_LOCK_TIMEOUT_S", 0.01,
                ):
                    await collector.replace_vpn(
                        "https://subscription.example/run-timeout")
                    task = collector._vpn_repair_task
                    await task
            finally:
                collector.run_lock.release()
            self.assertEqual(runtime.stop_calls, 0)
            self.assertEqual(runtime.starts, [])
            status = await collector.public_status()
            self.assertEqual(status["last_error_type"], "VPNRepairTimeout")

    async def test_stop_side_effect_failure_still_restarts_old_runtime(self):
        class StopOnceRuntime(FakeVPNRuntime):
            async def stop(self):
                self.trace.append("vpn_stop")
                self.stop_calls += 1
                self.ready = False
                if self.stop_calls == 1:
                    raise RuntimeError("late runtime cleanup failure")

        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            old_bytes = paths.vpn_active_node.read_bytes()
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"

            async def fetch(_source):
                return [candidate]

            runtime = StopOnceRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/late-stop-failure")
            task = collector._vpn_repair_task
            await task
            self.assertEqual(runtime.starts, [VPN_NODE])
            self.assertTrue(runtime.ready)
            self.assertEqual(paths.vpn_active_node.read_bytes(), old_bytes)
            status = await collector.public_status()
            self.assertEqual(status["last_error_type"], "VPNRepairFailed")

    async def test_run_lock_wait_does_not_consume_candidate_testing_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidate = copy.deepcopy(VPN_NODE)
            candidate["server"] = "2.2.2.2"

            async def fetch(_source):
                return [candidate]

            async def probe(*_args):
                return True

            # Verify the two deadline boundaries directly: wall-clock sleeps
            # made this release gate depend on GitHub runner load.
            wait_timeouts = []

            async def wait_for(awaitable, *, timeout):
                wait_timeouts.append(timeout)
                return await awaitable

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.run_lock.acquire()
            lock_held = True
            try:
                with (
                    patch.object(collector_module.asyncio, "wait_for", wait_for),
                    patch.object(
                        collector_module, "VPN_REPAIR_RUN_LOCK_TIMEOUT_S", 1.0),
                    patch.object(
                        collector_module, "VPN_REPAIR_TEST_TIMEOUT_S", 2.0),
                ):
                    await collector.replace_vpn(
                        "https://subscription.example/separate-budgets")
                    task = collector._vpn_repair_task
                    for _ in range(10):
                        await asyncio.sleep(0)
                        if len(wait_timeouts) >= 2:
                            break
                    self.assertEqual(wait_timeouts, [
                        collector_module.VPN_SUBSCRIPTION_TIMEOUT_S, 1.0,
                    ])
                    collector.run_lock.release()
                    lock_held = False
                    await task
            finally:
                if lock_held:
                    collector.run_lock.release()
            self.assertEqual(wait_timeouts, [
                collector_module.VPN_SUBSCRIPTION_TIMEOUT_S, 1.0, 2.0,
            ])
            self.assertEqual(read_json(paths.vpn_active_node), candidate)
            status = await collector.public_status()
            self.assertEqual(status["last_result"], "vpn_repaired")

    async def test_repair_requires_locked_nonrevoked_session(self):
        for case in ("missing_lock", "missing_session", "revocation_warning"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                paths = make_paths(Path(temporary))
                seed_locked(paths, watch_phase="active")
                if case == "missing_lock":
                    paths.chat_locked.unlink()
                elif case == "missing_session":
                    paths.telegram_session.unlink()
                else:
                    atomic_write_json(paths.revocation_warning, {
                        "schema": "sunny.personal-chats.revocation-warning.v2",
                        "warning": "TelegramLogoutUnconfirmed",
                        "created_at": "2026-08-04T00:00:00Z",
                    })
                collector = Collector(
                    paths,
                    vpn_runtime_factory=lambda private: FakeVPNRuntime(private),
                    subscription_fetcher=lambda _source: None,
                    clock=lambda: NOW,
                )
                with self.assertRaises((RuntimeError, ValueError)):
                    await collector.replace_vpn(
                        "https://subscription.example/precondition-secret")
                self.assertIsNone(collector._vpn_repair_task)

    async def test_repair_tests_at_most_eight_deduplicated_candidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            candidates = []
            for index in range(2, 12):
                node = copy.deepcopy(VPN_NODE)
                node["server"] = f"20.{index}.1.1"
                candidates.append(node)

            async def fetch(_source):
                return [candidates[0], candidates[0], *candidates]

            async def probe(*_args):
                raise TimeoutError

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/bounded-candidates")
            task = collector._vpn_repair_task
            await task
            self.assertEqual(runtime.starts[:-1], candidates[:8])
            self.assertEqual(runtime.starts[-1], VPN_NODE)
            status = await collector.public_status()
            self.assertEqual(status["vpn_repair_attempted"], 8)


class TestBugVPNRepairStatusFault20260819(unittest.IsolatedAsyncioTestCase):
    """Принятая замена маршрута обязана быть записана ДО spawn'а задачи.

    Residual ревью 2026-08-14: task создавался раньше `_write_status()`, и при
    локальном отказе записи status/heartbeat IPC возвращал ошибку, а фоновая
    задача продолжала работу и могла заменить маршрут. Проверяем оба файла
    записи: отказ любого из них оставляет маршрут нетронутым."""

    async def test_status_write_failure_leaves_no_background_repair(self):
        for target in ("status", "heartbeat"):
            with self.subTest(target=target):
                with tempfile.TemporaryDirectory() as temporary:
                    paths = make_paths(Path(temporary))
                    seed_locked(paths, watch_phase="active")
                    old_node_bytes = paths.vpn_active_node.read_bytes()
                    fetched = []

                    async def fetch(source):
                        fetched.append(source)
                        return [copy.deepcopy(VPN_NODE)]

                    async def probe(*_args):
                        return True

                    runtime = FakeVPNRuntime(paths.private_dir)
                    runtime.ready = True
                    collector = Collector(
                        paths,
                        vpn_runtime_factory=lambda _private: runtime,
                        subscription_fetcher=fetch,
                        telegram_probe_function=probe,
                        clock=lambda: NOW,
                    )
                    real_json = collector_module.atomic_write_json
                    real_bytes = collector_module.atomic_write_bytes

                    def fail_json(path, value, mode=0o600):
                        if target == "status" and path == paths.status:
                            raise OSError("simulated status write failure")
                        real_json(path, value, mode)

                    def fail_bytes(path, value, mode=0o600):
                        if target == "heartbeat" and path == paths.heartbeat:
                            raise OSError("simulated heartbeat write failure")
                        real_bytes(path, value, mode)

                    with patch.object(
                        collector_module, "atomic_write_json",
                        side_effect=fail_json,
                    ), patch.object(
                        collector_module, "atomic_write_bytes",
                        side_effect=fail_bytes,
                    ):
                        with self.assertRaises(OSError):
                            await collector.replace_vpn(
                                "https://subscription.example/status-fault")
                    # Задача, если бы её всё-таки создали, успела бы сходить
                    # за подпиской и поднять узел за эти витки цикла.
                    for _ in range(5):
                        await asyncio.sleep(0)

                    self.assertIsNone(collector._vpn_repair_task)
                    self.assertEqual(fetched, [])
                    self.assertEqual(runtime.starts, [])
                    self.assertEqual(
                        paths.vpn_active_node.read_bytes(), old_node_bytes)
                    status = await collector.public_status()
                    self.assertFalse(status["vpn_repairing"])
                    self.assertEqual(status["vpn_repair_state"], "idle")
                    self.assertIsNone(status["vpn_repair_error_type"])


class CollectorV2Tests(unittest.IsolatedAsyncioTestCase):

    async def test_configure_snapshots_node_starts_vpn_before_settings_and_never_persists_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            secret_url = (
                "https://subscription.example/client?token=never-persist-this")
            trace = []
            runtime = FakeVPNRuntime(paths.private_dir, trace)
            fetched = []

            async def fetch(url):
                fetched.append(url)
                return [copy.deepcopy(VPN_NODE)]

            original_save = collector_module.save_initial_config

            def assert_vpn_precedes_settings(*args):
                self.assertTrue(runtime.ready)
                self.assertTrue(paths.vpn_active_node.exists())
                trace.append("settings_commit")
                return original_save(*args)

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                clock=lambda: NOW,
            )
            with patch.object(
                    collector_module, "save_initial_config",
                    side_effect=assert_vpn_precedes_settings):
                status = await collector.configure(configure_payload(secret_url))

            self.assertEqual(fetched, [secret_url])
            self.assertEqual(trace, ["vpn_stop", "vpn_start", "settings_commit"])
            self.assertTrue(status["vpn_configured"])
            self.assertTrue(status["vpn_ready"])
            self.assertFalse(status["vpn_migration_required"])
            self.assertEqual(read_json(paths.vpn_active_node), VPN_NODE)
            persisted = b"".join(
                path.read_bytes() for path in (
                    paths.settings, paths.credentials, paths.known_hosts,
                    paths.vpn_active_node,
                ) if path.exists()
            )
            self.assertNotIn(secret_url.encode(), persisted)

    async def test_legacy_configuration_requires_reset_and_never_touches_telegram(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA, "phase": "configured",
                "chat_locked": False, "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {"scope": CONSENT_SCOPE,
                            "granted_at": "2026-08-04T00:00:00Z",
                            "expires_at": "2026-08-05T00:00:00Z"},
            })
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA, "telegram_api_id": 1,
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "secret-key-123456",
            })
            runtime = FakeVPNRuntime(paths.private_dir)
            gateway_calls = []
            collector = Collector(
                paths,
                gateway_factory=lambda *_args: gateway_calls.append(_args),
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )
            collector._setup_deadline_mono = collector.monotonic() + 3600

            status = await collector.public_status()
            self.assertFalse(status["vpn_configured"])
            self.assertFalse(status["vpn_ready"])
            self.assertTrue(status["vpn_migration_required"])
            with self.assertRaises(VPNMigrationRequiredError):
                await collector.send_code("+15555550123")
            self.assertEqual(gateway_calls, [])
            self.assertFalse(paths.telegram_session_outstanding.exists())

    async def test_configure_failure_cleans_partial_files_even_if_vpn_stop_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            runtime = FakeVPNRuntime(paths.private_dir)

            async def fetch(_url):
                return [copy.deepcopy(VPN_NODE)]

            def partial_save(target_paths, *_args):
                atomic_write_json(target_paths.settings, {"partial": True})
                atomic_write_json(target_paths.credentials, {"partial": True})
                atomic_write_bytes(target_paths.known_hosts, b"partial\n")
                runtime.stop_error = RuntimeError("child reap failed")
                raise OSError("config fsync failed")

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                clock=lambda: NOW,
            )
            with patch.object(
                collector_module, "save_initial_config", side_effect=partial_save,
            ):
                with self.assertRaises(OSError):
                    await collector.configure(
                        configure_payload("https://subscription.example/secret"))

            for path in (
                paths.vpn_active_node, paths.settings, paths.credentials,
                paths.known_hosts,
            ):
                self.assertFalse(path.exists(), path)

    async def test_reset_overtakes_send_code_blocked_in_vpn_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA, "phase": "configured",
                "chat_locked": False, "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {"scope": CONSENT_SCOPE,
                            "granted_at": "2026-08-04T00:00:00Z",
                            "expires_at": "2026-08-05T00:00:00Z"},
            })
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA, "telegram_api_id": 12345,
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "sk-or-test-secret",
            })
            atomic_write_json(paths.vpn_active_node, VPN_NODE)
            gateway = FakeGateway(paths)
            runtime = BlockingVPNRuntime(paths.private_dir)
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )
            collector._setup_deadline_mono = collector.monotonic() + 3600

            send = asyncio.create_task(collector.send_code("+15555550123"))
            await runtime.start_entered.wait()
            reset = asyncio.create_task(collector.revoke_and_reset())
            while not collector.revoked.is_set():
                await asyncio.sleep(0)
            self.assertTrue(paths.revocation_warning.exists())
            reset.cancel()
            reset.cancel()
            runtime.allow_start.set()

            with self.assertRaisesRegex(RuntimeError, "revocation|required|reset"):
                await send
            with self.assertRaises(asyncio.CancelledError):
                await reset

            self.assertEqual(gateway.send_code_calls, 0)
            self.assertFalse(paths.telegram_session.exists())
            self.assertFalse(paths.telegram_session_outstanding.exists())
            for path in paths.reset_files():
                self.assertFalse(path.exists(), path)
            self.assertFalse(paths.revocation_warning.exists())

    async def test_reset_overtakes_configure_blocked_in_vpn_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            runtime = BlockingVPNRuntime(paths.private_dir)

            async def fetch(_url):
                return [copy.deepcopy(VPN_NODE)]

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                clock=lambda: NOW,
            )
            configure = asyncio.create_task(collector.configure(
                configure_payload("https://subscription.example/secret")))
            await runtime.start_entered.wait()
            reset = asyncio.create_task(collector.revoke_and_reset())
            while not collector.revoked.is_set():
                await asyncio.sleep(0)
            runtime.allow_start.set()

            with self.assertRaisesRegex(RuntimeError, "revocation|required|reset"):
                await configure
            result = await reset

            self.assertEqual(result["last_result"], "reset")
            for path in (
                paths.vpn_active_node, paths.settings, paths.credentials,
                paths.known_hosts, paths.revocation_warning,
            ):
                self.assertFalse(path.exists(), path)

    async def test_dead_vpn_reset_never_attempts_direct_logout_and_requires_manual_revocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.start_error = RuntimeError("dead VPN")
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )

            result = await collector.revoke_and_reset()

            self.assertEqual(gateway.logout_calls, 0)
            self.assertTrue(result["revocation_required"])
            self.assertEqual(
                result["last_error_type"], "TelegramLogoutUnconfirmed")
            self.assertTrue(paths.revocation_warning.exists())
            self.assertFalse(paths.vpn_active_node.exists())

    async def test_vpn_stop_failure_cannot_block_exact_reset_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.stop_error = RuntimeError("child reap failed")
            collector = Collector(
                paths, vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )

            result = await collector.revoke_and_reset()

            self.assertTrue(result["revocation_required"])
            self.assertTrue(paths.revocation_warning.exists())
            for path in paths.reset_files():
                self.assertFalse(path.exists(), path)

    async def test_restart_with_revocation_warning_blocks_runtime_before_receiver(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            atomic_write_json(paths.revocation_warning, {
                "schema": "sunny.personal-chats.revocation-warning.v1",
                "warning": "TelegramLogoutUnconfirmed",
                "created_at": "2026-08-04T00:30:00Z",
            })
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate())
            runtime = FakeVPNRuntime(paths.private_dir)
            collector = Collector(
                paths,
                gateway_factory=lambda *_: gateway,
                transport_factory=lambda *_: transport,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )

            result = await collector.run_once()

            self.assertEqual(result["last_result"], "error")
            self.assertEqual(result["last_error_type"], "RuntimeError")
            self.assertEqual(transport.gate_calls, 0)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            self.assertEqual(gateway.fetch_calls, [])
            self.assertEqual(runtime.starts, [])

    async def test_gateway_receives_only_exact_proxy_after_vpn_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            runtime = FakeVPNRuntime(paths.private_dir)
            gateway_args = []

            def gateway_factory(*args):
                gateway_args.append(args)
                return FakeGateway(paths)

            collector = Collector(
                paths, gateway_factory=gateway_factory,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )
            await collector._ensure_vpn()
            collector._gateway(load_credentials(paths))

            self.assertEqual(gateway_args, [(
                12345, "a" * 32,
                {"proxy_type": "socks5", "addr": "127.0.0.1",
                 "port": 7891, "rdns": True},
            )])
            self.assertTrue(runtime.ready)

    async def test_close_reaps_vpn_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            atomic_write_json(paths.vpn_active_node, VPN_NODE)
            runtime = FakeVPNRuntime(paths.private_dir)
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW,
            )
            await collector._ensure_vpn()
            self.assertTrue(runtime.ready)

            await collector.close()

            self.assertFalse(runtime.ready)
            self.assertGreaterEqual(runtime.stop_calls, 2)

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
                "schema": DIALOG_CANDIDATES_SCHEMA,
                "selection_id": SELECTION_ID,
                "dialogs": [row.as_private_dict() for row in reversed(gateway.dialogs)],
            })

            async def keygen(_paths, source_id):
                uuid.UUID(source_id)
                return "ssh-ed25519 AAAAtest source", "SHA256:test"

            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                keygen_function=keygen, clock=lambda: NOW)
            collector._setup_deadline_mono = collector.monotonic() + 3600
            with self.assertRaisesRegex(ValueError, "stale"):
                await collector.select_chats({
                    "selection_id": "32345678-1234-4678-9234-567812345678",
                    "chat_ids": CHAT_IDS,
                })
            with self.assertRaisesRegex(ValueError, "chat_id is invalid"):
                await collector.select_chats({
                    "selection_id": SELECTION_ID,
                    "chat_ids": [f" {CHAT_IDS[0]}", CHAT_IDS[1]],
                })
            with self.assertRaisesRegex(ValueError, "chat_id is invalid"):
                await collector.select_chats({
                    "selection_id": SELECTION_ID,
                    "chat_ids": [float(CHAT_IDS[0]), CHAT_IDS[1]],
                })
            corrupted = read_json(paths.dialog_candidates)
            corrupted["unexpected"] = True
            atomic_write_json(paths.dialog_candidates, corrupted)
            with self.assertRaisesRegex(ValueError, "dialog candidates are invalid"):
                await collector.select_chats({
                    "selection_id": SELECTION_ID, "chat_ids": CHAT_IDS,
                })
            del corrupted["unexpected"]
            atomic_write_json(paths.dialog_candidates, corrupted)
            status = await collector.select_chats({
                "selection_id": SELECTION_ID,
                "chat_ids": list(reversed(CHAT_IDS)),
            })
            self.assertEqual([row["chat_id"] for row in status["chats"]], CHAT_IDS)
            settings = read_json(paths.settings)
            self.assertEqual([row["initial_message_id"] for row in settings["chats"]], [0, 0])
            self.assertFalse(paths.watch_state.exists())
            self.assertEqual(gateway.snapshot_calls, 0)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            with self.assertRaises(RuntimeError):
                await collector.select_chats({
                    "selection_id": SELECTION_ID, "chat_ids": CHAT_IDS,
                })

            collector.trigger_run = lambda: True
            activated = await collector.activate_monitoring()
            self.assertEqual(activated["monitoring_phase"], "activation_requested")
            self.assertEqual(read_json(paths.watch_state)["phase"], "activation_requested")

    async def test_message_links_resolve_without_fetching_the_linked_message(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA, "phase": "authenticated",
                "chat_locked": False, "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {"scope": CONSENT_SCOPE,
                            "granted_at": "2026-08-04T00:00:00Z",
                            "expires_at": "2026-08-05T00:00:00Z"},
            })
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA, "telegram_api_id": 1,
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "secret-key-123456",
            })
            atomic_write_bytes(paths.telegram_session, b"session")
            atomic_write_json(paths.vpn_active_node, VPN_NODE)
            gateway = FakeGateway(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW)
            collector._setup_deadline_mono = collector.monotonic() + 3600
            with self.assertRaisesRegex(ValueError, "1 to 16 message links"):
                await collector.resolve_chat_links([])
            with self.assertRaises(ValueError):
                await collector.resolve_chat_links(["https://t.me.evil.example/group/1"])
            with self.assertRaises(ValueError):
                await collector.resolve_chat_links(["https://t.me/contact/12345"])
            with self.assertRaises(ValueError):
                await collector.resolve_chat_links(["https://t.me/C/124/10"])
            with self.assertRaisesRegex(ValueError, "duplicate group locator"):
                await collector.resolve_chat_links([
                    "https://t.me/c/124/10",
                    "https://t.me/c/124/11",
                ])
            self.assertEqual(read_json(paths.settings)["phase"], "authenticated")
            self.assertEqual(gateway.resolve_calls, [])
            links = [
                "https://t.me/c/124/10",
                "https://t.me/public_group/20",
            ]
            result = await collector.resolve_chat_links(links)
            self.assertEqual(result["phase"], "dialogs_listed")
            self.assertEqual(gateway.resolve_calls, [links])
            self.assertEqual(
                read_json(paths.dialog_candidates)["dialogs"],
                [row.as_private_dict() for row in gateway.dialogs],
            )
            self.assertEqual(
                read_json(paths.dialog_candidates)["schema"],
                DIALOG_CANDIDATES_SCHEMA,
            )
            uuid.UUID(result["selection_id"])
            self.assertEqual(gateway.snapshot_calls, 0)
            self.assertEqual(gateway.aggregate_scan_calls, 0)
            self.assertEqual(gateway.boundary_calls, [])
            self.assertEqual(gateway.fetch_calls, [])
            persisted = paths.dialog_candidates.read_bytes() + paths.settings.read_bytes()
            self.assertNotIn(b"https://t.me/", persisted)

    async def test_link_resolution_attempt_is_durable_and_never_repeated_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA, "phase": "authenticated",
                "chat_locked": False, "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {"scope": CONSENT_SCOPE,
                            "granted_at": "2026-08-04T00:00:00Z",
                            "expires_at": "2026-08-05T00:00:00Z"},
            })
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA, "telegram_api_id": 1,
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "secret-key-123456",
            })
            atomic_write_bytes(paths.telegram_session, b"session")
            atomic_write_json(paths.vpn_active_node, VPN_NODE)
            gateway = FakeGateway(paths)

            async def fail_once(_session, links):
                self.assertEqual(
                    read_json(paths.settings)["phase"], "resolving_links")
                gateway.resolve_calls.append(list(links))
                raise TimeoutError("simulated")

            gateway.resolve_message_links = fail_once
            runtime = FakeVPNRuntime(paths.private_dir)
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW)
            collector._setup_deadline_mono = collector.monotonic() + 3600
            links = ["https://t.me/c/124/10"]
            with self.assertRaises(TimeoutError):
                await collector.resolve_chat_links(links)
            self.assertEqual(read_json(paths.settings)["phase"], "resolving_links")
            self.assertFalse(paths.dialog_candidates.exists())
            with self.assertRaisesRegex(RuntimeError, "already been used"):
                await collector.resolve_chat_links(links)
            self.assertEqual(gateway.resolve_calls, [links])

    async def test_candidate_write_without_phase_commit_never_reenumerates(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA, "phase": "authenticated",
                "chat_locked": False, "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {"scope": CONSENT_SCOPE,
                            "granted_at": "2026-08-04T00:00:00Z",
                            "expires_at": "2026-08-05T00:00:00Z"},
            })
            atomic_write_json(paths.credentials, {
                "schema": CREDENTIALS_SCHEMA, "telegram_api_id": 1,
                "telegram_api_hash": "a" * 32,
                "openrouter_api_key": "secret-key-123456",
            })
            atomic_write_bytes(paths.telegram_session, b"session")
            atomic_write_json(paths.vpn_active_node, VPN_NODE)
            gateway = FakeGateway(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW)
            collector._setup_deadline_mono = collector.monotonic() + 3600
            original_write = collector_module.atomic_write_json

            def fail_final_phase(path, value, mode=0o600):
                if path == paths.settings and value.get("phase") == "dialogs_listed":
                    raise OSError("simulated")
                return original_write(path, value, mode)

            links = [
                "https://t.me/c/124/10",
                "https://t.me/public_group/20",
            ]
            with patch.object(
                    collector_module, "atomic_write_json",
                    side_effect=fail_final_phase):
                with self.assertRaises(OSError):
                    await collector.resolve_chat_links(links)
            self.assertTrue(paths.dialog_candidates.exists())
            self.assertEqual(read_json(paths.settings)["phase"], "resolving_links")
            with self.assertRaisesRegex(RuntimeError, "already been used"):
                await collector.resolve_chat_links(links)
            self.assertEqual(gateway.resolve_calls, [links])

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
            gateway.boundary = {CHAT_IDS[0]: 100, CHAT_IDS[1]: 200}
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

    async def test_daily_digest_upload_carries_only_sanitized_llm_usage(self):
        class MeteredDigest(str):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.fetches = {
                CHAT_IDS[0]: FetchResult(
                    101, [SelectedMessage(101, 7, NOW, "A")]),
                CHAT_IDS[1]: FetchResult(
                    201, [SelectedMessage(201, 8, NOW, "B")]),
            }
            transport = FakeTransport(paths, gate(digest_due=True))
            collector = collector_for(paths, gateway, transport)
            usage = {
                "prompt_tokens": 1200,
                "completion_tokens": 340,
                "reasoning_tokens": 210,
                "cost": 0.73,
                "upstream_cost": 0.70,
            }

            async def metered(*_args):
                result = MeteredDigest("Общий дайджест")
                result.llm_usage = usage
                return result

            collector.digest_function = metered
            result = await collector.run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(transport.digest_uploads[0]["llm_usage"], usage)

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
            runtime = FakeVPNRuntime(paths.private_dir)
            collector = Collector(
                paths, gateway_factory=lambda *_: gateway,
                vpn_runtime_factory=lambda _private: runtime,
                clock=lambda: NOW)
            result = await collector.revoke_and_reset()
            self.assertEqual(result["last_result"], "reset")
            self.assertEqual(gateway.logout_calls, 1)
            for path in paths.reset_files():
                self.assertFalse(path.exists(), str(path))


class TestBugMonitorDigestStarvation20260814(
        unittest.IsolatedAsyncioTestCase):
    """A hung mention batch must not consume the whole daily digest window."""

    @staticmethod
    def sequenced_transport(paths, *values):
        class SequencedTransport(FakeTransport):
            def __init__(self):
                super().__init__(paths, values[0])
                self._values = list(values)

            async def gate(self, source_id, chat_ids, revoked):
                self.trace.append("status")
                self.gate_calls += 1
                if source_id != SOURCE_ID or chat_ids != CHAT_IDS or revoked.is_set():
                    raise AssertionError("invalid status binding")
                index = min(self.gate_calls - 1, len(self._values) - 1)
                return copy.deepcopy(self._values[index])

        return SequencedTransport()

    async def test_due_digest_runs_after_active_monitor_timeout_with_fresh_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            class HangingMonitorGateway(FakeGateway):
                async def snapshot_and_scan_mentions(self, *_args):
                    await asyncio.Event().wait()

            gateway = HangingMonitorGateway(paths)
            transport = FakeTransport(paths, gate(digest_due=True))
            digest_calls = []
            collector = collector_for(paths, gateway, transport, digest_calls)

            with patch.object(
                    collector_module, "TELEGRAM_FETCH_TIMEOUT_S", 0.01):
                result = await collector.run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(result["last_error_type"], "TimeoutError")
            self.assertEqual(result["failed_chat_count"], len(CHAT_IDS))
            self.assertEqual(transport.gate_calls, 2)
            self.assertEqual(len(digest_calls), 1)
            self.assertEqual(len(transport.digest_uploads), 1)
            self.assertFalse(paths.monitor_pending.exists())

    async def test_monitor_timeout_before_active_phase_never_runs_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="activation_requested")

            class HangingBaselineGateway(FakeGateway):
                async def snapshot_tops(self, *_args):
                    await asyncio.Event().wait()

            gateway = HangingBaselineGateway(paths)
            transport = FakeTransport(paths, gate(
                baseline_required=True, digest_due=True,
            ))
            digest_calls = []
            collector = collector_for(paths, gateway, transport, digest_calls)

            with patch.object(
                    collector_module, "TELEGRAM_FETCH_TIMEOUT_S", 0.01):
                result = await collector.run_once()

            self.assertEqual(result["last_result"], "error")
            self.assertEqual(result["last_error_type"], "TimeoutError")
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.digest_uploads, [])

    async def test_fresh_not_due_gate_after_timeout_never_fetches_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            class HangingMonitorGateway(FakeGateway):
                async def snapshot_and_scan_mentions(self, *_args):
                    await asyncio.Event().wait()

            gateway = HangingMonitorGateway(paths)
            transport = self.sequenced_transport(
                paths, gate(digest_due=True), gate(digest_due=False),
            )
            digest_calls = []
            collector = collector_for(paths, gateway, transport, digest_calls)

            with patch.object(
                    collector_module, "TELEGRAM_FETCH_TIMEOUT_S", 0.01):
                result = await collector.run_once()

            self.assertEqual(result["last_result"], "watched_not_due")
            self.assertEqual(result["last_error_type"], "TimeoutError")
            self.assertEqual(digest_calls, [])
            self.assertEqual(gateway.boundary_calls, [])
            self.assertEqual(gateway.fetch_calls, [])
            self.assertEqual(transport.digest_uploads, [])

    async def test_fresh_digest_chain_jump_still_blocks_all_digest_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            class HangingMonitorGateway(FakeGateway):
                async def snapshot_and_scan_mentions(self, *_args):
                    await asyncio.Event().wait()

            jumped = gate(
                digest_due=True, digest_sequence=2,
                digest_previous="a" * 64,
            )
            gateway = HangingMonitorGateway(paths)
            transport = self.sequenced_transport(
                paths, gate(digest_due=True), jumped,
            )
            digest_calls = []
            collector = collector_for(paths, gateway, transport, digest_calls)

            with patch.object(
                    collector_module, "TELEGRAM_FETCH_TIMEOUT_S", 0.01):
                result = await collector.run_once()

            self.assertEqual(result["last_result"], "error")
            self.assertEqual(result["last_error_type"], "RuntimeError")
            self.assertEqual(result["failed_chat_count"], len(CHAT_IDS))
            self.assertEqual(digest_calls, [])
            self.assertEqual(gateway.boundary_calls, [])
            self.assertEqual(gateway.fetch_calls, [])
            self.assertEqual(transport.digest_uploads, [])

    async def test_revocation_cancellation_during_monitor_never_runs_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            class CancelledMonitorGateway(FakeGateway):
                async def snapshot_and_scan_mentions(self, *_args):
                    raise asyncio.CancelledError

            gateway = CancelledMonitorGateway(paths)
            transport = FakeTransport(paths, gate(digest_due=True))
            digest_calls = []
            result = await collector_for(
                paths, gateway, transport, digest_calls,
            ).run_once()

            self.assertEqual(result["last_result"], "revoked")
            self.assertEqual(digest_calls, [])
            self.assertEqual(transport.digest_uploads, [])


class TestRecentRunsJournal20260817(unittest.IsolatedAsyncioTestCase):
    """Журнал прогонов в интерфейсе.

    Статус описывает только последний тик и перезаписывается каждую минуту,
    поэтому редкий отказ жил один тик: разбор падающего digest в августе
    2026 занял день ровно из-за этого. Журнал делает историю видимой, не
    вынося наружу ничего из переписки."""

    def _collector(self, paths):
        return collector_for(paths, FakeGateway(paths),
                             FakeTransport(paths, gate()), [])

    async def test_repeated_results_collapse_and_history_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            collector = self._collector(paths)

            for _ in range(30):
                collector._write_status(last_run_at="2026-08-17T10:00:00+00:00",
                                        last_result="digest_cooldown",
                                        last_error_type=None)
            status = collector._write_status(
                last_run_at="2026-08-17T10:05:00+00:00",
                last_result="error", last_error_type="OpenRouterError")

            runs = status["recent_runs"]
            self.assertLessEqual(len(runs), RECENT_RUNS_LIMIT)
            # тридцать одинаковых тиков — одна строка со счётчиком, иначе
            # ошибка вытеснялась бы из журнала ещё до того, как её увидят
            cooldowns = [row for row in runs if row["result"] == "digest_cooldown"]
            self.assertEqual(len(cooldowns), 1)
            self.assertEqual(cooldowns[0]["repeated"], 30)
            self.assertEqual(runs[-1]["result"], "error")
            self.assertEqual(runs[-1]["error_type"], "OpenRouterError")

    async def test_journal_survives_status_rewrites_and_carries_no_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._collector(paths)._write_status(
                last_run_at="2026-08-17T10:00:00+00:00",
                last_result="error", last_error_type="OpenRouterError")
            # другой инстанс читает журнал с диска, а не начинает с нуля
            status = await self._collector(paths).public_status()

            runs = status["recent_runs"]
            failures = [row for row in runs if row["result"] == "error"]
            self.assertEqual(failures[-1]["error_type"], "OpenRouterError")
            self.assertEqual(failures[-1]["at"], "2026-08-17T10:00:00+00:00")
            self.assertEqual(
                set(failures[-1]) - {"repeated"},
                {"at", "result", "error_type", "message_count", "failed_chat_count"},
            )

    async def test_distinct_outcomes_are_bounded_and_status_stays_small(self):
        """Граница журнала проверяется РАЗНЫМИ исходами: серия одинаковых
        схлопывается в одну строку и предела не достигает вовсе."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            collector = self._collector(paths)

            for index in range(RECENT_RUNS_LIMIT * 3):
                collector._write_status(
                    last_run_at=f"2026-08-17T03:{index % 60:02d}:00+00:00",
                    last_result="error" if index % 2 else "watched_not_due",
                    last_error_type="OpenRouterError" if index % 2 else None)

            status = json.loads(paths.status.read_text(encoding="utf-8"))
            self.assertEqual(len(status["recent_runs"]), RECENT_RUNS_LIMIT)
            # статус читается с лимитом 16 КБ — журнал обязан в него влезать
            self.assertLess(len(paths.status.read_bytes()), 16 * 1024)

    async def test_non_run_entries_carry_own_time_and_no_inherited_error(self):
        """Ревью 2026-08-17: запись «starting» после ночного падения брала
        время и тип ошибки предыдущего прогона — журнал показывал отказ,
        которого не было, да ещё и датированный чужим часом."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._collector(paths)._write_status(
                last_run_at="2026-08-17T03:05:00+00:00", last_result="error",
                last_error_type="OpenRouterError", failed_chat_count=2)
            # рестарт контейнера: конструктор пишет «starting» без last_run_at
            status = await self._collector(paths).public_status()

            starting = [row for row in status["recent_runs"]
                        if row["result"] == "starting"][-1]
            self.assertIsNone(starting["error_type"])
            self.assertIsNone(starting["failed_chat_count"])
            self.assertNotEqual(starting["at"], "2026-08-17T03:05:00+00:00")

    async def test_peer_failure_spike_is_not_collapsed_away(self):
        """Ревью 2026-08-17: схлопывание шло только по result/error_type, и
        одиночный тик, где отвалились все peer'ы, исчезал внутри длинной серии
        одинаковых исходов — то есть ровно та редкая ошибка, ради которой
        журнал и заводился."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            collector = self._collector(paths)

            collector._write_status(last_run_at="2026-08-17T03:00:00+00:00",
                                    last_result="digest_cooldown",
                                    last_error_type=None, failed_chat_count=0)
            collector._write_status(last_run_at="2026-08-17T03:01:00+00:00",
                                    last_result="digest_cooldown",
                                    last_error_type=None, failed_chat_count=16)
            status = collector._write_status(
                last_run_at="2026-08-17T03:02:00+00:00",
                last_result="digest_cooldown", last_error_type=None,
                failed_chat_count=0)

            spikes = [row for row in status["recent_runs"]
                      if row.get("failed_chat_count") == 16]
            self.assertEqual(len(spikes), 1)

    async def test_broken_repeated_value_from_disk_cannot_crash_the_write(self):
        """`repeated` приходит из файла статуса; строка вместо числа роняла бы
        планировщик на int()."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            collector = self._collector(paths)
            collector._write_status(last_result="watched_not_due",
                                    last_error_type=None)
            poisoned = json.loads(paths.status.read_text(encoding="utf-8"))
            poisoned["recent_runs"][-1]["repeated"] = "очень много"
            paths.status.write_text(json.dumps(poisoned), encoding="utf-8")

            # тот же коллектор: он перечитывает статус с диска, а новый
            # экземпляр вписал бы «starting» и разорвал серию
            status = collector._write_status(
                last_result="watched_not_due", last_error_type=None)
            self.assertEqual(status["recent_runs"][-1]["repeated"], 2)


class TestBugDigestOverReceiverLimit20260818(unittest.IsolatedAsyncioTestCase):
    """Выпуск длиннее потолка приёмника обрезается, а не теряется целиком.

    Приложение обновляется раньше приёмника: пока тот объявляет старый
    потолок, длинный выпуск в него не влезает. Падение здесь означало бы
    сутки без дайджеста вместо срезанного хвоста."""

    def setUp(self):
        FakeTunnel.instances.clear()

    async def test_chats_carry_the_link_prefix_of_their_own_peer(self):
        """Префикс ссылки выводится из chat_id того же чата.

        Перепутанный порядок или чужой chat_id дал бы ссылки, ведущие в
        другую группу, — и заметить это можно было бы только по клику."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            calls = []
            await collector_for(
                paths, FakeGateway(paths),
                FakeTransport(paths, gate(digest_due=True)), calls).run_once()

            chats = calls[0][0]
            self.assertTrue(chats)
            expected = {
                title: supergroup_link_prefix(chat_id)
                for chat_id, title in zip(CHAT_IDS, TITLES)
            }
            for chat in chats:
                self.assertEqual(chat.link_prefix, expected[chat.title])
                self.assertTrue(chat.link_prefix.startswith("https://t.me/c/"))

    async def test_long_digest_is_truncated_to_the_gate_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            transport = FakeTransport(paths, gate(digest_due=True))

            async def long_digest(*_args):
                # В потолок дайджеста (24 000 UTF-16 единиц) текст влезает,
                # а в 32 КБ payload старого приёмника — уже нет: кириллица
                # это два байта UTF-8 на единицу.
                return "\n".join(f"Строка {i}: " + "и" * 200
                                  for i in range(100))

            collector = collector_for(paths, FakeGateway(paths), transport)
            collector.digest_function = long_digest
            result = await collector.run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            payload = transport.digest_uploads[-1]
            limit = gate(digest_due=True)["digest"]["max_upload_bytes"]
            self.assertLessEqual(
                len(canonical_json_bytes(payload)), limit)
            self.assertTrue(payload["digest"].endswith(
                DIGEST_TRUNCATION_NOTE.strip()))
            self.assertIn("Строка 0", payload["digest"])


class TestOpenRouterTunnelLifecycle20260818(unittest.IsolatedAsyncioTestCase):
    """Канал до OpenRouter: поднимается на запрос, гасится всегда, digest-only."""

    def setUp(self):
        FakeTunnel.instances.clear()

    async def test_tunnel_is_raised_for_the_request_and_torn_down(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            transport = FakeTransport(paths, gate(digest_due=True))
            digest_calls = []
            result = await collector_for(
                paths, FakeGateway(paths), transport, digest_calls).run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(len(FakeTunnel.instances), 1)
            self.assertEqual(FakeTunnel.instances[0].started, 1)
            self.assertEqual(FakeTunnel.instances[0].stopped, 1)

    async def test_tunnel_is_torn_down_even_when_the_request_fails(self):
        """Иначе ssh оставался бы жить после каждой неудачи."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            async def failing_digest(*_args):
                raise RuntimeError("OpenRouter refused")

            collector = collector_for(
                paths, FakeGateway(paths), FakeTransport(paths, gate(digest_due=True)))
            collector.digest_function = failing_digest
            result = await collector.run_once()

            self.assertEqual(result["last_result"], "error")
            self.assertEqual(FakeTunnel.instances[-1].stopped, 1)

    async def test_dead_tunnel_after_request_fails_the_attempt(self):
        """Молчаливый успех при умершем канале означал бы дайджест,
        собранный неизвестно каким маршрутом."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            class DyingTunnel(FakeTunnel):
                async def start(self):
                    await super().start()
                    self.alive = False

            transport = FakeTransport(paths, gate(digest_due=True))
            collector = collector_for(paths, FakeGateway(paths), transport)
            collector.tunnel_factory = DyingTunnel
            result = await collector.run_once()

            self.assertEqual(result["last_result"], "error")
            self.assertEqual(result["last_error_type"], "TunnelUnavailableError")
            self.assertEqual(transport.digest_uploads, [])

    async def test_keygen_failure_does_not_stop_mention_monitoring(self):
        """Инвариант «ошибка digest не блокирует monitor»: канал — забота
        только дайджеста, и отказ ssh-keygen не должен уносить упоминания."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            async def failing_keygen(*_args):
                raise RuntimeError("ssh-keygen failed")

            trace = []
            transport = FakeTransport(paths, gate(digest_due=True), trace)
            collector = collector_for(paths, FakeGateway(paths), transport)
            collector.openrouter_keygen_function = failing_keygen
            result = await collector.run_once()

            # monitor успел пройти: гейт запрошен, Telegram просканирован —
            # раньше keygen стоял в общем префиксе и ронял тик до этого
            self.assertGreater(transport.gate_calls, 0)
            self.assertIn("status", trace)
            self.assertEqual(result["last_result"], "error")


class TestResetWipesTunnelKey20260818(unittest.IsolatedAsyncioTestCase):
    """Ревью 2026-08-18: ключ канала переживал factory reset и оставался
    авторизованным на DO, а его публичная часть светилась в статусе."""

    async def test_factory_reset_deletes_the_tunnel_keypair(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            paths.openrouter_key.write_text("private", encoding="ascii")
            paths.openrouter_public_key.write_text(
                "ssh-ed25519 AAAAold old@sunny-openrouter", encoding="ascii")

            collector = collector_for(
                paths, FakeGateway(paths), FakeTransport(paths, gate()))
            status = await collector.revoke_and_reset()

            self.assertFalse(paths.openrouter_key.exists())
            self.assertFalse(paths.openrouter_public_key.exists())
            self.assertIsNone(status.get("openrouter_public_key"))




class TestBugOpenRouterKeyOnEmptyDay20260819(unittest.IsolatedAsyncioTestCase):
    """Ключ канала обязан родиться на первой же попытке выпуска.

    Генерация стояла в ветке `else:` после `if total == 0`, поэтому на свежем
    экземпляре, у которого первые сутки прошли без сообщений, публичный ключ
    не появлялся в интерфейсе вовсе, и на DO его добавляли руками."""

    async def test_day_without_messages_still_generates_the_channel_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self.assertFalse(paths.openrouter_key.exists())
            gateway = FakeGateway(paths)
            gateway.fetches = {
                chat_id: FetchResult(BASELINE_TOPS[chat_id], [])
                for chat_id in CHAT_IDS
            }
            transport = FakeTransport(paths, gate(digest_due=True))
            collector = collector_for(paths, gateway, transport)
            tunnels_before = len(FakeTunnel.instances)

            result = await collector.run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(
                transport.digest_uploads[-1]["total_message_count"], 0)
            self.assertEqual(transport.digest_uploads[-1]["digest"], "")
            self.assertTrue(paths.openrouter_key.exists())
            self.assertIn(
                "sunny-openrouter", result["openrouter_public_key"])
            # Канал при этом не поднимался: запроса к модели на пустых сутках
            # нет, и платить за ssh-сессию не за что.
            self.assertEqual(len(FakeTunnel.instances), tunnels_before)


class TestBugVPNAddressRotation20260819(unittest.IsolatedAsyncioTestCase):
    """Ротация Primary IP не должна убивать Telegram до утра.

    Провайдер меняет адрес узла по расписанию, приложение держит IP-литерал
    (имя резолвится один раз), и Telegram молча пропадает до ручной замены
    узла — 13–16.08 четыре ночи подряд, затем снова 19.08. Подписку на диске
    хранить нельзя, поэтому лечение опирается на имя хоста: оно не секрет.
    """

    @staticmethod
    def _seed_origin(paths, hostname="vpn.example.com"):
        atomic_write_json(paths.vpn_node_origin, {"hostname": hostname}, 0o600)

    def _collector(self, paths, *, runtime, probe, resolved):
        """Резолвер подменяется целиком: DNS в тестах не спрашиваем, но путь
        от имени хоста до узла остаётся продакшновым."""
        def node_resolver(nodes):
            self.assertEqual(nodes[0]["server"], "vpn.example.com")
            return [dict(nodes[0], server=resolved)]

        return Collector(
            paths,
            vpn_runtime_factory=lambda _private: runtime,
            telegram_probe_function=probe,
            node_resolver=node_resolver,
            clock=lambda: NOW,
        )

    async def test_stall_triggers_reresolve_and_commits_the_new_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True

            async def probe(*_args):
                return True

            collector = self._collector(
                paths, runtime=runtime, probe=probe, resolved="9.9.9.9")
            collector._telegram_stall_ticks = 3
            self.assertTrue(collector._maybe_start_vpn_reresolve())
            await collector._vpn_repair_task

            self.assertEqual(collector._vpn_repair_state, "succeeded")
            self.assertEqual(read_json(paths.vpn_active_node)["server"], "9.9.9.9")
            # Имя хоста переживает переезд, иначе следующая ротация снова
            # потребовала бы человека.
            self.assertEqual(
                read_json(paths.vpn_node_origin), {"hostname": "vpn.example.com"})

    async def test_single_stall_and_unchanged_address_never_touch_the_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True

            async def probe(*_args):
                raise AssertionError("probe must not run")

            collector = self._collector(
                paths, runtime=runtime, probe=probe, resolved=VPN_NODE["server"])
            # Одиночная рябь порога не достигает.
            collector._note_telegram_stall(True)
            collector._note_telegram_stall(True)
            self.assertFalse(collector._maybe_start_vpn_reresolve())
            # Успешный тик обнуляет счётчик.
            collector._note_telegram_stall(False)
            self.assertEqual(collector._telegram_stall_ticks, 0)

            collector._telegram_stall_ticks = 3
            self.assertTrue(collector._maybe_start_vpn_reresolve())
            await collector._vpn_repair_task

            # Адрес не менялся — маршрут не гасили и узел не переписывали.
            self.assertEqual(collector._vpn_repair_state, "failed")
            self.assertEqual(runtime.stop_calls, 0)
            self.assertEqual(runtime.starts, [])
            self.assertEqual(read_json(paths.vpn_active_node), VPN_NODE)

    async def test_without_a_known_origin_nothing_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True

            async def probe(*_args):
                raise AssertionError("probe must not run")

            collector = self._collector(
                paths, runtime=runtime, probe=probe, resolved="9.9.9.9")
            collector._telegram_stall_ticks = 9
            # Узел настроен старой версией: имени хоста рядом нет, и выдумать
            # его нельзя — остаётся ручная замена.
            self.assertFalse(collector._maybe_start_vpn_reresolve())
            self.assertIsNone(collector._vpn_repair_task)

    async def test_cooldown_blocks_a_second_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True

            async def probe(*_args):
                return True

            collector = self._collector(
                paths, runtime=runtime, probe=probe, resolved="9.9.9.9")
            collector._telegram_stall_ticks = 3
            self.assertTrue(collector._maybe_start_vpn_reresolve())
            await collector._vpn_repair_task
            collector._telegram_stall_ticks = 3
            # Вторая попытка внутри окна: DNS не обновляется мгновенно, а
            # каждая попытка гасит рабочий маршрут.
            self.assertFalse(collector._maybe_start_vpn_reresolve())

    async def test_replacement_rewrites_the_origin_of_the_new_node(self):
        """Имя хоста обязано меняться вместе с узлом.

        Осталось бы прежним — авторезолв повёл бы следующую ротацию на
        адрес чужого узла, и отказ выглядел бы как «VPN просто не работает».
        """
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            seed_vpn_repair_protected_files(paths)
            self._seed_origin(paths, "old.example.com")
            fresh = copy.deepcopy(VPN_NODE)
            fresh["server"] = "5.5.5.5"

            async def fetch(_source):
                return [{**fresh, "origin": "new.example.com"}]

            async def probe(*_args):
                return True

            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                subscription_fetcher=fetch,
                telegram_probe_function=probe,
                clock=lambda: NOW,
            )
            await collector.replace_vpn(
                "https://subscription.example/client?token=secret")
            await collector._vpn_repair_task

            self.assertEqual(read_json(paths.vpn_active_node), fresh)
            self.assertEqual(
                read_json(paths.vpn_node_origin), {"hostname": "new.example.com"})

    async def test_every_chat_failing_counts_as_a_stall_through_run_once(self):
        """Самая частая форма мёртвого маршрута — не зависание.

        Пиры отваливаются каждый по своему таймауту, батч возвращается
        штатно, и раньше такой тик считался УСПЕХОМ и обнулял счётчик:
        авторезолв не запускался ни разу именно в целевом сценарии."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            gateway = FakeGateway(paths)
            gateway.scan_failures = list(CHAT_IDS)
            collector = collector_for(
                paths, gateway, FakeTransport(paths, gate(digest_due=False)))
            collector.node_resolver = lambda nodes: [
                dict(nodes[0], server="9.9.9.9")]

            async def probe(*_args):
                return True

            collector.telegram_probe_function = probe

            for _ in range(collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE):
                gateway.scan_failures = list(CHAT_IDS)
                await collector.run_once()

            self.assertIsNotNone(collector._vpn_repair_task)
            await collector._vpn_repair_task
            self.assertEqual(read_json(paths.vpn_active_node)["server"], "9.9.9.9")

    async def test_connection_error_counts_as_a_stall_through_run_once(self):
        """Протухший адрес, переиспользованный другим арендатором, отвечает
        RST: Telethon поднимает ConnectionError задолго до таймаута, и тик
        уходит в общий except. Этот путь тоже обязан взводить детектор."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            gateway = FakeGateway(paths)

            async def dead_route(*_args, **_kwargs):
                raise ConnectionError("Connection to Telegram failed")

            gateway.snapshot_and_scan_mentions = dead_route
            collector = collector_for(
                paths, gateway, FakeTransport(paths, gate(digest_due=False)))
            collector.node_resolver = lambda nodes: [
                dict(nodes[0], server="9.9.9.9")]

            async def probe(*_args):
                return True

            collector.telegram_probe_function = probe

            for _ in range(collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE):
                status = await collector.run_once()
            self.assertEqual(status["last_error_type"], "ConnectionError")

            self.assertIsNotNone(collector._vpn_repair_task)
            await collector._vpn_repair_task

    async def test_cooldown_expires_and_allows_a_second_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            clock = [1000.0]

            async def probe(*_args):
                return True

            def node_resolver(nodes):
                return [dict(nodes[0], server="9.9.9.9")]

            collector = Collector(
                paths,
                vpn_runtime_factory=lambda _private: runtime,
                telegram_probe_function=probe,
                node_resolver=node_resolver,
                clock=lambda: NOW,
                monotonic=lambda: clock[0],
            )
            collector._telegram_stall_ticks = (
                collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE)
            self.assertTrue(collector._maybe_start_vpn_reresolve())
            await collector._vpn_repair_task

            collector._telegram_stall_ticks = (
                collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE)
            self.assertFalse(collector._maybe_start_vpn_reresolve())
            clock[0] += collector_module.VPN_RERESOLVE_COOLDOWN_S + 1
            collector._telegram_stall_ticks = (
                collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE)
            # Окно истекло — следующая ротация не должна ждать человека.
            self.assertTrue(collector._maybe_start_vpn_reresolve())
            await collector._vpn_repair_task

    async def test_attempt_that_never_reached_a_probe_keeps_its_window(self):
        """Мёртвый маршрут растягивает тик, и авторезолв может не дождаться
        run_lock. Списать за это получасовое окно — значит отложить лечение
        именно из-за той поломки, которую лечим."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True

            async def probe(*_args):
                raise AssertionError("probe must not run")

            collector = self._collector(
                paths, runtime=runtime, probe=probe, resolved="9.9.9.9")
            await collector.run_lock.acquire()
            try:
                with patch.object(
                        collector_module, "VPN_REPAIR_RUN_LOCK_TIMEOUT_S", 0.01):
                    collector._telegram_stall_ticks = (
                        collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE)
                    self.assertTrue(collector._maybe_start_vpn_reresolve())
                    await collector._vpn_repair_task
            finally:
                collector.run_lock.release()

            self.assertEqual(collector._vpn_repair_state, "failed")
            self.assertIsNone(collector._vpn_reresolve_after_mono)
            collector._telegram_stall_ticks = (
                collector_module.VPN_STALL_TICKS_BEFORE_RERESOLVE)
            self.assertTrue(collector._maybe_start_vpn_reresolve())
            await collector._vpn_repair_task

    async def test_factory_reset_removes_the_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            self._seed_origin(paths)
            self.assertIn(paths.vpn_node_origin, paths.reset_files())


if __name__ == "__main__":
    unittest.main()


NEW_CHAT_ID = -1003334567890
NEW_PEER = PeerSpec("channel", 3334567890, 555444)


class TestChatSetExtension20260820(unittest.IsolatedAsyncioTestCase):
    """Приложение подхватывает чат, добавленный на приёмнике.

    Порядок именно такой: расширение объявляет сервер, приложение только
    принимает. Иначе взломанный Umbrel мог бы расширить себе доступ сам, а
    набор чатов — это то, что решает владелец сервера.
    """

    def _extended_gate(self):
        cursors = {chat_id: BASELINE_TOPS[chat_id] for chat_id in CHAT_IDS}
        cursors[NEW_CHAT_ID] = 0
        ordered = sorted(cursors)
        value = gate(monitor_cursors={key: cursors[key] for key in ordered},
                     digest_cursors={key: 0 for key in ordered})
        return value

    async def test_extension_baseline_is_sent_for_the_new_chat_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")

            # Сервер объявил новый чат, приложение уже приняло его в settings.
            settings = read_json(paths.settings)
            settings["chats"] = sorted(
                settings["chats"] + [{
                    "chat_id": NEW_CHAT_ID,
                    "title": "Добавленный чат",
                    "peer": NEW_PEER.as_dict(),
                    "initial_message_id": 0,
                }],
                key=lambda row: row["chat_id"])
            atomic_write_json(paths.settings, settings)
            watch = read_json(paths.watch_state)
            order = [row["chat_id"] for row in settings["chats"]]
            watch["monitor_cursors"] = collector_module._extended_cursor_rows(
                watch["monitor_cursors"], NEW_CHAT_ID,
                {"chat_id": NEW_CHAT_ID, "through_message_id": 0}, order)
            watch["chats"] = collector_module._extended_cursor_rows(
                watch["chats"], NEW_CHAT_ID,
                {"chat_id": NEW_CHAT_ID, "scan_through_message_id": 0,
                 "read_pending_through_message_id": 0,
                 "read_acked_through_message_id": 0}, order)
            watch["pending_extension_chat_ids"] = [NEW_CHAT_ID]
            atomic_write_json(paths.watch_state, watch)

            gateway = FakeGateway(paths)
            gateway.tops = {**BASELINE_TOPS, NEW_CHAT_ID: 4242}
            gateway.assert_exact_selected = lambda selected: None
            transport = FakeTransport(paths, self._extended_gate())
            transport.expected_chat_ids = order
            await collector_for(paths, gateway, transport).run_once()

            uploads = [row for row in transport.monitor_uploads
                       if row["kind"] == "extension_baseline"]
            self.assertEqual(len(uploads), 1)
            payload = uploads[0]
            # Только новый чат, от нуля, и цепочка продолжается.
            self.assertEqual(
                payload["ranges"],
                [{"chat_id": NEW_CHAT_ID, "from_message_id_exclusive": 0,
                  "through_message_id": 4242}])
            self.assertGreater(payload["sequence"], 1)
            self.assertIsNotNone(payload["previous_sha256"])
            self.assertEqual(payload["events"], [])

    async def test_settled_chats_never_get_a_second_extension(self):
        """Курсор работающего чата не должен обнуляться расширением."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            transport = FakeTransport(paths, gate(digest_due=False))

            await collector_for(paths, gateway, transport).run_once()

            self.assertEqual(
                [row for row in transport.monitor_uploads
                 if row["kind"] == "extension_baseline"], [])

    async def test_extend_chats_accepts_only_the_announced_chat(self):
        """Продовый путь целиком: без него фаза `resolving_extension` уходила
        в settings.json, которого load_settings не принимает, и приложение
        переставало работать вообще — ревью нашло это на реальном прогоне."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.dialogs = [DialogCandidate(
                NEW_CHAT_ID, "Добавленный чат", NEW_PEER)]
            transport = FakeTransport(paths, self._extended_gate())
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = collector_for(paths, gateway, transport, runtime=runtime)

            status = await collector.extend_chats("https://t.me/c/3334567890/12")

            self.assertEqual(status["last_result"], "chat_extension_accepted")
            settings = read_json(paths.settings)
            # Фаза откатилась, файл читается — иначе приложение мертво.
            self.assertEqual(settings["phase"], "chat_locked")
            collector_module.load_settings(paths)
            order = [row["chat_id"] for row in settings["chats"]]
            self.assertEqual(order, sorted(order))
            self.assertIn(NEW_CHAT_ID, order)
            watch = read_json(paths.watch_state)
            self.assertEqual(
                [row["chat_id"] for row in watch["monitor_cursors"]], order)
            self.assertEqual([row["chat_id"] for row in watch["chats"]], order)

    async def test_extend_chats_refuses_a_chat_the_receiver_never_announced(self):
        """Иначе приложение добавляло бы себе доступ само — ровно то, ради
        чего расширение начинается на сервере."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            gateway = FakeGateway(paths)
            gateway.dialogs = [DialogCandidate(
                -1009999999999, "Чужой чат", PeerSpec("channel", 9999999999, 1))]
            transport = FakeTransport(paths, self._extended_gate())
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = collector_for(paths, gateway, transport, runtime=runtime)

            with self.assertRaises(RuntimeError):
                await collector.extend_chats("https://t.me/c/9999999999/1")

            settings = read_json(paths.settings)
            self.assertEqual(settings["phase"], "chat_locked")
            self.assertNotIn(
                -1009999999999, [row["chat_id"] for row in settings["chats"]])

    async def test_extend_chats_refuses_when_the_gate_announced_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            transport = FakeTransport(paths, gate(digest_due=False))
            collector = collector_for(paths, FakeGateway(paths), transport)

            with self.assertRaisesRegex(RuntimeError, "has not announced"):
                await collector.extend_chats("https://t.me/c/3334567890/12")
            self.assertEqual(read_json(paths.settings)["phase"], "chat_locked")

    async def test_chat_without_messages_never_looks_like_an_extension(self):
        """Пустая группа даёт нулевой курсор и локально, и у приёмника.

        Пока «новизна» выводилась из нулей, такой чат бесконечно получал бы
        чужой extension_baseline и валил монитор — к расширению он отношения
        не имеет."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            watch = read_json(paths.watch_state)
            empty_id = CHAT_IDS[0]
            for row in watch["chats"]:
                if row["chat_id"] == empty_id:
                    row["scan_through_message_id"] = 0
            for row in watch["monitor_cursors"]:
                if row["chat_id"] == empty_id:
                    row["through_message_id"] = 0
            atomic_write_json(paths.watch_state, watch)

            cursors = dict(BASELINE_TOPS)
            cursors[empty_id] = 0
            transport = FakeTransport(paths, gate(monitor_cursors=cursors))
            await collector_for(paths, FakeGateway(paths), transport).run_once()

            self.assertEqual(
                [row for row in transport.monitor_uploads
                 if row["kind"] == "extension_baseline"], [])

    async def test_extension_repairs_the_digest_checkpoint(self):
        """Чекпойнт дайджеста сверяется с набором строгим равенством и
        переписывается только после успешного выпуска. Не дополнив его при
        расширении, мы теряли бы дайджест навсегда."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            atomic_write_json(paths.acknowledged, {
                "schema": "sunny.personal-chats.digest-ack.v1",
                "digest_date": "2026-08-03",
                "cursors": [
                    {"chat_id": chat_id, "through_message_id": 10}
                    for chat_id in CHAT_IDS
                ],
            })
            gateway = FakeGateway(paths)
            gateway.dialogs = [DialogCandidate(
                NEW_CHAT_ID, "Добавленный чат", NEW_PEER)]
            runtime = FakeVPNRuntime(paths.private_dir)
            runtime.ready = True
            collector = collector_for(
                paths, gateway, FakeTransport(paths, self._extended_gate()),
                runtime=runtime)

            await collector.extend_chats("https://t.me/c/3334567890/12")

            acknowledged = read_json(paths.acknowledged)
            order = [row["chat_id"] for row in read_json(paths.settings)["chats"]]
            self.assertEqual(
                [row["chat_id"] for row in acknowledged["cursors"]], order)
            self.assertEqual(
                next(row["through_message_id"] for row in acknowledged["cursors"]
                     if row["chat_id"] == NEW_CHAT_ID), 0)

    async def test_tick_survives_the_window_before_the_chat_is_accepted(self):
        """Окно между `extend_chat_set.sh` и принятием чата в приложении.

        Приёмник уже объявил новый курсор, локально чата ещё нет. Сверка
        позиции цепочки сравнивает КОРТЕЖ курсоров, поэтому вслепую она
        роняла каждый тик — вместе с дайджестом, который к расширению
        отношения не имеет."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            # settings и watch-state ещё СТАРЫЕ: приложение не приняло чат.
            transport = FakeTransport(paths, self._extended_gate())
            status = await collector_for(
                paths, FakeGateway(paths), transport).run_once()

            self.assertNotEqual(status["last_result"], "error")
            self.assertIsNone(status["last_error_type"])
            # Никакого extension baseline: чат ещё не принят приложением.
            self.assertEqual(
                [row for row in transport.monitor_uploads
                 if row["kind"] == "extension_baseline"], [])

    async def test_real_chain_jump_is_still_refused(self):
        """Послабление не должно проглотить настоящий откат цепочки — ради
        него проверка и писалась."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            jumped = gate(monitor_sequence=99, monitor_previous="c" * 64)
            status = await collector_for(
                paths, FakeGateway(paths),
                FakeTransport(paths, jumped)).run_once()

            self.assertEqual(status["last_result"], "error")
            self.assertEqual(status["last_error_type"], "RuntimeError")

    async def test_extension_survives_a_lost_upload_acknowledgement(self):
        """Обрыв между выгрузкой extension baseline и записью состояния.

        Это штатная авария, ради которой существует `monitor_pending`.
        Пока метку снимала только ветка отправки, восстановление ломалось
        навсегда: следующий тик снова считал чат ожидающим и падал на
        несовпадении курсора — то есть исправление делало аварию фатальной."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            settings = read_json(paths.settings)
            settings["chats"] = sorted(
                settings["chats"] + [{
                    "chat_id": NEW_CHAT_ID, "title": "Добавленный чат",
                    "peer": NEW_PEER.as_dict(), "initial_message_id": 0,
                }], key=lambda row: row["chat_id"])
            atomic_write_json(paths.settings, settings)
            order = [row["chat_id"] for row in settings["chats"]]
            watch = read_json(paths.watch_state)
            watch["monitor_cursors"] = collector_module._extended_cursor_rows(
                watch["monitor_cursors"], NEW_CHAT_ID,
                {"chat_id": NEW_CHAT_ID, "through_message_id": 0}, order)
            watch["chats"] = collector_module._extended_cursor_rows(
                watch["chats"], NEW_CHAT_ID,
                {"chat_id": NEW_CHAT_ID, "scan_through_message_id": 0,
                 "read_pending_through_message_id": 0,
                 "read_acked_through_message_id": 0}, order)
            watch["pending_extension_chat_ids"] = [NEW_CHAT_ID]
            atomic_write_json(paths.watch_state, watch)

            gateway = FakeGateway(paths)
            gateway.tops = {**BASELINE_TOPS, NEW_CHAT_ID: 4242}
            gateway.expected_chat_ids = order
            gateway.scans[NEW_CHAT_ID] = MentionScanResult(4242, [])
            transport = FakeTransport(paths, self._extended_gate())
            transport.expected_chat_ids = order
            transport.lose_monitor_ack = True
            collector = collector_for(paths, gateway, transport)

            first = await collector.run_once()
            self.assertEqual(first["last_result"], "error")

            # Приёмник расширение принял, квитанция потеряна — второй тик
            # обязан довести дело до конца, а не встать навсегда.
            accepted = {**BASELINE_TOPS, NEW_CHAT_ID: 4242}
            transport.value = gate(
                monitor_sequence=3, monitor_previous=transport.monitor_uploads[-1][
                    "content_sha256"],
                monitor_cursors={key: accepted[key] for key in order},
                digest_cursors={key: 0 for key in order})
            second = await collector.run_once()

            self.assertNotEqual(second["last_result"], "error")
            watch = read_json(paths.watch_state)
            self.assertNotIn("pending_extension_chat_ids", watch)
            self.assertEqual(
                len([row for row in transport.monitor_uploads
                     if row["kind"] == "extension_baseline"]), 1)


def seed_digest_ack(paths: Paths, *, digest_date: str, cursors,
                    sequence: int = 1, content_sha256: str = "c" * 64):
    atomic_write_json(paths.acknowledged, {
        "schema": collector_module.DIGEST_ACKNOWLEDGED_SCHEMA,
        "source_id": SOURCE_ID,
        "sequence": sequence,
        "content_sha256": content_sha256,
        "digest_date": digest_date,
        "cursors": [
            {"chat_id": chat_id, "through_message_id": cursors[chat_id]}
            for chat_id in CHAT_IDS
        ],
    })


class TestBugDigestExtendedChat20260825(unittest.IsolatedAsyncioTestCase):
    """Выпуск пересказывал историю чата с самого начала.

    Инцидент 21–25.08.2026 («Петровский остров»): чат, добавленный
    расширением, приходит с нулевым курсором посреди живой цепочки. Нижнюю
    временную границу выводил только ПЕРВЫЙ выпуск (`sequence == 1`), поэтому
    такой чат вычитывался от начала истории: пять суточных выпусков подряд
    пересказывали переписку 2023 года, продвигая курсор на бюджет промпта в
    сутки (0 → 454 при вершине чата 8398). Свежие сообщения этого чата в
    выпуск при этом не попадали вовсе.

    Тестов на ВТОРОЙ и последующие выпуски в наборе не было ни одного — все
    проверяли `sequence == 1`, где баг не воспроизводится.
    """

    def _second_issue(self, digest_cursors):
        return gate(
            digest_due=True, digest_sequence=2, digest_previous="c" * 64,
            digest_cursors=digest_cursors,
        )

    async def test_zero_cursor_mid_chain_starts_at_the_window_not_at_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            cursors = {CHAT_IDS[0]: 900, CHAT_IDS[1]: 0}
            seed_digest_ack(paths, digest_date="2026-08-03", cursors=cursors)
            gateway = FakeGateway(paths)
            gateway.boundary = {CHAT_IDS[0]: 880, CHAT_IDS[1]: 8300}
            gateway.fetches = {
                CHAT_IDS[0]: FetchResult(912, [SelectedMessage(905, 7, NOW, "A")]),
                CHAT_IDS[1]: FetchResult(8320, [SelectedMessage(8310, 8, NOW, "B")]),
            }
            transport = FakeTransport(paths, self._second_issue(cursors))

            result = await collector_for(paths, gateway, transport).run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            # Чтение начинается с границы окна, а не с нуля.
            self.assertEqual(
                [call["start"] for call in gateway.fetch_calls], [900, 8300])
            self.assertTrue(all(call["not_before"] == NOW - timedelta(hours=72)
                                for call in gateway.fetch_calls))
            self.assertEqual(
                [call[1] for call in gateway.boundary_calls],
                [NOW - timedelta(hours=72)] * len(CHAT_IDS))
            # А в цепочку по-прежнему уезжает курсор, объявленный приёмником:
            # прыжок вперёд не имеет права выглядеть как разрыв цепочки.
            payload = transport.digest_uploads[0]
            self.assertEqual(
                [row["from_message_id_exclusive"] for row in payload["chat_ranges"]],
                [900, 0])
            self.assertEqual(
                [row["through_message_id"] for row in payload["chat_ranges"]],
                [912, 8320])

    async def test_missed_days_stretch_the_window_instead_of_dropping_them(self):
        """Приложение простаивало 13–16.08.2026 на протухшем адресе узла.

        Жёсткая ретроспектива тихо срезала бы переписку тех суток, поэтому
        окно растягивается ровно на пропущенные дни.
        """
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            cursors = {CHAT_IDS[0]: 900, CHAT_IDS[1]: 700}
            seed_digest_ack(paths, digest_date="2026-07-31", cursors=cursors)
            gateway = FakeGateway(paths)
            gateway.boundary = {CHAT_IDS[0]: 0, CHAT_IDS[1]: 0}
            gateway.fetches = {
                CHAT_IDS[0]: FetchResult(912, [SelectedMessage(905, 7, NOW, "A")]),
                CHAT_IDS[1]: FetchResult(712, [SelectedMessage(705, 8, NOW, "B")]),
            }
            transport = FakeTransport(paths, self._second_issue(cursors))

            result = await collector_for(paths, gateway, transport).run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            expected = NOW - timedelta(hours=72) - timedelta(days=3)
            self.assertTrue(all(call["not_before"] == expected
                                for call in gateway.fetch_calls))
            self.assertEqual(
                [call[1] for call in gateway.boundary_calls],
                [expected] * len(CHAT_IDS))

    async def test_skipped_tail_of_a_live_chat_is_announced_in_the_issue(self):
        """Подтяжка курсора к границе может съесть непрочитанный хвост.

        `fetch` обрывается на бюджете промпта и оставляет остаток суток
        следующему выпуску. Если тот остаток переживёт окно, курсор через
        него перепрыгнет: в wire это не видно вовсе (диапазон объявляется от
        курсора приёмника), в статусе тоже. Поэтому выпуск обязан сказать о
        пропаже вслух — тихий скип и есть худший из отказов.

        У чата, впервые вошедшего в набор (`start == 0`), пропущенное — это
        его прежняя история, и предупреждать не о чем.
        """
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            cursors = {CHAT_IDS[0]: 900, CHAT_IDS[1]: 0}
            seed_digest_ack(paths, digest_date="2026-08-03", cursors=cursors)
            gateway = FakeGateway(paths)
            # Первый чат живой и отстал, второй только вошёл в набор.
            gateway.boundary = {CHAT_IDS[0]: 1500, CHAT_IDS[1]: 8300}
            gateway.fetches = {
                CHAT_IDS[0]: FetchResult(1600, [SelectedMessage(1550, 7, NOW, "A")]),
                CHAT_IDS[1]: FetchResult(8320, [SelectedMessage(8310, 8, NOW, "B")]),
            }
            transport = FakeTransport(paths, self._second_issue(cursors))

            result = await collector_for(paths, gateway, transport).run_once()

            self.assertEqual(result["last_result"], "uploaded_digest")
            self.assertEqual(
                [call["start"] for call in gateway.fetch_calls], [1500, 8300])
            text = transport.digest_uploads[0]["digest"]
            self.assertTrue(text.startswith(DIGEST_SKIP_NOTE_HEAD), text[:120])
            self.assertIn(f"{TITLES[0]}: сообщения 901–1500", text)
            # Про чат, вошедший в набор этим выпуском, предупреждения нет.
            self.assertNotIn(TITLES[1], text.split("\n\n")[0])
            self.assertIn("Общий дайджест", text)

    async def test_first_issue_of_a_chat_announces_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = make_paths(Path(temporary))
            seed_locked(paths, watch_phase="active")
            cursors = {CHAT_IDS[0]: 900, CHAT_IDS[1]: 0}
            seed_digest_ack(paths, digest_date="2026-08-03", cursors=cursors)
            gateway = FakeGateway(paths)
            gateway.boundary = {CHAT_IDS[0]: 880, CHAT_IDS[1]: 8300}
            gateway.fetches = {
                CHAT_IDS[0]: FetchResult(912, [SelectedMessage(905, 7, NOW, "A")]),
                CHAT_IDS[1]: FetchResult(8320, [SelectedMessage(8310, 8, NOW, "B")]),
            }
            transport = FakeTransport(paths, self._second_issue(cursors))

            await collector_for(paths, gateway, transport).run_once()

            self.assertEqual(
                transport.digest_uploads[0]["digest"], "Общий дайджест")
