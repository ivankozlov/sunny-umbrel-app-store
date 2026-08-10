from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sunny_digest.models import DigestChat, PeerSpec
from sunny_digest.prompting import prompt_size, render_digest_prompt
from sunny_digest.telegram_gateway import MAX_MENTION_EVENTS, TelethonGateway
from sunny_digest.version import MAX_PROMPT_BYTES, MAX_SCAN_MESSAGES


CHAT_ID = -1_000_000_100_123
CUTOFF = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def message(message_id: int, *, text: str | None = None,
            sent_at: datetime = CUTOFF, mentioned: bool = False,
            sender=None, post_author: str | None = None):
    return SimpleNamespace(
        id=message_id,
        peer_id=CHAT_ID,
        message=text if text is not None else f"message-{message_id}",
        date=sent_at,
        sender_id=7,
        sender=sender,
        post_author=post_author,
        mentioned=mentioned,
    )


class FakeUtils:
    @staticmethod
    def get_peer_id(peer_id):
        return peer_id


class FakeClient:
    def __init__(self, all_messages, upper_id):
        self.all_messages = all_messages
        self.upper_id = upper_id
        self.get_calls = []
        self.iter_calls = []
        self.raw_calls = []
        self.read_ack_calls = []
        self.connected = False
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.peer_dialogs = []

    async def connect(self):
        self.connect_calls += 1
        self.connected = True

    async def disconnect(self):
        self.disconnect_calls += 1
        self.connected = False

    async def is_user_authorized(self):
        return True

    async def get_messages(self, peer, **kwargs):
        self.get_calls.append((peer, kwargs))
        return [] if self.upper_id is None else [message(self.upper_id)]

    async def __call__(self, request):
        self.raw_calls.append(request)
        return SimpleNamespace(dialogs=self.peer_dialogs)

    async def send_read_acknowledge(self, peer, **kwargs):
        self.read_ack_calls.append((peer, kwargs))
        return True

    def iter_messages(self, peer, **kwargs):
        self.iter_calls.append((peer, kwargs))

        async def rows():
            selected = [
                row for row in self.all_messages
                if kwargs["min_id"] < row.id < kwargs["max_id"]
            ]
            selected.sort(key=lambda row: row.id)
            for row in selected[:kwargs["limit"]]:
                yield row

        return rows()


class GatewayUnderTest(TelethonGateway):
    def __init__(self, client):
        super().__init__(123, "a" * 32)
        self.fake_client = client

    def _client(self, _session):
        return self.fake_client

    def _input_peer(self, peer):
        if peer == PeerSpec("channel", 100123, 998877):
            return "exact-input-peer"
        if peer == PeerSpec("chat", 321, None):
            return "exact-legacy-peer"
        raise AssertionError("unexpected peer")

    def _modules(self):
        return (None, FakeUtils, None, None, None, None, None)

    def _peer_dialog_modules(self):
        class InputDialogPeer:
            def __init__(self, peer):
                self.peer = peer

        class GetPeerDialogsRequest:
            def __init__(self, peers):
                self.peers = peers

        return InputDialogPeer, GetPeerDialogsRequest


class TelegramFetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_bootstrap_cursor_is_exact_peer_and_strictly_before_boundary(self):
        client = FakeClient([], upper_id=5)
        gateway = GatewayUnderTest(client)
        now = CUTOFF.replace(second=1) + timedelta(hours=72)
        self.assertEqual(
            await gateway.bootstrap_cursor(
                "session", PeerSpec("channel", 100123, 998877), now),
            5,
        )
        client.upper_id = 6
        original = client.get_messages

        async def wrong_peer(peer, **kwargs):
            rows = await original(peer, **kwargs)
            rows[0].peer_id = -999
            return rows

        client.get_messages = wrong_peer
        with self.assertRaisesRegex(RuntimeError, "unexpected peer"):
            await gateway.bootstrap_cursor(
                "session", PeerSpec("channel", 100123, 998877), now)

    async def test_cursor_zero_uses_explicit_cutoff_id_window(self):
        client = FakeClient([message(i) for i in range(1, 8)], upper_id=5)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 0, CUTOFF)
        self.assertEqual([row.message_id for row in result.messages], [1, 2, 3, 4, 5])
        self.assertEqual(result.through_message_id, 5)
        self.assertEqual(client.get_calls[0][1], {"limit": 1, "offset_date": CUTOFF})
        self.assertEqual(client.iter_calls[0][1], {
            "min_id": 0, "max_id": 6, "reverse": True,
            "limit": MAX_SCAN_MESSAGES,
        })
        self.assertNotIn("offset_date", client.iter_calls[0][1])

    async def test_messages_after_cutoff_are_not_viewed(self):
        client = FakeClient([message(i) for i in range(1, 8)], upper_id=5)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 3, CUTOFF)
        self.assertEqual([row.message_id for row in result.messages], [4, 5])
        self.assertEqual(result.through_message_id, 5)

    async def test_bounded_scan_advances_only_to_last_fully_viewed_id(self):
        total = MAX_SCAN_MESSAGES + 5
        client = FakeClient(
            [message(i, text="") for i in range(1, total + 1)], upper_id=total)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 0, CUTOFF)
        self.assertEqual(result.messages, [])
        self.assertEqual(result.through_message_id, MAX_SCAN_MESSAGES)

    async def test_no_message_at_cutoff_does_not_iterate(self):
        client = FakeClient([], upper_id=None)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 10, CUTOFF)
        self.assertEqual(result.through_message_id, 10)
        self.assertEqual(result.messages, [])
        self.assertEqual(client.iter_calls, [])

    async def test_prompt_budget_stops_before_unincluded_text_and_resumes(self):
        rows = [message(i, text="я" * 4096) for i in range(1, 40)]
        client = FakeClient(rows, upper_id=39)
        gateway = GatewayUnderTest(client)
        first = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 0, CUTOFF)
        self.assertGreater(len(first.messages), 0)
        self.assertLess(first.through_message_id, 39)
        self.assertLessEqual(prompt_size(first.messages), MAX_PROMPT_BYTES)

        second = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            first.through_message_id, CUTOFF)
        self.assertEqual(second.messages[0].message_id, first.through_message_id + 1)
        self.assertLessEqual(prompt_size(second.messages), MAX_PROMPT_BYTES)

    async def test_one_oversized_row_is_deterministically_truncated(self):
        client = FakeClient([message(1, text="я" * 100_000)], upper_id=1)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 0, CUTOFF)
        self.assertEqual(result.through_message_id, 1)
        self.assertEqual(len(result.messages), 1)
        self.assertTrue(result.messages[0].text.endswith("[обрезано]"))
        self.assertLessEqual(prompt_size(result.messages), MAX_PROMPT_BYTES)

    async def test_per_chat_prompt_budget_stops_before_omitted_text(self):
        budget = 2_000
        rows = [message(i, text="я" * 500) for i in range(1, 8)]
        client = FakeClient(rows, upper_id=7)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            0, CUTOFF, max_prompt_bytes=budget,
        )
        self.assertGreater(len(result.messages), 0)
        self.assertLess(result.through_message_id, 7)
        self.assertLessEqual(prompt_size(result.messages), budget)
        with self.assertRaisesRegex(ValueError, "prompt budget"):
            await gateway.fetch(
                "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
                0, CUTOFF, max_prompt_bytes=MAX_PROMPT_BYTES + 1,
            )
        self.assertFalse(client.connected)

    async def test_long_titles_are_counted_byte_identically_in_combined_budget(self):
        title = "Ч" * 160
        budget = MAX_PROMPT_BYTES // 2
        rows = [message(i, text="данные " * 300) for i in range(1, 100)]
        first = await GatewayUnderTest(FakeClient(rows, upper_id=99)).fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 0,
            CUTOFF, max_prompt_bytes=budget, chat_title=title,
        )
        second = await GatewayUnderTest(FakeClient(rows, upper_id=99)).fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID, 0,
            CUTOFF, max_prompt_bytes=budget, chat_title=title,
        )
        self.assertLessEqual(prompt_size(first.messages, title), budget)
        combined = render_digest_prompt([
            DigestChat(title, first.messages), DigestChat(title, second.messages),
        ])
        self.assertLessEqual(len(combined.encode("utf-8")), MAX_PROMPT_BYTES)


class TelegramMonitorTests(unittest.IsolatedAsyncioTestCase):
    async def test_snapshot_tops_uses_only_exact_peer_dialog_request(self):
        client = FakeClient([], upper_id=None)
        client.peer_dialogs = [
            SimpleNamespace(peer=CHAT_ID, top_message=42),
            SimpleNamespace(peer=-321, top_message=7),
        ]
        gateway = GatewayUnderTest(client)
        tops = await gateway.snapshot_tops("session", [
            (CHAT_ID, PeerSpec("channel", 100123, 998877)),
            (-321, PeerSpec("chat", 321, None)),
        ])
        self.assertEqual(tops, {CHAT_ID: 42, -321: 7})
        self.assertEqual(len(client.raw_calls), 1)
        self.assertEqual(
            [item.peer for item in client.raw_calls[0].peers],
            ["exact-input-peer", "exact-legacy-peer"],
        )
        self.assertEqual(client.get_calls, [])
        self.assertEqual(client.iter_calls, [])

    async def test_snapshot_tops_fails_closed_on_missing_or_unexpected_peer(self):
        client = FakeClient([], upper_id=None)
        gateway = GatewayUnderTest(client)
        selected = [(CHAT_ID, PeerSpec("channel", 100123, 998877))]
        with self.assertRaisesRegex(RuntimeError, "exact selected peer set"):
            await gateway.snapshot_tops("session", selected)
        client.peer_dialogs = [SimpleNamespace(peer=-999, top_message=42)]
        with self.assertRaisesRegex(RuntimeError, "unexpected peer"):
            await gateway.snapshot_tops("session", selected)

    async def test_scan_is_oldest_first_native_mentions_and_deterministic(self):
        sender = SimpleNamespace(first_name="Иван", last_name="Петров", title=None,
                                 username="ivan")
        rows = [
            message(11, text="plain @text", mentioned=False, sender=sender),
            message(12, text="native", mentioned=True, sender=sender),
            message(13, text="also native", mentioned=True, sender=None,
                    post_author="Редактор"),
        ]
        client = FakeClient(rows, upper_id=None)
        gateway = GatewayUnderTest(client)
        result = await gateway.scan_mentions(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            "Рабочий чат", "source-1", 10, 13,
        )
        self.assertEqual([event.message_id for event in result.events], [12, 13])
        self.assertEqual(result.through_message_id, 13)
        self.assertEqual(result.events[0].sender, "Иван Петров")
        self.assertEqual(result.events[1].sender, "Редактор")
        self.assertEqual(result.events[0].link, "https://t.me/c/100123/12")
        self.assertEqual(
            result.events[0].event_id,
            hashlib.sha256(f"source-1:{CHAT_ID}:12".encode()).hexdigest(),
        )
        self.assertEqual(client.iter_calls[0][1], {
            "min_id": 10, "max_id": 14, "reverse": True,
            "limit": MAX_SCAN_MESSAGES,
        })

    async def test_scan_finds_mentions_already_read_elsewhere(self):
        row = message(11, mentioned=True)
        row.unread = False
        client = FakeClient([row], upper_id=None)
        result = await GatewayUnderTest(client).scan_mentions(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            "Chat", "source", 10, 11,
        )
        self.assertEqual([event.message_id for event in result.events], [11])

    async def test_eleventh_mention_is_not_crossed_and_resumes(self):
        rows = [message(i, mentioned=True) for i in range(1, 13)]
        client = FakeClient(rows, upper_id=None)
        gateway = GatewayUnderTest(client)
        first = await gateway.scan_mentions(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            "Chat", "source", 0, 12,
        )
        self.assertEqual(len(first.events), MAX_MENTION_EVENTS)
        self.assertEqual(first.through_message_id, 10)
        second = await gateway.scan_mentions(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            "Chat", "source", first.through_message_id, 12,
        )
        self.assertEqual([event.message_id for event in second.events], [11, 12])
        self.assertEqual(second.through_message_id, 12)

    async def test_scan_sanitizes_snippet_by_utf16_and_never_downloads_media(self):
        row = message(1, text="one\ntwo\u202e\x00  " + "😀" * 200, mentioned=True)
        row.photo = object()

        async def forbidden_download(*_args, **_kwargs):
            raise AssertionError("media must not be downloaded")

        row.download_media = forbidden_download
        client = FakeClient([row], upper_id=None)
        result = await GatewayUnderTest(client).scan_mentions(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            "Chat", "source", 0, 1,
        )
        snippet = result.events[0].snippet
        self.assertTrue(snippet.startswith("one two "))
        self.assertNotIn("\u202e", snippet)
        self.assertNotIn("\x00", snippet)
        self.assertLessEqual(sum(2 if ord(char) > 0xFFFF else 1 for char in snippet), 300)

    async def test_legacy_chat_has_no_link_and_sender_falls_back(self):
        row = message(1, mentioned=True)
        row.peer_id = -321
        row.sender = None
        row.post_author = None
        client = FakeClient([row], upper_id=None)
        result = await GatewayUnderTest(client).scan_mentions(
            "session", PeerSpec("chat", 321, None), -321,
            "Legacy", "source", 0, 1,
        )
        self.assertIsNone(result.events[0].link)
        self.assertEqual(result.events[0].sender, "Неизвестный отправитель")

    async def test_scan_rejects_wrong_peer_and_never_crosses_frozen_top(self):
        rows = [message(1, mentioned=True), message(2, mentioned=True)]
        rows[0].peer_id = -999
        client = FakeClient(rows, upper_id=None)
        gateway = GatewayUnderTest(client)
        with self.assertRaisesRegex(RuntimeError, "unexpected peer"):
            await gateway.scan_mentions(
                "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
                "Chat", "source", 0, 1,
            )
        self.assertEqual(client.iter_calls[0][1]["max_id"], 2)

    async def test_exact_read_ack_uses_max_id_and_clear_mentions(self):
        client = FakeClient([], upper_id=None)
        gateway = GatewayUnderTest(client)
        await gateway.acknowledge_read(
            "session", PeerSpec("channel", 100123, 998877), 42)
        self.assertEqual(client.read_ack_calls, [(
            "exact-input-peer", {"max_id": 42, "clear_mentions": True},
        )])

    async def test_ten_chat_tick_uses_one_scan_and_one_read_connection(self):
        class MultiClient(FakeClient):
            async def __call__(self, request):
                self.raw_calls.append(request)
                requested = request.peers[0].peer
                return SimpleNamespace(dialogs=[
                    SimpleNamespace(peer=requested, top_message=0),
                ])

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        client = MultiClient([], upper_id=None)
        gateway = MultiGateway(client)
        selected = [
            (-index, PeerSpec("chat", index, None), f"Chat {index}", 0)
            for index in range(10, 0, -1)
        ]
        _, scans, failed = await gateway.snapshot_and_scan_mentions(
            "session", "source", selected)
        self.assertEqual(failed, [])
        self.assertEqual(len(scans), 10)
        acknowledgements = [
            (chat_id, peer, 0) for chat_id, peer, _, _ in selected
        ]
        succeeded, failed = await gateway.acknowledge_reads(
            "session", acknowledgements)
        self.assertEqual(succeeded, [row[0] for row in selected])
        self.assertEqual(failed, [])
        self.assertEqual(client.connect_calls, 2)
        self.assertEqual(client.disconnect_calls, 2)

    async def test_broken_first_peer_does_not_block_second_in_same_scan_connection(self):
        class IsolatingClient(FakeClient):
            async def __call__(self, request):
                requested = request.peers[0].peer
                if requested == -2:
                    raise RuntimeError("stale access hash")
                return SimpleNamespace(dialogs=[
                    SimpleNamespace(peer=requested, top_message=0),
                ])

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        client = IsolatingClient([], upper_id=None)
        _, scans, failed = await MultiGateway(client).snapshot_and_scan_mentions(
            "session", "source", [
                (-2, PeerSpec("chat", 2, None), "Broken", 0),
                (-1, PeerSpec("chat", 1, None), "Good", 0),
            ])
        self.assertEqual(failed, [-2])
        self.assertEqual(list(scans), [-1])
        self.assertEqual(client.connect_calls, 1)


class TestBugTrustedLookback20260810(unittest.IsolatedAsyncioTestCase):
    """The first fetch excludes rows older than the trusted 72-hour boundary."""

    async def test_first_fetch_excludes_before_boundary_and_includes_boundary(self):
        boundary = CUTOFF - timedelta(hours=72)
        rows = [
            message(5, sent_at=boundary - timedelta(seconds=1)),
            message(6, sent_at=boundary - timedelta(microseconds=1)),
            message(7, sent_at=boundary),
            message(8, sent_at=boundary + timedelta(seconds=1)),
        ]
        client = FakeClient(rows, upper_id=8)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            5, CUTOFF, not_before_at=boundary,
        )
        self.assertEqual([row.message_id for row in result.messages], [7, 8])
        self.assertEqual(result.through_message_id, 8)
        self.assertEqual(client.iter_calls[0][1]["min_id"], 5)

    async def test_old_rows_after_cursor_advance_without_reaching_prompt(self):
        boundary = CUTOFF - timedelta(hours=72)
        client = FakeClient([
            message(6, sent_at=boundary - timedelta(microseconds=1)),
        ], upper_id=6)
        gateway = GatewayUnderTest(client)
        result = await gateway.fetch(
            "session", PeerSpec("channel", 100123, 998877), CHAT_ID,
            5, CUTOFF, not_before_at=boundary,
        )
        self.assertEqual(result.messages, [])
        self.assertEqual(result.through_message_id, 6)


if __name__ == "__main__":
    unittest.main()
