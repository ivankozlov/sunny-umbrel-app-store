from __future__ import annotations

import asyncio
import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from sunny_digest.models import DigestChat, PeerSpec
from sunny_digest.prompting import prompt_size, render_digest_prompt
from sunny_digest.mihomo import MIHOMO_SOCKS_HOST, MIHOMO_SOCKS_PORT
from sunny_digest.telegram_gateway import (
    MAX_MENTION_EVENTS,
    TelethonGateway,
    parse_message_link,
)
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
        super().__init__(123, "a" * 32, {
            "proxy_type": "socks5", "addr": "127.0.0.1",
            "port": 7891, "rdns": True,
        })
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


class TestBugTelegramMessageLinks20260811(unittest.IsolatedAsyncioTestCase):
    def test_every_real_telethon_client_has_mandatory_loopback_socks(self):
        calls = []

        class TelegramClient:
            def __init__(self, *args, **kwargs):
                calls.append((args, kwargs))

        class StringSession:
            def __init__(self, value):
                self.value = value

        gateway = TelethonGateway(12345, "a" * 32, {
            "proxy_type": "socks5", "addr": MIHOMO_SOCKS_HOST,
            "port": MIHOMO_SOCKS_PORT, "rdns": True,
        })
        gateway._modules = lambda: (
            TelegramClient, None, None, StringSession, None, None, None)

        gateway._client("session")

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["proxy"], {
            "proxy_type": "socks5",
            "addr": MIHOMO_SOCKS_HOST,
            "port": MIHOMO_SOCKS_PORT,
            "rdns": True,
        })
        self.assertNotIn("local_addr", calls[0][1])

    def test_parses_official_public_private_and_forum_links(self):
        self.assertEqual(
            parse_message_link("https://t.me/c/1234567890/42"),
            ("channel", 1234567890),
        )
        self.assertEqual(
            parse_message_link(
                "https://t.me/c/1234567890/7/42?single"),
            ("channel", 1234567890),
        )
        self.assertEqual(
            parse_message_link("https://telegram.me/Example_Group/42?thread=7"),
            ("username", "example_group"),
        )
        self.assertEqual(
            parse_message_link("https://t.me/Example_Group/7/42"),
            ("username", "example_group"),
        )
        self.assertEqual(
            parse_message_link(
                "https://t.me/x/42?single&t=1h23m10s&task=3&option=0JrQvtGC#ignored"),
            ("username", "x"),
        )

    def test_rejects_non_message_spoofed_and_ambiguous_links(self):
        invalid = (
            "http://t.me/c/123/42",
            "https://t.me.evil.example/c/123/42",
            "https://www.t.me/c/123/42",
            "https://t.me./c/123/42",
            "https://ｔ.me/c/123/42",
            "https://user@t.me/c/123/42",
            "https://t.me\\@evil.example/c/123/42",
            "https://t.me:443/c/123/42",
            "https://t.me/+invite",
            "https://t.me/joinchat/invite",
            "https://t.me/c/123",
            "https://t.me/c/123/0",
            "https://t.me/c/0123/42",
            "https://t.me/c/123/042",
            "https://t.me/C/123/42",
            "https://t.me/c/123/2147483648",
            "https://t.me/c/123/1/2/3",
            "https://t.me/example_group",
            "https://t.me/example_group/not-a-message",
            "https://t.me/example_group/42?start=payload",
            "https://t.me/example_group/42?comment=9",
            "https://t.me/example_group/42?single&single",
            "https://t.me/example_group/42?&&",
            "https://t.me/example_group/7/42?thread=7",
            "https://t.me/example_group/42?thread=0",
            "https://t.me/example_group/42?t=1:234",
            "https://t.me/example_group/42?task=0",
            "https://t.me/example_group/42?option=__8",
            "https://t.me/example_group/%34%32",
            "https://t.me/example_group/%2F42",
            "https://t.me/example_group/s/42",
            "https://t.me/share/url?url=https://example.com",
            "https://t.me/boost/example_group",
            "https://t.me/contact/12345",
            "https://t.me/giftcode/12345",
            "https://t.me/call/12345",
            "https://t.me/m/12345",
            "tg://resolve?domain=example_group&post=42",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_message_link(value)

    async def test_resolves_only_accessible_groups_without_fetching_linked_messages(self):
        class InputPeerChannel:
            def __init__(self, channel_id, access_hash):
                self.channel_id = channel_id
                self.access_hash = access_hash

        class InputPeerChat:
            def __init__(self, chat_id):
                self.chat_id = chat_id

        class InputPeerUser:
            pass

        class ResolveUtils:
            @staticmethod
            def get_input_peer(entity):
                return entity.input_peer

        class ResolveClient:
            def __init__(self):
                self.connect_calls = 0
                self.disconnect_calls = 0
                self.iter_calls = []
                self.dialogs = [
                    SimpleNamespace(
                        id=-(1_000_000_000_000 + 1234567890),
                        name="Приватная группа",
                        is_group=True,
                        entity=SimpleNamespace(
                            username=None,
                            usernames=[],
                            input_peer=InputPeerChannel(1234567890, 11),
                        ),
                    ),
                    SimpleNamespace(
                        id=-(1_000_000_000_000 + 777),
                        name="Публичная группа",
                        is_group=True,
                        entity=SimpleNamespace(
                            username="Primary_Name",
                            usernames=[
                                SimpleNamespace(username="Alias_Name", active=True),
                                SimpleNamespace(username="Old_Name", active=False),
                            ],
                            input_peer=InputPeerChannel(777, 22),
                        ),
                    ),
                    SimpleNamespace(
                        id=-(1_000_000_000_000 + 888),
                        name="Broadcast channel",
                        is_group=False,
                        entity=SimpleNamespace(
                            username="broadcast",
                            usernames=[],
                            input_peer=InputPeerChannel(888, 33),
                        ),
                    ),
                    SimpleNamespace(
                        id=-(1_000_000_000_000 + 999),
                        name="Left group",
                        is_group=True,
                        entity=SimpleNamespace(
                            username="left_group",
                            usernames=[],
                            left=True,
                            input_peer=InputPeerChannel(999, 44),
                        ),
                    ),
                ]

            async def connect(self):
                self.connect_calls += 1

            async def disconnect(self):
                self.disconnect_calls += 1

            async def is_user_authorized(self):
                return True

            def iter_dialogs(self, **kwargs):
                self.iter_calls.append(kwargs)

                async def rows():
                    for row in self.dialogs:
                        yield row

                return rows()

        class ResolveGateway(TelethonGateway):
            def __init__(self, client):
                super().__init__(123, "a" * 32, {
                    "proxy_type": "socks5", "addr": "127.0.0.1",
                    "port": 7891, "rdns": True,
                })
                self.client = client

            def _client(self, _session):
                return self.client

            def _modules(self):
                return (
                    None, ResolveUtils, None, None,
                    InputPeerChannel, InputPeerChat, InputPeerUser,
                )

        client = ResolveClient()
        gateway = ResolveGateway(client)
        selected = await gateway.resolve_message_links("session", [
            "https://t.me/c/1234567890/42",
            "https://t.me/Alias_Name/7/43",
        ])
        self.assertEqual(
            [(row.chat_id, row.title) for row in selected],
            [
                (-(1_000_000_000_000 + 1234567890), "Приватная группа"),
                (-(1_000_000_000_000 + 777), "Публичная группа"),
            ],
        )
        self.assertEqual(client.iter_calls, [{"limit": 500}])
        self.assertEqual(client.connect_calls, 1)
        self.assertEqual(client.disconnect_calls, 1)

        with self.assertRaisesRegex(ValueError, "same Telegram group"):
            await gateway.resolve_message_links("session", [
                "https://t.me/Primary_Name/42",
                "https://t.me/c/777/43",
            ])
        with self.assertRaisesRegex(ValueError, "accessible group"):
            await gateway.resolve_message_links(
                "session", ["https://t.me/broadcast/42"])
        with self.assertRaisesRegex(ValueError, "accessible group"):
            await gateway.resolve_message_links(
                "session", ["https://t.me/Old_Name/42"])
        with self.assertRaisesRegex(ValueError, "accessible group"):
            await gateway.resolve_message_links(
                "session", ["https://t.me/left_group/42"])


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


class TestBugPeerTimeoutIsolation20260814(unittest.IsolatedAsyncioTestCase):
    """One hanging peer must become a local failure, not cancel the whole batch."""

    async def test_hung_first_scan_peer_does_not_block_second(self):
        class IsolatingClient(FakeClient):
            async def __call__(self, request):
                requested = request.peers[0].peer
                if requested == -2:
                    await asyncio.Event().wait()
                return SimpleNamespace(dialogs=[
                    SimpleNamespace(peer=requested, top_message=0),
                ])

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        client = IsolatingClient([], upper_id=None)
        with patch(
                "sunny_digest.telegram_gateway.PEER_OPERATION_TIMEOUT_S", 0.01):
            _, scans, failed = await MultiGateway(
                client,
            ).snapshot_and_scan_mentions("session", "source", [
                (-2, PeerSpec("chat", 2, None), "Hung", 0),
                (-1, PeerSpec("chat", 1, None), "Good", 0),
            ])

        self.assertEqual(failed, [-2])
        self.assertEqual(list(scans), [-1])
        self.assertEqual(client.connect_calls, 1)
        self.assertEqual(client.disconnect_calls, 1)

    async def test_many_hung_scan_peers_cannot_starve_healthy_tail(self):
        class IsolatingClient(FakeClient):
            def __init__(self):
                super().__init__([], upper_id=None)
                self.active = 0
                self.max_active = 0

            async def __call__(self, request):
                requested = request.peers[0].peer
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                try:
                    if requested <= -5:
                        await asyncio.Event().wait()
                    return SimpleNamespace(dialogs=[
                        SimpleNamespace(peer=requested, top_message=0),
                    ])
                finally:
                    self.active -= 1

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        selected = [
            (-index, PeerSpec("chat", index, None), f"Chat {index}", 0)
            for index in range(16, 0, -1)
        ]
        client = IsolatingClient()
        with patch(
                "sunny_digest.telegram_gateway.PEER_OPERATION_TIMEOUT_S", 0.02):
            _, scans, failed = await asyncio.wait_for(
                MultiGateway(client).snapshot_and_scan_mentions(
                    "session", "source", selected),
                timeout=0.15,
            )

        self.assertEqual(failed, list(range(-16, -4)))
        self.assertEqual(list(scans), [-4, -3, -2, -1])
        self.assertEqual(client.max_active, 4)
        self.assertEqual(client.disconnect_calls, 1)

    async def test_hung_first_read_ack_does_not_block_second(self):
        class IsolatingClient(FakeClient):
            async def send_read_acknowledge(self, peer, **kwargs):
                self.read_ack_calls.append((peer, kwargs))
                if peer == -2:
                    await asyncio.Event().wait()
                return True

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        client = IsolatingClient([], upper_id=None)
        with patch(
                "sunny_digest.telegram_gateway.PEER_OPERATION_TIMEOUT_S", 0.01):
            succeeded, failed = await MultiGateway(client).acknowledge_reads(
                "session", [
                    (-2, PeerSpec("chat", 2, None), 20),
                    (-1, PeerSpec("chat", 1, None), 10),
                ],
            )

        self.assertEqual(succeeded, [-1])
        self.assertEqual(failed, [-2])
        self.assertEqual([row[0] for row in client.read_ack_calls], [-2, -1])
        self.assertEqual(client.connect_calls, 1)
        self.assertEqual(client.disconnect_calls, 1)

    async def test_many_hung_read_acks_cannot_starve_healthy_tail(self):
        class IsolatingClient(FakeClient):
            def __init__(self):
                super().__init__([], upper_id=None)
                self.active = 0
                self.max_active = 0

            async def send_read_acknowledge(self, peer, **kwargs):
                self.read_ack_calls.append((peer, kwargs))
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                try:
                    if peer <= -5:
                        await asyncio.Event().wait()
                    return True
                finally:
                    self.active -= 1

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        targets = [
            (-index, PeerSpec("chat", index, None), index)
            for index in range(16, 0, -1)
        ]
        client = IsolatingClient()
        with patch(
                "sunny_digest.telegram_gateway.PEER_OPERATION_TIMEOUT_S", 0.02):
            succeeded, failed = await asyncio.wait_for(
                MultiGateway(client).acknowledge_reads("session", targets),
                timeout=0.15,
            )

        self.assertEqual(failed, list(range(-16, -4)))
        self.assertEqual(succeeded, [-4, -3, -2, -1])
        self.assertEqual(client.max_active, 4)
        self.assertEqual(client.disconnect_calls, 1)

    async def test_cancelled_scan_batch_joins_siblings_before_disconnect(self):
        class CancellingClient(FakeClient):
            def __init__(self):
                super().__init__([], upper_id=None)
                self.started = asyncio.Event()
                self.started_count = 0
                self.cancelled = []

            async def __call__(self, request):
                requested = request.peers[0].peer
                self.started_count += 1
                if self.started_count == 2:
                    self.started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    self.cancelled.append(requested)
                    raise

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        client = CancellingClient()
        task = asyncio.create_task(
            MultiGateway(client).snapshot_and_scan_mentions(
                "session", "source", [
                    (-2, PeerSpec("chat", 2, None), "Two", 0),
                    (-1, PeerSpec("chat", 1, None), "One", 0),
                ],
            ),
        )
        await asyncio.wait_for(client.started.wait(), timeout=0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(sorted(client.cancelled), [-2, -1])
        self.assertEqual(client.disconnect_calls, 1)

    async def test_cancelled_ack_batch_joins_siblings_before_disconnect(self):
        class CancellingClient(FakeClient):
            def __init__(self):
                super().__init__([], upper_id=None)
                self.started = asyncio.Event()
                self.started_count = 0
                self.cancelled = []

            async def send_read_acknowledge(self, peer, **kwargs):
                self.read_ack_calls.append((peer, kwargs))
                self.started_count += 1
                if self.started_count == 2:
                    self.started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    self.cancelled.append(peer)
                    raise

        class MultiGateway(GatewayUnderTest):
            def _input_peer(self, peer):
                return peer.telegram_chat_id()

        client = CancellingClient()
        task = asyncio.create_task(MultiGateway(client).acknowledge_reads(
            "session", [
                (-2, PeerSpec("chat", 2, None), 20),
                (-1, PeerSpec("chat", 1, None), 10),
            ],
        ))
        await asyncio.wait_for(client.started.wait(), timeout=0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(sorted(client.cancelled), [-2, -1])
        self.assertEqual(client.disconnect_calls, 1)

    async def test_cancelled_connect_still_disconnects_partial_client(self):
        class ConnectingClient(FakeClient):
            def __init__(self):
                super().__init__([], upper_id=None)
                self.connect_started = asyncio.Event()

            async def connect(self):
                self.connect_calls += 1
                self.connected = True
                self.connect_started.set()
                await asyncio.Event().wait()

        client = ConnectingClient()
        task = asyncio.create_task(GatewayUnderTest(
            client,
        ).snapshot_and_scan_mentions("session", "source", [
            (CHAT_ID, PeerSpec("channel", 100123, 998877), "Chat", 0),
        ]))
        await asyncio.wait_for(client.connect_started.wait(), timeout=0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(client.disconnect_calls, 1)
        self.assertFalse(client.connected)

    async def test_repeated_cancel_waits_for_disconnect_to_finish(self):
        class SlowDisconnectClient(FakeClient):
            def __init__(self):
                super().__init__([], upper_id=None)
                self.disconnect_started = asyncio.Event()
                self.allow_disconnect = asyncio.Event()

            def disconnect(self):
                self.disconnect_calls += 1
                self.disconnect_started.set()

                async def finish():
                    await self.allow_disconnect.wait()
                    self.connected = False

                return asyncio.shield(asyncio.create_task(finish()))

        client = SlowDisconnectClient()
        task = asyncio.create_task(GatewayUnderTest(
            client,
        ).snapshot_and_scan_mentions("session", "source", [
            (CHAT_ID, PeerSpec("channel", 100123, 998877), "Chat", 0),
        ]))
        await asyncio.wait_for(client.disconnect_started.wait(), timeout=0.1)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        client.allow_disconnect.set()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(client.disconnect_calls, 1)
        self.assertFalse(client.connected)


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
