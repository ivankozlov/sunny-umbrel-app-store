from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sunny_digest.models import PeerSpec
from sunny_digest.prompting import prompt_size
from sunny_digest.telegram_gateway import TelethonGateway
from sunny_digest.version import MAX_PROMPT_BYTES, MAX_SCAN_MESSAGES


CHAT_ID = -1_000_000_100_123
CUTOFF = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def message(message_id: int, *, text: str | None = None,
            sent_at: datetime = CUTOFF):
    return SimpleNamespace(
        id=message_id,
        peer_id=CHAT_ID,
        message=text if text is not None else f"message-{message_id}",
        date=sent_at,
        sender_id=7,
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
        self.connected = False

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def is_user_authorized(self):
        return True

    async def get_messages(self, peer, **kwargs):
        self.get_calls.append((peer, kwargs))
        return [] if self.upper_id is None else [message(self.upper_id)]

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
        if peer != PeerSpec("channel", 100123, 998877):
            raise AssertionError("unexpected peer")
        return "exact-input-peer"

    def _modules(self):
        return (None, FakeUtils, None, None, None, None, None)


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
