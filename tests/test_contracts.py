from __future__ import annotations

import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sunny_digest.contracts import (
    build_digest_upload,
    build_monitor_upload,
    canonical_digest_bytes,
    canonical_monitor_bytes,
    content_hash,
    mention_event_id,
    status_request,
    validate_digest_upload,
    validate_gate,
    validate_monitor_upload,
)
from sunny_digest.models import DigestChat, SelectedMessage
from sunny_digest.openrouter import (
    OpenRouterError,
    _blocking_digest,
    _prompt,
    create_digest,
)
from sunny_digest.version import MAX_DIGEST_CHARS


SOURCE_ID = "12345678-1234-4678-9234-567812345678"
CHAT_IDS = [-1_000_000_000_124, -1_000_000_000_123]
NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def gate(*, monitor_sequence: int = 1, monitor_previous=None,
         monitor_cursors=(0, 0), baseline_required: bool = True,
         digest_sequence: int = 1, digest_previous=None,
         digest_cursors=(0, 0), due: bool = True):
    return {
        "schema": "sunny.personal-chats.status-gate.v2",
        "ok": True,
        "server_time": "2026-08-04T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "monitor": {
            "baseline_required": baseline_required,
            "next_sequence": monitor_sequence,
            "previous_sha256": monitor_previous,
            "cursors": [
                {"chat_id": chat_id, "through_message_id": cursor}
                for chat_id, cursor in zip(CHAT_IDS, monitor_cursors)
            ],
            "max_upload_bytes": 32768,
        },
        "digest": {
            "due": due,
            "reason": "due" if due else "before_window",
            "digest_date": "2026-08-04",
            "prepare_not_before": "2026-08-04T03:00:00+03:00",
            "accept_until": "2026-08-04T04:45:00+03:00",
            "next_sequence": digest_sequence,
            "previous_sha256": digest_previous,
            "cursors": [
                {"chat_id": chat_id, "through_message_id": cursor}
                for chat_id, cursor in zip(CHAT_IDS, digest_cursors)
            ],
            "max_upload_bytes": 32768,
        },
    }


def event(chat_id=CHAT_IDS[0], message_id=11):
    return {
        "event_id": mention_event_id(SOURCE_ID, chat_id, message_id),
        "message_id": message_id,
        "date": "2026-08-04T00:29:00Z",
        "chat_title": "Рабочий чат",
        "sender": "Иван",
        "snippet": "@ivan посмотри, пожалуйста",
        "link": f"https://t.me/c/{abs(chat_id) - 1_000_000_000_000}/{message_id}",
    }


class FakeResponse:
    def __init__(self, digest: str):
        self.raw = json.dumps({
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps({"digest": digest})},
            }]
        }).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int):
        return self.raw[:limit]


class FakeWorkerStdin:
    def __init__(self):
        self.data = b""

    def write(self, value):
        self.data += value

    async def drain(self):
        return None

    def close(self):
        return None

    async def wait_closed(self):
        return None


class FakeHungWorker:
    def __init__(self):
        self.stdin = FakeWorkerStdin()
        self.stdout = self
        self.returncode = None
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()
        self.terminated = False

    async def read(self, _limit):
        self.started.set()
        await self.stopped.wait()
        return b""

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stopped.set()

    def kill(self):
        self.terminate()

    async def wait(self):
        await self.stopped.wait()
        return self.returncode


class FakeSlowKillWorker(FakeHungWorker):
    def __init__(self):
        super().__init__()
        self.kill_started = asyncio.Event()
        self.allow_kill_exit = asyncio.Event()
        self.killed = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.kill_started.set()

    async def wait(self):
        if self.killed:
            await self.allow_kill_exit.wait()
            self.returncode = -9
            self.stopped.set()
        await self.stopped.wait()
        return self.returncode


class ContractTests(unittest.TestCase):
    def test_status_v2_binds_exact_sorted_chat_set_and_independent_chains(self):
        value = validate_gate(gate(), CHAT_IDS)
        self.assertTrue(value["monitor"]["baseline_required"])
        self.assertEqual(value["digest"]["next_sequence"], 1)
        request = json.loads(status_request(SOURCE_ID, CHAT_IDS))
        self.assertEqual(set(request), {
            "schema", "source_id", "chat_ids", "collector_version",
        })
        self.assertEqual(request["chat_ids"], CHAT_IDS)
        for bad in (list(reversed(CHAT_IDS)), [], CHAT_IDS + [CHAT_IDS[-1]]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    status_request(SOURCE_ID, bad)

    def test_baseline_is_sequence_one_and_covers_every_remote_cursor(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 20 + index}
            for index, chat_id in enumerate(CHAT_IDS)
        ]
        payload = build_monitor_upload(
            source_id=SOURCE_ID, gate=gate(), kind="baseline",
            ranges=ranges, events=[], generated_at=NOW,
        )
        self.assertEqual(set(payload), {
            "schema", "source_id", "sequence", "previous_sha256", "kind",
            "generated_at", "ranges", "events", "collector_version",
            "content_sha256",
        })
        self.assertEqual(validate_monitor_upload(payload), payload)
        self.assertTrue(canonical_monitor_bytes(payload).endswith(b"\n"))
        for invalid_ranges in (ranges[:1], list(reversed(ranges))):
            with self.subTest(invalid_ranges=invalid_ranges):
                with self.assertRaises(ValueError):
                    build_monitor_upload(
                        source_id=SOURCE_ID, gate=gate(), kind="baseline",
                        ranges=invalid_ranges, events=[], generated_at=NOW,
                    )

    def test_mentions_use_remote_cursor_and_exact_stable_event_id_vector(self):
        # This literal pins sha256(f"{source_id}:{chat_id}:{message_id}").
        self.assertEqual(
            mention_event_id(
                "4d3768cd-07cf-4a59-a177-4ae4e0465aab",
                -1_002_234_567_890,
                103,
            ),
            "953dadfa391d0033c3c03e8bf94e8af82988e97946979bab3a937a7f717c1cd6",
        )
        value = gate(
            monitor_sequence=2, monitor_previous="a" * 64,
            monitor_cursors=(5, 8), baseline_required=False,
        )
        payload = build_monitor_upload(
            source_id=SOURCE_ID, gate=value, kind="mentions",
            ranges=[{
                "chat_id": CHAT_IDS[0],
                "from_message_id_exclusive": 5,
                "through_message_id": 11,
            }],
            events=[event()], generated_at=NOW,
        )
        self.assertEqual(validate_monitor_upload(payload), payload)
        self.assertEqual(set(payload["events"][0]), {
            "event_id", "message_id", "date", "chat_title", "sender",
            "snippet", "link",
        })
        self.assertNotIn("chat_id", payload["events"][0])
        self.assertIn("date", payload["events"][0])
        bad = [dict(payload["events"][0], event_id="0" * 64)]
        with self.assertRaisesRegex(ValueError, "event_id"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=payload["ranges"], events=bad, generated_at=NOW,
            )

    def test_mentions_reject_more_than_ten_and_utf16_over_300(self):
        value = gate(
            monitor_sequence=2, monitor_previous="a" * 64,
            monitor_cursors=(5, 8), baseline_required=False,
        )
        events = [event(message_id=message_id) for message_id in range(6, 17)]
        with self.assertRaisesRegex(ValueError, "mentions upload shape"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=[{"chat_id": CHAT_IDS[0], "from_message_id_exclusive": 5,
                         "through_message_id": 16}],
                events=events, generated_at=NOW,
            )
        oversized = event()
        oversized["snippet"] = "😀" * 151
        with self.assertRaisesRegex(ValueError, "snippet"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=[{"chat_id": CHAT_IDS[0], "from_message_id_exclusive": 5,
                         "through_message_id": 11}],
                events=[oversized], generated_at=NOW,
            )

    def test_mentions_require_sorted_events_and_link_bound_to_chat_kind(self):
        value = gate(
            monitor_sequence=2, monitor_previous="a" * 64,
            monitor_cursors=(5, 8), baseline_required=False,
        )
        mention_range = [{"chat_id": CHAT_IDS[0],
                          "from_message_id_exclusive": 5,
                          "through_message_id": 12}]
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=mention_range,
                events=[event(message_id=12), event(message_id=11)],
                generated_at=NOW,
            )
        wrong_link = event(message_id=11)
        wrong_link["link"] = "https://t.me/c/999/11"
        with self.assertRaisesRegex(ValueError, "supergroup chat_id"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=mention_range, events=[wrong_link], generated_at=NOW,
            )

        legacy = build_monitor_upload(
            source_id=SOURCE_ID, gate=value, kind="mentions",
            ranges=mention_range, events=[event(message_id=11)], generated_at=NOW,
        )
        legacy["ranges"][0]["chat_id"] = -123
        legacy["events"][0].update({
            "event_id": mention_event_id(SOURCE_ID, -123, 11),
            "link": None,
        })
        legacy["content_sha256"] = content_hash({
            key: item for key, item in legacy.items() if key != "content_sha256"
        })
        self.assertEqual(validate_monitor_upload(legacy), legacy)
        legacy["events"][0]["link"] = "https://t.me/c/123/11"
        legacy["content_sha256"] = content_hash({
            key: item for key, item in legacy.items() if key != "content_sha256"
        })
        with self.assertRaisesRegex(ValueError, "legacy group"):
            validate_monitor_upload(legacy)

    def test_digest_requires_complete_sorted_ranges_and_aggregate_count(self):
        ranges = [
            {"chat_id": CHAT_IDS[0], "from_message_id_exclusive": 0,
             "through_message_id": 11, "message_count": 1},
            {"chat_id": CHAT_IDS[1], "from_message_id_exclusive": 0,
             "through_message_id": 20, "message_count": 2},
        ]
        payload = build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="Общий дайджест", model="anthropic/example", generated_at=NOW,
        )
        self.assertEqual(set(payload), {
            "schema", "source_id", "sequence", "previous_sha256",
            "digest_date", "timezone", "generated_at", "cutoff_at",
            "chat_ranges", "total_message_count", "empty", "digest",
            "model", "prompt_version", "collector_version", "content_sha256",
        })
        self.assertTrue(all(set(row) == {
            "chat_id", "from_message_id_exclusive", "through_message_id",
            "message_count",
        } for row in payload["chat_ranges"]))
        self.assertEqual(payload["total_message_count"], 3)
        self.assertEqual(validate_digest_upload(payload), payload)
        self.assertTrue(canonical_digest_bytes(payload).endswith(b"\n"))
        invalid = dict(payload, total_message_count=2)
        with self.assertRaisesRegex(ValueError, "aggregate"):
            validate_digest_upload(invalid)

    def test_digest_boundary_counts_telegram_utf16_units(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 1, "message_count": 1}
            for chat_id in CHAT_IDS
        ]
        accepted = build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="😀" * (MAX_DIGEST_CHARS // 2),
            model="anthropic/example", generated_at=NOW,
        )
        self.assertEqual(len(accepted["digest"].encode("utf-16-le")) // 2,
                         MAX_DIGEST_CHARS)
        with self.assertRaises(ValueError):
            build_digest_upload(
                source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
                digest="😀" * (MAX_DIGEST_CHARS // 2 + 1),
                model="anthropic/example", generated_at=NOW,
            )

    def test_generated_at_hard_limit_is_one_receiver_clock_hour(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 1, "message_count": 1}
            for chat_id in CHAT_IDS
        ]
        build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="Готово", model="anthropic/example",
            generated_at=NOW + timedelta(hours=1),
        )
        with self.assertRaisesRegex(ValueError, "timestamp order"):
            build_digest_upload(
                source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
                digest="Опоздало", model="anthropic/example",
                generated_at=NOW + timedelta(hours=1, seconds=1),
            )

    def test_openrouter_uses_same_3700_boundary(self):
        self.assertIn("at most 3400 UTF-16 code units", _prompt([]))
        with patch("sunny_digest.openrouter.urllib.request.urlopen",
                   return_value=FakeResponse("x" * MAX_DIGEST_CHARS)):
            self.assertEqual(
                len(_blocking_digest([], "anthropic/example", "secret")),
                MAX_DIGEST_CHARS,
            )
        for invalid in ("x" * (MAX_DIGEST_CHARS + 1), "unsafe\u2066text"):
            with patch("sunny_digest.openrouter.urllib.request.urlopen",
                       return_value=FakeResponse(invalid)):
                with self.assertRaises(OpenRouterError):
                    _blocking_digest([], "anthropic/example", "secret")

    def test_openrouter_prompt_pseudonymizes_stable_telegram_ids(self):
        rendered = _prompt([DigestChat("Первый чат", [
            SelectedMessage(987654321, 8675309, NOW, "Первое сообщение"),
            SelectedMessage(987654322, 8675309, NOW, "Второе сообщение"),
            SelectedMessage(987654323, 42424242, NOW, "Третье сообщение"),
        ])])
        self.assertIn('"sender":"participant-1"', rendered)
        self.assertIn('"sender":"participant-2"', rendered)
        for stable_id in ("987654321", "8675309", "42424242"):
            self.assertNotIn(stable_id, rendered)


class TestBugOpenRouterPrivacy20260810(unittest.TestCase):
    def test_every_request_denies_collection_and_requires_zdr(self):
        with patch("sunny_digest.openrouter.urllib.request.urlopen",
                   return_value=FakeResponse("Готово")) as urlopen:
            _blocking_digest([], "anthropic/example", "secret")
        request = urlopen.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(body["provider"], {"zdr": True, "data_collection": "deny"})
        self.assertEqual(request.get_header("User-agent"),
                         "sunny-personal-chats/0.2")
        self.assertEqual(request.get_header("X-title"), "Sunny Personal Chats")


class OpenRouterProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_revocation_terminates_blocking_openrouter_worker_process(self):
        worker = FakeHungWorker()
        revoked = asyncio.Event()
        messages = [DigestChat("Чат", [SelectedMessage(1, 7, NOW, "Текст")])]
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker) as spawn:
            task = asyncio.create_task(create_digest(
                messages, "anthropic/example", "sk-or-test-secret", revoked))
            await asyncio.wait_for(worker.started.wait(), timeout=2)
            revoked.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
        self.assertTrue(worker.terminated)
        self.assertIn(b"sk-or-test-secret", worker.stdin.data)
        self.assertEqual(
            json.loads(worker.stdin.data)["schema"],
            "sunny.personal-chats.openrouter-worker.v2",
        )
        command = " ".join(str(part) for part in spawn.call_args.args)
        self.assertNotIn("sk-or-test-secret", command)
        self.assertNotIn("Текст", command)


class TestBugOpenRouterSecondCancellation20260812(
        unittest.IsolatedAsyncioTestCase):
    """Reset cancellation must not strand a bearer-bearing worker after TERM."""

    async def test_second_cancellation_cannot_interrupt_worker_kill_and_reap(self):
        worker = FakeSlowKillWorker()
        revoked = asyncio.Event()
        messages = [DigestChat("Чат", [SelectedMessage(1, 7, NOW, "Текст")])]
        with patch(
            "sunny_digest.openrouter.asyncio.create_subprocess_exec",
            return_value=worker,
        ), patch(
            "sunny_digest.openrouter.WORKER_TERMINATE_GRACE_S", 0.01,
        ):
            task = asyncio.create_task(create_digest(
                messages, "anthropic/example", "sk-or-test-secret", revoked))
            await worker.started.wait()
            revoked.set()
            while not worker.terminated:
                await asyncio.sleep(0)
            await asyncio.wait_for(worker.kill_started.wait(), timeout=0.5)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            worker.allow_kill_exit.set()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(worker.killed)
        self.assertIsNotNone(worker.returncode)


if __name__ == "__main__":
    unittest.main()
