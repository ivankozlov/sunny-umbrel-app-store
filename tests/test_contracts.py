from __future__ import annotations

import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sunny_digest.contracts import (
    build_upload,
    canonical_upload_bytes,
    validate_gate,
    validate_upload,
)
from sunny_digest.openrouter import (
    OpenRouterError,
    _blocking_digest,
    _prompt,
    create_digest,
)
from sunny_digest.models import SelectedMessage
from sunny_digest.version import MAX_DIGEST_CHARS


SOURCE_ID = "12345678-1234-4678-9234-567812345678"
NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def gate(*, sequence: int = 1, previous=None, day: str = "2026-08-04",
         due: bool = True):
    return {
        "schema": "sunny.personal-digest-gate.v1",
        "ok": True,
        "due": due,
        "reason": "due" if due else "before_window",
        "server_time": "2026-08-04T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "digest_date": day,
        "prepare_not_before": "2026-08-04T03:00:00+03:00",
        "accept_until": "2026-08-04T04:45:00+03:00",
        "next_sequence": sequence,
        "previous_sha256": previous,
        "from_message_id_exclusive": 10,
        "max_upload_bytes": 32768,
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


class ContractTests(unittest.TestCase):
    def test_initial_gate_requires_null_previous_hash(self):
        self.assertIsNone(validate_gate(gate())["previous_sha256"])
        invalid = gate(previous="0" * 64)
        with self.assertRaisesRegex(ValueError, "initial gate"):
            validate_gate(invalid)

    def test_later_gate_requires_hash(self):
        with self.assertRaisesRegex(ValueError, "previous_sha256"):
            validate_gate(gate(sequence=2, previous=None))
        self.assertEqual(
            validate_gate(gate(sequence=2, previous="a" * 64))["previous_sha256"],
            "a" * 64,
        )

    def test_initial_upload_is_canonical_and_uses_remote_plan(self):
        payload = build_upload(
            source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
            through_message_id=12, message_count=2, digest="Готово",
            model="anthropic/example", generated_at=NOW,
        )
        self.assertIsNone(payload["previous_sha256"])
        self.assertEqual(payload["digest_date"], "2026-08-04")
        self.assertEqual(payload["timezone"], "Europe/Istanbul")
        self.assertEqual(payload["cutoff_at"], "2026-08-04T00:30:00Z")
        self.assertEqual(validate_upload(payload), payload)
        self.assertTrue(canonical_upload_bytes(payload).endswith(b"\n"))

    def test_generated_at_hard_limit_is_one_receiver_clock_hour(self):
        accepted = build_upload(
            source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
            through_message_id=11, message_count=1, digest="Готово",
            model="anthropic/example", generated_at=NOW + timedelta(hours=1),
        )
        self.assertEqual(accepted["generated_at"], "2026-08-04T01:30:00Z")
        with self.assertRaisesRegex(ValueError, "timestamp order"):
            build_upload(
                source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
                through_message_id=11, message_count=1, digest="Опоздало",
                model="anthropic/example",
                generated_at=NOW + timedelta(hours=1, seconds=1),
            )

    def test_digest_boundary_and_receiver_control_rules(self):
        payload = build_upload(
            source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
            through_message_id=11, message_count=1,
            digest="x" * MAX_DIGEST_CHARS, model="anthropic/example",
            generated_at=NOW,
        )
        self.assertEqual(len(payload["digest"]), 3700)
        for invalid in (
                "x" * (MAX_DIGEST_CHARS + 1), "ok\rno", "ok\u202eno",
                "ok\x7f", "ok\u0085no", "ok\u200fno"):
            with self.subTest(invalid_length=len(invalid)):
                with self.assertRaises(ValueError):
                    build_upload(
                        source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
                        through_message_id=11, message_count=1, digest=invalid,
                        model="anthropic/example", generated_at=NOW,
                    )

    def test_digest_boundary_counts_telegram_utf16_units(self):
        accepted = build_upload(
            source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
            through_message_id=11, message_count=1,
            digest="😀" * (MAX_DIGEST_CHARS // 2),
            model="anthropic/example", generated_at=NOW,
        )
        self.assertEqual(
            len(accepted["digest"].encode("utf-16-le")) // 2,
            MAX_DIGEST_CHARS,
        )
        for invalid in (
                "😀" * (MAX_DIGEST_CHARS // 2 + 1),
                "😀" * MAX_DIGEST_CHARS,
                "\ud800"):
            with self.subTest(code_points=len(invalid)):
                with self.assertRaises(ValueError):
                    build_upload(
                        source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
                        through_message_id=11, message_count=1, digest=invalid,
                        model="anthropic/example", generated_at=NOW,
                    )

    def test_empty_payload_can_advance_cursor(self):
        payload = build_upload(
            source_id=SOURCE_ID, gate=gate(), chat_id=-100123,
            through_message_id=15, message_count=0, digest="",
            model="anthropic/example", generated_at=NOW,
        )
        self.assertTrue(payload["empty"])
        self.assertEqual(payload["through_message_id"], 15)

    def test_openrouter_uses_same_3700_boundary(self):
        self.assertIn("at most 3400 UTF-16 code units", _prompt([]))
        with patch("sunny_digest.openrouter.urllib.request.urlopen",
                   return_value=FakeResponse("x" * MAX_DIGEST_CHARS)):
            self.assertEqual(
                len(_blocking_digest([], "anthropic/example", "secret")),
                MAX_DIGEST_CHARS,
            )
        for invalid in ("x" * (MAX_DIGEST_CHARS + 1), "unsafe\u2066text"):
            with self.subTest(invalid_length=len(invalid)):
                with patch("sunny_digest.openrouter.urllib.request.urlopen",
                           return_value=FakeResponse(invalid)):
                    with self.assertRaises(OpenRouterError):
                        _blocking_digest([], "anthropic/example", "secret")

    def test_openrouter_prompt_pseudonymizes_stable_telegram_ids(self):
        rendered = _prompt([
            SelectedMessage(987654321, 8675309, NOW, "Первое сообщение"),
            SelectedMessage(987654322, 8675309, NOW, "Второе сообщение"),
            SelectedMessage(987654323, 42424242, NOW, "Третье сообщение"),
        ])
        self.assertIn('"sender":"participant-1"', rendered)
        self.assertIn('"sender":"participant-2"', rendered)
        self.assertNotIn("sender_id", rendered)
        self.assertNotIn("message_id", rendered)
        for stable_id in ("987654321", "8675309", "42424242"):
            self.assertNotIn(stable_id, rendered)


class OpenRouterProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_revocation_terminates_blocking_openrouter_worker_process(self):
        worker = FakeHungWorker()
        revoked = asyncio.Event()
        messages = [SelectedMessage(1, 7, NOW, "Текст")]
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
        command = " ".join(str(part) for part in spawn.call_args.args)
        self.assertNotIn("sk-or-test-secret", command)
        self.assertNotIn("Текст", command)


if __name__ == "__main__":
    unittest.main()
