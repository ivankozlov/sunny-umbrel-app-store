from __future__ import annotations

import asyncio
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sunny_digest.telegram_probe import (
    MAX_WORKER_RESPONSE_BYTES,
    WORKER_SCHEMA,
    TelegramProbeError,
    probe_telegram_session,
)
from sunny_digest import telegram_probe_worker


class FakeStdin:
    def __init__(self):
        self.data = b""

    def write(self, value):
        self.data += value

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        return None

    async def wait_closed(self):
        return None


class FakeStdout:
    def __init__(self, value: bytes):
        self.value = value
        self.offset = 0

    async def read(self, limit):
        await asyncio.sleep(0)
        chunk = self.value[self.offset:self.offset + limit]
        self.offset += len(chunk)
        return chunk


class FakeWorker:
    def __init__(self, response: bytes, returncode=0):
        self.stdin = FakeStdin()
        self.stdout = FakeStdout(response)
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.wait_count = 0

    async def wait(self):
        self.wait_count += 1
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class HungStdout:
    def __init__(self, stopped: asyncio.Event):
        self.started = asyncio.Event()
        self.stopped = stopped

    async def read(self, _limit):
        self.started.set()
        await self.stopped.wait()
        return b""


class HungWorker(FakeWorker):
    def __init__(self):
        super().__init__(b"", returncode=None)
        self.stopped = asyncio.Event()
        self.stdout = HungStdout(self.stopped)

    async def wait(self):
        self.wait_count += 1
        await self.stopped.wait()
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stopped.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stopped.set()


class KillOnlyWorker(HungWorker):
    def __init__(self):
        super().__init__()
        self.terminate_started = asyncio.Event()

    def terminate(self):
        self.terminated = True
        self.terminate_started.set()


class RevokingWorker(FakeWorker):
    def __init__(self, revoked: asyncio.Event):
        super().__init__(b'{"authorized":true}\n')
        self.revoked = revoked

    async def wait(self):
        self.wait_count += 1
        self.revoked.set()
        return self.returncode


class TelegramProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_secrets_travel_only_over_worker_stdin(self):
        secret_hash = "a" * 32
        secret_session = "secret-string-session"
        worker = FakeWorker(b'{"authorized":true}\n')
        create = AsyncMock(return_value=worker)

        with patch(
            "sunny_digest.telegram_probe.asyncio.create_subprocess_exec", create,
        ):
            authorized = await probe_telegram_session(
                12345, secret_hash, secret_session, asyncio.Event())

        self.assertTrue(authorized)
        self.assertEqual(json.loads(worker.stdin.data), {
            "schema": WORKER_SCHEMA,
            "api_id": 12345,
            "api_hash": secret_hash,
            "session": secret_session,
        })
        command = " ".join(str(part) for part in create.await_args.args)
        self.assertNotIn(secret_hash, command)
        self.assertNotIn(secret_session, command)
        self.assertNotIn(secret_hash, repr(create.await_args.kwargs))
        self.assertNotIn(secret_session, repr(create.await_args.kwargs))
        self.assertEqual(
            create.await_args.args[-2:],
            ("-m", "sunny_digest.telegram_probe_worker"),
        )

    async def test_false_and_malformed_worker_responses_fail_closed(self):
        for response, expected in (
            (b'{"authorized":false}\n', False),
            (b'{"authorized":"yes"}\n', TelegramProbeError),
            (b'secret-string-session\n', TelegramProbeError),
            (b' {"authorized":true}\n', TelegramProbeError),
            (b'{"authorized":true}\n\n', TelegramProbeError),
        ):
            with self.subTest(response=response):
                worker = FakeWorker(response)
                with patch(
                    "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
                    AsyncMock(return_value=worker),
                ):
                    if expected is False:
                        self.assertFalse(await probe_telegram_session(
                            12345, "a" * 32, "session", asyncio.Event()))
                    else:
                        with self.assertRaises(TelegramProbeError) as raised:
                            await probe_telegram_session(
                                12345, "a" * 32, "session", asyncio.Event())
                        self.assertNotIn("secret-string-session", str(raised.exception))

    async def test_cancellation_terminates_and_reaps_secret_worker(self):
        worker = HungWorker()
        with patch(
            "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            task = asyncio.create_task(probe_telegram_session(
                12345, "a" * 32, "session", asyncio.Event()))
            await worker.stdout.started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(worker.terminated)
        self.assertGreaterEqual(worker.wait_count, 1)

    async def test_internal_timeout_escalates_to_kill_and_reaps_worker(self):
        worker = KillOnlyWorker()
        with (
            patch(
                "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
                AsyncMock(return_value=worker),
            ),
            patch("sunny_digest.telegram_probe.WORKER_TIMEOUT_S", 0.01),
            patch("sunny_digest.telegram_probe.WORKER_TERMINATE_GRACE_S", 0.01),
        ):
            with self.assertRaises(TelegramProbeError) as raised:
                await probe_telegram_session(
                    12345, "a" * 32, "secret-session", asyncio.Event())

        self.assertEqual(str(raised.exception),
                         "Telegram authorization probe timed out")
        self.assertNotIn("secret-session", str(raised.exception))
        self.assertTrue(worker.terminated)
        self.assertTrue(worker.killed)
        self.assertTrue(worker.stopped.is_set())
        self.assertGreaterEqual(worker.wait_count, 2)

    async def test_revocation_wins_when_worker_finishes_same_turn(self):
        revoked = asyncio.Event()
        worker = RevokingWorker(revoked)
        with patch(
            "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await probe_telegram_session(
                    12345, "a" * 32, "secret-session", revoked)

        self.assertTrue(worker.terminated)
        self.assertGreaterEqual(worker.wait_count, 1)

    async def test_revocation_after_wait_snapshot_still_wins(self):
        revoked = asyncio.Event()
        worker = FakeWorker(b'{"authorized":true}\n')
        real_wait = asyncio.wait

        async def wait_then_revoke(*args, **kwargs):
            result = await real_wait(*args, **kwargs)
            revoked.set()
            return result

        with (
            patch(
                "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
                AsyncMock(return_value=worker),
            ),
            patch(
                "sunny_digest.telegram_probe.asyncio.wait",
                side_effect=wait_then_revoke,
            ),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await probe_telegram_session(
                    12345, "a" * 32, "secret-session", revoked)

        self.assertTrue(worker.terminated)
        self.assertGreaterEqual(worker.wait_count, 1)

    async def test_oversized_stdout_is_bounded_and_worker_is_reaped(self):
        worker = FakeWorker(b"x" * (MAX_WORKER_RESPONSE_BYTES + 1))
        with patch(
            "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            with self.assertRaises(TelegramProbeError) as raised:
                await probe_telegram_session(
                    12345, "a" * 32, "secret-session", asyncio.Event())

        self.assertEqual(
            str(raised.exception),
            "Telegram probe worker response is oversized",
        )
        self.assertNotIn("secret-session", str(raised.exception))
        self.assertTrue(worker.terminated)
        self.assertGreaterEqual(worker.wait_count, 1)
        self.assertEqual(worker.stdout.offset, MAX_WORKER_RESPONSE_BYTES + 1)

    async def test_nonzero_worker_exit_is_redacted_and_reaped(self):
        worker = FakeWorker(b"secret-session\n", returncode=7)
        with patch(
            "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            with self.assertRaises(TelegramProbeError) as raised:
                await probe_telegram_session(
                    12345, "a" * 32, "secret-session", asyncio.Event())

        self.assertEqual(
            str(raised.exception), "Telegram authorization probe failed")
        self.assertNotIn("secret-session", str(raised.exception))
        self.assertTrue(worker.terminated)
        self.assertGreaterEqual(worker.wait_count, 2)

    async def test_repeated_cancellation_cannot_interrupt_kill_and_reap(self):
        worker = KillOnlyWorker()
        with (
            patch(
                "sunny_digest.telegram_probe.asyncio.create_subprocess_exec",
                AsyncMock(return_value=worker),
            ),
            patch("sunny_digest.telegram_probe.WORKER_TERMINATE_GRACE_S", 0.03),
        ):
            task = asyncio.create_task(probe_telegram_session(
                12345, "a" * 32, "secret-session", asyncio.Event()))
            await worker.stdout.started.wait()
            task.cancel()
            await worker.terminate_started.wait()
            for _ in range(4):
                task.cancel()
                await asyncio.sleep(0)
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(worker.terminated)
        self.assertTrue(worker.killed)
        self.assertTrue(worker.stopped.is_set())
        self.assertGreaterEqual(worker.wait_count, 2)

    async def test_worker_transport_errors_never_write_secret_material(self):
        secret_hash = "a" * 32
        secret_session = "secret-session"
        request = json.dumps({
            "schema": WORKER_SCHEMA,
            "api_id": 12345,
            "api_hash": secret_hash,
            "session": secret_session,
        }).encode("utf-8")
        stdout = io.BytesIO()
        stderr = io.StringIO()
        with (
            patch.object(
                telegram_probe_worker.sys, "stdin",
                SimpleNamespace(buffer=io.BytesIO(request)),
            ),
            patch.object(
                telegram_probe_worker.sys, "stdout",
                SimpleNamespace(buffer=stdout),
            ),
            patch.object(telegram_probe_worker.sys, "stderr", stderr),
            patch.object(
                telegram_probe_worker, "_probe",
                AsyncMock(side_effect=RuntimeError(secret_session)),
            ),
        ):
            result = await asyncio.get_running_loop().run_in_executor(
                None, telegram_probe_worker.main)

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), b"")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
