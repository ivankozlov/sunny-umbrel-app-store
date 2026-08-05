from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sunny_digest.contracts import build_upload, canonical_upload_bytes, status_request
from sunny_digest.ssh_transport import MAX_SSH_RESPONSE_BYTES, SSHTransport
from sunny_digest.storage import Paths


SOURCE_ID = "12345678-1234-4678-9234-567812345678"
CHAT_ID = -100123


def gate():
    return {
        "schema": "sunny.personal-digest-gate.v1",
        "ok": True,
        "due": True,
        "reason": "due",
        "server_time": "2026-08-04T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "digest_date": "2026-08-04",
        "prepare_not_before": "2026-08-04T03:00:00+03:00",
        "accept_until": "2026-08-04T04:45:00+03:00",
        "next_sequence": 1,
        "previous_sha256": None,
        "from_message_id_exclusive": 10,
        "max_upload_bytes": 32768,
    }


class FakeStdin:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        return None

    async def wait_closed(self):
        return None


class FakeStdout:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    async def read(self, limit):
        await asyncio.sleep(0)
        chunk = self.data[self.offset:self.offset + limit]
        self.offset += len(chunk)
        return chunk


class FakeProcess:
    def __init__(self, response: dict):
        self.response = json.dumps(response, separators=(",", ":")).encode("utf-8")
        self.returncode = 0
        self.stdin = FakeStdin()
        self.stdout = FakeStdout(self.response)

    async def wait(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class SSHTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_literal_commands_and_bound_status_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            transport = SSHTransport(paths, {
                "host": "receiver.example", "port": 22, "user": "root",
            })
            gate_value = gate()
            payload = build_upload(
                source_id=SOURCE_ID, gate=gate_value, chat_id=CHAT_ID,
                through_message_id=11, message_count=1, digest="Дайджест",
                model="anthropic/example",
                generated_at=datetime(2026, 8, 4, 0, 31, tzinfo=timezone.utc),
            )
            receipt = {
                "ok": True,
                "status": "accepted",
                "sequence": 1,
                "content_sha256": payload["content_sha256"],
                "received_at": "2026-08-04T00:31:01Z",
                "through_message_id": 11,
            }
            status_process = FakeProcess(gate_value)
            upload_process = FakeProcess(receipt)
            create = AsyncMock(side_effect=[status_process, upload_process])
            revoked = asyncio.Event()
            with patch("sunny_digest.ssh_transport.asyncio.create_subprocess_exec", create):
                self.assertEqual(
                    (await transport.gate(SOURCE_ID, CHAT_ID, revoked))["next_sequence"], 1)
                await transport.upload(canonical_upload_bytes(payload), revoked)

            status_args = create.await_args_list[0].args
            upload_args = create.await_args_list[1].args
            self.assertEqual(status_args[-2:], ("root@receiver.example", "status-v1"))
            self.assertEqual(upload_args[-2:], ("root@receiver.example", "upload-v1"))
            self.assertEqual(status_process.stdin.data, status_request(SOURCE_ID, CHAT_ID))
            self.assertEqual(upload_process.stdin.data, canonical_upload_bytes(payload))
            self.assertNotIn("shell", create.await_args_list[0].kwargs)

    async def test_oversized_receiver_output_is_stopped_at_hard_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            transport = SSHTransport(paths, {
                "host": "receiver.example", "port": 22, "user": "root",
            })
            process = FakeProcess({"ok": True})
            process.stdout = FakeStdout(b"x" * (MAX_SSH_RESPONSE_BYTES + 1))
            with patch(
                    "sunny_digest.ssh_transport.asyncio.create_subprocess_exec",
                    AsyncMock(return_value=process)):
                with self.assertRaisesRegex(RuntimeError, "size limit"):
                    await transport.gate(SOURCE_ID, CHAT_ID, asyncio.Event())
            self.assertIn(process.returncode, (-15, -9))

    def test_unknown_remote_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            transport = SSHTransport(paths, {
                "host": "receiver.example", "port": 22, "user": "root",
            })
            with self.assertRaises(ValueError):
                transport._args("arbitrary")


if __name__ == "__main__":
    unittest.main()
