from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sunny_digest.contracts import (
    build_digest_upload,
    build_monitor_upload,
    canonical_digest_bytes,
    canonical_monitor_bytes,
    status_request,
)
from sunny_digest.ssh_transport import MAX_SSH_RESPONSE_BYTES, SSHTransport
from sunny_digest.storage import Paths


SOURCE_ID = "12345678-1234-4678-9234-567812345678"
CHAT_IDS = [-1_000_000_000_124, -1_000_000_000_123]
NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def gate():
    cursors = [{"chat_id": chat_id, "through_message_id": 0} for chat_id in CHAT_IDS]
    return {
        "schema": "sunny.personal-chats.status-gate.v2",
        "ok": True,
        "server_time": "2026-08-04T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "monitor": {
            "baseline_required": True, "next_sequence": 1,
            "previous_sha256": None, "cursors": cursors,
            "max_upload_bytes": 32768,
        },
        "digest": {
            "due": True, "reason": "due", "digest_date": "2026-08-04",
            "prepare_not_before": "2026-08-04T03:00:00+03:00",
            "accept_until": "2026-08-04T04:45:00+03:00",
            "next_sequence": 1, "previous_sha256": None,
            "cursors": cursors, "max_upload_bytes": 32768,
        },
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
        self.returncode = 0
        self.stdin = FakeStdin()
        self.stdout = FakeStdout(json.dumps(response, separators=(",", ":")).encode())

    async def wait(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


def receipt(upload, stream):
    return {
        "schema": "sunny.personal-chats.receipt.v2",
        "ok": True,
        "status": "accepted",
        "stream": stream,
        "sequence": upload["sequence"],
        "content_sha256": upload["content_sha256"],
        "received_at": "2026-08-04T00:31:01Z",
    }


class SSHTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_literal_v2_commands_and_bound_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            transport = SSHTransport(paths, {
                "host": "receiver.example", "port": 22, "user": "root",
            })
            gate_value = gate()
            monitor = build_monitor_upload(
                source_id=SOURCE_ID, gate=gate_value, kind="baseline",
                ranges=[{"chat_id": chat_id, "from_message_id_exclusive": 0,
                         "through_message_id": 10} for chat_id in CHAT_IDS],
                events=[], generated_at=NOW,
            )
            digest = build_digest_upload(
                source_id=SOURCE_ID, gate=gate_value,
                chat_ranges=[{"chat_id": chat_id, "from_message_id_exclusive": 0,
                              "through_message_id": 11, "message_count": 1}
                             for chat_id in CHAT_IDS],
                digest="Дайджест", model="anthropic/example", generated_at=NOW,
            )
            processes = [
                FakeProcess(gate_value), FakeProcess(receipt(monitor, "monitor")),
                FakeProcess(receipt(digest, "digest")),
            ]
            create = AsyncMock(side_effect=processes)
            with patch("sunny_digest.ssh_transport.asyncio.create_subprocess_exec", create):
                await transport.gate(SOURCE_ID, CHAT_IDS, asyncio.Event())
                await transport.upload_monitor(canonical_monitor_bytes(monitor), asyncio.Event())
                await transport.upload_digest(canonical_digest_bytes(digest), asyncio.Event())

            self.assertEqual(
                [call.args[-1] for call in create.await_args_list],
                ["status-v2", "monitor-upload-v2", "digest-upload-v2"],
            )
            self.assertEqual(processes[0].stdin.data, status_request(SOURCE_ID, CHAT_IDS))
            self.assertEqual(processes[1].stdin.data, canonical_monitor_bytes(monitor))
            self.assertEqual(processes[2].stdin.data, canonical_digest_bytes(digest))
            for call in create.await_args_list:
                self.assertNotIn("shell", call.kwargs)

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
            with patch("sunny_digest.ssh_transport.asyncio.create_subprocess_exec",
                       AsyncMock(return_value=process)):
                with self.assertRaisesRegex(RuntimeError, "size limit"):
                    await transport.gate(SOURCE_ID, CHAT_IDS, asyncio.Event())
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
