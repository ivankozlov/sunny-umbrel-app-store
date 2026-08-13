from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunny_digest.ipc import _handle
from sunny_digest.web import (
    IPC_CONNECT_TIMEOUT_S,
    IPC_RESPONSE_TIMEOUT_S,
    IPC_SEND_TIMEOUT_S,
    IPCClient,
)


class _StatusCollector:
    async def public_status(self):
        return {"phase": "fresh"}


class _FailingStatusCollector:
    async def public_status(self):
        raise RuntimeError("secret-provider-detail")


class _Reader:
    async def readline(self):
        return b'{"command":"status"}\n'


class _Writer:
    def __init__(self, *, fail_at=None, error_type=BrokenPipeError):
        self.fail_at = fail_at
        self.error_type = error_type
        self.raw = b""
        self.closed = False

    def _fail(self, stage):
        if self.fail_at == stage:
            raise self.error_type()

    def write(self, raw):
        self._fail("write")
        self.raw += raw

    async def drain(self):
        self._fail("drain")

    def close(self):
        self.closed = True
        self._fail("close")

    async def wait_closed(self):
        self._fail("wait_closed")


class _SocketStream:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def readline(self, _limit):
        return b'{"ok":true,"result":{"phase":"fresh"}}\n'


class _Socket:
    def __init__(self):
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, _path):
        return None

    def sendall(self, _raw):
        return None

    def makefile(self, _mode):
        return _SocketStream()


class IPCTests(unittest.TestCase):
    def test_client_defaults_cover_longest_synchronous_collector_action(self):
        self.assertEqual(IPC_RESPONSE_TIMEOUT_S, 150)
        self.assertGreater(IPC_RESPONSE_TIMEOUT_S, 120)
        self.assertGreater(IPC_CONNECT_TIMEOUT_S, 0)
        self.assertGreater(IPC_SEND_TIMEOUT_S, 0)

    def test_client_bounds_connect_send_and_response_separately(self):
        connection = _Socket()
        client = IPCClient(
            "/runtime/control.sock",
            connect_timeout=1,
            send_timeout=2,
            response_timeout=3,
        )
        with patch("sunny_digest.web.socket.socket", return_value=connection):
            self.assertEqual(client.request("status"), {"phase": "fresh"})
        self.assertEqual(connection.timeouts, [1, 2, 3])

    def test_client_accepts_delayed_real_unix_response_with_injected_timeouts(self):
        async def scenario(socket_path):
            async def respond(reader, writer):
                await reader.readline()
                await asyncio.sleep(0.05)
                writer.write(b'{"ok":true,"result":{"phase":"fresh"}}\n')
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_unix_server(respond, path=str(socket_path))
            client = IPCClient(
                str(socket_path),
                connect_timeout=0.2,
                send_timeout=0.2,
                response_timeout=0.2,
            )
            try:
                async with server:
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(
                        None, client.request, "status")
            finally:
                server.close()
                await server.wait_closed()

        with tempfile.TemporaryDirectory() as directory:
            result = asyncio.run(scenario(Path(directory) / "control.sock"))
        self.assertEqual(result, {"phase": "fresh"})

    def test_late_client_disconnect_is_not_an_unhandled_server_error(self):
        cases = (
            ("write", BrokenPipeError),
            ("drain", ConnectionResetError),
            ("close", BrokenPipeError),
            ("wait_closed", ConnectionResetError),
        )
        for stage, error_type in cases:
            with self.subTest(stage=stage, error_type=error_type.__name__):
                writer = _Writer(fail_at=stage, error_type=error_type)
                asyncio.run(_handle(_StatusCollector(), _Reader(), writer))
                self.assertTrue(writer.closed)

    def test_dispatch_error_response_remains_redacted(self):
        writer = _Writer()
        asyncio.run(_handle(_FailingStatusCollector(), _Reader(), writer))
        response = json.loads(writer.raw.decode("utf-8"))
        self.assertEqual(
            response, {"ok": False, "error_type": "RuntimeError"})
        self.assertNotIn(b"secret-provider-detail", writer.raw)


if __name__ == "__main__":
    unittest.main()
