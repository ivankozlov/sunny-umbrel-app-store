from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sunny_digest.openrouter_tunnel import (
    OPENROUTER_HOST,
    OPENROUTER_PORT,
    OpenRouterTunnel,
    TUNNEL_HOST,
    TUNNEL_PORT,
    TunnelUnavailableError,
)
from sunny_digest.storage import Paths

UPLOAD = {"host": "do.example", "port": 22, "user": "sunny-digest"}


def paths_for(root: Path) -> Paths:
    paths = Paths(root / "config", root / "private", root / "runtime",
                  root / "runtime" / "control.sock")
    paths.ensure()
    return paths


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode
        self.terminated = False
        self._exit = asyncio.Event()
        if returncode is not None:
            self._exit.set()

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self._exit.set()

    def kill(self):
        self.terminate()

    async def wait(self):
        await self._exit.wait()
        return self.returncode


class FakeWriter:
    def close(self):
        return None

    async def wait_closed(self):
        return None


class TunnelTests(unittest.IsolatedAsyncioTestCase):
    def test_forward_is_pinned_to_openrouter_and_key_is_dedicated(self):
        """Форвард жёстко на openrouter.ai:443 и своим ключом.

        Upload-ключ не годится: у него в authorized_keys стоит restrict с
        forced command, форвард по нему невозможен. А широкий форвард сделал бы
        из канала общий выход в интернет."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = paths_for(Path(temporary))
            args = OpenRouterTunnel(paths, UPLOAD)._args()

            self.assertIn("-N", args)
            forward = args[args.index("-L") + 1]
            self.assertEqual(
                forward,
                f"{TUNNEL_HOST}:{TUNNEL_PORT}:{OPENROUTER_HOST}:{OPENROUTER_PORT}")
            self.assertEqual(args[args.index("-i") + 1], str(paths.openrouter_key))
            self.assertNotEqual(str(paths.openrouter_key), str(paths.upload_key))
            # обрыв форварда обязан ронять ssh, а не оставлять мёртвый канал
            self.assertIn("ExitOnForwardFailure=yes", args)
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("BatchMode=yes", args)

    async def test_missing_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = paths_for(Path(temporary))
            with self.assertRaises(TunnelUnavailableError):
                await OpenRouterTunnel(paths, UPLOAD).start()

    async def test_ssh_exit_before_readiness_is_reported_not_awaited(self):
        """Занятый порт или отказ permitopen роняют ssh сразу — ждать нечего."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = paths_for(Path(temporary))
            paths.openrouter_key.write_text("key", encoding="ascii")
            tunnel = OpenRouterTunnel(paths, UPLOAD, ready_timeout=5,
                                      probe_interval=0)
            with patch("sunny_digest.openrouter_tunnel.asyncio.create_subprocess_exec",
                       AsyncMock(return_value=FakeProcess(returncode=255))):
                with self.assertRaises(TunnelUnavailableError):
                    await tunnel.start()

    async def test_ready_when_local_end_accepts_and_stop_reaps_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = paths_for(Path(temporary))
            paths.openrouter_key.write_text("key", encoding="ascii")
            process = FakeProcess()
            tunnel = OpenRouterTunnel(paths, UPLOAD, ready_timeout=5,
                                      probe_interval=0)
            connect = AsyncMock(side_effect=[OSError, (object(), FakeWriter())])

            with patch("sunny_digest.openrouter_tunnel.asyncio.create_subprocess_exec",
                       AsyncMock(return_value=process)), \
                    patch("sunny_digest.openrouter_tunnel.asyncio.open_connection",
                          connect):
                await tunnel.start()
                tunnel.ensure_alive()
                self.assertEqual(connect.await_args_list[-1].args,
                                 (TUNNEL_HOST, TUNNEL_PORT))
                await tunnel.stop()

            self.assertTrue(process.terminated)
            with self.assertRaises(TunnelUnavailableError):
                tunnel.ensure_alive()

    async def test_dead_tunnel_is_detected_after_the_request(self):
        """Если ssh умер во время запроса, попытка обязана считаться неудачной."""
        with tempfile.TemporaryDirectory() as temporary:
            paths = paths_for(Path(temporary))
            paths.openrouter_key.write_text("key", encoding="ascii")
            process = FakeProcess()
            tunnel = OpenRouterTunnel(paths, UPLOAD, ready_timeout=5,
                                      probe_interval=0)
            with patch("sunny_digest.openrouter_tunnel.asyncio.create_subprocess_exec",
                       AsyncMock(return_value=process)), \
                    patch("sunny_digest.openrouter_tunnel.asyncio.open_connection",
                          AsyncMock(return_value=(object(), FakeWriter()))):
                await tunnel.start()
                process.returncode = 255
                with self.assertRaises(TunnelUnavailableError):
                    tunnel.ensure_alive()
                await tunnel.stop()


if __name__ == "__main__":
    unittest.main()
