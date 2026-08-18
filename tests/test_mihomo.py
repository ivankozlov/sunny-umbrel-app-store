from __future__ import annotations

import asyncio
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sunny_digest.mihomo import (
    MIHOMO_SOCKS_HOST,
    MIHOMO_SOCKS_PORT,
    MihomoExitedError,
    MihomoPaths,
    MihomoRuntime,
    render_mihomo_config,
    write_mihomo_config,
)


def reality_node(**overrides):
    value = {
        "name": "untrusted subscription name",
        "type": "vless",
        "server": "1.1.1.1",
        "port": 443,
        "uuid": "11111111-2222-4333-8444-555555555555",
        "network": "tcp",
        "tls": True,
        "servername": "cdn.example",
        "client-fingerprint": "chrome",
        "reality-opts": {
            "public-key": "reality-public-key",
            "short-id": "1a2b3c4d",
        },
        "flow": "xtls-rprx-vision",
        "udp": True,
    }
    value.update(overrides)
    return value


class FakeReader:
    def __init__(self, response=b"\x05\x00"):
        self.response = response
        self.requests = []

    async def readexactly(self, size):
        self.requests.append(size)
        return self.response


class FakeWriter:
    def __init__(self):
        self.writes = []
        self.closed = False
        self.waited = False

    def write(self, value):
        self.writes.append(value)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.waited = True


class FakeProcess:
    def __init__(self, *, returncode=None, hang_after_terminate=False,
                 exit_during_terminate=False):
        self.returncode = returncode
        self.hang_after_terminate = hang_after_terminate
        self.exit_during_terminate = exit_during_terminate
        self.terminated = False
        self.killed = False
        self.wait_calls = 0
        self._exit = asyncio.Event()
        if returncode is not None:
            self._exit.set()

    def terminate(self):
        self.terminated = True
        if self.exit_during_terminate:
            self.returncode = 0
            self._exit.set()
            raise ProcessLookupError
        if not self.hang_after_terminate:
            self.returncode = -15
            self._exit.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self._exit.set()

    async def wait(self):
        self.wait_calls += 1
        await self._exit.wait()
        return self.returncode

    def exit(self, returncode):
        self.returncode = returncode
        self._exit.set()


class SlowKillProcess(FakeProcess):
    def __init__(self):
        super().__init__(hang_after_terminate=True)
        self.kill_started = asyncio.Event()
        self.allow_kill_exit = asyncio.Event()

    def kill(self):
        self.killed = True
        self.kill_started.set()

    async def wait(self):
        self.wait_calls += 1
        if self.killed:
            await self.allow_kill_exit.wait()
            self.returncode = -9
            self._exit.set()
        await self._exit.wait()
        return self.returncode


class TestBugMihomoVlessRealityRuntime20260812(unittest.IsolatedAsyncioTestCase):
    def test_writes_only_private_deterministic_static_vless_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            paths = MihomoPaths.for_runtime_root(runtime_root)
            config = write_mihomo_config(runtime_root, reality_node())

            self.assertEqual(config, paths.config)
            first = paths.config.read_bytes()
            self.assertEqual(first, render_mihomo_config(reality_node()))
            write_mihomo_config(runtime_root, reality_node())
            self.assertEqual(paths.config.read_bytes(), first)

            self.assertTrue(stat.S_ISDIR(paths.root.stat().st_mode))
            self.assertEqual(stat.S_IMODE(paths.root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(paths.config.stat().st_mode), 0o600)

            value = json.loads(first)
            self.assertEqual(set(value), {
                "allow-lan", "ipv6", "listeners", "log-level", "mode",
                "proxies", "rules",
            })
            # Ровно один listener: SOCKS для Telegram. OpenRouter ходит не
            # сюда, а через ssh-форвард до DO (0.2.7), поэтому лишнего
            # локального HTTP-прокси в конфиге быть не должно.
            self.assertEqual(value["listeners"], [{
                "listen": MIHOMO_SOCKS_HOST,
                "name": "telegram-socks",
                "port": MIHOMO_SOCKS_PORT,
                "type": "socks",
                "udp": False,
                "users": [],
            }])
            self.assertEqual(value["rules"], ["MATCH,vpn-active"])
            self.assertEqual(value["proxies"][0]["name"], "vpn-active")
            self.assertIs(value["proxies"][0]["udp"], False)
            self.assertEqual(value["proxies"][0]["flow"], "xtls-rprx-vision")
            self.assertNotIn("proxy-providers", value)
            self.assertNotIn("proxy-groups", value)
            self.assertNotIn("DIRECT", first.decode("utf-8").upper())
            self.assertNotIn("COMPATIBLE", first.decode("utf-8").upper())

    def test_rejects_non_reality_or_route_escape_nodes(self):
        invalid = (
            {},
            reality_node(type="vmess"),
            reality_node(tls=False),
            reality_node(**{"reality-opts": {}}),
            reality_node(server="DIRECT"),
            reality_node(**{"dialer-proxy": "DIRECT"}),
            reality_node(port=float("nan")),
            reality_node(server="vpn.example"),
            reality_node(server="224.0.0.1"),
            reality_node(server="239.255.255.250"),
            reality_node(**{"skip-cert-verify": True}),
        )
        for node in invalid:
            with self.subTest(node=node), self.assertRaises(ValueError):
                render_mihomo_config(node)

    def test_overrides_untrusted_identity_and_udp(self):
        config = json.loads(render_mihomo_config(reality_node(
            name="DIRECT",
            udp=True,
        )))
        node = config["proxies"][0]
        self.assertEqual(node["name"], "vpn-active")
        self.assertIs(node["udp"], False)
        self.assertEqual(node["network"], "tcp")

    async def test_starts_with_sanitized_process_and_real_socks_handshake(self):
        with tempfile.TemporaryDirectory() as temporary:
            private_dir = Path(temporary) / "private"
            process = FakeProcess()
            reader = FakeReader()
            writer = FakeWriter()
            create = AsyncMock(return_value=process)
            connect = AsyncMock(side_effect=[OSError, (reader, writer)])
            runtime = MihomoRuntime(
                private_dir,
                binary="/opt/mihomo/mihomo",
                runtime_parent=Path(temporary),
                startup_timeout=1,
                stop_timeout=1,
                probe_interval=0,
            )

            with patch("sunny_digest.mihomo.asyncio.create_subprocess_exec", create), \
                    patch("sunny_digest.mihomo.asyncio.open_connection", connect):
                await runtime.start(reality_node())
                runtime.ensure_alive()
                runtime_root = runtime.paths.root
                (runtime_root / "cache.db").write_bytes(b"derived secret cache")
                await runtime.stop()
                await runtime.stop()

            self.assertEqual(create.await_count, 1)
            args = create.await_args.args
            kwargs = create.await_args.kwargs
            self.assertEqual(runtime_root, Path(args[2]))
            paths = MihomoPaths.for_runtime_root(runtime_root)
            self.assertEqual(args, (
                "/opt/mihomo/mihomo", "-d", str(paths.root),
                "-f", str(paths.config),
            ))
            self.assertIs(kwargs["stdin"], asyncio.subprocess.DEVNULL)
            self.assertIs(kwargs["stdout"], asyncio.subprocess.DEVNULL)
            self.assertIs(kwargs["stderr"], asyncio.subprocess.DEVNULL)
            self.assertEqual(kwargs["cwd"], str(paths.root))
            self.assertEqual(kwargs["umask"], 0o077)
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(kwargs["env"], {
                "HOME": str(paths.root),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TMPDIR": str(paths.root),
                "XDG_CONFIG_HOME": str(paths.root),
            })
            self.assertEqual(connect.await_args_list[-1].args,
                             (MIHOMO_SOCKS_HOST, MIHOMO_SOCKS_PORT))
            self.assertEqual(reader.requests, [2])
            self.assertEqual(writer.writes, [b"\x05\x01\x00"])
            self.assertTrue(writer.closed)
            self.assertTrue(writer.waited)
            self.assertTrue(process.terminated)
            self.assertFalse(process.killed)
            self.assertFalse(runtime.ready)
            self.assertFalse(runtime_root.exists())

    async def test_readiness_failure_terminates_and_reaps_without_leaking_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = FakeProcess(returncode=23)
            create = AsyncMock(return_value=process)
            connect = AsyncMock()
            runtime = MihomoRuntime(
                Path(temporary), startup_timeout=0.05, stop_timeout=0.05,
                probe_interval=0,
            )
            with patch("sunny_digest.mihomo.asyncio.create_subprocess_exec", create), \
                    patch("sunny_digest.mihomo.asyncio.open_connection", connect):
                with self.assertRaises(MihomoExitedError) as raised:
                    await runtime.start(reality_node())
            self.assertIn("23", str(raised.exception))
            self.assertEqual(process.wait_calls, 1)
            self.assertFalse(process.terminated)
            self.assertFalse(runtime.ready)

    async def test_readiness_timeout_stops_child_and_stop_escalates_to_kill(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = FakeProcess(hang_after_terminate=True)
            create = AsyncMock(return_value=process)
            connect = AsyncMock(side_effect=OSError)
            runtime = MihomoRuntime(
                Path(temporary), startup_timeout=0.01, stop_timeout=0.01,
                probe_interval=0,
            )
            with patch("sunny_digest.mihomo.asyncio.create_subprocess_exec", create), \
                    patch("sunny_digest.mihomo.asyncio.open_connection", connect):
                with self.assertRaises(TimeoutError):
                    await runtime.start(reality_node())
            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)
            self.assertGreaterEqual(process.wait_calls, 2)
            self.assertFalse(runtime.ready)

    async def test_stop_reaps_child_that_exits_during_terminate_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = FakeProcess(exit_during_terminate=True)
            create = AsyncMock(return_value=process)
            reader = FakeReader()
            writer = FakeWriter()
            connect = AsyncMock(return_value=(reader, writer))
            runtime = MihomoRuntime(Path(temporary), startup_timeout=1)
            with patch("sunny_digest.mihomo.asyncio.create_subprocess_exec", create), \
                    patch("sunny_digest.mihomo.asyncio.open_connection", connect):
                await runtime.start(reality_node())
                await runtime.stop()
            self.assertTrue(process.terminated)
            self.assertEqual(process.wait_calls, 1)
            self.assertFalse(runtime.ready)

    async def test_wait_until_exit_surfaces_post_readiness_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = FakeProcess()
            create = AsyncMock(return_value=process)
            reader = FakeReader()
            writer = FakeWriter()
            connect = AsyncMock(return_value=(reader, writer))
            runtime = MihomoRuntime(Path(temporary), startup_timeout=1)
            with patch("sunny_digest.mihomo.asyncio.create_subprocess_exec", create), \
                    patch("sunny_digest.mihomo.asyncio.open_connection", connect):
                await runtime.start(reality_node())
                runtime_root = runtime.paths.root
                process.exit(17)
                with self.assertRaises(MihomoExitedError) as raised:
                    await runtime.wait_until_exit()
            self.assertIn("17", str(raised.exception))
            self.assertFalse(runtime.ready)
            self.assertFalse(runtime_root.exists())

    async def test_cancelled_stop_still_kills_reaps_and_erases_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = SlowKillProcess()
            create = AsyncMock(return_value=process)
            reader = FakeReader()
            writer = FakeWriter()
            connect = AsyncMock(return_value=(reader, writer))
            runtime = MihomoRuntime(
                Path(temporary), runtime_parent=Path(temporary),
                startup_timeout=1, stop_timeout=0.01,
            )
            with patch("sunny_digest.mihomo.asyncio.create_subprocess_exec", create), \
                    patch("sunny_digest.mihomo.asyncio.open_connection", connect):
                await runtime.start(reality_node())
                runtime_root = runtime.paths.root
                stop = asyncio.create_task(runtime.stop())
                await process.kill_started.wait()
                stop.cancel()
                await asyncio.sleep(0)
                self.assertFalse(stop.done())
                self.assertTrue(runtime_root.exists())
                process.allow_kill_exit.set()
                with self.assertRaises(asyncio.CancelledError):
                    await stop

            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)
            self.assertIsNotNone(process.returncode)
            self.assertFalse(runtime_root.exists())
            self.assertIsNone(runtime._process)


if __name__ == "__main__":
    unittest.main()
