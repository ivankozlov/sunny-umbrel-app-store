from __future__ import annotations

import asyncio
import base64
import json
import socket
import ssl
import unittest
import urllib.request
from unittest.mock import AsyncMock, Mock, patch

import sunny_digest.vpn_subscription_worker as subscription_worker
from sunny_digest.vpn_subscription import (
    MAX_SUBSCRIPTION_BYTES,
    WORKER_SCHEMA,
    _fetch_https_bytes,
    fetch_vless_subscription,
    parse_vless_subscription,
    resolve_public_node_servers,
    resolve_public_subscription_host,
    validate_subscription_url,
)

UUID = "11111111-2222-4333-8444-555555555555"
PBK = "E" * 43


def vless_uri(**changes):
    values = {
        "host": "vpn.example",
        "port": "443",
        "uuid": UUID,
        "security": "reality",
        "encryption": "none",
        "sni": "cdn.example",
        "fp": "chrome",
        "pbk": PBK,
        "sid": "1a2b3c4d",
        "type": "tcp",
        "flow": "xtls-rprx-vision",
    }
    values.update(changes)
    query = "&".join(
        f"{key}={values[key]}" for key in (
            "encryption", "security", "sni", "fp", "pbk", "sid",
            "type", "flow",
        )
    )
    return (
        f"vless://{values['uuid']}@{values['host']}:{values['port']}?"
        f"{query}#ignored-name"
    )


def parsed_node(server="1.1.1.1"):
    return parse_vless_subscription(vless_uri(host=server).encode())[0]


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


class FakeHungStdout:
    def __init__(self, stopped: asyncio.Event):
        self.started = asyncio.Event()
        self.stopped = stopped

    async def read(self, _limit):
        self.started.set()
        await self.stopped.wait()
        return b""


class FakeHungWorker(FakeWorker):
    def __init__(self):
        super().__init__(b"")
        self.stopped = asyncio.Event()
        self.stdout = FakeHungStdout(self.stopped)
        self.returncode = None

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


class FakeUncooperativeWorker(FakeHungWorker):
    def terminate(self):
        self.terminated = True


class SlowKillWorker(FakeUncooperativeWorker):
    def __init__(self):
        super().__init__()
        self.kill_started = asyncio.Event()
        self.allow_kill_exit = asyncio.Event()

    def kill(self):
        self.killed = True
        self.kill_started.set()

    async def wait(self):
        self.wait_count += 1
        if self.killed:
            await self.allow_kill_exit.wait()
            self.returncode = -9
            self.stopped.set()
        await self.stopped.wait()
        return self.returncode


class FakeHTTPSResponse:
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def getcode(self):
        return 200

    def geturl(self):
        return "https://subscription.example/client?token=secret"

    def read(self, _limit):
        return vless_uri().encode()


class SubscriptionURLTests(unittest.TestCase):
    def test_accepts_only_bounded_opaque_https_hostname_url(self):
        value = "https://subscription.example/api/v1/client?token=a%2Fb-c_9"
        self.assertEqual(validate_subscription_url(value), value)

        invalid = (
            "http://subscription.example/api",
            "https:///missing-host",
            "https://localhost/api",
            "https://127.0.0.1/api",
            "https://user@subscription.example/api",
            "https://subscription.example:443/api",
            "https://subscription.example/api#fragment",
            " https://subscription.example/api",
            "https://subscription.example/a b",
            "https://subscription.example/a\\b",
            "https://subscription.example/a\u200bb",
            "https://subscription.example/a%20b",
            "https://subscription.example/a%E2%80%8Bb",
            "https://subscription.example/%not-hex",
            "https://-bad.subscription.example/api",
            "https://subscription.example/" + "a" * 2021,
            42,
        )
        for candidate in invalid:
            with self.subTest(candidate=repr(candidate)), self.assertRaises(ValueError):
                validate_subscription_url(candidate)

    def test_url_never_appears_in_validation_error(self):
        secret = "top-secret-bearer"
        value = f"http://subscription.example/api?token={secret}"
        with self.assertRaises(ValueError) as raised:
            validate_subscription_url(value)
        self.assertNotIn(secret, str(raised.exception))

    def test_origin_preflight_rejects_any_non_public_dns_answer(self):
        url = "https://subscription.example/client?token=secret"
        public_and_private = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
        ]
        with self.assertRaisesRegex(ValueError, "origin resolution failed"):
            resolve_public_subscription_host(
                url, resolver=Mock(return_value=public_and_private),
            )

    def test_origin_preflight_and_pinned_connection_reject_multicast(self):
        url = "https://subscription.example/client?token=secret"
        for address in ("224.0.0.1", "239.255.255.250"):
            answers = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)),
            ]
            with self.subTest(address=address), self.assertRaisesRegex(
                ValueError, "origin resolution failed",
            ):
                resolve_public_subscription_host(
                    url, resolver=Mock(return_value=answers),
                )
            from sunny_digest.vpn_subscription import _PinnedHTTPSConnection
            with self.subTest(address=address), self.assertRaisesRegex(
                ValueError, "origin address is invalid",
            ):
                _PinnedHTTPSConnection(
                    "subscription.example", pinned_address=address,
                )

    def test_worker_preflights_origin_before_https_fetch(self):
        calls = []

        def preflight(_url):
            calls.append("preflight")
            return "1.1.1.1"

        def fetch(_url, _timeout_s, _max_bytes, pinned_address):
            calls.append("fetch")
            self.assertEqual(pinned_address, "1.1.1.1")
            return vless_uri(host="1.1.1.1").encode()

        with patch.object(
            subscription_worker, "resolve_public_subscription_host", preflight,
        ), patch.object(
            subscription_worker, "_fetch_https_bytes", fetch,
        ):
            nodes = subscription_worker._fetch_nodes(
                "https://subscription.example/client?token=secret", 5.0,
            )

        self.assertEqual(calls, ["preflight", "fetch"])
        self.assertEqual(nodes[0]["server"], "1.1.1.1")

    def test_https_fetch_explicitly_ignores_ambient_proxy_environment(self):
        opener = Mock()
        opener.open.return_value = FakeHTTPSResponse()
        with patch(
            "sunny_digest.vpn_subscription.urllib.request.build_opener",
            return_value=opener,
        ) as build_opener:
            payload = _fetch_https_bytes(
                "https://subscription.example/client?token=secret", 5.0,
                MAX_SUBSCRIPTION_BYTES, "1.1.1.1",
            )

        self.assertTrue(payload.startswith(b"vless://"))
        proxy_handler = build_opener.call_args.args[0]
        self.assertIsInstance(proxy_handler, urllib.request.ProxyHandler)
        self.assertEqual(proxy_handler.proxies, {})

    def test_pinned_https_connects_to_vetted_ip_but_keeps_origin_for_tls(self):
        from sunny_digest.vpn_subscription import _PinnedHTTPSConnection

        raw_socket = Mock()
        wrapped_socket = Mock()
        context = Mock(spec=ssl.SSLContext)
        context.wrap_socket.return_value = wrapped_socket
        connection = _PinnedHTTPSConnection(
            "subscription.example", pinned_address="1.1.1.1",
            timeout=7, context=context,
        )
        with patch(
            "sunny_digest.vpn_subscription.socket.create_connection",
            return_value=raw_socket,
        ) as create:
            connection.connect()

        create.assert_called_once_with(("1.1.1.1", 443), 7, None)
        context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="subscription.example",
        )


class VlessRealityParserTests(unittest.TestCase):
    def test_parses_raw_and_base64_wrapped_lists_to_sanitized_nodes(self):
        first = vless_uri()
        second = vless_uri(
            host="1.1.1.1", port="8443",
            uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            fp="firefox", sid="A0B2",
        )
        expected = [{
            "type": "vless",
            "server": "vpn.example",
            "port": 443,
            "uuid": UUID,
            "network": "tcp",
            "tls": True,
            "servername": "cdn.example",
            "client-fingerprint": "chrome",
            "reality-opts": {
                "public-key": PBK,
                "short-id": "1a2b3c4d",
            },
            "flow": "xtls-rprx-vision",
            "udp": False,
        }, {
            "type": "vless",
            "server": "1.1.1.1",
            "port": 8443,
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "network": "tcp",
            "tls": True,
            "servername": "cdn.example",
            "client-fingerprint": "firefox",
            "reality-opts": {
                "public-key": PBK,
                "short-id": "a0b2",
            },
            "flow": "xtls-rprx-vision",
            "udp": False,
        }]
        raw = f"{first}\n\n{second}\n".encode()
        wrapped = base64.b64encode(raw).rstrip(b"=")

        self.assertEqual(parse_vless_subscription(raw), expected)
        self.assertEqual(parse_vless_subscription(wrapped), expected)
        self.assertNotIn("ignored-name", repr(expected))
        self.assertNotIn("name", expected[0])

        blank_sid = parse_vless_subscription(vless_uri(sid="").encode())
        self.assertEqual(blank_sid[0]["reality-opts"]["short-id"], "")

    def test_allows_only_a_narrow_tcp_reality_vision_profile(self):
        invalid = (
            vless_uri().replace("vless://", "vmess://", 1),
            vless_uri(security="tls"),
            vless_uri(encryption="auto"),
            vless_uri(type="ws"),
            vless_uri(flow=""),
            vless_uri(fp="qq"),
            vless_uri(pbk="bad+key"),
            vless_uri(sid="abc"),
            vless_uri(sid="0123456789abcdef00"),
            vless_uri(host="127.0.0.1"),
            vless_uri(host="DIRECT"),
            vless_uri(uuid="AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"),
            vless_uri(port="0"),
            vless_uri().replace(
                "#ignored-name", "&allowInsecure=1#ignored-name"),
            vless_uri().replace(
                "#ignored-name", "&skip-cert-verify=true#ignored-name"),
            vless_uri().replace(
                "#ignored-name", "&dialer-proxy=DIRECT#ignored-name"),
            vless_uri().replace(
                "#ignored-name", "&security=reality#ignored-name"),
            vless_uri().replace(
                "#ignored-name", "&unknown=value#ignored-name"),
            vless_uri().replace(
                "#ignored-name", "#ignored\tname"),
            vless_uri().replace(
                "#ignored-name", "&spx=relative#ignored-name"),
            vless_uri().replace(
                "#ignored-name", "&spx=%2F" + "x" * 257 + "#ignored-name"),
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate[:80]), self.assertRaises(ValueError):
                parse_vless_subscription(candidate.encode())

    def test_accepts_standard_bounded_spider_x_without_persisting_it(self):
        node = parse_vless_subscription(
            vless_uri().replace(
                "#ignored-name", "&spx=%2Ftelegram%3Fa%3D1#ignored-name",
            ).encode()
        )[0]
        self.assertNotIn("spider-x", repr(node))
        self.assertNotIn("telegram", repr(node))

    def test_rejects_empty_oversized_and_overpopulated_payloads_without_secrets(self):
        secret = "secret-node-material"
        invalid = (
            b"",
            b"not a subscription",
            (vless_uri() + "#" + "x" * 4097).encode(),
            ((vless_uri() + "\n") * 65).encode(),
            vless_uri().replace(
                "#ignored-name", f"&unknown={secret}#ignored-name").encode(),
        )
        for payload in invalid:
            with self.subTest(size=len(payload)), self.assertRaises(ValueError) as raised:
                parse_vless_subscription(payload)
            self.assertNotIn(secret, str(raised.exception))


class NodeResolutionTests(unittest.TestCase):
    def test_hostname_is_pinned_to_deterministic_ipv4_first_public_address(self):
        resolver = Mock(return_value=[
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
             ("2606:4700:4700::1111", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.2", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        ])
        node = parse_vless_subscription(vless_uri().encode())[0]

        resolved = resolve_public_node_servers([node], resolver=resolver)

        self.assertEqual(resolved[0]["server"], "1.1.1.1")
        self.assertEqual(resolved[0]["servername"], "cdn.example")
        self.assertEqual(node["server"], "vpn.example")
        resolver.assert_called_once_with(
            "vpn.example", 443, type=socket.SOCK_STREAM,
        )

    def test_any_non_public_dns_answer_rejects_the_node(self):
        node = parse_vless_subscription(vless_uri().encode())[0]
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with self.assertRaisesRegex(ValueError, "resolution failed"):
            resolve_public_node_servers([node], resolver=Mock(return_value=answers))

    def test_multicast_literal_and_dns_answers_are_rejected(self):
        node = parse_vless_subscription(vless_uri().encode())[0]
        for address in ("224.0.0.1", "239.255.255.250"):
            answers = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)),
            ]
            with self.subTest(address=address), self.assertRaisesRegex(
                ValueError, "resolution failed",
            ):
                resolve_public_node_servers(
                    [node], resolver=Mock(return_value=answers),
                )
            with self.subTest(address=address), self.assertRaises(ValueError):
                parse_vless_subscription(vless_uri(host=address).encode())

    def test_ipv6_only_node_is_rejected(self):
        node = parse_vless_subscription(vless_uri().encode())[0]
        answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
             ("2606:4700:4700::1111", 443, 0, 0)),
        ]
        with self.assertRaisesRegex(ValueError, "resolution failed"):
            resolve_public_node_servers([node], resolver=Mock(return_value=answers))

    def test_public_literal_never_uses_dns(self):
        resolver = Mock(side_effect=AssertionError("DNS must not be used"))
        resolved = resolve_public_node_servers(
            [parsed_node()], resolver=resolver,
        )
        self.assertEqual(resolved[0]["server"], "1.1.1.1")
        resolver.assert_not_called()


class SubscriptionFetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_fetch_is_bounded_and_parses_without_forwarding_headers(self):
        calls = []

        def fetcher(url, timeout_s, max_bytes):
            calls.append((url, timeout_s, max_bytes))
            return vless_uri().encode()

        value = "https://subscription.example/client?token=secret"
        nodes = await fetch_vless_subscription(
            value, fetcher=fetcher, timeout_s=7,
        )
        self.assertEqual(nodes[0]["server"], "vpn.example")
        self.assertEqual(calls, [(value, 7, MAX_SUBSCRIPTION_BYTES)])

    async def test_fetch_errors_and_oversize_never_expose_bearer_url(self):
        secret = "secret-bearer-token"
        url = f"https://subscription.example/client?token={secret}"

        def failed_fetcher(received, timeout_s, max_bytes):
            raise RuntimeError(f"download of {received} failed")

        with self.assertRaises(RuntimeError) as raised:
            await fetch_vless_subscription(url, fetcher=failed_fetcher)
        self.assertNotIn(secret, str(raised.exception))

        def huge_fetcher(received, timeout_s, max_bytes):
            return b"x" * (max_bytes + 1)

        with self.assertRaises(RuntimeError) as raised:
            await fetch_vless_subscription(url, fetcher=huge_fetcher)
        self.assertNotIn(secret, str(raised.exception))

    async def test_default_fetch_passes_bearer_only_over_worker_stdin(self):
        secret = "secret-bearer-token"
        url = f"https://subscription.example/client?token={secret}"
        response = json.dumps({"nodes": [parsed_node()]}, separators=(",", ":"))
        worker = FakeWorker(response.encode())
        create = AsyncMock(return_value=worker)

        with patch(
            "sunny_digest.vpn_subscription.asyncio.create_subprocess_exec", create,
        ):
            nodes = await fetch_vless_subscription(url)

        self.assertEqual(nodes[0]["server"], "1.1.1.1")
        request = json.loads(worker.stdin.data)
        self.assertEqual(request, {
            "schema": WORKER_SCHEMA, "timeout_s": 15.0, "url": url,
        })
        command = " ".join(str(part) for part in create.await_args.args)
        self.assertNotIn(secret, command)
        self.assertNotIn(secret, repr(create.await_args.kwargs))
        self.assertEqual(
            create.await_args.args[-2:],
            ("-m", "sunny_digest.vpn_subscription_worker"),
        )

    async def test_worker_response_rejects_multicast_server(self):
        node = parsed_node()
        node["server"] = "224.0.0.1"
        response = json.dumps({
            "nodes": [node],
        }, separators=(",", ":")).encode()
        worker = FakeWorker(response)
        with patch(
            "sunny_digest.vpn_subscription.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            with self.assertRaisesRegex(RuntimeError, "download failed"):
                await fetch_vless_subscription(
                    "https://subscription.example/client?token=secret",
                )

    async def test_cancellation_terminates_and_reaps_worker(self):
        worker = FakeHungWorker()
        with patch(
            "sunny_digest.vpn_subscription.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            task = asyncio.create_task(fetch_vless_subscription(
                "https://subscription.example/client?token=secret",
            ))
            await asyncio.wait_for(worker.stdout.started.wait(), timeout=2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)

        self.assertTrue(worker.terminated)
        self.assertGreaterEqual(worker.wait_count, 1)

    async def test_timeout_escalates_to_kill_and_reaps_worker(self):
        worker = FakeUncooperativeWorker()
        with patch(
            "sunny_digest.vpn_subscription.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ), patch(
            "sunny_digest.vpn_subscription.WORKER_TERMINATE_GRACE_S", 0.01,
        ):
            with self.assertRaisesRegex(RuntimeError, "download failed"):
                await fetch_vless_subscription(
                    "https://subscription.example/client?token=secret",
                    timeout_s=0.001,
                )

        self.assertTrue(worker.terminated)
        self.assertTrue(worker.killed)
        self.assertGreaterEqual(worker.wait_count, 2)

    async def test_second_cancellation_cannot_interrupt_worker_kill_and_reap(self):
        worker = SlowKillWorker()
        with patch(
            "sunny_digest.vpn_subscription.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ), patch(
            "sunny_digest.vpn_subscription.WORKER_TERMINATE_GRACE_S", 0.01,
        ):
            task = asyncio.create_task(fetch_vless_subscription(
                "https://subscription.example/client?token=secret",
            ))
            await worker.stdout.started.wait()
            task.cancel()
            await worker.kill_started.wait()
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            worker.allow_kill_exit.set()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(worker.terminated)
        self.assertTrue(worker.killed)
        self.assertIsNotNone(worker.returncode)

    async def test_failed_worker_error_is_redacted(self):
        secret = "secret-bearer-token"
        worker = FakeWorker(b"", returncode=1)
        with patch(
            "sunny_digest.vpn_subscription.asyncio.create_subprocess_exec",
            AsyncMock(return_value=worker),
        ):
            with self.assertRaises(RuntimeError) as raised:
                await fetch_vless_subscription(
                    f"https://subscription.example/client?token={secret}",
                )
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
