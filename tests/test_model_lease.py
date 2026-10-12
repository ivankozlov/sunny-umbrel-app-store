from __future__ import annotations

import asyncio
import io
import json
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sunny_digest import openrouter_worker
from sunny_digest.guardian_jobs import JobBroker, RemoteDigest
from sunny_digest.model_collector import fetch_job, run_job
from sunny_digest.model_lease import remaining_lease
from sunny_digest.openrouter import (
    WORKER_SCHEMA, OpenRouterError, _TunnelHTTPSConnection, blocking_fetch_response,
)
from tests.test_job_contracts import job, result


class TestBugModelLeaseSuspend20261007(unittest.IsolatedAsyncioTestCase):
    """Linux monotonic stops during suspend; old model grants must stop too."""

    def setUp(self):
        self.mono, self.boot = 1000.0, 2000.0
        self.value = job()
        self.value.update(expires_mono=self.mono + 30, expires_boot=self.boot + 30)
        self.broker = JobBroker(clock=lambda: self.mono, boot_clock=lambda: self.boot)

    def clocks(self):
        return patch.multiple("sunny_digest.model_lease",
                              boottime=lambda: self.boot,
                              time=type("Time", (), {"monotonic": lambda: self.mono}))

    async def test_queued_grant_cannot_issue_secrets_after_resume_inside_or_outside_window(self):
        for sleep_s in (2, 40):
            with self.subTest(sleep_s=sleep_s):
                task = asyncio.create_task(self.broker.request(self.value))
                await asyncio.sleep(0)
                self.boot += sleep_s
                try:
                    self.assertIsNone(self.broker.next_job()["job"])
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                finally:
                    await self.broker.cancel()
                    if self.broker.active is not None:
                        self.broker.reaped(self.value["job_id"])
                    await asyncio.gather(task, return_exceptions=True)
                    self.boot -= sleep_s

    async def test_inflight_grant_rejects_late_result_and_waits_for_cleanup(self):
        task = asyncio.create_task(self.broker.request(self.value))
        await asyncio.sleep(0)
        self.broker.next_job()
        self.boot += 2
        self.assertFalse(self.broker.status(self.value["job_id"])["active"])
        with self.assertRaises(ValueError):
            self.broker.result(result(self.value))
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.broker.reaped(self.value["job_id"])
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_broker_expires_after_resume_without_a_worker_poll(self):
        task = asyncio.create_task(self.broker.request(self.value))
        await asyncio.sleep(0)
        self.boot += 40
        try:
            # wait observes completion without cancelling the subject. A stuck
            # broker must fail this assertion, not inherit our timeout exception.
            done, _ = await asyncio.wait({task}, timeout=1)
            self.assertIn(task, done, "broker did not expire the grant itself")
            with self.assertRaises(asyncio.TimeoutError):
                task.result()
            self.assertIsNone(self.broker.active)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_suspend_between_policy_check_and_issuance_cannot_renew_gate(self):
        def policy_check():
            self.boot += 40
            return 30
        paths = SimpleNamespace(
            openrouter_key=SimpleNamespace(read_bytes=lambda: b"synthetic-key" * 10),
            known_hosts=SimpleNamespace(read_text=lambda *_: self.value["model_access"]["known_hosts"]),
        )
        guardian = SimpleNamespace(
            engine=SimpleNamespace(paths=paths), jobs=self.broker,
            vault=SimpleNamespace(snapshot={"security_epoch": 3}),
            model_seconds_left=policy_check, _gate_pair=(None, None, self.mono, self.boot),
        )
        with patch("sunny_digest.settings.load_settings", return_value={
                "upload": {"host": "receiver.example", "port": 22}}):
            with self.assertRaises(OpenRouterError):
                await asyncio.wait_for(RemoteDigest(guardian).attempt(
                    [], "synthetic", self.value["model"], "synthetic-model-key",
                    asyncio.Event(), None), .1)
        self.assertIsNone(self.broker.active)

    async def test_collector_does_not_fetch_an_old_grant_even_if_guardian_is_unreachable(self):
        trace = []
        class Client:
            def request(self, command, data):
                trace.append(command)
                raise OSError("guardian unreachable")
        self.boot += 40
        with self.clocks(), patch("sunny_digest.model_collector.fetch_job") as fetch:
            await run_job(Client(), self.value, None)
        fetch.assert_not_called()
        self.assertNotIn("job_result", trace)
        self.assertIn("job_reaped", trace)

    async def test_live_fetch_is_cancelled_on_resume_even_when_status_stays_active(self):
        trace = []
        async def fetch(*_):
            self.boot += 2
            try:
                await asyncio.Event().wait()
            finally:
                trace.append("cleanup")
        class Client:
            def request(self, command, data):
                trace.append(command)
                return {"active": True}
        with self.clocks(), patch("sunny_digest.model_collector.fetch_job", side_effect=fetch):
            await run_job(Client(), self.value, None)
        self.assertNotIn("job_result", trace)
        self.assertLess(trace.index("cleanup"), trace.index("job_reaped"))

    async def test_sleep_during_tunnel_start_never_spawns_http_child(self):
        trace = []
        test = self
        class Tunnel:
            def __init__(self, *_): pass
            async def start(self): test.boot += 2
            async def stop(self): trace.append("tunnel_stopped")
        @contextmanager
        def files(*_):
            yield {"identity": "synthetic", "known_hosts": "synthetic"}
        with self.clocks(), patch("sunny_digest.model_collector.secret_files", files), \
                patch("sunny_digest.model_collector.OpenRouterTunnel", Tunnel), \
                patch("sunny_digest.model_collector.asyncio.create_subprocess_exec") as spawn:
            response = await fetch_job(self.value, None)
        spawn.assert_not_called()
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(trace, ["tunnel_stopped"])

    def test_http_child_and_transport_check_the_lease_before_sending(self):
        lease = {key: self.value[key] for key in ("expires_mono", "expires_boot")}
        request = json.dumps({"schema": WORKER_SCHEMA, "prompt": "synthetic",
                              "model": self.value["model"], "api_key": "synthetic-model-key",
                              "lease": lease}).encode()
        self.boot += 2
        with self.clocks(), patch("sys.stdin", io.TextIOWrapper(io.BytesIO(request))), \
                patch.object(openrouter_worker, "blocking_fetch_response") as fetch:
            self.assertNotEqual(openrouter_worker.main(), 0)
        fetch.assert_not_called()
        with self.clocks(), patch("sunny_digest.openrouter.urllib.request.build_opener") as opener:
            with self.assertRaises(OpenRouterError):
                blocking_fetch_response("synthetic", self.value["model"], "synthetic-model-key", lease=lease)
        opener.return_value.open.assert_not_called()
        connection = _TunnelHTTPSConnection("openrouter.ai", lease=lease)
        connection.sock = Mock()
        with self.clocks(), self.assertRaises(TimeoutError):
            connection.send(b"synthetic request")
        connection.sock.sendall.assert_not_called()
        connection.close()

    def test_tls_handshake_resume_closes_socket_before_headers_or_prompt(self):
        lease = {key: self.value[key] for key in ("expires_mono", "expires_boot")}
        tls = Mock()
        connection = _TunnelHTTPSConnection("openrouter.ai", lease=lease)
        context = Mock()
        def wrap(*_, **__):
            self.boot += 2
            return tls
        context.wrap_socket.side_effect = wrap
        connection._context = context
        with self.clocks(), patch("sunny_digest.openrouter.socket.create_connection"), \
                self.assertRaises(TimeoutError):
            connection.send(b"synthetic request")
        tls.sendall.assert_not_called()
        tls.close.assert_called_once()

    def test_active_lease_uses_earliest_clock_and_does_not_mutate_job(self):
        with self.clocks():
            self.assertEqual(remaining_lease(self.value), 30)
            self.mono += 5
            self.boot += 5
            self.assertEqual(remaining_lease(self.value), 25)
        self.assertEqual(self.value["expires_mono"], 1030)
