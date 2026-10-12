from __future__ import annotations

import asyncio
import base64
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from sunny_digest.guardian_ipc import dispatch
from sunny_digest.guardian_jobs import JobBroker
from sunny_digest.job_contracts import (
    JOB_SCHEMA, RESULT_SCHEMA, strict_json, validate_job, validate_result,
)
from sunny_digest.openrouter import OPUS_55_MODEL, OpenRouterError
from sunny_digest.model_lease import boottime


def job():
    kind = b"ssh-ed25519"
    blob = len(kind).to_bytes(4, "big") + kind + (32).to_bytes(4, "big") + b"x" * 32
    return {
        "schema": JOB_SCHEMA, "job_id": str(uuid.uuid4()), "security_epoch": 3,
        "model": OPUS_55_MODEL, "prompt": "bounded synthetic prompt", "timeout_s": 10,
        "expires_mono": time.monotonic() + 30,
        "expires_boot": boottime() + 30,
        "model_access": {"api_key": "synthetic-model-key", "host": "receiver.example",
                         "port": 22, "known_hosts": "receiver.example ssh-ed25519 " + base64.b64encode(blob).decode() + "\n",
                         "tunnel_key": base64.b64encode(b"synthetic-key" * 10).decode()},
    }


def result(value):
    return {"schema": RESULT_SCHEMA, "job_id": value["job_id"],
            "security_epoch": value["security_epoch"], "model": value["model"],
            "outcome": "ok", "response": {"answer": {"chats": []}}}


class TestJobContracts(unittest.TestCase):
    def test_json_and_job_are_closed_and_bounded(self):
        for raw in (b'{"a":1,"a":2}', b'{"value":NaN}', b'[]', b'{}' * (512 * 1024)):
            with self.subTest(raw=raw[:32]), self.assertRaises(ValueError):
                strict_json(raw)
        for mutation in (
                lambda value: value.update(telegram_method="fetch"),
                lambda value: value.update(security_epoch=True),
                lambda value: value.update(expires_mono=float("inf")),
                lambda value: value.update(expires_boot=float("nan")),
                lambda value: value.update(expires_boot=True),
                lambda value: value.update(prompt="x" * (96 * 1024 + 1)),
                lambda value: value["model_access"].update(upload_key="secret"),
                lambda value: value["model_access"].update(command="shell"),
                lambda value: value["model_access"].update(known_hosts=123),
                lambda value: value.update(model="unapproved/model")):
            value = job(); mutation(value)
            with self.assertRaises(ValueError):
                validate_job(value)
        self.assertEqual(validate_job(job())["security_epoch"], 3)

    def test_result_rejects_delivery_state_and_provider_text_in_failures(self):
        for field in ("chat_ids", "cursors", "gate", "sequence", "upload_key"):
            value = result(job()); value[field] = "untrusted"
            with self.assertRaises(ValueError): validate_result(value)
        value = result(job()); value.update(outcome="error", failure={"code": "worker_failed", "raw_body": "private"})
        value.pop("response")
        with self.assertRaises(ValueError): validate_result(value)


class TestJobBroker(unittest.IsolatedAsyncioTestCase):
    async def test_missing_cleanup_ack_is_terminal_and_repeated_cancel_waits(self):
        broker = JobBroker(); value = job()
        native_wait_for = asyncio.wait_for
        async def bounded_wait(awaitable, timeout):
            return await native_wait_for(awaitable, .02 if timeout == 10 else timeout)
        with patch("sunny_digest.guardian_jobs.asyncio.wait_for", side_effect=bounded_wait):
            task = asyncio.create_task(broker.request(value))
            await asyncio.sleep(0); broker.next_job(); task.cancel()
            await asyncio.sleep(0); task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
        self.assertTrue(broker.cleanup_unconfirmed)
        self.assertIsNone(broker.active)
        with self.assertRaises(OpenRouterError):
            await broker.request(job())

    async def test_single_delivery_and_canonical_result_identity(self):
        broker = JobBroker(); value = job()
        task = asyncio.create_task(broker.request(value))
        await asyncio.sleep(0)
        fetched = broker.next_job()["job"]
        self.assertIsNotNone(fetched)
        fetched["prompt"] = "tampered client object"
        self.assertEqual(broker.active["job"]["prompt"], value["prompt"])
        self.assertIsNone(broker.next_job()["job"])
        for field in ("job_id", "security_epoch", "model"):
            bad = result(value)
            bad[field] = str(uuid.uuid4()) if field == "job_id" else 4 if field == "security_epoch" else "z-ai/glm-5.3"
            with self.assertRaises(ValueError): broker.result(bad)
        broker.result(result(value))
        self.assertEqual(await task, result(value))
        with self.assertRaises(ValueError): broker.result(result(value))
        self.assertIsNone(broker.active)

    async def test_revoke_waits_for_worker_cleanup_ack_and_refuses_late_result(self):
        broker = JobBroker(); value = job()
        task = asyncio.create_task(broker.request(value))
        await asyncio.sleep(0); broker.next_job()
        await broker.cancel()
        self.assertFalse(broker.status(value["job_id"])["active"])
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        with self.assertRaises(ValueError): broker.result(result(value))
        broker.reaped(value["job_id"])
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertFalse(broker.cleanup_unconfirmed)

    async def test_expired_undelivered_job_never_reaches_a_worker(self):
        clock = [1000.0]
        broker = JobBroker(clock=lambda: clock[0], boot_clock=lambda: clock[0]); value = job()
        value.update(expires_mono=1001.0, expires_boot=1001.0)
        task = asyncio.create_task(broker.request(value)); await asyncio.sleep(0)
        clock[0] = 1002.0
        self.assertIsNone(broker.next_job()["job"])
        await broker.cancel()
        with self.assertRaises(asyncio.CancelledError): await task

    async def test_jobs_role_cannot_invoke_telegram_admin_or_bootstrap(self):
        guardian = SimpleNamespace(jobs=JobBroker())
        for uid in (1000, 1002):
            with self.assertRaises(PermissionError):
                await dispatch(guardian, "jobs", uid, {"command": "next_job"})
        for command in ("configure", "operation_finish", "console_bootstrap", "status", "fetch", "ack", "run_now"):
            with self.assertRaises((PermissionError, ValueError)):
                await dispatch(guardian, "jobs", 1001, {"command": command, "data": {"job_id": str(uuid.uuid4())}})
        self.assertEqual(await dispatch(guardian, "jobs", 1001, {"command": "next_job"}), {"job": None})


class TestModelRoleCancellation(unittest.IsolatedAsyncioTestCase):
    async def test_job_result_is_submitted_only_after_fetch_cleanup(self):
        from sunny_digest.model_collector import run_job
        trace = []
        value = job()
        async def fetch(*_):
            trace.extend(("fetch", "reaped"))
            return result(value)
        class Client:
            def request(self, command, data):
                trace.append(command)
                return {"active": True}
        with patch("sunny_digest.model_collector.fetch_job", side_effect=fetch):
            await run_job(Client(), value, None)
        self.assertLess(trace.index("reaped"), trace.index("job_result"))
        self.assertIn("job_reaped", trace)

    async def test_revoked_job_cancels_fetch_then_acknowledges_cleanup(self):
        from sunny_digest.model_collector import run_job
        trace = []
        entered = asyncio.Event()
        async def fetch(*_):
            entered.set()
            try: await asyncio.Event().wait()
            finally: trace.append("reaped")
        class Client:
            def request(self, command, data):
                trace.append(command)
                return {"active": False}
        with patch("sunny_digest.model_collector.fetch_job", side_effect=fetch):
            await run_job(Client(), job(), None)
        self.assertNotIn("job_result", trace)
        self.assertLess(trace.index("reaped"), trace.index("job_reaped"))
