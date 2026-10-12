from __future__ import annotations

import asyncio
import unittest

from sunny_digest.guardian import Guardian
from tests.test_guardian import Clock


class TestGuardianScheduler(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_collection_keeps_scheduler_and_run_now_preserves_cadence(self):
        clock = Clock()
        guardian = object.__new__(Guardian)
        guardian.clock = clock
        guardian._admin_lock = asyncio.Lock()
        guardian._wakeup = asyncio.Event()
        guardian.exit_requested = asyncio.Event()
        guardian._service_requested = False
        guardian._next_tick = clock()
        guardian._tick_task = None
        guardian.jobs = type("Jobs", (), {"cleanup_unconfirmed": False})()
        entered = asyncio.Event()
        calls = []
        class Engine:
            async def run_once(self):
                calls.append(clock())
                entered.set()
                if len(calls) == 1:
                    await asyncio.Event().wait()
        guardian.engine = Engine()
        async def status(): return {}
        guardian.status = status
        scheduler = asyncio.create_task(guardian.scheduler())
        try:
            await asyncio.wait_for(entered.wait(), 1)
            guardian._tick_task.cancel()
            for _ in range(20):
                await asyncio.sleep(0)
                if guardian._tick_task is None: break
            self.assertFalse(scheduler.done())
            self.assertEqual(guardian._next_tick, clock() + 300)
            clock.value += 100
            guardian.trigger_run()
            await asyncio.sleep(.01)
            self.assertEqual(len(calls), 1)
            clock.value += 200
            guardian.trigger_run()
            for _ in range(20):
                await asyncio.sleep(0)
                if len(calls) == 2: break
            self.assertEqual(len(calls), 2)
        finally:
            scheduler.cancel()
            with self.assertRaises(asyncio.CancelledError): await scheduler
