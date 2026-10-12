"""Unprivileged model role: receives a frozen job; cannot trigger collection."""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from .job_contracts import validate_job, RESULT_SCHEMA
from .model_lease import require_lease, remaining_lease
from .openrouter import (
    OpenRouterError, WORKER_SCHEMA, WORKER_FAILURE_EXIT,
    _bounded_worker_exchange, _cleanup_failed_worker, _worker_failure,
)
from .openrouter_tunnel import OpenRouterTunnel
from .secret_files import secret_files, clean_secret_scratch
from .storage import canonical_json_bytes, atomic_write_bytes
from .web import IPCClient


async def fetch_job(job: dict, scratch: Path) -> dict:
    job = validate_job(job)
    require_lease(job)
    access = job["model_access"]
    response = {
        "schema": RESULT_SCHEMA, "job_id": job["job_id"],
        "security_epoch": job["security_epoch"], "model": job["model"],
    }
    try:
        with secret_files(scratch, {
            "identity": base64.b64decode(access["tunnel_key"], validate=True),
            "known_hosts": access["known_hosts"].encode("ascii"),
        }) as files:
            tunnel = OpenRouterTunnel(
                SimpleNamespace(openrouter_key=files["identity"], known_hosts=files["known_hosts"], guarded_native=True),
                {"host": access["host"], "port": access["port"]})
            await tunnel.start()
            try:
                require_lease(job)
                request = canonical_json_bytes({
                    "schema": WORKER_SCHEMA, "prompt": job["prompt"],
                    "model": job["model"], "api_key": access["api_key"],
                    "lease": {key: job[key] for key in ("expires_mono", "expires_boot")},
                }) + b"\n"
                process = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "sunny_digest.openrouter_worker",
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
                exchange = asyncio.create_task(_bounded_worker_exchange(process, request))
                try:
                    raw = await asyncio.wait_for(exchange, job["timeout_s"])
                    if process.returncode == WORKER_FAILURE_EXIT:
                        raise OpenRouterError("model failed", **_worker_failure(raw))
                    if process.returncode != 0:
                        raise OpenRouterError("model worker failed", "worker_failed")
                    from .job_contracts import strict_json
                    result = strict_json(raw)
                    tunnel.ensure_alive()
                    response.update(outcome="ok", response=result)
                except BaseException:
                    cleanup = asyncio.create_task(_cleanup_failed_worker(process, exchange))
                    while not cleanup.done():
                        try:
                            await asyncio.shield(cleanup)
                        except asyncio.CancelledError:
                            pass
                    cleanup.result()
                    raise
            finally:
                await tunnel.stop()
    except Exception as exc:
        failure = exc.failure if isinstance(exc, OpenRouterError) else {"code": "worker_failed"}
        response.update(outcome="error", failure=failure)
    return response


async def run_job(client, job, scratch):
    job = validate_job(job)
    async def bounded_fetch():
        remaining = require_lease(job)
        return await asyncio.wait_for(fetch_job(job, scratch), remaining)
    task = asyncio.create_task(bounded_fetch())
    async def watch():
        while True:
            if remaining_lease(job) <= 0:
                return
            status = await asyncio.to_thread(client.request, "job_status", {"job_id": job["job_id"]})
            if status.get("active") is not True:
                return
            await asyncio.sleep(0.5)
    guard = asyncio.create_task(watch())
    try:
        done, _ = await asyncio.wait((task, guard), return_when=asyncio.FIRST_COMPLETED)
        if guard in done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return
        result = task.result()
        require_lease(job)
        await asyncio.to_thread(client.request, "job_result", result)
    finally:
        guard.cancel()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, guard, return_exceptions=True)
        try:
            await asyncio.to_thread(client.request, "job_reaped", {"job_id": job["job_id"]})
        except Exception:
            pass


def serve() -> None:
    scratch = Path(os.environ.get("SUNNY_SCRATCH_DIR", "/run/collector-private"))
    clean_secret_scratch(scratch)
    client = IPCClient(os.environ.get("SUNNY_JOBS_SOCKET", "/data/ipc/jobs.sock"))
    while True:
        atomic_write_bytes(scratch / "heartbeat", b"ok\n")
        try:
            result = client.request("next_job")
            job = result.get("job")
            if job is not None:
                asyncio.run(run_job(client, job, scratch))
        except Exception:
            # No provider text, prompt, credentials or socket payload in logs.
            pass
        time.sleep(1)
