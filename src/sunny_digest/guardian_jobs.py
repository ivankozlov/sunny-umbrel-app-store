"""Guardian-owned single-job mailbox; polling has no collection side effects."""
from __future__ import annotations

import asyncio
import base64
import copy
import time
import uuid

from .contracts import validate_llm_usage
from .job_contracts import JOB_SCHEMA, validate_job, validate_result
from .model_lease import boottime, remaining_lease
from .openrouter import (
    DigestText, OpenRouterError, FALLBACK_MODEL, is_refusal,
    _render_and_validate, NOTHING_NOTABLE,
)
from .prompting import render_digest_prompt


class JobBroker:
    def __init__(self, *, clock=time.monotonic, boot_clock=boottime):
        self.clock, self.boot_clock = clock, boot_clock
        self.active = None
        self.cleanup_unconfirmed = False

    def _remaining(self, job):
        return remaining_lease(job, monotonic=self.clock, boot_clock=self.boot_clock)

    def _active(self, current):
        if current is None or current["cancelled"]:
            return False
        if self._remaining(current["job"]) <= 0:
            current["cancelled"] = True
            if not current["future"].done():
                current["future"].cancel()
            return False
        return True

    async def request(self, job: dict) -> dict:
        validate_job(job)
        if self.active is not None or self.cleanup_unconfirmed or self._remaining(job) <= 0:
            raise OpenRouterError("model job unavailable", "worker_failed")
        future = asyncio.get_running_loop().create_future()
        self.active = {"job": copy.deepcopy(job), "delivered": False,
                       "cancelled": False, "future": future,
                       "reaped": asyncio.Event()}
        current = self.active
        try:
            while True:
                remaining = self._remaining(current["job"])
                if remaining <= 0:
                    raise asyncio.TimeoutError
                try:
                    return await asyncio.wait_for(asyncio.shield(future), min(.5, remaining))
                except asyncio.TimeoutError:
                    # asyncio timers use monotonic time, which stops in Linux
                    # suspend. Recheck BOOTTIME as soon as the host resumes.
                    pass
        finally:
            current["cancelled"] = True
            if not future.done():
                future.cancel()
            interrupted = False
            if current["delivered"]:
                async def cleanup():
                    try:
                        await asyncio.wait_for(current["reaped"].wait(), 10)
                    except asyncio.TimeoutError:
                        # The ACK is cooperation, not proof against a compromised
                        # worker. Missing ACKs are never reported as cleanup.
                        self.cleanup_unconfirmed = True
                reaper = asyncio.create_task(cleanup())
                while not reaper.done():
                    try:
                        await asyncio.shield(reaper)
                    except asyncio.CancelledError:
                        interrupted = True
                reaper.result()
            if self.active is current:
                self.active = None
            if interrupted:
                raise asyncio.CancelledError

    def next_job(self):
        current = self.active
        if not self._active(current) or current["delivered"]:
            return {"job": None}
        current["delivered"] = True
        return {"job": copy.deepcopy(current["job"])}

    def status(self, job_id: str):
        current = self.active
        return {"active": bool(self._active(current) and current["job"]["job_id"] == job_id)}

    def result(self, value: dict):
        value = validate_result(value)
        current = self.active
        if (not self._active(current) or not current["delivered"]
                or any(value[k] != current["job"][k] for k in ("job_id", "security_epoch", "model"))
                or current["future"].done()):
            raise ValueError("model result is stale or repeated")
        # The worker submits only after stopping its tunnel and reaping the child.
        current["reaped"].set()
        current["future"].set_result(value)
        return {"accepted": True}

    def reaped(self, job_id: str):
        current = self.active
        if current is None or current["job"]["job_id"] != job_id:
            raise ValueError("unknown model job")
        current["reaped"].set()
        return {"accepted": True}

    async def cancel(self):
        current = self.active
        if current is not None:
            current["cancelled"] = True
            if not current["future"].done():
                current["future"].cancel()


class RemoteDigest:
    def __init__(self, guardian):
        self.guardian = guardian

    async def __call__(self, chats, model, api_key, revoked, before_fallback=None, layout=None):
        if revoked.is_set():
            raise asyncio.CancelledError
        prompt = render_digest_prompt(chats)
        try:
            return await self.attempt(chats, prompt, model, api_key, revoked, layout)
        except OpenRouterError as exc:
            if model == FALLBACK_MODEL or not is_refusal(exc.failure):
                raise
        if before_fallback is not None:
            await before_fallback()
        result = await self.attempt(chats, prompt, FALLBACK_MODEL, api_key, revoked, layout)
        return DigestText(str(result), getattr(result, "llm_usage", None),
                          model=FALLBACK_MODEL, fallback_after_refusal=True)

    async def attempt(self, chats, prompt, model, api_key, revoked, layout):
        g = self.guardian
        paths = g.engine.paths
        snapshot = g.vault.snapshot
        from .settings import load_settings
        settings = load_settings(paths)
        remaining = g.model_seconds_left()
        if remaining <= 0 or revoked.is_set():
            raise asyncio.CancelledError
        budget = min(235, remaining)
        expires_mono = g.jobs.clock() + budget
        _, _, gate_mono, gate_boot = g._gate_pair
        job = {
            "schema": JOB_SCHEMA, "job_id": str(uuid.uuid4()),
            "security_epoch": snapshot["security_epoch"], "model": model,
            "prompt": prompt, "timeout_s": min(210, max(1, int(remaining))),
            "expires_mono": expires_mono,
            # Anchor both clocks to the receiver gate, not to job creation:
            # a suspend between the policy check and issuance must not renew it.
            "expires_boot": expires_mono + (gate_boot - gate_mono),
            "model_access": {
                "api_key": api_key, "tunnel_key": base64.b64encode(paths.openrouter_key.read_bytes()).decode("ascii"),
                "known_hosts": paths.known_hosts.read_text("ascii"),
                "host": settings["upload"]["host"], "port": settings["upload"]["port"],
            },
        }
        result = await g.jobs.request(job)
        if (g.vault.snapshot["security_epoch"] != snapshot["security_epoch"]
                or revoked.is_set() or g.model_seconds_left() <= 0):
            raise asyncio.CancelledError
        if result["outcome"] == "error":
            raise OpenRouterError("model request failed", **result["failure"])
        response = result["response"]
        try:
            text = _render_and_validate(response["answer"], chats, layout)
            if text == NOTHING_NOTABLE and response.get("meta", {}).get("recovered") is True:
                raise OpenRouterError("model returned empty recovered structure", "content_not_json", detail="empty_recovered")
            usage = validate_llm_usage(response["usage"]) if "usage" in response else None
        except OpenRouterError:
            raise
        except Exception:
            raise OpenRouterError("model structure is invalid", "structure_invalid") from None
        return DigestText(text, usage, model=model)


class ModelTunnelBoundary:
    """Compatibility seam: tunnel lifetime belongs to the isolated model role."""
    def __init__(self, *_):
        pass
    async def start(self):
        pass
    def ensure_alive(self):
        pass
    async def stop(self):
        pass
