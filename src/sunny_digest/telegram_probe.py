from __future__ import annotations

import asyncio
import json
import re
import sys
from typing import Any

from .storage import canonical_json_bytes


WORKER_SCHEMA = "sunny.personal-chats.telegram-probe-worker.v2"
MAX_WORKER_REQUEST_BYTES = 16 * 1024
MAX_WORKER_RESPONSE_BYTES = 128
WORKER_TIMEOUT_S = 20.0
WORKER_TERMINATE_GRACE_S = 2.0


class TelegramProbeError(RuntimeError):
    pass


async def _terminate_worker_inner(process: Any) -> None:
    try:
        process.terminate()
    except ProcessLookupError:
        await process.wait()
        return
    try:
        await asyncio.wait_for(
            process.wait(), timeout=WORKER_TERMINATE_GRACE_S)
    except (asyncio.TimeoutError, ProcessLookupError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()


async def _cleanup_failed_worker(
    process: Any, exchange: asyncio.Task[Any],
) -> None:
    try:
        await _terminate_worker_inner(process)
    finally:
        if not exchange.done():
            exchange.cancel()
        try:
            await exchange
        except BaseException:
            pass


async def _bounded_worker_exchange(process: Any, request: bytes) -> bytes:
    if process.stdin is None or process.stdout is None:
        raise TelegramProbeError("Telegram probe worker pipes are unavailable")
    process.stdin.write(request)
    await process.stdin.drain()
    process.stdin.close()
    try:
        await process.stdin.wait_closed()
    except (AttributeError, BrokenPipeError, ConnectionResetError):
        pass
    chunks = []
    size = 0
    while True:
        chunk = await process.stdout.read(
            min(128, MAX_WORKER_RESPONSE_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_WORKER_RESPONSE_BYTES:
            raise TelegramProbeError("Telegram probe worker response is oversized")
    await process.wait()
    return b"".join(chunks)


def _worker_request(api_id: int, api_hash: str, session_text: str) -> bytes:
    if isinstance(api_id, bool) or type(api_id) is not int or api_id <= 0:
        raise TelegramProbeError("Telegram probe credentials are invalid")
    if not isinstance(api_hash, str) or not re.fullmatch(r"[0-9a-f]{32}", api_hash):
        raise TelegramProbeError("Telegram probe credentials are invalid")
    if (
        not isinstance(session_text, str)
        or not session_text
        or len(session_text) > 8192
        or "\n" in session_text
        or "\r" in session_text
    ):
        raise TelegramProbeError("Telegram probe session is invalid")
    try:
        session_text.encode("ascii")
    except UnicodeEncodeError:
        raise TelegramProbeError("Telegram probe session is invalid") from None
    request = canonical_json_bytes({
        "schema": WORKER_SCHEMA,
        "api_id": api_id,
        "api_hash": api_hash,
        "session": session_text,
    }) + b"\n"
    if len(request) > MAX_WORKER_REQUEST_BYTES:
        raise TelegramProbeError("Telegram probe request is oversized")
    return request


async def probe_telegram_session(
    api_id: int,
    api_hash: str,
    session_text: str,
    revoked: asyncio.Event,
) -> bool:
    """Probe one existing Telegram session in a killable child process."""
    if revoked.is_set():
        raise asyncio.CancelledError
    request = _worker_request(api_id, api_hash, session_text)
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "sunny_digest.telegram_probe_worker",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        raise TelegramProbeError("Telegram probe worker failed to start") from None
    exchange = asyncio.create_task(_bounded_worker_exchange(process, request))
    cancelled = asyncio.create_task(revoked.wait())
    try:
        done, _ = await asyncio.wait(
            (exchange, cancelled),
            timeout=WORKER_TIMEOUT_S,
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Revocation wins even if it lands after asyncio.wait captured its
        # completed-task snapshot but before this coroutine resumes.
        if revoked.is_set():
            raise asyncio.CancelledError
        if exchange not in done:
            raise TelegramProbeError("Telegram authorization probe timed out")
        raw = exchange.result()
        if process.returncode != 0:
            raise TelegramProbeError("Telegram authorization probe failed")
    except BaseException:
        cleanup = asyncio.create_task(_cleanup_failed_worker(process, exchange))
        cleanup_cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cleanup_cancelled = True
        cleanup.result()
        if cleanup_cancelled:
            raise asyncio.CancelledError
        raise
    finally:
        cancelled.cancel()
        await asyncio.gather(cancelled, return_exceptions=True)
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TelegramProbeError("Telegram probe worker response is invalid") from None
    if (
        not isinstance(response, dict)
        or set(response) != {"authorized"}
        or type(response["authorized"]) is not bool
    ):
        raise TelegramProbeError("Telegram probe worker response is invalid")
    if raw != canonical_json_bytes(response) + b"\n":
        raise TelegramProbeError("Telegram probe worker response is invalid")
    return response["authorized"]
