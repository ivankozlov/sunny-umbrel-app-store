from __future__ import annotations

import asyncio
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List

from .contracts import validate_digest_text
from .models import DigestChat
from .prompting import render_digest_prompt
from .storage import canonical_json_bytes


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# Запрос обязан идти через тот же VPN, что и Telegram. Прямой выход из
# домашней сети возвращает HTTP 403 от фильтра на маршруте, и дайджест не
# собирается ни разу (инцидент 2026-08-17: monitor работал, digest падал
# OpenRouterError каждые пять минут). Прокси — HTTP-listener Mihomo; DIRECT
# fallback'а здесь нет и быть не должно: без туннеля запрос всё равно не
# пройдёт, а тихий обход маскировал бы поломку VPN.
#
# Пиннится на самом Request через set_proxy, а НЕ через ProxyHandler: тот
# спрашивает urllib.request.proxy_bypass, и `no_proxy=*` в окружении вернул бы
# запрос на прямой путь — то есть ровно ту поломку, ради которой этот прокси и
# появился, только молча.
OPENROUTER_PROXY = "127.0.0.1:7892"
MAX_RESPONSE_BYTES = 128 * 1024
MAX_WORKER_REQUEST_BYTES = 128 * 1024
WORKER_SCHEMA = "sunny.personal-chats.openrouter-worker.v2"
WORKER_TERMINATE_GRACE_S = 2.0


class OpenRouterError(RuntimeError):
    pass


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Не следовать за 3xx.

    Редирект создаётся новым Request без нашего set_proxy, поэтому поход по
    Location ушёл бы мимо туннеля, а на `http://` унёс бы ещё и bearer-ключ
    открытым текстом. Легитимных редиректов у completions-эндпоинта нет:
    отказ превращается в HTTPError и дальше в OpenRouterError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _prompt(chats: List[DigestChat]) -> str:
    try:
        return render_digest_prompt(chats)
    except ValueError as exc:
        raise OpenRouterError("prompt exceeds bounded input size") from exc


def _blocking_digest_prompt(prompt: str, model: str, api_key: str) -> str:
    request_body = canonical_json_bytes({
        "model": model,
        "provider": {
            "zdr": True,
            "data_collection": "deny",
        },
        "messages": [
            {"role": "system", "content": "You summarize only the supplied selected-groups text."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 16_384,
        "response_format": {"type": "json_object"},
    })
    request = urllib.request.Request(
        OPENROUTER_URL,
        data=request_body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "sunny-personal-chats/0.2",
            "HTTP-Referer": "https://github.com/ivankozlov/sunny-umbrel-app-store",
            "X-Title": "Sunny Personal Chats",
        },
    )
    # CONNECT на loopback-listener Mihomo; TLS до openrouter.ai остаётся
    # сквозным, прокси видит только имя хоста, но не тело и не bearer-ключ.
    request.set_proxy(OPENROUTER_PROXY, "https")
    opener = urllib.request.build_opener(_RefuseRedirects())
    try:
        with opener.open(request, timeout=90) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise OpenRouterError(f"OpenRouter transport failed: {type(exc).__name__}") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OpenRouterError("OpenRouter response exceeds size limit")
    try:
        body: Dict[str, Any] = json.loads(raw.decode("utf-8"))
        choices = body["choices"]
        choice = choices[0]
        if choice.get("finish_reason") != "stop":
            raise OpenRouterError("OpenRouter response did not finish cleanly")
        content = choice["message"]["content"]
        parsed = json.loads(content)
    except OpenRouterError:
        raise
    except (KeyError, IndexError, TypeError, ValueError, UnicodeDecodeError):
        raise OpenRouterError("OpenRouter response shape is invalid") from None
    if not isinstance(parsed, dict) or set(parsed) != {"digest"}:
        raise OpenRouterError("OpenRouter digest JSON has unexpected fields")
    digest = parsed["digest"]
    if not isinstance(digest, str):
        raise OpenRouterError("OpenRouter digest is not text")
    digest = digest.strip()
    try:
        validate_digest_text(digest, allow_empty=False)
    except ValueError as exc:
        raise OpenRouterError("OpenRouter digest text is invalid") from exc
    return digest


def _blocking_digest(chats: List[DigestChat], model: str, api_key: str) -> str:
    return _blocking_digest_prompt(_prompt(chats), model, api_key)


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
        raise OpenRouterError("OpenRouter worker pipes are unavailable")
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
        chunk = await process.stdout.read(min(8192, MAX_RESPONSE_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise OpenRouterError("OpenRouter worker response exceeds size limit")
    await process.wait()
    return b"".join(chunks)


async def create_digest(chats: List[DigestChat], model: str, api_key: str,
                        revoked: asyncio.Event) -> str:
    if not chats or not any(chat.messages for chat in chats):
        return ""
    if revoked.is_set():
        raise asyncio.CancelledError
    request = canonical_json_bytes({
        "schema": WORKER_SCHEMA,
        "prompt": _prompt(chats),
        "model": model,
        "api_key": api_key,
    }) + b"\n"
    if len(request) > MAX_WORKER_REQUEST_BYTES:
        raise OpenRouterError("OpenRouter worker request exceeds size limit")
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "sunny_digest.openrouter_worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    exchange = asyncio.create_task(_bounded_worker_exchange(process, request))
    cancelled = asyncio.create_task(revoked.wait())
    try:
        done, _ = await asyncio.wait(
            (exchange, cancelled), timeout=100,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancelled in done and revoked.is_set():
            raise asyncio.CancelledError
        if exchange not in done:
            raise OpenRouterError("OpenRouter worker timed out")
        raw = exchange.result()
        if process.returncode != 0:
            raise OpenRouterError("OpenRouter worker failed")
    except BaseException:
        # Reset can signal revocation and cancel this task almost together.
        # Repeated cancellation must not strand a worker containing the API key
        # and raw chat prompt, so TERM/KILL/reap lives in a shielded task.
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
        raise OpenRouterError("OpenRouter worker response is invalid") from None
    if not isinstance(response, dict) or set(response) != {"digest"}:
        raise OpenRouterError("OpenRouter worker response is invalid")
    try:
        return validate_digest_text(response["digest"], allow_empty=False)
    except ValueError:
        raise OpenRouterError("OpenRouter worker digest is invalid") from None
