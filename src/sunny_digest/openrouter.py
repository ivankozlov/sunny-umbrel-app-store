from __future__ import annotations

import asyncio
import json
import math
import re
import sys
import http.client
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .contracts import validate_digest_text, validate_llm_usage
from .openrouter_tunnel import TUNNEL_HOST, TUNNEL_PORT
from .models import DigestChat
from .prompting import (
    digest_sender_names,
    digest_sources,
    fit_by_lines,
    render_digest_prompt,
)
from .storage import canonical_json_bytes
from .version import MAX_DIGEST_CHARS


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
NOTHING_NOTABLE = "За сутки в чатах не было ничего существенного."
# Запрос обязан идти через DO: прямой путь из домашней сети отбивает фильтр
# (`Access denied by security policy`), а через VLESS-туннель Cloudflare
# отвечает 403 с любого узла (инцидент 2026-08-17/18). Дроплет openrouter.ai
# отдаёт штатно, поэтому соединение идёт сквозь ssh-форвард до него.
#
# Адрес локального конца туннеля, НЕ прокси: ssh форвардит на openrouter.ai:443
# напрямую, а TLS остаётся сквозным — ни DO, ни ssh тела запроса не видят.
# Имя хоста для проверки сертификата и SNI задаётся отдельно, иначе python
# проверял бы сертификат против 127.0.0.1 и соединение падало бы.
# Ответ теперь структурный и вмещает выпуск целиком: 24 000 UTF-16
# единиц кириллицы — это уже ~48 КБ UTF-8, плюс JSON-обвязка и
# экранирование. Потолок держится выше того, что физически способен
# выдать max_tokens, чтобы предел ставила модель, а не наш буфер.
MAX_RESPONSE_BYTES = 256 * 1024
MAX_WORKER_REQUEST_BYTES = 128 * 1024
# v3: воркер отдаёт СТРУКТУРУ ответа модели, а текст со ссылками
# собирает родитель. Карта «номер → t.me-ссылка» живёт только там,
# поэтому message_id и peer_id не попадают даже в подпроцесс.
WORKER_SCHEMA = "sunny.personal-chats.openrouter-worker.v3"
WORKER_TERMINATE_GRACE_S = 2.0
_SENDER_ALIAS = re.compile(r"(?<![\w-])participant-[1-9][0-9]*(?![\w-])")


class OpenRouterError(RuntimeError):
    pass


class DigestText(str):
    """Текст выпуска с обезличенной provider-телеметрией одного вызова."""

    llm_usage: Dict[str, Any]

    def __new__(cls, value: str, llm_usage: Dict[str, Any]):
        instance = super().__new__(cls, value)
        instance.llm_usage = llm_usage
        return instance


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Не следовать за 3xx.

    Редирект создаётся новым Request без нашего set_proxy, поэтому поход по
    Location ушёл бы мимо туннеля, а на `http://` унёс бы ещё и bearer-ключ
    открытым текстом. Легитимных редиректов у completions-эндпоинта нет:
    отказ превращается в HTTPError и дальше в OpenRouterError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _TunnelHTTPSConnection(http.client.HTTPSConnection):
    """TCP идёт на локальный конец форварда, TLS проверяется против openrouter.ai.

    Разделение обязательно: подменить `host` нельзя — по нему же открывается
    сокет, и запрос ушёл бы на openrouter.ai:7893. А проверять сертификат
    против 127.0.0.1 нельзя тем более: тогда любой, кто занял локальный порт,
    получил бы и запрос, и bearer-ключ."""

    def __init__(self, tls_host: str, **kwargs: Any) -> None:
        super().__init__(TUNNEL_HOST, TUNNEL_PORT, **kwargs)
        self._tls_host = tls_host

    def connect(self) -> None:
        sock = socket.create_connection(
            (TUNNEL_HOST, TUNNEL_PORT), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_host)


class _TunnelHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):  # noqa: ANN001
        def build(host: str, **kwargs: Any) -> http.client.HTTPSConnection:
            kwargs.pop("context", None)
            return _TunnelHTTPSConnection(
                host.split(":", 1)[0], context=ssl.create_default_context(), **kwargs)

        return self.do_open(build, req)


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _clean(value: Any, limit: int) -> str:
    """Строка из ответа модели: обрезаем и чистим, но не доверяем длине."""
    if not isinstance(value, str):
        raise OpenRouterError("OpenRouter digest field is not text")
    text = " ".join(value.split())
    return text[:limit]


def _link(sources: Dict[int, str], ref: Any) -> Optional[str]:
    """Ссылка по номеру, названному моделью.

    `isinstance(True, int)` — истина, поэтому bool отсекается явно: `ref: true`
    иначе дал бы ссылку на ПЕРВОЕ сообщение прогона. Строку с цифрами принимаем
    (модели легко отдают "12" вместо 12), всё остальное — не источник."""
    if isinstance(ref, bool):
        return None
    if isinstance(ref, str) and ref.isdigit():
        ref = int(ref)
    if not isinstance(ref, int):
        return None
    return sources.get(ref)


def _restore_sender_names(value: Any, names: Dict[str, str]) -> Any:
    if not isinstance(value, str) or not names:
        return value
    return _SENDER_ALIAS.sub(
        lambda match: names.get(match.group(0), match.group(0)), value)


def render_digest(
    parsed: Any,
    sources: Dict[int, str],
    sender_names: Optional[Dict[str, Dict[str, str]]] = None,
) -> str:
    """Собрать текст выпуска из структурированного ответа.

    Ссылки подставляет КОД по порядковым номерам: модель их не пишет и
    Telegram-идентификаторов не видит. Номер вне карты источников молча
    отбрасывается — выдуманная моделью ссылка не должна дойти до Ивана.
    Ссылка стоит отдельной строкой: доставка снимает markdown, а голый URL
    Telegram делает кликабельным сам."""
    if not isinstance(parsed, dict) or set(parsed) != {"chats"}:
        raise OpenRouterError("OpenRouter digest JSON has unexpected fields")
    chats = parsed["chats"]
    if not isinstance(chats, list):
        raise OpenRouterError("OpenRouter digest chats are invalid")

    blocks = []
    for chat in chats:
        if not isinstance(chat, dict) or set(chat) - {"chat", "topics", "links"}:
            raise OpenRouterError("OpenRouter digest chat is invalid")
        title = _clean(chat.get("chat", ""), 160)
        names = (sender_names or {}).get(title, {})
        topics = chat.get("topics") or []
        links = chat.get("links") or []
        if not isinstance(topics, list) or not isinstance(links, list):
            raise OpenRouterError("OpenRouter digest sections are invalid")

        lines = []
        for topic in topics:
            if not isinstance(topic, dict):
                raise OpenRouterError("OpenRouter digest topic is invalid")
            topic_title = _clean(
                _restore_sender_names(topic.get("title", ""), names), 200)
            lines.append(f"▸ {topic_title}")
            summary = _clean(
                _restore_sender_names(topic.get("summary", ""), names), 4000)
            if summary:
                lines.append(summary)
            refs = topic.get("refs") or []
            if isinstance(refs, list):
                for ref in refs[:5]:
                    link = _link(sources, ref)
                    if link:
                        lines.append(link)
            lines.append("")

        link_lines = []
        for row in links:
            if not isinstance(row, dict):
                raise OpenRouterError("OpenRouter digest link is invalid")
            note = _clean(
                _restore_sender_names(row.get("note", ""), names), 400)
            entry = _clean(
                _restore_sender_names(row.get("title", ""), names), 200)
            link_lines.append(f"• {entry}" + (f" — {note}" if note else ""))
            ref = row.get("ref")
            link = _link(sources, ref)
            if link:
                link_lines.append(f"  {link}")

        if not lines and not link_lines:
            continue
        block = [f"**{title}**", ""] if title else []
        block.extend(lines)
        if link_lines:
            block.append("📎 Ссылки и материалы")
            block.extend(link_lines)
            block.append("")
        blocks.append("\n".join(block).strip())

    if not blocks:
        # Промпт прямо разрешает «за сутки ничего стоящего»: пустые списки у
        # каждого чата — это ответ, а не сбой. Отказ здесь оборачивался бы
        # ночным `missing_daily_digest` вместо честного тихого дня. Но пустой
        # `chats` — уже не ответ: модель не прошла ни по одному чату.
        if not chats:
            raise OpenRouterError("OpenRouter digest has no chats")
        return NOTHING_NOTABLE
    text = "\n\n".join(blocks).strip()
    if _utf16_units(text) <= MAX_DIGEST_CHARS:
        return text
    # Модель может выдать больше, чем помещается в потолок дайджеста: тем
    # много, каждая обрезана по отдельности, а их сумма никем не гейтится.
    # Ронять из-за этого весь выпуск — худший исход, чем отдать начало.
    fitted = fit_by_lines(text, _utf16_units, MAX_DIGEST_CHARS)
    if fitted is None:
        raise OpenRouterError("OpenRouter digest text is invalid")
    return fitted


def _prompt(chats: List[DigestChat]) -> str:
    try:
        return render_digest_prompt(chats)
    except ValueError as exc:
        raise OpenRouterError("prompt exceeds bounded input size") from exc


def _usage_summary(value: Any) -> Dict[str, Any]:
    usage = value if isinstance(value, dict) else {}
    details = usage.get("completion_tokens_details")
    if not isinstance(details, dict):
        details = {}
    cost_details = usage.get("cost_details")
    if not isinstance(cost_details, dict):
        cost_details = {}

    def tokens(raw: Any) -> Optional[int]:
        return raw if type(raw) is int and raw >= 0 else None

    def cost(raw: Any) -> Optional[float]:
        if (isinstance(raw, bool) or not isinstance(raw, (int, float))):
            return None
        number = float(raw)
        return number if math.isfinite(number) and number >= 0 else None

    return {
        "prompt_tokens": tokens(usage.get("prompt_tokens")),
        "completion_tokens": tokens(usage.get("completion_tokens")),
        "reasoning_tokens": tokens(details.get("reasoning_tokens")),
        "cost": cost(usage.get("cost")),
        "upstream_cost": cost(cost_details.get("upstream_inference_cost")),
    }


def blocking_fetch_response(
    prompt: str, model: str, api_key: str,
) -> Dict[str, Any]:
    """Запрос к OpenRouter: структура ответа и безопасная usage-сводка."""
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
        # Выпуск стал длиннее одного сообщения Telegram: 16 384 токена
        # адаптивное мышление Opus съедало почти целиком.
        "max_tokens": 32_768,
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
    opener = urllib.request.build_opener(
        _TunnelHTTPSHandler(), _RefuseRedirects())
    try:
        with opener.open(request, timeout=90) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException,
            OSError) as exc:
        # http.client.HTTPException и OSError тоже: упавший ssh-туннель рвёт
        # соединение как RemoteDisconnected/ConnectionReset, а это не URLError —
        # без них отказ канала улетал бы наружу необёрнутым и попадал в статус
        # чужим типом вместо OpenRouterError.
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
        usage = _usage_summary(body.get("usage"))
    except OpenRouterError:
        raise
    except (KeyError, IndexError, TypeError, ValueError, UnicodeDecodeError):
        raise OpenRouterError("OpenRouter response shape is invalid") from None
    return {"answer": parsed, "usage": usage}


def blocking_fetch_answer(prompt: str, model: str, api_key: str) -> Any:
    """Совместимый helper: вернуть только структуру ответа модели."""
    return blocking_fetch_response(prompt, model, api_key)["answer"]


def _render_and_validate(parsed: Any, chats: List[DigestChat]) -> str:
    digest = render_digest(
        parsed, digest_sources(chats), digest_sender_names(chats))
    try:
        validate_digest_text(digest, allow_empty=False)
    except ValueError as exc:
        raise OpenRouterError("OpenRouter digest text is invalid") from exc
    return digest


def _blocking_digest(chats: List[DigestChat], model: str, api_key: str) -> str:
    """Синхронный путь целиком — им пользуются тесты контракта запроса."""
    return _render_and_validate(
        blocking_fetch_answer(_prompt(chats), model, api_key), chats)


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
    if (not isinstance(response, dict)
            or set(response) not in ({"answer"}, {"answer", "usage"})):
        raise OpenRouterError("OpenRouter worker response is invalid")
    # Сборка текста и подстановка ссылок — здесь, а не в воркере: только у
    # родителя есть карта «номер → сообщение», и она никуда не уезжает.
    digest = _render_and_validate(response["answer"], chats)
    if "usage" not in response:
        return digest
    try:
        usage = validate_llm_usage(response["usage"])
    except ValueError as exc:
        raise OpenRouterError("OpenRouter worker usage is invalid") from exc
    return DigestText(digest, usage)
