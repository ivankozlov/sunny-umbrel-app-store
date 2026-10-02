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
    digest_material_urls,
    digest_sender_names,
    digest_sources,
    fit_by_lines,
    render_digest_prompt,
)
from .storage import canonical_json_bytes
from .version import MAX_DIGEST_CHARS


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPUS_55_MODEL = "anthropic/claude-opus-5.5"
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
_SENDER_ALIAS = re.compile(r"(?<![\w-])participant-[1-9][0-9]*(?![\w-])", re.IGNORECASE)


# Код отказа выпуска для статуса и журнала прогонов. 02.10.2026 тринадцать
# попыток подряд дошли до модели и были оплачены (~$0,18 каждая), но выпуск
# не собрался, а в статусе стояло только `OpenRouterError`: воркер на любой
# ошибке выходил с кодом 1, и HTTP-отказ, отказ модели и битая структура
# были неразличимы. Здесь — только служебные метаданные: ни текста ответа,
# ни сообщения провайдера, ни промпта.
WORKER_FAILURE_EXIT = 3
FAILURE_CODES = frozenset({
    "http_error", "provider_error", "transport_error", "response_too_large",
    "response_invalid", "finish_reason", "content_not_json",
    "structure_invalid", "no_chats", "text_invalid", "prompt_too_large",
    "worker_request_too_large", "worker_pipes", "worker_timeout",
    "worker_failed", "worker_response_invalid", "usage_invalid",
    "unclassified",
})
_FAILURE_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,31}\Z")
_FAILURE_DETAIL = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_FAILURE_PROVIDER = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._/()-]{0,47}\Z")
_GENERATION_ID = re.compile(r"[A-Za-z0-9_-]{1,96}\Z")


def _bounded_int(value: Any, low: int, high: int) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def _matching(value: Any, pattern: re.Pattern) -> Optional[str]:
    return value if isinstance(value, str) and pattern.match(value) else None


def sanitize_failure(value: Any) -> Optional[Dict[str, Any]]:
    """Закрытый набор полей отказа; всё непрошедшее проверку отбрасывается.

    Значения приходят от провайдера и через границу воркера, поэтому каждое
    поле сверяется с формой, а неизвестные ключи молча выпадают."""
    if not isinstance(value, dict) or value.get("code") not in FAILURE_CODES:
        return None
    checked = {
        "http_status": _bounded_int(value.get("http_status"), 100, 599),
        "finish_reason": _matching(value.get("finish_reason"), _FAILURE_TOKEN),
        "native_finish_reason": _matching(
            value.get("native_finish_reason"), _FAILURE_TOKEN),
        "detail": _matching(value.get("detail"), _FAILURE_DETAIL),
        "provider": _matching(value.get("provider"), _FAILURE_PROVIDER),
        "completion_tokens": _bounded_int(
            value.get("completion_tokens"), 0, 10_000_000),
        "generation_id": _matching(value.get("generation_id"), _GENERATION_ID),
    }
    failure = {"code": value["code"]}
    failure.update((key, item) for key, item in checked.items() if item is not None)
    return failure


def failure_label(failure: Optional[Dict[str, Any]]) -> Optional[str]:
    """Короткая стабильная метка для журнала: код и одно уточнение.

    Число токенов и id генерации сюда не входят намеренно: они различаются
    от попытки к попытке, и одинаковые отказы перестали бы схлопываться."""
    if not failure:
        return None
    extra = (failure.get("http_status") or failure.get("finish_reason")
             or failure.get("detail"))
    return f"{failure['code']}:{extra}" if extra else failure["code"]


class OpenRouterError(RuntimeError):
    def __init__(self, message: str, code: str = "unclassified",
                 **facts: Any) -> None:
        super().__init__(message)
        self.failure: Dict[str, Any] = (
            sanitize_failure({**facts, "code": code}) or {"code": "unclassified"})


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
        raise OpenRouterError(
            "OpenRouter digest field is not text", "structure_invalid",
            detail="field")
    text = " ".join(value.split())
    return text[:limit]


def _ref_number(ref: Any) -> Optional[int]:
    """Валидный сквозной номер сообщения из ответа модели."""
    if isinstance(ref, bool):
        return None
    if isinstance(ref, str) and ref.isdigit():
        ref = int(ref)
    return ref if isinstance(ref, int) else None


def _source_links(sources: Dict[int, str], material_urls: Dict[int, List[str]],
                  ref: Any) -> List[str]:
    """Прямые ссылки на материалы, затем ссылка на сообщение-источник.

    `isinstance(True, int)` — истина, поэтому bool отсекается явно: `ref: true`
    иначе дал бы ссылку на ПЕРВОЕ сообщение прогона. Строку с цифрами принимаем
    (модели легко отдают "12" вместо 12), всё остальное — не источник."""
    ref = _ref_number(ref)
    if ref is None:
        return []
    urls = list(material_urls.get(ref, []))
    return _mark_source_link(urls, sources.get(ref))


def _topic_links(sources: Dict[int, str], material_urls: Dict[int, List[str]],
                 refs: List[Any]) -> List[str]:
    """Материалы всех refs и один самый ранний доступный source permalink."""
    urls: List[str] = []
    source_ref = None
    for ref in refs:
        number = _ref_number(ref)
        if number is None:
            continue
        urls.extend(material_urls.get(number, []))
        if number in sources and (source_ref is None or number < source_ref):
            source_ref = number
    return _mark_source_link(urls, sources.get(source_ref))


def _mark_source_link(urls: List[str], source: Optional[str]) -> List[str]:
    # 25.09: материал тоже бывает ссылкой в Telegram, включая приватный чат.
    # Только родитель знает происхождение URL; hostname не доказывает source.
    links = list(dict.fromkeys(url for url in urls if url != source))
    if source:
        links.append(f"[Сообщение]({source})")
    return links


def _restore_sender_names(value: Any, names: Dict[str, str]) -> Any:
    if not isinstance(value, str) or not names:
        return value
    return _SENDER_ALIAS.sub(
        lambda match: names.get(match.group(0).lower(), match.group(0)), value)


def render_digest(
    parsed: Any,
    sources: Dict[int, str],
    sender_names: Optional[Dict[str, Dict[str, str]]] = None,
    material_urls: Optional[Dict[int, List[str]]] = None,
) -> str:
    """Собрать текст выпуска из структурированного ответа.

    Ссылки подставляет КОД по порядковым номерам: модель их не пишет и
    Telegram-идентификаторов не видит. Номер вне карты источников молча
    отбрасывается — выдуманная моделью ссылка не должна дойти до Ивана.
    Материалы стоят отдельными URL-строками, source — именованной ссылкой
    «Сообщение». Sunny превращает их в нативные Telegram entities."""
    if not isinstance(parsed, dict) or set(parsed) != {"chats"}:
        raise OpenRouterError(
            "OpenRouter digest JSON has unexpected fields", "structure_invalid",
            detail="top_fields")
    chats = parsed["chats"]
    if not isinstance(chats, list):
        raise OpenRouterError(
            "OpenRouter digest chats are invalid", "structure_invalid",
            detail="chats")

    blocks = []
    for chat in chats:
        if not isinstance(chat, dict) or set(chat) - {"chat", "topics", "links"}:
            raise OpenRouterError(
                "OpenRouter digest chat is invalid", "structure_invalid",
                detail="chat")
        title = _clean(chat.get("chat", ""), 160)
        names = (sender_names or {}).get(title, {})
        topics = chat.get("topics") or []
        links = chat.get("links") or []
        if not isinstance(topics, list) or not isinstance(links, list):
            raise OpenRouterError(
                "OpenRouter digest sections are invalid", "structure_invalid",
                detail="sections")

        lines = []
        for topic in topics:
            if not isinstance(topic, dict):
                raise OpenRouterError(
                    "OpenRouter digest topic is invalid", "structure_invalid",
                    detail="topic")
            topic_title = _clean(
                _restore_sender_names(topic.get("title", ""), names), 200)
            lines.append(f"▸ {topic_title}")
            summary = _clean(
                _restore_sender_names(topic.get("summary", ""), names), 4000)
            if summary:
                lines.append(summary)
            refs = topic.get("refs") or []
            if isinstance(refs, list):
                lines.extend(_topic_links(
                    sources, material_urls or {}, refs))
            lines.append("")

        link_lines = []
        for row in links:
            if not isinstance(row, dict):
                raise OpenRouterError(
                    "OpenRouter digest link is invalid", "structure_invalid",
                    detail="link")
            note = _clean(
                _restore_sender_names(row.get("note", ""), names), 400)
            entry = _clean(
                _restore_sender_names(row.get("title", ""), names), 200)
            link_lines.append(f"• {entry}" + (f" — {note}" if note else ""))
            ref = row.get("ref")
            for link in _source_links(sources, material_urls or {}, ref):
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
            raise OpenRouterError("OpenRouter digest has no chats", "no_chats")
        return NOTHING_NOTABLE
    text = "\n\n".join(blocks).strip()
    if _utf16_units(text) <= MAX_DIGEST_CHARS:
        return text
    # Модель может выдать больше, чем помещается в потолок дайджеста: тем
    # много, каждая обрезана по отдельности, а их сумма никем не гейтится.
    # Ронять из-за этого весь выпуск — худший исход, чем отдать начало.
    fitted = fit_by_lines(text, _utf16_units, MAX_DIGEST_CHARS)
    if fitted is None:
        raise OpenRouterError("OpenRouter digest text is invalid", "text_invalid")
    return fitted


def _prompt(chats: List[DigestChat]) -> str:
    try:
        return render_digest_prompt(chats)
    except ValueError as exc:
        raise OpenRouterError(
            "prompt exceeds bounded input size", "prompt_too_large") from exc


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
    payload = {
        "model": model,
        "provider": {
            "zdr": True,
            "data_collection": "deny",
        },
        "messages": [
            {"role": "system", "content": "You summarize only the supplied selected-groups text."},
            {"role": "user", "content": prompt},
        ],
        # Выпуск стал длиннее одного сообщения Telegram: 16 384 токена
        # адаптивное мышление Opus съедало почти целиком.
        "max_tokens": 32_768,
        "response_format": {"type": "json_object"},
    }
    # Opus 5.5 принимает только default sampling. Остальные маршруты сохраняют
    # прежний детерминированный режим, чтобы миграция не меняла их выпуск.
    if model != OPUS_55_MODEL:
        payload["temperature"] = 0
    request_body = canonical_json_bytes(payload)
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
    except urllib.error.HTTPError as exc:
        # Раньше URLError: HTTPError — его подкласс. Код ответа и имя
        # провайдера — служебные; тело ошибки (message, metadata.raw) может
        # пересказывать запрос и наружу не уходит.
        raise OpenRouterError(
            "OpenRouter returned an HTTP error", "http_error",
            http_status=exc.code, provider=_http_error_provider(exc)) from None
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException,
            OSError) as exc:
        # http.client.HTTPException и OSError тоже: упавший ssh-туннель рвёт
        # соединение как RemoteDisconnected/ConnectionReset, а это не URLError —
        # без них отказ канала улетал бы наружу необёрнутым и попадал в статус
        # чужим типом вместо OpenRouterError.
        raise OpenRouterError(
            f"OpenRouter transport failed: {type(exc).__name__}",
            "transport_error", detail=type(exc).__name__) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OpenRouterError(
            "OpenRouter response exceeds size limit", "response_too_large")
    try:
        body: Dict[str, Any] = json.loads(raw.decode("utf-8"))
        if not isinstance(body, dict):
            raise TypeError
    except (TypeError, ValueError, UnicodeDecodeError):
        raise OpenRouterError(
            "OpenRouter response shape is invalid", "response_invalid") from None
    facts = _response_facts(body)
    error = body.get("error")
    if isinstance(error, dict) and "choices" not in body:
        raise OpenRouterError(
            "OpenRouter returned an error body", "provider_error",
            http_status=error.get("code"),
            provider=_error_provider(error), **facts)
    try:
        choice = body["choices"][0]
        finish_reason = choice.get("finish_reason")
        if finish_reason != "stop":
            raise OpenRouterError(
                "OpenRouter response did not finish cleanly", "finish_reason",
                finish_reason=finish_reason,
                native_finish_reason=choice.get("native_finish_reason"),
                **facts)
        content = choice["message"]["content"]
        if not isinstance(content, str):
            raise TypeError
    except OpenRouterError:
        raise
    except (KeyError, IndexError, TypeError, AttributeError):
        raise OpenRouterError(
            "OpenRouter response shape is invalid", "response_invalid",
            **facts) from None
    try:
        parsed = json.loads(content)
    except ValueError:
        raise OpenRouterError(
            "OpenRouter answer is not JSON", "content_not_json", **facts) from None
    usage = _usage_summary(body.get("usage"))
    meta = {key: facts[key] for key in ("generation_id", "provider")
            if key in facts}
    return {"answer": parsed, "usage": usage, "meta": meta}


def _response_facts(body: Dict[str, Any]) -> Dict[str, Any]:
    """id генерации, провайдер и число выходных токенов — без содержимого.

    По id генерации владелец ключа найдёт запрос в OpenRouter, а число
    токенов отличает отказ модели (единицы) от обрезанного выпуска."""
    usage = body.get("usage")
    failure = sanitize_failure({
        "code": "unclassified",
        "generation_id": body.get("id"),
        "provider": body.get("provider"),
        "completion_tokens": (
            usage.get("completion_tokens") if isinstance(usage, dict) else None),
    }) or {}
    failure.pop("code", None)
    return failure


def _error_provider(error: Dict[str, Any]) -> Optional[str]:
    metadata = error.get("metadata")
    if not isinstance(metadata, dict):
        return None
    return _matching(metadata.get("provider_name"), _FAILURE_PROVIDER)


def _http_error_provider(exc: urllib.error.HTTPError) -> Optional[str]:
    try:
        raw = exc.read(16 * 1024)
        body = json.loads(raw.decode("utf-8"))
        error = body.get("error") if isinstance(body, dict) else None
        return _error_provider(error) if isinstance(error, dict) else None
    except Exception:
        return None
    finally:
        try:
            exc.close()
        except Exception:
            pass


def _worker_failure(raw: bytes) -> Dict[str, Any]:
    """Классифицированный отказ, который воркер отдал вместо ответа."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        value = None
    failure = (sanitize_failure(value.get("failure"))
               if isinstance(value, dict) and set(value) == {"failure"} else None)
    return failure or {"code": "worker_response_invalid"}


def blocking_fetch_answer(prompt: str, model: str, api_key: str) -> Any:
    """Совместимый helper: вернуть только структуру ответа модели."""
    return blocking_fetch_response(prompt, model, api_key)["answer"]


def _render_and_validate(parsed: Any, chats: List[DigestChat]) -> str:
    digest = render_digest(
        parsed, digest_sources(chats), digest_sender_names(chats),
        digest_material_urls(chats))
    try:
        validate_digest_text(digest, allow_empty=False)
    except ValueError as exc:
        raise OpenRouterError(
            "OpenRouter digest text is invalid", "text_invalid") from exc
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
        raise OpenRouterError(
            "OpenRouter worker pipes are unavailable", "worker_pipes")
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
            raise OpenRouterError(
                "OpenRouter worker response exceeds size limit",
                "response_too_large")
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
        raise OpenRouterError(
            "OpenRouter worker request exceeds size limit",
            "worker_request_too_large")
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
            raise OpenRouterError("OpenRouter worker timed out", "worker_timeout")
        raw = exchange.result()
        if process.returncode == WORKER_FAILURE_EXIT:
            raise OpenRouterError(
                "OpenRouter request failed", **_worker_failure(raw))
        if process.returncode != 0:
            raise OpenRouterError("OpenRouter worker failed", "worker_failed")
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
        raise OpenRouterError(
            "OpenRouter worker response is invalid",
            "worker_response_invalid") from None
    if (not isinstance(response, dict) or "answer" not in response
            or not set(response) <= {"answer", "usage", "meta"}):
        raise OpenRouterError(
            "OpenRouter worker response is invalid", "worker_response_invalid")
    # Сборка текста и подстановка ссылок — здесь, а не в воркере: только у
    # родителя есть карта «номер → сообщение», и она никуда не уезжает.
    try:
        try:
            digest = _render_and_validate(response["answer"], chats)
        except OpenRouterError:
            raise
        except Exception:
            # Ответ модели произволен: `"²".isdigit()` истинно, а `int("²")`
            # падает ValueError (ревью 02.10.2026). Любой сбой сборки — это
            # отбракованный оплаченный ответ, и классифицироваться он обязан
            # так же, иначе статус снова покажет голый тип без id генерации.
            raise OpenRouterError(
                "OpenRouter digest could not be rendered", "structure_invalid",
                detail="render_error") from None
    except OpenRouterError as exc:
        # Отказ проверки структуры — уже после оплаченного ответа модели:
        # id генерации и число токенов нужны, чтобы найти его у провайдера.
        meta = response.get("meta")
        usage = response.get("usage")
        exc.failure = sanitize_failure({
            **(meta if isinstance(meta, dict) else {}),
            "completion_tokens": (usage.get("completion_tokens")
                                  if isinstance(usage, dict) else None),
            **exc.failure,
        }) or exc.failure
        raise
    if "usage" not in response:
        return digest
    try:
        usage = validate_llm_usage(response["usage"])
    except ValueError as exc:
        raise OpenRouterError(
            "OpenRouter worker usage is invalid", "usage_invalid") from exc
    return DigestText(digest, usage)
