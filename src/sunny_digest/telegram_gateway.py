from __future__ import annotations

import asyncio
import time
import base64
import binascii
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .models import (
    DialogCandidate,
    FetchResult,
    PeerSpec,
    SelectedMessage,
)
from .prompting import prompt_size
from .version import (
    APP_VERSION,
    MAX_PROMPT_BYTES,
    MAX_SCAN_MESSAGES,
)


_MESSAGE_LINK_HOSTS = frozenset(("t.me", "telegram.me"))
_MESSAGE_LINK_QUERY_KEYS = frozenset(("single", "thread", "t", "task", "option"))
_RESERVED_MESSAGE_LINK_ROOTS = frozenset((
    "a", "addemoji", "addlist", "addstickers", "addstyle", "addtheme",
    "auction", "auth", "bg", "boost", "c", "call", "confirmphone", "contact",
    "giftcode", "invoice", "iv", "joinchat", "k", "login", "m", "msg",
    "newbot", "nft", "oauth", "proxy", "setlanguage", "share", "socks",
    "web", "z",
))
_USERNAME = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_MEDIA_TIMESTAMP = re.compile(
    r"(?:[0-9]+|[0-9]+:[0-9]{1,2}|"
    r"(?:(?:[0-9]+h)?(?:[0-9]{1,2}m)?(?:[0-9]{1,2}s)?))"
)
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
PEER_OPERATION_TIMEOUT_S = 30.0
PEER_OPERATION_CONCURRENCY = 4
# Потолок топиков за один проход. Форум с сотнями топиков не должен
# растягивать peer-unit: непрочитанное в остальных закроется на
# следующих тиках, а дедлайн важнее полноты одного прохода.
MAX_FORUM_TOPICS = 100
UNKNOWN_SENDER = "Неизвестный отправитель"


async def _gather_peer_tasks(tasks):
    """Cancel and join every peer task before its shared client disconnects."""
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        async def cancel_and_join() -> None:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        cleanup = asyncio.create_task(cancel_and_join())
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                continue
        cleanup.result()
        raise


async def _disconnect_client(client) -> None:
    """Finish disconnect even if cancellation arrives during cleanup."""
    cleanup = asyncio.ensure_future(client.disconnect())
    cancelled = False
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            cancelled = True
    cleanup.result()
    if cancelled:
        raise asyncio.CancelledError()


def _positive_decimal(value: str, label: str, *, maximum: int = 2**63 - 1) -> int:
    if not _DECIMAL.fullmatch(value):
        raise ValueError(f"Telegram message link {label} is invalid")
    number = int(value)
    if number > maximum:
        raise ValueError(f"Telegram message link {label} is invalid")
    return number


def _message_link_query(query: str, *, path_has_thread: bool) -> Dict[str, str]:
    if "%" in query:
        raise ValueError("Telegram message link query is invalid")
    if not query:
        return {}
    fields = query.split("&")
    if (len(fields) > len(_MESSAGE_LINK_QUERY_KEYS)
            or any(not field for field in fields)):
        raise ValueError("Telegram message link query is invalid")
    values: Dict[str, str] = {}
    for field in fields:
        key, separator, value = field.partition("=")
        if not separator:
            value = ""
        if key in values:
            raise ValueError("Telegram message link query is ambiguous")
        values[key] = value
    if not set(values).issubset(_MESSAGE_LINK_QUERY_KEYS):
        # `comment` targets a message in another linked discussion group, so
        # treating the path peer as the selected chat would be unsafe.
        raise ValueError("Telegram message link query is unsupported")
    if "single" in values and values["single"]:
        raise ValueError("Telegram message link single flag is invalid")
    if "thread" in values:
        if path_has_thread:
            raise ValueError("Telegram message link thread is ambiguous")
        _positive_decimal(values["thread"], "thread id", maximum=2**31 - 1)
    if "t" in values and (
            not 1 <= len(values["t"]) <= 32
            or not _MEDIA_TIMESTAMP.fullmatch(values["t"])):
        raise ValueError("Telegram message link timestamp is invalid")
    if "task" in values:
        _positive_decimal(values["task"], "task id", maximum=2**31 - 1)
    if "option" in values:
        option = values["option"]
        if not 1 <= len(option) <= 1024 or not _BASE64URL.fullmatch(option):
            raise ValueError("Telegram message link option is invalid")
        try:
            base64.urlsafe_b64decode(option + "=" * (-len(option) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            raise ValueError("Telegram message link option is invalid") from None
    return values


def parse_message_link(value: Any) -> Tuple[str, Any]:
    """Return an exact group locator without fetching or following the URL."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048
            or value != value.strip()
            or any(ord(char) > 127 or ord(char) < 32 or ord(char) == 127
                   or unicodedata.category(char) in ("Cf", "Cs")
                   for char in value)):
        raise ValueError("Telegram message link is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("Telegram message link is invalid") from None
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Telegram message link is invalid")

    if parsed.scheme == "https":
        if parsed.netloc.lower() not in _MESSAGE_LINK_HOSTS or port is not None:
            raise ValueError("Telegram message link host is invalid")
        if ("%" in parsed.path or "\\" in parsed.path
                or not parsed.path.startswith("/") or parsed.path.endswith("/")):
            raise ValueError("Telegram message link path is invalid")
        parts = parsed.path[1:].split("/")
        if any(not part for part in parts):
            raise ValueError("Telegram message link path is invalid")
        if parts[0] == "c":
            if len(parts) not in (3, 4):
                raise ValueError("Telegram private message link path is invalid")
            _message_link_query(parsed.query, path_has_thread=len(parts) == 4)
            channel_id = _positive_decimal(parts[1], "channel")
            for part in parts[2:]:
                _positive_decimal(part, "message id", maximum=2**31 - 1)
            if channel_id > 2**63 - 1 - 1_000_000_000_000:
                raise ValueError("Telegram message link channel is invalid")
            return "channel", channel_id
        if (len(parts) not in (2, 3)
                or parts[0].lower() in _RESERVED_MESSAGE_LINK_ROOTS
                or not _USERNAME.fullmatch(parts[0])):
            raise ValueError("Telegram public message link path is invalid")
        _message_link_query(parsed.query, path_has_thread=len(parts) == 3)
        for part in parts[1:]:
            _positive_decimal(part, "message id", maximum=2**31 - 1)
        return "username", parts[0].lower()
    raise ValueError("Telegram message link scheme is invalid")


def _truncate_first_to_budget(message: SelectedMessage,
                              max_prompt_bytes: int,
                              chat_title: Optional[str]) -> SelectedMessage:
    """Fit one anomalously large row into the caller's per-chat budget."""
    if prompt_size([message], chat_title) <= max_prompt_bytes:
        return message
    suffix = "\n[обрезано]"
    low, high = 0, len(message.text)
    best = ""
    while low <= high:
        middle = (low + high) // 2
        candidate_text = message.text[:middle].rstrip() + suffix
        candidate = SelectedMessage(
            message.message_id, message.sender_id, message.sent_at,
            candidate_text, message.sender_name, message.material_urls)
        if prompt_size([candidate], chat_title) <= max_prompt_bytes:
            best = candidate_text
            low = middle + 1
        else:
            high = middle - 1
    if not best:
        raise ValueError("one Telegram message cannot fit the prompt budget")
    return SelectedMessage(
        message.message_id, message.sender_id, message.sent_at, best,
        message.sender_name, message.material_urls)


def _message_material_urls(message: Any) -> Tuple[str, ...]:
    """Прямые HTTP(S)-ссылки из уже полученного сообщения, без запросов.

    TNN удаляет сообщения через сутки (задача 235): ссылка на сообщение
    перестаёт открываться. URL берём из entities, включая скрытые под текстом;
    offset/length Telegram считает в UTF-16 ДО strip, а не в символах Python.
    """
    raw = str(message.message or "").encode("utf-16-le")
    urls: List[str] = []
    for entity in getattr(message, "entities", None) or ():
        kind = type(entity).__name__
        if kind == "MessageEntityTextUrl":
            url = entity.url
        elif kind == "MessageEntityUrl":
            offset, length = entity.offset, entity.length
            if offset < 0 or length <= 0 or (offset + length) * 2 > len(raw):
                continue
            try:
                url = raw[offset * 2:(offset + length) * 2].decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            # Telegram распознаёт и ссылки без схемы: example.org/article.
            if "://" not in url:
                url = "https://" + url
        else:
            continue
        if (not isinstance(url, str) or not url
                or any(char.isspace() or unicodedata.category(char) in
                       ("Cc", "Cf", "Cs") for char in url)):
            continue
        try:
            parsed = urlsplit(url)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None):
                continue
            parsed.port  # Невалидный порт — не рабочая ссылка на материал.
        except ValueError:
            continue
        if url not in urls:
            urls.append(url)
    return tuple(urls)


def _clean_text(value: Any, *, max_utf16_units: Optional[int] = None) -> str:
    raw = "" if value is None else str(value)
    clean = "".join(
        " " if char.isspace() else char
        for char in raw
        if (char.isspace()
            or unicodedata.category(char) not in ("Cc", "Cf", "Cs"))
    )
    clean = " ".join(clean.split())
    if max_utf16_units is None:
        return clean
    used = 0
    kept: List[str] = []
    for char in clean:
        units = 2 if ord(char) > 0xFFFF else 1
        if used + units > max_utf16_units:
            break
        kept.append(char)
        used += units
    return "".join(kept)


def _sender_display(message: Any) -> str:
    post_author = _clean_text(getattr(message, "post_author", None))
    if post_author:
        return _clean_text(post_author, max_utf16_units=160)
    sender = getattr(message, "sender", None)
    if sender is not None:
        full_name = " ".join(filter(None, (
            _clean_text(getattr(sender, "first_name", None)),
            _clean_text(getattr(sender, "last_name", None)),
        )))
        display = full_name or _clean_text(getattr(sender, "title", None))
        if not display:
            username = _clean_text(getattr(sender, "username", None))
            display = f"@{username}" if username else ""
        if display:
            return _clean_text(display, max_utf16_units=160)
    return UNKNOWN_SENDER


class TelethonGateway:
    """Telethon boundary. Imports stay local so unit tests need no network library."""

    def __init__(self, api_id: int, api_hash: str, proxy: Dict[str, Any]):
        expected_proxy = {
            "proxy_type": "socks5",
            "addr": "127.0.0.1",
            "port": 7891,
            "rdns": True,
        }
        if proxy != expected_proxy:
            raise ValueError("Telegram requires the app-scoped SOCKS proxy")
        # Часы peer-unit: подменяются в тестах, поэтому дедлайн проверяем
        # именно ими, а не time.monotonic напрямую.
        self.monotonic = time.monotonic
        self.api_id = api_id
        self.api_hash = api_hash
        self.proxy = dict(expected_proxy)

    def _modules(self):
        from telethon import TelegramClient, utils
        from telethon.errors import SessionPasswordNeededError
        from telethon.sessions import StringSession
        from telethon.tl.types import InputPeerChannel, InputPeerChat, InputPeerUser
        return (TelegramClient, utils, SessionPasswordNeededError, StringSession,
                InputPeerChannel, InputPeerChat, InputPeerUser)

    def _client(self, session_text: str):
        TelegramClient, _, _, StringSession, _, _, _ = self._modules()
        return TelegramClient(
            StringSession(session_text), self.api_id, self.api_hash,
            receive_updates=False,
            proxy=self.proxy,
            device_model="Sunny Umbrel",
            system_version="umbrelOS",
            app_version=APP_VERSION,
        )

    def _forum_modules(self):
        """Форумные вызовы живут в `messages`, а НЕ в `channels`.

        В layer 227 их перенесли, и почти все примеры в сети ссылаются на
        `channels.GetForumTopicsRequest`, которого в Telethon 1.44 нет вовсе —
        такой импорт падает на ровном месте."""
        from telethon.tl.functions.messages import (
            GetForumTopicsRequest,
            ReadDiscussionRequest,
        )
        from telethon.tl.types import ForumTopic
        return GetForumTopicsRequest, ReadDiscussionRequest, ForumTopic

    def _peer_dialog_modules(self):
        from telethon.tl.functions.messages import GetPeerDialogsRequest
        from telethon.tl.types import InputDialogPeer
        return InputDialogPeer, GetPeerDialogsRequest

    async def probe_authorization(self, session_text: str) -> bool:
        """Verify the existing session without reading dialogs or messages."""
        client = self._client(session_text)
        try:
            await client.connect()
            return bool(await client.is_user_authorized())
        finally:
            await _disconnect_client(client)

    async def send_code(self, session_text: str, phone: str) -> Tuple[str, str]:
        client = self._client(session_text)
        await client.connect()
        try:
            sent = await client.send_code_request(phone)
            return client.session.save(), sent.phone_code_hash
        finally:
            await client.disconnect()

    async def submit_code(self, session_text: str, phone: str, code: str,
                          phone_code_hash: str) -> Tuple[str, bool]:
        _, _, SessionPasswordNeededError, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        try:
            try:
                await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
            except SessionPasswordNeededError:
                return client.session.save(), True
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram authorization did not complete")
            return client.session.save(), False
        finally:
            await client.disconnect()

    async def submit_password(self, session_text: str, password: str) -> str:
        client = self._client(session_text)
        await client.connect()
        try:
            await client.sign_in(password=password)
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram authorization did not complete")
            return client.session.save()
        finally:
            await client.disconnect()

    async def resolve_message_links(
            self, session_text: str, links: Sequence[str]) -> List[DialogCandidate]:
        """Match locators to exact accessible peers without fetching linked messages."""
        targets = [parse_message_link(link) for link in links]
        wanted_channels = {locator for kind, locator in targets if kind == "channel"}
        wanted_usernames = {locator for kind, locator in targets if kind == "username"}
        _, utils, _, _, InputPeerChannel, InputPeerChat, InputPeerUser = self._modules()
        client = self._client(session_text)
        await client.connect()
        by_channel: Dict[int, DialogCandidate] = {}
        by_username: Dict[str, DialogCandidate] = {}
        try:
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            async for dialog in client.iter_dialogs(limit=500):
                entity = dialog.entity
                if (not bool(getattr(dialog, "is_group", False))
                        or bool(getattr(entity, "left", False))
                        or bool(getattr(entity, "broadcast", False))
                        or int(dialog.id) >= 0):
                    continue
                input_peer = utils.get_input_peer(entity)
                if isinstance(input_peer, InputPeerChannel):
                    peer = PeerSpec(
                        "channel", int(input_peer.channel_id), int(input_peer.access_hash))
                elif isinstance(input_peer, InputPeerChat):
                    peer = PeerSpec("chat", int(input_peer.chat_id), None)
                elif isinstance(input_peer, InputPeerUser):
                    continue
                else:
                    continue
                title = _clean_text(
                    dialog.name or "Unnamed chat", max_utf16_units=160,
                ) or "Unnamed chat"
                candidate = DialogCandidate(int(dialog.id), title, peer)
                if peer.kind == "channel" and peer.peer_id in wanted_channels:
                    if peer.peer_id in by_channel:
                        raise RuntimeError("Telegram returned a duplicated group peer")
                    by_channel[peer.peer_id] = candidate
                usernames: List[str] = []
                primary = getattr(entity, "username", None)
                if isinstance(primary, str):
                    usernames.append(primary)
                for row in getattr(entity, "usernames", None) or ():
                    username = getattr(row, "username", None)
                    if getattr(row, "active", False) and isinstance(username, str):
                        usernames.append(username)
                for username in usernames:
                    canonical = username.lower()
                    if canonical not in wanted_usernames:
                        continue
                    previous = by_username.get(canonical)
                    if previous is not None and previous.chat_id != candidate.chat_id:
                        raise RuntimeError("Telegram returned an ambiguous group username")
                    by_username[canonical] = candidate
                if (wanted_channels.issubset(by_channel)
                        and wanted_usernames.issubset(by_username)):
                    break

            selected: List[DialogCandidate] = []
            seen = set()
            for kind, locator in targets:
                candidate = (
                    by_channel.get(locator)
                    if kind == "channel"
                    else by_username.get(locator)
                )
                if candidate is None:
                    raise ValueError(
                        "Telegram message link does not identify an accessible group")
                if candidate.chat_id in seen:
                    raise ValueError(
                        "message links identify the same Telegram group more than once")
                seen.add(candidate.chat_id)
                selected.append(candidate)
            return selected
        finally:
            await client.disconnect()

    def _input_peer(self, peer: PeerSpec):
        _, _, _, _, InputPeerChannel, InputPeerChat, _ = self._modules()
        if peer.kind == "channel":
            return InputPeerChannel(peer.peer_id, int(peer.access_hash))
        if peer.kind == "chat":
            return InputPeerChat(peer.peer_id)
        raise ValueError("only an exact group peer can be read")

    def _validate_selected_peers(
            self, selected_peers: Sequence[Tuple[int, PeerSpec]]) -> Dict[int, PeerSpec]:
        if not selected_peers:
            raise ValueError("at least one exact peer is required")
        expected: Dict[int, PeerSpec] = {}
        for chat_id, peer in selected_peers:
            if type(chat_id) is not int or chat_id != peer.telegram_chat_id():
                raise ValueError("selected chat_id does not match peer")
            if chat_id in expected:
                raise ValueError("selected chat_id is duplicated")
            expected[chat_id] = peer
        return expected

    async def _snapshot_tops_connected(
            self, client: Any, selected_peers: Sequence[Tuple[int, PeerSpec]],
            utils: Any) -> Dict[int, int]:
        expected = self._validate_selected_peers(selected_peers)
        InputDialogPeer, GetPeerDialogsRequest = self._peer_dialog_modules()
        request = GetPeerDialogsRequest(peers=[
            InputDialogPeer(peer=self._input_peer(peer))
            for _, peer in selected_peers
        ])
        response = await client(request)
        tops: Dict[int, int] = {}
        for dialog in getattr(response, "dialogs", ()):
            chat_id = int(utils.get_peer_id(dialog.peer))
            if chat_id not in expected:
                raise RuntimeError("Telegram snapshot returned an unexpected peer")
            if chat_id in tops:
                raise RuntimeError("Telegram snapshot duplicated an exact peer")
            top = dialog.top_message
            if type(top) is not int or top < 0:
                raise RuntimeError("Telegram snapshot returned an invalid top message")
            tops[chat_id] = top
        if set(tops) != set(expected):
            raise RuntimeError("Telegram snapshot did not return the exact selected peer set")
        return tops

    async def snapshot_tops(
            self, session_text: str,
            selected_peers: Sequence[Tuple[int, PeerSpec]]) -> Dict[int, int]:
        """Return top IDs for the exact locked peers without listing dialogs/history."""
        self._validate_selected_peers(selected_peers)
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        try:
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            return await self._snapshot_tops_connected(client, selected_peers, utils)
        finally:
            await client.disconnect()

    async def snapshot_peer_tops(
            self, session_text: str,
            selected_peers: Sequence[Tuple[int, PeerSpec]],
    ) -> Tuple[Dict[int, int], List[int]]:
        """Вершины точных peer для утренней пометки прочитанным.

        Тот же `GetPeerDialogs`, что и у `snapshot_tops`: без листинга
        диалогов и без чтения истории, из ответа берётся только
        `top_message`. Отличие — изоляция: каждый peer запрашивается отдельно
        в общем соединении, с тем же 30-секундным дедлайном и не больше
        четырёх одновременно. Один протухший access_hash или зависший RPC
        (инцидент 2026-08-14) не должен оставить непрочитанными все чаты
        сразу, а общий запрос на весь набор падает целиком."""
        self._validate_selected_peers(selected_peers)
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            semaphore = asyncio.Semaphore(PEER_OPERATION_CONCURRENCY)

            async def snapshot_one(
                    chat_id: int, peer: PeerSpec) -> Tuple[int, Optional[int]]:
                async with semaphore:
                    try:
                        tops = await asyncio.wait_for(
                            self._snapshot_tops_connected(
                                client, [(chat_id, peer)], utils),
                            timeout=PEER_OPERATION_TIMEOUT_S,
                        )
                        return chat_id, tops[chat_id]
                    except Exception:
                        # Отказ peer намеренно обезличен: текст ошибки
                        # Telegram наружу не идёт.
                        return chat_id, None

            tasks = [
                asyncio.create_task(snapshot_one(chat_id, peer))
                for chat_id, peer in selected_peers
            ]
            tops: Dict[int, int] = {}
            failed: List[int] = []
            for chat_id, top in await _gather_peer_tasks(tasks):
                if top is None:
                    failed.append(chat_id)
                else:
                    tops[chat_id] = top
            return tops, failed
        finally:
            await _disconnect_client(client)

    async def acknowledge_read(self, session_text: str, peer: PeerSpec,
                               through_message_id: int) -> None:
        succeeded, failed = await self.acknowledge_reads(
            session_text, [(peer.telegram_chat_id(), peer, through_message_id)])
        if failed or succeeded != [peer.telegram_chat_id()]:
            raise RuntimeError("Telegram read acknowledgement failed")

    async def _acknowledge_forum_topics(
            self, client, peer: PeerSpec, through_message_id: int) -> None:
        """Пометить прочитанными топики форума.

        `send_read_acknowledge` уходит в `channels.readHistory`, у которого нет
        поля топика: у форума он гасит общий счётчик, а бейджи топиков остаются
        гореть неделями. Официальные клиенты закрывают топик отдельным
        `messages.readDiscussion` на каждый — так же делаем и мы.

        Перечисление возвращает и последние сообщения топиков; берём из ответа
        ТОЛЬКО метаданные (`id`, `unread_count`), тексты не читаем и не храним —
        то же ограничение, что и у enumeration диалогов при настройке.

        Не форум — `CHANNEL_FORUM_MISSING`, и это штатный ответ, а не сбой."""
        if peer.kind != "channel":
            return
        GetForumTopicsRequest, ReadDiscussionRequest, ForumTopic = (
            self._forum_modules())
        input_peer = self._input_peer(peer)
        try:
            topics = await client(GetForumTopicsRequest(
                peer=input_peer, offset_date=None, offset_id=0, offset_topic=0,
                limit=MAX_FORUM_TOPICS,
            ))
        except Exception:
            # Обычная супергруппа отвечает CHANNEL_FORUM_MISSING; отличать её от
            # сетевого сбоя здесь нечем и незачем — пометка peer уже прошла.
            return
        rows = getattr(topics, "topics", None) or []
        for row in rows[:MAX_FORUM_TOPICS]:
            # ForumTopicDeleted несёт только id — у него нет ни unread_count,
            # ни чего-либо ещё, и read по нему бессмыслен.
            if not isinstance(row, ForumTopic):
                continue
            if int(getattr(row, "unread_count", 0) or 0) <= 0:
                continue
            topic_id = int(row.id)
            try:
                await client(ReadDiscussionRequest(
                    peer=input_peer, msg_id=topic_id,
                    read_max_id=through_message_id,
                ))
            except Exception:
                # Каждый топик отвечает за себя: закрытый или удалённый даёт
                # MSG_ID_INVALID, и обрывать на нём весь обход значило бы
                # оставить все последующие топики непрочитанными навсегда.
                continue

    async def acknowledge_reads(
            self, session_text: str,
            acknowledgements: Sequence[Tuple[int, PeerSpec, int]],
    ) -> Tuple[List[int], List[int]]:
        if not acknowledgements:
            return [], []
        for chat_id, peer, through_message_id in acknowledgements:
            if chat_id != peer.telegram_chat_id():
                raise ValueError("read acknowledgement chat_id does not match peer")
            if type(through_message_id) is not int or through_message_id < 0:
                raise ValueError("Telegram read acknowledgement ID is invalid")
        client = self._client(session_text)
        succeeded: List[int] = []
        failed: List[int] = []
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            semaphore = asyncio.Semaphore(PEER_OPERATION_CONCURRENCY)

            async def acknowledge_one(
                    chat_id: int, peer: PeerSpec, through_message_id: int,
            ) -> Tuple[int, bool]:
                async with semaphore:
                    # ОДИН дедлайн на весь peer-unit, а не по одному на шаг:
                    # два независимых таймаута удваивали бюджет чата, и
                    # шестнадцать чатов переставали укладываться в агрегатный
                    # лимит вызывающего.
                    deadline = self.monotonic() + PEER_OPERATION_TIMEOUT_S
                    try:
                        # clear_mentions=False — решение Ивана 13.09.2026:
                        # упоминания больше не доставляются в Sunny, поэтому
                        # «@» в группе остаётся гореть, пока он сам не откроет
                        # чат. Снимать его здесь значило бы молча прятать
                        # упоминание, о котором он больше нигде не узнает.
                        # Правило одно для всех путей, включая baseline-активацию.
                        await asyncio.wait_for(
                            client.send_read_acknowledge(
                                self._input_peer(peer), max_id=through_message_id,
                                clear_mentions=False,
                            ),
                            timeout=PEER_OPERATION_TIMEOUT_S,
                        )
                    except Exception:
                        return chat_id, False
                    remaining = deadline - self.monotonic()
                    if remaining > 0:
                        try:
                            # Топики — вторым шагом, в остатке того же бюджета:
                            # их отказ не отменяет уже состоявшуюся пометку
                            # peer, иначе один недоступный топик заставил бы
                            # перечитывать всю группу заново на каждом тике.
                            await asyncio.wait_for(
                                self._acknowledge_forum_topics(
                                    client, peer, through_message_id),
                                timeout=remaining,
                            )
                        except Exception:
                            pass
                    return chat_id, True

            tasks = [
                asyncio.create_task(acknowledge_one(chat_id, peer, through_message_id))
                for chat_id, peer, through_message_id in acknowledgements
            ]
            for chat_id, succeeded_one in await _gather_peer_tasks(tasks):
                (succeeded if succeeded_one else failed).append(chat_id)
            return succeeded, failed
        finally:
            await _disconnect_client(client)

    async def boundary_cursor(self, session_text: str, peer: PeerSpec,
                              not_before: datetime) -> int:
        """Последнее сообщение чата СТРОГО до нижней границы выпуска.

        Граница приходит снаружи и считается от времени приёмника: сам
        по себе этот вызов ничего не знает ни про ретроспективу, ни про
        то, первый это выпуск или сотый.
        """
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        try:
            boundary = not_before.astimezone(timezone.utc)
            messages = await client.get_messages(
                self._input_peer(peer), limit=1, offset_date=boundary)
            if not messages:
                return 0
            actual_chat_id = int(utils.get_peer_id(messages[0].peer_id))
            if actual_chat_id != peer.telegram_chat_id():
                raise RuntimeError("Telegram boundary cursor came from an unexpected peer")
            sent_at = messages[0].date
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=timezone.utc)
            if sent_at.astimezone(timezone.utc) >= boundary:
                raise RuntimeError("Telegram boundary cursor is not before the lookback boundary")
            return max(0, int(messages[0].id))
        finally:
            await client.disconnect()

    async def fetch(self, session_text: str, peer: PeerSpec, expected_chat_id: int,
                    from_message_id_exclusive: int, cutoff_at: datetime,
                    not_before_at: Optional[datetime] = None,
                    max_prompt_bytes: int = MAX_PROMPT_BYTES,
                    chat_title: Optional[str] = None) -> FetchResult:
        if not_before_at is not None and not_before_at.tzinfo is None:
            raise ValueError("Telegram lower time boundary must be timezone-aware")
        if (type(max_prompt_bytes) is not int
                or not 0 < max_prompt_bytes <= MAX_PROMPT_BYTES):
            raise ValueError("Telegram prompt budget is invalid")
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        through = from_message_id_exclusive
        selected: List[SelectedMessage] = []
        not_before = (
            not_before_at.astimezone(timezone.utc)
            if not_before_at is not None else None
        )
        try:
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            # Telethon reverses offset semantics together with reverse=True,
            # and min_id can make offset_date ineffective. Resolve the remote
            # cutoff to an explicit exclusive max_id first, then scan only that
            # closed ID window. This also makes cursor=0 unambiguous.
            upper_messages = await client.get_messages(
                self._input_peer(peer), limit=1, offset_date=cutoff_at)
            if not upper_messages:
                return FetchResult(through, selected)
            upper_chat_id = int(utils.get_peer_id(upper_messages[0].peer_id))
            if upper_chat_id != expected_chat_id:
                raise RuntimeError("Telegram cutoff snapshot came from an unexpected peer")
            upper_id = int(upper_messages[0].id)
            if upper_id <= from_message_id_exclusive:
                return FetchResult(through, selected)
            async for message in client.iter_messages(
                    self._input_peer(peer), min_id=from_message_id_exclusive,
                    max_id=upper_id + 1, reverse=True, limit=MAX_SCAN_MESSAGES):
                message_id = int(message.id)
                if message_id <= from_message_id_exclusive:
                    continue
                if message_id > upper_id:
                    raise RuntimeError("Telegram returned a message beyond the cutoff snapshot")
                actual_chat_id = int(utils.get_peer_id(message.peer_id))
                if actual_chat_id != expected_chat_id:
                    raise RuntimeError("Telegram returned a message from an unexpected peer")
                sent_at = message.date
                if sent_at.tzinfo is None:
                    sent_at = sent_at.replace(tzinfo=timezone.utc)
                sent_at = sent_at.astimezone(timezone.utc)
                if not_before is not None and sent_at < not_before:
                    through = max(through, message_id)
                    continue
                text = str(message.message or "").strip()
                if not text:
                    # Cursor follows fully viewed media/service events. No media
                    # download method is ever called.
                    through = max(through, message_id)
                    continue
                sender_name = _sender_display(message)
                candidate = SelectedMessage(
                    message_id=message_id,
                    sender_id=int(message.sender_id) if message.sender_id is not None else None,
                    sent_at=sent_at,
                    text=text,
                    sender_name=(
                        sender_name if sender_name != UNKNOWN_SENDER else None
                    ),
                    material_urls=_message_material_urls(message),
                )
                if prompt_size(selected + [candidate], chat_title) > max_prompt_bytes:
                    if selected:
                        # Do not advance across text omitted from the bounded
                        # prompt; a later due run resumes from this message —
                        # for as long as the tail stays younger than that run's
                        # lower boundary. A tail that outlives the window is
                        # skipped instead, and the issue says so out loud
                        # (`digest_skip_note`).
                        break
                    candidate = _truncate_first_to_budget(
                        candidate, max_prompt_bytes, chat_title)
                selected.append(candidate)
                through = max(through, message_id)
            return FetchResult(through, selected)
        finally:
            await client.disconnect()

    async def logout(self, session_text: str) -> bool:
        if not session_text:
            return True
        client = self._client(session_text)
        await client.connect()
        try:
            if await client.is_user_authorized():
                return bool(await client.log_out())
            return True
        finally:
            await client.disconnect()
