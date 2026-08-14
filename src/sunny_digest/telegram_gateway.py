from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .models import (
    DialogCandidate,
    FetchResult,
    MentionEvent,
    MentionScanResult,
    PeerSpec,
    SelectedMessage,
)
from .prompting import prompt_size
from .version import (
    APP_VERSION,
    DEFAULT_LOOKBACK_HOURS,
    MAX_MENTION_EVENTS,
    MAX_MENTION_SNIPPET_UTF16,
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
            message.message_id, message.sender_id, message.sent_at, candidate_text)
        if prompt_size([candidate], chat_title) <= max_prompt_bytes:
            best = candidate_text
            low = middle + 1
        else:
            high = middle - 1
    if not best:
        raise ValueError("one Telegram message cannot fit the prompt budget")
    return SelectedMessage(message.message_id, message.sender_id, message.sent_at, best)


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
    return "Неизвестный отправитель"


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

    async def _scan_mentions_connected(
            self, client: Any, utils: Any, peer: PeerSpec, expected_chat_id: int,
            chat_title: str, source_id: str, from_message_id_exclusive: int,
            frozen_through_message_id: int) -> MentionScanResult:
        if expected_chat_id != peer.telegram_chat_id():
            raise ValueError("expected chat_id does not match peer")
        if (type(from_message_id_exclusive) is not int
                or type(frozen_through_message_id) is not int
                or from_message_id_exclusive < 0
                or frozen_through_message_id < from_message_id_exclusive):
            raise ValueError("Telegram mention scan range is invalid")
        if not isinstance(source_id, str) or not source_id:
            raise ValueError("source_id is invalid")
        clean_title = _clean_text(chat_title, max_utf16_units=160) or "Unnamed chat"
        if frozen_through_message_id == from_message_id_exclusive:
            return MentionScanResult(from_message_id_exclusive, [])
        through = from_message_id_exclusive
        events: List[MentionEvent] = []
        viewed = 0
        stopped_at_mention_cap = False
        async for message in client.iter_messages(
                self._input_peer(peer), min_id=from_message_id_exclusive,
                max_id=frozen_through_message_id + 1, reverse=True,
                limit=MAX_SCAN_MESSAGES):
            viewed += 1
            message_id = int(message.id)
            if not through < message_id <= frozen_through_message_id:
                raise RuntimeError("Telegram mention scan returned an invalid message order")
            actual_chat_id = int(utils.get_peer_id(message.peer_id))
            if actual_chat_id != expected_chat_id:
                raise RuntimeError("Telegram returned a message from an unexpected peer")
            if bool(getattr(message, "mentioned", False)):
                if len(events) >= MAX_MENTION_EVENTS:
                    stopped_at_mention_cap = True
                    break
                sent_at = message.date
                if sent_at.tzinfo is None:
                    sent_at = sent_at.replace(tzinfo=timezone.utc)
                sent_at = sent_at.astimezone(timezone.utc)
                event_id = hashlib.sha256(
                    f"{source_id}:{expected_chat_id}:{message_id}".encode("utf-8")
                ).hexdigest()
                link = (
                    f"https://t.me/c/{peer.peer_id}/{message_id}"
                    if peer.kind == "channel" else None
                )
                events.append(MentionEvent(
                    event_id=event_id,
                    chat_id=expected_chat_id,
                    message_id=message_id,
                    sent_at=sent_at,
                    chat_title=clean_title,
                    sender=_sender_display(message),
                    snippet=_clean_text(
                        getattr(message, "message", None),
                        max_utf16_units=MAX_MENTION_SNIPPET_UTF16,
                    ),
                    link=link,
                ))
            through = message_id

        if (not stopped_at_mention_cap
                and (viewed < MAX_SCAN_MESSAGES
                     or through == frozen_through_message_id)):
            through = frozen_through_message_id
        return MentionScanResult(through, events)

    async def scan_mentions(
            self, session_text: str, peer: PeerSpec, expected_chat_id: int,
            chat_title: str, source_id: str, from_message_id_exclusive: int,
            frozen_through_message_id: int) -> MentionScanResult:
        """Scan one exact frozen ID window using Telegram's native mention flag."""
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        try:
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            return await self._scan_mentions_connected(
                client, utils, peer, expected_chat_id, chat_title, source_id,
                from_message_id_exclusive, frozen_through_message_id,
            )
        finally:
            await client.disconnect()

    async def snapshot_and_scan_mentions(
            self, session_text: str, source_id: str,
            selected: Sequence[Tuple[int, PeerSpec, str, int]],
    ) -> Tuple[Dict[int, int], Dict[int, MentionScanResult], List[int]]:
        """Snapshot and scan every exact peer in one authenticated connection."""
        pairs = [(chat_id, peer) for chat_id, peer, _, _ in selected]
        self._validate_selected_peers(pairs)
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            tops: Dict[int, int] = {}
            scans: Dict[int, MentionScanResult] = {}
            failed: List[int] = []
            semaphore = asyncio.Semaphore(PEER_OPERATION_CONCURRENCY)

            async def scan_one(
                    chat_id: int, peer: PeerSpec, title: str, start: int,
            ) -> Tuple[int, Optional[int], Optional[MentionScanResult], bool]:
                async with semaphore:
                    try:
                        async def peer_operation() -> Tuple[int, MentionScanResult]:
                            top = (await self._snapshot_tops_connected(
                                client, [(chat_id, peer)], utils))[chat_id]
                            scan = await self._scan_mentions_connected(
                                client, utils, peer, chat_id, title, source_id,
                                start, top,
                            )
                            return top, scan

                        top, scan = await asyncio.wait_for(
                            peer_operation(), timeout=PEER_OPERATION_TIMEOUT_S,
                        )
                        return chat_id, top, scan, True
                    except Exception:
                        # Peer-local failures are intentionally redacted. One
                        # stale access_hash or hanging RPC must not starve the
                        # other locked chats.
                        return chat_id, None, None, False

            tasks = [
                asyncio.create_task(scan_one(chat_id, peer, title, start))
                for chat_id, peer, title, start in selected
            ]
            for chat_id, top, scan, succeeded in await _gather_peer_tasks(tasks):
                if succeeded:
                    assert top is not None and scan is not None
                    tops[chat_id] = top
                    scans[chat_id] = scan
                else:
                    failed.append(chat_id)
            return tops, scans, failed
        finally:
            await _disconnect_client(client)

    async def acknowledge_read(self, session_text: str, peer: PeerSpec,
                               through_message_id: int) -> None:
        succeeded, failed = await self.acknowledge_reads(
            session_text, [(peer.telegram_chat_id(), peer, through_message_id)])
        if failed or succeeded != [peer.telegram_chat_id()]:
            raise RuntimeError("Telegram read acknowledgement failed")

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
                    try:
                        await asyncio.wait_for(
                            client.send_read_acknowledge(
                                self._input_peer(peer), max_id=through_message_id,
                                clear_mentions=True,
                            ),
                            timeout=PEER_OPERATION_TIMEOUT_S,
                        )
                        return chat_id, True
                    except Exception:
                        return chat_id, False

            tasks = [
                asyncio.create_task(acknowledge_one(chat_id, peer, through_message_id))
                for chat_id, peer, through_message_id in acknowledgements
            ]
            for chat_id, succeeded_one in await _gather_peer_tasks(tasks):
                (succeeded if succeeded_one else failed).append(chat_id)
            return succeeded, failed
        finally:
            await _disconnect_client(client)

    async def bootstrap_cursor(self, session_text: str, peer: PeerSpec,
                               now: datetime) -> int:
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        try:
            cutoff = now.astimezone(timezone.utc) - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
            messages = await client.get_messages(self._input_peer(peer), limit=1, offset_date=cutoff)
            if not messages:
                return 0
            actual_chat_id = int(utils.get_peer_id(messages[0].peer_id))
            if actual_chat_id != peer.telegram_chat_id():
                raise RuntimeError("Telegram bootstrap cursor came from an unexpected peer")
            sent_at = messages[0].date
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=timezone.utc)
            if sent_at.astimezone(timezone.utc) >= cutoff:
                raise RuntimeError("Telegram bootstrap cursor is not before the lookback boundary")
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
                candidate = SelectedMessage(
                    message_id=message_id,
                    sender_id=int(message.sender_id) if message.sender_id is not None else None,
                    sent_at=sent_at,
                    text=text,
                )
                if prompt_size(selected + [candidate], chat_title) > max_prompt_bytes:
                    if selected:
                        # Do not advance across text omitted from the bounded
                        # prompt; a later due run resumes from this message.
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
