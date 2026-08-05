from __future__ import annotations

import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, List, Tuple

from .models import DialogCandidate, FetchResult, PeerSpec, SelectedMessage
from .prompting import prompt_size, truncate_first_to_budget
from .version import (
    COLLECTOR_VERSION,
    DEFAULT_LOOKBACK_HOURS,
    MAX_PROMPT_BYTES,
    MAX_SCAN_MESSAGES,
)


class TelethonGateway:
    """Telethon boundary. Imports stay local so unit tests need no network library."""

    def __init__(self, api_id: int, api_hash: str):
        self.api_id = api_id
        self.api_hash = api_hash

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
            device_model="Sunny Umbrel",
            system_version="umbrelOS",
            app_version=COLLECTOR_VERSION,
        )

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

    async def list_dialogs(self, session_text: str) -> List[DialogCandidate]:
        _, utils, _, _, InputPeerChannel, InputPeerChat, InputPeerUser = self._modules()
        client = self._client(session_text)
        await client.connect()
        candidates: List[DialogCandidate] = []
        try:
            if not await client.is_user_authorized():
                raise RuntimeError("Telegram session is not authorized")
            async for dialog in client.iter_dialogs(limit=500):
                # The initial receiver pilot is bound to one group/supergroup.
                # Private users and broadcast-only channels are not selectable.
                if not bool(getattr(dialog, "is_group", False)) or int(dialog.id) >= 0:
                    continue
                input_peer = utils.get_input_peer(dialog.entity)
                if isinstance(input_peer, InputPeerChannel):
                    peer = PeerSpec("channel", int(input_peer.channel_id), int(input_peer.access_hash))
                elif isinstance(input_peer, InputPeerChat):
                    peer = PeerSpec("chat", int(input_peer.chat_id), None)
                elif isinstance(input_peer, InputPeerUser):
                    continue
                else:
                    continue
                raw_title = "".join(
                    char for char in str(dialog.name or "Unnamed chat")
                    if unicodedata.category(char) not in ("Cc", "Cf")
                )
                title = " ".join(raw_title.split())[:160] or "Unnamed chat"
                candidates.append(DialogCandidate(int(dialog.id), title, peer))
            return candidates
        finally:
            await client.disconnect()

    def _input_peer(self, peer: PeerSpec):
        _, _, _, _, InputPeerChannel, InputPeerChat, _ = self._modules()
        if peer.kind == "channel":
            return InputPeerChannel(peer.peer_id, int(peer.access_hash))
        if peer.kind == "chat":
            return InputPeerChat(peer.peer_id)
        raise ValueError("only an exact group peer can be read")

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
                    from_message_id_exclusive: int, cutoff_at: datetime) -> FetchResult:
        _, utils, _, _, _, _, _ = self._modules()
        client = self._client(session_text)
        await client.connect()
        through = from_message_id_exclusive
        selected: List[SelectedMessage] = []
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
                text = str(message.message or "").strip()
                if not text:
                    # Cursor follows fully viewed media/service events. No media
                    # download method is ever called.
                    through = max(through, message_id)
                    continue
                sent_at = message.date
                if sent_at.tzinfo is None:
                    sent_at = sent_at.replace(tzinfo=timezone.utc)
                candidate = SelectedMessage(
                    message_id=message_id,
                    sender_id=int(message.sender_id) if message.sender_id is not None else None,
                    sent_at=sent_at.astimezone(timezone.utc),
                    text=text,
                )
                if prompt_size(selected + [candidate]) > MAX_PROMPT_BYTES:
                    if selected:
                        # Do not advance across text omitted from the bounded
                        # prompt; a later due run resumes from this message.
                        break
                    candidate = truncate_first_to_budget(candidate)
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
