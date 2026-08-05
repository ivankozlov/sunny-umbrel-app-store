from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PeerSpec:
    kind: str
    peer_id: int
    access_hash: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "peer_id": self.peer_id,
            "access_hash": self.access_hash,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "PeerSpec":
        if set(value) != {"kind", "peer_id", "access_hash"}:
            raise ValueError("peer has unexpected fields")
        kind = value["kind"]
        peer_id = value["peer_id"]
        access_hash = value["access_hash"]
        if kind not in ("chat", "channel"):
            raise ValueError("peer kind is invalid")
        if type(peer_id) is not int or not 0 < peer_id <= 2**63 - 1:
            raise ValueError("peer id is invalid")
        if kind == "chat":
            if access_hash is not None:
                raise ValueError("chat peer must not have access_hash")
        elif type(access_hash) is not int or not -(2**63) <= access_hash <= 2**63 - 1:
            raise ValueError("peer access_hash is invalid")
        return cls(kind, peer_id, access_hash)

    def telegram_chat_id(self) -> int:
        if self.kind == "chat":
            return -self.peer_id
        if self.kind == "channel":
            return -(1_000_000_000_000 + self.peer_id)
        raise ValueError("only group peers have a Telegram chat_id")


@dataclass(frozen=True)
class DialogCandidate:
    chat_id: int
    title: str
    peer: PeerSpec

    def as_private_dict(self) -> Dict[str, Any]:
        return {"chat_id": self.chat_id, "title": self.title, "peer": self.peer.as_dict()}

    @classmethod
    def from_private_dict(cls, value: Dict[str, Any]) -> "DialogCandidate":
        if set(value) != {"chat_id", "title", "peer"}:
            raise ValueError("dialog candidate has unexpected fields")
        if type(value["chat_id"]) is not int or not -(2**63) <= value["chat_id"] < 0:
            raise ValueError("dialog chat_id is invalid")
        if (not isinstance(value["title"], str) or not value["title"]
                or len(value["title"]) > 160
                or any(unicodedata.category(char) in ("Cc", "Cf")
                       for char in value["title"])):
            raise ValueError("dialog title is invalid")
        if not isinstance(value["peer"], dict):
            raise ValueError("dialog peer is invalid")
        peer = PeerSpec.from_dict(value["peer"])
        if value["chat_id"] != peer.telegram_chat_id():
            raise ValueError("dialog chat_id does not match peer")
        return cls(value["chat_id"], value["title"], peer)

    def as_ui_dict(self) -> Dict[str, Any]:
        return {"chat_id": self.chat_id, "title": self.title, "kind": self.peer.kind}


@dataclass(frozen=True)
class SelectedMessage:
    message_id: int
    sender_id: Optional[int]
    sent_at: datetime
    text: str


@dataclass(frozen=True)
class FetchResult:
    through_message_id: int
    messages: List[SelectedMessage]
