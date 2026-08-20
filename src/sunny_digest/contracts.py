from __future__ import annotations

import hashlib
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .storage import canonical_json_bytes
from .version import (
    COLLECTOR_VERSION,
    DIGEST_UPLOAD_SCHEMA,
    GATE_SCHEMA,
    MAX_DIGEST_CHARS,
    MAX_MENTION_EVENTS,
    MAX_MENTION_SNIPPET_UTF16,
    MAX_SELECTED_CHATS,
    MAX_UPLOAD_BYTES,
    MONITOR_UPLOAD_SCHEMA,
    PROMPT_VERSION,
    RECEIPT_SCHEMA,
    STATUS_REQUEST_SCHEMA,
)


CURSOR_KEYS = ("chat_id", "through_message_id")
RANGE_KEYS = (
    "chat_id", "from_message_id_exclusive", "through_message_id",
)
DIGEST_RANGE_KEYS = RANGE_KEYS + ("message_count",)
EVENT_KEYS = (
    "event_id", "message_id", "date", "chat_title", "sender", "snippet",
    "link",
)
MONITOR_UPLOAD_KEYS = (
    "schema", "source_id", "sequence", "previous_sha256", "kind",
    "generated_at", "ranges", "events", "collector_version",
    "content_sha256",
)
DIGEST_UPLOAD_KEYS = (
    "schema", "source_id", "sequence", "previous_sha256", "digest_date",
    "timezone", "generated_at", "cutoff_at", "chat_ranges",
    "total_message_count", "empty", "digest", "model", "prompt_version",
    "collector_version", "content_sha256",
)
GATE_KEYS = ("schema", "ok", "server_time", "timezone", "monitor", "digest")
MONITOR_GATE_KEYS = (
    "baseline_required", "next_sequence", "previous_sha256", "cursors",
    "max_upload_bytes",
)
DIGEST_GATE_KEYS = (
    "due", "reason", "digest_date", "prepare_not_before", "accept_until",
    "next_sequence", "previous_sha256", "cursors", "max_upload_bytes",
)
RECEIPT_KEYS = (
    "schema", "ok", "status", "stream", "sequence", "content_sha256",
    "received_at",
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._:+/@-]+$")
_BIDI_CONTROLS = {
    "\u061c", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\u206a", "\u206b",
    "\u206c", "\u206d", "\u206e", "\u206f", "\ufeff",
}


def _exact_keys(value: Dict[str, Any], expected: Iterable[str], label: str) -> None:
    if set(value) != set(expected):
        raise ValueError(f"{label} has unexpected fields")


def _source_id(value: Any) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("source_id is invalid") from None
    if parsed != value:
        raise ValueError("source_id is invalid")
    return value


def _chat_id(value: Any, label: str = "chat_id") -> int:
    if type(value) is not int or not -(2**63) <= value < 0:
        raise ValueError(f"{label} is invalid")
    return value


def _message_id(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError(f"{label} is invalid")
    return value


def _utf16_units(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        raise ValueError(f"{label} is invalid") from None


def _safe_text(value: Any, label: str, *, maximum: int, allow_empty: bool) -> str:
    if not isinstance(value, str) or "\r" in value:
        raise ValueError(f"{label} is invalid")
    if not allow_empty and not value.strip():
        raise ValueError(f"{label} is empty")
    if _utf16_units(value, label) > maximum:
        raise ValueError(f"{label} is too long")
    for char in value:
        if ((ord(char) < 32 and char != "\n") or 127 <= ord(char) <= 159
                or char in _BIDI_CONTROLS):
            raise ValueError(f"{label} contains a forbidden control character")
    return value


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError(f"{label} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc)


def parse_wire_utc(value: Any, label: str) -> datetime:
    parsed = parse_utc(value, label)
    original = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if original.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _day(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{label} is invalid") from None
    if parsed.isoformat() != value:
        raise ValueError(f"{label} is invalid")
    return value


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _validate_chat_ids(chat_ids: Any, *, label: str = "chat_ids") -> List[int]:
    if not isinstance(chat_ids, list) or not 1 <= len(chat_ids) <= MAX_SELECTED_CHATS:
        raise ValueError(f"{label} must contain 1 to 16 entries")
    result: List[int] = []
    previous: Optional[int] = None
    for value in chat_ids:
        chat_id = _chat_id(value)
        if previous is not None and chat_id <= previous:
            raise ValueError(f"{label} must be unique and sorted")
        previous = chat_id
        result.append(chat_id)
    return result


def status_request(source_id: str, chat_ids: Sequence[int]) -> bytes:
    _source_id(source_id)
    canonical_ids = _validate_chat_ids(list(chat_ids))
    return canonical_json_bytes({
        "schema": STATUS_REQUEST_SCHEMA,
        "source_id": source_id,
        "chat_ids": canonical_ids,
        "collector_version": COLLECTOR_VERSION,
    }) + b"\n"


def _validate_hash_chain(value: Dict[str, Any], label: str) -> None:
    sequence = value["next_sequence"]
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise ValueError(f"{label} next_sequence is invalid")
    previous = value["previous_sha256"]
    if sequence == 1:
        if previous is not None:
            raise ValueError(f"initial {label} previous_sha256 must be null")
    elif not isinstance(previous, str) or not _HEX64.fullmatch(previous):
        raise ValueError(f"{label} previous_sha256 is invalid")


def _validate_cursors(value: Any, label: str) -> List[Dict[str, int]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} cursors are invalid")
    ids: List[int] = []
    rows: List[Dict[str, int]] = []
    for row in value:
        if not isinstance(row, dict):
            raise ValueError(f"{label} cursor is invalid")
        _exact_keys(row, CURSOR_KEYS, f"{label} cursor")
        chat_id = _chat_id(row["chat_id"])
        through = _message_id(row["through_message_id"], "through_message_id")
        ids.append(chat_id)
        rows.append({"chat_id": chat_id, "through_message_id": through})
    _validate_chat_ids(ids, label=f"{label} cursor chat_ids")
    return rows


def _validate_upload_limit(value: Any, label: str) -> None:
    if type(value) is not int or not 1024 <= value <= MAX_UPLOAD_BYTES:
        raise ValueError(f"{label} max_upload_bytes is invalid")


def validate_gate(value: Dict[str, Any], expected_chat_ids: Optional[Sequence[int]] = None) -> Dict[str, Any]:
    _exact_keys(value, GATE_KEYS, "gate response")
    if value["schema"] != GATE_SCHEMA or value["ok"] is not True:
        raise ValueError("gate response is not successful v2")
    parse_wire_utc(value["server_time"], "server_time")
    if (not isinstance(value["timezone"], str) or not 1 <= len(value["timezone"]) <= 64
            or not _TOKEN.fullmatch(value["timezone"])):
        raise ValueError("gate timezone is invalid")

    monitor = value["monitor"]
    if not isinstance(monitor, dict):
        raise ValueError("monitor gate is invalid")
    _exact_keys(monitor, MONITOR_GATE_KEYS, "monitor gate")
    if not isinstance(monitor["baseline_required"], bool):
        raise ValueError("monitor gate baseline_required must be boolean")
    _validate_hash_chain(monitor, "monitor gate")
    monitor_cursors = _validate_cursors(monitor["cursors"], "monitor gate")
    _validate_upload_limit(monitor["max_upload_bytes"], "monitor gate")
    if monitor["baseline_required"]:
        if (monitor["next_sequence"] != 1
                or monitor["previous_sha256"] is not None
                or any(row["through_message_id"] != 0 for row in monitor_cursors)):
            raise ValueError("required baseline must start at the zero monitor chain")
    elif monitor["next_sequence"] == 1:
        raise ValueError("monitor sequence one must require baseline")

    digest = value["digest"]
    if not isinstance(digest, dict):
        raise ValueError("digest gate is invalid")
    _exact_keys(digest, DIGEST_GATE_KEYS, "digest gate")
    if not isinstance(digest["due"], bool):
        raise ValueError("digest gate due must be boolean")
    if not isinstance(digest["reason"], str) or len(digest["reason"]) > 120:
        raise ValueError("digest gate reason is invalid")
    _day(digest["digest_date"], "digest gate digest_date")
    parse_utc(digest["prepare_not_before"], "prepare_not_before")
    parse_utc(digest["accept_until"], "accept_until")
    _validate_hash_chain(digest, "digest gate")
    digest_cursors = _validate_cursors(digest["cursors"], "digest gate")
    _validate_upload_limit(digest["max_upload_bytes"], "digest gate")

    monitor_ids = [row["chat_id"] for row in monitor_cursors]
    digest_ids = [row["chat_id"] for row in digest_cursors]
    if monitor_ids != digest_ids:
        raise ValueError("monitor and digest gates bind different chats")
    if expected_chat_ids is not None and monitor_ids != list(expected_chat_ids):
        # Приёмник — источник истины по набору чатов, и он может объявить
        # РАСШИРЕНИЕ: свои чаты плюс новые. Это не рассинхрон, а приглашение
        # добавить чат; всё остальное по-прежнему отказ. Уменьшение набора
        # отказом и остаётся: снять чат расширением нельзя.
        expected = list(expected_chat_ids)
        added = [row for row in monitor_ids if row not in set(expected)]
        if not added or [row for row in monitor_ids if row in set(expected)] != expected:
            raise ValueError("gate chat set does not match locked settings")
    return value


def content_hash(payload_without_hash: Dict[str, Any]) -> str:
    if "content_sha256" in payload_without_hash:
        raise ValueError("content hash input includes itself")
    return hashlib.sha256(canonical_json_bytes(payload_without_hash)).hexdigest()


def mention_event_id(source_id: str, chat_id: int, message_id: int) -> str:
    _source_id(source_id)
    _chat_id(chat_id)
    _message_id(message_id, "message_id")
    return hashlib.sha256(f"{source_id}:{chat_id}:{message_id}".encode("utf-8")).hexdigest()


def _validate_range(row: Any, label: str) -> Dict[str, int]:
    if not isinstance(row, dict):
        raise ValueError(f"{label} is invalid")
    _exact_keys(row, RANGE_KEYS, label)
    chat_id = _chat_id(row["chat_id"])
    start = _message_id(row["from_message_id_exclusive"], "from_message_id_exclusive")
    through = _message_id(row["through_message_id"], "through_message_id")
    if through < start:
        raise ValueError(f"{label} moved backwards")
    return {
        "chat_id": chat_id,
        "from_message_id_exclusive": start,
        "through_message_id": through,
    }


def supergroup_link_prefix(chat_id: int) -> Optional[str]:
    """`https://t.me/c/<peer_id>` для супергруппы, иначе None.

    Одна формула на двух потребителей: проверку ссылки mention-события и
    сборку ссылок дайджеста. У обычной группы адресуемых ссылок нет — там
    None, и пункт дайджеста останется без источника, а не получит чужой."""
    if chat_id <= -1_000_000_000_000:
        return f"https://t.me/c/{-chat_id - 1_000_000_000_000}"
    return None


def _validate_event(event: Any, source_id: str, chat_id: int) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("monitor event is invalid")
    _exact_keys(event, EVENT_KEYS, "monitor event")
    message_id = _message_id(event["message_id"], "event message_id")
    if event["event_id"] != mention_event_id(source_id, chat_id, message_id):
        raise ValueError("monitor event_id mismatch")
    parse_wire_utc(event["date"], "event date")
    _safe_text(event["chat_title"], "event chat_title", maximum=160, allow_empty=False)
    _safe_text(event["sender"], "event sender", maximum=160, allow_empty=False)
    _safe_text(
        event["snippet"], "event snippet",
        maximum=MAX_MENTION_SNIPPET_UTF16, allow_empty=True,
    )
    link = event["link"]
    prefix = supergroup_link_prefix(chat_id)
    if prefix is not None:
        if link != f"{prefix}/{message_id}":
            raise ValueError("event link does not match supergroup chat_id")
    elif link is not None:
        raise ValueError("legacy group event link must be null")
    return event


def build_monitor_upload(
    *, source_id: str, gate: Dict[str, Any], kind: str,
    ranges: Sequence[Dict[str, int]], events: Sequence[Dict[str, Any]],
    generated_at: datetime,
) -> Dict[str, Any]:
    validate_gate(dict(gate))
    monitor = gate["monitor"]
    payload: Dict[str, Any] = {
        "schema": MONITOR_UPLOAD_SCHEMA,
        "source_id": source_id,
        "sequence": monitor["next_sequence"],
        "previous_sha256": monitor["previous_sha256"],
        "kind": kind,
        "generated_at": utc_iso(generated_at),
        "ranges": list(ranges),
        "events": list(events),
        "collector_version": COLLECTOR_VERSION,
    }
    payload["content_sha256"] = content_hash(payload)
    validate_monitor_upload(payload)

    remote = {row["chat_id"]: row["through_message_id"] for row in monitor["cursors"]}
    if (kind == "baseline") != monitor["baseline_required"]:
        raise ValueError("monitor kind disagrees with baseline_required")
    if kind == "baseline" and [row["chat_id"] for row in ranges] != list(remote):
        raise ValueError("baseline must cover every locked chat")
    if kind == "extension_baseline" and not ranges:
        raise ValueError("extension baseline must cover at least one chat")
    for row in ranges:
        if remote.get(row["chat_id"]) != row["from_message_id_exclusive"]:
            raise ValueError("monitor range does not start at receiver cursor")
    return payload


def validate_monitor_upload(value: Dict[str, Any]) -> Dict[str, Any]:
    _exact_keys(value, MONITOR_UPLOAD_KEYS, "monitor upload")
    if value["schema"] != MONITOR_UPLOAD_SCHEMA:
        raise ValueError("monitor upload schema is invalid")
    source_id = _source_id(value["source_id"])
    sequence = value["sequence"]
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise ValueError("monitor sequence is invalid")
    previous = value["previous_sha256"]
    if sequence == 1:
        if previous is not None:
            raise ValueError("initial monitor previous_sha256 must be null")
    elif not isinstance(previous, str) or not _HEX64.fullmatch(previous):
        raise ValueError("monitor previous_sha256 is invalid")
    kind = value["kind"]
    if kind not in ("baseline", "mentions", "extension_baseline"):
        raise ValueError("monitor kind is invalid")
    parse_wire_utc(value["generated_at"], "generated_at")
    if value["collector_version"] != COLLECTOR_VERSION:
        raise ValueError("monitor collector_version is invalid")
    if not isinstance(value["ranges"], list):
        raise ValueError("monitor ranges are invalid")
    ranges = [_validate_range(row, "monitor range") for row in value["ranges"]]
    range_ids = [row["chat_id"] for row in ranges]
    _validate_chat_ids(range_ids, label="monitor range chat_ids")
    if not isinstance(value["events"], list):
        raise ValueError("monitor events are invalid")
    if kind == "baseline":
        if sequence != 1 or value["events"]:
            raise ValueError("baseline must be sequence one with no events")
    elif kind == "extension_baseline":
        # Расширение продолжает цепочку, а не начинает её: чат добавляется к
        # работающему набору, и курсоры остальных обязаны уцелеть.
        if sequence == 1 or value["events"]:
            raise ValueError(
                "extension baseline continues the chain and carries no events")
        if any(row["from_message_id_exclusive"] != 0 for row in ranges):
            raise ValueError("extension baseline starts every new chat at zero")
    else:
        if sequence == 1 or len(ranges) != 1 or not 1 <= len(value["events"]) <= MAX_MENTION_EVENTS:
            raise ValueError("mentions upload shape is invalid")
        monitor_range = ranges[0]
        events = [
            _validate_event(event, source_id, monitor_range["chat_id"])
            for event in value["events"]
        ]
        seen: set[int] = set()
        previous_message_id = monitor_range["from_message_id_exclusive"]
        for event in events:
            message_id = event["message_id"]
            if not monitor_range["from_message_id_exclusive"] < message_id <= monitor_range[
                    "through_message_id"]:
                raise ValueError("monitor event escaped its message range")
            if message_id in seen:
                raise ValueError("monitor event message_id is duplicated")
            if message_id <= previous_message_id:
                raise ValueError("monitor events must be strictly increasing")
            seen.add(message_id)
            previous_message_id = message_id
    if not isinstance(value["content_sha256"], str) or not _HEX64.fullmatch(
            value["content_sha256"]):
        raise ValueError("monitor content_sha256 is invalid")
    expected = content_hash({
        key: value[key] for key in MONITOR_UPLOAD_KEYS if key != "content_sha256"
    })
    if value["content_sha256"] != expected:
        raise ValueError("monitor content_sha256 mismatch")
    return value


def validate_digest_text(value: Any, *, allow_empty: bool) -> str:
    return _safe_text(
        value, "digest", maximum=MAX_DIGEST_CHARS, allow_empty=allow_empty,
    )


def _validate_digest_range(row: Any) -> Dict[str, int]:
    if not isinstance(row, dict):
        raise ValueError("digest range is invalid")
    _exact_keys(row, DIGEST_RANGE_KEYS, "digest range")
    base = _validate_range(
        {key: row[key] for key in RANGE_KEYS}, "digest range",
    )
    count = _message_id(row["message_count"], "range message_count")
    if count > base["through_message_id"] - base["from_message_id_exclusive"]:
        raise ValueError("range message_count exceeds id span")
    return {**base, "message_count": count}


def build_digest_upload(
    *, source_id: str, gate: Dict[str, Any],
    chat_ranges: Sequence[Dict[str, int]], digest: str, model: str,
    generated_at: datetime,
) -> Dict[str, Any]:
    validate_gate(dict(gate))
    digest_gate = gate["digest"]
    if digest_gate["due"] is not True:
        raise ValueError("cannot build digest upload when gate is not due")
    message_count = sum(row["message_count"] for row in chat_ranges)
    payload: Dict[str, Any] = {
        "schema": DIGEST_UPLOAD_SCHEMA,
        "source_id": source_id,
        "sequence": digest_gate["next_sequence"],
        "previous_sha256": digest_gate["previous_sha256"],
        "digest_date": digest_gate["digest_date"],
        "timezone": gate["timezone"],
        "generated_at": utc_iso(generated_at),
        "cutoff_at": gate["server_time"],
        "chat_ranges": list(chat_ranges),
        "total_message_count": message_count,
        "empty": message_count == 0,
        "digest": digest,
        "model": model,
        "prompt_version": PROMPT_VERSION,
        "collector_version": COLLECTOR_VERSION,
    }
    payload["content_sha256"] = content_hash(payload)
    validate_digest_upload(payload)
    expected = digest_gate["cursors"]
    if [row["chat_id"] for row in chat_ranges] != [row["chat_id"] for row in expected]:
        raise ValueError("digest upload must cover every locked chat")
    for row, cursor in zip(chat_ranges, expected):
        if row["from_message_id_exclusive"] != cursor["through_message_id"]:
            raise ValueError("digest range does not start at receiver cursor")
    return payload


def validate_digest_upload(value: Dict[str, Any]) -> Dict[str, Any]:
    _exact_keys(value, DIGEST_UPLOAD_KEYS, "digest upload")
    if value["schema"] != DIGEST_UPLOAD_SCHEMA:
        raise ValueError("digest upload schema is invalid")
    _source_id(value["source_id"])
    sequence = value["sequence"]
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise ValueError("digest sequence is invalid")
    previous = value["previous_sha256"]
    if sequence == 1:
        if previous is not None:
            raise ValueError("initial digest previous_sha256 must be null")
    elif not isinstance(previous, str) or not _HEX64.fullmatch(previous):
        raise ValueError("digest previous_sha256 is invalid")
    _day(value["digest_date"], "digest_date")
    if (not isinstance(value["timezone"], str) or not 1 <= len(value["timezone"]) <= 64
            or not _TOKEN.fullmatch(value["timezone"])):
        raise ValueError("digest timezone is invalid")
    generated = parse_wire_utc(value["generated_at"], "generated_at")
    cutoff = parse_wire_utc(value["cutoff_at"], "cutoff_at")
    if cutoff > generated or generated - cutoff > timedelta(hours=1):
        raise ValueError("digest timestamp order is invalid")
    if not isinstance(value["chat_ranges"], list):
        raise ValueError("digest chat_ranges are invalid")
    ranges = [_validate_digest_range(row) for row in value["chat_ranges"]]
    _validate_chat_ids([row["chat_id"] for row in ranges], label="digest range chat_ids")
    total = _message_id(value["total_message_count"], "total_message_count")
    if total != sum(row["message_count"] for row in ranges):
        raise ValueError("digest aggregate message_count mismatch")
    if type(value["empty"]) is not bool or value["empty"] != (total == 0):
        raise ValueError("digest empty flag disagrees with count")
    if (value["digest"] == "") != value["empty"]:
        raise ValueError("digest text disagrees with empty flag")
    validate_digest_text(value["digest"], allow_empty=value["empty"])
    for name, expected in (
            ("model", None), ("prompt_version", PROMPT_VERSION),
            ("collector_version", COLLECTOR_VERSION)):
        token = value[name]
        if not isinstance(token, str) or not token or len(token) > 160 or not _TOKEN.fullmatch(token):
            raise ValueError(f"digest {name} is invalid")
        if expected is not None and token != expected:
            raise ValueError(f"digest {name} is invalid")
    if not isinstance(value["content_sha256"], str) or not _HEX64.fullmatch(
            value["content_sha256"]):
        raise ValueError("digest content_sha256 is invalid")
    expected_hash = content_hash({
        key: value[key] for key in DIGEST_UPLOAD_KEYS if key != "content_sha256"
    })
    if value["content_sha256"] != expected_hash:
        raise ValueError("digest content_sha256 mismatch")
    return value


def validate_receipt(value: Dict[str, Any], upload: Dict[str, Any], stream: str) -> Dict[str, Any]:
    _exact_keys(value, RECEIPT_KEYS, "receipt")
    if (value["schema"] != RECEIPT_SCHEMA or value["ok"] is not True
            or value["status"] not in ("accepted", "duplicate")):
        raise ValueError("receipt is not successful")
    if stream not in ("monitor", "digest") or value["stream"] != stream:
        raise ValueError("receipt stream mismatch")
    if type(value["sequence"]) is not int or value["sequence"] != upload["sequence"]:
        raise ValueError("receipt sequence mismatch")
    if value["content_sha256"] != upload["content_sha256"]:
        raise ValueError("receipt hash mismatch")
    parse_wire_utc(value["received_at"], "received_at")
    return value


def canonical_monitor_bytes(value: Dict[str, Any]) -> bytes:
    validate_monitor_upload(value)
    raw = canonical_json_bytes(value) + b"\n"
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("monitor upload exceeds hard limit")
    return raw


def canonical_digest_bytes(value: Dict[str, Any]) -> bytes:
    validate_digest_upload(value)
    raw = canonical_json_bytes(value) + b"\n"
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("digest upload exceeds hard limit")
    return raw
