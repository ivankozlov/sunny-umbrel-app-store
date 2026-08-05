from __future__ import annotations

import hashlib
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable

from .storage import canonical_json_bytes
from .version import (
    COLLECTOR_VERSION,
    GATE_SCHEMA,
    MAX_DIGEST_CHARS,
    MAX_UPLOAD_BYTES,
    PROMPT_VERSION,
    STATUS_REQUEST_SCHEMA,
    UPLOAD_SCHEMA,
)


UPLOAD_KEYS = (
    "schema",
    "source_id",
    "sequence",
    "previous_sha256",
    "digest_date",
    "timezone",
    "generated_at",
    "cutoff_at",
    "chat_id",
    "from_message_id_exclusive",
    "through_message_id",
    "message_count",
    "empty",
    "digest",
    "model",
    "prompt_version",
    "collector_version",
    "content_sha256",
)

GATE_KEYS = (
    "schema",
    "ok",
    "due",
    "reason",
    "server_time",
    "timezone",
    "digest_date",
    "prepare_not_before",
    "accept_until",
    "next_sequence",
    "previous_sha256",
    "from_message_id_exclusive",
    "max_upload_bytes",
)

RECEIPT_KEYS = (
    "ok",
    "status",
    "sequence",
    "content_sha256",
    "received_at",
    "through_message_id",
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


def status_request(source_id: str, chat_id: int) -> bytes:
    _source_id(source_id)
    if type(chat_id) is not int or not -(2**63) <= chat_id < 0:
        raise ValueError("chat_id is invalid")
    return canonical_json_bytes({
        "schema": STATUS_REQUEST_SCHEMA,
        "source_id": source_id,
        "chat_id": chat_id,
        "collector_version": COLLECTOR_VERSION,
    }) + b"\n"


def validate_gate(value: Dict[str, Any]) -> Dict[str, Any]:
    _exact_keys(value, GATE_KEYS, "gate response")
    if value["schema"] != GATE_SCHEMA or value["ok"] is not True:
        raise ValueError("gate response is not successful v1")
    if not isinstance(value["due"], bool):
        raise ValueError("gate due must be boolean")
    if not isinstance(value["reason"], str) or len(value["reason"]) > 120:
        raise ValueError("gate reason is invalid")
    parse_wire_utc(value["server_time"], "server_time")
    for key in ("prepare_not_before", "accept_until"):
        parse_utc(value[key], key)
    if (not isinstance(value["timezone"], str) or not 1 <= len(value["timezone"]) <= 64
            or not _TOKEN.fullmatch(value["timezone"])):
        raise ValueError("gate timezone is invalid")
    _day(value["digest_date"], "gate digest_date")
    if type(value["next_sequence"]) is not int or not (
            1 <= value["next_sequence"] <= 2**63 - 1):
        raise ValueError("gate next_sequence is invalid")
    if type(value["from_message_id_exclusive"]) is not int or value[
            "from_message_id_exclusive"] < 0 or value[
                "from_message_id_exclusive"] > 2**63 - 1:
        raise ValueError("gate cursor is invalid")
    previous = value["previous_sha256"]
    if value["next_sequence"] == 1:
        if previous is not None:
            raise ValueError("initial gate previous_sha256 must be null")
    elif not isinstance(previous, str) or not _HEX64.fullmatch(previous):
        raise ValueError("gate previous_sha256 is invalid")
    if type(value["max_upload_bytes"]) is not int or not (
            1024 <= value["max_upload_bytes"] <= MAX_UPLOAD_BYTES):
        raise ValueError("gate max_upload_bytes is invalid")
    return value


def content_hash(payload_without_hash: Dict[str, Any]) -> str:
    if "content_sha256" in payload_without_hash:
        raise ValueError("content hash input includes itself")
    return hashlib.sha256(canonical_json_bytes(payload_without_hash)).hexdigest()


def validate_digest_text(value: Any, *, allow_empty: bool) -> str:
    if not isinstance(value, str) or "\r" in value:
        raise ValueError("digest is invalid")
    try:
        # Telegram's message limit is defined by the UTF-16 string length used
        # by its clients/API, not Python's Unicode code-point count. Astral
        # characters therefore consume two units.
        utf16_units = len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        raise ValueError("digest is invalid") from None
    if utf16_units > MAX_DIGEST_CHARS:
        raise ValueError("digest is invalid")
    for char in value:
        if ((ord(char) < 32 and char != "\n") or 127 <= ord(char) <= 159
                or char in _BIDI_CONTROLS):
            raise ValueError("digest contains a forbidden control character")
    if not allow_empty and not value.strip():
        raise ValueError("digest is empty")
    return value


def build_upload(
    *, source_id: str, gate: Dict[str, Any], chat_id: int,
    through_message_id: int, message_count: int, digest: str, model: str,
    generated_at: datetime,
) -> Dict[str, Any]:
    gate = validate_gate(dict(gate))
    if gate["due"] is not True:
        raise ValueError("cannot build upload when gate is not due")
    _source_id(source_id)
    start = gate["from_message_id_exclusive"]
    if type(through_message_id) is not int or not start <= through_message_id <= 2**63 - 1:
        raise ValueError("through_message_id is invalid")
    if type(message_count) is not int or not 0 <= message_count <= 2**63 - 1:
        raise ValueError("message_count is invalid")
    if message_count > through_message_id - start:
        raise ValueError("message_count cannot exceed viewed message id span")
    empty = message_count == 0
    validate_digest_text(digest, allow_empty=empty)
    if empty != (digest == ""):
        raise ValueError("empty, message_count and digest disagree")
    if not empty and through_message_id <= start:
        raise ValueError("non-empty digest did not advance cursor")
    if not isinstance(model, str) or not 1 <= len(model) <= 160:
        raise ValueError("model is invalid")

    payload: Dict[str, Any] = {
        "schema": UPLOAD_SCHEMA,
        "source_id": source_id,
        "sequence": gate["next_sequence"],
        "previous_sha256": gate["previous_sha256"],
        "digest_date": gate["digest_date"],
        "timezone": gate["timezone"],
        "generated_at": utc_iso(generated_at),
        # server_time is the remote-issued upper bound used for Telegram fetch.
        "cutoff_at": gate["server_time"],
        "chat_id": chat_id,
        "from_message_id_exclusive": start,
        "through_message_id": through_message_id,
        "message_count": message_count,
        "empty": empty,
        "digest": digest,
        "model": model,
        "prompt_version": PROMPT_VERSION,
        "collector_version": COLLECTOR_VERSION,
    }
    payload["content_sha256"] = content_hash(payload)
    validate_upload(payload)
    return payload


def validate_upload(value: Dict[str, Any]) -> Dict[str, Any]:
    _exact_keys(value, UPLOAD_KEYS, "upload")
    if value["schema"] != UPLOAD_SCHEMA:
        raise ValueError("upload schema is invalid")
    _source_id(value["source_id"])
    for name in ("sequence", "from_message_id_exclusive", "through_message_id",
                 "message_count"):
        if type(value[name]) is not int or not 0 <= value[name] <= 2**63 - 1:
            raise ValueError(f"upload {name} is invalid")
    if type(value["chat_id"]) is not int or not -(2**63) <= value["chat_id"] < 0:
        raise ValueError("upload chat_id is invalid")
    if value["sequence"] < 1 or value["through_message_id"] < value[
            "from_message_id_exclusive"]:
        raise ValueError("upload sequence/cursor is invalid")
    if value["message_count"] > value["through_message_id"] - value[
            "from_message_id_exclusive"]:
        raise ValueError("upload message count exceeds id span")
    if type(value["empty"]) is not bool or value["empty"] != (value["message_count"] == 0):
        raise ValueError("upload empty flag disagrees with count")
    if (value["digest"] == "") != value["empty"]:
        raise ValueError("upload digest disagrees with empty flag")
    validate_digest_text(value["digest"], allow_empty=value["empty"])
    previous = value["previous_sha256"]
    if value["sequence"] == 1:
        if previous is not None:
            raise ValueError("initial upload previous_sha256 must be null")
    elif not isinstance(previous, str) or not _HEX64.fullmatch(previous):
        raise ValueError("upload previous_sha256 is invalid")
    if not isinstance(value["content_sha256"], str) or not _HEX64.fullmatch(
            value["content_sha256"]):
        raise ValueError("upload content_sha256 is invalid")
    _day(value["digest_date"], "upload digest_date")
    if (not isinstance(value["timezone"], str) or not 1 <= len(value["timezone"]) <= 64
            or not _TOKEN.fullmatch(value["timezone"])):
        raise ValueError("upload timezone is invalid")
    generated = parse_wire_utc(value["generated_at"], "generated_at")
    cutoff = parse_wire_utc(value["cutoff_at"], "cutoff_at")
    if cutoff > generated or generated - cutoff > timedelta(hours=1):
        raise ValueError("upload timestamp order is invalid")
    token_limits = {"model": 160, "prompt_version": 80, "collector_version": 120}
    for name, limit in token_limits.items():
        if (not isinstance(value[name], str) or not value[name]
                or len(value[name]) > limit or not _TOKEN.fullmatch(value[name])):
            raise ValueError(f"upload {name} is invalid")
    expected = content_hash({key: value[key] for key in UPLOAD_KEYS if key != "content_sha256"})
    if value["content_sha256"] != expected:
        raise ValueError("upload content_sha256 mismatch")
    return value


def validate_receipt(value: Dict[str, Any], upload: Dict[str, Any]) -> Dict[str, Any]:
    _exact_keys(value, RECEIPT_KEYS, "receipt")
    if value["ok"] is not True or value["status"] not in ("accepted", "duplicate"):
        raise ValueError("receipt is not successful")
    if type(value["sequence"]) is not int or value["sequence"] != upload["sequence"]:
        raise ValueError("receipt sequence mismatch")
    if value["content_sha256"] != upload["content_sha256"]:
        raise ValueError("receipt hash mismatch")
    if (type(value["through_message_id"]) is not int
            or value["through_message_id"] != upload["through_message_id"]):
        raise ValueError("receipt cursor mismatch")
    parse_wire_utc(value["received_at"], "received_at")
    return value


def canonical_upload_bytes(value: Dict[str, Any]) -> bytes:
    validate_upload(value)
    raw = canonical_json_bytes(value) + b"\n"
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("upload exceeds hard limit")
    return raw
