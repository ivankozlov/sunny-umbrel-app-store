from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from .contracts import parse_utc, utc_iso
from .models import PeerSpec, validate_chat_title
from .storage import Paths, atomic_write_bytes, atomic_write_json, read_json
from .version import MAX_SELECTED_CHATS


SETTINGS_SCHEMA = "sunny.personal-chats.settings.v2"
CREDENTIALS_SCHEMA = "sunny.personal-chats.credentials.v2"
CONSENT_SCOPE = (
    "selected-groups-daily-text-to-zdr-openrouter-native-mention-title-sender-"
    "link-snippet-300-durable-sunny-and-telegram-read-acks"
)
MAX_CONSENT_DAYS = 90
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,158}$")


def _validate_host(host: Any) -> str:
    if not isinstance(host, str) or not _HOST.fullmatch(host) or ".." in host:
        raise ValueError("upload host is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("upload host is invalid")
    return host


def normalize_known_host(line: Any, host: str, port: int) -> bytes:
    if not isinstance(line, str) or "\n" in line or "\r" in line or len(line) > 4096:
        raise ValueError("known_hosts entry is invalid")
    fields = line.strip().split()
    if len(fields) < 3 or fields[1] != "ssh-ed25519":
        raise ValueError("an ssh-ed25519 known_hosts entry is required")
    expected = f"[{host}]:{port}"
    allowed = {expected}
    if port == 22:
        allowed.add(host)
    if fields[0] not in allowed:
        raise ValueError("known_hosts host/port does not match upload endpoint")
    try:
        decoded = base64.b64decode(fields[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("known_hosts key is invalid") from exc
    key_type = b"ssh-ed25519"
    expected_blob = (
        len(key_type).to_bytes(4, "big") + key_type
        + (32).to_bytes(4, "big")
    )
    if len(decoded) != len(expected_blob) + 32 or not decoded.startswith(expected_blob):
        raise ValueError("known_hosts key is invalid")
    return f"{fields[0]} ssh-ed25519 {fields[2]}\n".encode("ascii")


def validate_configure(value: Dict[str, Any], now: datetime) -> tuple[Dict[str, Any], Dict[str, Any], bytes]:
    expected = {
        "telegram_api_id", "telegram_api_hash", "openrouter_api_key",
        "openrouter_model", "upload_host", "upload_port", "upload_user",
        "known_host", "consent_expires_at",
    }
    if set(value) != expected:
        raise ValueError("configure request has unexpected fields")
    try:
        api_id = int(value["telegram_api_id"])
    except (TypeError, ValueError) as exc:
        raise ValueError("telegram_api_id is invalid") from exc
    if api_id <= 0:
        raise ValueError("telegram_api_id is invalid")
    api_hash = value["telegram_api_hash"]
    if not isinstance(api_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash):
        raise ValueError("telegram_api_hash must be 32 hexadecimal characters")
    openrouter_key = value["openrouter_api_key"]
    if not isinstance(openrouter_key, str) or not 16 <= len(openrouter_key) <= 512:
        raise ValueError("OpenRouter key is invalid")
    model = value["openrouter_model"]
    if not isinstance(model, str) or not _MODEL.fullmatch(model):
        raise ValueError("OpenRouter model is invalid")
    host = _validate_host(value["upload_host"])
    try:
        port = int(value["upload_port"])
    except (TypeError, ValueError) as exc:
        raise ValueError("upload port is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("upload port is invalid")
    user = value["upload_user"]
    if user != "root":
        raise ValueError("upload user must match the root forced-command installer")
    current = now.astimezone(timezone.utc)
    expires = validate_consent_expiry(value["consent_expires_at"], current)
    known_host = normalize_known_host(value["known_host"], host, port)

    settings = {
        "schema": SETTINGS_SCHEMA,
        "phase": "configured",
        "chat_locked": False,
        "openrouter_model": model,
        "upload": {"host": host, "port": port, "user": user},
        "consent": {
            "scope": CONSENT_SCOPE,
            "granted_at": utc_iso(current),
            "expires_at": utc_iso(expires),
        },
    }
    credentials = {
        "schema": CREDENTIALS_SCHEMA,
        "telegram_api_id": api_id,
        "telegram_api_hash": api_hash.lower(),
        "openrouter_api_key": openrouter_key,
    }
    return settings, credentials, known_host


def validate_consent_expiry(value: Any, now: datetime) -> datetime:
    expires = parse_utc(value, "consent_expires_at")
    current = now.astimezone(timezone.utc)
    if expires < current + timedelta(hours=1) or expires > current + timedelta(
            days=MAX_CONSENT_DAYS):
        raise ValueError("consent expiry must be 1 hour to 90 days in the future")
    return expires


def load_settings(paths: Paths) -> Dict[str, Any]:
    value = read_json(paths.settings)
    base_keys = {
        "schema", "phase", "chat_locked", "openrouter_model", "upload", "consent",
    }
    locked_keys = {
        "source_id", "chats", "upload_public_key", "upload_key_fingerprint",
    }
    expected = base_keys | locked_keys if value.get("chat_locked") is True else base_keys
    if set(value) != expected:
        raise ValueError("settings have unexpected fields")
    if value.get("schema") != SETTINGS_SCHEMA:
        raise ValueError("settings schema is invalid")
    if value.get("phase") not in (
            "configured", "code_sent", "password_required", "authenticated",
            "dialogs_listed", "chat_locked"):
        raise ValueError("settings phase is invalid")
    if not isinstance(value.get("chat_locked"), bool):
        raise ValueError("settings chat_locked is invalid")
    model = value.get("openrouter_model")
    if not isinstance(model, str) or not _MODEL.fullmatch(model):
        raise ValueError("settings OpenRouter model is invalid")
    upload = value.get("upload")
    if not isinstance(upload, dict) or set(upload) != {"host", "port", "user"}:
        raise ValueError("settings upload endpoint is invalid")
    _validate_host(upload["host"])
    if not isinstance(upload["port"], int) or not 1 <= upload["port"] <= 65535:
        raise ValueError("settings upload port is invalid")
    if upload["user"] != "root":
        raise ValueError("settings upload user is invalid")
    if not isinstance(value.get("consent"), dict):
        raise ValueError("settings consent is invalid")
    consent = value["consent"]
    if set(consent) != {"scope", "granted_at", "expires_at"} or consent[
            "scope"] != CONSENT_SCOPE:
        raise ValueError("settings consent is invalid")
    granted = parse_utc(consent["granted_at"], "consent granted_at")
    expires = parse_utc(consent["expires_at"], "consent expires_at")
    if granted >= expires or expires - granted > timedelta(days=MAX_CONSENT_DAYS):
        raise ValueError("settings consent interval is invalid")
    if value["chat_locked"] != paths.chat_locked.exists():
        raise ValueError("settings lock marker mismatch")
    if value["chat_locked"]:
        if value["phase"] != "chat_locked":
            raise ValueError("locked settings phase is invalid")
        validate_locked_chats(value["chats"])
        try:
            canonical_source = str(uuid.UUID(value["source_id"]))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("locked source_id is invalid") from None
        if canonical_source != value["source_id"]:
            raise ValueError("locked source_id is invalid")
        if (not isinstance(value["upload_public_key"], str)
                or not value["upload_public_key"].startswith("ssh-ed25519 ")
                or len(value["upload_public_key"]) > 1024):
            raise ValueError("locked upload public key is invalid")
        if (not isinstance(value["upload_key_fingerprint"], str)
                or not value["upload_key_fingerprint"].startswith("SHA256:")
                or len(value["upload_key_fingerprint"]) > 160):
            raise ValueError("locked upload fingerprint is invalid")
    elif value["phase"] == "chat_locked":
        raise ValueError("unlocked settings phase is invalid")
    return value


def load_credentials(paths: Paths) -> Dict[str, Any]:
    value = read_json(paths.credentials, max_bytes=16 * 1024)
    if set(value) != {
            "schema", "telegram_api_id", "telegram_api_hash", "openrouter_api_key"}:
        raise ValueError("credentials have unexpected fields")
    if value["schema"] != CREDENTIALS_SCHEMA:
        raise ValueError("credentials schema is invalid")
    if not isinstance(value["telegram_api_id"], int) or value["telegram_api_id"] <= 0:
        raise ValueError("telegram credentials are invalid")
    if not isinstance(value["telegram_api_hash"], str) or not re.fullmatch(
            r"[0-9a-f]{32}", value["telegram_api_hash"]):
        raise ValueError("telegram credentials are invalid")
    if not isinstance(value["openrouter_api_key"], str) or not value["openrouter_api_key"]:
        raise ValueError("OpenRouter credentials are invalid")
    return value


def consent_active(settings: Dict[str, Any], now: datetime) -> bool:
    consent = settings.get("consent")
    if not isinstance(consent, dict) or consent.get("scope") != CONSENT_SCOPE:
        return False
    try:
        granted = parse_utc(consent.get("granted_at"), "consent_granted_at")
        expires = parse_utc(consent.get("expires_at"), "consent_expires_at")
    except ValueError:
        return False
    current = now.astimezone(timezone.utc)
    return (
        granted <= current < expires
        and expires - granted <= timedelta(days=MAX_CONSENT_DAYS)
    )


def validate_locked_chats(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SELECTED_CHATS:
        raise ValueError("locked chats must contain 1 to 16 entries")
    validated: List[Dict[str, Any]] = []
    previous: int | None = None
    for row in value:
        if not isinstance(row, dict) or set(row) != {
                "chat_id", "title", "peer", "initial_message_id"}:
            raise ValueError("locked chat has unexpected fields")
        chat_id = row["chat_id"]
        if type(chat_id) is not int or not -(2**63) <= chat_id < 0:
            raise ValueError("locked chat_id is invalid")
        if previous is not None and chat_id <= previous:
            raise ValueError("locked chats must be unique and sorted")
        previous = chat_id
        if not isinstance(row["peer"], dict):
            raise ValueError("locked peer is invalid")
        peer = PeerSpec.from_dict(row["peer"])
        if chat_id != peer.telegram_chat_id():
            raise ValueError("locked chat_id does not match peer")
        validate_chat_title(row["title"])
        if type(row["initial_message_id"]) is not int or row[
                "initial_message_id"] != 0:
            raise ValueError("initial cursor must be zero")
        validated.append(row)
    return validated


def save_initial_config(paths: Paths, settings: Dict[str, Any], credentials: Dict[str, Any],
                        known_host: bytes) -> None:
    if paths.settings.exists() or paths.credentials.exists() or paths.chat_locked.exists():
        raise RuntimeError("configuration already exists; factory reset is required")
    atomic_write_json(paths.credentials, credentials)
    atomic_write_bytes(paths.known_hosts, known_host)
    atomic_write_json(paths.settings, settings)


def new_source_id() -> str:
    return str(uuid.uuid4())
