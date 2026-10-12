"""Closed, memory-only model jobs. No Telegram methods or delivery state."""
from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from .openrouter import OPUS_55_MODEL, FALLBACK_MODEL, sanitize_failure
from .settings import _validate_host, normalize_known_host
from .version import MAX_PROMPT_BYTES
from .model_lease import validate_lease

MAX_IPC_BYTES = 512 * 1024
JOB_SCHEMA = "sunny.personal-chats.model-job.v1"
RESULT_SCHEMA = "sunny.personal-chats.model-result.v1"
MODELS = {OPUS_55_MODEL, FALLBACK_MODEL}


def strict_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("non-finite JSON number")
    if not raw or len(raw) > MAX_IPC_BYTES:
        raise ValueError("IPC size is invalid")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("IPC root is invalid")
    return value


def validate_identity(value: dict, schema: str) -> None:
    if value.get("schema") != schema:
        raise ValueError("job schema is invalid")
    try:
        if str(uuid.UUID(value["job_id"])) != value["job_id"]:
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("job identity is invalid") from None
    if type(value.get("security_epoch")) is not int or value["security_epoch"] < 0:
        raise ValueError("job epoch is invalid")
    if value.get("model") not in MODELS:
        raise ValueError("job model is invalid")


def validate_job(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema", "job_id", "security_epoch", "model", "prompt", "timeout_s", "expires_mono", "expires_boot", "model_access",
    }:
        raise ValueError("job fields are invalid")
    validate_identity(value, JOB_SCHEMA)
    if (not isinstance(value["prompt"], str)
            or not 1 <= len(value["prompt"].encode("utf-8")) <= MAX_PROMPT_BYTES
            or type(value["timeout_s"]) is not int or not 1 <= value["timeout_s"] <= 210):
        raise ValueError("job bounds are invalid")
    validate_lease({key: value[key] for key in ("expires_mono", "expires_boot")})
    access = value["model_access"]
    if not isinstance(access, dict) or set(access) != {"api_key", "tunnel_key", "known_hosts", "host", "port"}:
        raise ValueError("model access fields are invalid")
    if not isinstance(access["api_key"], str) or not 16 <= len(access["api_key"]) <= 512:
        raise ValueError("model access key is invalid")
    _validate_host(access["host"])
    if type(access["port"]) is not int or not 1 <= access["port"] <= 65535:
        raise ValueError("model access port is invalid")
    if not isinstance(access["known_hosts"], str):
        raise ValueError("model pinned host is invalid")
    normalize_known_host(access["known_hosts"].strip(), access["host"], access["port"])
    if not isinstance(access["tunnel_key"], str) or len(access["tunnel_key"]) > 24 * 1024:
        raise ValueError("model access tunnel key is invalid")
    secret = base64.b64decode(access["tunnel_key"], validate=True)
    if not 64 <= len(secret) <= 16 * 1024:
        raise ValueError("model access tunnel key is invalid")
    if len(json.dumps(value, allow_nan=False).encode()) > MAX_IPC_BYTES:
        raise ValueError("job is oversized")
    return value


def validate_result(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ValueError("job result is invalid")
    outcome = value.get("outcome")
    extra = "response" if outcome == "ok" else "failure" if outcome == "error" else None
    if extra is None or set(value) != {"schema", "job_id", "security_epoch", "model", "outcome", extra}:
        raise ValueError("job result fields are invalid")
    validate_identity(value, RESULT_SCHEMA)
    if outcome == "ok":
        response = value["response"]
        if (not isinstance(response, dict) or "answer" not in response
                or not set(response) <= {"answer", "usage", "meta"}):
            raise ValueError("model response fields are invalid")
    else:
        if not isinstance(value["failure"], dict) or sanitize_failure(value["failure"]) != value["failure"]:
            raise ValueError("model failure is invalid")
    if len(json.dumps(value, allow_nan=False).encode()) > MAX_IPC_BYTES:
        raise ValueError("job result is oversized")
    return value
