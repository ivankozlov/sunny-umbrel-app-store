from __future__ import annotations

import json
import sys

from .openrouter import (
    MAX_WORKER_REQUEST_BYTES,
    WORKER_FAILURE_EXIT,
    WORKER_SCHEMA,
    OpenRouterError,
    blocking_fetch_response,
)
from .storage import canonical_json_bytes
from .model_lease import validate_lease, require_lease


def main() -> int:
    """Isolate the blocking HTTPS call in a process that reset can kill."""
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_WORKER_REQUEST_BYTES:
            return 2
        value = json.loads(raw.decode("utf-8"))
        fields = {"schema", "prompt", "model", "api_key"}
        if not isinstance(value, dict) or set(value) not in (fields, fields | {"lease"}):
            return 2
        prompt = value["prompt"]
        model = value["model"]
        api_key = value["api_key"]
        if (value["schema"] != WORKER_SCHEMA
                or not isinstance(prompt, str)
                or not 1 <= len(prompt.encode("utf-8")) <= 100 * 1024
                or not isinstance(model, str) or not 1 <= len(model) <= 160
                or not isinstance(api_key, str) or not 16 <= len(api_key) <= 512):
            return 2
        try:
            if "lease" in value:
                lease = validate_lease(value["lease"])
                require_lease(lease)
                response = blocking_fetch_response(prompt, model, api_key, lease=lease)
            else:
                # Legacy helper is exercised only by offline state-machine tests.
                response = blocking_fetch_response(prompt, model, api_key)
        except OpenRouterError as exc:
            # Наружу — только уже санитизированный код отказа и служебные
            # поля (HTTP-статус, finish_reason, id генерации), без текста
            # исключения: так родитель отличает отказ модели от HTTP-ошибки.
            sys.stdout.buffer.write(
                canonical_json_bytes({"failure": exc.failure}) + b"\n")
            sys.stdout.buffer.flush()
            return WORKER_FAILURE_EXIT
        sys.stdout.buffer.write(
            canonical_json_bytes(response) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Provider exceptions can include request metadata.  The parent receives
        # only a non-zero status and never stderr text.
        return 1


if __name__ == "__main__":
    from .memory_guard import protect_process
    protect_process()
    raise SystemExit(main())
