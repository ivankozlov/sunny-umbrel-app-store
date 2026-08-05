from __future__ import annotations

import json
import sys

from .openrouter import (
    MAX_WORKER_REQUEST_BYTES,
    WORKER_SCHEMA,
    _blocking_digest_prompt,
)
from .storage import canonical_json_bytes


def main() -> int:
    """Isolate the blocking HTTPS call in a process that reset can kill."""
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_WORKER_REQUEST_BYTES:
            return 2
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
                "schema", "prompt", "model", "api_key"}:
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
        digest = _blocking_digest_prompt(prompt, model, api_key)
        sys.stdout.buffer.write(canonical_json_bytes({"digest": digest}) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Provider exceptions can include request metadata.  The parent receives
        # only a non-zero status and never stderr text.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
