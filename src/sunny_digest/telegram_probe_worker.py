from __future__ import annotations

import asyncio
import json
import re
import sys

from .mihomo import MIHOMO_SOCKS_HOST, MIHOMO_SOCKS_PORT
from .storage import canonical_json_bytes
from .telegram_gateway import TelethonGateway
from .telegram_probe import MAX_WORKER_REQUEST_BYTES, WORKER_SCHEMA


async def _probe(value):
    gateway = TelethonGateway(
        value["api_id"], value["api_hash"], {
            "proxy_type": "socks5",
            "addr": MIHOMO_SOCKS_HOST,
            "port": MIHOMO_SOCKS_PORT,
            "rdns": True,
        },
    )
    return await gateway.probe_authorization(value["session"])


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_WORKER_REQUEST_BYTES:
            return 2
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
            "schema", "api_id", "api_hash", "session",
        }:
            return 2
        if (
            value["schema"] != WORKER_SCHEMA
            or isinstance(value["api_id"], bool)
            or type(value["api_id"]) is not int
            or value["api_id"] <= 0
            or not isinstance(value["api_hash"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["api_hash"])
            or not isinstance(value["session"], str)
            or not value["session"]
            or len(value["session"]) > 8192
            or "\n" in value["session"]
            or "\r" in value["session"]
        ):
            return 2
        value["session"].encode("ascii")
        authorized = bool(asyncio.run(_probe(value)))
        sys.stdout.buffer.write(canonical_json_bytes({
            "authorized": authorized,
        }) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Session/API material and transport failures never reach stdout/stderr.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
