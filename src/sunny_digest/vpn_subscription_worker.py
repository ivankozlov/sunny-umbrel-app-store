from __future__ import annotations

import json
import math
import sys

from .vpn_subscription import (
    MAX_SUBSCRIPTION_BYTES,
    MAX_SUBSCRIPTION_URL,
    WORKER_SCHEMA,
    _fetch_https_bytes,
    origin_hostname,
    parse_vless_subscription,
    resolve_public_node_servers,
    resolve_public_subscription_host,
    validate_subscription_url,
)

MAX_WORKER_REQUEST_BYTES = MAX_SUBSCRIPTION_URL + 256


def _fetch_nodes(url: str, timeout_s: float):
    """Узлы с пиннингом адреса и имена хостов, из которых он получен.

    Порядок списков совпадает: `resolve_public_node_servers` сохраняет
    порядок входа. Имя нужно родителю, чтобы пережить ротацию адреса —
    сам резолв затирает его литералом."""
    pinned_address = resolve_public_subscription_host(url)
    payload = _fetch_https_bytes(
        url, timeout_s, MAX_SUBSCRIPTION_BYTES, pinned_address,
    )
    parsed = parse_vless_subscription(payload)
    origins = [origin_hostname(node) for node in parsed]
    return resolve_public_node_servers(parsed), origins


def main() -> int:
    """Run the bearer-bearing HTTPS operation in a killable child process."""
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_WORKER_REQUEST_BYTES:
            return 2
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
                "schema", "timeout_s", "url"}:
            return 2
        timeout_s = value["timeout_s"]
        if (
            value["schema"] != WORKER_SCHEMA
            or isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or not 0 < timeout_s <= 60
        ):
            return 2
        url = validate_subscription_url(value["url"])
        nodes, origins = _fetch_nodes(url, float(timeout_s))
        response = json.dumps(
            {"nodes": nodes, "origins": origins},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Request URLs and transport exceptions may contain bearer material.
        # The parent gets only a non-zero exit status and no stderr.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
