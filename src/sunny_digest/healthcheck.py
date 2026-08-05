from __future__ import annotations

import http.client
import os
import sys
import time
from pathlib import Path


def check_web() -> bool:
    port = int(os.environ.get("SUNNY_WEB_PORT", "8080"))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        response.read(1024)
        return response.status == 200
    finally:
        connection.close()


def check_collector() -> bool:
    runtime = Path(os.environ.get("SUNNY_RUNTIME_DIR", "/data/runtime"))
    socket = Path(os.environ.get("SUNNY_IPC_SOCKET", str(runtime / "control.sock")))
    heartbeat = runtime / "heartbeat"
    return socket.is_socket() and heartbeat.is_file() and time.time() - heartbeat.stat().st_mtime < 900


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        healthy = check_web() if mode == "web" else check_collector() if mode == "collector" else False
    except Exception:
        healthy = False
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
