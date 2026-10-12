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


def _fresh(path: Path) -> bool:
    return path.is_file() and time.time() - path.stat().st_mtime < 900


def check_collector() -> bool:
    socket = Path(os.environ.get("SUNNY_JOBS_SOCKET", "/data/ipc/jobs.sock"))
    scratch = Path(os.environ.get("SUNNY_SCRATCH_DIR", "/run/collector-private"))
    return socket.is_socket() and _fresh(scratch / "heartbeat")


def check_guardian() -> bool:
    runtime = Path(os.environ.get("SUNNY_RUNTIME_DIR", "/data/runtime"))
    return (runtime / "ipc/admin/admin.sock").is_socket() and (runtime / "ipc/jobs/jobs.sock").is_socket() and _fresh(runtime / "guardian-heartbeat")


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        healthy = (check_web() if mode == "web" else check_collector() if mode == "collector"
                   else check_guardian() if mode == "guardian" else False)
    except Exception:
        healthy = False
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
