from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict

from .collector import Collector
from .storage import Paths, canonical_json_bytes, safe_unlink


MAX_IPC_BYTES = 512 * 1024


async def dispatch(collector: Collector, request: Dict[str, Any]) -> Dict[str, Any]:
    command = request.get("command")
    allowed_shape = {"command"} if command in (
        "status", "run_now", "revoke_and_reset",
        "acknowledge_manual_revocation", "activate_monitoring",
    ) else {"command", "data"}
    if set(request) != allowed_shape:
        raise ValueError("IPC request has unexpected fields")
    if command == "status":
        return await collector.public_status()
    if command == "configure":
        data = request["data"]
        if not isinstance(data, dict):
            raise ValueError("configure data must be an object")
        return await collector.configure(data)
    if command == "replace_vpn":
        data = request["data"]
        if not isinstance(data, str):
            raise ValueError("replace_vpn data must be a string")
        return await collector.replace_vpn(data)
    if command == "extend_chats":
        data = request["data"]
        if not isinstance(data, str):
            raise ValueError("extend_chats data must be a string")
        return await collector.extend_chats(data)
    if command == "send_code":
        return await collector.send_code(request["data"])
    if command == "submit_code":
        return await collector.submit_code(request["data"])
    if command == "submit_password":
        return await collector.submit_password(request["data"])
    if command == "resolve_chat_links":
        return await collector.resolve_chat_links(request["data"])
    if command == "select_chats":
        return await collector.select_chats(request["data"])
    if command == "activate_monitoring":
        return await collector.activate_monitoring()
    if command == "run_now":
        triggered = collector.trigger_run()
        status = await collector.public_status()
        status["run_triggered"] = triggered
        return status
    if command == "renew_consent":
        return await collector.renew_consent(request["data"])
    if command == "revoke_and_reset":
        return await collector.revoke_and_reset()
    if command == "acknowledge_manual_revocation":
        return await collector.acknowledge_manual_revocation()
    raise ValueError("unknown IPC command")


async def _handle(collector: Collector, reader: asyncio.StreamReader,
                  writer: asyncio.StreamWriter) -> None:
    response: Dict[str, Any]
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=30)
        if not raw or len(raw) > MAX_IPC_BYTES or not raw.endswith(b"\n"):
            raise ValueError("IPC request is empty, oversized, or unterminated")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("IPC request root must be an object")
        result = await dispatch(collector, value)
        response = {"ok": True, "result": result}
    except Exception as exc:
        # Never return exception text: providers may include credentials or content.
        response = {"ok": False, "error_type": type(exc).__name__}
    try:
        writer.write(canonical_json_bytes(response) + b"\n")
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        # The web request can time out while a valid long-running collector
        # action is still completing. Its closed socket is not a server error.
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _scheduler(collector: Collector, interval: int) -> None:
    await asyncio.sleep(5)
    while True:
        await collector.run_once()
        await asyncio.sleep(interval)


async def serve(paths: Paths) -> None:
    collector = Collector(paths)
    safe_unlink(paths.ipc_socket)
    server = await asyncio.start_unix_server(
        lambda reader, writer: _handle(collector, reader, writer),
        path=str(paths.ipc_socket), limit=MAX_IPC_BYTES,
    )
    os.chmod(paths.ipc_socket, 0o600)
    try:
        raw_interval = int(os.environ.get("SUNNY_COLLECT_INTERVAL_S", "60"))
        interval = max(60, min(raw_interval, 3600))
        scheduler = asyncio.create_task(_scheduler(collector, interval))
        async with server:
            await server.serve_forever()
    finally:
        if "scheduler" in locals():
            scheduler.cancel()
            await asyncio.gather(scheduler, return_exceptions=True)
        await collector.close()
        safe_unlink(paths.ipc_socket)
