"""Separate admin/jobs sockets authenticated by kernel peer UID."""
from __future__ import annotations

import asyncio
import os
import socket
import struct
import re
from pathlib import Path

from .guardian import Guardian, SETUP_STEPS, PRESENTATION
from .job_contracts import MAX_IPC_BYTES, strict_json
from .secret_files import clean_secret_scratch
from .storage import Paths, canonical_json_bytes, safe_unlink


def peer_uid(writer) -> int:
    connection = writer.get_extra_info("socket")
    if not hasattr(socket, "SO_PEERCRED") or connection is None:
        raise PermissionError("kernel peer credentials unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)[1]


async def dispatch(guardian, role, uid, request):
    command = request.get("command")
    if role == "jobs":
        if uid != 1001:
            raise PermissionError("model peer uid is invalid")
        if command == "next_job" and set(request) == {"command"}:
            return guardian.jobs.next_job()
        if set(request) != {"command", "data"}:
            raise ValueError("jobs request fields are invalid")
        data = request["data"]
        if command == "job_result":
            return guardian.jobs.result(data)
        if (not isinstance(data, dict) or set(data) != {"job_id"}
                or not isinstance(data["job_id"], str) or len(data["job_id"]) > 64):
            raise ValueError("jobs identity is invalid")
        if command == "job_status":
            return guardian.jobs.status(data["job_id"])
        if command == "job_reaped":
            return guardian.jobs.reaped(data["job_id"])
        raise PermissionError("command is unavailable on jobs socket")
    if role != "admin" or uid not in {1000, 1002}:
        raise PermissionError("admin peer uid is invalid")
    if command == "console_bootstrap" and set(request) == {"command"}:
        if uid != 1000 or guardian.vault.path.exists():
            raise PermissionError("bootstrap requires guardian console")
        return {"token": guardian._auth().create_bootstrap()}
    if command == "status":
        if set(request) == {"command"}:
            return await guardian.status()
        if set(request) == {"command", "data"} and isinstance(request["data"], dict) and set(request["data"]) == {"view_token"}:
            return await guardian.status(request["data"]["view_token"])
        raise ValueError("status fields are invalid")
    if set(request) != {"command", "data"}:
        raise ValueError("admin request fields are invalid")
    if command == "operation_begin":
        return await guardian.begin(request["data"])
    if command == "operation_finish":
        return await guardian.finish(request["data"])
    if command == "bootstrap_begin":
        return await guardian.bootstrap_begin(request["data"])
    if command == "registration_finish":
        return await guardian.registration_finish(request["data"])
    if command in SETUP_STEPS | PRESENTATION:
        data = request["data"]
        if not isinstance(data, dict) or set(data) != {"value", "view_token"}:
            raise ValueError("admin step fields are invalid")
        guardian._require_unlocked()
        if not guardian._view_valid(data["view_token"]):
            raise PermissionError("admin view session expired")
        # The setup state machine independently checks its uninterrupted lease
        # and exact phase before every Telegram operation.
        from .ipc import dispatch as engine_dispatch
        async with guardian._admin_lock:
            guardian._require_unlocked()
            if not guardian._view_valid(data["view_token"]):
                raise PermissionError("admin view session expired")
            value = data["value"]
            if command == "set_chat_display" and isinstance(value, dict) and isinstance(value.get("chat_id"), str):
                if not re.fullmatch(r"-[1-9][0-9]{0,18}", value["chat_id"]):
                    raise ValueError("chat id is invalid")
                value = {**value, "chat_id": int(value["chat_id"])}
            await engine_dispatch(guardian.engine, {"command": command, "data": value})
        return await guardian.status(data["view_token"])
    if command == "run_now" and request["data"] == {}:
        guardian.trigger_run()
        return await guardian.status()
    raise PermissionError("command requires a passkey ceremony")


async def handle(guardian, role, reader, writer):
    try:
        uid = peer_uid(writer)  # Before reading a body containing secrets.
        if uid not in ({1001} if role == "jobs" else {1000, 1002}):
            raise PermissionError("peer uid is invalid")
        raw = await asyncio.wait_for(reader.readline(), 30)
        if not raw.endswith(b"\n"):
            raise ValueError("IPC frame is unterminated")
        response = {"ok": True, "result": await dispatch(guardian, role, uid, strict_json(raw))}
    except Exception as exc:
        response = {"ok": False, "error_type": type(exc).__name__}
    try:
        encoded = canonical_json_bytes(response) + b"\n"
        if len(encoded) > MAX_IPC_BYTES:
            encoded = b'{"ok":false,"error_type":"ResponseSizeError"}\n'
        writer.write(encoded)
        await asyncio.wait_for(writer.drain(), 5)
    except (BrokenPipeError, ConnectionError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionError):
            pass


def check_socket_directory(path: Path, gid: int):
    info = path.lstat()
    if (path.is_symlink() or not path.is_dir() or info.st_uid != 1000
            or info.st_gid != gid or info.st_mode & 0o7777 != 0o2750):
        raise PermissionError("prepare the role IPC directory on the host")


async def serve(paths: Paths) -> int:
    scratch = Path(os.environ.get("SUNNY_SCRATCH_DIR", "/run/guardian-private"))
    clean_secret_scratch(scratch)
    guardian = Guardian(paths, scratch=scratch)
    sockets = {"admin": (paths.runtime_dir / "ipc/admin/admin.sock", 1002),
               "jobs": (paths.runtime_dir / "ipc/jobs/jobs.sock", 1001)}
    servers = []
    try:
        for role, (path, gid) in sockets.items():
            check_socket_directory(path.parent, gid)
            if path.exists():
                if not path.is_socket():
                    raise PermissionError("unexpected IPC file")
                safe_unlink(path)
            server = await asyncio.start_unix_server(
                lambda reader, writer, role=role: handle(guardian, role, reader, writer),
                path=str(path), limit=MAX_IPC_BYTES)
            os.chmod(path, 0o660)
            servers.append(server)
        scheduler = asyncio.create_task(guardian.scheduler())
        exit_waiter = asyncio.create_task(guardian.exit_requested.wait())
        done, _ = await asyncio.wait((scheduler, exit_waiter), return_when=asyncio.FIRST_COMPLETED)
        if scheduler in done and not guardian.exit_requested.is_set():
            # A dead scheduler cannot leave an apparently live admin daemon.
            # Its exception text is not copied into logs or IPC responses.
            scheduler.exception() if not scheduler.cancelled() else None
        await asyncio.sleep(0.1)  # Let the lock response flush before process exit.
        return 75  # restart:on-failure starts a fresh, locked process.
    finally:
        if "scheduler" in locals():
            scheduler.cancel()
            await asyncio.gather(scheduler, return_exceptions=True)
        if "exit_waiter" in locals():
            exit_waiter.cancel()
            await asyncio.gather(exit_waiter, return_exceptions=True)
        for server in servers:
            server.close()
            await server.wait_closed()
        await guardian.close()
        for path, _ in sockets.values():
            if path.is_socket():
                safe_unlink(path)
