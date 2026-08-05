from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

from .contracts import (
    canonical_upload_bytes,
    status_request,
    validate_gate,
    validate_receipt,
    validate_upload,
)
from .storage import Paths


MAX_SSH_RESPONSE_BYTES = 64 * 1024


async def _terminate(process: Any) -> None:
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2)
    except (asyncio.TimeoutError, ProcessLookupError):
        try:
            process.kill()
        except ProcessLookupError:
            return
        await process.wait()


async def _run_command(args: list[str], stdin: bytes | None = None,
                       timeout: float = 30.0) -> Tuple[int, bytes]:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(stdin), timeout=timeout)
    except BaseException:
        await _terminate(process)
        raise
    if len(stdout) > MAX_SSH_RESPONSE_BYTES:
        raise RuntimeError("SSH response exceeds size limit")
    return process.returncode, stdout


async def _bounded_exchange(process: Any, request: bytes) -> bytes:
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("SSH pipes are unavailable")
    process.stdin.write(request)
    await process.stdin.drain()
    process.stdin.close()
    try:
        await process.stdin.wait_closed()
    except (AttributeError, BrokenPipeError, ConnectionResetError):
        pass

    chunks = []
    size = 0
    while True:
        chunk = await process.stdout.read(min(8192, MAX_SSH_RESPONSE_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_SSH_RESPONSE_BYTES:
            raise RuntimeError("SSH response exceeds size limit")
    await process.wait()
    return b"".join(chunks)


async def generate_upload_key(paths: Paths, source_id: str) -> Tuple[str, str]:
    if paths.upload_key.exists() or paths.upload_public_key.exists():
        raise RuntimeError("upload key already exists")
    args = [
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
        f"{source_id}@sunny-umbrel", "-f", str(paths.upload_key),
    ]
    returncode, _ = await _run_command(args, timeout=15)
    if returncode != 0:
        raise RuntimeError("ssh-keygen failed")
    os.chmod(paths.upload_key, 0o600)
    os.chmod(paths.upload_public_key, 0o600)
    public_key = paths.upload_public_key.read_text(encoding="ascii").strip()
    returncode, output = await _run_command(
        ["ssh-keygen", "-lf", str(paths.upload_public_key), "-E", "sha256"], timeout=10)
    if returncode != 0:
        raise RuntimeError("ssh-keygen fingerprint failed")
    fields = output.decode("ascii").strip().split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise RuntimeError("ssh-keygen returned an invalid fingerprint")
    return public_key, fields[1]


class SSHTransport:
    def __init__(self, paths: Paths, upload: Dict[str, Any]):
        self.paths = paths
        self.host = upload["host"]
        self.port = int(upload["port"])
        self.user = upload["user"]

    def _args(self, command: str) -> list[str]:
        if command not in ("status-v1", "upload-v1"):
            raise ValueError("unsupported receiver command")
        return [
            "ssh", "-F", "/dev/null", "-T",
            "-i", str(self.paths.upload_key),
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.paths.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "PubkeyAcceptedAlgorithms=ssh-ed25519",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "UpdateHostKeys=no",
            "-o", "RequestTTY=no",
            "-o", "LogLevel=ERROR",
            f"{self.user}@{self.host}",
            command,
        ]

    async def _exchange(self, command: str, request: bytes,
                        revoked: asyncio.Event) -> Dict[str, Any]:
        if revoked.is_set():
            raise asyncio.CancelledError
        process = await asyncio.create_subprocess_exec(
            *self._args(command), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        exchange = asyncio.create_task(_bounded_exchange(process, request))
        cancelled = asyncio.create_task(revoked.wait())
        try:
            done, _ = await asyncio.wait(
                (exchange, cancelled), timeout=30, return_when=asyncio.FIRST_COMPLETED)
            if cancelled in done and revoked.is_set():
                await _terminate(process)
                exchange.cancel()
                await asyncio.gather(exchange, return_exceptions=True)
                raise asyncio.CancelledError
            if exchange not in done:
                await _terminate(process)
                exchange.cancel()
                await asyncio.gather(exchange, return_exceptions=True)
                raise RuntimeError("SSH exchange timed out")
            stdout = exchange.result()
        except BaseException:
            await _terminate(process)
            if not exchange.done():
                exchange.cancel()
                await asyncio.gather(exchange, return_exceptions=True)
            raise
        finally:
            cancelled.cancel()
            await asyncio.gather(cancelled, return_exceptions=True)
        if revoked.is_set():
            # Receipt may already be durable remotely. Keep pending bytes and let the
            # next status-v1 query reconcile the chain.
            raise asyncio.CancelledError
        if process.returncode != 0:
            raise RuntimeError("SSH forced command failed")
        try:
            value = json.loads(stdout.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("SSH response is not valid JSON") from None
        if not isinstance(value, dict):
            raise RuntimeError("SSH response root is not an object")
        return value

    async def gate(self, source_id: str, chat_id: int, revoked: asyncio.Event) -> Dict[str, Any]:
        request = status_request(source_id, chat_id)
        return validate_gate(await self._exchange("status-v1", request, revoked))

    async def upload(self, pending_bytes: bytes, revoked: asyncio.Event) -> Dict[str, Any]:
        try:
            upload = json.loads(pending_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("pending upload is invalid") from None
        if not isinstance(upload, dict):
            raise RuntimeError("pending upload is invalid")
        validate_upload(upload)
        if canonical_upload_bytes(upload) != pending_bytes:
            raise RuntimeError("pending upload bytes are not canonical")
        receipt = await self._exchange("upload-v1", pending_bytes, revoked)
        return validate_receipt(receipt, upload)
