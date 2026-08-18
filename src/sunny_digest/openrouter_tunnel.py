"""SSH-туннель до OpenRouter.

Инцидент 2026-08-17/18: запрос к OpenRouter не проходил ни одним прямым путём.
Из домашней сети фильтр отвечал `Access denied by security policy`, а через
VLESS-туннель Cloudflare отдавал 403 с любого из трёх узлов — при том, что с
самих узлов и с DO тот же запрос проходил. Поэтому трафик уходит через DO, и
только он: дроплет открывает соединение к openrouter.ai, а TLS остаётся
сквозным — прокси видит имя хоста, но не тело запроса и не ключ.

Канал узкий по построению. Ключ отдельный от upload-ключа, и в authorized_keys
у него `restrict,port-forwarding,permitopen="openrouter.ai:443"`: sshd не даст
ни shell, ни другого адреса, даже если приложение скомпрометировано. Ограничение
живёт на стороне сервера, а не в нашем коде.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .storage import Paths

TUNNEL_HOST = "127.0.0.1"
TUNNEL_PORT = 7893
# Свой непривилегированный пользователь, НЕ root receiver'а: permitopen
# ограничивает только адреса локального проброса, а флаг port-forwarding
# включает форварды целиком, вместе с обратным (-R). Ключ к root с такими
# правами позволял бы открыть порт на дроплете наружу, поэтому канал живёт под
# отдельной учёткой, а sshd в блоке `Match User` разрешает ей ровно
# `AllowTcpForwarding local` на один адрес.
TUNNEL_USER = "sunny-openrouter"
OPENROUTER_HOST = "openrouter.ai"
OPENROUTER_PORT = 443
READY_TIMEOUT_S = 20.0
PROBE_INTERVAL_S = 0.2


class TunnelUnavailableError(RuntimeError):
    """Туннель не поднялся или умер; digest без него не собирается."""


async def generate_openrouter_key(paths: Paths, source_id: str) -> Tuple[str, str]:
    """Ключ канала. Публичную часть Иван добавляет на DO install-скриптом."""
    from .ssh_transport import _run_command

    if paths.openrouter_key.exists() or paths.openrouter_public_key.exists():
        raise RuntimeError("openrouter key already exists")
    returncode, _ = await _run_command([
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
        f"{source_id}@sunny-openrouter", "-f", str(paths.openrouter_key),
    ], timeout=15)
    if returncode != 0:
        raise RuntimeError("ssh-keygen failed")
    os.chmod(paths.openrouter_key, 0o600)
    os.chmod(paths.openrouter_public_key, 0o600)
    public_key = paths.openrouter_public_key.read_text(encoding="ascii").strip()
    returncode, output = await _run_command(
        ["ssh-keygen", "-lf", str(paths.openrouter_public_key), "-E", "sha256"],
        timeout=10)
    if returncode != 0:
        raise RuntimeError("ssh-keygen fingerprint failed")
    fields = output.decode("ascii").strip().split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise RuntimeError("ssh-keygen returned an invalid fingerprint")
    return public_key, fields[1]


class OpenRouterTunnel:
    """Супервизор дочернего ssh — по образцу MihomoRuntime.

    Держит `ssh -N -L`, поднимается перед digest-запросом и гасится после.
    Постоянного соединения намеренно нет: канал нужен раз в сутки, а живущий
    круглосуточно ssh пришлось бы сторожить и переподнимать."""

    def __init__(self, paths: Paths, upload: Dict[str, Any], *,
                 port: int = TUNNEL_PORT, ready_timeout: float = READY_TIMEOUT_S,
                 probe_interval: float = PROBE_INTERVAL_S) -> None:
        self.paths = paths
        self.host = upload["host"]
        self.port = int(upload["port"])
        # хост и порт те же, что у receiver'а, а пользователь свой
        self.user = TUNNEL_USER
        self.local_port = port
        self.ready_timeout = ready_timeout
        self.probe_interval = probe_interval
        self._process: Optional[asyncio.subprocess.Process] = None

    def _args(self) -> list[str]:
        return [
            "ssh", "-F", "/dev/null", "-N", "-T",
            "-i", str(self.paths.openrouter_key),
            "-p", str(self.port),
            "-L", f"{TUNNEL_HOST}:{self.local_port}:{OPENROUTER_HOST}:{OPENROUTER_PORT}",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.paths.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "PubkeyAcceptedAlgorithms=ssh-ed25519",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "RequestTTY=no",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=3",
            "-o", "LogLevel=ERROR",
            f"{self.user}@{self.host}",
        ]

    async def start(self) -> None:
        if self._process is not None:
            raise RuntimeError("tunnel already started")
        if not self.paths.openrouter_key.exists():
            raise TunnelUnavailableError("openrouter tunnel key is missing")
        self._process = await asyncio.create_subprocess_exec(
            *self._args(), stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await self._wait_until_ready()
        except BaseException:
            await self.stop()
            raise

    async def _wait_until_ready(self) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.ready_timeout
        while True:
            process = self._process
            if process is None or process.returncode is not None:
                # ExitOnForwardFailure: занятый порт или отказ permitopen
                # роняет ssh сразу, и ждать готовности больше нечего
                raise TunnelUnavailableError("ssh tunnel exited before readiness")
            if loop.time() >= deadline:
                raise TunnelUnavailableError("ssh tunnel readiness timed out")
            try:
                _reader, writer = await asyncio.open_connection(
                    TUNNEL_HOST, self.local_port)
            except (OSError, ConnectionError):
                await asyncio.sleep(self.probe_interval)
                continue
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

    def ensure_alive(self) -> None:
        process = self._process
        if process is None or process.returncode is not None:
            raise TunnelUnavailableError("ssh tunnel is not running")

    async def stop(self) -> None:
        process, self._process = self._process, None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
