from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .storage import atomic_write_bytes
from .vpn_subscription import is_public_unicast_ipv4

MIHOMO_SOCKS_HOST = "127.0.0.1"
MIHOMO_SOCKS_PORT = 7891
MIHOMO_PROXY_NAME = "vpn-active"
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_MODERN_FINGERPRINTS = frozenset({
    "android", "chrome", "edge", "firefox", "ios", "random", "randomized",
    "safari",
})


class MihomoExitedError(RuntimeError):
    """The supervised Mihomo child exited or is no longer usable."""


@dataclass(frozen=True)
class MihomoPaths:
    root: Path
    config: Path

    @classmethod
    def for_runtime_root(cls, root: Path) -> "MihomoPaths":
        root = Path(root)
        return cls(root=root, config=root / "config.yaml")

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)


def _json_copy(value: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
        copied = json.loads(encoded)
    except (TypeError, ValueError):
        raise ValueError("sanitized Mihomo node is invalid") from None
    if not isinstance(copied, dict):
        raise ValueError("sanitized Mihomo node is invalid")
    return copied


def _contains_route_escape(value: Any) -> bool:
    if isinstance(value, str):
        return value.upper() in ("DIRECT", "COMPATIBLE")
    if isinstance(value, list):
        return any(_contains_route_escape(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_route_escape(item) for item in value.values())
    return False


def _static_node(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("sanitized Mihomo node is invalid")
    node = _json_copy(value)
    node.pop("name", None)
    node.pop("udp", None)

    expected = {
        "type", "server", "port", "uuid", "network", "tls", "servername",
        "client-fingerprint", "reality-opts", "flow",
    }
    if set(node) != expected:
        raise ValueError("sanitized Mihomo node has unsupported fields")
    try:
        server_address = ipaddress.ip_address(node.get("server"))
        canonical_uuid = str(uuid.UUID(node.get("uuid")))
    except (AttributeError, TypeError, ValueError):
        raise ValueError("sanitized Mihomo node identity is invalid") from None

    if (node.get("type") != "vless"
            or node.get("tls") is not True
            or not is_public_unicast_ipv4(server_address)
            or node["server"] != server_address.compressed
            or isinstance(node.get("port"), bool)
            or not isinstance(node.get("port"), int)
            or not 1 <= node["port"] <= 65535
            or not isinstance(node.get("uuid"), str)
            or node["uuid"] != canonical_uuid
            or node.get("network") != "tcp"
            or node.get("flow") != "xtls-rprx-vision"
            or node.get("client-fingerprint") not in _MODERN_FINGERPRINTS
            or not isinstance(node.get("servername"), str)
            or not 1 <= len(node["servername"]) <= 253
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in node["servername"]
            )):
        raise ValueError("sanitized Mihomo node is not VLESS")
    reality = node.get("reality-opts")
    if (not isinstance(reality, dict)
            or set(reality) != {"public-key", "short-id"}
            or not isinstance(reality.get("public-key"), str)
            or not 16 <= len(reality["public-key"]) <= 128
            or not _BASE64URL.fullmatch(reality["public-key"])
            or not isinstance(reality.get("short-id"), str)
            or len(reality["short-id"]) > 16
            or len(reality["short-id"]) % 2
            or (reality["short-id"] != ""
                and not _HEX.fullmatch(reality["short-id"]))):
        raise ValueError("sanitized Mihomo node is not REALITY")
    if any(key in node for key in (
            "dialer-proxy", "interface-name", "routing-mark")):
        raise ValueError("sanitized Mihomo node can escape its route")
    if _contains_route_escape(node):
        raise ValueError("sanitized Mihomo node can escape its route")

    node["name"] = MIHOMO_PROXY_NAME
    node["udp"] = False
    return node


def render_mihomo_config(node: Mapping[str, Any]) -> bytes:
    """Render JSON (valid YAML) so remote strings cannot inject configuration."""
    value = {
        "allow-lan": False,
        "ipv6": False,
        "listeners": [{
            "listen": MIHOMO_SOCKS_HOST,
            "name": "telegram-socks",
            "port": MIHOMO_SOCKS_PORT,
            "type": "socks",
            "udp": False,
            "users": [],
        }],
        "log-level": "silent",
        "mode": "rule",
        "proxies": [_static_node(node)],
        "rules": [f"MATCH,{MIHOMO_PROXY_NAME}"],
    }
    return (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    )


def write_mihomo_config(runtime_root: Path, node: Mapping[str, Any]) -> Path:
    paths = MihomoPaths.for_runtime_root(runtime_root)
    paths.ensure()
    atomic_write_bytes(paths.config, render_mihomo_config(node), 0o600)
    return paths.config


class MihomoRuntime:
    """Own one fail-closed Mihomo subprocess and its loopback SOCKS endpoint."""

    def __init__(
        self,
        private_dir: Path,
        *,
        binary: str = "/usr/local/bin/mihomo",
        runtime_parent: Path = Path("/tmp"),
        startup_timeout: float = 20.0,
        stop_timeout: float = 5.0,
        probe_interval: float = 0.1,
    ):
        if startup_timeout <= 0 or stop_timeout <= 0 or probe_interval < 0:
            raise ValueError("Mihomo runtime timeouts are invalid")
        self.private_dir = Path(private_dir)
        self.runtime_parent = Path(runtime_parent)
        self.paths: Optional[MihomoPaths] = None
        self._temporary: Optional[tempfile.TemporaryDirectory] = None
        self.binary = binary
        self.startup_timeout = startup_timeout
        self.stop_timeout = stop_timeout
        self.probe_interval = probe_interval
        self._process: Optional[asyncio.subprocess.Process] = None
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        self._ready = False

    @property
    def ready(self) -> bool:
        return self._ready and self._process is not None \
            and self._process.returncode is None

    async def start(self, node: Mapping[str, Any]) -> None:
        if self._process is not None:
            raise RuntimeError("Mihomo runtime is already started")
        if self._temporary is not None or self.paths is not None:
            raise RuntimeError("Mihomo runtime directory was not cleaned")
        try:
            self._temporary = tempfile.TemporaryDirectory(
                prefix="sunny-mihomo-", dir=str(self.runtime_parent))
            self.paths = MihomoPaths.for_runtime_root(Path(self._temporary.name))
            self.paths.ensure()
            write_mihomo_config(self.paths.root, node)
            environment = {
                "HOME": str(self.paths.root),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TMPDIR": str(self.paths.root),
                "XDG_CONFIG_HOME": str(self.paths.root),
            }
            self._process = await asyncio.create_subprocess_exec(
                self.binary,
                "-d", str(self.paths.root),
                "-f", str(self.paths.config),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=str(self.paths.root),
                env=environment,
                umask=0o077,
                start_new_session=True,
            )
            await self._wait_until_ready()
            self._ready = True
        except BaseException:
            await self.stop()
            raise

    def ensure_alive(self) -> None:
        process = self._process
        if not self.ready:
            returncode = None if process is None else process.returncode
            suffix = "" if returncode is None else f" (exit {returncode})"
            raise MihomoExitedError(f"Mihomo SOCKS is not ready{suffix}")

    async def wait_until_exit(self) -> None:
        process = self._process
        if process is None:
            raise MihomoExitedError("Mihomo runtime is not started")
        returncode = await process.wait()
        self._ready = False
        await self.stop()
        raise MihomoExitedError(f"Mihomo exited with status {returncode}")

    async def stop(self) -> None:
        self._ready = False
        cleanup = self._cleanup_task
        if cleanup is None:
            process = self._process
            temporary = self._temporary
            if process is None and temporary is None:
                return
            cleanup = asyncio.create_task(
                self._terminate_reap_and_cleanup(process, temporary))
            self._cleanup_task = cleanup

        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # Cancellation is returned only after the child is physically
                # gone and its bearer-derived runtime directory is erased.
                cancelled = True
        try:
            cleanup.result()
        finally:
            if self._cleanup_task is cleanup:
                self._process = None
                self._temporary = None
                self.paths = None
                self._cleanup_task = None
        if cancelled:
            raise asyncio.CancelledError

    async def _terminate_reap_and_cleanup(
        self,
        process: Optional[asyncio.subprocess.Process],
        temporary: Optional[tempfile.TemporaryDirectory],
    ) -> None:
        try:
            if process is not None:
                if process.returncode is None:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        # The event loop can observe exit just after returncode
                        # was checked; wait() still performs the required reap.
                        pass
                    try:
                        await asyncio.wait_for(
                            process.wait(), timeout=self.stop_timeout)
                    except asyncio.TimeoutError:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        await process.wait()
                else:
                    await process.wait()
        finally:
            if temporary is not None:
                # This exact random directory is owned by TemporaryDirectory.
                # Mihomo may create cache.db or other runtime material inside;
                # cleanup happens only after the child has been reaped.
                temporary.cleanup()

    async def _wait_until_ready(self) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.startup_timeout
        while True:
            process = self._process
            if process is None:
                raise MihomoExitedError("Mihomo runtime is not started")
            if process.returncode is not None:
                raise MihomoExitedError(
                    "Mihomo exited before readiness with status "
                    f"{process.returncode}")
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("Mihomo SOCKS readiness timed out")
            try:
                await asyncio.wait_for(
                    self._probe_socks(), timeout=min(1.0, remaining))
                if process.returncode is not None:
                    raise MihomoExitedError(
                        "Mihomo exited before readiness with status "
                        f"{process.returncode}")
                return
            except (OSError, ConnectionError, asyncio.IncompleteReadError,
                    asyncio.TimeoutError):
                delay = min(self.probe_interval, max(0.0, deadline - loop.time()))
                if delay:
                    await asyncio.sleep(delay)

    async def _probe_socks(self) -> None:
        reader, writer = await asyncio.open_connection(
            MIHOMO_SOCKS_HOST, MIHOMO_SOCKS_PORT)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise ConnectionError("Mihomo SOCKS negotiation failed")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
