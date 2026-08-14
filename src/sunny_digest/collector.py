from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .contracts import (
    build_digest_upload,
    build_monitor_upload,
    canonical_digest_bytes,
    canonical_monitor_bytes,
    parse_utc,
    utc_iso,
    validate_digest_upload,
    validate_gate,
    validate_monitor_upload,
)
from .models import DialogCandidate, DigestChat, PeerSpec
from .mihomo import (
    MIHOMO_SOCKS_HOST,
    MIHOMO_SOCKS_PORT,
    MihomoRuntime,
    render_mihomo_config,
)
from .openrouter import create_digest
from .settings import (
    MAX_CONSENT_DAYS,
    CONSENT_SCOPE,
    consent_active,
    load_credentials,
    load_settings,
    new_source_id,
    save_initial_config,
    validate_consent_expiry,
    validate_configure,
)
from .ssh_transport import SSHTransport, generate_upload_key
from .storage import (
    Paths,
    atomic_write_bytes,
    atomic_write_json,
    read_json,
    safe_unlink,
    unlink_atomic_material,
)
from .telegram_gateway import TelethonGateway, parse_message_link
from .version import (
    DEFAULT_LOOKBACK_HOURS,
    MAX_PROMPT_BYTES,
    MAX_SELECTED_CHATS,
    MAX_UPLOAD_BYTES,
)
from .vpn_subscription import fetch_vless_subscription


GatewayFactory = Callable[[int, str, Dict[str, Any]], Any]
DigestFunction = Callable[[List[DigestChat], str, str, asyncio.Event], Awaitable[str]]
TransportFactory = Callable[[Paths, Dict[str, Any]], Any]
KeygenFunction = Callable[[Paths, str], Awaitable[tuple[str, str]]]
VPNRuntimeFactory = Callable[[Path], Any]
SubscriptionFetcher = Callable[[Any], Awaitable[List[Dict[str, Any]]]]


DIGEST_ACKNOWLEDGED_SCHEMA = "sunny.personal-chats.digest-acknowledged.v2"
WATCH_STATE_SCHEMA = "sunny.personal-chats.watch-state.v2"
REVOCATION_WARNING_SCHEMA = "sunny.personal-chats.revocation-warning.v2"
SESSION_OUTSTANDING_SCHEMA = "sunny.personal-chats.session-outstanding.v2"
DIALOG_CANDIDATES_SCHEMA = "sunny.personal-chats.dialog-candidates.v2"
TELEGRAM_SETUP_TIMEOUT_S = 90
TELEGRAM_DIALOG_TIMEOUT_S = 120
TELEGRAM_FETCH_TIMEOUT_S = 180
KEYGEN_TIMEOUT_S = 30
OPENROUTER_TIMEOUT_S = 120
VPN_SUBSCRIPTION_TIMEOUT_S = 30
SETUP_CONSENT_LEASE_S = 3600


class VPNMigrationRequiredError(RuntimeError):
    """An accepted pre-VPN configuration cannot make Telegram connections."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _masked_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return f"+***{digits[-4:]}" if len(digits) >= 4 else "+***"


def _load_dialog_candidates(paths: Paths) -> tuple[str, List[DialogCandidate]]:
    value = read_json(paths.dialog_candidates, max_bytes=512 * 1024)
    if not isinstance(value, dict) or set(value) != {
            "schema", "selection_id", "dialogs"}:
        raise ValueError("dialog candidates are invalid")
    if value.get("schema") != DIALOG_CANDIDATES_SCHEMA:
        raise ValueError("dialog candidates are invalid")
    try:
        selection_id = str(uuid.UUID(value.get("selection_id")))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("dialog candidates are invalid") from None
    if selection_id != value.get("selection_id"):
        raise ValueError("dialog candidates are invalid")
    rows = value.get("dialogs")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_SELECTED_CHATS:
        raise ValueError("dialog candidates are invalid")
    candidates = [DialogCandidate.from_private_dict(row) for row in rows]
    if len({row.chat_id for row in candidates}) != len(candidates):
        raise ValueError("dialog candidates are invalid")
    return selection_id, candidates


class Collector:
    def __init__(
        self,
        paths: Paths,
        *,
        gateway_factory: GatewayFactory = TelethonGateway,
        digest_function: DigestFunction = create_digest,
        transport_factory: TransportFactory = SSHTransport,
        keygen_function: KeygenFunction = generate_upload_key,
        vpn_runtime_factory: VPNRuntimeFactory = MihomoRuntime,
        subscription_fetcher: SubscriptionFetcher = fetch_vless_subscription,
        clock: Callable[[], datetime] = _now,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.paths = paths
        self.paths.ensure()
        self.gateway_factory = gateway_factory
        self.digest_function = digest_function
        self.transport_factory = transport_factory
        self.keygen_function = keygen_function
        self.subscription_fetcher = subscription_fetcher
        self._vpn_runtime = vpn_runtime_factory(self.paths.private_dir)
        self.clock = clock
        self.monotonic = monotonic
        self.state_lock = asyncio.Lock()
        self.run_lock = asyncio.Lock()
        self.vpn_lock = asyncio.Lock()
        self.revoked = asyncio.Event()
        self._run_task: Optional[asyncio.Task[Any]] = None
        self._active_run_task: Optional[asyncio.Task[Any]] = None
        self._external_tasks: set[asyncio.Task[Any]] = set()
        self._last_attempt: Optional[tuple[int, float]] = None
        # Pre-lock Telegram metadata access has no authenticated server clock.
        # A single in-process monotonic lease prevents wall-clock rollback from
        # extending setup; restart before chat lock therefore fails closed.
        self._setup_deadline_mono: Optional[float] = None
        # This non-secret marker survives backup while StringSession does not.
        # Restoring config alone must not make a possibly live remote session
        # look revoked merely because its local credential is absent.
        if (self.paths.telegram_session_outstanding.exists()
                and not self.paths.telegram_session.exists()):
            self._write_revocation_warning()
        self._write_status(last_result="starting")

    def _write_revocation_warning(self) -> None:
        atomic_write_json(self.paths.revocation_warning, {
            "schema": REVOCATION_WARNING_SCHEMA,
            "warning": "TelegramLogoutUnconfirmed",
            "created_at": self.clock().astimezone(timezone.utc).isoformat(
                timespec="seconds").replace("+00:00", "Z"),
        })

    def _mark_session_outstanding(self) -> None:
        if self.paths.telegram_session_outstanding.exists():
            return
        atomic_write_json(self.paths.telegram_session_outstanding, {
            "schema": SESSION_OUTSTANDING_SCHEMA,
            "outstanding": True,
            "created_at": self.clock().astimezone(timezone.utc).isoformat(
                timespec="seconds").replace("+00:00", "Z"),
        })

    async def _bounded_external(self, awaitable: Awaitable[Any], timeout: float) -> Any:
        """Give every network/keygen operation an absolute cancellable deadline."""
        task = asyncio.ensure_future(awaitable)
        self._external_tasks.add(task)
        try:
            return await asyncio.wait_for(task, timeout=timeout)
        finally:
            self._external_tasks.discard(task)

    async def _cancel_active_operations(self) -> None:
        """Overtake setup and runtime work before reset removes credentials."""
        current = asyncio.current_task()
        targets = {
            task for task in (
                self._active_run_task,
                self._run_task,
                *tuple(self._external_tasks),
            )
            if task is not None and task is not current and not task.done()
        }
        for task in targets:
            task.cancel()
        if targets:
            await asyncio.gather(*targets, return_exceptions=True)

    @staticmethod
    def _validate_vpn_node(node: Any) -> Dict[str, Any]:
        if not isinstance(node, dict) or set(node) != {
                "type", "server", "port", "uuid", "network", "tls",
                "servername", "client-fingerprint", "reality-opts", "flow", "udp"}:
            raise ValueError("stored Telegram VPN node is invalid")
        if (node.get("network") != "tcp"
                or node.get("flow") != "xtls-rprx-vision"
                or node.get("udp") is not False
                or not isinstance(node.get("reality-opts"), dict)
                or set(node["reality-opts"]) != {"public-key", "short-id"}):
            raise ValueError("stored Telegram VPN node is invalid")
        # The runtime validator is a second, independent boundary before exec.
        render_mihomo_config(node)
        return node

    def _load_vpn_node(self) -> Dict[str, Any]:
        if not self.paths.vpn_active_node.exists():
            if self.paths.settings.exists():
                raise VPNMigrationRequiredError(
                    "factory reset is required to configure the Telegram VPN")
            raise RuntimeError("Telegram VPN is not configured")
        return self._validate_vpn_node(
            read_json(self.paths.vpn_active_node, max_bytes=16 * 1024))

    async def _start_vpn_node(self, node: Dict[str, Any]) -> None:
        async with self.vpn_lock:
            # This also reaps a child which died after an earlier successful start.
            await self._vpn_runtime.stop()
            await self._vpn_runtime.start(node)
            self._vpn_runtime.ensure_alive()

    async def _ensure_vpn(self) -> None:
        async with self.vpn_lock:
            if getattr(self._vpn_runtime, "ready", False):
                self._vpn_runtime.ensure_alive()
                return
            node = self._load_vpn_node()
            await self._vpn_runtime.stop()
            await self._vpn_runtime.start(node)
            self._vpn_runtime.ensure_alive()

    async def _stop_vpn(self) -> None:
        async with self.vpn_lock:
            await self._vpn_runtime.stop()

    def _require_no_revocation_warning(self) -> None:
        if self.paths.revocation_warning.exists():
            raise RuntimeError("manual Telegram device revocation is required")

    def _capture_epoch(self) -> asyncio.Event:
        self._require_no_revocation_warning()
        epoch = self.revoked
        if epoch.is_set():
            raise RuntimeError("factory reset is in progress")
        return epoch

    def _require_current_epoch(self, epoch: asyncio.Event) -> None:
        self._require_no_revocation_warning()
        if epoch is not self.revoked or epoch.is_set():
            raise RuntimeError("factory reset is in progress")

    def _gateway(self, credentials: Dict[str, Any]):
        # Even a missed caller-side readiness check cannot construct a direct
        # Telegram client: gateway creation itself requires the SOCKS child.
        self._vpn_runtime.ensure_alive()
        return self.gateway_factory(
            credentials["telegram_api_id"], credentials["telegram_api_hash"], {
                "proxy_type": "socks5",
                "addr": MIHOMO_SOCKS_HOST,
                "port": MIHOMO_SOCKS_PORT,
                "rdns": True,
            })

    def _session_text(self) -> str:
        if not self.paths.telegram_session.exists():
            return ""
        raw = self.paths.telegram_session.read_text(encoding="ascii").strip()
        if len(raw) > 8192:
            raise ValueError("Telegram session exceeds size limit")
        return raw

    def _save_session(self, value: str) -> None:
        if not isinstance(value, str) or not value or len(value) > 8192 or "\n" in value:
            raise ValueError("Telegram session is invalid")
        atomic_write_bytes(self.paths.telegram_session, value.encode("ascii"), 0o600)

    def _base_status(self) -> Dict[str, Any]:
        status: Dict[str, Any] = {
            "schema": "sunny.personal-chats.local-status.v2",
            "phase": "fresh",
            "configured": False,
            "chat_locked": False,
            "consent_active": False,
            "pending_digest_upload": self.paths.pending.exists(),
            "pending_monitor_upload": self.paths.monitor_pending.exists(),
            "source_id": None,
            "chats": [],
            "monitoring_phase": "not_selected",
            "activation_required": False,
            "monitoring_active": False,
            "upload_public_key": None,
            "upload_key_fingerprint": None,
            "model": None,
            "upload_target": None,
            "consent_expires_at": None,
            "phone_masked": None,
            "dialogs": [],
            "selection_id": None,
            "last_run_at": None,
            "last_result": None,
            "last_error_type": None,
            "last_message_count": None,
            "last_through_message_id": None,
            "failed_chat_count": 0,
            "revocation_required": self.paths.revocation_warning.exists(),
            "vpn_configured": self.paths.vpn_active_node.exists(),
            "vpn_ready": bool(getattr(self._vpn_runtime, "ready", False)),
            "vpn_migration_required": (
                self.paths.settings.exists()
                and not self.paths.vpn_active_node.exists()
            ),
        }
        if self.paths.settings.exists():
            try:
                settings = load_settings(self.paths)
                status.update(
                    phase=settings["phase"],
                    configured=True,
                    chat_locked=settings["chat_locked"],
                    consent_active=(
                        consent_active(settings, self.clock())
                        if settings["chat_locked"]
                        else self._setup_consent_active(settings)
                    ),
                )
                if settings["chat_locked"]:
                    chats = [
                        {"chat_id": row["chat_id"], "title": row["title"],
                         "kind": row["peer"]["kind"]}
                        for row in settings["chats"]
                    ]
                    monitoring_phase = "activation_required"
                    if self.paths.watch_state.exists():
                        watch = read_json(self.paths.watch_state, max_bytes=64 * 1024)
                        if watch.get("schema") == WATCH_STATE_SCHEMA:
                            monitoring_phase = str(watch.get("phase"))
                    status.update(
                        source_id=settings["source_id"],
                        chats=chats,
                        monitoring_phase=monitoring_phase,
                        activation_required=not self.paths.watch_state.exists(),
                        monitoring_active=monitoring_phase == "active",
                        upload_public_key=settings["upload_public_key"],
                        upload_key_fingerprint=settings["upload_key_fingerprint"],
                        model=settings["openrouter_model"],
                        upload_target=(
                            f'{settings["upload"]["user"]}@{settings["upload"]["host"]}:'
                            f'{settings["upload"]["port"]}'
                        ),
                        consent_expires_at=settings["consent"]["expires_at"],
                    )
                elif (status["consent_active"]
                      and settings["phase"] == "dialogs_listed"
                      and self.paths.dialog_candidates.exists()):
                    selection_id, candidates = _load_dialog_candidates(self.paths)
                    status["selection_id"] = selection_id
                    status["dialogs"] = [row.as_ui_dict() for row in candidates]
                if self.paths.setup_state.exists():
                    setup = read_json(self.paths.setup_state, max_bytes=16 * 1024)
                    if isinstance(setup.get("phone_masked"), str):
                        status["phone_masked"] = setup["phone_masked"]
            except Exception as exc:
                status.update(phase="error", last_error_type=type(exc).__name__)
        if self.paths.status.exists():
            try:
                previous = read_json(self.paths.status, max_bytes=16 * 1024)
                for key in (
                    "last_run_at", "last_result", "last_error_type",
                    "last_message_count", "last_through_message_id",
                    "failed_chat_count",
                ):
                    if key in previous:
                        status[key] = previous[key]
            except Exception:
                pass
        if self.paths.revocation_warning.exists():
            try:
                warning = read_json(self.paths.revocation_warning, max_bytes=4096)
                if (set(warning) == {"schema", "warning", "created_at"}
                        and warning.get("schema") == REVOCATION_WARNING_SCHEMA
                        and warning.get("warning") == "TelegramLogoutUnconfirmed"):
                    parse_utc(warning.get("created_at"), "revocation created_at")
                    status["revocation_required"] = True
                    status["last_error_type"] = "TelegramLogoutUnconfirmed"
                else:
                    status.update(phase="error", revocation_required=True,
                                  last_error_type="RevocationWarningInvalid")
            except Exception:
                status.update(phase="error", revocation_required=True,
                              last_error_type="RevocationWarningInvalid")
            # This is the only actionable state. Hide restored or corrupt setup
            # metadata until the operator has handled the remote Telegram device.
            status.update(
                phase="fresh", configured=False, chat_locked=False,
                consent_active=False, pending_digest_upload=False,
                pending_monitor_upload=False, source_id=None, chats=[],
                monitoring_phase="not_selected", activation_required=False,
                monitoring_active=False,
                upload_public_key=None, upload_key_fingerprint=None, model=None,
                upload_target=None, consent_expires_at=None, phone_masked=None,
                dialogs=[], selection_id=None, revocation_required=True,
            )
        # A locked runtime status must never expose dialog candidates or setup state.
        if status["chat_locked"]:
            status["dialogs"] = []
            status["selection_id"] = None
            status["phone_masked"] = None
        return status

    def _write_status(self, **changes: Any) -> Dict[str, Any]:
        status = self._base_status()
        status.update(changes)
        allowed = {
            "schema", "phase", "configured", "chat_locked", "consent_active",
            "pending_digest_upload", "pending_monitor_upload", "source_id", "chats",
            "monitoring_phase", "activation_required", "monitoring_active",
            "upload_public_key", "upload_key_fingerprint",
            "model", "upload_target", "consent_expires_at",
            "phone_masked", "dialogs", "selection_id", "last_run_at", "last_result",
            "last_error_type", "last_message_count", "last_through_message_id",
            "failed_chat_count", "revocation_required",
            "vpn_configured", "vpn_ready", "vpn_migration_required",
        }
        status = {key: status.get(key) for key in allowed}
        atomic_write_json(self.paths.status, status, 0o600)
        atomic_write_bytes(self.paths.heartbeat, b"ok\n", 0o600)
        return status

    async def public_status(self) -> Dict[str, Any]:
        return self._write_status()

    def _setup_consent_active(self, settings: Dict[str, Any]) -> bool:
        return (
            consent_active(settings, self.clock())
            and self._setup_deadline_mono is not None
            and self.monotonic() < self._setup_deadline_mono
        )

    def _require_setup_consent(self, settings: Dict[str, Any]) -> None:
        if not self._setup_consent_active(settings):
            raise RuntimeError("setup consent is expired")

    async def configure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        async with self.state_lock:
            if (self.paths.revocation_warning.exists()
                    or self.paths.telegram_session_outstanding.exists()):
                raise RuntimeError(
                    "manual Telegram device revocation must be acknowledged first")
            if (self.paths.chat_locked.exists() or self.paths.settings.exists()
                    or self.paths.credentials.exists()
                    or self.paths.vpn_active_node.exists()):
                raise RuntimeError("factory reset is required before configuration")
            epoch = self._capture_epoch()
            settings, credentials, known_host, subscription_url = validate_configure(
                data, self.clock())
            try:
                nodes = await self._bounded_external(
                    self.subscription_fetcher(subscription_url),
                    VPN_SUBSCRIPTION_TIMEOUT_S,
                )
                self._require_current_epoch(epoch)
                if not isinstance(nodes, list) or not nodes:
                    raise RuntimeError("Telegram VPN subscription is empty")
                node = self._validate_vpn_node(nodes[0])
                await self._start_vpn_node(node)
                self._require_current_epoch(epoch)
                atomic_write_json(self.paths.vpn_active_node, node, 0o600)
                save_initial_config(self.paths, settings, credentials, known_host)
            except BaseException:
                try:
                    try:
                        await self._stop_vpn()
                    except BaseException:
                        # Preserve the configure failure after the supervised
                        # child has completed its own non-cancellable cleanup.
                        pass
                finally:
                    unlink_atomic_material((
                        self.paths.vpn_active_node,
                        self.paths.credentials,
                        self.paths.known_hosts,
                        self.paths.settings,
                    ))
                    self.paths.remove_empty_vpn_dir()
                raise
            self._setup_deadline_mono = self.monotonic() + SETUP_CONSENT_LEASE_S
            return self._write_status(last_result="configured", last_error_type=None)

    async def send_code(self, phone: Any) -> Dict[str, Any]:
        async with self.state_lock:
            epoch = self._capture_epoch()
            settings = load_settings(self.paths)
            if settings["chat_locked"] or settings["phase"] != "configured":
                raise RuntimeError("send_code is not allowed in this phase")
            self._require_setup_consent(settings)
            if not isinstance(phone, str) or not re.fullmatch(r"\+[0-9]{7,15}", phone):
                raise ValueError("phone must use international +digits format")
            await self._ensure_vpn()
            self._require_current_epoch(epoch)
            # Arm before the first authorization network call. There is no
            # transaction with Telegram: a false-positive manual device check
            # after a crash is safer than an untracked live session.
            self._mark_session_outstanding()
            credentials = load_credentials(self.paths)
            session, phone_code_hash = await self._bounded_external(
                self._gateway(credentials).send_code(self._session_text(), phone),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            self._require_current_epoch(epoch)
            self._save_session(session)
            self._require_setup_consent(settings)
            atomic_write_json(self.paths.setup_state, {
                "phone": phone,
                "phone_masked": _masked_phone(phone),
                "phone_code_hash": phone_code_hash,
            })
            settings["phase"] = "code_sent"
            atomic_write_json(self.paths.settings, settings)
            return self._write_status(last_result="code_sent", last_error_type=None)

    async def submit_code(self, code: Any) -> Dict[str, Any]:
        async with self.state_lock:
            epoch = self._capture_epoch()
            settings = load_settings(self.paths)
            if settings["chat_locked"] or settings["phase"] != "code_sent":
                raise RuntimeError("submit_code is not allowed in this phase")
            self._require_setup_consent(settings)
            if not isinstance(code, str) or not re.fullmatch(r"[0-9]{3,8}", code):
                raise ValueError("Telegram code is invalid")
            setup = read_json(self.paths.setup_state, max_bytes=16 * 1024)
            credentials = load_credentials(self.paths)
            await self._ensure_vpn()
            self._require_current_epoch(epoch)
            session, needs_password = await self._bounded_external(
                self._gateway(credentials).submit_code(
                    self._session_text(), setup["phone"], code,
                    setup["phone_code_hash"],
                ),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            self._require_current_epoch(epoch)
            self._save_session(session)
            self._require_setup_consent(settings)
            settings["phase"] = "password_required" if needs_password else "authenticated"
            atomic_write_json(self.paths.settings, settings)
            if not needs_password:
                safe_unlink(self.paths.setup_state)
            return self._write_status(
                last_result="password_required" if needs_password else "authenticated",
                last_error_type=None,
            )

    async def submit_password(self, password: Any) -> Dict[str, Any]:
        async with self.state_lock:
            epoch = self._capture_epoch()
            settings = load_settings(self.paths)
            if settings["chat_locked"] or settings["phase"] != "password_required":
                raise RuntimeError("submit_password is not allowed in this phase")
            self._require_setup_consent(settings)
            if not isinstance(password, str) or not 1 <= len(password) <= 512:
                raise ValueError("Telegram 2FA password is invalid")
            credentials = load_credentials(self.paths)
            await self._ensure_vpn()
            self._require_current_epoch(epoch)
            session = await self._bounded_external(
                self._gateway(credentials).submit_password(
                    self._session_text(), password),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            self._require_current_epoch(epoch)
            self._save_session(session)
            self._require_setup_consent(settings)
            settings["phase"] = "authenticated"
            atomic_write_json(self.paths.settings, settings)
            safe_unlink(self.paths.setup_state)
            return self._write_status(last_result="authenticated", last_error_type=None)

    async def resolve_chat_links(self, links: Any) -> Dict[str, Any]:
        async with self.state_lock:
            epoch = self._capture_epoch()
            settings = load_settings(self.paths)
            # The durable phase is committed before dialog enumeration. A failed or
            # interrupted attempt therefore cannot silently enumerate again.
            if settings["chat_locked"] or self.paths.chat_locked.exists():
                raise RuntimeError("chat link resolution is disabled for the locked session")
            if settings["phase"] != "authenticated" or self.paths.dialog_candidates.exists():
                raise RuntimeError("chat link resolution has already been used or is unavailable")
            if not isinstance(links, list) or not 1 <= len(links) <= MAX_SELECTED_CHATS:
                raise ValueError("1 to 16 message links are required")
            if any(not isinstance(link, str) or not 1 <= len(link) <= 2048
                   for link in links):
                raise ValueError("Telegram message link is invalid")
            locators = [parse_message_link(link) for link in links]
            if len(set(locators)) != len(locators):
                raise ValueError("message links contain a duplicate group locator")
            self._require_setup_consent(settings)
            credentials = load_credentials(self.paths)
            session_text = self._session_text()
            settings["phase"] = "resolving_links"
            atomic_write_json(self.paths.settings, settings)
            await self._ensure_vpn()
            self._require_current_epoch(epoch)
            dialogs = await self._bounded_external(
                self._gateway(credentials).resolve_message_links(
                    session_text, links),
                TELEGRAM_DIALOG_TIMEOUT_S,
            )
            self._require_current_epoch(epoch)
            self._require_setup_consent(settings)
            dialogs = [
                DialogCandidate.from_private_dict(candidate.as_private_dict())
                for candidate in dialogs
            ]
            if len(dialogs) != len(links):
                raise RuntimeError("Telegram did not resolve every message link")
            if len({candidate.chat_id for candidate in dialogs}) != len(dialogs):
                raise RuntimeError("Telegram resolved duplicate group candidates")
            selection_id = new_source_id()
            atomic_write_json(self.paths.dialog_candidates, {
                "schema": DIALOG_CANDIDATES_SCHEMA,
                "selection_id": selection_id,
                "dialogs": [candidate.as_private_dict() for candidate in dialogs]
            })
            settings["phase"] = "dialogs_listed"
            atomic_write_json(self.paths.settings, settings)
            return self._write_status(
                last_result="message_links_resolved", last_error_type=None)

    async def select_chats(self, selection: Any) -> Dict[str, Any]:
        async with self.state_lock:
            epoch = self._capture_epoch()
            settings = load_settings(self.paths)
            if settings["chat_locked"] or self.paths.chat_locked.exists():
                raise RuntimeError("chats are already permanently locked for this session")
            if settings["phase"] != "dialogs_listed":
                raise RuntimeError("select_chats is not allowed in this phase")
            if not isinstance(selection, dict) or set(selection) != {
                    "selection_id", "chat_ids"}:
                raise ValueError("chat selection is invalid")
            selection_id = selection.get("selection_id")
            chat_ids = selection.get("chat_ids")
            if not isinstance(selection_id, str):
                raise ValueError("chat selection is invalid")
            if not isinstance(chat_ids, list) or not 1 <= len(chat_ids) <= MAX_SELECTED_CHATS:
                raise ValueError("1 to 16 chats must be selected")
            requested: List[int] = []
            for raw in chat_ids:
                if isinstance(raw, bool):
                    raise ValueError("chat_id is invalid")
                if isinstance(raw, int):
                    chat_id = raw
                elif isinstance(raw, str):
                    try:
                        chat_id = int(raw)
                    except ValueError as exc:
                        raise ValueError("chat_id is invalid") from exc
                    if raw != str(chat_id):
                        raise ValueError("chat_id is invalid")
                else:
                    raise ValueError("chat_id is invalid")
                if chat_id >= 0:
                    raise ValueError("only Telegram groups or supergroups can be selected")
                requested.append(chat_id)
            if len(set(requested)) != len(requested):
                raise ValueError("selected chat_ids must be unique")
            requested.sort()
            stored_selection_id, candidates = _load_dialog_candidates(self.paths)
            if selection_id != stored_selection_id:
                raise ValueError("chat selection is stale")
            by_id = {row.chat_id: row for row in candidates}
            if any(chat_id not in by_id for chat_id in requested):
                raise ValueError("chat_id was not in the one-time dialog list")
            selected = [by_id[chat_id] for chat_id in requested]
            self._require_setup_consent(settings)
            source_id = new_source_id()
            public_key, fingerprint = await self._bounded_external(
                self.keygen_function(self.paths, source_id), KEYGEN_TIMEOUT_S)
            try:
                self._require_current_epoch(epoch)
                self._require_setup_consent(settings)
            except RuntimeError:
                # The real key generator has already created this exact pair.
                # Remove it before returning to dialogs_listed so a confirmed
                # reset/retry cannot be trapped by stale key material.
                unlink_atomic_material((
                    self.paths.upload_key,
                    self.paths.upload_public_key,
                ))
                raise
            settings.update({
                "phase": "chat_locked",
                "chat_locked": True,
                "source_id": source_id,
                "chats": [{
                    "chat_id": row.chat_id,
                    "title": row.title,
                    "peer": row.peer.as_dict(),
                    # The first daily boundary is resolved only after a trusted
                    # receiver gate. Selection never reads Telegram history.
                    "initial_message_id": 0,
                } for row in selected],
                "upload_public_key": public_key,
                "upload_key_fingerprint": fingerprint,
            })
            # Marker first means any crash before settings commit fails closed.
            atomic_write_bytes(self.paths.chat_locked, b"locked\n", 0o600)
            atomic_write_json(self.paths.settings, settings)
            safe_unlink(self.paths.dialog_candidates)
            safe_unlink(self.paths.setup_state)
            self._setup_deadline_mono = None
            return self._write_status(last_result="chat_locked", last_error_type=None)

    async def activate_monitoring(self) -> Dict[str, Any]:
        async with self.state_lock:
            self._capture_epoch()
            settings = load_settings(self.paths)
            if not settings["chat_locked"] or settings["phase"] != "chat_locked":
                raise RuntimeError("monitoring can only be activated for locked chats")
            if not consent_active(settings, self.clock()):
                raise RuntimeError("consent is expired")
            if self.paths.watch_state.exists():
                raise RuntimeError("monitoring activation was already requested")
            atomic_write_json(self.paths.watch_state, {
                "schema": WATCH_STATE_SCHEMA,
                "source_id": settings["source_id"],
                "phase": "activation_requested",
                "monitor_sequence": 0,
                "monitor_content_sha256": None,
                "monitor_cursors": [
                    {"chat_id": row["chat_id"], "through_message_id": 0}
                    for row in settings["chats"]
                ],
                "chats": [
                    {"chat_id": row["chat_id"], "scan_through_message_id": 0,
                     "read_pending_through_message_id": 0,
                     "read_acked_through_message_id": 0}
                    for row in settings["chats"]
                ],
            })
        triggered = self.trigger_run()
        return self._write_status(
            last_result="activation_requested", last_error_type=None,
            monitoring_phase="activation_requested", activation_required=False,
            monitoring_active=False, run_triggered=triggered,
        )

    async def revoke_and_reset(self) -> Dict[str, Any]:
        revoked = self.revoked
        revoked.set()
        possible_session = (
            self.paths.telegram_session_outstanding.exists()
            or self.paths.telegram_session.exists()
        )
        # Persist the operator action before the first await. Cancellation or
        # power loss while hung Telethon work is being cancelled must not let a
        # restart reuse the still-live session as if reset had never begun.
        self._write_revocation_warning()
        cleanup = asyncio.create_task(
            self._revoke_and_reset_inner(possible_session))
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        result = cleanup.result()
        if cancelled:
            raise asyncio.CancelledError
        return result

    async def _revoke_and_reset_inner(
        self, possible_session: bool,
    ) -> Dict[str, Any]:
        # Cancel first: setup methods intentionally hold state_lock across their
        # network operation, so waiting for the lock before cancellation would
        # make reset unavailable when Telegram hangs.
        await self._cancel_active_operations()
        logout_confirmed = not possible_session
        logout_cancelled = False
        async with self.state_lock:
            try:
                if self.paths.credentials.exists() and self.paths.telegram_session.exists():
                    # A failed or missing VPN makes remote logout unknowable. It
                    # must never fall back to Telegram over the host route.
                    await self._ensure_vpn()
                    credentials = load_credentials(self.paths)
                    logout_confirmed = bool(await asyncio.wait_for(
                        self._gateway(credentials).logout(self._session_text()), timeout=20))
            except asyncio.CancelledError:
                logout_confirmed = False
                logout_cancelled = True
            except Exception:
                logout_confirmed = False
            finally:
                try:
                    await self._stop_vpn()
                except asyncio.CancelledError:
                    logout_confirmed = False
                    logout_cancelled = True
                except Exception:
                    # Local credential deletion and the persistent remote-
                    # revocation warning must not depend on a clean child exit.
                    logout_confirmed = False
                finally:
                    unlink_atomic_material(self.paths.reset_files())
                    self.paths.remove_empty_vpn_dir()
                    if logout_confirmed:
                        unlink_atomic_material((
                            self.paths.telegram_session_outstanding,
                            self.paths.revocation_warning,
                        ))
                    else:
                        self._write_revocation_warning()
                    # Old runs retain the set Event object; new setup receives a new one.
                    self.revoked = asyncio.Event()
                    self._last_attempt = None
                    self._setup_deadline_mono = None
        result = self._write_status(
            phase="fresh", configured=False, chat_locked=False,
            consent_active=False, pending_digest_upload=False,
            pending_monitor_upload=False, source_id=None, chats=[],
            monitoring_phase="not_selected", activation_required=False,
            monitoring_active=False,
            upload_public_key=None, upload_key_fingerprint=None,
            model=None, upload_target=None, consent_expires_at=None,
            dialogs=[], phone_masked=None, last_result="reset",
            last_error_type=None if logout_confirmed else "TelegramLogoutUnconfirmed",
            revocation_required=not logout_confirmed,
            last_message_count=None, last_through_message_id=None,
        )
        return result

    async def acknowledge_manual_revocation(self) -> Dict[str, Any]:
        """Clear the fail-closed warning only after explicit UI confirmation."""
        async with self.state_lock:
            if not self.paths.revocation_warning.exists():
                raise RuntimeError("there is no manual revocation warning")
            # The operator asserted remote termination. Finish any config-only
            # restore or failed-reset cleanup as one fresh credential epoch.
            try:
                await self._stop_vpn()
            finally:
                unlink_atomic_material(self.paths.reset_files())
                self.paths.remove_empty_vpn_dir()
            unlink_atomic_material((
                self.paths.telegram_session_outstanding,
                self.paths.revocation_warning,
            ))
            self._setup_deadline_mono = None
            return self._write_status(
                phase="fresh", configured=False, chat_locked=False,
                consent_active=False, pending_digest_upload=False,
                pending_monitor_upload=False, source_id=None, chats=[],
                monitoring_phase="not_selected", activation_required=False,
                monitoring_active=False,
                upload_public_key=None, upload_key_fingerprint=None,
                model=None, upload_target=None, consent_expires_at=None,
                dialogs=[], phone_masked=None,
                last_result="manual_revocation_acknowledged",
                last_error_type=None,
                revocation_required=False,
            )

    async def renew_consent(self, expires_at: Any) -> Dict[str, Any]:
        async with self.state_lock:
            self._capture_epoch()
            settings = load_settings(self.paths)
            if not settings["chat_locked"] or settings["phase"] != "chat_locked":
                raise RuntimeError("consent can only be renewed for locked chats")
            current = self.clock().astimezone(timezone.utc)
            expires = validate_consent_expiry(expires_at, current)
            settings["consent"] = {
                "scope": CONSENT_SCOPE,
                "granted_at": current.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "expires_at": expires.isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
            atomic_write_json(self.paths.settings, settings)
            return self._write_status(last_result="consent_renewed", last_error_type=None)

    def _assert_active_locked(
        self, revoked: asyncio.Event, source_id: str, chat_ids: List[int],
        trusted_now: Optional[datetime] = None,
    ) -> None:
        self._require_no_revocation_warning()
        if revoked.is_set():
            raise asyncio.CancelledError
        settings = load_settings(self.paths)
        actual_ids = [row["chat_id"] for row in settings.get("chats", [])]
        if (not settings["chat_locked"] or settings["source_id"] != source_id
                or actual_ids != chat_ids):
            raise asyncio.CancelledError
        if not consent_active(settings, self.clock()):
            raise asyncio.CancelledError
        if trusted_now is not None:
            granted = parse_utc(settings["consent"]["granted_at"], "consent_granted_at")
            expires = parse_utc(settings["consent"]["expires_at"], "consent_expires_at")
            trusted = trusted_now.astimezone(timezone.utc)
            if (not granted <= trusted < expires
                    or expires > trusted + timedelta(days=MAX_CONSENT_DAYS)):
                raise asyncio.CancelledError

    async def _assert_active(
        self, revoked: asyncio.Event, source_id: str, chat_ids: List[int],
        trusted_now: Optional[datetime] = None,
    ) -> None:
        if revoked.is_set():
            raise asyncio.CancelledError
        async with self.state_lock:
            self._assert_active_locked(revoked, source_id, chat_ids, trusted_now)
        if revoked.is_set():
            raise asyncio.CancelledError

    def _generated_at(self, gate: Dict[str, Any], gate_received_mono: float) -> datetime:
        elapsed = self.monotonic() - gate_received_mono
        if elapsed < 0 or elapsed > 3600:
            raise RuntimeError("gate age is outside the generation bound")
        return parse_utc(gate["server_time"], "server_time") + timedelta(seconds=elapsed)

    @staticmethod
    def _cursor_map(rows: List[Dict[str, Any]]) -> Dict[int, int]:
        return {row["chat_id"]: row["through_message_id"] for row in rows}

    @staticmethod
    def _cursor_rows(cursors: Dict[int, int]) -> List[Dict[str, int]]:
        return [
            {"chat_id": chat_id, "through_message_id": cursors[chat_id]}
            for chat_id in sorted(cursors)
        ]

    def _load_watch_state(self, source_id: str, chat_ids: List[int]) -> Dict[str, Any]:
        value = read_json(self.paths.watch_state, max_bytes=64 * 1024)
        if set(value) != {
                "schema", "source_id", "phase", "monitor_sequence",
                "monitor_content_sha256", "monitor_cursors", "chats"}:
            raise ValueError("watch state has unexpected fields")
        if (value["schema"] != WATCH_STATE_SCHEMA or value["source_id"] != source_id
                or value["phase"] not in (
                    "activation_requested", "baseline_read_pending", "active")):
            raise ValueError("watch state identity/phase is invalid")
        sequence = value["monitor_sequence"]
        previous = value["monitor_content_sha256"]
        if type(sequence) is not int or not 0 <= sequence <= 2**63 - 1:
            raise ValueError("watch monitor sequence is invalid")
        if ((sequence == 0 and previous is not None)
                or (sequence > 0 and (
                    not isinstance(previous, str)
                    or re.fullmatch(r"[0-9a-f]{64}", previous) is None))):
            raise ValueError("watch monitor hash is invalid")
        monitor_rows = value["monitor_cursors"]
        chat_rows = value["chats"]
        if not isinstance(monitor_rows, list) or not isinstance(chat_rows, list):
            raise ValueError("watch cursors are invalid")
        if [row.get("chat_id") for row in monitor_rows if isinstance(row, dict)] != chat_ids:
            raise ValueError("watch monitor chat set is invalid")
        if [row.get("chat_id") for row in chat_rows if isinstance(row, dict)] != chat_ids:
            raise ValueError("watch local chat set is invalid")
        monitor_cursors: Dict[int, int] = {}
        for row in monitor_rows:
            if set(row) != {"chat_id", "through_message_id"}:
                raise ValueError("watch monitor cursor is invalid")
            through = row["through_message_id"]
            if type(through) is not int or not 0 <= through <= 2**63 - 1:
                raise ValueError("watch monitor cursor is invalid")
            monitor_cursors[row["chat_id"]] = through
        for row in chat_rows:
            if set(row) != {
                    "chat_id", "scan_through_message_id",
                    "read_pending_through_message_id",
                    "read_acked_through_message_id"}:
                raise ValueError("watch local cursor is invalid")
            scan = row["scan_through_message_id"]
            pending = row["read_pending_through_message_id"]
            acked = row["read_acked_through_message_id"]
            if (any(type(item) is not int for item in (scan, pending, acked))
                    or not 0 <= acked <= pending == scan <= 2**63 - 1
                    or monitor_cursors[row["chat_id"]] > scan):
                raise ValueError("watch local cursor ordering is invalid")
        if value["phase"] == "activation_requested" and (
                sequence != 0 or any(row["through_message_id"] != 0 for row in monitor_rows)
                or any(row["scan_through_message_id"] != 0 for row in chat_rows)):
            raise ValueError("activation state must start at zero")
        return value

    def _read_pending(self, path: Any, stream: str) -> Optional[bytes]:
        if not path.exists():
            return None
        with path.open("rb") as file:
            raw = file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise ValueError(f"pending {stream} upload exceeds hard limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError(f"pending {stream} upload is invalid") from None
        if not isinstance(value, dict):
            raise ValueError(f"pending {stream} upload is invalid")
        canonical = (
            canonical_monitor_bytes(validate_monitor_upload(value))
            if stream == "monitor"
            else canonical_digest_bytes(validate_digest_upload(value))
        )
        if canonical != raw:
            raise ValueError(f"pending {stream} upload bytes changed")
        return raw

    def _apply_monitor_payload(
        self, state: Dict[str, Any], payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if state["monitor_sequence"] == payload["sequence"]:
            if state["monitor_content_sha256"] != payload["content_sha256"]:
                raise RuntimeError("monitor checkpoint hash mismatch")
            return state
        if (payload["sequence"] != state["monitor_sequence"] + 1
                or payload["previous_sha256"] != state["monitor_content_sha256"]):
            raise RuntimeError("monitor payload is not linked to local checkpoint")
        remote = self._cursor_map(state["monitor_cursors"])
        local = {row["chat_id"]: row for row in state["chats"]}
        for row in payload["ranges"]:
            chat_id = row["chat_id"]
            if remote.get(chat_id) != row["from_message_id_exclusive"]:
                raise RuntimeError("monitor payload skipped remote cursor")
            through = row["through_message_id"]
            if through < local[chat_id]["scan_through_message_id"]:
                raise RuntimeError("monitor payload moved local cursor backwards")
            remote[chat_id] = through
            local[chat_id]["scan_through_message_id"] = through
            local[chat_id]["read_pending_through_message_id"] = through
        if payload["kind"] == "baseline":
            if state["phase"] != "activation_requested":
                raise RuntimeError("baseline does not match local activation phase")
            state["phase"] = "baseline_read_pending"
        elif state["phase"] != "active":
            raise RuntimeError("mentions require active monitoring")
        state["monitor_sequence"] = payload["sequence"]
        state["monitor_content_sha256"] = payload["content_sha256"]
        state["monitor_cursors"] = self._cursor_rows(remote)
        state["chats"] = [local[chat_id] for chat_id in sorted(local)]
        return state

    @staticmethod
    def _monitor_position(gate_section: Dict[str, Any]) -> tuple[Any, ...]:
        return (
            gate_section["next_sequence"], gate_section["previous_sha256"],
            tuple((row["chat_id"], row["through_message_id"])
                  for row in gate_section["cursors"]),
        )

    def _expected_monitor_position(self, state: Dict[str, Any]) -> tuple[Any, ...]:
        return (
            state["monitor_sequence"] + 1,
            state["monitor_content_sha256"],
            tuple((row["chat_id"], row["through_message_id"])
                  for row in state["monitor_cursors"]),
        )

    def _position_after_monitor_payload(
        self, state: Dict[str, Any], payload: Dict[str, Any],
    ) -> tuple[Any, ...]:
        cursors = self._cursor_map(state["monitor_cursors"])
        for row in payload["ranges"]:
            cursors[row["chat_id"]] = row["through_message_id"]
        return (
            payload["sequence"] + 1, payload["content_sha256"],
            tuple(sorted(cursors.items())),
        )

    async def _handle_monitor_pending(
        self, raw: bytes, gate: Dict[str, Any], transport: Any,
        revoked: asyncio.Event, source_id: str, chat_ids: List[int],
        gate_received_mono: float,
    ) -> Dict[str, Any]:
        payload = json.loads(raw.decode("utf-8"))
        state = self._load_watch_state(source_id, chat_ids)
        remote = self._monitor_position(gate["monitor"])
        local = self._expected_monitor_position(state)
        accepted = remote == self._position_after_monitor_payload(state, payload)
        if not accepted and remote != local:
            raise RuntimeError("pending monitor upload does not match remote chain")
        if not accepted:
            if len(raw) > gate["monitor"]["max_upload_bytes"]:
                raise RuntimeError("pending monitor upload exceeds receiver limit")
            await self._assert_active(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            await transport.upload_monitor(raw, revoked)
        async with self.state_lock:
            self._assert_active_locked(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            state = self._load_watch_state(source_id, chat_ids)
            state = self._apply_monitor_payload(state, payload)
            atomic_write_json(self.paths.watch_state, state)
            safe_unlink(self.paths.monitor_pending)
        return state

    async def _retry_read_acks(
        self, state: Dict[str, Any], gateway: Any, session: str,
        chats: List[Dict[str, Any]], revoked: asyncio.Event, source_id: str,
        chat_ids: List[int], gate: Dict[str, Any], gate_received_mono: float,
    ) -> tuple[Dict[str, Any], List[int]]:
        by_id = {row["chat_id"]: row for row in chats}
        targets: List[tuple[int, PeerSpec, int]] = []
        expected: Dict[int, int] = {}
        for cursor in state["chats"]:
            pending = cursor["read_pending_through_message_id"]
            if pending <= cursor["read_acked_through_message_id"]:
                continue
            chat = by_id[cursor["chat_id"]]
            targets.append((
                cursor["chat_id"], PeerSpec.from_dict(chat["peer"]), pending,
            ))
            expected[cursor["chat_id"]] = pending
        if targets:
            await self._assert_active(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            succeeded, failed = await self._bounded_external(
                gateway.acknowledge_reads(session, targets),
                TELEGRAM_FETCH_TIMEOUT_S,
            )
            expected_ids = set(expected)
            if (not isinstance(succeeded, list) or not isinstance(failed, list)
                    or len(succeeded) != len(set(succeeded))
                    or len(failed) != len(set(failed))
                    or set(succeeded).intersection(failed)
                    or set(succeeded).union(failed) != expected_ids):
                raise RuntimeError("Telegram read acknowledgement result is invalid")
            async with self.state_lock:
                self._assert_active_locked(
                    revoked, source_id, chat_ids,
                    self._generated_at(gate, gate_received_mono),
                )
                latest = self._load_watch_state(source_id, chat_ids)
                for chat_id in succeeded:
                    latest_row = next(
                        row for row in latest["chats"] if row["chat_id"] == chat_id)
                    if latest_row["read_pending_through_message_id"] != expected[chat_id]:
                        raise RuntimeError("read acknowledgement target changed")
                    latest_row["read_acked_through_message_id"] = expected[chat_id]
                atomic_write_json(self.paths.watch_state, latest)
                state = latest
        else:
            failed = []
        if (state["phase"] == "baseline_read_pending"
                and all(row["read_acked_through_message_id"]
                        == row["read_pending_through_message_id"]
                        for row in state["chats"])):
            async with self.state_lock:
                latest = self._load_watch_state(source_id, chat_ids)
                latest["phase"] = "active"
                atomic_write_json(self.paths.watch_state, latest)
                state = latest
        return state, failed

    async def _fresh_gate(
        self, transport: Any, source_id: str, chat_ids: List[int],
        revoked: asyncio.Event,
    ) -> tuple[Dict[str, Any], float]:
        gate = await transport.gate(source_id, chat_ids, revoked)
        validate_gate(gate, chat_ids)
        received = self.monotonic()
        await self._assert_active(
            revoked, source_id, chat_ids, self._generated_at(gate, received))
        return gate, received

    async def _run_monitor(
        self, gate: Dict[str, Any], gate_received_mono: float, transport: Any,
        gateway: Any, settings: Dict[str, Any], session: str,
        revoked: asyncio.Event,
    ) -> tuple[Dict[str, Any], float, int, int]:
        source_id = settings["source_id"]
        chats = settings["chats"]
        chat_ids = [row["chat_id"] for row in chats]
        state = self._load_watch_state(source_id, chat_ids)
        pending_raw = self._read_pending(self.paths.monitor_pending, "monitor")
        allowed = {self._expected_monitor_position(state)}
        if pending_raw is not None:
            pending = json.loads(pending_raw.decode("utf-8"))
            allowed.add(self._position_after_monitor_payload(state, pending))
        if self._monitor_position(gate["monitor"]) not in allowed:
            raise RuntimeError("receiver monitor chain rolled back or jumped")
        if pending_raw is not None:
            state = await self._handle_monitor_pending(
                pending_raw, gate, transport, revoked, source_id, chat_ids,
                gate_received_mono,
            )
            # A remote mutation makes the old monitor gate stale.
            gate, gate_received_mono = await self._fresh_gate(
                transport, source_id, chat_ids, revoked)
        failed_chat_count = 0

        # Baseline completion is its own durable phase. A retry tick performs
        # only the outstanding read batch; active scans start on the next tick,
        # keeping the watcher at no more than two Telegram connections per tick.
        if state["phase"] == "baseline_read_pending":
            state, failed_chat_ids = await self._retry_read_acks(
                state, gateway, session, chats, revoked, source_id, chat_ids,
                gate, gate_received_mono,
            )
            return gate, gate_received_mono, 0, len(failed_chat_ids)

        if state["phase"] == "activation_requested":
            if not gate["monitor"]["baseline_required"]:
                raise RuntimeError("receiver refused required baseline")
            selected = [
                (row["chat_id"], PeerSpec.from_dict(row["peer"])) for row in chats
            ]
            await self._assert_active(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            tops = await self._bounded_external(
                gateway.snapshot_tops(session, selected), TELEGRAM_FETCH_TIMEOUT_S)
            ranges = [
                {"chat_id": row["chat_id"],
                 "from_message_id_exclusive": gate["monitor"]["cursors"][index][
                     "through_message_id"],
                 "through_message_id": tops[row["chat_id"]]}
                for index, row in enumerate(chats)
            ]
            payload = build_monitor_upload(
                source_id=source_id, gate=gate, kind="baseline", ranges=ranges,
                events=[], generated_at=self._generated_at(gate, gate_received_mono),
            )
            pending = canonical_monitor_bytes(payload)
            if len(pending) > gate["monitor"]["max_upload_bytes"]:
                raise RuntimeError("baseline exceeds receiver max_upload_bytes")
            async with self.state_lock:
                self._assert_active_locked(
                    revoked, source_id, chat_ids,
                    self._generated_at(gate, gate_received_mono),
                )
                atomic_write_bytes(self.paths.monitor_pending, pending, 0o600)
            await transport.upload_monitor(pending, revoked)
            async with self.state_lock:
                self._assert_active_locked(
                    revoked, source_id, chat_ids,
                    self._generated_at(gate, gate_received_mono),
                )
                state = self._load_watch_state(source_id, chat_ids)
                state = self._apply_monitor_payload(state, payload)
                atomic_write_json(self.paths.watch_state, state)
                safe_unlink(self.paths.monitor_pending)
            state, read_failures = await self._retry_read_acks(
                state, gateway, session, chats, revoked, source_id, chat_ids,
                gate, gate_received_mono,
            )
            # Do not scan beyond the frozen baseline without a fresh status.
            fresh_gate, fresh_mono = await self._fresh_gate(
                transport, source_id, chat_ids, revoked)
            return fresh_gate, fresh_mono, 0, len(set(read_failures))

        if state["phase"] != "active" or gate["monitor"]["baseline_required"]:
            raise RuntimeError("local and remote baseline state disagree")

        selected = []
        for row in chats:
            local_row = next(
                item for item in state["chats"] if item["chat_id"] == row["chat_id"])
            selected.append((
                row["chat_id"], PeerSpec.from_dict(row["peer"]), row["title"],
                local_row["scan_through_message_id"],
            ))
        await self._assert_active(
            revoked, source_id, chat_ids,
            self._generated_at(gate, gate_received_mono),
        )
        _, scans, scan_failures = await self._bounded_external(
            gateway.snapshot_and_scan_mentions(session, source_id, selected),
            TELEGRAM_FETCH_TIMEOUT_S,
        )
        await self._assert_active(
            revoked, source_id, chat_ids,
            self._generated_at(gate, gate_received_mono),
        )
        if (not isinstance(scans, dict) or not isinstance(scan_failures, list)
                or len(scan_failures) != len(set(scan_failures))
                or set(scans).intersection(scan_failures)
                or set(scans).union(scan_failures) != set(chat_ids)):
            raise RuntimeError("Telegram mention scan result is invalid")
        failed_chat_ids = set(scan_failures)
        mention_count = 0
        for chat in chats:
            chat_id = chat["chat_id"]
            if chat_id not in scans:
                continue
            local_row = next(row for row in state["chats"] if row["chat_id"] == chat_id)
            start = local_row["scan_through_message_id"]
            scan = scans[chat_id]
            await self._assert_active(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            if scan.through_message_id < start:
                raise RuntimeError("mention scan moved backwards")
            if scan.events:
                remote_cursor = next(
                    row["through_message_id"] for row in gate["monitor"]["cursors"]
                    if row["chat_id"] == chat_id)
                wire_events = [{
                    "event_id": event.event_id,
                    "message_id": event.message_id,
                    "date": utc_iso(event.sent_at),
                    "chat_title": event.chat_title,
                    "sender": event.sender,
                    "snippet": event.snippet,
                    "link": event.link,
                } for event in scan.events]
                payload = build_monitor_upload(
                    source_id=source_id, gate=gate, kind="mentions",
                    ranges=[{
                        "chat_id": chat_id,
                        "from_message_id_exclusive": remote_cursor,
                        "through_message_id": scan.through_message_id,
                    }],
                    events=wire_events,
                    generated_at=self._generated_at(gate, gate_received_mono),
                )
                pending = canonical_monitor_bytes(payload)
                if len(pending) > gate["monitor"]["max_upload_bytes"]:
                    raise RuntimeError("mentions exceed receiver max_upload_bytes")
                async with self.state_lock:
                    self._assert_active_locked(
                        revoked, source_id, chat_ids,
                        self._generated_at(gate, gate_received_mono),
                    )
                    atomic_write_bytes(self.paths.monitor_pending, pending, 0o600)
                await transport.upload_monitor(pending, revoked)
                async with self.state_lock:
                    self._assert_active_locked(
                        revoked, source_id, chat_ids,
                        self._generated_at(gate, gate_received_mono),
                    )
                    state = self._load_watch_state(source_id, chat_ids)
                    state = self._apply_monitor_payload(state, payload)
                    atomic_write_json(self.paths.watch_state, state)
                    safe_unlink(self.paths.monitor_pending)
                mention_count += len(scan.events)
                gate, gate_received_mono = await self._fresh_gate(
                    transport, source_id, chat_ids, revoked)
            else:
                async with self.state_lock:
                    self._assert_active_locked(
                        revoked, source_id, chat_ids,
                        self._generated_at(gate, gate_received_mono),
                    )
                    state = self._load_watch_state(source_id, chat_ids)
                    row = next(item for item in state["chats"] if item["chat_id"] == chat_id)
                    row["scan_through_message_id"] = scan.through_message_id
                    row["read_pending_through_message_id"] = scan.through_message_id
                    atomic_write_json(self.paths.watch_state, state)
        state, read_failures = await self._retry_read_acks(
            state, gateway, session, chats, revoked, source_id, chat_ids,
            gate, gate_received_mono,
        )
        failed_chat_ids.update(read_failures)
        failed_chat_count = len(failed_chat_ids)
        return gate, gate_received_mono, mention_count, failed_chat_count

    def _load_digest_ack(
        self, source_id: str, chat_ids: List[int],
    ) -> Optional[Dict[str, Any]]:
        if not self.paths.acknowledged.exists():
            return None
        value = read_json(self.paths.acknowledged, max_bytes=32 * 1024)
        if set(value) != {
                "schema", "source_id", "sequence", "content_sha256",
                "digest_date", "cursors"}:
            raise ValueError("digest checkpoint has unexpected fields")
        if (value["schema"] != DIGEST_ACKNOWLEDGED_SCHEMA
                or value["source_id"] != source_id
                or type(value["sequence"]) is not int or value["sequence"] < 1
                or not isinstance(value["content_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", value["content_sha256"]) is None):
            raise ValueError("digest checkpoint is invalid")
        try:
            if date.fromisoformat(value["digest_date"]).isoformat() != value["digest_date"]:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("digest checkpoint date is invalid") from None
        rows = value["cursors"]
        if (not isinstance(rows, list)
                or [row.get("chat_id") for row in rows if isinstance(row, dict)] != chat_ids):
            raise ValueError("digest checkpoint chat set is invalid")
        for row in rows:
            if (set(row) != {"chat_id", "through_message_id"}
                    or type(row["through_message_id"]) is not int
                    or row["through_message_id"] < 0):
                raise ValueError("digest checkpoint cursor is invalid")
        return value

    def _save_digest_ack(self, payload: Dict[str, Any]) -> None:
        validate_digest_upload(payload)
        atomic_write_json(self.paths.acknowledged, {
            "schema": DIGEST_ACKNOWLEDGED_SCHEMA,
            "source_id": payload["source_id"],
            "sequence": payload["sequence"],
            "content_sha256": payload["content_sha256"],
            "digest_date": payload["digest_date"],
            "cursors": [
                {"chat_id": row["chat_id"],
                 "through_message_id": row["through_message_id"]}
                for row in payload["chat_ranges"]
            ],
        })

    @staticmethod
    def _digest_position(section: Dict[str, Any]) -> tuple[Any, ...]:
        return (
            section["next_sequence"], section["previous_sha256"],
            tuple((row["chat_id"], row["through_message_id"])
                  for row in section["cursors"]),
        )

    def _digest_base(
        self, acknowledged: Optional[Dict[str, Any]], chat_ids: List[int],
    ) -> tuple[Any, ...]:
        if acknowledged is None:
            return 1, None, tuple((chat_id, 0) for chat_id in chat_ids)
        return (
            acknowledged["sequence"] + 1, acknowledged["content_sha256"],
            tuple((row["chat_id"], row["through_message_id"])
                  for row in acknowledged["cursors"]),
        )

    @staticmethod
    def _digest_after(payload: Dict[str, Any]) -> tuple[Any, ...]:
        return (
            payload["sequence"] + 1, payload["content_sha256"],
            tuple((row["chat_id"], row["through_message_id"])
                  for row in payload["chat_ranges"]),
        )

    async def _run_digest(
        self, gate: Dict[str, Any], gate_received_mono: float, transport: Any,
        gateway: Any, settings: Dict[str, Any], credentials: Dict[str, Any],
        session: str, revoked: asyncio.Event,
    ) -> tuple[str, int]:
        source_id = settings["source_id"]
        chats = settings["chats"]
        chat_ids = [row["chat_id"] for row in chats]
        acknowledged = self._load_digest_ack(source_id, chat_ids)
        pending_raw = self._read_pending(self.paths.pending, "digest")
        pending_value = json.loads(pending_raw.decode("utf-8")) if pending_raw else None
        base = self._digest_base(acknowledged, chat_ids)
        allowed = {base}
        stale_local_pending = False
        if pending_value is not None:
            pending_base = (
                pending_value["sequence"], pending_value["previous_sha256"],
                tuple((row["chat_id"], row["from_message_id_exclusive"])
                      for row in pending_value["chat_ranges"]),
            )
            if pending_base == base:
                allowed.add(self._digest_after(pending_value))
            elif (acknowledged is not None
                  and pending_value["sequence"] == acknowledged["sequence"]
                  and pending_value["content_sha256"] == acknowledged["content_sha256"]
                  and pending_value["digest_date"] == acknowledged["digest_date"]
                  and self._digest_after(pending_value) == base):
                # The acknowledged checkpoint was fsynced before unlinking the
                # pending file. A power loss in that tiny window leaves both.
                stale_local_pending = True
            else:
                raise RuntimeError("pending digest is not linked to local checkpoint")
        remote = self._digest_position(gate["digest"])
        if remote not in allowed:
            raise RuntimeError("receiver digest chain rolled back or jumped")
        if stale_local_pending:
            async with self.state_lock:
                self._assert_active_locked(
                    revoked, source_id, chat_ids,
                    self._generated_at(gate, gate_received_mono),
                )
                safe_unlink(self.paths.pending)
            pending_raw = None
            pending_value = None
        if pending_value is not None:
            if remote == self._digest_after(pending_value):
                async with self.state_lock:
                    self._assert_active_locked(
                        revoked, source_id, chat_ids,
                        self._generated_at(gate, gate_received_mono),
                    )
                    self._save_digest_ack(pending_value)
                    safe_unlink(self.paths.pending)
                acknowledged = pending_value
                pending_raw = None
            else:
                same_plan = (
                    gate["digest"]["digest_date"] == pending_value["digest_date"]
                    and gate["timezone"] == pending_value["timezone"])
                if not same_plan and gate["digest"]["due"]:
                    safe_unlink(self.paths.pending)
                    pending_raw = None
                elif not same_plan:
                    raise RuntimeError("pending digest does not match remote plan")
                elif not gate["digest"]["due"]:
                    return "pending_digest_not_due", 0
                else:
                    if len(pending_raw) > gate["digest"]["max_upload_bytes"]:
                        raise RuntimeError("pending digest exceeds receiver limit")
                    await transport.upload_digest(pending_raw, revoked)
                    async with self.state_lock:
                        self._assert_active_locked(
                            revoked, source_id, chat_ids,
                            self._generated_at(gate, gate_received_mono),
                        )
                        self._save_digest_ack(pending_value)
                        safe_unlink(self.paths.pending)
                    return "uploaded_pending_digest", pending_value["total_message_count"]
        if not gate["digest"]["due"]:
            return "watched_not_due", 0

        if acknowledged is not None:
            last_day = date.fromisoformat(acknowledged["digest_date"])
            if date.fromisoformat(gate["digest"]["digest_date"]) <= last_day:
                raise RuntimeError("receiver digest date did not advance")
        now_mono = self.monotonic()
        sequence = gate["digest"]["next_sequence"]
        if (self._last_attempt and self._last_attempt[0] == sequence
                and now_mono - self._last_attempt[1] < 300):
            return "digest_cooldown", 0
        self._last_attempt = (sequence, now_mono)

        cutoff = parse_utc(gate["server_time"], "server_time")
        first = acknowledged is None and sequence == 1
        per_chat_budget = max(1024, MAX_PROMPT_BYTES // len(chats))
        digest_chats: List[DigestChat] = []
        ranges: List[Dict[str, int]] = []
        for chat, cursor in zip(chats, gate["digest"]["cursors"]):
            peer = PeerSpec.from_dict(chat["peer"])
            start = cursor["through_message_id"]
            effective = start
            not_before: Optional[datetime] = None
            if first:
                not_before = cutoff - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
                await self._assert_active(
                    revoked, source_id, chat_ids,
                    self._generated_at(gate, gate_received_mono),
                )
                trusted_cursor = await self._bounded_external(
                    gateway.bootstrap_cursor(session, peer, cutoff),
                    TELEGRAM_FETCH_TIMEOUT_S,
                )
                await self._assert_active(
                    revoked, source_id, chat_ids,
                    self._generated_at(gate, gate_received_mono),
                )
                effective = max(start, trusted_cursor)
            await self._assert_active(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            fetched = await self._bounded_external(
                gateway.fetch(
                    session, peer, chat["chat_id"], effective, cutoff,
                    not_before_at=not_before, max_prompt_bytes=per_chat_budget,
                    chat_title=chat["title"],
                ),
                TELEGRAM_FETCH_TIMEOUT_S,
            )
            await self._assert_active(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            if fetched.through_message_id < effective:
                raise RuntimeError("Telegram digest cursor moved backwards")
            ranges.append({
                "chat_id": chat["chat_id"],
                "from_message_id_exclusive": start,
                "through_message_id": fetched.through_message_id,
                "message_count": len(fetched.messages),
            })
            if fetched.messages:
                digest_chats.append(DigestChat(chat["title"], fetched.messages))

        total = sum(row["message_count"] for row in ranges)
        digest = "" if total == 0 else await self._bounded_external(
            self.digest_function(
                digest_chats, settings["openrouter_model"],
                credentials["openrouter_api_key"], revoked,
            ),
            OPENROUTER_TIMEOUT_S,
        )
        await self._assert_active(
            revoked, source_id, chat_ids,
            self._generated_at(gate, gate_received_mono),
        )
        payload = build_digest_upload(
            source_id=source_id, gate=gate, chat_ranges=ranges, digest=digest,
            model=settings["openrouter_model"],
            generated_at=self._generated_at(gate, gate_received_mono),
        )
        pending = canonical_digest_bytes(payload)
        if len(pending) > gate["digest"]["max_upload_bytes"]:
            raise RuntimeError("digest exceeds receiver max_upload_bytes")
        async with self.state_lock:
            self._assert_active_locked(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            atomic_write_bytes(self.paths.pending, pending, 0o600)
        await transport.upload_digest(pending, revoked)
        async with self.state_lock:
            self._assert_active_locked(
                revoked, source_id, chat_ids,
                self._generated_at(gate, gate_received_mono),
            )
            self._save_digest_ack(payload)
            safe_unlink(self.paths.pending)
        self._last_attempt = None
        return "uploaded_digest", total

    async def run_once(self) -> Dict[str, Any]:
        async with self.run_lock:
            current_task = asyncio.current_task()
            self._active_run_task = current_task
            revoked = self.revoked
            failed_chat_count = 0
            try:
                async with self.state_lock:
                    self._require_no_revocation_warning()
                    settings = load_settings(self.paths)
                    credentials = load_credentials(self.paths)
                    if not settings["chat_locked"] or not self.paths.chat_locked.exists():
                        raise RuntimeError("chats are not locked")
                    if not consent_active(settings, self.clock()):
                        raise RuntimeError("consent is expired")
                    if not self.paths.watch_state.exists():
                        return self._write_status(
                            last_run_at=self.clock().isoformat(),
                            last_result="activation_required", last_error_type=None,
                        )
                    session = self._session_text()
                    source_id = settings["source_id"]
                    chat_ids = [row["chat_id"] for row in settings["chats"]]
                    upload_config = dict(settings["upload"])
                transport = self.transport_factory(self.paths, upload_config)
                gate, gate_received_mono = await self._fresh_gate(
                    transport, source_id, chat_ids, revoked)
                await self._ensure_vpn()
                self._require_current_epoch(revoked)
                gateway = self._gateway(credentials)
                monitor_error_type = None
                try:
                    gate, gate_received_mono, mentions, failed_chat_count = await self._run_monitor(
                        gate, gate_received_mono, transport, gateway, settings,
                        session, revoked,
                    )
                except asyncio.TimeoutError:
                    # 2026-08-14: one hanging active-monitor operation consumed
                    # the aggregate deadline on every tick and starved the
                    # independent daily stream. Baseline transitions remain
                    # fail-closed; active state continues only from a fresh,
                    # authenticated receiver gate.
                    watch = self._load_watch_state(source_id, chat_ids)
                    if watch["phase"] != "active":
                        raise
                    monitor_error_type = "TimeoutError"
                    failed_chat_count = len(chat_ids)
                    gate, gate_received_mono = await self._fresh_gate(
                        transport, source_id, chat_ids, revoked)
                watch = self._load_watch_state(source_id, chat_ids)
                if watch["phase"] != "active":
                    return self._write_status(
                        last_run_at=self.clock().isoformat(),
                        last_result="baseline_read_pending", last_error_type=None,
                        failed_chat_count=failed_chat_count,
                    )
                result, message_count = await self._run_digest(
                    gate, gate_received_mono, transport, gateway, settings,
                    credentials, session, revoked,
                )
                return self._write_status(
                    last_run_at=self.clock().isoformat(), last_result=result,
                    last_error_type=monitor_error_type,
                    last_message_count=message_count,
                    pending_digest_upload=self.paths.pending.exists(),
                    pending_monitor_upload=self.paths.monitor_pending.exists(),
                    failed_chat_count=failed_chat_count,
                )
            except asyncio.CancelledError:
                return self._write_status(
                    last_run_at=self.clock().isoformat(), last_result="revoked",
                    last_error_type=None,
                    pending_digest_upload=self.paths.pending.exists(),
                    pending_monitor_upload=self.paths.monitor_pending.exists(),
                    failed_chat_count=0,
                )
            except Exception as exc:
                return self._write_status(
                    last_run_at=self.clock().isoformat(), last_result="error",
                    last_error_type=type(exc).__name__,
                    pending_digest_upload=self.paths.pending.exists(),
                    pending_monitor_upload=self.paths.monitor_pending.exists(),
                    failed_chat_count=failed_chat_count,
                )
            finally:
                if self._active_run_task is current_task:
                    self._active_run_task = None

    async def close(self) -> None:
        """Cancel collector work and reap the app-scoped VPN child."""
        await self._cancel_active_operations()
        async with self.state_lock:
            await self._stop_vpn()

    def trigger_run(self) -> bool:
        if self._run_task is not None and not self._run_task.done():
            return False
        self._run_task = asyncio.create_task(self.run_once())
        return True
