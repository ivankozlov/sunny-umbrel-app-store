from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .contracts import (
    canonical_upload_bytes,
    build_upload,
    parse_utc,
    validate_upload,
)
from .models import DialogCandidate, PeerSpec
from .openrouter import create_digest
from .settings import (
    MAX_CONSENT_DAYS,
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
from .telegram_gateway import TelethonGateway
from .version import MAX_UPLOAD_BYTES


GatewayFactory = Callable[[int, str], Any]
DigestFunction = Callable[[List[Any], str, str, asyncio.Event], Awaitable[str]]
TransportFactory = Callable[[Paths, Dict[str, Any]], Any]
KeygenFunction = Callable[[Paths, str], Awaitable[tuple[str, str]]]


ACKNOWLEDGED_SCHEMA = "sunny.personal-digest-acknowledged.v1"
REVOCATION_WARNING_SCHEMA = "sunny.personal-digest-revocation-warning.v1"
SESSION_OUTSTANDING_SCHEMA = "sunny.personal-digest-session-outstanding.v1"
TELEGRAM_SETUP_TIMEOUT_S = 90
TELEGRAM_DIALOG_TIMEOUT_S = 120
TELEGRAM_FETCH_TIMEOUT_S = 180
KEYGEN_TIMEOUT_S = 30
OPENROUTER_TIMEOUT_S = 120


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _masked_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return f"+***{digits[-4:]}" if len(digits) >= 4 else "+***"


class Collector:
    def __init__(
        self,
        paths: Paths,
        *,
        gateway_factory: GatewayFactory = TelethonGateway,
        digest_function: DigestFunction = create_digest,
        transport_factory: TransportFactory = SSHTransport,
        keygen_function: KeygenFunction = generate_upload_key,
        clock: Callable[[], datetime] = _now,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.paths = paths
        self.paths.ensure()
        self.gateway_factory = gateway_factory
        self.digest_function = digest_function
        self.transport_factory = transport_factory
        self.keygen_function = keygen_function
        self.clock = clock
        self.monotonic = monotonic
        self.state_lock = asyncio.Lock()
        self.run_lock = asyncio.Lock()
        self.revoked = asyncio.Event()
        self._run_task: Optional[asyncio.Task[Any]] = None
        self._active_run_task: Optional[asyncio.Task[Any]] = None
        self._external_tasks: set[asyncio.Task[Any]] = set()
        self._last_attempt: Optional[tuple[int, float]] = None
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

    def _gateway(self, credentials: Dict[str, Any]):
        return self.gateway_factory(
            credentials["telegram_api_id"], credentials["telegram_api_hash"])

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
            "schema": "sunny.personal-digest-local-status.v1",
            "phase": "fresh",
            "configured": False,
            "chat_locked": False,
            "consent_active": False,
            "pending_upload": self.paths.pending.exists(),
            "source_id": None,
            "chat_id": None,
            "chat_title": None,
            "initial_message_id": None,
            "upload_public_key": None,
            "upload_key_fingerprint": None,
            "model": None,
            "upload_target": None,
            "consent_expires_at": None,
            "phone_masked": None,
            "dialogs": [],
            "last_run_at": None,
            "last_result": None,
            "last_error_type": None,
            "last_message_count": None,
            "last_through_message_id": None,
            "revocation_required": self.paths.revocation_warning.exists(),
        }
        if self.paths.settings.exists():
            try:
                settings = load_settings(self.paths)
                status.update(
                    phase=settings["phase"],
                    configured=True,
                    chat_locked=settings["chat_locked"],
                    consent_active=consent_active(settings, self.clock()),
                )
                if settings["chat_locked"]:
                    status.update(
                        source_id=settings["source_id"],
                        chat_id=settings["chat_id"],
                        chat_title=settings["chat_title"],
                        initial_message_id=settings["initial_message_id"],
                        upload_public_key=settings["upload_public_key"],
                        upload_key_fingerprint=settings["upload_key_fingerprint"],
                        model=settings["openrouter_model"],
                        upload_target=(
                            f'{settings["upload"]["user"]}@{settings["upload"]["host"]}:'
                            f'{settings["upload"]["port"]}'
                        ),
                        consent_expires_at=settings["consent"]["expires_at"],
                    )
                elif settings["phase"] == "dialogs_listed" and self.paths.dialog_candidates.exists():
                    private = read_json(self.paths.dialog_candidates, max_bytes=512 * 1024)
                    rows = private.get("dialogs")
                    if isinstance(rows, list):
                        status["dialogs"] = [
                            DialogCandidate.from_private_dict(row).as_ui_dict()
                            for row in rows
                        ]
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
                consent_active=False, pending_upload=False, source_id=None,
                chat_id=None, chat_title=None, initial_message_id=None,
                upload_public_key=None, upload_key_fingerprint=None, model=None,
                upload_target=None, consent_expires_at=None, phone_masked=None,
                dialogs=[], revocation_required=True,
            )
        # A locked runtime status must never expose dialog candidates or setup state.
        if status["chat_locked"]:
            status["dialogs"] = []
            status["phone_masked"] = None
        return status

    def _write_status(self, **changes: Any) -> Dict[str, Any]:
        status = self._base_status()
        status.update(changes)
        allowed = {
            "schema", "phase", "configured", "chat_locked", "consent_active",
            "pending_upload", "source_id", "chat_id", "chat_title",
            "initial_message_id", "upload_public_key", "upload_key_fingerprint",
            "model", "upload_target", "consent_expires_at",
            "phone_masked", "dialogs", "last_run_at", "last_result",
            "last_error_type", "last_message_count", "last_through_message_id",
            "revocation_required",
        }
        status = {key: status.get(key) for key in allowed}
        atomic_write_json(self.paths.status, status, 0o600)
        atomic_write_bytes(self.paths.heartbeat, b"ok\n", 0o600)
        return status

    async def public_status(self) -> Dict[str, Any]:
        return self._write_status()

    async def configure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        async with self.state_lock:
            if (self.paths.revocation_warning.exists()
                    or self.paths.telegram_session_outstanding.exists()):
                raise RuntimeError(
                    "manual Telegram device revocation must be acknowledged first")
            if self.paths.chat_locked.exists() or self.paths.settings.exists():
                raise RuntimeError("factory reset is required before configuration")
            settings, credentials, known_host = validate_configure(data, self.clock())
            save_initial_config(self.paths, settings, credentials, known_host)
            return self._write_status(last_result="configured", last_error_type=None)

    async def send_code(self, phone: Any) -> Dict[str, Any]:
        async with self.state_lock:
            settings = load_settings(self.paths)
            if settings["chat_locked"] or settings["phase"] != "configured":
                raise RuntimeError("send_code is not allowed in this phase")
            if not isinstance(phone, str) or not re.fullmatch(r"\+[0-9]{7,15}", phone):
                raise ValueError("phone must use international +digits format")
            # Arm before the first authorization network call. There is no
            # transaction with Telegram: a false-positive manual device check
            # after a crash is safer than an untracked live session.
            self._mark_session_outstanding()
            credentials = load_credentials(self.paths)
            session, phone_code_hash = await self._bounded_external(
                self._gateway(credentials).send_code(self._session_text(), phone),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            self._save_session(session)
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
            settings = load_settings(self.paths)
            if settings["chat_locked"] or settings["phase"] != "code_sent":
                raise RuntimeError("submit_code is not allowed in this phase")
            if not isinstance(code, str) or not re.fullmatch(r"[0-9]{3,8}", code):
                raise ValueError("Telegram code is invalid")
            setup = read_json(self.paths.setup_state, max_bytes=16 * 1024)
            credentials = load_credentials(self.paths)
            session, needs_password = await self._bounded_external(
                self._gateway(credentials).submit_code(
                    self._session_text(), setup["phone"], code,
                    setup["phone_code_hash"],
                ),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            self._save_session(session)
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
            settings = load_settings(self.paths)
            if settings["chat_locked"] or settings["phase"] != "password_required":
                raise RuntimeError("submit_password is not allowed in this phase")
            if not isinstance(password, str) or not 1 <= len(password) <= 512:
                raise ValueError("Telegram 2FA password is invalid")
            credentials = load_credentials(self.paths)
            session = await self._bounded_external(
                self._gateway(credentials).submit_password(
                    self._session_text(), password),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            self._save_session(session)
            settings["phase"] = "authenticated"
            atomic_write_json(self.paths.settings, settings)
            safe_unlink(self.paths.setup_state)
            return self._write_status(last_result="authenticated", last_error_type=None)

    async def list_dialogs(self) -> Dict[str, Any]:
        async with self.state_lock:
            settings = load_settings(self.paths)
            # Exactly once, and permanently impossible after selection for this session.
            if settings["chat_locked"] or self.paths.chat_locked.exists():
                raise RuntimeError("dialog listing is permanently disabled for the locked session")
            if settings["phase"] != "authenticated" or self.paths.dialog_candidates.exists():
                raise RuntimeError("dialog listing has already been used or is unavailable")
            credentials = load_credentials(self.paths)
            dialogs = await self._bounded_external(
                self._gateway(credentials).list_dialogs(self._session_text()),
                TELEGRAM_DIALOG_TIMEOUT_S,
            )
            dialogs = [
                DialogCandidate.from_private_dict(candidate.as_private_dict())
                for candidate in dialogs
            ]
            if not dialogs:
                raise RuntimeError("Telegram returned no selectable dialogs")
            atomic_write_json(self.paths.dialog_candidates, {
                "dialogs": [candidate.as_private_dict() for candidate in dialogs]
            })
            settings["phase"] = "dialogs_listed"
            atomic_write_json(self.paths.settings, settings)
            return self._write_status(last_result="dialogs_listed", last_error_type=None)

    async def select_chat(self, chat_id: Any) -> Dict[str, Any]:
        async with self.state_lock:
            settings = load_settings(self.paths)
            if settings["chat_locked"] or self.paths.chat_locked.exists():
                raise RuntimeError("chat is already permanently locked for this session")
            if settings["phase"] != "dialogs_listed":
                raise RuntimeError("select_chat is not allowed in this phase")
            try:
                requested = int(chat_id)
            except (TypeError, ValueError) as exc:
                raise ValueError("chat_id is invalid") from exc
            if requested >= 0:
                raise ValueError("only a Telegram group or supergroup can be selected")
            candidates_value = read_json(self.paths.dialog_candidates, max_bytes=512 * 1024)
            rows = candidates_value.get("dialogs")
            if not isinstance(rows, list):
                raise ValueError("dialog candidates are invalid")
            candidates = [DialogCandidate.from_private_dict(row) for row in rows]
            selected = next((row for row in candidates if row.chat_id == requested), None)
            if selected is None:
                raise ValueError("chat_id was not in the one-time dialog list")
            credentials = load_credentials(self.paths)
            initial_id = await self._bounded_external(
                self._gateway(credentials).bootstrap_cursor(
                    self._session_text(), selected.peer, self.clock()),
                TELEGRAM_SETUP_TIMEOUT_S,
            )
            source_id = new_source_id()
            public_key, fingerprint = await self._bounded_external(
                self.keygen_function(self.paths, source_id), KEYGEN_TIMEOUT_S)
            settings.update({
                "phase": "chat_locked",
                "chat_locked": True,
                "source_id": source_id,
                "chat_id": selected.chat_id,
                "chat_title": selected.title,
                "peer": selected.peer.as_dict(),
                "initial_message_id": initial_id,
                "upload_public_key": public_key,
                "upload_key_fingerprint": fingerprint,
            })
            # Marker first means any crash before settings commit fails closed.
            atomic_write_bytes(self.paths.chat_locked, b"locked\n", 0o600)
            atomic_write_json(self.paths.settings, settings)
            safe_unlink(self.paths.dialog_candidates)
            safe_unlink(self.paths.setup_state)
            return self._write_status(last_result="chat_locked", last_error_type=None)

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
        if possible_session:
            self._write_revocation_warning()
        # Cancel first: setup methods intentionally hold state_lock across their
        # network operation, so waiting for the lock before cancellation would
        # make reset unavailable when Telegram hangs.
        await self._cancel_active_operations()
        logout_confirmed = not possible_session
        logout_cancelled = False
        async with self.state_lock:
            try:
                if self.paths.credentials.exists() and self.paths.telegram_session.exists():
                    credentials = load_credentials(self.paths)
                    logout_confirmed = bool(await asyncio.wait_for(
                        self._gateway(credentials).logout(self._session_text()), timeout=20))
            except asyncio.CancelledError:
                logout_confirmed = False
                logout_cancelled = True
            except Exception:
                logout_confirmed = False
            finally:
                unlink_atomic_material(self.paths.reset_files())
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
        result = self._write_status(
            phase="fresh", configured=False, chat_locked=False,
            consent_active=False, pending_upload=False, source_id=None,
            chat_id=None, chat_title=None, initial_message_id=None,
            upload_public_key=None, upload_key_fingerprint=None,
            model=None, upload_target=None, consent_expires_at=None,
            dialogs=[], phone_masked=None, last_result="reset",
            last_error_type=None if logout_confirmed else "TelegramLogoutUnconfirmed",
            revocation_required=not logout_confirmed,
            last_message_count=None, last_through_message_id=None,
        )
        if logout_cancelled:
            raise asyncio.CancelledError
        return result

    async def acknowledge_manual_revocation(self) -> Dict[str, Any]:
        """Clear the fail-closed warning only after explicit UI confirmation."""
        async with self.state_lock:
            if not self.paths.revocation_warning.exists():
                raise RuntimeError("there is no manual revocation warning")
            # The operator asserted remote termination. Finish any config-only
            # restore or failed-reset cleanup as one fresh credential epoch.
            unlink_atomic_material(self.paths.reset_files())
            unlink_atomic_material((
                self.paths.telegram_session_outstanding,
                self.paths.revocation_warning,
            ))
            return self._write_status(
                phase="fresh", configured=False, chat_locked=False,
                consent_active=False, pending_upload=False, source_id=None,
                chat_id=None, chat_title=None, initial_message_id=None,
                upload_public_key=None, upload_key_fingerprint=None,
                model=None, upload_target=None, consent_expires_at=None,
                dialogs=[], phone_masked=None,
                last_result="manual_revocation_acknowledged",
                last_error_type=None,
                revocation_required=False,
            )

    async def renew_consent(self, expires_at: Any) -> Dict[str, Any]:
        async with self.state_lock:
            settings = load_settings(self.paths)
            if not settings["chat_locked"] or settings["phase"] != "chat_locked":
                raise RuntimeError("consent can only be renewed for a locked chat")
            current = self.clock().astimezone(timezone.utc)
            expires = validate_consent_expiry(expires_at, current)
            settings["consent"] = {
                "scope": "one-exact-chat-text-and-captions",
                "granted_at": current.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "expires_at": expires.isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
            atomic_write_json(self.paths.settings, settings)
            return self._write_status(last_result="consent_renewed", last_error_type=None)

    def _assert_active_locked(self, revoked: asyncio.Event, source_id: str,
                              chat_id: int,
                              trusted_now: Optional[datetime] = None) -> None:
        if revoked.is_set():
            raise asyncio.CancelledError
        settings = load_settings(self.paths)
        if not settings["chat_locked"] or settings["source_id"] != source_id or settings[
                "chat_id"] != chat_id:
            raise asyncio.CancelledError
        if not consent_active(settings, self.clock()):
            raise asyncio.CancelledError
        if trusted_now is not None:
            expires = parse_utc(settings["consent"]["expires_at"], "consent_expires_at")
            trusted = trusted_now.astimezone(timezone.utc)
            if (trusted >= expires
                    or expires > trusted + timedelta(days=MAX_CONSENT_DAYS)):
                raise asyncio.CancelledError

    async def _assert_active(self, revoked: asyncio.Event, source_id: str, chat_id: int,
                             trusted_now: Optional[datetime] = None) -> None:
        if revoked.is_set():
            raise asyncio.CancelledError
        async with self.state_lock:
            self._assert_active_locked(revoked, source_id, chat_id, trusted_now)
        if revoked.is_set():
            raise asyncio.CancelledError

    def _read_pending_bytes(self) -> Optional[bytes]:
        if not self.paths.pending.exists():
            return None
        with self.paths.pending.open("rb") as stream:
            raw = stream.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise ValueError("pending upload exceeds hard limit")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("pending upload is invalid")
        validate_upload(value)
        if canonical_upload_bytes(value) != raw:
            raise ValueError("pending upload bytes changed")
        return raw

    def _load_acknowledged(self, source_id: str, chat_id: int) -> Optional[Dict[str, Any]]:
        if not self.paths.acknowledged.exists():
            return None
        value = read_json(self.paths.acknowledged, max_bytes=16 * 1024)
        if set(value) != {
                "schema", "source_id", "chat_id", "sequence", "content_sha256",
                "through_message_id", "digest_date"}:
            raise ValueError("acknowledged checkpoint has unexpected fields")
        if (value.get("schema") != ACKNOWLEDGED_SCHEMA
                or value.get("source_id") != source_id
                or value.get("chat_id") != chat_id
                or type(value.get("sequence")) is not int
                or not 1 <= value["sequence"] <= 2**63 - 1
                or type(value.get("through_message_id")) is not int
                or not 0 <= value["through_message_id"] <= 2**63 - 1
                or not isinstance(value.get("content_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", value["content_sha256"]) is None):
            raise ValueError("acknowledged checkpoint is invalid")
        try:
            checkpoint_day = date.fromisoformat(value.get("digest_date"))
        except (TypeError, ValueError):
            raise ValueError("acknowledged checkpoint date is invalid") from None
        if checkpoint_day.isoformat() != value["digest_date"]:
            raise ValueError("acknowledged checkpoint date is invalid")
        return value

    def _save_acknowledged(self, upload: Dict[str, Any]) -> None:
        validate_upload(upload)
        atomic_write_json(self.paths.acknowledged, {
            "schema": ACKNOWLEDGED_SCHEMA,
            "source_id": upload["source_id"],
            "chat_id": upload["chat_id"],
            "sequence": upload["sequence"],
            "content_sha256": upload["content_sha256"],
            "through_message_id": upload["through_message_id"],
            "digest_date": upload["digest_date"],
        })

    @staticmethod
    def _position(sequence: int, previous: Optional[str], cursor: int) -> tuple[Any, ...]:
        return sequence, previous, cursor

    def _validate_gate_chain(
        self,
        gate: Dict[str, Any],
        acknowledged: Optional[Dict[str, Any]],
        pending: Optional[Dict[str, Any]],
        initial_message_id: int,
        source_id: str,
        chat_id: int,
    ) -> None:
        """Reject receiver rollback/jumps before Telegram can be contacted."""
        if acknowledged is None:
            base = self._position(1, None, initial_message_id)
            last_day: Optional[date] = None
        else:
            base = self._position(
                acknowledged["sequence"] + 1,
                acknowledged["content_sha256"],
                acknowledged["through_message_id"],
            )
            last_day = date.fromisoformat(acknowledged["digest_date"])

        allowed = {base}
        if pending is not None:
            if (pending["source_id"] != source_id or pending["chat_id"] != chat_id
                    or self._position(
                        pending["sequence"], pending["previous_sha256"],
                        pending["from_message_id_exclusive"],
                    ) != base):
                raise RuntimeError("pending upload is not linked to local checkpoint")
            if (last_day is not None
                    and date.fromisoformat(pending["digest_date"]) <= last_day):
                raise RuntimeError("pending digest date did not advance")
            allowed.add(self._position(
                pending["sequence"] + 1,
                pending["content_sha256"],
                pending["through_message_id"],
            ))

        remote = self._position(
            gate["next_sequence"], gate["previous_sha256"],
            gate["from_message_id_exclusive"],
        )
        if remote not in allowed:
            raise RuntimeError("receiver chain rolled back or jumped")
        if gate["due"] and last_day is not None:
            try:
                gate_day = date.fromisoformat(gate["digest_date"])
            except ValueError:
                raise RuntimeError("receiver digest date is invalid") from None
            if gate_day <= last_day:
                raise RuntimeError("receiver digest date did not advance")

    def _generated_at(self, gate: Dict[str, Any], gate_received_mono: float) -> datetime:
        elapsed = self.monotonic() - gate_received_mono
        if elapsed < 0 or elapsed > 3600:
            raise RuntimeError("gate age is outside the generation bound")
        # Artifact timestamps stay entirely in the receiver's clock domain;
        # Umbrel's wall clock may be arbitrarily ahead or behind.
        return parse_utc(gate["server_time"], "server_time") + timedelta(
            seconds=elapsed)

    async def _handle_pending(self, raw: bytes, gate: Dict[str, Any], transport: Any,
                              revoked: asyncio.Event, source_id: str,
                              chat_id: int,
                              gate_received_mono: float) -> Optional[Dict[str, Any]]:
        pending = json.loads(raw.decode("utf-8"))
        accepted = (
            gate["next_sequence"] == pending["sequence"] + 1
            and gate["previous_sha256"] == pending["content_sha256"]
            and gate["from_message_id_exclusive"] == pending["through_message_id"]
        )
        if accepted:
            # Remote chain is authoritative only once mirrored locally.  Write
            # the checkpoint before deleting pending so every crash window can
            # either replay bytes or prove the accepted position.
            async with self.state_lock:
                self._assert_active_locked(
                    revoked, source_id, chat_id,
                    self._generated_at(gate, gate_received_mono),
                )
                self._save_acknowledged(pending)
                safe_unlink(self.paths.pending)
            return self._write_status(
                last_run_at=self.clock().isoformat(), last_result="reconciled",
                last_error_type=None, pending_upload=False,
                last_message_count=pending["message_count"],
                last_through_message_id=pending["through_message_id"],
            )
        same_position = (
            gate["next_sequence"] == pending["sequence"]
            and gate["previous_sha256"] == pending["previous_sha256"]
            and gate["from_message_id_exclusive"] == pending["from_message_id_exclusive"]
        )
        if not same_position:
            raise RuntimeError("pending upload does not match remote chain")
        plan_changed = (
            gate["digest_date"] != pending["digest_date"]
            or gate["timezone"] != pending["timezone"]
        )
        if plan_changed and gate["due"]:
            # The receiver never accepted the old final payload. Once it issues
            # a different due plan at the same chain position (next local day or
            # a timezone change), that summary is deterministically obsolete;
            # no raw text is involved. Accepted lost-ACK is handled above first.
            safe_unlink(self.paths.pending)
            return None
        same_plan = (
            gate["digest_date"] == pending["digest_date"]
            and gate["timezone"] == pending["timezone"]
        )
        if not same_plan:
            raise RuntimeError("pending upload does not match remote plan")
        if not gate["due"]:
            return self._write_status(
                last_run_at=self.clock().isoformat(), last_result="pending_not_due",
                last_error_type=None, pending_upload=True)
        if len(raw) > gate["max_upload_bytes"]:
            raise RuntimeError("pending upload exceeds receiver limit")
        await self._assert_active(
            revoked, source_id, chat_id,
            self._generated_at(gate, gate_received_mono),
        )
        await transport.upload(raw, revoked)
        async with self.state_lock:
            self._assert_active_locked(
                revoked, source_id, chat_id,
                self._generated_at(gate, gate_received_mono),
            )
            self._save_acknowledged(pending)
            safe_unlink(self.paths.pending)
        return self._write_status(
            last_run_at=self.clock().isoformat(), last_result="uploaded_pending",
            last_error_type=None, pending_upload=False,
            last_message_count=pending["message_count"],
            last_through_message_id=pending["through_message_id"],
        )

    async def run_once(self) -> Dict[str, Any]:
        async with self.run_lock:
            current_task = asyncio.current_task()
            self._active_run_task = current_task
            revoked = self.revoked
            try:
                async with self.state_lock:
                    settings = load_settings(self.paths)
                    credentials = load_credentials(self.paths)
                    if not settings["chat_locked"] or not self.paths.chat_locked.exists():
                        raise RuntimeError("chat is not locked")
                    if not consent_active(settings, self.clock()):
                        raise RuntimeError("consent is expired")
                    session = self._session_text()
                    source_id = settings["source_id"]
                    chat_id = settings["chat_id"]
                    peer = PeerSpec.from_dict(settings["peer"])
                    initial_message_id = settings["initial_message_id"]
                    model = settings["openrouter_model"]
                    upload_config = dict(settings["upload"])
                transport = self.transport_factory(self.paths, upload_config)

                # The remote gate is always queried before Telegram or OpenRouter.
                gate = await transport.gate(source_id, chat_id, revoked)
                gate_received_mono = self.monotonic()
                await self._assert_active(
                    revoked, source_id, chat_id,
                    self._generated_at(gate, gate_received_mono),
                )
                pending_raw = self._read_pending_bytes()
                pending_value = (
                    json.loads(pending_raw.decode("utf-8"))
                    if pending_raw is not None else None
                )
                acknowledged = self._load_acknowledged(source_id, chat_id)
                self._validate_gate_chain(
                    gate, acknowledged, pending_value, initial_message_id,
                    source_id, chat_id,
                )
                if pending_raw is not None:
                    pending_result = await self._handle_pending(
                        pending_raw, gate, transport, revoked, source_id, chat_id,
                        gate_received_mono)
                    if pending_result is not None:
                        return pending_result
                if not gate["due"]:
                    return self._write_status(
                        last_run_at=self.clock().isoformat(), last_result="not_due",
                        last_error_type=None, pending_upload=False)

                # Limit repeated paid attempts for one server-issued plan.
                now_mono = self.monotonic()
                if self._last_attempt and self._last_attempt[0] == gate["next_sequence"] \
                        and now_mono - self._last_attempt[1] < 300:
                    return self._write_status(
                        last_run_at=self.clock().isoformat(), last_result="cooldown",
                        last_error_type=None)
                self._last_attempt = (gate["next_sequence"], now_mono)

                # The receiver round-trip may outlive the consent window. Check
                # again immediately before the first operation that reads the
                # selected Telegram peer, then again after it completes.
                await self._assert_active(
                    revoked, source_id, chat_id,
                    self._generated_at(gate, gate_received_mono),
                )
                cutoff = parse_utc(gate["server_time"], "server_time")
                fetched = await self._bounded_external(
                    self._gateway(credentials).fetch(
                        session, peer, chat_id,
                        gate["from_message_id_exclusive"], cutoff,
                    ),
                    TELEGRAM_FETCH_TIMEOUT_S,
                )
                await self._assert_active(
                    revoked, source_id, chat_id,
                    self._generated_at(gate, gate_received_mono),
                )

                # Empty text selection (for example media/service-only events)
                # advances the cursor without contacting OpenRouter.
                digest = "" if not fetched.messages else await self._bounded_external(
                    self.digest_function(
                        fetched.messages, model,
                        credentials["openrouter_api_key"], revoked,
                    ),
                    OPENROUTER_TIMEOUT_S,
                )
                await self._assert_active(
                    revoked, source_id, chat_id,
                    self._generated_at(gate, gate_received_mono),
                )

                payload = build_upload(
                    source_id=source_id,
                    gate=gate,
                    chat_id=chat_id,
                    through_message_id=fetched.through_message_id,
                    message_count=len(fetched.messages),
                    digest=digest,
                    model=model,
                    generated_at=self._generated_at(gate, gate_received_mono),
                )
                pending = canonical_upload_bytes(payload)
                if len(pending) > gate["max_upload_bytes"]:
                    raise RuntimeError("digest exceeds receiver max_upload_bytes")
                # Persist exactly the bytes that SSH receives. A crash or uncertain
                # receipt can only retry/reconcile this immutable payload. The
                # final revocation check and write share the reset lock: reset
                # therefore either deletes this file afterwards or wins first.
                async with self.state_lock:
                    self._assert_active_locked(
                        revoked, source_id, chat_id,
                        self._generated_at(gate, gate_received_mono),
                    )
                    atomic_write_bytes(self.paths.pending, pending, 0o600)
                await self._assert_active(
                    revoked, source_id, chat_id,
                    self._generated_at(gate, gate_received_mono),
                )
                await transport.upload(pending, revoked)
                async with self.state_lock:
                    self._assert_active_locked(
                        revoked, source_id, chat_id,
                        self._generated_at(gate, gate_received_mono),
                    )
                    self._save_acknowledged(payload)
                    safe_unlink(self.paths.pending)
                self._last_attempt = None
                return self._write_status(
                    last_run_at=self.clock().isoformat(), last_result="uploaded",
                    last_error_type=None, pending_upload=False,
                    last_message_count=len(fetched.messages),
                    last_through_message_id=fetched.through_message_id,
                )
            except asyncio.CancelledError:
                return self._write_status(
                    last_run_at=self.clock().isoformat(), last_result="revoked",
                    last_error_type=None, pending_upload=self.paths.pending.exists())
            except Exception as exc:
                return self._write_status(
                    last_run_at=self.clock().isoformat(), last_result="error",
                    last_error_type=type(exc).__name__,
                    pending_upload=self.paths.pending.exists())
            finally:
                if self._active_run_task is current_task:
                    self._active_run_task = None

    def trigger_run(self) -> bool:
        if self._run_task is not None and not self._run_task.done():
            return False
        self._run_task = asyncio.create_task(self.run_once())
        return True
