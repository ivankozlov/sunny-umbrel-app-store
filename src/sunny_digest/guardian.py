"""Trusted service owning the vault, Telegram policy and receipt state machine."""
from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import stat
import time
from pathlib import Path

from .authn import WebAuthnAuthorizer, AuthorizationError, _records
from .guardian_engine import Collector, _load_dialog_candidates
from .contracts import parse_utc
from .guardian_jobs import JobBroker, RemoteDigest, ModelTunnelBoundary
from .ipc import dispatch as dispatch_engine
from .memory_guard import protect_process
from .migrate_vault import VaultMigration, MANIFEST_SCHEMA, legacy_inventory, write_manifest
from .mihomo import MihomoRuntime
from .settings import (
    validate_configure, validate_consent_expiry, load_settings, load_credentials,
)
from .storage import Paths, atomic_write_bytes, read_json
from .vault import Vault
from .vault_storage import VaultPaths, RECORD_NAMES
from .vpn_subscription import validate_subscription_url


PROTECTED = {
    "configure", "select_chats", "activate_monitoring", "renew_consent", "extend_chats",
    "replace_vpn", "revoke_and_reset", "acknowledge_manual_revocation", "lock",
    "passkey_add", "passkey_remove", "change_passphrase", "view_status", "migration_resume",
}
SETUP_STEPS = {"send_code", "submit_code", "submit_password", "resolve_chat_links"}
PRESENTATION = {"set_digest_rich", "set_chat_display"}


def _phrase(value):
    if not isinstance(value, str) or not 20 <= len(value.encode("utf-8")) <= 1024:
        raise ValueError("use a separate bounded passphrase of at least 20 UTF-8 bytes")
    return value


def _snapshot_schema(snapshot):
    if not _records(snapshot["passkeys"]):
        raise ValueError("at least one passkey is required")


class Guardian:
    def __init__(self, paths: Paths, *, scratch: Path, authorizer=None,
                 memory_preflight=protect_process, vault_factory=Vault,
                 engine_factory=Collector, monotonic=time.monotonic):
        # These injections are Python test seams, never environment bypasses.
        memory_preflight()
        self.paths, self.scratch, self.engine_factory = paths, scratch, engine_factory
        self.clock = monotonic
        for directory in (paths.config_dir, paths.private_dir, paths.runtime_dir):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise PermissionError("prepare the private guardian layout on the host")
        self.vault = vault_factory(paths.private_dir / "vault.json",
                                   allowed_record_names=RECORD_NAMES.values(), validator=_snapshot_schema)
        self.engine = None
        self.jobs = JobBroker(clock=monotonic)
        self._admin_lock = asyncio.Lock()
        self._views = {}
        self._registration = {}
        self._unlock_pending = None
        self._unlock_retry_at = 0.0
        self._gate_pair = None
        self._gate_pairs = {}
        self._morning_active = False
        self._wakeup = asyncio.Event()
        self.exit_requested = asyncio.Event()
        self._service_requested = False
        self._tick_task = None
        self._next_tick = monotonic() + 5
        self.authorizer = authorizer
        if authorizer is None:
            origin_file = paths.config_dir / "security-origin.json"
            if origin_file.exists():
                value = read_json(origin_file, max_bytes=4096)
                if set(value) != {"origin", "rp_id"}:
                    raise ValueError("trusted origin configuration is invalid")
                self.authorizer = WebAuthnAuthorizer(trusted_origin=value["origin"], rp_id=value["rp_id"])
        self.migration = VaultMigration(paths, self.vault, validator=self._check_runtime_state)

    def security_state(self):
        if self.migration.marker.exists() or legacy_inventory(self.paths):
            return "migration_blocked"
        if self.engine is not None:
            return "unlocked"
        if self._unlock_pending is not None and self._unlock_pending[1] > self.clock():
            return "unlock_pending"
        return "locked" if self.vault.path.exists() else "uninitialized"

    def _auth(self):
        if self.authorizer is None:
            raise AuthorizationError("trusted HTTPS origin is not configured")
        return self.authorizer

    def _require_unlocked(self):
        if self.engine is None or self.security_state() != "unlocked":
            raise AuthorizationError("guardian is locked")

    def _view_valid(self, token):
        self._views = {key: expiry for key, expiry in self._views.items() if expiry > self.clock()}
        if not isinstance(token, str) or len(token) > 128:
            return False
        return hashlib.sha256(token.encode()).digest() in self._views

    def _issue_view(self):
        self._view_valid(None)
        if len(self._views) >= 32:
            self._views.pop(next(iter(self._views)))
        token = secrets.token_urlsafe(32)
        self._views[hashlib.sha256(token.encode()).digest()] = self.clock() + 900
        return token

    async def status(self, token=None):
        result = {
            "security_state": self.security_state(), "trusted_origin_configured": self.authorizer is not None,
            "app_version": __import__("sunny_digest.version", fromlist=["APP_VERSION"]).APP_VERSION,
            "revocation_required": self.paths.revocation_warning.exists(),
            "phase": "secured", "configured": self.vault.path.exists(),
            "view_authorized": False,
        }
        if self.authorizer is not None:
            result["trusted_origin"] = self.authorizer.trusted_origin
        if self.engine is not None and self._view_valid(token):
            result.update(await self.engine.public_status(), view_authorized=True)
            result["passkeys"] = [{"credential_id": key, "name": row["name"]}
                                  for key, row in self.vault.snapshot["passkeys"].items()]
        atomic_write_bytes(self.paths.runtime_dir / "guardian-heartbeat", b"ok\n")
        return result

    def _manifest(self):
        value = read_json(self.paths.private_dir / "vault-manifest.json", max_bytes=128 * 1024)
        if (set(value) != {"schema", "vault_id", "security_epoch", "policy_revision", "passkeys"}
                or value["schema"] != MANIFEST_SCHEMA):
            raise AuthorizationError("vault browser hints are invalid")
        _records(value["passkeys"])
        return value

    def _identity(self):
        snapshot = self.vault.snapshot
        return {"vault_id": self.vault.vault_id, "security_epoch": snapshot["security_epoch"],
                "policy_revision": snapshot["policy_revision"]}

    def _normalize(self, operation, payload):
        if operation not in PROTECTED or not isinstance(payload, dict):
            raise ValueError("admin operation is invalid")
        empty = {"lock", "view_status", "activate_monitoring", "revoke_and_reset",
                 "acknowledge_manual_revocation", "passkey_add", "migration_resume"}
        if operation in empty:
            if payload:
                raise ValueError("operation expects an empty payload")
        elif operation == "configure":
            validate_configure(payload, self.engine.clock())
            from .openrouter import OPUS_55_MODEL
            if payload["openrouter_model"] != OPUS_55_MODEL:
                raise ValueError("model policy is fixed")
        elif operation == "select_chats":
            if set(payload) != {"selection_id", "chat_ids"} or not isinstance(payload["chat_ids"], list):
                raise ValueError("chat selection is invalid")
            if not 1 <= len(payload["chat_ids"]) <= 16:
                raise ValueError("chat selection size is invalid")
            ids = [int(value) for value in payload["chat_ids"] if type(value) in (int, str)]
            if len(ids) != len(payload["chat_ids"]) or len(set(ids)) != len(ids) or any(value >= 0 for value in ids):
                raise ValueError("chat selection is invalid")
            payload = {"selection_id": payload["selection_id"], "chat_ids": sorted(ids)}
        elif operation in {"replace_vpn", "extend_chats", "renew_consent", "change_passphrase", "passkey_remove"}:
            if set(payload) != {"value"}:
                raise ValueError("operation fields are invalid")
            value = payload["value"]
            if operation == "replace_vpn":
                validate_subscription_url(value)
            elif operation == "extend_chats":
                from .telegram_gateway import parse_message_link
                parse_message_link(value)
            elif operation == "renew_consent":
                validate_consent_expiry(value, self.engine.clock())
            elif operation == "change_passphrase":
                _phrase(value)
            elif value not in self.vault.snapshot["passkeys"] or len(self.vault.snapshot["passkeys"]) <= 1:
                raise ValueError("last or unknown passkey cannot be removed")
        return payload

    async def begin(self, data):
        if not isinstance(data, dict) or set(data) != {"operation", "payload"}:
            raise ValueError("admin begin fields are invalid")
        operation = data["operation"]
        if operation in {"unlock", "migration_resume"} and self.engine is None:
            if data["payload"]:
                raise ValueError("unlock has no mutable payload")
            if self.clock() < self._unlock_retry_at:
                raise AuthorizationError("unlock rate limit exceeded")
            if self._unlock_pending is not None and self._unlock_pending[1] > self.clock():
                raise AuthorizationError("an unlock ceremony is already pending")
            hints = self._manifest()
            result = self._auth().begin_operation(
                operation=operation, normalized_payload={},
                credential_index=hints["passkeys"],
                **{key: hints[key] for key in ("vault_id", "security_epoch", "policy_revision")})
            self._unlock_pending = (result["challenge_id"], self.clock() + 120)
            return result
        self._require_unlocked()
        payload = self._normalize(operation, data["payload"])
        return self._auth().begin_operation(operation=operation, normalized_payload=payload,
                                            credential_index=self.vault.snapshot["passkeys"], **self._identity())

    async def finish(self, data):
        if not isinstance(data, dict) or not {"challenge_id", "credential"} <= set(data) or set(data) - {
            "challenge_id", "credential", "passphrase"}:
            raise ValueError("admin finish fields are invalid")
        async with self._admin_lock:
            candidate = self.engine is None
            try:
                if candidate:
                    if self.clock() < self._unlock_retry_at:
                        raise AuthorizationError("unlock rate limit exceeded")
                    self._unlock_retry_at = self.clock() + 2
                    pending, self._unlock_pending = self._unlock_pending, None
                    if pending is None or pending[0] != data["challenge_id"] or pending[1] <= self.clock():
                        raise AuthorizationError("unlock ceremony is unavailable")
                    def canonical_loader():
                        self.vault.unlock(_phrase(data.get("passphrase")))
                        self._check_runtime_state()
                        return {"credentials": self.vault.snapshot["passkeys"], **self._identity()}
                    grant = self._auth().verify_locked_operation(
                        challenge_id=data["challenge_id"], credential=data["credential"],
                        canonical_loader=canonical_loader)
                elif "passphrase" in data:
                    raise ValueError("unlocked operation does not accept a passphrase")
                else:
                    grant = self._auth().verify_operation(
                        challenge_id=data["challenge_id"], credential=data["credential"],
                        credentials=self.vault.snapshot["passkeys"], **self._identity())
                if not grant.matches(**self._identity()):
                    raise AuthorizationError("security state changed")
                if candidate:
                    if grant.operation == "migration_resume":
                        self.migration.resume()
                        self.vault.close()
                        return await self.status()
                    if grant.operation != "unlock" or self.security_state() == "migration_blocked":
                        raise AuthorizationError("migration must be completed first")
                    self._install_engine()
                else:
                    await self._execute(grant.operation, grant.payload)
                if grant.operation == "lock":
                    return await self.status()
                if grant.operation == "passkey_add":
                    ceremony = self._auth().begin_passkey_add(authorization=grant, credentials=self.vault.snapshot["passkeys"])
                    self._registration[ceremony["challenge_id"]] = ("add", self._identity(), self.clock() + 120)
                    return {"registration": ceremony}
                token = self._issue_view()
                result = await self.status(token)
                result["view_token"] = token
                return result
            except BaseException:
                if candidate:
                    self.vault.close()
                    self.engine = None
                elif self.vault._snapshot is None:
                    # Unknown commit state after a filesystem error is terminal.
                    self.exit_requested.set()
                raise

    def _check_runtime_state(self):
        paths = VaultPaths(self.paths, self.vault, self.scratch)
        if paths.settings.exists():
            settings = load_settings(paths)
            load_credentials(paths)
            if settings.get("source_id") and settings["source_id"] != self.vault.snapshot["source_id"]:
                raise ValueError("vault source identity mismatch")
            Collector._validate_vpn_node(read_json(paths.vpn_active_node, max_bytes=16 * 1024))
            from .settings import normalize_known_host
            raw_hosts = paths.known_hosts.read_text("ascii")
            if normalize_known_host(raw_hosts.rstrip("\n"), settings["upload"]["host"],
                                    settings["upload"]["port"]) != raw_hosts.encode("ascii"):
                raise ValueError("vault pinned host is not canonical")
            if settings["chat_locked"] and (not paths.telegram_session.exists() or not paths.upload_key.exists()):
                raise ValueError("locked vault is incomplete")
            if paths.telegram_session.exists():
                from telethon.sessions import StringSession
                StringSession(paths.telegram_session.read_text().strip())
            if paths.dialog_candidates.exists():
                _load_dialog_candidates(paths)
            if paths.setup_state.exists():
                setup = read_json(paths.setup_state, max_bytes=16 * 1024)
                if set(setup) != {"phone", "phone_masked", "phone_code_hash"} or any(
                        not isinstance(value, str) or not value or len(value) > 512 for value in setup.values()):
                    raise ValueError("vault setup record is invalid")
            from .secret_files import validate_encrypted_keypair
            for secret_name, public_name in (("upload_key", "upload_public_key"),
                                             ("openrouter_key", "openrouter_public_key")):
                if getattr(paths, secret_name).exists() or getattr(paths, public_name).exists():
                    validate_encrypted_keypair(paths, secret_name, public_name)
            # Reuse the same validators as the production receipt state machine,
            # without constructing a gateway or starting a network operation.
            validator = object.__new__(Collector)
            validator.paths = paths
            source = self.vault.snapshot["source_id"]
            ids = [row["chat_id"] for row in settings.get("chats", [])]
            if paths.watch_state.exists():
                if not settings["chat_locked"]:
                    raise ValueError("watch checkpoint without locked chats")
                validator._load_watch_state(source, ids)
            validator._load_digest_ack(source, ids)
            for path, stream in ((paths.pending, "digest"), (paths.monitor_pending, "monitor")):
                raw = validator._read_pending(path, stream)
                if raw is not None:
                    import json
                    pending = json.loads(raw)
                    rows = pending["chat_ranges"] if stream == "digest" else pending["ranges"]
                    pending_ids = [row["chat_id"] for row in rows]
                    same_chats = pending_ids == ids if stream == "digest" else set(pending_ids) <= set(ids)
                    if pending["source_id"] != source or not same_chats:
                        raise ValueError("pending checkpoint identity mismatch")
        elif any(paths.vault.snapshot["records"]):
            raise ValueError("vault settings are missing")
        elif any(path.exists() for path in (paths.watch_state, paths.acknowledged,
                                           paths.pending, paths.monitor_pending)):
            raise ValueError("checkpoints require their original encrypted policy")

    def _install_engine(self):
        paths = VaultPaths(self.paths, self.vault, self.scratch)
        self.engine = self.engine_factory(
            paths, digest_function=RemoteDigest(self), tunnel_factory=ModelTunnelBoundary,
            monotonic=self.clock,
            vpn_runtime_factory=lambda _: MihomoRuntime(self.scratch, runtime_parent=self.scratch, require_memory_guards=True))
        self.engine.trigger_run = self.trigger_run
        original_generated = self.engine._generated_at
        def generated(gate, received):
            result = original_generated(gate, received)
            pair = self._gate_pairs.get(received)
            if pair is not None:
                _, mono, boot = pair
                if abs((self._boottime() - boot) - (self.clock() - mono)) > 1:
                    raise RuntimeError("fresh receiver gate required after suspend")
            elif self.clock() - received > 1:
                raise RuntimeError("receiver gate lease is unavailable")
            if self._morning_active and result >= parse_utc(gate["digest"]["accept_until"], "accept_until"):
                raise RuntimeError("morning operation exceeded receiver window")
            return result
        self.engine._generated_at = generated
        original_gate = self.engine._fresh_gate
        async def fresh(*args, **kwargs):
            gate, received = await original_gate(*args, **kwargs)
            self._gate_pair = (gate, received, self.clock(), self._boottime())
            self._gate_pairs[received] = (gate, self.clock(), self._boottime())
            self._gate_pairs = {key: value for key, value in self._gate_pairs.items()
                                if self.clock() - key <= 3600}
            return gate, received
        self.engine._fresh_gate = fresh
        original_morning = self.engine._run_morning_pass
        async def morning(*args, **kwargs):
            self._morning_active = True
            try:
                return await original_morning(*args, **kwargs)
            finally:
                self._morning_active = False
        self.engine._run_morning_pass = morning
        self._next_tick = self.clock() + 5
        self._wakeup.set()

    @staticmethod
    def _boottime():
        return time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, "CLOCK_BOOTTIME") else time.monotonic()

    def model_seconds_left(self):
        if self.engine is None or self._gate_pair is None:
            return 0
        gate, received, mono, boot = self._gate_pair
        if abs((self._boottime() - boot) - (self.clock() - mono)) > 1:
            raise RuntimeError("fresh receiver gate required after suspend")
        now = self.engine._generated_at(gate, received)
        expiry = min(parse_utc(gate["digest"]["accept_until"], "accept_until"),
                     parse_utc(load_settings(self.engine.paths)["consent"]["expires_at"], "consent"))
        return max(0.0, (expiry - now).total_seconds())

    async def _execute(self, operation, payload):
        if operation == "view_status" or operation == "passkey_add":
            return
        if operation == "revoke_and_reset":
            # Persist the reset intent before cancellation/cleanup can yield or
            # fail. Restart must not reuse a possibly live Telegram session.
            self.engine._write_revocation_warning()
        await self._end_epoch()
        if operation == "lock":
            self.vault.close()
            self.engine = None
            self.exit_requested.set()
            return
        if operation == "change_passphrase":
            self.vault.change_passphrase(payload["value"])
        elif operation == "passkey_remove":
            snapshot = self.vault.snapshot
            del snapshot["passkeys"][payload["value"]]
            self.vault.update(snapshot)
        else:
            data = payload if operation in {"configure", "select_chats"} else payload.get("value")
            await dispatch_engine(self.engine, {"command": operation, **({"data": data} if data is not None else {})})
            if operation in {"activate_monitoring", "extend_chats"}:
                self._service_requested = True
                self._wakeup.set()
        write_manifest(self.paths, self.vault)

    async def _end_epoch(self):
        """Stop trusted operations before changing the encrypted policy."""
        await self.jobs.cancel()
        await self.engine.close()
        if self.jobs.cleanup_unconfirmed:
            self.exit_requested.set()
            raise RuntimeError("model cleanup was not confirmed; restart locked")
        self.engine.revoked = asyncio.Event()
        self._views.clear()
        self._registration.clear()
        self._auth().cancel_pending()
        snapshot = self.vault.snapshot
        snapshot["policy_revision"] += 1
        snapshot["security_epoch"] += 1
        self.vault.update(snapshot)
        write_manifest(self.paths, self.vault)

    def trigger_run(self):
        self._wakeup.set()
        return True

    async def bootstrap_begin(self, data):
        if self.vault.path.exists() or self.engine is not None:
            raise AuthorizationError("bootstrap unavailable for an existing vault")
        if not isinstance(data, dict) or set(data) != {"token"}:
            raise ValueError("bootstrap fields are invalid")
        identity = secrets.token_urlsafe(24)
        ceremony = self._auth().begin_bootstrap_registration(vault_id=identity, credentials={}, bootstrap_token=data["token"])
        self._registration[ceremony["challenge_id"]] = ("bootstrap", None, self.clock() + 120)
        self._registration = {key: value for key, value in self._registration.items()
                              if value[2] > self.clock()}
        return ceremony

    async def registration_finish(self, data):
        if not isinstance(data, dict) or not {"challenge_id", "credential", "name"} <= set(data) or set(data) - {
            "challenge_id", "credential", "name", "passphrase", "confirm_migration"}:
            raise ValueError("registration fields are invalid")
        async with self._admin_lock:
            pending = self._registration.pop(data["challenge_id"], None)
            if pending is None or self.clock() >= pending[2]:
                raise AuthorizationError("registration expired")
            mode, identity, _ = pending
            if mode == "add" and (self.engine is None or identity != self._identity()):
                raise AuthorizationError("security state changed")
            credentials = {} if mode == "bootstrap" else self.vault.snapshot["passkeys"]
            record = self._auth().finish_registration(challenge_id=data["challenge_id"], credential=data["credential"], credentials=credentials, name=data["name"])
            if mode == "bootstrap":
                if self.vault.path.exists() or (legacy_inventory(self.paths) and data.get("confirm_migration") is not True):
                    raise AuthorizationError("explicit migration confirmation required")
                try:
                    self.migration.apply(_phrase(data.get("passphrase")), {record["credential_id"]: record})
                    self._check_runtime_state()
                finally:
                    self.vault.close()
                return await self.status()
            if set(data) != {"challenge_id", "credential", "name"}:
                raise ValueError("passkey add has unexpected fields")
            await self._end_epoch()
            snapshot = self.vault.snapshot
            snapshot["passkeys"][record["credential_id"]] = record
            self.vault.update(snapshot)
            write_manifest(self.paths, self.vault)
            token = self._issue_view()
            return {**await self.status(token), "view_token": token}

    async def scheduler(self):
        while not self.exit_requested.is_set():
            await self.status()
            wait = max(0.0, self._next_tick - self.clock()) if self.engine is not None else 300
            if self._admin_lock.locked():
                wait = max(0.1, wait)
            self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), wait)
            except asyncio.TimeoutError:
                pass
            if self.engine is None or self._admin_lock.locked():
                continue
            if self.clock() < self._next_tick and not self._service_requested:
                continue
            self._service_requested = False
            # The state machine cancels its active run on admin mutations.
            # Give it a child task so that cancellation never kills scheduler.
            self._tick_task = asyncio.create_task(self.engine.run_once())
            try:
                await self._tick_task
            except asyncio.CancelledError:
                # Closing an epoch cancels the child. Only cancellation of this
                # scheduler itself is a terminal service shutdown.
                if asyncio.current_task().cancelling():
                    raise
            finally:
                if self._tick_task is not None and not self._tick_task.done():
                    self._tick_task.cancel()
                    await asyncio.gather(self._tick_task, return_exceptions=True)
                self._tick_task = None
            if self.jobs.cleanup_unconfirmed:
                self.exit_requested.set()
                return
            self._next_tick = self.clock() + 300

    async def close(self):
        await self.jobs.cancel()
        if self.engine is not None:
            await self.engine.close()
        self.vault.close()
        self.engine = None
