#!/usr/bin/env python3
"""Synthetic active-job cancellation and abrupt migration crash/resume probes.

The native entry point uses production memory guards, Guardian, Collector,
JobBroker and model_collector. The model is held before SSH authentication by a
loopback TCP sink. Its in-process dispatch bridge does not prove kernel peer
credentials; the separate role probe covers those. No real Telegram/model/SSH
endpoint or owner credential is used.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone

from check_linux_lifecycle import ORIGIN, RP_ID, PHRASE, assertion, registration

PHASES = ("started", "encrypted", "committed", "plaintext_removed", "cleaned", "ready")
SOURCE = "12345678-1234-4678-9234-567812345678"
CANARY = b"SYNTHETIC-MIGRATION-KEY-CANARY"


def layout(root):
    from sunny_digest.storage import Paths, atomic_write_json
    paths = Paths(root/"config", root/"private", root/"runtime", root/"runtime/admin.sock")
    paths.ensure()
    scratch = root/"scratch"
    scratch.mkdir(mode=0o700, exist_ok=True)
    atomic_write_json(paths.config_dir/"security-origin.json", {"origin": ORIGIN, "rp_id": RP_ID})
    return paths, scratch


async def bootstrap(guardian, *, migrate=False):
    token = guardian._auth().create_bootstrap()
    begin = await guardian.bootstrap_begin({"token": token})
    return await guardian.registration_finish({
        "challenge_id": begin["challenge_id"],
        "credential": registration(begin["public_key"]["challenge"]),
        "name": "Synthetic state probe", "passphrase": PHRASE,
        "confirm_migration": migrate,
    })


async def signed(guardian, operation, *, phrase=False):
    begin = await guardian.begin({"operation": operation, "payload": {}})
    payload = {"challenge_id": begin["challenge_id"],
               "credential": assertion(begin["public_key"]["challenge"])}
    if phrase:
        payload["passphrase"] = PHRASE
    return await guardian.finish(payload)


def seed_legacy(paths):
    """Canonical locked policy and both delivery domains, generated offline."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from telethon.crypto import AuthKey
    from telethon.sessions import StringSession
    from sunny_digest.contracts import build_digest_upload, build_monitor_upload, canonical_digest_bytes, canonical_monitor_bytes
    from sunny_digest.guardian_engine import WATCH_STATE_SCHEMA, DIGEST_ACKNOWLEDGED_SCHEMA
    from sunny_digest.models import PeerSpec
    from sunny_digest.openrouter import OPUS_55_MODEL
    from sunny_digest.secret_files import generate_encrypted_ed25519
    from sunny_digest.settings import validate_configure
    from sunny_digest.storage import atomic_write_bytes, atomic_write_json
    from sunny_digest.vault_storage import RECORD_NAMES

    now = datetime.now(timezone.utc)
    host_public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    settings, credentials, known_host, _ = validate_configure({
        "telegram_api_id": 12345, "telegram_api_hash": "a"*32,
        "openrouter_api_key": CANARY.decode(), "openrouter_model": OPUS_55_MODEL,
        "upload_host": "receiver.example", "upload_port": 22, "upload_user": "root",
        "known_host": "receiver.example "+host_public,
        "consent_expires_at": (now+timedelta(days=1)).isoformat(),
        "vpn_subscription_url": "https://subscription.example/synthetic",
    }, now)
    public, fingerprint = generate_encrypted_ed25519(paths, "upload_key", "upload_public_key", "synthetic-upload")
    generate_encrypted_ed25519(paths, "openrouter_key", "openrouter_public_key", "synthetic-model")
    peers = [PeerSpec("channel", 124, 91), PeerSpec("channel", 123, 92)]
    ids = [peer.telegram_chat_id() for peer in peers]
    settings.update(phase="chat_locked", chat_locked=True, source_id=SOURCE,
                    upload_public_key=public, upload_key_fingerprint=fingerprint,
                    chats=[{"chat_id": chat, "title": "Synthetic chat "+str(index),
                            "peer": peer.as_dict(), "initial_message_id": 0}
                           for index, (chat, peer) in enumerate(zip(ids, peers))])
    atomic_write_json(paths.settings, settings)
    atomic_write_json(paths.credentials, credentials)
    atomic_write_bytes(paths.known_hosts, known_host)
    atomic_write_bytes(paths.chat_locked, b"locked\n")
    session = StringSession()
    session.set_dc(1, "149.154.175.53", 443)
    session.auth_key = AuthKey(data=b"s"*256)
    atomic_write_bytes(paths.telegram_session, session.save().encode())
    atomic_write_json(paths.vpn_active_node, {
        "type": "vless", "server": "1.1.1.1", "port": 443,
        "uuid": "11111111-2222-4333-8444-555555555555", "network": "tcp", "tls": True,
        "servername": "cdn.example", "client-fingerprint": "chrome",
        "reality-opts": {"public-key": "E"*43, "short-id": "1a2b3c4d"},
        "flow": "xtls-rprx-vision", "udp": False,
    })
    atomic_write_json(paths.watch_state, {
        "schema": WATCH_STATE_SCHEMA, "source_id": SOURCE, "phase": "active",
        "monitor_sequence": 2, "monitor_content_sha256": "b"*64,
        "monitor_cursors": [{"chat_id": chat, "through_message_id": 0 if i == 0 else 31} for i, chat in enumerate(ids)],
        "pending_extension_chat_ids": [ids[0]],
        "chats": [{"chat_id": chat, "scan_through_message_id": 0 if i == 0 else 36,
                   "read_pending_through_message_id": 0 if i == 0 else 36,
                   "read_acked_through_message_id": 0 if i == 0 else 35}
                  for i, chat in enumerate(ids)],
    })
    atomic_write_json(paths.acknowledged, {
        "schema": DIGEST_ACKNOWLEDGED_SCHEMA, "source_id": SOURCE, "sequence": 6,
        "content_sha256": "a"*64, "digest_date": "2026-10-09",
        "cursors": [{"chat_id": chat, "through_message_id": 10+i} for i, chat in enumerate(ids)],
    })
    gate = {
        "schema": "sunny.personal-chats.status-gate.v2", "ok": True,
        "server_time": "2026-10-10T05:30:00Z", "timezone": "Europe/Moscow",
        "monitor": {"baseline_required": False, "next_sequence": 3, "previous_sha256": "b"*64,
                    "cursors": [{"chat_id": chat, "through_message_id": 0 if i == 0 else 31} for i, chat in enumerate(ids)],
                    "max_upload_bytes": 32768},
        "digest": {"due": True, "reason": "due", "digest_date": "2026-10-10",
                   "prepare_not_before": "2026-10-10T05:00:00Z", "accept_until": "2026-10-10T06:45:00Z",
                   "next_sequence": 7, "previous_sha256": "a"*64,
                   "cursors": [{"chat_id": chat, "through_message_id": 10+i} for i, chat in enumerate(ids)],
                   "max_upload_bytes": 32768},
    }
    when = datetime(2026, 10, 10, 5, 30, tzinfo=timezone.utc)
    digest = build_digest_upload(source_id=SOURCE, gate=gate,
        chat_ranges=[{"chat_id": chat, "from_message_id_exclusive": 10+i,
                      "through_message_id": 11+i, "message_count": 1} for i, chat in enumerate(ids)],
        digest="Synthetic pending digest", model=OPUS_55_MODEL, generated_at=when)
    atomic_write_bytes(paths.pending, canonical_digest_bytes(digest))
    monitor = build_monitor_upload(source_id=SOURCE, gate=gate, kind="extension_baseline",
        ranges=[{"chat_id": ids[0], "from_message_id_exclusive": 0, "through_message_id": 31}],
        events=[], generated_at=when)
    atomic_write_bytes(paths.monitor_pending, canonical_monitor_bytes(monitor))
    for path in (paths.telegram_session_outstanding, paths.revocation_warning):
        atomic_write_bytes(path, b"synthetic-warning-preserved\n")
    atomic_write_bytes(paths.private_dir/".unrelated", b"unknown-file-must-survive\n")
    atomic_write_bytes(paths.credentials.with_name(".credentials.json.crash-remnant"), CANARY)
    records = {record: getattr(paths, name).read_bytes() for name, record in RECORD_NAMES.items()
               if getattr(paths, name).exists()}
    preserved = {path: path.read_bytes() for path in (paths.watch_state, paths.acknowledged,
        paths.pending, paths.monitor_pending, paths.telegram_session_outstanding, paths.revocation_warning,
        paths.private_dir/".unrelated")}
    if not records or not preserved or not all(preserved.values()):
        raise RuntimeError("synthetic state is empty")
    return records, preserved


async def migration_case(root, phase, crash, *, guardian_factory=None):
    from sunny_digest.authn import AuthorizationError
    from sunny_digest.guardian import Guardian
    from sunny_digest.guardian_engine import Collector
    from sunny_digest.migrate_vault import legacy_inventory
    from sunny_digest.vault import VaultLockedError
    from sunny_digest.vault_storage import RECORD_NAMES
    factory = guardian_factory or Guardian
    paths, scratch = layout(root)
    records, preserved = seed_legacy(paths)
    crash(root, phase)
    guardian = factory(paths, scratch=scratch)
    try:
        state = "locked" if phase == "ready" else "migration_blocked"
        if guardian.security_state() != state or guardian.engine is not None:
            raise RuntimeError("migration crash did not start blocked/locked")
        if phase == "started":
            before = {getattr(paths, name): getattr(paths, name).read_bytes()
                      for name in RECORD_NAMES
                      if getattr(paths, name).exists()}
            try:
                guardian.migration.resume()
            except VaultLockedError:
                pass
            else:
                raise RuntimeError("unauthenticated migration resume succeeded")
            if any(path.read_bytes() != value for path, value in before.items()):
                raise RuntimeError("failed resume changed legacy bytes")
            await bootstrap(guardian, migrate=True)
        else:
            # A real canonical assertion cannot unlock an unfinished migration.
            if phase == "encrypted":
                try:
                    await signed(guardian, "unlock", phrase=True)
                except AuthorizationError:
                    pass
                else:
                    raise RuntimeError("unlock bypassed migration")
                if guardian.engine is not None or guardian.vault._snapshot is not None:
                    raise RuntimeError("failed unlock retained secrets")
                # New process state avoids waiting out the earlier ceremony's rate limit.
                await guardian.close()
                guardian = factory(paths, scratch=scratch)
            await signed(guardian, "migration_resume", phrase=True)
        if (guardian.security_state() != "locked" or guardian.engine is not None
                or guardian.vault._snapshot is not None or guardian.migration.marker.exists()
                or legacy_inventory(paths)):
            raise RuntimeError("migration did not finish locked without plaintext")
        await guardian.close()
        guardian = factory(paths, scratch=scratch)
        await signed(guardian, "unlock", phrase=True)
        if not isinstance(guardian.engine, Collector):
            raise RuntimeError("fresh unlock did not install the production Collector")
        snapshot = guardian.vault.snapshot
        actual = {name: base64.b64decode(value, validate=True) for name, value in snapshot["records"].items()}
        if snapshot["source_id"] != SOURCE or actual != records or len(snapshot["passkeys"]) != 1:
            raise RuntimeError("migration changed canonical policy/secret bytes")
        if any(not path.is_file() or path.read_bytes() != value for path, value in preserved.items()):
            raise RuntimeError("migration changed checkpoint/pending/warning/unknown bytes")
        if paths.credentials.with_name(".credentials.json.crash-remnant").exists():
            raise RuntimeError("migration left a named plaintext remnant")
        for path in root.rglob('*'):
            if path.is_file() and CANARY in path.read_bytes():
                raise RuntimeError("migration left a plaintext canary")
        print("MIGRATION CRASH / SIGNED RECOVERY: PASS phase="+phase, flush=True)
    finally:
        await guardian.close()


async def crash_child(root, phase):
    from sunny_digest.guardian import Guardian
    paths, scratch = layout(root)
    guardian = Guardian(paths, scratch=scratch)
    def barrier(value):
        if value == phase:
            print("MIGRATION CRASH BARRIER: "+phase, flush=True)
            os._exit(75)  # Deliberately bypass finally/destructors; synthetic tmpfs only.
    guardian.migration.barrier = barrier
    await bootstrap(guardian, migrate=True)
    raise RuntimeError("requested migration crash barrier was not reached")


class DispatchBridge:
    """Only a thread-to-loop adapter; role/SO_PEERCRED acceptance is separate."""
    def __init__(self, guardian):
        self.guardian, self.loop = guardian, asyncio.get_running_loop()
        self.calls = []
        self.before_reaped = lambda: None

    def request(self, command, data):
        from sunny_digest.guardian_ipc import dispatch
        self.calls.append(command)
        if command == "job_reaped":
            self.before_reaped()
        return asyncio.run_coroutine_threadsafe(
            dispatch(self.guardian, "jobs", 1001, {"command": command, "data": data}), self.loop).result(timeout=5)


async def active_case(root, *, guardian_factory=None, observe=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    from sunny_digest.guardian import Guardian
    from sunny_digest.job_contracts import JOB_SCHEMA, RESULT_SCHEMA
    from sunny_digest.model_collector import run_job
    from sunny_digest.model_lease import boottime, require_lease
    from sunny_digest.openrouter import OPUS_55_MODEL
    from check_linux_native_children import observe_ssh, audit_reaped
    paths, scratch = layout(root)
    guardian = (guardian_factory or Guardian)(paths, scratch=scratch)
    accepted, writers = asyncio.Event(), set()
    def connected(_reader, writer):
        writers.add(writer)
        accepted.set()
    server = await asyncio.start_server(connected, "127.0.0.1", 0)
    task = requester = None
    pid = None
    try:
        await bootstrap(guardian)
        await signed(guardian, "unlock", phrase=True)
        initial = guardian.vault.snapshot
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
        port = server.sockets[0].getsockname()[1]
        job = {"schema": JOB_SCHEMA, "job_id": str(uuid.uuid4()),
               "security_epoch": initial["security_epoch"], "model": OPUS_55_MODEL,
               "prompt": "Synthetic active-job probe only", "timeout_s": 60,
               "expires_mono": time.monotonic()+90, "expires_boot": boottime()+90,
               "model_access": {"api_key": "synthetic-model-key", "host": "127.0.0.1", "port": port,
                   "known_hosts": f"[127.0.0.1]:{port} {public}\n",
                   "tunnel_key": base64.b64encode(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())).decode()}}
        requester = asyncio.create_task(guardian.jobs.request(job))
        guardian.engine._active_run_task = requester
        await asyncio.sleep(0)
        delivered = guardian.jobs.next_job().get("job")
        if delivered != job or guardian.jobs.next_job() != {"job": None}:
            raise RuntimeError("active job was not delivered exactly once")
        client = DispatchBridge(guardian)
        task = asyncio.create_task(run_job(client, delivered, scratch))
        if observe is None:
            pid = await observe_ssh(task, accepted, scratch, os.getuid())
            client.before_reaped = lambda: audit_reaped(pid)
        else:
            await observe(task, accepted, scratch)
        if guardian.jobs.status(job["job_id"]) != {"active": True} or task.done() or requester.done():
            raise RuntimeError("active-job positive control failed")
        require_lease(job)
        await asyncio.wait_for(signed(guardian, "lock"), timeout=15)
        await asyncio.wait_for(task, timeout=5)
        require_lease(job)  # Refusal must be revocation, not expiry.
        if (not requester.cancelled() or guardian.jobs.active is not None or guardian.jobs.cleanup_unconfirmed
                or client.calls.count("job_reaped") != 1 or "job_result" in client.calls
                or guardian.engine is not None or guardian.vault._snapshot is not None
                or not guardian.exit_requested.is_set() or guardian.security_state() != "locked"):
            raise RuntimeError("signed lock did not cancel/reap the delivered job before closing keys")
        if pid is not None:
            audit_reaped(pid)
        if any(path.name.startswith("secret-") for path in scratch.iterdir()):
            raise RuntimeError("active job left secret scratch")
        try:
            guardian.jobs.result({"schema": RESULT_SCHEMA, "job_id": job["job_id"],
                "security_epoch": job["security_epoch"], "model": job["model"],
                "outcome": "error", "failure": {"code": "worker_failed"}})
        except ValueError:
            pass
        else:
            raise RuntimeError("late cancelled result was accepted")
        guardian.vault.unlock(PHRASE)
        after = guardian.vault.snapshot
        if (after["security_epoch"] != initial["security_epoch"]+1
                or after["policy_revision"] != initial["policy_revision"]+1):
            raise RuntimeError("signed lock did not persist the new epoch")
        guardian.vault.close()
        print("ACTIVE MODEL / SIGNED LOCK: PASS (cancel, reaped before ACK, late result refused, vault closed)", flush=True)
    finally:
        if task is not None and not task.done():
            task.cancel()
        if requester is not None and not requester.done():
            requester.cancel()
        await asyncio.gather(*(item for item in (task, requester) if item is not None), return_exceptions=True)
        await guardian.close()
        server.close()
        for writer in writers:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
        await server.wait_closed()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("active", "migration", "crash"))
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--phase", choices=PHASES)
    args = parser.parse_args()
    sys.path.insert(0, str(args.context/"scripts"))
    from check_linux_crypto import verify_image
    verify_image(args.context)
    if args.mode == "crash":
        if args.root is None or args.phase is None or not args.root.resolve().is_relative_to('/run/guardian-private'):
            raise ValueError("synthetic crash scope differs")
        asyncio.run(crash_child(args.root, args.phase))
        return
    if args.root is not None or args.phase is not None:
        raise ValueError("only the synthetic crash child accepts root/phase")
    with tempfile.TemporaryDirectory(prefix="sunny-state-", dir="/run/guardian-private") as directory:
        root = Path(directory)
        if args.mode == "active":
            asyncio.run(active_case(root))
        else:
            def crash(stage, phase):
                result = subprocess.run([sys.executable, "-B", __file__, "crash", "--context="+str(args.context),
                    "--root="+str(stage), "--phase="+phase], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
                if result.returncode != 75 or result.stdout.decode().splitlines().count("MIGRATION CRASH BARRIER: "+phase) != 1:
                    raise RuntimeError("synthetic process did not exit at its exact migration barrier")
            for phase in PHASES:
                stage = root/phase
                stage.mkdir(mode=0o700)
                asyncio.run(migration_case(stage, phase, crash))
    print("STATE CASE EXIT: 0 mode="+args.mode, flush=True)


if __name__ == "__main__":
    main()
