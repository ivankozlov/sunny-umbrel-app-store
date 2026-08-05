#!/usr/bin/env python3
"""Visual-test fixture for the real web IPC path; never imported by production."""

from __future__ import annotations

import argparse
import json
import os
import socketserver
from pathlib import Path


def fixture(phase: str):
    base = {
        "schema": "sunny.personal-digest-local-status.v1",
        "phase": phase,
        "configured": phase != "fresh",
        "chat_locked": phase == "chat_locked",
        "consent_active": phase == "chat_locked",
        "pending_upload": False,
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
    }
    if phase == "dialogs_listed":
        base["dialogs"] = [
            {"chat_id": -1001234567890, "title": "Тестовая группа", "kind": "channel"},
            {"chat_id": -987654321, "title": "Семейный чат", "kind": "chat"},
        ]
    if phase == "chat_locked":
        base.update({
            "source_id": "12345678-1234-4678-9234-567812345678",
            "chat_id": -1001234567890,
            "chat_title": "Тестовая группа",
            "initial_message_id": 4821,
            "upload_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey sunny-test",
            "upload_key_fingerprint": "SHA256:fixture-only-not-a-key",
            "model": "anthropic/example-model",
            "upload_target": "root@receiver.example:22",
            "consent_expires_at": "2026-10-01T00:00:00Z",
            "last_result": "not_due",
        })
    return base


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(64 * 1024 + 1)
        try:
            request = json.loads(raw.decode("utf-8"))
            if request != {"command": "status"}:
                raise ValueError
            response = {"ok": True, "result": self.server.status}
        except Exception:
            response = {"ok": False, "error_type": "FixtureReadOnly"}
        self.wfile.write(json.dumps(
            response, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n")


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument(
        "--phase", default="fresh",
        choices=("fresh", "configured", "code_sent", "password_required",
                 "authenticated", "dialogs_listed", "chat_locked"),
    )
    args = parser.parse_args()
    path = Path(args.socket)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    server = Server(str(path), Handler)
    server.status = fixture(args.phase)
    os.chmod(path, 0o600)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
