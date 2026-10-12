#!/usr/bin/env python3
"""Synthetic signed IPC client for an isolated role-restart probe."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys


ORIGIN = "https://admin.example.test"
RP_ID = "example.test"
PHRASE = "synthetic-lifecycle-phrase-only"
CREDENTIAL_ID = b"synthetic-lifecycle-passkey"


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def synthetic_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    # Public test material, deliberately reproducible across client restarts.
    # Never use this key or phrase in an owner vault.
    return ec.derive_private_key(1, ec.SECP256R1())


def client_data(kind, nonce):
    return json.dumps({"type": kind, "challenge": nonce, "origin": ORIGIN,
                       "crossOrigin": False}, separators=(",", ":")).encode()


def registration(nonce):
    import cbor2
    public = synthetic_key().public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1,
                       -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")})
    auth = (hashlib.sha256(RP_ID.encode()).digest() + b"\x45" + b"\0" * 4
            + b"\0" * 16 + len(CREDENTIAL_ID).to_bytes(2, "big") + CREDENTIAL_ID + cose)
    return {"id": b64(CREDENTIAL_ID), "rawId": b64(CREDENTIAL_ID), "type": "public-key",
            "response": {"clientDataJSON": b64(client_data("webauthn.create", nonce)),
                         "attestationObject": b64(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth}))}}


def assertion(nonce):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    data = client_data("webauthn.get", nonce)
    auth = hashlib.sha256(RP_ID.encode()).digest() + b"\x05" + b"\0" * 4
    signature = synthetic_key().sign(auth + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
    return {"id": b64(CREDENTIAL_ID), "rawId": b64(CREDENTIAL_ID), "type": "public-key",
            "response": {"clientDataJSON": b64(data), "authenticatorData": b64(auth),
                         "signature": b64(signature), "userHandle": None}}


def prepare(client, operation):
    begin = client.request("operation_begin", {"operation": operation, "payload": {}})
    return {"challenge_id": begin["challenge_id"],
            "credential": assertion(begin["public_key"]["challenge"])}


def exchange(client, step, data):
    if step == "bootstrap" and data == {}:
        token = client.request("console_bootstrap")["token"]
        begin = client.request("bootstrap_begin", {"token": token})
        return client.request("registration_finish", {
            "challenge_id": begin["challenge_id"],
            "credential": registration(begin["public_key"]["challenge"]),
            "name": "Synthetic lifecycle", "passphrase": PHRASE})
    if step == "unlock" and data == {}:
        return client.request("operation_finish", {**prepare(client, "unlock"), "passphrase": PHRASE})
    if step == "status" and (data == {} or set(data) == {"view_token"}):
        return client.request("status", data) if data else client.request("status")
    if step == "prepare_view" and data == {}:
        return prepare(client, "view_status")
    if step == "finish_view" and set(data) == {"challenge_id", "credential"}:
        return client.request("operation_finish", data)
    if step == "stale_view" and set(data) == {"challenge_id", "credential"}:
        try:
            client.request("operation_finish", data)
        except RuntimeError as exc:
            if str(exc) == "AuthorizationError":
                return {"rejected": "AuthorizationError"}
            raise
        raise RuntimeError("pre-restart ceremony was accepted")
    if step == "lock" and data == {}:
        return client.request("operation_finish", prepare(client, "lock"))
    raise ValueError("synthetic lifecycle step differs")


def verify_environment(step):
    import sunny_digest
    from sunny_digest.memory_guard import protect_process, verify_native_parent
    from sunny_digest.version import APP_VERSION, COLLECTOR_VERSION
    uid = 1000 if step == "bootstrap" else 1002
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() != uid
            or Path(sunny_digest.__file__).resolve().parent != Path("/app/src/sunny_digest")
            or (APP_VERSION, COLLECTOR_VERSION) != ("0.3.0", "0.2.1")
            or resource.getrlimit(resource.RLIMIT_CORE) != (0, 0)):
        raise RuntimeError("lifecycle image/platform/role/core differs")
    manifest = json.loads(Path(__file__).with_name("probe-manifest.json").read_text())
    source = Path("/app/src")
    expected = {name[4:]: digest for name, digest in manifest["files"].items() if name.startswith("src/")}
    actual = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in source.rglob("*") if path.is_file()}
    if not expected or actual != expected or hashlib.sha256(Path("/app/requirements.txt").read_bytes()).hexdigest() != manifest["files"]["requirements.txt"]:
        raise RuntimeError("lifecycle image source differs")
    protect_process()
    verify_native_parent()
    return uid


def main():
    from sunny_digest.web import IPCClient
    raw = sys.stdin.buffer.read(32769)
    if not raw or len(raw) > 32768:
        raise ValueError("lifecycle input size differs")
    request = json.loads(raw)
    if (not isinstance(request, dict) or set(request) != {"step", "data"}
            or not isinstance(request["step"], str) or not isinstance(request["data"], dict)):
        raise ValueError("lifecycle input fields differ")
    uid = verify_environment(request["step"])
    socket = "/data/runtime/ipc/admin/admin.sock" if uid == 1000 else "/data/ipc/admin.sock"
    client = IPCClient(socket, connect_timeout=5, send_timeout=5, response_timeout=5)
    if client.request("status").get("trusted_origin") != ORIGIN:
        raise RuntimeError("lifecycle trusted origin differs")
    result = exchange(client, request["step"], request["data"])
    # Only the host controller captures this synthetic JSON; it logs no bodies.
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
