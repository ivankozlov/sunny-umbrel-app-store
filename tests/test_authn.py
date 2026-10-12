from __future__ import annotations

import base64
import hashlib
import json
import unittest

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sunny_digest.authn import (
    AuthorizationError,
    BOOTSTRAP_TTL_S,
    CHALLENGE_TTL_S,
    OpaqueAuthorization,
    WebAuthnAuthorizer,
)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def challenge(options):
    return options["public_key"]["challenge"]


def client_data(kind, nonce, origin="https://admin.example.test"):
    return json.dumps({
        "type": kind, "challenge": nonce, "origin": origin,
        "crossOrigin": False,
    }, separators=(",", ":")).encode("utf-8")


def key_material():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")})
    return private, cose


def registration_credential(nonce, private, credential_id=b"credential-1", rp_id=b"example.test"):
    _, cose = key_material() if private is None else (private, cbor2.dumps({
        1: 2, 3: -7, -1: 1,
        -2: private.public_key().public_numbers().x.to_bytes(32, "big"),
        -3: private.public_key().public_numbers().y.to_bytes(32, "big"),
    }))
    auth_data = (
        hashlib.sha256(rp_id).digest() + b"\x45" + (0).to_bytes(4, "big")
        + b"\0" * 16 + len(credential_id).to_bytes(2, "big") + credential_id + cose
    )
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    return {
        "id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
        "response": {"clientDataJSON": b64(client_data("webauthn.create", nonce)), "attestationObject": b64(attestation)},
    }, cose


def assertion(nonce, private, credential_id=b"credential-1", *, origin="https://admin.example.test", flags=0x05, sign_count=0, rp_id=b"example.test"):
    data = client_data("webauthn.get", nonce, origin)
    auth_data = hashlib.sha256(rp_id).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")
    signature = private.sign(auth_data + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
        "response": {
            "clientDataJSON": b64(data), "authenticatorData": b64(auth_data),
            "signature": b64(signature), "userHandle": None,
        },
    }


class AuthnTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.authn = WebAuthnAuthorizer(
            trusted_origin="https://admin.example.test", rp_id="example.test", clock=self.clock)
        self.vault_id = "vault-1"
        self.private, self.cose = key_material()
        self.records = {
            b64(b"credential-1"): {
                "credential_id": b64(b"credential-1"), "public_key": b64(self.cose),
                "sign_count": 7, "user_handle": b64(hashlib.sha256(self.vault_id.encode()).digest()),
                "name": "Main passkey",
            }
        }

    def begin(self, payload={"enabled": True}, operation="lock"):
        return self.authn.begin_operation(
            operation=operation, normalized_payload=payload, vault_id=self.vault_id,
            security_epoch=4, policy_revision=9, credential_index=self.records)

    def verify(self, started, credential=None, **snapshot):
        return self.authn.verify_operation(
            challenge_id=started["challenge_id"], credential=credential or assertion(challenge(started), self.private),
            credentials=self.records, vault_id=snapshot.get("vault_id", self.vault_id),
            security_epoch=snapshot.get("security_epoch", 4), policy_revision=snapshot.get("policy_revision", 9),
        )

    def test_cryptographic_assertion_binds_frozen_payload_and_snapshot(self):
        started = self.begin({"action": "lock", "reason": "owner"})
        grant = self.verify(started)
        self.assertIsInstance(grant, OpaqueAuthorization)
        self.assertEqual(grant.payload, {"action": "lock", "reason": "owner"})
        self.assertTrue(grant.matches(vault_id=self.vault_id, security_epoch=4, policy_revision=9))
        self.assertFalse(grant.matches(vault_id=self.vault_id, security_epoch=5, policy_revision=9))

    def test_replay_is_refused_even_for_valid_signature(self):
        started = self.begin()
        response = assertion(challenge(started), self.private)
        self.verify(started, response)
        with self.assertRaises(AuthorizationError):
            self.verify(started, response)

    def test_expired_challenge_and_stale_epoch_or_revision_are_refused(self):
        expired = self.begin()
        self.clock.value += CHALLENGE_TTL_S + 1
        with self.assertRaises(AuthorizationError):
            self.verify(expired)
        for snapshot in ({"security_epoch": 5}, {"policy_revision": 10}, {"vault_id": "other"}):
            started = self.begin()
            with self.assertRaises(AuthorizationError):
                self.verify(started, **snapshot)

    def test_origin_rp_challenge_signature_and_uv_up_are_verified_cryptographically(self):
        bad_cases = [
            lambda started: assertion(challenge(started), self.private, origin="https://other.example.test"),
            lambda started: assertion(b64(b"wrong challenge"), self.private),
            lambda started: assertion(challenge(started), self.private, flags=0x01),
            lambda started: assertion(challenge(started), self.private, flags=0x04),
            lambda started: assertion(challenge(started), ec.generate_private_key(ec.SECP256R1())),
        ]
        for build in bad_cases:
            started = self.begin()
            with self.assertRaises(AuthorizationError):
                self.verify(started, build(started))
        started = self.begin()
        wrong_rp = assertion(challenge(started), self.private)
        decoded = base64.urlsafe_b64decode(wrong_rp["response"]["authenticatorData"] + "==")
        wrong_rp["response"]["authenticatorData"] = b64(hashlib.sha256(b"other.test").digest() + decoded[32:])
        with self.assertRaises(AuthorizationError):
            self.verify(started, wrong_rp)

    def test_closed_credential_shape_and_unknown_credential_are_refused(self):
        started = self.begin()
        malformed = assertion(challenge(started), self.private)
        malformed["extra"] = "no"
        with self.assertRaises(AuthorizationError):
            self.verify(started, malformed)
        started = self.begin()
        unknown = assertion(challenge(started), self.private, credential_id=b"other")
        with self.assertRaises(AuthorizationError):
            self.verify(started, unknown)

    def test_synced_counter_zero_and_nonincreasing_do_not_block_owner(self):
        for count in (0, 1, 7):
            started = self.begin()
            self.verify(started, assertion(challenge(started), self.private, sign_count=count))

    def test_bootstrap_is_hashed_expiring_and_consumed_only_after_registration(self):
        bootstrap = self.authn.create_bootstrap()
        self.assertNotIn(bootstrap, repr(self.authn.__dict__))
        start = self.authn.begin_bootstrap_registration(
            vault_id=self.vault_id, credentials={}, bootstrap_token=bootstrap)
        created, _ = registration_credential(challenge(start), self.private)
        record = self.authn.finish_registration(
            challenge_id=start["challenge_id"], credential=created, credentials={}, name="Backup")
        self.assertEqual(record["credential_id"], b64(b"credential-1"))
        with self.assertRaises(AuthorizationError):
            self.authn.begin_bootstrap_registration(
                vault_id=self.vault_id, credentials={}, bootstrap_token=bootstrap)
        token = self.authn.create_bootstrap()
        self.clock.value += BOOTSTRAP_TTL_S + 1
        with self.assertRaises(AuthorizationError):
            self.authn.begin_bootstrap_registration(vault_id=self.vault_id, credentials={}, bootstrap_token=token)

    def test_registration_requires_bootstrap_and_rejects_duplicate_credential(self):
        with self.assertRaises(AuthorizationError):
            self.authn.begin_bootstrap_registration(vault_id=self.vault_id, credentials={}, bootstrap_token="no")
        token = self.authn.create_bootstrap()
        start = self.authn.begin_bootstrap_registration(vault_id=self.vault_id, credentials={}, bootstrap_token=token)
        created, _ = registration_credential(challenge(start), self.private)
        with self.assertRaises(AuthorizationError):
            self.authn.finish_registration(
                challenge_id=start["challenge_id"], credential=created, credentials=self.records, name="Duplicate")

    def test_passkey_add_requires_a_consumed_authorization(self):
        started = self.begin(operation="passkey_add")
        grant = self.verify(started)
        registration = self.authn.begin_passkey_add(authorization=grant, credentials=self.records)
        self.assertIn("challenge_id", registration)
        with self.assertRaises(AuthorizationError):
            self.authn.begin_passkey_add(
                authorization=OpaqueAuthorization("lock", {}, self.vault_id, 4, 9), credentials=self.records)

    def test_trusted_origin_rejects_http_ip_wildcard_path_and_nonmatching_rp(self):
        for origin, rp_id in (
            ("http://admin.example.test", "example.test"),
            ("https://127.0.0.1", "example.test"),
            ("https://*.example.test", "example.test"),
            ("https://admin.example.test/path", "example.test"),
            ("https://admin.example.test", "other.test"),
        ):
            with self.assertRaises(ValueError):
                WebAuthnAuthorizer(trusted_origin=origin, rp_id=rp_id)


if __name__ == "__main__":
    unittest.main()
