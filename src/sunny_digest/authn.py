"""Bounded server-side WebAuthn ceremonies for the guardian.

This module owns only short-lived in-memory ceremonies.  The guardian owns the
encrypted vault and must pass the canonical passkey records from that vault to
verification; an index visible while locked is only a browser hint.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)


CHALLENGE_TTL_S = 120
BOOTSTRAP_TTL_S = 600
MAX_PENDING_CHALLENGES = 32
MAX_CEREMONIES_PER_TTL = 16
MAX_PASSKEYS = 8
MAX_CREDENTIAL_JSON_BYTES = 24 * 1024
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_DNS_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
SUPPORTED_ALGORITHMS = (
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
)
OPERATIONS = frozenset({
    "unlock", "lock", "configure", "select_chats", "view_status", "migration_resume", "activate_monitoring", "renew_consent",
    "extend_chats", "replace_vpn", "revoke_and_reset",
    "acknowledge_manual_revocation", "passkey_add", "passkey_remove",
    "change_passphrase",
})


class AuthorizationError(ValueError):
    """A deliberately detail-free refusal suitable for the admin IPC boundary."""


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64(value: Any, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2 or not _B64URL.fullmatch(value):
        raise AuthorizationError(f"{label} is invalid")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise AuthorizationError(f"{label} is invalid") from exc
    if not result or len(result) > maximum or _b64(result) != value:
        raise AuthorizationError(f"{label} is invalid")
    return result


def _trusted_origin(origin: str, rp_id: str) -> tuple[str, str]:
    if not isinstance(origin, str) or not isinstance(rp_id, str):
        raise ValueError("trusted origin and rp_id are required")
    if not _DNS_NAME.fullmatch(rp_id) or rp_id != rp_id.lower():
        raise ValueError("rp_id must be a lower-case DNS name")
    try:
        ipaddress.ip_address(rp_id)
    except ValueError:
        pass
    else:
        raise ValueError("rp_id must not be an IP address")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("trusted origin must be an exact HTTPS origin")
    try:
        port = parsed.port
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        port = parsed.port
    else:
        raise ValueError("trusted origin must not use an IP address")
    host = parsed.hostname
    if host != host.lower() or not _DNS_NAME.fullmatch(host):
        raise ValueError("trusted origin host is invalid")
    expected_netloc = host if port is None else f"{host}:{port}"
    if parsed.netloc != expected_netloc or not (host == rp_id or host.endswith("." + rp_id)):
        raise ValueError("trusted origin does not match rp_id")
    return origin, rp_id


def _canonical_payload(payload: Any) -> tuple[Any, bytes]:
    if not isinstance(payload, dict):
        raise AuthorizationError("operation payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("operation payload is not JSON") from exc
    if not 2 <= len(encoded) <= 128 * 1024:
        raise AuthorizationError("operation payload is too large")
    try:
        frozen = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("operation payload is not JSON") from exc
    return frozen, hashlib.sha256(encoded).digest()


def _credential_shape(value: Any, *, registration: bool) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"id", "rawId", "type", "response"}:
        raise AuthorizationError("credential has unexpected fields")
    if value["type"] != "public-key":
        raise AuthorizationError("credential type is invalid")
    raw_id = _decode_b64(value["rawId"], "credential rawId", 1024)
    if value["id"] != _b64(raw_id):
        raise AuthorizationError("credential id is invalid")
    response = value["response"]
    expected = {"clientDataJSON", "attestationObject"} if registration else {
        "clientDataJSON", "authenticatorData", "signature", "userHandle"}
    if not isinstance(response, dict) or set(response) != expected:
        raise AuthorizationError("credential response has unexpected fields")
    _decode_b64(response["clientDataJSON"], "clientDataJSON", 8192)
    if registration:
        _decode_b64(response["attestationObject"], "attestationObject", 16 * 1024)
    else:
        _decode_b64(response["authenticatorData"], "authenticatorData", 4096)
        _decode_b64(response["signature"], "signature", 4096)
        if response["userHandle"] is not None:
            _decode_b64(response["userHandle"], "userHandle", 256)
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_CREDENTIAL_JSON_BYTES:
        raise AuthorizationError("credential is too large")
    return value


def _records(records: Mapping[str, Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    if not isinstance(records, Mapping) or len(records) > MAX_PASSKEYS:
        raise AuthorizationError("passkey records are invalid")
    result: Dict[str, Mapping[str, Any]] = {}
    for credential_id, record in records.items():
        key = _decode_b64(credential_id, "credential id", 1024)
        if not isinstance(record, Mapping) or set(record) != {
                "credential_id", "public_key", "sign_count", "user_handle", "name"}:
            raise AuthorizationError("passkey record has unexpected fields")
        if record["credential_id"] != credential_id:
            raise AuthorizationError("passkey record id is invalid")
        _decode_b64(record["public_key"], "credential public key", 4096)
        _decode_b64(record["user_handle"], "credential user handle", 256)
        if type(record["sign_count"]) is not int or not 0 <= record["sign_count"] <= 2**32 - 1:
            raise AuthorizationError("credential sign count is invalid")
        if not isinstance(record["name"], str) or not 1 <= len(record["name"]) <= 80:
            raise AuthorizationError("credential name is invalid")
        result[_b64(key)] = record
    return result


@dataclass(frozen=True)
class OpaqueAuthorization:
    """A verified, consumed operation whose frozen payload is safe to execute once."""
    operation: str
    payload: Any
    vault_id: str
    security_epoch: int
    policy_revision: int

    def matches(self, *, vault_id: str, security_epoch: int, policy_revision: int) -> bool:
        return (secrets.compare_digest(self.vault_id, vault_id)
                and self.security_epoch == security_epoch
                and self.policy_revision == policy_revision)


@dataclass
class _Challenge:
    nonce: bytes
    operation: str
    payload: Any
    payload_hash: bytes
    vault_id: str
    security_epoch: int
    policy_revision: int
    expires_at: float
    registration: bool = False
    bootstrap_hash: Optional[bytes] = None


class WebAuthnAuthorizer:
    """In-memory guardian-side ceremonies; no Host/proxy-derived trust exists here."""

    def __init__(self, *, trusted_origin: str, rp_id: str,
                 clock: Callable[[], float] = time.monotonic):
        self.trusted_origin, self.rp_id = _trusted_origin(trusted_origin, rp_id)
        self._clock = clock
        self._pending: Dict[str, _Challenge] = {}
        self._ceremony_starts: list[float] = []
        self._bootstrap_hash: Optional[bytes] = None
        self._bootstrap_expires_at = 0.0
        self._bootstrap_failures = 0

    def create_bootstrap(self) -> str:
        """Create a console-delivered one-time token; only its hash remains in RAM."""
        token = secrets.token_urlsafe(32)
        self._bootstrap_hash = hashlib.sha256(token.encode("ascii")).digest()
        self._bootstrap_expires_at = self._clock() + BOOTSTRAP_TTL_S
        self._bootstrap_failures = 0
        return token

    def _prune(self) -> None:
        now = self._clock()
        for challenge_id, challenge in tuple(self._pending.items()):
            if challenge.expires_at <= now:
                del self._pending[challenge_id]
        if self._bootstrap_expires_at <= now:
            self._bootstrap_hash = None
            self._bootstrap_failures = 0

    def _remember(self, challenge: _Challenge) -> str:
        self._prune()
        now = self._clock()
        self._ceremony_starts = [start for start in self._ceremony_starts if start > now - CHALLENGE_TTL_S]
        if len(self._ceremony_starts) >= MAX_CEREMONIES_PER_TTL:
            raise AuthorizationError("ceremony rate limit exceeded")
        if len(self._pending) >= MAX_PENDING_CHALLENGES:
            raise AuthorizationError("too many pending ceremonies")
        challenge_id = secrets.token_urlsafe(18)
        self._pending[challenge_id] = challenge
        self._ceremony_starts.append(now)
        return challenge_id

    def _take(self, challenge_id: Any) -> _Challenge:
        self._prune()
        if not isinstance(challenge_id, str) or len(challenge_id) > 128:
            raise AuthorizationError("challenge is invalid")
        try:
            challenge = self._pending.pop(challenge_id)
        except KeyError as exc:
            raise AuthorizationError("challenge is unavailable") from exc
        if challenge.expires_at <= self._clock():
            raise AuthorizationError("challenge is unavailable")
        return challenge

    def begin_operation(self, *, operation: str, normalized_payload: Any,
                        vault_id: str, security_epoch: int, policy_revision: int,
                        credential_index: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        if operation not in OPERATIONS:
            raise AuthorizationError("operation is invalid")
        records = _records(credential_index)
        if not records:
            raise AuthorizationError("no passkeys are registered")
        payload, payload_hash = _canonical_payload(normalized_payload)
        if not isinstance(vault_id, str) or not vault_id or type(security_epoch) is not int or type(policy_revision) is not int:
            raise AuthorizationError("security snapshot is invalid")
        nonce = secrets.token_bytes(32)
        options = generate_authentication_options(
            rp_id=self.rp_id, challenge=nonce, timeout=CHALLENGE_TTL_S * 1000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=_decode_b64(key, "credential id", 1024)) for key in records],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        challenge_id = self._remember(_Challenge(
            nonce, operation, payload, payload_hash, vault_id, security_epoch,
            policy_revision, self._clock() + CHALLENGE_TTL_S,
        ))
        return {"challenge_id": challenge_id, "public_key": json.loads(options_to_json(options))}

    def begin_passkey_add(self, *, authorization: OpaqueAuthorization,
                          credentials: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        if authorization.operation != "passkey_add":
            raise AuthorizationError("passkey authorization is invalid")
        return self._begin_registration(
            vault_id=authorization.vault_id, credentials=credentials,
            bootstrap_hash=None,
        )

    def begin_bootstrap_registration(self, *, vault_id: str,
                                     credentials: Mapping[str, Mapping[str, Any]],
                                     bootstrap_token: str) -> Dict[str, Any]:
        self._prune()
        if _records(credentials):
            raise AuthorizationError("bootstrap registration is unavailable")
        if (not isinstance(bootstrap_token, str) or self._bootstrap_hash is None
                or self._bootstrap_failures >= 5
                or not secrets.compare_digest(hashlib.sha256(bootstrap_token.encode("utf-8")).digest(), self._bootstrap_hash)):
            self._bootstrap_failures += 1
            raise AuthorizationError("bootstrap token is unavailable")
        return self._begin_registration(vault_id=vault_id, credentials=credentials,
                                        bootstrap_hash=self._bootstrap_hash)

    def _begin_registration(self, *, vault_id: str,
                            credentials: Mapping[str, Mapping[str, Any]],
                            bootstrap_hash: Optional[bytes]) -> Dict[str, Any]:
        records = _records(credentials)
        if len(records) >= MAX_PASSKEYS:
            raise AuthorizationError("passkey limit reached")
        if not isinstance(vault_id, str) or not vault_id:
            raise AuthorizationError("vault id is invalid")
        nonce = secrets.token_bytes(32)
        user_handle = hashlib.sha256(vault_id.encode("utf-8")).digest()
        options = generate_registration_options(
            rp_id=self.rp_id, rp_name="Sunny Personal Chats", user_name="owner",
            user_display_name="Sunny owner", user_id=user_handle, challenge=nonce,
            timeout=CHALLENGE_TTL_S * 1000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=_decode_b64(key, "credential id", 1024)) for key in records],
            supported_pub_key_algs=list(SUPPORTED_ALGORITHMS),
        )
        challenge_id = self._remember(_Challenge(
            nonce, "passkey_add", None, b"", vault_id, 0, 0,
            self._clock() + CHALLENGE_TTL_S, registration=True,
            bootstrap_hash=bootstrap_hash,
        ))
        return {"challenge_id": challenge_id, "public_key": json.loads(options_to_json(options))}

    def finish_registration(self, *, challenge_id: str, credential: Any,
                            credentials: Mapping[str, Mapping[str, Any]], name: str) -> Dict[str, Any]:
        challenge = self._take(challenge_id)  # consume before parsing/side effects
        if not challenge.registration or not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise AuthorizationError("registration is invalid")
        records = _records(credentials)
        checked = _credential_shape(credential, registration=True)
        try:
            verified = verify_registration_response(
                credential=checked, expected_challenge=challenge.nonce,
                expected_rp_id=self.rp_id, expected_origin=self.trusted_origin,
                require_user_presence=True, require_user_verification=True,
                supported_pub_key_algs=list(SUPPORTED_ALGORITHMS),
            )
        except Exception as exc:
            raise AuthorizationError("registration verification failed") from exc
        credential_id = _b64(verified.credential_id)
        if credential_id in records:
            raise AuthorizationError("passkey is already registered")
        if challenge.bootstrap_hash is not None:
            if self._bootstrap_hash is None or not secrets.compare_digest(challenge.bootstrap_hash, self._bootstrap_hash):
                raise AuthorizationError("bootstrap token is unavailable")
            self._bootstrap_hash = None
            self._bootstrap_expires_at = 0.0
        return {
            "credential_id": credential_id,
            "public_key": _b64(verified.credential_public_key),
            "sign_count": verified.sign_count,
            "user_handle": _b64(hashlib.sha256(challenge.vault_id.encode("utf-8")).digest()),
            "name": name,
        }

    def verify_operation(self, *, challenge_id: str, credential: Any,
                         credentials: Mapping[str, Mapping[str, Any]], vault_id: str,
                         security_epoch: int, policy_revision: int) -> OpaqueAuthorization:
        challenge = self._take(challenge_id)  # single-use even for a bad assertion
        return self._verify_operation(challenge, credential=credential, credentials=credentials,
                                      vault_id=vault_id, security_epoch=security_epoch,
                                      policy_revision=policy_revision)

    def verify_locked_operation(self, *, challenge_id: str, credential: Any,
                                canonical_loader: Callable[[], Dict[str, Any]]) -> OpaqueAuthorization:
        # Consume before KDF/decrypt: a wrong phrase never leaves a reusable
        # challenge. The loader provides only the decrypted canonical records.
        challenge = self._take(challenge_id)
        if challenge.registration or challenge.operation not in {"unlock", "migration_resume"}:
            raise AuthorizationError("locked operation is invalid")
        _credential_shape(credential, registration=False)
        canonical = canonical_loader()
        return self._verify_operation(challenge, credential=credential, **canonical)

    def cancel_pending(self) -> None:
        self._pending.clear()
        self._bootstrap_hash = None
        self._bootstrap_expires_at = 0.0

    def _verify_operation(self, challenge: _Challenge, *, credential: Any,
                          credentials: Mapping[str, Mapping[str, Any]], vault_id: str,
                          security_epoch: int, policy_revision: int) -> OpaqueAuthorization:
        if challenge.registration or not (secrets.compare_digest(challenge.vault_id, vault_id)
                                          and challenge.security_epoch == security_epoch
                                          and challenge.policy_revision == policy_revision):
            raise AuthorizationError("security state changed")
        records = _records(credentials)
        checked = _credential_shape(credential, registration=False)
        credential_id = checked["id"]
        try:
            record = records[credential_id]
        except KeyError as exc:
            raise AuthorizationError("credential is not authorized") from exc
        supplied_handle = checked["response"]["userHandle"]
        if supplied_handle is not None and not secrets.compare_digest(supplied_handle, record["user_handle"]):
            raise AuthorizationError("credential user handle is invalid")
        try:
            # Synced passkeys legitimately report zero or non-increasing counters.
            # The ceremony nonce remains the replay defence, so clone heuristics do
            # not turn a valid owner operation into an automatic hard failure.
            verified = verify_authentication_response(
                credential=checked, expected_challenge=challenge.nonce,
                expected_rp_id=self.rp_id, expected_origin=self.trusted_origin,
                credential_public_key=base64url_to_bytes(record["public_key"]),
                credential_current_sign_count=0,
                require_user_verification=True,
            )
        except Exception as exc:
            raise AuthorizationError("assertion verification failed") from exc
        if not verified.user_verified:
            raise AuthorizationError("assertion verification failed")
        return OpaqueAuthorization(
            challenge.operation, copy.deepcopy(challenge.payload), challenge.vault_id,
            challenge.security_epoch, challenge.policy_revision,
        )
