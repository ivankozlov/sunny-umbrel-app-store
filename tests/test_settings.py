from __future__ import annotations

import base64
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sunny_digest.models import DialogCandidate, PeerSpec, validate_chat_title
from sunny_digest.settings import (
    CONSENT_SCOPE,
    SETTINGS_SCHEMA,
    consent_active,
    load_settings,
    normalize_known_host,
    validate_configure,
)
from sunny_digest.storage import Paths, atomic_write_bytes, atomic_write_json


NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def public_blob() -> str:
    key_type = b"ssh-ed25519"
    blob = len(key_type).to_bytes(4, "big") + key_type + (32).to_bytes(
        4, "big") + b"x" * 32
    return base64.b64encode(blob).decode("ascii")


def configure(*, user="root", expires="2026-08-05T00:00:00Z"):
    return {
        "telegram_api_id": "12345",
        "telegram_api_hash": "a" * 32,
        "vpn_subscription_url": "https://subscription.example/client?token=test",
        "openrouter_api_key": "sk-or-test-secret",
        "openrouter_model": "anthropic/example",
        "upload_host": "receiver.example",
        "upload_port": "22",
        "upload_user": user,
        "known_host": f"receiver.example ssh-ed25519 {public_blob()}",
        "consent_expires_at": expires,
        "vpn_subscription_url": "https://subscription.example/client?token=secret",
    }


class SettingsTests(unittest.TestCase):
    def test_dialog_candidate_binds_group_chat_id_and_rejects_bidi_title(self):
        candidate = DialogCandidate.from_private_dict({
            "chat_id": -1_000_000_000_123,
            "title": "Pilot group",
            "peer": PeerSpec("channel", 123, 9).as_dict(),
        })
        self.assertEqual(candidate.peer.telegram_chat_id(), candidate.chat_id)
        for invalid in (
            {**candidate.as_private_dict(), "chat_id": -123},
            {**candidate.as_private_dict(), "title": "Pilot\u202egroup"},
        ):
            with self.assertRaises(ValueError):
                DialogCandidate.from_private_dict(invalid)

    def test_known_host_requires_exact_host_and_ed25519_wire_blob(self):
        line = f"receiver.example ssh-ed25519 {public_blob()}"
        self.assertEqual(normalize_known_host(line, "receiver.example", 22),
                         (line + "\n").encode("ascii"))
        with self.assertRaises(ValueError):
            normalize_known_host(line, "other.example", 22)
        invalid = "receiver.example ssh-ed25519 " + base64.b64encode(
            b"x" * 51).decode("ascii")
        with self.assertRaises(ValueError):
            normalize_known_host(invalid, "receiver.example", 22)

    def test_receiver_login_is_fixed_to_root(self):
        settings, credentials, _known_host, subscription_url = validate_configure(
            configure(), NOW)
        self.assertNotIn("vpn", settings)
        self.assertNotIn("vpn", credentials)
        self.assertEqual(
            subscription_url,
            "https://subscription.example/client?token=secret",
        )
        with self.assertRaisesRegex(ValueError, "root forced-command"):
            validate_configure(configure(user="sunny-digest"), NOW)

    def test_subscription_url_is_required_but_never_enters_persisted_values(self):
        missing = configure()
        del missing["vpn_subscription_url"]
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            validate_configure(missing, NOW)

        secret = "never-persist-this-bearer"
        value = configure()
        value["vpn_subscription_url"] = (
            f"https://subscription.example/client?token={secret}")
        settings, credentials, known_host, returned = validate_configure(value, NOW)
        persisted = repr((settings, credentials, known_host))
        self.assertNotIn(secret, persisted)
        self.assertIn(secret, returned)

    def test_consent_bounds_are_inclusive(self):
        exact_hour = (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        exact_ninety = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
        validate_configure(configure(expires=exact_hour), NOW)
        validate_configure(configure(expires=exact_ninety), NOW)
        too_soon = (NOW + timedelta(hours=1, seconds=-1)).isoformat().replace(
            "+00:00", "Z")
        too_late = (NOW + timedelta(days=90, seconds=1)).isoformat().replace(
            "+00:00", "Z")
        with self.assertRaises(ValueError):
            validate_configure(configure(expires=too_soon), NOW)
        with self.assertRaises(ValueError):
            validate_configure(configure(expires=too_late), NOW)


class TestBugConsentInterval20260810(unittest.TestCase):
    """Consent is active only inside its bounded half-open interval."""

    def test_consent_active_is_half_open_interval(self):
        granted = NOW
        expires = NOW + timedelta(hours=1)
        settings = {
            "consent": {
                "scope": CONSENT_SCOPE,
                "granted_at": granted.isoformat().replace("+00:00", "Z"),
                "expires_at": expires.isoformat().replace("+00:00", "Z"),
            },
        }
        self.assertFalse(consent_active(settings, granted - timedelta(seconds=1)))
        self.assertTrue(consent_active(settings, granted))
        self.assertTrue(consent_active(settings, expires - timedelta(microseconds=1)))
        self.assertFalse(consent_active(settings, expires))

    def test_load_settings_rejects_consent_interval_over_ninety_days(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(
                root / "config", root / "private", root / "runtime",
                root / "runtime" / "control.sock",
            )
            paths.ensure()
            atomic_write_json(paths.settings, {
                "schema": SETTINGS_SCHEMA,
                "phase": "configured",
                "chat_locked": False,
                "openrouter_model": "anthropic/example",
                "upload": {"host": "receiver.example", "port": 22, "user": "root"},
                "consent": {
                    "scope": CONSENT_SCOPE,
                    "granted_at": NOW.isoformat().replace("+00:00", "Z"),
                    "expires_at": (
                        NOW + timedelta(days=90, seconds=1)
                    ).isoformat().replace("+00:00", "Z"),
                },
            })
            with self.assertRaisesRegex(ValueError, "consent interval"):
                load_settings(paths)


class LockedChatsV2Tests(unittest.TestCase):
    def _locked(self, paths, chats):
        atomic_write_json(paths.settings, {
            "schema": SETTINGS_SCHEMA,
            "phase": "chat_locked",
            "chat_locked": True,
            "openrouter_model": "anthropic/example",
            "upload": {"host": "receiver.example", "port": 22, "user": "root"},
            "consent": {
                "scope": CONSENT_SCOPE,
                "granted_at": NOW.isoformat().replace("+00:00", "Z"),
                "expires_at": (NOW + timedelta(days=1)).isoformat().replace(
                    "+00:00", "Z"),
            },
            "source_id": "12345678-1234-4678-9234-567812345678",
            "chats": chats,
            "upload_public_key": "ssh-ed25519 AAAAtest source",
            "upload_key_fingerprint": "SHA256:test",
        })
        (paths.chat_locked).write_bytes(b"locked\n")

    def test_v2_locked_settings_accept_sorted_unique_group_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            paths.ensure()
            chats = [
                {"chat_id": -1_000_000_000_124, "title": "A",
                 "peer": PeerSpec("channel", 124, 9).as_dict(),
                 "initial_message_id": 0},
                {"chat_id": -123, "title": "B",
                 "peer": PeerSpec("chat", 123, None).as_dict(),
                 "initial_message_id": 0},
            ]
            self._locked(paths, chats)
            self.assertEqual(load_settings(paths)["chats"], chats)

    def test_v2_locked_settings_reject_invalid_chat_sets_and_v1(self):
        base = {"chat_id": -123, "title": "B",
                "peer": PeerSpec("chat", 123, None).as_dict(),
                "initial_message_id": 0}
        invalid_sets = (
            [],
            [base, dict(base)],
            [dict(base, initial_message_id=1)],
            [dict(base, chat_id=-124)],
            [dict(base, chat_id=1)],
            [dict(base, title="bad\u202etitle")],
            [dict(base, title="bad\ntitle")],
            [dict(base, title="😀" * 81)],
            [dict(base, chat_id=-(index + 1),
                  peer=PeerSpec("chat", index + 1, None).as_dict())
             for index in reversed(range(17))],
        )
        for chats in invalid_sets:
            with self.subTest(chats=len(chats)):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    paths = Paths(root / "config", root / "private", root / "runtime",
                                  root / "runtime" / "control.sock")
                    paths.ensure()
                    self._locked(paths, chats)
                    with self.assertRaises(ValueError):
                        load_settings(paths)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            paths.ensure()
            self._locked(paths, [base])
            value = __import__("json").loads(paths.settings.read_text())
            value["schema"] = "sunny.personal-digest-settings.v1"
            atomic_write_json(paths.settings, value)
            with self.assertRaisesRegex(ValueError, "schema"):
                load_settings(paths)

    def test_chat_title_rejects_lone_surrogate(self):
        with self.assertRaises(ValueError):
            validate_chat_title("\ud800")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = Paths(root / "config", root / "private", root / "runtime",
                          root / "runtime" / "control.sock")
            paths.ensure()
            self._locked(paths, [{
                "chat_id": -123,
                "title": "B",
                "peer": PeerSpec("chat", 123, None).as_dict(),
                "initial_message_id": 0,
            }])
            tampered = paths.settings.read_bytes().replace(
                b'"title":"B"', b'"title":"\\ud800"')
            atomic_write_bytes(paths.settings, tampered)
            with self.assertRaises(ValueError):
                load_settings(paths)


if __name__ == "__main__":
    unittest.main()
