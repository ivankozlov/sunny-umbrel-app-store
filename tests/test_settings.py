from __future__ import annotations

import base64
import unittest
from datetime import datetime, timedelta, timezone

from sunny_digest.models import DialogCandidate, PeerSpec
from sunny_digest.settings import normalize_known_host, validate_configure


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
        "openrouter_api_key": "sk-or-test-secret",
        "openrouter_model": "anthropic/example",
        "upload_host": "receiver.example",
        "upload_port": "22",
        "upload_user": user,
        "known_host": f"receiver.example ssh-ed25519 {public_blob()}",
        "consent_expires_at": expires,
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
        validate_configure(configure(), NOW)
        with self.assertRaisesRegex(ValueError, "root forced-command"):
            validate_configure(configure(user="sunny-digest"), NOW)

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


if __name__ == "__main__":
    unittest.main()
