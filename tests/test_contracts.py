from __future__ import annotations

import asyncio
import email.message
import io
import ssl
import json
import os
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sunny_digest.contracts import (
    build_digest_upload,
    build_monitor_upload,
    canonical_digest_bytes,
    canonical_monitor_bytes,
    content_hash,
    mention_event_id,
    status_request,
    validate_digest_upload,
    validate_gate,
    validate_monitor_upload,
)
from sunny_digest.models import DigestChat, SelectedMessage
from sunny_digest.storage import canonical_json_bytes
from sunny_digest.openrouter import (
    FALLBACK_MODEL,
    render_digest,
    HTTP_TIMEOUT_S,
    WORKER_TIMEOUT_S,
    FALLBACK_PROVIDERS,
    OPENROUTER_URL,
    WORKER_FAILURE_EXIT,
    WORKER_SCHEMA,
    OpenRouterError,
    failure_label,
    sanitize_failure,
    _blocking_digest,
    _prompt,
    blocking_fetch_response,
    create_digest,
)
from sunny_digest.prompting import (
    DIGEST_TARGET_UTF16_UNITS,
    DIGEST_TRUNCATION_NOTE,
    PROMPT_PREFIX_BYTES,
    digest_sources,
    prompt_size,
    render_digest_prompt,
)
from sunny_digest.version import (
    MAX_DIGEST_CHARS,
    MAX_PROMPT_BYTES,
    PROMPT_VERSION,
)


SOURCE_ID = "12345678-1234-4678-9234-567812345678"
CHAT_IDS = [-1_000_000_000_124, -1_000_000_000_123]
NOW = datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc)


def gate(*, monitor_sequence: int = 1, monitor_previous=None,
         monitor_cursors=(0, 0), baseline_required: bool = True,
         digest_sequence: int = 1, digest_previous=None,
         digest_cursors=(0, 0), due: bool = True):
    return {
        "schema": "sunny.personal-chats.status-gate.v2",
        "ok": True,
        "server_time": "2026-08-04T00:30:00Z",
        "timezone": "Europe/Istanbul",
        "monitor": {
            "baseline_required": baseline_required,
            "next_sequence": monitor_sequence,
            "previous_sha256": monitor_previous,
            "cursors": [
                {"chat_id": chat_id, "through_message_id": cursor}
                for chat_id, cursor in zip(CHAT_IDS, monitor_cursors)
            ],
            "max_upload_bytes": 32768,
        },
        "digest": {
            "due": due,
            "reason": "due" if due else "before_window",
            "digest_date": "2026-08-04",
            "prepare_not_before": "2026-08-04T03:00:00+03:00",
            "accept_until": "2026-08-04T04:45:00+03:00",
            "next_sequence": digest_sequence,
            "previous_sha256": digest_previous,
            "cursors": [
                {"chat_id": chat_id, "through_message_id": cursor}
                for chat_id, cursor in zip(CHAT_IDS, digest_cursors)
            ],
            "max_upload_bytes": 32768,
        },
    }


def event(chat_id=CHAT_IDS[0], message_id=11):
    return {
        "event_id": mention_event_id(SOURCE_ID, chat_id, message_id),
        "message_id": message_id,
        "date": "2026-08-04T00:29:00Z",
        "chat_title": "Рабочий чат",
        "sender": "Иван",
        "snippet": "@ivan посмотри, пожалуйста",
        "link": f"https://t.me/c/{abs(chat_id) - 1_000_000_000_000}/{message_id}",
    }


class FakeResponse:
    """Ответ модели в формате v3: текст выпуска собирает код, не модель."""

    def __init__(self, digest: str = "Готово", *, content=None, usage=None):
        if content is None:
            content = {"chats": [{
                "chat": "Чат",
                "topics": [{"title": "Тема", "summary": digest, "refs": []}],
                "links": [],
            }]}
        body = {
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps(content)},
            }]
        }
        if usage is not None:
            body["usage"] = usage
        self.raw = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int):
        return self.raw[:limit]


class FakeWorkerStdin:
    def __init__(self):
        self.data = b""

    def write(self, value):
        self.data += value

    async def drain(self):
        return None

    def close(self):
        return None

    async def wait_closed(self):
        return None


class FakeHungWorker:
    def __init__(self):
        self.stdin = FakeWorkerStdin()
        self.stdout = self
        self.returncode = None
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()
        self.terminated = False

    async def read(self, _limit):
        self.started.set()
        await self.stopped.wait()
        return b""

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stopped.set()

    def kill(self):
        self.terminate()

    async def wait(self):
        await self.stopped.wait()
        return self.returncode


class FakeSlowKillWorker(FakeHungWorker):
    def __init__(self):
        super().__init__()
        self.kill_started = asyncio.Event()
        self.allow_kill_exit = asyncio.Event()
        self.killed = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.kill_started.set()

    async def wait(self):
        if self.killed:
            await self.allow_kill_exit.wait()
            self.returncode = -9
            self.stopped.set()
        await self.stopped.wait()
        return self.returncode


class ContractTests(unittest.TestCase):
    def test_status_v2_binds_exact_sorted_chat_set_and_independent_chains(self):
        value = validate_gate(gate(), CHAT_IDS)
        self.assertTrue(value["monitor"]["baseline_required"])
        self.assertEqual(value["digest"]["next_sequence"], 1)
        request = json.loads(status_request(SOURCE_ID, CHAT_IDS))
        self.assertEqual(set(request), {
            "schema", "source_id", "chat_ids", "collector_version",
        })
        self.assertEqual(request["chat_ids"], CHAT_IDS)
        for bad in (list(reversed(CHAT_IDS)), [], CHAT_IDS + [CHAT_IDS[-1]]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    status_request(SOURCE_ID, bad)

    def test_baseline_is_sequence_one_and_covers_every_remote_cursor(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 20 + index}
            for index, chat_id in enumerate(CHAT_IDS)
        ]
        payload = build_monitor_upload(
            source_id=SOURCE_ID, gate=gate(), kind="baseline",
            ranges=ranges, events=[], generated_at=NOW,
        )
        self.assertEqual(set(payload), {
            "schema", "source_id", "sequence", "previous_sha256", "kind",
            "generated_at", "ranges", "events", "collector_version",
            "content_sha256",
        })
        self.assertEqual(validate_monitor_upload(payload), payload)
        self.assertTrue(canonical_monitor_bytes(payload).endswith(b"\n"))
        for invalid_ranges in (ranges[:1], list(reversed(ranges))):
            with self.subTest(invalid_ranges=invalid_ranges):
                with self.assertRaises(ValueError):
                    build_monitor_upload(
                        source_id=SOURCE_ID, gate=gate(), kind="baseline",
                        ranges=invalid_ranges, events=[], generated_at=NOW,
                    )

    def test_mentions_use_remote_cursor_and_exact_stable_event_id_vector(self):
        # This literal pins sha256(f"{source_id}:{chat_id}:{message_id}").
        self.assertEqual(
            mention_event_id(
                "4d3768cd-07cf-4a59-a177-4ae4e0465aab",
                -1_002_234_567_890,
                103,
            ),
            "953dadfa391d0033c3c03e8bf94e8af82988e97946979bab3a937a7f717c1cd6",
        )
        value = gate(
            monitor_sequence=2, monitor_previous="a" * 64,
            monitor_cursors=(5, 8), baseline_required=False,
        )
        payload = build_monitor_upload(
            source_id=SOURCE_ID, gate=value, kind="mentions",
            ranges=[{
                "chat_id": CHAT_IDS[0],
                "from_message_id_exclusive": 5,
                "through_message_id": 11,
            }],
            events=[event()], generated_at=NOW,
        )
        self.assertEqual(validate_monitor_upload(payload), payload)
        self.assertEqual(set(payload["events"][0]), {
            "event_id", "message_id", "date", "chat_title", "sender",
            "snippet", "link",
        })
        self.assertNotIn("chat_id", payload["events"][0])
        self.assertIn("date", payload["events"][0])
        bad = [dict(payload["events"][0], event_id="0" * 64)]
        with self.assertRaisesRegex(ValueError, "event_id"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=payload["ranges"], events=bad, generated_at=NOW,
            )

    def test_mentions_reject_more_than_ten_and_utf16_over_300(self):
        value = gate(
            monitor_sequence=2, monitor_previous="a" * 64,
            monitor_cursors=(5, 8), baseline_required=False,
        )
        events = [event(message_id=message_id) for message_id in range(6, 17)]
        with self.assertRaisesRegex(ValueError, "mentions upload shape"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=[{"chat_id": CHAT_IDS[0], "from_message_id_exclusive": 5,
                         "through_message_id": 16}],
                events=events, generated_at=NOW,
            )
        oversized = event()
        oversized["snippet"] = "😀" * 151
        with self.assertRaisesRegex(ValueError, "snippet"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=[{"chat_id": CHAT_IDS[0], "from_message_id_exclusive": 5,
                         "through_message_id": 11}],
                events=[oversized], generated_at=NOW,
            )

    def test_mentions_require_sorted_events_and_link_bound_to_chat_kind(self):
        value = gate(
            monitor_sequence=2, monitor_previous="a" * 64,
            monitor_cursors=(5, 8), baseline_required=False,
        )
        mention_range = [{"chat_id": CHAT_IDS[0],
                          "from_message_id_exclusive": 5,
                          "through_message_id": 12}]
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=mention_range,
                events=[event(message_id=12), event(message_id=11)],
                generated_at=NOW,
            )
        wrong_link = event(message_id=11)
        wrong_link["link"] = "https://t.me/c/999/11"
        with self.assertRaisesRegex(ValueError, "supergroup chat_id"):
            build_monitor_upload(
                source_id=SOURCE_ID, gate=value, kind="mentions",
                ranges=mention_range, events=[wrong_link], generated_at=NOW,
            )

        legacy = build_monitor_upload(
            source_id=SOURCE_ID, gate=value, kind="mentions",
            ranges=mention_range, events=[event(message_id=11)], generated_at=NOW,
        )
        legacy["ranges"][0]["chat_id"] = -123
        legacy["events"][0].update({
            "event_id": mention_event_id(SOURCE_ID, -123, 11),
            "link": None,
        })
        legacy["content_sha256"] = content_hash({
            key: item for key, item in legacy.items() if key != "content_sha256"
        })
        self.assertEqual(validate_monitor_upload(legacy), legacy)
        legacy["events"][0]["link"] = "https://t.me/c/123/11"
        legacy["content_sha256"] = content_hash({
            key: item for key, item in legacy.items() if key != "content_sha256"
        })
        with self.assertRaisesRegex(ValueError, "legacy group"):
            validate_monitor_upload(legacy)

    def test_digest_requires_complete_sorted_ranges_and_aggregate_count(self):
        ranges = [
            {"chat_id": CHAT_IDS[0], "from_message_id_exclusive": 0,
             "through_message_id": 11, "message_count": 1},
            {"chat_id": CHAT_IDS[1], "from_message_id_exclusive": 0,
             "through_message_id": 20, "message_count": 2},
        ]
        payload = build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="Общий дайджест", model="anthropic/example", generated_at=NOW,
        )
        self.assertEqual(set(payload), {
            "schema", "source_id", "sequence", "previous_sha256",
            "digest_date", "timezone", "generated_at", "cutoff_at",
            "chat_ranges", "total_message_count", "empty", "digest",
            "model", "prompt_version", "collector_version", "content_sha256",
        })
        self.assertTrue(all(set(row) == {
            "chat_id", "from_message_id_exclusive", "through_message_id",
            "message_count",
        } for row in payload["chat_ranges"]))
        self.assertEqual(payload["total_message_count"], 3)
        self.assertEqual(validate_digest_upload(payload), payload)
        self.assertTrue(canonical_digest_bytes(payload).endswith(b"\n"))
        invalid = dict(payload, total_message_count=2)
        with self.assertRaisesRegex(ValueError, "aggregate"):
            validate_digest_upload(invalid)

    def test_digest_usage_is_optional_hashed_and_strict(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 1, "message_count": 1}
            for chat_id in CHAT_IDS
        ]
        usage = {
            "prompt_tokens": 1200,
            "completion_tokens": 340,
            "reasoning_tokens": 210,
            "cost": 0.73,
            "upstream_cost": 0.70,
        }
        payload = build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="Общий дайджест", model="anthropic/example",
            generated_at=NOW, llm_usage=usage,
        )
        self.assertEqual(payload["llm_usage"], usage)
        self.assertEqual(validate_digest_upload(payload), payload)
        broken = dict(payload)
        broken["llm_usage"] = {**usage, "cost": -1}
        broken["content_sha256"] = content_hash({
            key: value for key, value in broken.items()
            if key != "content_sha256"
        })
        with self.assertRaisesRegex(ValueError, "llm_usage cost"):
            validate_digest_upload(broken)

    def test_openrouter_usage_is_sanitized_without_response_content(self):
        provider_usage = {
            "prompt_tokens": 1200,
            "completion_tokens": 340,
            "completion_tokens_details": {"reasoning_tokens": 210},
            "cost": 0.73,
            "cost_details": {"upstream_inference_cost": 0.70},
            "provider_specific_secret": "must-not-cross-worker-boundary",
        }
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse(
                content={"chats": []}, usage=provider_usage)):
            response = blocking_fetch_response(
                "bounded prompt", "anthropic/example", "secret")
        self.assertEqual(response["usage"], {
            "prompt_tokens": 1200,
            "completion_tokens": 340,
            "reasoning_tokens": 210,
            "cost": 0.73,
            "upstream_cost": 0.70,
        })

    def test_opus_55_request_omits_sampling_but_keeps_required_contract(self):
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse(
                content={"chats": []})) as opened:
            blocking_fetch_response(
                "bounded prompt", "anthropic/claude-opus-5.5", "secret")
        request = opened.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["model"], "anthropic/claude-opus-5.5")
        self.assertNotIn("temperature", payload)
        self.assertEqual(payload["provider"], {
            "zdr": True,
            "data_collection": "deny",
        })
        self.assertEqual(payload["max_tokens"], 32_768)
        self.assertEqual(payload["response_format"], {"type": "json_object"})

        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse(
                content={"chats": []})) as opened:
            blocking_fetch_response("bounded prompt", "anthropic/example", "secret")
        previous_route = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(previous_route["temperature"], 0)

    def test_digest_boundary_counts_telegram_utf16_units(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 1, "message_count": 1}
            for chat_id in CHAT_IDS
        ]
        accepted = build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="😀" * (MAX_DIGEST_CHARS // 2),
            model="anthropic/example", generated_at=NOW,
        )
        self.assertEqual(len(accepted["digest"].encode("utf-16-le")) // 2,
                         MAX_DIGEST_CHARS)
        with self.assertRaises(ValueError):
            build_digest_upload(
                source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
                digest="😀" * (MAX_DIGEST_CHARS // 2 + 1),
                model="anthropic/example", generated_at=NOW,
            )

    def test_generated_at_hard_limit_is_one_receiver_clock_hour(self):
        ranges = [
            {"chat_id": chat_id, "from_message_id_exclusive": 0,
             "through_message_id": 1, "message_count": 1}
            for chat_id in CHAT_IDS
        ]
        build_digest_upload(
            source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
            digest="Готово", model="anthropic/example",
            generated_at=NOW + timedelta(hours=1),
        )
        with self.assertRaisesRegex(ValueError, "timestamp order"):
            build_digest_upload(
                source_id=SOURCE_ID, gate=gate(), chat_ranges=ranges,
                digest="Опоздало", model="anthropic/example",
                generated_at=NOW + timedelta(hours=1, seconds=1),
            )

    def test_openrouter_digest_never_exceeds_the_shared_boundary(self):
        self.assertIn(str(DIGEST_TARGET_UTF16_UNITS), _prompt([]))
        self.assertIn(PROMPT_VERSION, _prompt([]))
        # Тем много, каждая обрезана по отдельности, а их сумма ничем не
        # ограничена — выпуск обязан быть срезан, а не отвергнут целиком.
        oversized = {"chats": [{
            "chat": "Чат",
            "topics": [
                {"title": f"Тема {i}", "summary": "и" * 3000, "refs": []}
                for i in range(10)
            ],
            "links": [],
        }]}
        with patch("urllib.request.OpenerDirector.open",
                   return_value=FakeResponse(content=oversized)):
            digest = _blocking_digest([], "anthropic/example", "secret")
        self.assertLessEqual(
            len(digest.encode("utf-16-le")) // 2, MAX_DIGEST_CHARS)
        self.assertTrue(digest.endswith(DIGEST_TRUNCATION_NOTE.strip()))
        with patch("urllib.request.OpenerDirector.open",
                   return_value=FakeResponse("unsafe\u2066text")):
            with self.assertRaises(OpenRouterError):
                _blocking_digest([], "anthropic/example", "secret")

    def test_openrouter_prompt_pseudonymizes_stable_telegram_ids(self):
        rendered = _prompt([DigestChat("Первый чат", [
            SelectedMessage(987654321, 8675309, NOW, "Первое сообщение"),
            SelectedMessage(987654322, 8675309, NOW, "Второе сообщение"),
            SelectedMessage(987654323, 42424242, NOW, "Третье сообщение"),
        ])])
        self.assertIn('"sender":"participant-1"', rendered)
        self.assertIn('"sender":"participant-2"', rendered)
        for stable_id in ("987654321", "8675309", "42424242"):
            self.assertNotIn(stable_id, rendered)


class TestBugDigestLinks20260818(unittest.TestCase):
    """Ссылки на сообщения собирает код, а не модель.

    Модель видит только порядковые номера: стабильные Telegram-идентификаторы
    не покидают Umbrel, а выдуманная моделью ссылка не может дойти до Ивана —
    номер вне карты источников молча отбрасывается."""

    CHATS = [
        DigestChat("Первый чат", [
            SelectedMessage(41, 7, NOW, "Первое"),
            SelectedMessage(42, 8, NOW, "Второе"),
        ], "https://t.me/c/1234567890"),
        DigestChat("Второй чат", [
            SelectedMessage(77, 9, NOW, "Третье"),
        ], None),
    ]

    def test_numbering_matches_prompt_order(self):
        rendered = _prompt(self.CHATS)
        self.assertIn('"n":1', rendered)
        self.assertIn('"n":3', rendered)
        # Голыми подстроками, а не JSON-формой ключа: поле `link_prefix`
        # теперь едет вместе с DigestChat, и «полезная» строка вида
        # "link": "<prefix>/<id>" не должна пройти незамеченной ни в каком
        # написании.
        for secret in ("1234567890", "41", "42", "77"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(digest_sources(self.CHATS), {
            1: "https://t.me/c/1234567890/41",
            2: "https://t.me/c/1234567890/42",
        })

    def test_refs_become_links_and_unknown_numbers_are_dropped(self):
        content = {"chats": [{
            "chat": "Первый чат",
            "topics": [{"title": "Тема", "summary": "Суть", "refs": [2, 3, 99]}],
            "links": [{"title": "Статья", "note": "зачем", "ref": 1}],
        }]}
        with patch("urllib.request.OpenerDirector.open",
                   return_value=FakeResponse(content=content)):
            digest = _blocking_digest(
                self.CHATS, "anthropic/example", "secret")
        self.assertIn("https://t.me/c/1234567890/42", digest)
        self.assertIn("https://t.me/c/1234567890/41", digest)
        # 3 — сообщение чата без префикса, 99 — вымысел модели.
        self.assertEqual(digest.count("https://t.me/c/"), 2)
        self.assertIn("Статья", digest)

    def test_unexpected_response_shape_is_rejected(self):
        for content in ({"digest": "старый формат"},
                        {"chats": "не список"},
                        {"chats": [{"chat": "Ч", "topics": [42], "links": []}]}):
            with patch("urllib.request.OpenerDirector.open",
                       return_value=FakeResponse(content=content)):
                with self.assertRaises(OpenRouterError):
                    _blocking_digest(self.CHATS, "anthropic/example", "secret")


class TestBugOpenRouterPrivacy20260810(unittest.TestCase):
    def test_every_request_denies_collection_and_requires_zdr(self):
        with patch("urllib.request.OpenerDirector.open",
                   return_value=FakeResponse("Готово")) as urlopen:
            _blocking_digest([], "anthropic/example", "secret")
        request = urlopen.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(body["provider"], {"zdr": True, "data_collection": "deny"})
        self.assertEqual(request.get_header("User-agent"),
                         "sunny-personal-chats/0.2")
        self.assertEqual(request.get_header("X-title"), "Sunny Personal Chats")


class TestBugOpenRouterEgress20260818(unittest.TestCase):
    """Инциденты 2026-08-17/18: запрос к OpenRouter не проходил ничем.

    Прямой путь из домашней сети отбивал фильтр (`Access denied by security
    policy`), а через VLESS-туннель Cloudflare отвечал 403 с любого из трёх
    узлов — при том, что с самих узлов и с DO тот же запрос проходил. Поэтому
    соединение идёт ssh-форвардом до DO, и только им."""

    def _sent_connection(self):
        """Прогон по настоящему opener'у: подменяется только сокетный слой."""
        made = {}

        class FakeSocket:
            """Достаточно, чтобы http.client дошёл до отправки и оборвался."""

            def __init__(self, hostname):
                made["server_hostname"] = hostname

            def sendall(self, *_a, **_kw):
                return None

            def settimeout(self, *_a, **_kw):
                return None

            def close(self, *_a, **_kw):
                return None

            def makefile(self, *_a, **_kw):
                return io.BytesIO(b"")

        def fake_wrap(_self, sock, server_hostname=None, **_kw):
            made["wrapped"] = sock
            made["context"] = _self
            return FakeSocket(server_hostname)

        def fake_create_connection(address, *_a, **_kw):
            made["address"] = address
            return object()

        with patch("socket.create_connection", fake_create_connection), \
                patch("ssl.SSLContext.wrap_socket", fake_wrap):
            try:
                _blocking_digest([], "anthropic/example", "secret")
            except OpenRouterError:
                pass  # ответ не эмулируем — проверяется сам маршрут
        return made

    def test_connects_to_local_tunnel_end_not_to_openrouter_directly(self):
        from sunny_digest.openrouter_tunnel import TUNNEL_HOST, TUNNEL_PORT

        made = self._sent_connection()
        self.assertEqual(made.get("address"), (TUNNEL_HOST, TUNNEL_PORT))

    def test_tls_is_verified_against_openrouter_not_against_loopback(self):
        """Проверять сертификат против 127.0.0.1 нельзя: тогда любой, кто занял
        локальный порт, получил бы и запрос, и bearer-ключ."""
        made = self._sent_connection()
        self.assertEqual(made.get("server_hostname"), "openrouter.ai")
        # одного имени мало: снятая верификация прошла бы этот тест зелёной
        context = made.get("context")
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_redirects_are_refused_so_the_key_cannot_leave_the_tunnel(self):
        from sunny_digest.openrouter import _RefuseRedirects

        self.assertIsNone(_RefuseRedirects().redirect_request(
            None, None, 302, "Found", {}, "http://openrouter.ai/v1/x"))


class TestBugOpusDigestBudget20260814(unittest.TestCase):
    """Opus reasoning must not consume the whole bounded response budget."""

    def test_opus_request_has_explicit_reasoning_safe_output_budget(self):
        with patch("urllib.request.OpenerDirector.open",
                   return_value=FakeResponse("Готово")) as urlopen:
            _blocking_digest([], "anthropic/claude-opus-5.5", "secret")

        body = json.loads(urlopen.call_args.args[0].data)
        self.assertGreaterEqual(body["max_tokens"], 16_384)


class FakeAnsweringWorker(FakeHungWorker):
    """Воркер, отвечающий ровно так, как настоящий: структурой, не текстом."""

    def __init__(self, answer, usage=None):
        super().__init__()
        response = {"answer": answer}
        if usage is not None:
            response["usage"] = usage
        self.raw = canonical_json_bytes(response) + b"\n"
        self.sent = False

    async def read(self, _limit):
        self.started.set()
        if self.sent:
            return b""
        self.sent = True
        self.returncode = 0
        self.stopped.set()
        return self.raw

    async def wait(self):
        self.returncode = 0
        return 0


class TestBugDigestLinksProductionPath20260818(unittest.IsolatedAsyncioTestCase):
    """Ссылки обязаны появляться на ПРОДАКШН-пути, а не только в юнит-хелпере.

    Запрос уходит в killable подпроцесс (`create_digest` → `openrouter_worker`),
    и карта «номер → сообщение» живёт только в родителе. Первая версия этой
    миграции собирала текст внутри воркера, где карты нет: все ссылки молча
    исчезали, а тест на `_blocking_digest` оставался зелёным."""

    CHATS = [DigestChat("Рабочий чат", [
        SelectedMessage(41, 7, NOW, "Первое", "Алиса"),
        SelectedMessage(42, 8, NOW, "Второе", "Боб"),
    ], "https://t.me/c/1234567890")]

    async def test_links_survive_the_worker_boundary(self):
        answer = {"chats": [{
            "chat": "Рабочий чат",
            "topics": [{
                "title": "Тема participant-2",
                "summary": "participant-1 предложила решение",
                "refs": [2],
            }],
            "links": [{
                "title": "Статья participant-1",
                "note": "participant-2 советует прочитать",
                "ref": 1,
            }],
        }]}
        worker = FakeAnsweringWorker(answer)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(
                self.CHATS, "anthropic/example", "sk-or-test-secret",
                asyncio.Event())
        self.assertIn("https://t.me/c/1234567890/42", digest)
        self.assertIn("https://t.me/c/1234567890/41", digest)
        # Воркер не получает ни идентификаторов сообщений, ни префикса:
        # ему уходит только промпт с порядковыми номерами.
        request = json.loads(worker.stdin.data)
        self.assertEqual(set(request), {"schema", "prompt", "model", "api_key"})
        for secret in ("1234567890", "41", "42"):
            self.assertNotIn(secret, request["prompt"])
        for name in ("Алиса", "Боб"):
            self.assertIn(name, digest)
            self.assertNotIn(name, request["prompt"])
        self.assertNotIn("participant-1", digest)
        self.assertNotIn("participant-2", digest)

    async def test_ambiguous_or_unknown_sender_stays_pseudonymous(self):
        chats = [DigestChat("Рабочий чат", [
            SelectedMessage(41, 7, NOW, "Первое", "Алиса"),
            SelectedMessage(42, 7, NOW, "Второе", "Боб"),
            SelectedMessage(43, 8, NOW, "Третье"),
        ])]
        answer = {"chats": [{
            "chat": "Рабочий чат",
            "topics": [{
                "title": "Тема",
                "summary": "participant-1 и participant-2 обсудили вопрос",
                "refs": [],
            }],
            "links": [],
        }]}
        worker = FakeAnsweringWorker(answer)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(
                chats, "anthropic/example", "sk-or-test-secret",
                asyncio.Event())
        self.assertIn("participant-1", digest)
        self.assertIn("participant-2", digest)

    async def test_usage_survives_the_killable_worker_boundary(self):
        usage = {
            "prompt_tokens": 1200,
            "completion_tokens": 340,
            "reasoning_tokens": 210,
            "cost": 0.73,
            "upstream_cost": 0.70,
        }
        answer = {"chats": [{
            "chat": "Рабочий чат",
            "topics": [{"title": "Тема", "summary": "Суть", "refs": []}],
            "links": [],
        }]}
        worker = FakeAnsweringWorker(answer, usage)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(
                self.CHATS, "anthropic/example", "sk-or-test-secret",
                asyncio.Event())
        self.assertEqual(digest.llm_usage, usage)


class TestBugDigestSenderCase20260914(unittest.IsolatedAsyncioTestCase):
    """238: выпуск 04.09 сохранил Participant-N из-за заглавной P."""

    async def test_names_are_restored_in_all_fields_and_stay_in_their_chat(self):
        chats = [
            DigestChat("Первый", [SelectedMessage(41, 7, NOW, "Текст", "Алиса")]),
            DigestChat("Второй", [SelectedMessage(42, 8, NOW, "Текст", "Боб")]),
        ]
        answer = {"chats": [{"chat": chat.title, "topics": [{
            "title": "Participant-1: решение",
            "summary": "PARTICIPANT-1 предложил, participant-1 поддержал",
            "refs": [],
        }], "links": [{"title": "Participant-1", "note": "PARTICIPANT-1", "ref": 1}]}
            for chat in chats]}
        worker = FakeAnsweringWorker(answer)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(chats, "anthropic/example", "test-key",
                                         asyncio.Event())
        first, second = digest.split("**Второй**")
        self.assertEqual(first.count("Алиса"), 5)
        self.assertEqual(second.count("Боб"), 5)
        self.assertNotIn("Боб", first)
        self.assertNotIn("Алиса", second)
        self.assertNotIn("participant-", digest.lower())

    def test_unknown_ambiguous_and_partial_aliases_are_not_guessed(self):
        from sunny_digest.openrouter import _restore_sender_names
        names = {"participant-1": "Алиса"}
        text = "Participant-10 Participant-99 xParticipant-1 Participant-1-x"
        self.assertEqual(_restore_sender_names(text, names), text)
        self.assertEqual(_restore_sender_names("Participant-1", {}), "Participant-1")


class TestBugDigestTopicSource20260918(unittest.TestCase):
    """238: одна ранняя source-ссылка; bool и материал без permalink не мешают."""

    def test_earliest_source_and_material_after_fifth_ref_are_preserved(self):
        from sunny_digest.openrouter import render_digest
        sources = {n: f"https://t.me/c/123/{100+n}" for n in range(1, 7)}
        answer = {"chats": [{"chat": "Тест", "topics": [{
            "title": "Тема", "summary": "Суть", "refs": [6, 5, 4, 3, 2, 1],
            "materials": [{"n": 1, "i": 1}, {"n": 6, "i": 1}],
        }], "links": []}]}
        text = render_digest(answer, sources, material_urls={
            1: ["https://example.org/earliest"],
            6: ["https://example.org/latest"],
        })
        self.assertEqual(text.count(sources[1]), 1)
        for n in range(2, 7):
            self.assertNotIn(sources[n], text)
        self.assertIn("https://example.org/earliest", text)
        self.assertIn("https://example.org/latest", text)

    def test_earliest_available_permalink_and_material_deduplication(self):
        from sunny_digest.openrouter import render_digest
        sources = {1: "https://t.me/c/123/101", 3: "https://t.me/c/123/103",
                   4: "https://t.me/c/123/104"}
        materials = {2: ["https://example.org/a"],
                     4: ["https://example.org/a", "https://example.org/b"]}
        answer = {"chats": [{"chat": "Тест", "topics": [{
            "title": "Тема", "summary": "Суть", "refs": [True, 2, "4", 3, "oops"],
            "materials": [{"n": 2, "i": 1}, {"n": 4, "i": 2}, {"n": 4, "i": 1}],
        }], "links": []}]}
        text = render_digest(answer, sources, material_urls=materials)
        self.assertEqual(text.count("https://t.me/c/123/103"), 1)
        self.assertNotIn(sources[1], text)
        self.assertNotIn(sources[4], text)
        self.assertEqual(text.count("https://example.org/a"), 1)
        self.assertEqual(text.count("https://example.org/b"), 1)


class TestBugDigestMaterialLinksProductionPath20260914(unittest.IsolatedAsyncioTestCase):
    """235: родитель подставляет исходные URL после ответа killable worker."""

    async def test_topic_keeps_earliest_source_and_all_materials_from_unordered_refs(self):
        chats = [DigestChat("TNN", [
            SelectedMessage(100, 7, NOW, "Раннее сообщение"),
            SelectedMessage(101, 8, NOW, "Первый материал", material_urls=(
                "https://example.org/first",)),
            SelectedMessage(102, 9, NOW, "Второй материал", material_urls=(
                "https://t.me/other_channel/77",)),
        ], "https://t.me/c/9876543210")]
        answer = {"chats": [{"chat": "TNN", "topics": [{
            "title": "Тема", "summary": "Суть", "refs": [3, "1", 2],
            "materials": [{"n": 2, "i": 1}, {"n": 3, "i": 1}],
        }], "links": []}]}
        worker = FakeAnsweringWorker(answer)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(chats, "anthropic/example", "test-key",
                                         asyncio.Event())
        self.assertIn("https://example.org/first", digest)
        self.assertIn("https://t.me/other_channel/77", digest)
        self.assertEqual(digest.count("https://t.me/c/9876543210/100"), 1)
        self.assertIn('[Сообщение](https://t.me/c/9876543210/100)', digest)
        self.assertNotIn('[Сообщение](https://t.me/other_channel/77)', digest)
        self.assertNotIn("https://t.me/c/9876543210/101", digest)
        self.assertNotIn("https://t.me/c/9876543210/102", digest)

    async def test_materials_survive_worker_boundary_in_topics_and_links(self):
        chats = [
            DigestChat("Первый", [SelectedMessage(90, 7, NOW, "Привет")]),
            DigestChat("TNN", [SelectedMessage(
                91, 8, NOW, "Обсудили статью и исследование", "Алиса",
                ("https://example.org/article?x=1&y=2", "https://example.net/paper"),
            )], "https://t.me/c/9876543210"),
        ]
        answer = {"chats": [{"chat": "TNN", "topics": [{
            "title": "Исследование", "summary": "participant-1 поделилась статьёй",
            "refs": [2, 2, True, 999],
            "materials": [{"n": 2, "i": 1}, {"n": 2, "i": 2}, {"n": 999, "i": 1}],
        }], "links": [{"title": "Статья", "note": "Разбор", "ref": "2",
                       "materials": [1, "2", 7]}]}]}
        worker = FakeAnsweringWorker(answer)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(chats, "anthropic/example", "test-key",
                                         asyncio.Event())
        topic, materials = digest.split("📎 Ссылки и материалы")
        for section in (topic, materials):
            for url in chats[1].messages[0].material_urls:
                self.assertEqual(section.count(url), 1)
                self.assertLess(section.index(url), section.index("https://t.me/"))
            self.assertEqual(section.count("https://t.me/c/9876543210/91"), 1)
            self.assertIn('[Сообщение](https://t.me/c/9876543210/91)', section)
        self.assertIn("Алиса", digest)
        request = json.loads(worker.stdin.data)
        for local_only in (*chats[1].messages[0].material_urls, "9876543210", "Алиса"):
            self.assertNotIn(local_only, request["prompt"])
        # модели — только номера и подписи; адреса остаются у родителя
        self.assertIn('"materials":[{"i":1,"label":', request["prompt"])
        self.assertIn('{"i":2,"label":', request["prompt"])

    async def test_material_without_telegram_permalink_and_invalid_refs(self):
        url = "https://example.org/paper"
        chats = [DigestChat("TNN", [SelectedMessage(
            91, 8, NOW, "Исследование", material_urls=(url,))])]
        answer = {"chats": [{"chat": "TNN", "topics": [], "links": [
            {"title": "Материал", "ref": 1, "materials": [1]},
            {"title": "Ошибочный номер", "ref": True},
            {"title": "Выдуманный номер", "ref": 999,
             "url": "https://invented.example/paper"},
        ]}]}
        worker = FakeAnsweringWorker(answer)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            digest = await create_digest(chats, "anthropic/example", "test-key",
                                         asyncio.Event())
        self.assertEqual(digest.count(url), 1)
        self.assertNotIn("https://invented.example", digest)
        self.assertNotIn("https://t.me/", digest)


class TestBugPromptBudgetCountsNumber20260818(unittest.TestCase):
    """Бюджет отбора обязан учитывать поле `n`.

    Гейт отбирает сообщения по `prompt_size` для ОДНОГО чата, а собранный
    промпт нумеруется сквозным `n`. Не учтённые в оценке байты вылезали за
    MAX_PROMPT_BYTES уже после отбора — и весь суточный дайджест падал на
    `prompt exceeds bounded input size`, каждый день заново."""

    def test_saturated_selection_still_fits_the_prompt(self):
        for chat_count, text_length in ((7, 40), (2, 120), (16, 40)):
            budget = max(1024, PROMPT_PREFIX_BYTES + (
                MAX_PROMPT_BYTES - PROMPT_PREFIX_BYTES) // chat_count)
            chats, message_id = [], 1
            for index in range(chat_count):
                title = f"Чат {index}"
                selected = []
                while True:
                    candidate = SelectedMessage(
                        message_id, 1, NOW, "я" * text_length)
                    if prompt_size(selected + [candidate], title) > budget:
                        break
                    selected.append(candidate)
                    message_id += 1
                chats.append(DigestChat(title, selected, None))
            rendered = render_digest_prompt(chats)
            self.assertLessEqual(
                len(rendered.encode("utf-8")), MAX_PROMPT_BYTES,
                f"{chat_count} чатов по {text_length} символов")


class OpenRouterProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_revocation_terminates_blocking_openrouter_worker_process(self):
        worker = FakeHungWorker()
        revoked = asyncio.Event()
        messages = [DigestChat("Чат", [SelectedMessage(1, 7, NOW, "Текст")])]
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker) as spawn:
            task = asyncio.create_task(create_digest(
                messages, "anthropic/example", "sk-or-test-secret", revoked))
            await asyncio.wait_for(worker.started.wait(), timeout=2)
            revoked.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
        self.assertTrue(worker.terminated)
        self.assertIn(b"sk-or-test-secret", worker.stdin.data)
        self.assertEqual(
            json.loads(worker.stdin.data)["schema"],
            WORKER_SCHEMA,
        )
        command = " ".join(str(part) for part in spawn.call_args.args)
        self.assertNotIn("sk-or-test-secret", command)
        self.assertNotIn("Текст", command)


class TestBugOpenRouterSecondCancellation20260812(
        unittest.IsolatedAsyncioTestCase):
    """Reset cancellation must not strand a bearer-bearing worker after TERM."""

    async def test_second_cancellation_cannot_interrupt_worker_kill_and_reap(self):
        worker = FakeSlowKillWorker()
        revoked = asyncio.Event()
        messages = [DigestChat("Чат", [SelectedMessage(1, 7, NOW, "Текст")])]
        with patch(
            "sunny_digest.openrouter.asyncio.create_subprocess_exec",
            return_value=worker,
        ), patch(
            "sunny_digest.openrouter.WORKER_TERMINATE_GRACE_S", 0.01,
        ):
            task = asyncio.create_task(create_digest(
                messages, "anthropic/example", "sk-or-test-secret", revoked))
            await worker.started.wait()
            revoked.set()
            while not worker.terminated:
                await asyncio.sleep(0)
            await asyncio.wait_for(worker.kill_started.wait(), timeout=0.5)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            worker.allow_kill_exit.set()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(worker.killed)
        self.assertIsNotNone(worker.returncode)



class FakeRawResponse(FakeResponse):
    """Ответ OpenRouter с произвольным телом — для веток отказа."""

    def __init__(self, body):
        self.raw = (body if isinstance(body, bytes)
                    else json.dumps(body).encode("utf-8"))


class FakeFailingWorker(FakeAnsweringWorker):
    """Воркер, вернувший классифицированный отказ вместо ответа."""

    def __init__(self, raw, returncode=WORKER_FAILURE_EXIT):
        super().__init__({"chats": []})
        self.raw = raw
        self.code = returncode

    async def read(self, limit):
        chunk = await super().read(limit)
        self.returncode = self.code
        return chunk

    async def wait(self):
        self.returncode = self.code
        return self.code


class TestBugDigestFailureDiagnostics20261002(unittest.IsolatedAsyncioTestCase):
    """Отказ выпуска обязан быть различим в статусе.

    02.10.2026 тринадцать попыток подряд дошли до модели и были оплачены,
    но выпуск не собрался, а статус показывал одно `OpenRouterError`:
    воркер на любой ошибке выходил с кодом 1, и HTTP-отказ, отказ модели и
    битая структура были неразличимы. Причину установить не удалось. Код
    отказа несёт только служебные поля — ни текста ответа, ни сообщения
    провайдера, ни промпта."""

    PROMPT_SECRET = "секретный текст переписки"

    def _fetch_failure(self, response):
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaises(OpenRouterError) as caught:
                blocking_fetch_response(
                    self.PROMPT_SECRET, "anthropic/claude-opus-5.5", "secret")
        return caught.exception.failure

    def test_http_error_keeps_status_and_provider_but_not_message(self):
        body = json.dumps({"error": {
            "code": 402, "message": f"echo: {self.PROMPT_SECRET}",
            "metadata": {"provider_name": "Amazon Bedrock",
                         "raw": self.PROMPT_SECRET},
        }}).encode("utf-8")
        error = urllib.error.HTTPError(
            OPENROUTER_URL, 402, "Payment Required",
            email.message.Message(), io.BytesIO(body))
        with patch("urllib.request.OpenerDirector.open", side_effect=error):
            with self.assertRaises(OpenRouterError) as caught:
                blocking_fetch_response(
                    self.PROMPT_SECRET, "anthropic/claude-opus-5.5", "secret")
        failure = caught.exception.failure
        self.assertEqual(failure, {
            "code": "http_error", "http_status": 402,
            "provider": "Amazon Bedrock"})
        self.assertNotIn(self.PROMPT_SECRET, json.dumps(failure, ensure_ascii=False))
        self.assertEqual(failure_label(failure), "http_error:402")

    def test_unfinished_answer_keeps_finish_reasons_and_generation(self):
        failure = self._fetch_failure(FakeRawResponse({
            "id": "gen-1759390000-abcDEF",
            "provider": "Amazon Bedrock",
            "choices": [{
                "finish_reason": "content_filter",
                "native_finish_reason": "refusal",
                "message": {"content": self.PROMPT_SECRET},
            }],
            "usage": {"completion_tokens": 12},
        }))
        self.assertEqual(failure, {
            "code": "finish_reason", "finish_reason": "content_filter",
            "native_finish_reason": "refusal", "provider": "Amazon Bedrock",
            "completion_tokens": 12, "generation_id": "gen-1759390000-abcDEF",
        })
        self.assertEqual(failure_label(failure), "finish_reason:content_filter")

    def test_non_json_answer_and_error_body_are_classified(self):
        failure = self._fetch_failure(FakeRawResponse({
            "id": "gen-x", "choices": [{
                "finish_reason": "stop", "message": {"content": "не JSON"}}],
        }))
        self.assertEqual(failure, {"code": "content_not_json",
                                   "generation_id": "gen-x"})
        failure = self._fetch_failure(FakeRawResponse({"error": {
            "code": 502, "message": self.PROMPT_SECRET,
            "metadata": {"provider_name": "Google"}}}))
        self.assertEqual(failure, {"code": "provider_error",
                                   "http_status": 502, "provider": "Google"})
        failure = self._fetch_failure(FakeRawResponse(b"<html>"))
        self.assertEqual(failure, {"code": "response_invalid"})

    def test_successful_response_carries_only_safe_meta(self):
        with patch("urllib.request.OpenerDirector.open", return_value=FakeRawResponse({
                "id": "gen-ok", "provider": "Amazon Bedrock\nInjected",
                "choices": [{"finish_reason": "stop",
                             "message": {"content": json.dumps({"chats": []})}}],
        })):
            response = blocking_fetch_response(
                "prompt", "anthropic/claude-opus-5.5", "secret")
        # имя провайдера с переводом строки не проходит форму и выпадает
        self.assertEqual(response["meta"], {"generation_id": "gen-ok"})

    def test_sanitizer_drops_unknown_fields_and_bad_values(self):
        self.assertIsNone(sanitize_failure({"code": "made_up"}))
        self.assertIsNone(sanitize_failure("http_error"))
        self.assertEqual(sanitize_failure({
            "code": "http_error", "http_status": True, "message": "text",
            "finish_reason": "<script>", "completion_tokens": -1,
            "generation_id": "gen/../x", "detail": "ok_detail",
        }), {"code": "http_error", "detail": "ok_detail"})

    async def test_worker_failure_crosses_the_boundary_classified(self):
        failure = {"code": "finish_reason", "finish_reason": "length",
                   "completion_tokens": 32768, "generation_id": "gen-w"}
        worker = FakeFailingWorker(
            canonical_json_bytes({"failure": failure}) + b"\n")
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            with self.assertRaises(OpenRouterError) as caught:
                await create_digest(
                    TestBugDigestLinksProductionPath20260818.CHATS,
                    "anthropic/claude-opus-5.5", "sk-or-test-secret",
                    asyncio.Event())
        self.assertEqual(caught.exception.failure,
                         {**failure, "model": "anthropic/claude-opus-5.5"})

    async def test_garbled_or_plain_worker_failure_is_still_classified(self):
        for raw, code, expected in (
                (b"{\"failure\": {\"code\": \"invented\"}}\n",
                 WORKER_FAILURE_EXIT, "worker_response_invalid"),
                (b"", 1, "worker_failed")):
            worker = FakeFailingWorker(raw, returncode=code)
            with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                       return_value=worker):
                with self.assertRaises(OpenRouterError) as caught:
                    await create_digest(
                        TestBugDigestLinksProductionPath20260818.CHATS,
                        "anthropic/claude-opus-5.5", "sk-or-test-secret",
                        asyncio.Event())
            self.assertEqual(caught.exception.failure, {
                "code": expected, "model": "anthropic/claude-opus-5.5"})

    async def test_parent_side_structure_failure_keeps_generation_meta(self):
        worker = FakeAnsweringWorker(
            {"chats": [], "summary": "лишнее поле"},
            usage={"prompt_tokens": 30000, "completion_tokens": 40,
                   "reasoning_tokens": None, "cost": 0.18,
                   "upstream_cost": 0.18})
        response = json.loads(worker.raw)
        response["meta"] = {"generation_id": "gen-p", "provider": "Google"}
        worker.raw = canonical_json_bytes(response) + b"\n"
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            with self.assertRaises(OpenRouterError) as caught:
                await create_digest(
                    TestBugDigestLinksProductionPath20260818.CHATS,
                    "anthropic/claude-opus-5.5", "sk-or-test-secret",
                    asyncio.Event())
        self.assertEqual(caught.exception.failure, {
            "code": "structure_invalid", "detail": "top_fields",
            "completion_tokens": 40, "generation_id": "gen-p",
            "provider": "Google", "model": "anthropic/claude-opus-5.5"})

    async def test_unexpected_render_crash_is_still_classified(self):
        """`"²".isdigit()` истинно, а `int("²")` падает ValueError (ревью
        02.10.2026): такой ref не должен уводить отказ мимо классификации."""
        answer = {"chats": [{"chat": "Рабочий чат", "topics": [
            {"title": "Тема", "summary": "s", "refs": ["²"]}], "links": []}]}
        worker = FakeAnsweringWorker(answer, usage={
            "prompt_tokens": 10, "completion_tokens": 7,
            "reasoning_tokens": None, "cost": 0.1, "upstream_cost": 0.1})
        response = json.loads(worker.raw)
        response["meta"] = {"generation_id": "gen-r"}
        worker.raw = canonical_json_bytes(response) + b"\n"
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            with self.assertRaises(OpenRouterError) as caught:
                await create_digest(
                    TestBugDigestLinksProductionPath20260818.CHATS,
                    "anthropic/claude-opus-5.5", "sk-or-test-secret",
                    asyncio.Event())
        self.assertEqual(caught.exception.failure, {
            "code": "structure_invalid", "detail": "render_error",
            "completion_tokens": 7, "generation_id": "gen-r",
            "model": "anthropic/claude-opus-5.5"})

    def test_real_worker_emits_failure_without_exception_text(self):
        from sunny_digest import openrouter_worker

        request = canonical_json_bytes({
            "schema": WORKER_SCHEMA, "prompt": "prompt",
            "model": "anthropic/claude-opus-5.5",
            "api_key": "sk-or-test-secret-0000",
        }) + b"\n"
        stdout = io.BytesIO()

        def refuse(*_args):
            raise OpenRouterError(
                f"provider said {self.PROMPT_SECRET}", "http_error",
                http_status=429)

        with patch.object(openrouter_worker, "blocking_fetch_response", refuse), \
                patch("sys.stdin", io.TextIOWrapper(io.BytesIO(request))), \
                patch("sys.stdout", io.TextIOWrapper(stdout)):
            code = openrouter_worker.main()
            written = stdout.getvalue()
        self.assertEqual(code, WORKER_FAILURE_EXIT)
        self.assertNotIn(self.PROMPT_SECRET.encode("utf-8"), written)
        self.assertEqual(json.loads(written), {
            "failure": {"code": "http_error", "http_status": 429}})



class TestBugOpusRefusalFallback20261003(unittest.IsolatedAsyncioTestCase):
    """Отказ Opus 5.5 обязан переходить на запасную модель.

    02–03.10.2026 Opus 5.5 26 попыток подряд отвечал `content_filter` /
    `refusal` на одну и ту же переписку (Bedrock, 90 токенов размышления), а
    растянутая ретроспектива держала этот кусок во всех следующих запросах.
    Решение Ивана: при отказе — GLM-5.3, только через американские и
    европейские хосты, с прежними ZDR и data_collection=deny."""

    CHATS = TestBugDigestLinksProductionPath20260818.CHATS
    ANSWER = {"chats": [{"chat": "Рабочий чат", "topics": [
        {"title": "Тема", "summary": "Итог", "refs": [1]}], "links": []}]}
    REFUSAL = {"code": "finish_reason", "finish_reason": "content_filter",
               "native_finish_reason": "refusal", "completion_tokens": 90,
               "provider": "Amazon Bedrock"}

    def _refusing(self, failure=None):
        return FakeFailingWorker(canonical_json_bytes(
            {"failure": failure or self.REFUSAL}) + b"\n")

    def test_fallback_request_is_pinned_to_allowed_hosts_with_zdr(self):
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse(
                content={"chats": []})) as opened:
            blocking_fetch_response("prompt", FALLBACK_MODEL, "secret")
        payload = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(payload["model"], "z-ai/glm-5.3")
        self.assertEqual(payload["provider"], {
            "zdr": True, "data_collection": "deny",
            "only": list(FALLBACK_PROVIDERS), "require_parameters": True})
        for chinese in ("z-ai", "siliconflow", "novita", "moonshotai",
                        "alibaba", "deepseek", "tencent"):
            self.assertNotIn(chinese, payload["provider"]["only"])
        self.assertEqual(payload["max_tokens"], 32_768)
        self.assertEqual(payload["response_format"], {"type": "json_object"})

        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse(
                content={"chats": []})) as opened:
            blocking_fetch_response(
                "prompt", "anthropic/claude-opus-5.5", "secret")
        primary = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(primary["provider"],
                         {"zdr": True, "data_collection": "deny"})

    async def test_refusal_switches_to_fallback_model(self):
        fallback = FakeAnsweringWorker(self.ANSWER, usage={
            "prompt_tokens": 100, "completion_tokens": 20,
            "reasoning_tokens": None, "cost": 0.01, "upstream_cost": 0.01})
        refusing = self._refusing()
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   side_effect=[refusing, fallback]):
            digest = await create_digest(
                self.CHATS, "anthropic/claude-opus-5.5", "sk-or-test-secret",
                asyncio.Event())
        self.assertIn("Итог", digest)
        self.assertEqual(digest.model, FALLBACK_MODEL)
        self.assertTrue(digest.fallback_after_refusal)
        self.assertEqual(digest.llm_usage["completion_tokens"], 20)
        first = json.loads(refusing.stdin.data)
        second = json.loads(fallback.stdin.data)
        self.assertEqual(first["model"], "anthropic/claude-opus-5.5")
        self.assertEqual(second["model"], FALLBACK_MODEL)
        # тот же промпт: номера `n` и псевдонимы обязаны совпасть с картой
        self.assertEqual(first["prompt"], second["prompt"])

    async def test_other_failures_do_not_reach_the_fallback(self):
        for failure in (
                {"code": "http_error", "http_status": 402},
                {"code": "finish_reason", "finish_reason": "length"},
                {"code": "content_not_json"}):
            calls = []

            def spawn(*_args, **_kwargs):
                calls.append(1)
                return self._refusing(failure)

            with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                       side_effect=spawn):
                with self.assertRaises(OpenRouterError) as caught:
                    await create_digest(
                        self.CHATS, "anthropic/claude-opus-5.5",
                        "sk-or-test-secret", asyncio.Event())
            self.assertEqual(len(calls), 1)
            self.assertEqual(caught.exception.failure["model"],
                             "anthropic/claude-opus-5.5")

    async def test_fallback_refusal_is_reported_without_a_third_call(self):
        calls = []

        def spawn(*_args, **_kwargs):
            calls.append(1)
            return self._refusing()

        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   side_effect=spawn):
            with self.assertRaises(OpenRouterError) as caught:
                await create_digest(
                    self.CHATS, "anthropic/claude-opus-5.5",
                    "sk-or-test-secret", asyncio.Event())
        self.assertEqual(len(calls), 2)
        self.assertEqual(caught.exception.failure["model"], FALLBACK_MODEL)
        self.assertEqual(caught.exception.failure["native_finish_reason"],
                         "refusal")

    async def test_failed_gate_before_fallback_stops_the_second_call(self):
        calls, gates = [], []

        def spawn(*_args, **_kwargs):
            calls.append(1)
            return self._refusing()

        async def expired():
            gates.append(1)
            raise RuntimeError("setup consent is expired")

        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   side_effect=spawn):
            with self.assertRaisesRegex(RuntimeError, "consent"):
                await create_digest(
                    self.CHATS, "anthropic/claude-opus-5.5",
                    "sk-or-test-secret", asyncio.Event(), expired)
        self.assertEqual((len(calls), len(gates)), (1, 1))

    async def test_gate_is_not_called_without_a_refusal(self):
        gates = []

        async def gate():
            gates.append(1)

        worker = FakeAnsweringWorker(self.ANSWER)
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            await create_digest(
                self.CHATS, "anthropic/claude-opus-5.5", "sk-or-test-secret",
                asyncio.Event(), gate)
        self.assertEqual(gates, [])

    async def test_revocation_between_attempts_stops_the_fallback(self):
        revoked = asyncio.Event()
        calls = []

        def spawn(*_args, **_kwargs):
            calls.append(1)
            revoked.set()
            return self._refusing()

        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   side_effect=spawn):
            with self.assertRaises(asyncio.CancelledError):
                await create_digest(
                    self.CHATS, "anthropic/claude-opus-5.5",
                    "sk-or-test-secret", revoked)
        self.assertEqual(len(calls), 1)



class TestBugOpusWorkerTimeout20261004(unittest.IsolatedAsyncioTestCase):
    """Длинный выпуск Opus не должен упираться в лимит воркера.

    04.10.2026 пять попыток подряд упали `worker_timeout` на 100 с (промпт
    ~33 тыс. токенов, 5800 выходных плюс размышление), уложилась лишь
    шестая за 66 с; оборванные генерации оплачены. Лимит поднят до 210 с, а
    HTTP-таймаут держится ниже, чтобы воркер успел вернуть классифицированный
    отказ, а не был убит родителем."""

    def test_limits_are_ordered_and_cover_both_attempts(self):
        from sunny_digest.collector import OPENROUTER_TIMEOUT_S

        self.assertGreaterEqual(WORKER_TIMEOUT_S, 200)
        self.assertLess(HTTP_TIMEOUT_S, WORKER_TIMEOUT_S)
        self.assertGreater(OPENROUTER_TIMEOUT_S, 2 * WORKER_TIMEOUT_S)

    def test_request_uses_the_http_timeout(self):
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse(
                content={"chats": []})) as opened:
            blocking_fetch_response(
                "prompt", "anthropic/claude-opus-5.5", "secret")
        self.assertEqual(opened.call_args.kwargs["timeout"], HTTP_TIMEOUT_S)

    async def test_worker_limit_is_the_named_constant(self):
        worker = FakeHungWorker()
        with patch("sunny_digest.openrouter.WORKER_TIMEOUT_S", 0.05), \
                patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                      return_value=worker):
            with self.assertRaises(OpenRouterError) as caught:
                # внешний предел: литерал вместо константы дал бы зелёный,
                # но долгий тест, а не красный
                await asyncio.wait_for(create_digest(
                    TestBugDigestLinksProductionPath20260818.CHATS,
                    "anthropic/claude-opus-5.5", "sk-or-test-secret",
                    asyncio.Event()), 5)
        self.assertEqual(caught.exception.failure, {
            "code": "worker_timeout", "model": "anthropic/claude-opus-5.5"})
        self.assertTrue(worker.terminated)



class TestBugAnswerNotJson20261005(unittest.TestCase):
    """Обёрнутый JSON не должен стоить оплаченной попытки.

    05.10.2026 Opus 5.5 ответил 5020 токенами с `finish_reason=stop`, но
    ответ не разобрался как JSON (`content_not_json`, Amazon Bedrock):
    выпуск ушёл на следующий тик, генерация оплачена. Извлечение терпимо к
    markdown-обёртке и окружающей фразе, а структуру по-прежнему строго
    проверяет `render_digest`."""

    ANSWER = {"chats": [{"chat": "Чат", "topics": [
        {"title": "Тема", "summary": "Итог { со скобками }", "refs": [1]}],
        "links": []}]}

    def _fetch(self, content):
        body = {"id": "gen-j", "choices": [{
            "finish_reason": "stop", "message": {"content": content}}]}
        with patch("urllib.request.OpenerDirector.open",
                   return_value=FakeRawResponse(body)):
            return blocking_fetch_response(
                "prompt", "anthropic/claude-opus-5.5", "secret")

    def test_wrapped_answers_are_recovered(self):
        raw = json.dumps(self.ANSWER, ensure_ascii=False, indent=2)
        for content in (
                raw,
                f"```json\n{raw}\n```",
                f"```\n{raw}\n```",
                f"  ```JSON\n{raw}```  ",
                f"Вот дайджест:\n{raw}\nГотово.",
                f"Вот дайджест:\n```json\n{raw}\n```\nНадеюсь, полезно."):
            with self.subTest(content=content[:30]):
                self.assertEqual(self._fetch(content)["answer"], self.ANSWER)

    def test_unrecoverable_answer_stays_content_not_json(self):
        for content in ("Не могу помочь.", "```json\n{oops\n```",
                        "{\"chats\": [", "} перевёрнуто {"):
            with self.subTest(content=content):
                with self.assertRaises(OpenRouterError) as caught:
                    self._fetch(content)
                self.assertEqual(caught.exception.failure["code"],
                                 "content_not_json")

    def test_recovery_is_flagged_in_meta(self):
        raw = json.dumps(self.ANSWER, ensure_ascii=False)
        self.assertNotIn("recovered", self._fetch(raw)["meta"])
        self.assertTrue(self._fetch(f"```json\n{raw}\n```")["meta"]["recovered"])

    def test_recovered_answer_is_still_checked_by_structure(self):
        parsed = self._fetch("Ответ: {\"summary\": \"не та схема\"}")["answer"]
        with self.assertRaises(OpenRouterError) as caught:
            render_digest(parsed, {})
        self.assertEqual(caught.exception.failure["code"], "structure_invalid")



class TestBugEmptySkeletonInProse20261005(unittest.IsolatedAsyncioTestCase):
    """Скелет с пустыми разделами в прозе — не тихий день.

    Ревью 0.2.21: «Я не могу пересказывать эти переписки. {"chats":[…пусто…]}»
    после извлечения по скобкам давал бы «ничего существенного» и закрывал
    сутки молча. Правило проекта: пустой валидный результат — худший отказ."""

    CHATS = TestBugDigestLinksProductionPath20260818.CHATS
    SKELETON = {"chats": [{"chat": "Рабочий чат", "topics": [], "links": []}]}

    async def _digest(self, meta):
        worker = FakeAnsweringWorker(self.SKELETON)
        response = json.loads(worker.raw)
        response["meta"] = meta
        worker.raw = canonical_json_bytes(response) + b"\n"
        with patch("sunny_digest.openrouter.asyncio.create_subprocess_exec",
                   return_value=worker):
            return await create_digest(
                self.CHATS, "anthropic/claude-opus-5.5", "sk-or-test-secret",
                asyncio.Event())

    async def test_recovered_empty_skeleton_is_a_failure(self):
        with self.assertRaises(OpenRouterError) as caught:
            await self._digest({"generation_id": "gen-e", "recovered": True})
        self.assertEqual(caught.exception.failure["code"], "content_not_json")
        self.assertEqual(caught.exception.failure["detail"], "empty_recovered")
        self.assertEqual(caught.exception.failure["generation_id"], "gen-e")

    async def test_clean_empty_answer_stays_a_quiet_day(self):
        digest = await self._digest({"generation_id": "gen-c"})
        self.assertIn("ничего существенного", digest)



class TestBugMaterialFlood20261006(unittest.TestCase):
    """Не больше трёх выбранных материалов на пункт и счёт остальных.

    06.10.2026 под ссылкой на конференцию DigiTec вывалились все 37 URL
    исходного сообщения (LinkedIn каждого спикера, сайты компаний,
    Википедия): код 0.2.14 подставлял каждый прямой URL сообщения, а модель
    видела лишь их число. Решение Ивана: модель выбирает до трёх главных
    по подписям, код подставляет адреса и пишет «+N ссылок — в сообщении»."""

    URLS = [f"https://site{i}.example/page" for i in range(1, 38)]

    def _render(self, link):
        from sunny_digest.openrouter import render_digest
        answer = {"chats": [{"chat": "Чат", "topics": [], "links": [link]}]}
        return render_digest(answer, {1: "https://t.me/c/1/2103"},
                             material_urls={1: self.URLS})

    def test_three_picks_and_a_counted_tail(self):
        text = self._render({"title": "Конференция", "note": "Зачем идти",
                             "ref": 1, "materials": [3, 1, 2, 4, 5]})
        shown = [url for url in self.URLS if url in text]
        self.assertEqual(shown, [self.URLS[0], self.URLS[1], self.URLS[2]])
        self.assertIn("+34 ссылки — в сообщении", text)
        self.assertIn("[Сообщение](https://t.me/c/1/2103)", text)
        self.assertLess(text.index("+34 ссылки"), text.index("[Сообщение]"))

    def test_no_picks_means_no_flood(self):
        text = self._render({"title": "Конференция", "ref": 1})
        self.assertFalse(any(url in text for url in self.URLS))
        self.assertIn("+37 ссылок — в сообщении", text)

    def test_invented_or_foreign_picks_are_dropped(self):
        from sunny_digest.openrouter import render_digest
        answer = {"chats": [{"chat": "Чат", "topics": [{
            "title": "Тема", "summary": "Суть", "refs": [1],
            "materials": [{"n": 2, "i": 1}, {"n": 1, "i": 99},
                          {"n": 1, "i": True}, {"n": 1, "i": "x"}, "junk"],
        }], "links": []}]}
        text = render_digest(answer, {1: "https://t.me/c/1/5"}, material_urls={
            1: ["https://a.example/x"], 2: ["https://b.example/y"]})
        self.assertNotIn("https://b.example/y", text)
        self.assertNotIn("https://a.example/x", text)
        self.assertIn("+1 ссылка — в сообщении", text)

    def test_plural_forms(self):
        from sunny_digest.openrouter import _plural_links
        for count, expected in ((1, "1 ссылка"), (2, "2 ссылки"), (5, "5 ссылок"),
                                (11, "11 ссылок"), (21, "21 ссылка"),
                                (34, "34 ссылки"), (112, "112 ссылок")):
            self.assertEqual(_plural_links(count), expected)

    def test_long_note_is_cut_on_a_word_with_ellipsis(self):
        from sunny_digest.openrouter import _clean
        cut = _clean("слово " * 100 + "CTO Mozilla", 400)
        self.assertTrue(cut.endswith("…"))
        self.assertLessEqual(len(cut), 400)
        self.assertTrue(cut[:-1].endswith("слово"))
        self.assertEqual(_clean("коротко", 400), "коротко")


class TestBugMaterialLabels20261006(unittest.TestCase):
    """В промпт уходят подписи материалов, а не скрытые адреса."""

    def test_labels_come_from_visible_text_only(self):
        from sunny_digest.telegram_gateway import _message_materials

        class Entity:
            def __init__(self, kind, offset, length, url=None):
                self.__class__ = type(kind, (), {})
                self.offset, self.length, self.url = offset, length, url

        text = "Спикер Rev Lebaredian и сайт digitec.am/en-US"
        hidden = "https://www.linkedin.com/in/revlebaredian/"

        class Message:
            message = text
            entities = [
                Entity("MessageEntityTextUrl", text.index("Rev"), len("Rev Lebaredian"),
                       url=hidden),
                Entity("MessageEntityUrl", text.index("digitec"), len("digitec.am/en-US")),
            ]

        result = _message_materials(Message())
        self.assertEqual(result["material_urls"],
                         (hidden, "https://digitec.am/en-US"))
        self.assertEqual(result["material_labels"],
                         ("Rev Lebaredian", "digitec.am/en-US"))
        row = render_digest_prompt([DigestChat("Чат", [SelectedMessage(
            1, 7, NOW, text, None, result["material_urls"],
            result["material_labels"])])])
        self.assertIn('"label":"Rev Lebaredian"', row)
        self.assertNotIn("linkedin.com", row)



class TestBugMaterialReview20261006(unittest.TestCase):
    """Ревью 0.2.22: ограниченная строка промпта и честное «где остальное»."""

    def test_prompt_lists_at_most_twenty_materials(self):
        urls = tuple(f"https://s{i}.example/p" for i in range(50))
        row = render_digest_prompt([DigestChat("Чат", [SelectedMessage(
            1, 7, NOW, "пост", None, urls, tuple("Подпись" for _ in urls))])])
        self.assertIn('{"i":20,"label":', row)
        self.assertNotIn('{"i":21,', row)

    def test_dense_post_survives_a_narrow_budget_by_dropping_labels(self):
        from sunny_digest.telegram_gateway import _truncate_first_to_budget
        urls = tuple(f"https://s{i}.example/p" for i in range(20))
        labels = tuple("Очень длинная подпись ссылки " * 3 for _ in urls)
        message = SelectedMessage(1, 7, NOW, "текст " * 400, None, urls, labels)
        budget = prompt_size([SelectedMessage(1, 7, NOW, "x", None, urls)]) + 300
        self.assertGreater(prompt_size([SelectedMessage(
            1, 7, NOW, "", None, urls, labels)]), budget)
        fitted = _truncate_first_to_budget(message, budget, None)
        self.assertLessEqual(prompt_size([fitted]), budget)
        self.assertEqual(fitted.material_urls, urls)
        self.assertEqual(fitted.material_labels, ())

    def test_tail_names_the_right_place(self):
        from sunny_digest.openrouter import render_digest
        answer = {"chats": [{"chat": "Чат", "topics": [{
            "title": "Тема", "summary": "Суть", "refs": [1, 2]}], "links": []}]}
        text = render_digest(answer, {1: "https://t.me/c/1/10",
                                      2: "https://t.me/c/1/11"},
                             material_urls={2: ["https://a.example/x"]})
        self.assertIn("+1 ссылка — в исходных сообщениях", text)
        same = render_digest(answer, {1: "https://t.me/c/1/10"},
                             material_urls={1: ["https://a.example/x"]})
        self.assertIn("+1 ссылка — в сообщении", same)


if __name__ == "__main__":
    unittest.main()
