from __future__ import annotations

import asyncio
import email.message
import io
import ssl
import json
import os
import unittest
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
    WORKER_SCHEMA,
    OpenRouterError,
    _blocking_digest,
    _prompt,
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

    def __init__(self, digest: str = "Готово", *, content=None):
        if content is None:
            content = {"chats": [{
                "chat": "Чат",
                "topics": [{"title": "Тема", "summary": digest, "refs": []}],
                "links": [],
            }]}
        self.raw = json.dumps({
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps(content)},
            }]
        }).encode("utf-8")

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
            _blocking_digest([], "anthropic/claude-opus-4.8", "secret")

        body = json.loads(urlopen.call_args.args[0].data)
        self.assertGreaterEqual(body["max_tokens"], 16_384)


class FakeAnsweringWorker(FakeHungWorker):
    """Воркер, отвечающий ровно так, как настоящий: структурой, не текстом."""

    def __init__(self, answer):
        super().__init__()
        self.raw = canonical_json_bytes({"answer": answer}) + b"\n"
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


if __name__ == "__main__":
    unittest.main()
