from __future__ import annotations

import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sunny_digest.layout import (  # noqa: E402
    CHAT_DISPLAY_SCHEMA, ChatMeta, DigestLayout, date_in_text, plural,
    short_date, validate_chat_display, validate_chat_display_row,
)
from sunny_digest.openrouter import NOTHING_NOTABLE, render_digest  # noqa: E402


LAYOUT = DigestLayout(date(2026, 10, 6), (
    ChatMeta("Клуб", "🏛"),
    ChatMeta("Дом", "🏠"),
    ChatMeta("TNN", "📰", "news"),
    ChatMeta("Инвесторы", "💼"),
))
SOURCES = {n: f"https://t.me/c/1/{100 + n}" for n in range(1, 40)}


def topic(tid, title, importance="normal", refs=(1,), **extra):
    return {"id": tid, "title": title, "summary": "", "importance": importance,
            "refs": list(refs), **extra}


class TestBugDigestGuideline20261006(unittest.TestCase):
    """Раскладка по гайдлайну, утверждённому Иваном 06.10.2026.

    Выпуск 05.10 был «фаршем»: сплошной текст, под одной ссылкой 37 URL.
    Модель отбирает и формулирует; дату, порядок, бюджеты, значки,
    счётчики и «Главное» считает код — эти тесты держат именно код."""

    def render(self, answer, **kwargs):
        return render_digest(answer, SOURCES, layout=LAYOUT, **kwargs)

    def test_header_lead_order_and_quiet_line(self):
        text = self.render({
            "lead": [
                {"topic_id": "cfo", "text": "Решение по CFO"},
                {"topic_id": "water", "text": "Отключат воду"},
                {"topic_id": "ghost", "text": "Несуществующая тема"},
                {"topic_id": "minor", "text": "Мелочь не в главное"},
            ],
            "chats": [
                {"chat": "Дом", "topics": [topic("water", "Отключение воды", "action")]},
                {"chat": "Клуб", "topics": [
                    topic("cfo", "CFO на seed: fractional до раунда A", "high"),
                    topic("minor", "Мелкая тема", "normal")]},
            ]})
        lines = text.split("\n")
        self.assertEqual(lines[0], "☀️ Чаты · вт, 6 окт")
        self.assertEqual(lines[1], "2 чата · 3 темы")
        lead = text.split("⚡ Главное\n")[1].split("\n\n")[0].split("\n")
        # действие раньше решения, несуществующие и normal-темы не попадают
        self.assertEqual(lead, ["🏠 Отключат воду", "🏛 Решение по CFO"])
        # порядок чатов — из настроек, а не из ответа модели
        self.assertLess(text.index("🏛 Клуб · 2"), text.index("🏠 Дом · 1"))
        self.assertTrue(text.endswith("💤 Без важного: TNN, Инвесторы"))

    def test_budget_moves_overflow_and_low_into_more(self):
        topics = [topic(f"t{i}", f"Тема номер {i}", "normal") for i in range(6)]
        topics.append(topic("low", "Мелочь", "low"))
        text = self.render({"chats": [{"chat": "Клуб", "topics": topics,
                                        "more": ["От модели"]}]})
        self.assertEqual(text.count("▸ "), 4)
        self.assertIn("Ещё: Тема номер 4; Тема номер 5; Мелочь", text)
        self.assertIn("ещё 3 свёрнуто", text)

    def test_heading_is_glued_to_first_topic_and_blocks_have_no_blank_lines(self):
        text = self.render({"chats": [{"chat": "Клуб", "topics": [
            topic("a", "Первая тема", summary="Суть"),
            topic("b", "Вторая тема")]}]})
        section = text.split("\n\n")[1]
        self.assertTrue(section.startswith("🏛 Клуб · 2\n▸ Первая тема\nСуть\n"))
        for block in text.split("\n\n"):
            self.assertNotIn("\n\n", block)

    def test_news_feed_is_one_line_per_item_with_overflow(self):
        links = [{"title": f"Новость {i}", "ref": i + 1} for i in range(10)]
        text = self.render({"chats": [{"chat": "TNN", "topics": [], "links": links}]})
        feed = text.split("📰 TNN · 8\n")[1].split("\n\n")[0]
        self.assertEqual(feed.count("• Новость"), 8)
        self.assertEqual(feed.count("[Сообщение]("), 8)
        self.assertIn("+ ещё 2 новости — в канале", feed)

    def test_date_is_rendered_by_code_only_when_present_in_source(self):
        when = {"date": "2026-10-07", "start": "10:00", "end": "14:00"}
        answer = {"chats": [{"chat": "Дом", "topics": [
            topic("w", "Отключение воды", "action", refs=(4,), when=when)]}]}
        real = self.render(answer, message_texts={4: "7 октября с 10 до 14 без воды"})
        self.assertIn("⚡ Отключение воды — ср, 7 окт, 10:00–14:00", real)
        invented = self.render(answer, message_texts={4: "в субботу без воды"})
        self.assertIn("⚡ Отключение воды\n", invented)
        self.assertNotIn("ср, 7 окт", invented)

    def test_unknown_chat_from_model_is_kept_at_the_end(self):
        text = self.render({"chats": [{"chat": "Клуб (искажено)", "topics": [
            topic("x", "Тема из искажённого чата")]}]})
        self.assertIn("💬 Клуб (искажено) · 1", text)

    def test_legacy_answer_without_new_fields_still_renders(self):
        text = render_digest({"chats": [{"chat": "Чат", "topics": [
            {"title": "Тема", "summary": "Суть", "refs": [1]}], "links": [
            {"title": "Статья", "note": "Зачем", "ref": 2}]}]}, SOURCES)
        self.assertTrue(text.startswith("☀️ Чаты\n1 чат · 2 темы"))
        self.assertIn("▸ Тема\nСуть\n[Сообщение](https://t.me/c/1/101)", text)
        self.assertIn("• Статья — Зачем\n[Сообщение](https://t.me/c/1/102)", text)

    def test_empty_answer_stays_nothing_notable(self):
        self.assertEqual(
            self.render({"chats": [{"chat": "Клуб", "topics": [], "links": []}]}),
            NOTHING_NOTABLE)

    def test_soft_volume_limit_drops_normal_summaries_first(self):
        chats = [{"chat": f"Чат {c}", "topics": [
            topic(f"{c}-{i}", f"Тема {c}-{i}", "high" if i == 0 else "normal",
                  summary="с" * 150) for i in range(4)]} for c in range(20)]
        text = render_digest({"chats": chats}, SOURCES)
        self.assertLessEqual(len(text), 24_000)
        high_block = text.split("▸ Тема 0-0\n")[1].split("\n")[0]
        self.assertEqual(high_block, "с" * 150)
        normal_block = text.split("▸ Тема 0-1\n")[1].split("\n")[0]
        self.assertTrue(normal_block.startswith("[Сообщение]("))

    def test_helpers(self):
        self.assertEqual(short_date(date(2026, 10, 7)), "ср, 7 окт")
        self.assertEqual(plural(21, "тема", "темы", "тем"), "21 тема")
        self.assertEqual(plural(12, "тема", "темы", "тем"), "12 тем")
        self.assertTrue(date_in_text(date(2026, 10, 7), ["встреча 07.10 в 19"]))
        self.assertTrue(date_in_text(date(2026, 5, 1), ["1 мая"]))
        self.assertFalse(date_in_text(date(2026, 10, 7), ["17 октября"]))


class TestBugGuidelineReview20261006(unittest.TestCase):
    """Находки независимого ревью 0.2.23 (22 агента, 9 разных проблем)."""

    def render(self, answer, layout=LAYOUT, **kwargs):
        return render_digest(answer, SOURCES, layout=layout, **kwargs)

    def test_model_demoted_count_is_not_double_counted(self):
        topics = [topic("a", "Главная тема", "high"),
                  topic("b", "Мелочь один", "low"), topic("c", "Мелочь два", "low")]
        text = self.render({"demoted_count": 2,
                            "chats": [{"chat": "Клуб", "topics": topics}]})
        # 2 low код свернул сам + 2 модель выбросила целиком
        self.assertIn("ещё 4 свёрнуто", text)

    def test_low_only_day_is_not_nothing_notable(self):
        text = self.render({"chats": [
            {"chat": "Клуб", "topics": [topic("a", "Мелочь клуба", "low")]},
            {"chat": "TNN", "links": [{"title": "Мелкая новость", "ref": 2,
                                       "importance": "low"}]}]})
        self.assertNotEqual(text, NOTHING_NOTABLE)
        self.assertIn("🏛 Клуб\nЕщё: Мелочь клуба", text)
        self.assertIn("📰 TNN\nЕщё: Мелкая новость", text)

    def test_news_keeps_picked_material_next_to_permalink(self):
        text = render_digest(
            {"chats": [{"chat": "TNN", "links": [
                {"title": "Tabby привлекла $233M", "ref": 1, "materials": [1]}]}]},
            SOURCES, material_urls={1: ["https://arabnews.example/tabby",
                                        "https://x.example/other"]}, layout=LAYOUT)
        self.assertIn("• Tabby привлекла $233M\nhttps://arabnews.example/tabby\n"
                      "[Сообщение](https://t.me/c/1/101)", text)
        self.assertNotIn("x.example/other", text)

    def test_colliding_topic_id_is_not_used_for_lead(self):
        text = self.render({
            "lead": [{"topic_id": "t1", "text": "Отключат воду"}],
            "chats": [
                {"chat": "Дом", "topics": [topic("t1", "Отключение воды", "action")]},
                {"chat": "Клуб", "topics": [topic("t1", "Другая тема", "normal")]}]})
        self.assertNotIn("⚡ Главное", text)

    def test_duplicate_locked_titles_render_entry_once(self):
        layout = DigestLayout(None, (ChatMeta("Двойник", "🏛"), ChatMeta("Двойник", "🏠")))
        text = self.render({"chats": [{"chat": "Двойник", "topics": [
            topic("a", "Единственная тема")]}]}, layout=layout)
        self.assertEqual(text.count("Единственная тема"), 1)
        self.assertIn("💤 Без важного: Двойник", text)

    def test_model_title_variants_match_the_locked_chat(self):
        layout = DigestLayout(None, (ChatMeta("«Клуб» Директоров 🏛", "🏛"),))
        text = self.render({"chats": [{"chat": "клуб  директоров", "topics": [
            topic("a", "Тема клуба")]}]}, layout=layout)
        self.assertIn("🏛 «Клуб» Директоров 🏛 · 1\n▸ Тема клуба", text)
        self.assertNotIn("💤", text)
        self.assertNotIn("💬", text)

    def test_date_check_month_forms(self):
        self.assertFalse(date_in_text(date(2026, 5, 1), ["1 марта"]))
        self.assertFalse(date_in_text(date(2026, 5, 1), ["купим 1 машину"]))
        self.assertTrue(date_in_text(date(2026, 5, 1), ["1 мая"]))
        self.assertTrue(date_in_text(date(2026, 10, 1), ["01 октября"]))
        self.assertTrue(date_in_text(date(2026, 3, 8), ["8 марта"]))


class TestBugDigestRichTierB20261006(unittest.TestCase):
    """Уровень B: разметку для рендера chats_text_v3 ставит только код.

    Иван попросил «уровень B» 06.10. Ядро Sunny понимает **жирный**,
    __курсив__, [подпись](url) в строке и строки «> »/«>> » как цитаты.
    Модельный текст обязан быть очищен от той же разметки, иначе модель
    сама ставила бы ссылки с подписями и цитаты в выпуск."""

    RICH = DigestLayout(date(2026, 10, 7), LAYOUT.chats, rich=True)

    def test_rich_structure(self):
        text = render_digest({
            "lead": [{"topic_id": "w", "text": "Отключат воду"}],
            "chats": [
                {"chat": "Дом", "topics": [
                    topic("w", "Отключение воды", "action", summary="По словам УК")]},
                {"chat": "Клуб", "topics": [topic("a", "CFO: итог", "high")]},
                {"chat": "TNN", "links": [{"title": f"Новость {i}", "ref": i + 1}
                                          for i in range(6)]}]},
            SOURCES, layout=self.RICH)
        self.assertTrue(text.startswith("**☀️ Чаты · ср, 7 окт**\n__"))
        self.assertIn("> **⚡ Главное**\n> 🏠 Отключат воду", text)
        self.assertIn("**🏛 Клуб** · 1\n**CFO: итог** · [Сообщение](https://t.me/c/1/101)", text)
        self.assertIn("⚡ **Отключение воды**\nПо словам УК · [Сообщение](", text)
        self.assertIn("• [Новость 3](https://t.me/c/1/104)\n>> • [Новость 4](", text)
        self.assertTrue(text.endswith("__💤 Без важного: Инвесторы__"))

    def test_model_text_cannot_inject_markup(self):
        text = render_digest({"chats": [{"chat": "Клуб", "topics": [topic(
            "a", "**Жирно** [фишинг](https://evil.example/x)", "high",
            summary="> цитата __курсив__")]}]}, SOURCES, layout=self.RICH)
        self.assertNotIn("](https://evil.example", text)
        self.assertNotIn("****", text)
        self.assertNotIn("\n> цитата", text)
        self.assertNotIn("__курсив__", text)

    def test_markup_cleaning_is_idempotent_and_keeps_text(self):
        text = render_digest({"chats": [
            {"chat": "Клуб", "topics": [
                topic("a", "*__*Срочно*__*", "high", summary="> > Фейк"),
                topic("b", "C* в проде и dev_team", "high"),
                topic("c", "[Анонс] Митап_", "high"),
                topic("d", "a*__*b", "high")]}]}, SOURCES, layout=self.RICH)
        self.assertIn("**a*_*b**", text)
        self.assertIn("**Срочно**\nФейк", text)
        self.assertIn("**C* в проде и dev_team**", text)
        self.assertIn("**(Анонс) Митап**", text)
        self.assertNotIn("\n> ", text.split("> **⚡ Главное**")[-1].split("\n\n", 1)[-1])

    def test_news_title_with_brackets_stays_a_link(self):
        text = render_digest({"chats": [{"chat": "TNN", "links": [
            {"title": "[Анонс] Митап", "ref": 1}]}]}, SOURCES, layout=self.RICH)
        self.assertIn("• [(Анонс) Митап](https://t.me/c/1/101)", text)

    def test_hidden_tail_keeps_where(self):
        from sunny_digest.layout import _inline_links
        self.assertEqual(_inline_links(["+5 ссылок — в исходных сообщениях"]),
                         (["__ещё 5 ссылок в исходных сообщениях__"], []))

    def test_rich_is_off_by_default(self):
        text = render_digest({"chats": [{"chat": "Клуб", "topics": [
            topic("a", "Тема")]}]}, SOURCES, layout=LAYOUT)
        self.assertNotIn("**", text)
        self.assertIn("▸ Тема\n[Сообщение](", text)

    def test_material_and_hidden_tail_become_inline_segments(self):
        text = render_digest({"chats": [{"chat": "Клуб", "topics": [topic(
            "a", "DigiTec", "normal", summary="Суть", refs=(2,),
            materials=[{"n": 2, "i": 1}])]}]}, SOURCES,
            material_urls={2: ["https://www.digitec.am/en-US", "https://b.example/x"]},
            layout=self.RICH)
        self.assertIn("**DigiTec**\nСуть · [digitec.am](https://www.digitec.am/en-US)"
                      " · __ещё 1 ссылка в сообщении__ · [Сообщение](https://t.me/c/1/102)", text)


class TestBugDigestRichSecondReview20261006(unittest.TestCase):
    """Второе ревью уровня B 06.10: цитата через «*>», подмена подписи через
    цель материала, заметка о пропуске с названием чата от админа группы."""

    RICH = DigestLayout(date(2026, 10, 7), LAYOUT.chats, rich=True)

    def test_markup_plain_is_idempotent(self):
        from sunny_digest.layout import markup_plain
        for raw in ["*> Важно", "_>> x", "> *> **y**", "[a](https://e.x)", "a*__*b",
                    " _*_ > z", "**", ">"]:
            once = markup_plain(raw)
            self.assertEqual(markup_plain(once), once, raw)
            self.assertFalse(once.startswith(">"), raw)
            self.assertNotIn("**", once)
            self.assertNotIn("__", once)
            self.assertNotIn("[", once)

    def test_star_quote_summary_is_not_a_quote(self):
        text = render_digest({"chats": [{"chat": "Клуб", "topics": [topic(
            "a", "Тема", "high", summary="*> Важно")]}]}, SOURCES, layout=self.RICH)
        self.assertNotIn("\n> Важно", text)
        self.assertIn("\nВажно · [Сообщение](", text)

    def test_hostile_material_target_goes_to_own_line(self):
        hostile = "https://a.com/x)[sberbank.ru](https://evil.com"
        text = render_digest({"chats": [
            {"chat": "Клуб", "topics": [topic(
                "a", "Тема", "high", summary="Суть", refs=(2,),
                materials=[{"n": 2, "i": 1}, {"n": 2, "i": 2}])]},
            {"chat": "TNN", "links": [{"title": "Новость", "ref": 2, "materials": [1]}]}]},
            SOURCES, material_urls={2: [hostile, "https://ok.example/a_(b)"]},
            layout=self.RICH)
        self.assertNotIn("[sberbank.ru]", text.replace(f"\n{hostile}", ""))
        self.assertIn(f"\n{hostile}", text)
        self.assertIn("[ok.example](https://ok.example/a_(b))", text)

    def test_skip_note_title_is_plain(self):
        from sunny_digest.prompting import digest_skip_note
        note = digest_skip_note([("> Срочно", 1, 2), ("Чат [Сбер](https://evil.com)", 3, 4)])
        self.assertIn("\nСрочно: диапазон ID 1–2", note)
        self.assertNotIn("[Сбер]", note)


class TestBugDigestMoreLinks20261008(unittest.TestCase):
    """Иван 08.10: в строке «Ещё» уровня B не было ссылок.

    Свёрнутые темы и мелкие новости знают своё сообщение, но строка «Ещё»
    печатала только заголовки; мелочи модели были строками без номера.
    Теперь пункт — ссылка на permalink источника; материал за подпись не
    прячется; бюджет строки — по видимому тексту, не по разметке."""

    RICH = DigestLayout(date(2026, 10, 8), LAYOUT.chats, rich=True)

    def test_overflow_low_and_more_become_links(self):
        text = render_digest({"chats": [{"chat": "Клуб", "topics": [
            topic(f"t{i}", f"Тема {i}", "high", refs=(i,)) for i in range(1, 6)] + [
            topic("low", "Мелкая", "low", refs=(7,))],
            "more": [{"text": "Квартира с потолками", "ref": 8}, "Старая мелочь"]}]},
            SOURCES, layout=self.RICH)
        self.assertIn("__Ещё:__ [Тема 5](https://t.me/c/1/105); "
                      "[Мелкая](https://t.me/c/1/107); "
                      "[Квартира с потолками](https://t.me/c/1/108)", text)

    def test_more_without_source_stays_italic(self):
        text = render_digest({"chats": [{"chat": "Клуб", "more": [
            "Старая мелочь", {"text": "Без номера"}, {"text": "Чужой", "ref": 999},
            {"text": "Булев", "ref": True}]}]}, SOURCES, layout=self.RICH)
        self.assertIn("**🏛 Клуб**\n__Ещё:__ __Старая мелочь__; __Без номера__; __Чужой__", text)
        self.assertNotIn("](", text)

    def test_news_low_items_link_to_post(self):
        text = render_digest({"chats": [{"chat": "TNN", "links": [
            {"title": "Уровень Невы 119 см", "ref": 3, "importance": "low"},
            {"title": "Переиздание Bloodhound Gang", "ref": 4, "importance": "low"}]}]},
            SOURCES, layout=self.RICH)
        self.assertIn("**📰 TNN**\n__Ещё:__ [Уровень Невы 119 см](https://t.me/c/1/103); "
                      "[Переиздание Bloodhound Gang](https://t.me/c/1/104)", text)

    def test_material_is_not_hidden_behind_title(self):
        text = render_digest({"chats": [{"chat": "TNN", "links": [
            {"title": "Новость", "ref": 39, "materials": [1], "importance": "low"}]}]},
            {}, material_urls={39: ["https://evil.example/x"]}, layout=self.RICH)
        self.assertIn("__Ещё:__ __Новость__", text)
        self.assertNotIn("evil.example", text)

    def test_budget_counts_visible_text_and_keeps_links_whole(self):
        import re
        titles = ["Длинный заголовок номер один про очень важные вещи и детали",
                  "Второй длинный заголовок тоже про многое и разное сразу тут",
                  "Третий длинный заголовок который уже не поместится в строку"]
        text = render_digest({"chats": [{"chat": "Клуб", "more": [
            {"text": title, "ref": n} for n, title in enumerate(titles, 1)]}]},
            SOURCES, layout=self.RICH)
        line = next(row for row in text.split("\n") if row.startswith("__Ещё:__"))
        links = re.findall(r"\[([^\]]+)\]\((https://t\.me/c/1/\d+)\)", line)
        visible = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line).replace("__", "")
        self.assertLessEqual(len(visible), 160)
        self.assertEqual(len(links), 3)
        self.assertTrue(links[-1][0].endswith("…"))
        self.assertEqual(re.sub(r"\[[^\]]+\]\([^)]+\)", "", line.split(" ", 1)[1])
                         .replace("; ", ""), "")

    def test_more_text_cannot_inject_link(self):
        text = render_digest({"chats": [{"chat": "Клуб", "more": [
            {"text": "Жми [сюда](https://evil.example/x)", "ref": 2}]}]},
            SOURCES, layout=self.RICH)
        self.assertNotIn("](https://evil.example", text)
        self.assertIn("[Жми (сюда)(https://evil.example/x)](https://t.me/c/1/102)", text)

    def test_tier_a_line_is_unchanged(self):
        text = render_digest({"chats": [{"chat": "Клуб", "topics": [
            topic(f"t{i}", f"Тема {i}", "high") for i in range(1, 6)],
            "more": [{"text": "Мелочь", "ref": 2}, "Строка"]}]}, SOURCES, layout=LAYOUT)
        self.assertIn("\nЕщё: Тема 5; Мелочь; Строка", text)
        self.assertNotIn("__", text)


class TestChatDisplayValidation20261006(unittest.TestCase):
    """Значки чатов — только из палитры, только для зафиксированных чатов."""

    def test_valid_file_and_foreign_chat_is_ignored(self):
        value = {"schema": CHAT_DISPLAY_SCHEMA, "chats": {
            "-100": {"emoji": "🏛", "kind": "discussion", "short_name": "  Клуб  "},
            "-999": {"emoji": "🏠", "kind": "news", "short_name": None}}}
        self.assertEqual(validate_chat_display(value, [-100]), {
            -100: {"emoji": "🏛", "kind": "discussion", "short_name": "Клуб"}})

    def test_hostile_rows_are_refused(self):
        for row in (
                {"emoji": "<b>", "kind": "discussion", "short_name": None},
                {"emoji": "🏛", "kind": "chat", "short_name": None},
                {"emoji": "🏛", "kind": "news", "short_name": "x" * 40},
                {"emoji": "🏛", "kind": "news", "short_name": "a\u202eb"},
                {"emoji": "🏛", "kind": "news", "short_name": "a\u061cb"},
                {"emoji": "🏛", "kind": "news", "short_name": "a\u200bb"},
                {"emoji": "🏛", "kind": "news", "short_name": "a\u206ab"},
                {"emoji": "🏛", "kind": "news", "short_name": "", "extra": 1}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                validate_chat_display_row(row)


if __name__ == "__main__":
    unittest.main()
