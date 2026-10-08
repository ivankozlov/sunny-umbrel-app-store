"""Раскладка выпуска «Чаты» по гайдлайну 06.10.2026 (уровень A).

Выпуск 05.10 Иван назвал «фаршем»: темы и ссылки шли сплошным текстом,
под одной ссылкой — 37 URL. Гайдлайн собрала дизайн-панель (три
независимых дизайнера и судья), Иван утвердил его 06.10. Здесь — только
детерминированный код: модель отбирает и формулирует, а дату, день недели,
порядок, бюджеты, значки и счётчики считает этот модуль.

Ограничения канала (уровень A, без выкатки worker на DO): Telegram-ядро
Sunny снимает markdown, ссылкой делает только строку, целиком состоящую из
URL или из `[Сообщение](…)`, и режет выпуск по пустым строкам. Поэтому
каждая ссылка стоит на своей строке, внутри темы нет пустых строк, а
заголовок чата приклеен к первой теме — висеть в конце части ему нечем.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from datetime import date
from typing import Any, Callable, Dict, List, Optional, Tuple

# Закрытая палитра значков чатов: задаётся в UI Umbrel, модель их не
# выбирает. Без ZWJ-последовательностей — только одиночные символы.
CHAT_EMOJI = (
    "💬", "🏛", "🏠", "🛡", "📰", "💼", "🚀", "🎓", "🏢", "🤖", "💰",
    "⚽", "🎨", "🧪", "🌍",
)
DEFAULT_CHAT_EMOJI = "💬"
CHAT_KINDS = ("discussion", "news")
IMPORTANCE_RANK = {"action": 0, "high": 1, "normal": 2, "low": 3}
STATES = ("resolved", "open", "info")

TOPICS_PER_CHAT = 4
NEWS_PER_CHAT = 8
LEAD_MAX = 4
LEAD_PER_CHAT = 2
MORE_MAX = 3
CHAT_NAME_LIMIT = 34
TITLE_LIMIT = 70
SUMMARY_LIMIT = 160
NOTE_LIMIT = 120
LEAD_LIMIT = 80
MORE_ITEM_LIMIT = 60
MORE_LINE_LIMIT = 160
# Мягкий потолок: выше него у обычных тем убирается строка сути. Жёсткий
# потолок выпуска (MAX_DIGEST_CHARS) по-прежнему режет хвост по строкам.
VOLUME_SOFT_LIMIT = 9_000

WEEKDAYS = ("пн", "вт", "ср", "чт", "пт", "сб", "вс")
MONTHS = ("янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен",
          "окт", "ноя", "дек")
# Родительный падеж с окончанием: «ма» без «[яй]» совпадало бы с «марта» и
# «машину» (ревью 0.2.23).
_MONTH_WORDS = ("январ[яь]", "феврал[яь]", "март[а]?", "апрел[яь]", "ма[яй]",
                "июн[яь]", "июл[яь]", "август[а]?", "сентябр[яь]", "октябр[яь]",
                "ноябр[яь]", "декабр[яь]")
_TIME = re.compile(r"(?:[01]?[0-9]|2[0-3]):[0-5][0-9]\Z")


@dataclass(frozen=True)
class ChatMeta:
    title: str
    emoji: str = DEFAULT_CHAT_EMOJI
    kind: str = "discussion"
    short_name: Optional[str] = None

    @property
    def name(self) -> str:
        return self.short_name or self.title


@dataclass(frozen=True)
class DigestLayout:
    digest_date: Optional[date] = None
    chats: Tuple[ChatMeta, ...] = field(default_factory=tuple)
    # Уровень B: включает владелец в UI после выкатки рендера v3 на DO.
    rich: bool = False


CHAT_DISPLAY_SCHEMA = "sunny.personal-chats.chat-display.v1"
DIGEST_STYLE_SCHEMA = "sunny.personal-chats.digest-style.v1"


def validate_chat_display(value: Any, chat_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """Файл значков: {schema, chats: {"<chat_id>": {emoji, kind, short_name}}}.

    Неизвестный chat_id, значок вне палитры, тип вне списка или битое имя —
    отказ целиком: файл пишет только collector из проверенной формы UI."""
    if not isinstance(value, dict) or set(value) != {"schema", "chats"} \
            or value["schema"] != CHAT_DISPLAY_SCHEMA or not isinstance(value["chats"], dict):
        raise ValueError("chat display is invalid")
    result: Dict[int, Dict[str, Any]] = {}
    for key, row in value["chats"].items():
        if not isinstance(key, str) or not key.lstrip("-").isdigit():
            raise ValueError("chat display key is invalid")
        chat_id = int(key)
        if chat_id not in chat_ids:
            continue
        result[chat_id] = validate_chat_display_row(row)
    return result


def validate_chat_display_row(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict) or set(row) != {"emoji", "kind", "short_name"}:
        raise ValueError("chat display row is invalid")
    if row["emoji"] not in CHAT_EMOJI or row["kind"] not in CHAT_KINDS:
        raise ValueError("chat display value is invalid")
    short = row["short_name"]
    if short is not None:
        # Та же строгость, что у названий чатов (validate_chat_title): любые
        # Cc/Cf/Cs, включая bidi из списков трёх валидаторов, — отказ. Иначе
        # одно сохранённое имя роняло бы каждый выпуск (ревью 0.2.23).
        if (not isinstance(short, str) or not short.strip()
                or len(short.encode("utf-16-le", "surrogatepass")) // 2 > CHAT_NAME_LIMIT
                or any(unicodedata.category(char) in ("Cc", "Cf", "Cs")
                       for char in short)):
            raise ValueError("chat display name is invalid")
        short = " ".join(short.split())
    return {"emoji": row["emoji"], "kind": row["kind"], "short_name": short}


def short_date(day: date) -> str:
    return f"{WEEKDAYS[day.weekday()]}, {day.day} {MONTHS[day.month - 1]}"


def plural(count: int, one: str, few: str, many: str) -> str:
    tail = count % 100
    if 11 <= tail <= 14:
        word = many
    elif count % 10 == 1:
        word = one
    elif 2 <= count % 10 <= 4:
        word = few
    else:
        word = many
    return f"{count} {word}"


def date_in_text(day: date, texts: List[str]) -> bool:
    """Дата из `when` обязана встречаться в тексте исходных сообщений.

    Модель легко превращает «в субботу» в число с выдуманным днём недели;
    такую дату код отбрасывает (тема остаётся, слова источника — в заголовке)."""
    patterns = [
        re.compile(rf"(?<![0-9])0?{day.day}\s*(?:-го\s*)?"
                   rf"{_MONTH_WORDS[day.month - 1]}(?![а-яё])", re.IGNORECASE),
        re.compile(rf"(?<![0-9])0?{day.day}[./]0?{day.month}(?![0-9])"),
    ]
    return any(pattern.search(text) for text in texts for pattern in patterns)


def _when(value: Any, texts: List[str]) -> Optional[Tuple[date, str]]:
    if not isinstance(value, dict):
        return None
    try:
        day = date.fromisoformat(str(value.get("date")))
    except ValueError:
        return None
    if not date_in_text(day, texts):
        return None
    start, end = value.get("start"), value.get("end")
    hours = ""
    if isinstance(start, str) and _TIME.match(start):
        hours = start
        if isinstance(end, str) and _TIME.match(end):
            hours = f"{start}–{end}"
    return day, hours


def _mentions_date(title: str, day: date) -> bool:
    return date_in_text(day, [title])


@dataclass
class _Item:
    kind: str                # "topic" | "link"
    importance: str
    title: str
    summary: str
    links: List[str]
    when: Optional[Tuple[date, str]] = None
    topic_id: Optional[str] = None


def render_layout(
    chats: List[Tuple[ChatMeta, Optional[Dict[str, Any]]]],
    *,
    digest_date: Optional[date],
    lead: Any,
    demoted_by_model: int,
    clean: Callable[[Any, int], str],
    topic_links: Callable[[Dict[str, Any]], List[str]],
    link_links: Callable[[Dict[str, Any]], List[str]],
    news_link: Callable[[Dict[str, Any]], List[str]],
    restore: Callable[[Any, str], Any],
    ref_texts: Callable[[List[Any]], List[str]],
    with_summaries: bool = True,
    rich: bool = False,
    more_link: Callable[[Any], Optional[str]] = lambda ref: None,
) -> Optional[str]:
    """Собрать текст; None — ни в одном чате нет ни одного пункта.

    `rich` — уровень B: разметка для рендера `chats_text_v3` ядра Sunny
    (жирный, курсив, цитаты, ссылки с подписью в строке). Модельный и
    пользовательский текст в этом режиме очищается от той же разметки,
    чтобы её ставил только код."""
    if rich:
        clean = _markup_safe(clean)
    sections: List[str] = []
    quiet: List[str] = []
    topic_index: Dict[str, Optional[Tuple[ChatMeta, str]]] = {}
    shown_topics = 0
    shown_chats = 0
    demoted = max(0, demoted_by_model)
    for meta, entry in chats:
        items, more = _chat_items(
            meta, entry or {}, clean=clean, topic_links=topic_links,
            link_links=link_links, news_link=news_link, restore=restore,
            ref_texts=ref_texts, more_link=more_link)
        if meta.kind == "news":
            visible = [item for item in items if item.importance != "low"]
            overflow = len(visible) - NEWS_PER_CHAT
            low_titles = [_more_entry(item) for item in items if item.importance == "low"]
            visible = visible[:NEWS_PER_CHAT]
            demoted += max(0, overflow) + len(low_titles)
            if not visible:
                if low_titles:
                    sections.append(_chat_heading(meta, 0, clean, rich) + "\n"
                                    + _more_line(low_titles[:MORE_MAX], clean, rich))
                    shown_chats += 1
                else:
                    quiet.append(meta.name)
                continue
            lines = [_chat_heading(meta, len(visible), clean, rich)]
            for position, item in enumerate(visible):
                if rich:
                    prefix = ">> " if position >= NEWS_RICH_VISIBLE else ""
                    lines.extend(prefix + line for line in _rich_news_lines(item))
                else:
                    lines.append(f"• {item.title}")
                    lines.extend(item.links)
            if overflow > 0:
                tail = (f"+ ещё {plural(overflow, 'новость', 'новости', 'новостей')}"
                        " — в канале")
                lines.append(f"__{tail}__" if rich else tail)
            sections.append("\n".join(lines))
            shown_chats += 1
            shown_topics += len(visible)
            continue
        ordered = sorted(items, key=lambda item: IMPORTANCE_RANK[item.importance])
        main = [item for item in ordered if item.importance != "low"]
        overflow = main[TOPICS_PER_CHAT:]
        main = main[:TOPICS_PER_CHAT]
        extra = [_more_entry(item) for item in overflow] + [
            _more_entry(item) for item in ordered if item.importance == "low"]
        demoted += len(extra)
        more_titles = (extra + more)[:MORE_MAX]
        if not main and not more_titles:
            quiet.append(meta.name)
            continue
        blocks = []
        for item in main:
            if item.topic_id:
                # Одинаковый id в разных чатах неоднозначен: «Главное» по нему
                # не строится, иначе строка ушла бы чужому чату (ревью 0.2.23).
                topic_index[item.topic_id] = (
                    None if item.topic_id in topic_index else (meta, item.importance))
            blocks.append(_item_block(item, with_summaries, rich))
        if more_titles:
            blocks.append(_more_line(more_titles, clean, rich))
        # Чат только с мелочами — раздел из одной строки «Ещё», а не тишина:
        # иначе день из одних low-тем превращался в «ничего существенного»
        # и для извлечённого ответа — в отказ empty_recovered (ревью 0.2.23).
        head = _chat_heading(meta, len(main), clean, rich)
        sections.append(head + "\n" + "\n\n".join(blocks))
        shown_chats += 1
        shown_topics += len(main)
    if not sections:
        return None

    out: List[str] = []
    header = "☀️ Чаты" + (f" · {short_date(digest_date)}" if digest_date else "")
    counts = (f"{plural(shown_chats, 'чат', 'чата', 'чатов')} · "
              f"{plural(shown_topics, 'тема', 'темы', 'тем')}")
    if demoted:
        counts += f" · ещё {demoted} свёрнуто"
    out.append(f"**{header}**\n__{counts}__" if rich else header + "\n" + counts)
    lead_lines = _lead_lines(lead, topic_index, clean, restore)
    if lead_lines:
        if rich:
            out.append("> **⚡ Главное**\n" + "\n".join("> " + line for line in lead_lines))
        else:
            out.append("⚡ Главное\n" + "\n".join(lead_lines))
    out.extend(sections)
    if quiet:
        quiet_line = "💤 Без важного: " + ", ".join(clean(name, CHAT_NAME_LIMIT) for name in quiet)
        out.append(f"__{quiet_line}__" if rich else quiet_line)
    return "\n\n".join(out)


def _chat_heading(meta: ChatMeta, count: int, clean: Callable[[Any, int], str],
                  rich: bool = False) -> str:
    name = f"{meta.emoji} {clean(meta.name, CHAT_NAME_LIMIT)}"
    if rich:
        name = f"**{name}**"
    return f"{name} · {count}" if count else name


# Уровень B: в ленте сначала четыре новости, остальные — в сворачиваемой цитате.
NEWS_RICH_VISIBLE = 4
_HIDDEN_TAIL = re.compile(r"\+(?P<count>\d+ \S+) — (?P<where>.+)$")


_MARKUP_RUNS = re.compile(r"\*{2,}|_{2,}")


def _markup_safe(clean: Callable[[Any, int], str]) -> Callable[[Any, int], str]:
    """Модельный и пользовательский текст не ставит разметку уровня B сам.

    Ревью 06.10: одноразовая замена не идемпотентна («*__*» давало «**»),
    а одиночные маркеры на краю ломали обёртки кода. Поэтому серии «*»/«_»
    схлопываются до одного символа (одиночные внутри — обычный текст для
    рендера v3), края очищаются от них, скобки «[]» становятся «()» —
    подпись ссылки ставит только код, — и снимается ведущий «>» любой
    глубины."""
    def wrapped(value: Any, limit: int) -> str:
        return markup_plain(clean(value, limit))
    return wrapped


def markup_plain(text: str) -> str:
    """Очистка разметки уровня B до неподвижной точки.

    Второе ревью 06.10: края чистились после снятия «>», и «*> Важно»
    давало «> Важно» — цитату от модели. Цикл гарантирует идемпотентность."""
    while True:
        cleaned = _MARKUP_RUNS.sub(lambda match: match.group(0)[0], text)
        cleaned = cleaned.replace("[", "(").replace("]", ")")
        cleaned = re.sub(r"^[>\s]+", "", cleaned.strip("*_ "))
        if cleaned == text:
            return cleaned
        text = cleaned


# Адрес, который рендер v3 целиком примет как цель ссылки в строке. Цель
# материала задаёт любой участник чата (скрытый TextUrl): адрес вида
# `…/x)[sberbank.ru](https://evil` иначе дал бы вторую ссылку с чужой
# подписью (второе ревью 06.10). Всё остальное — отдельной строкой-URL,
# которую рендер подписывает сам (hostname+path), как в уровне A.
_INLINE_SAFE_URL = re.compile(r"https?://(?:[^()\[\]\s]|\([^()\[\]\s]*\))+", re.I)


def _source_url(links: List[str]) -> Optional[str]:
    """Permalink исходного сообщения — его ставит код из карты источников."""
    for line in links:
        if line.startswith("[Сообщение](") and line.endswith(")"):
            url = line[len("[Сообщение]("):-1]
            if _INLINE_SAFE_URL.fullmatch(url):
                return url
    return None


def _more_entry(item: "_Item") -> Tuple[str, Optional[str]]:
    return item.title, _source_url(item.links)


def _more_line(entries: List[Tuple[str, Optional[str]]],
               clean: Callable[[Any, int], str], rich: bool) -> str:
    """Строка «Ещё». В уровне B каждый пункт — ссылка на своё сообщение.

    Иван 08.10: в «Ещё» не хватало ссылок. Цель — только permalink
    источника (как у заголовка новости): адрес материала задаёт участник
    чата, и за подписью-заголовком его хост был бы не виден. Пункт без
    источника остаётся курсивом. Бюджет строки считается по видимому
    тексту: обрезка всей строки разрезала бы разметку ссылки."""
    if not rich:
        return clean("Ещё: " + "; ".join(title for title, _url in entries),
                     MORE_LINE_LIMIT)
    parts: List[str] = []
    room = MORE_LINE_LIMIT - len("Ещё: ")
    for title, url in entries:
        room -= 2 if parts else 0
        if room < 8:
            break
        label = clean(title, room)
        if not label:
            continue
        room -= len(label)
        parts.append(f"[{label}]({url})" if url else f"__{label}__")
        if label != title:
            break
    return "__Ещё:__ " + "; ".join(parts) if parts else ""


def _link_label(url: str) -> str:
    host = (urlsplit(url).hostname or "ссылка").lower()
    return host[4:] if host.startswith("www.") else host


def _inline_links(lines: List[str]) -> Tuple[List[str], List[str]]:
    """Строки ссылок уровня A → сегменты одной строки уровня B и адреса,
    которые безопасно ставить только отдельной строкой."""
    segments: List[str] = []
    loose: List[str] = []
    for line in lines:
        value = line.strip()
        if value.startswith("[Сообщение]("):
            segments.append(value)
            continue
        hidden = _HIDDEN_TAIL.match(value)
        if hidden:
            segments.append(f"__ещё {hidden.group('count')} {hidden.group('where')}__")
        elif value.lower().startswith(("http://", "https://")):
            if _INLINE_SAFE_URL.fullmatch(value):
                segments.append(f"[{_link_label(value)}]({value})")
            else:
                loose.append(value)
    return segments, loose


def _rich_news_lines(item: "_Item") -> List[str]:
    source = next((line for line in item.links if line.startswith("[Сообщение](")), None)
    materials = [line for line in item.links if line != source]
    if source:
        url = source[len("[Сообщение]("):-1]
        head = f"• [{item.title}]({url})"
    else:
        head = f"• {item.title}"
    segments, loose = _inline_links(materials)
    return [head + "".join(f" · {segment}" for segment in segments)] + loose


def _item_block(item: _Item, with_summaries: bool, rich: bool = False) -> str:
    marker = "⚡" if item.importance == "action" else ("▸" if item.kind == "topic" else "•")
    title = item.title
    if item.when is not None:
        day, hours = item.when
        if not _mentions_date(title, day):
            title += f" — {short_date(day)}"
        if hours and hours not in title:
            title += f", {hours}"
    keep_summary = with_summaries or item.importance in ("action", "high")
    summary = item.summary if keep_summary else ""
    if rich:
        # ▸ делает жирный; ⚡ остаётся сигналом действия, • — у ссылок.
        head = f"**{title}**"
        if marker != "▸":
            head = f"{marker} {head}"
        segments, loose = _inline_links(item.links)
        tail = "".join(f" · {segment}" for segment in segments)
        block = f"{head}\n{summary}{tail}" if summary else f"{head}{tail}"
        return "\n".join([block] + loose)
    lines = [f"{marker} {title}"]
    if summary:
        lines.append(summary)
    lines.extend(item.links)
    return "\n".join(lines)


def _importance(value: Any, default: str = "normal") -> str:
    return value if value in IMPORTANCE_RANK else default


def _chat_items(meta: ChatMeta, entry: Dict[str, Any], *, clean, topic_links,
                link_links, news_link, restore, ref_texts,
                more_link) -> Tuple[List[_Item], List[Tuple[str, Optional[str]]]]:
    names_key = meta.title
    items: List[_Item] = []
    topics = entry.get("topics") or []
    links = entry.get("links") or []
    for topic in topics:
        title = clean(restore(topic.get("title", ""), names_key), TITLE_LIMIT)
        if not title:
            continue
        refs = topic.get("refs") if isinstance(topic.get("refs"), list) else []
        topic_id = topic.get("id")
        items.append(_Item(
            kind="topic",
            importance=_importance(topic.get("importance")),
            title=title,
            summary=clean(restore(topic.get("summary", ""), names_key), SUMMARY_LIMIT),
            links=topic_links(topic),
            when=_when(topic.get("when"), ref_texts(refs)),
            topic_id=topic_id if isinstance(topic_id, str) and topic_id else None,
        ))
    for row in links:
        title = clean(restore(row.get("title", ""), names_key), TITLE_LIMIT)
        if not title:
            continue
        note = clean(restore(row.get("note", "") or "", names_key), NOTE_LIMIT)
        if meta.kind == "news":
            items.append(_Item("link", _importance(row.get("importance")),
                               title, "", news_link(row)))
        else:
            items.append(_Item(
                "link", _importance(row.get("importance")),
                title + (f" — {note}" if note else ""), "", link_links(row)))
    more_raw = entry.get("more")
    more: List[Tuple[str, Optional[str]]] = []
    if isinstance(more_raw, list):
        for value in more_raw[:MORE_MAX]:
            # С 08.10 мелочь — {text, ref}: номер сообщения даёт ссылку в
            # уровне B. Прежняя форма — строка без ссылки.
            ref = value.get("ref") if isinstance(value, dict) else None
            if isinstance(value, dict):
                value = value.get("text")
            text = clean(restore(value, names_key), MORE_ITEM_LIMIT) if isinstance(value, str) else ""
            if text:
                url = more_link(ref) if ref is not None else None
                more.append((text, url if url and _INLINE_SAFE_URL.fullmatch(url) else None))
    return items, more


def _lead_lines(lead: Any, topic_index: Dict[str, Optional[Tuple[ChatMeta, str]]],
                clean: Callable[[Any, int], str],
                restore: Callable[[Any, str], Any]) -> List[str]:
    if not isinstance(lead, list):
        return []
    lines: List[Tuple[int, int, str]] = []
    per_chat: Dict[str, int] = {}
    for row in lead:
        if len(lines) >= LEAD_MAX:
            break
        if not isinstance(row, dict):
            continue
        topic_id = row.get("topic_id")
        found = topic_index.get(topic_id) if isinstance(topic_id, str) else None
        # None в индексе — неоднозначный id; отсутствие — несуществующий.
        if found is None or found[1] not in ("action", "high"):
            continue
        meta = found[0]
        if per_chat.get(meta.title, 0) >= LEAD_PER_CHAT:
            continue
        text = (clean(restore(row.get("text"), meta.title), LEAD_LIMIT)
                if isinstance(row.get("text"), str) else "")
        if not text:
            continue
        per_chat[meta.title] = per_chat.get(meta.title, 0) + 1
        lines.append((IMPORTANCE_RANK[found[1]], len(lines), f"{meta.emoji} {text}"))
    # Порядок считает код: сначала действия, затем решения; внутри — как у модели.
    return [line for _rank, _index, line in sorted(lines)]
