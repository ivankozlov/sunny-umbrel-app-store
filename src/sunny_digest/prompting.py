from __future__ import annotations

from typing import Dict, List, Optional

from .models import DigestChat, SelectedMessage
from .storage import canonical_json_bytes
from .version import MAX_PROMPT_BYTES, PROMPT_VERSION


DIGEST_TARGET_UTF16_UNITS = 20_000
PROMPT_PREFIX = (
    "Ты составляешь ежедневный дайджест профессиональных Telegram-чатов для "
    "одного человека. Он не успевает читать их сам и не хочет пропустить "
    "важное. Пиши по-русски.\n"
    "\n"
    "Каждое сообщение пронумеровано полем n. Ссылайся на источники ЭТИМИ "
    "номерами — ссылки подставит код, сам ссылок не пиши.\n"
    "\n"
    "Что делать:\n"
    "1. Раздели содержательные обсуждения по темам. Для каждой темы дай "
    "суть: о чём спорили, к чему пришли, какие аргументы прозвучали, что "
    "осталось открытым. Пиши так, чтобы читавший понял позицию сторон без "
    "исходной переписки. Одна тема — один блок, даже если она обсуждалась "
    "в разных местах чата.\n"
    "2. Отдельно собери статьи, ссылки, анонсы, вакансии и прочую "
    "фактическую информацию: что это и зачем смотреть.\n"
    "3. Отбрось флуд, мемы, реакции, приветствия, спам и перепалки без "
    "содержания. Лучше короткий честный дайджест, чем раздутый.\n"
    "\n"
    "Правила:\n"
    "- Не выдумывай ничего, чего нет в сообщениях. Домыслы недопустимы.\n"
    "- Не пересказывай дословно: сжимай, но сохраняй конкретику — числа, "
    "даты, названия, решения, договорённости.\n"
    "- Если в чате за сутки не было ничего стоящего, верни для него пустые "
    "списки. Пустой раздел лучше выдуманного.\n"
    f"- Общий объём — до {DIGEST_TARGET_UTF16_UNITS} UTF-16 единиц.\n"
    "\n"
    "Верни ровно один JSON-объект:\n"
    '{"chats": [{"chat": "<название как во входных данных>", '
    '"topics": [{"title": "<тема>", "summary": "<суть>", "refs": [<n>]}], '
    '"links": [{"title": "<что это>", "note": "<зачем>", "ref": <n>}]}]}\n'
    f"Prompt version: {PROMPT_VERSION}.\n"
)
# Инструкция входит в бюджет КАЖДОГО чата (`prompt_size` считает её
# вместе со строками), поэтому делящий бюджет обязан вычесть её один
# раз и прибавить к доле каждого чата — иначе N чатов оплатят её N раз.
PROMPT_PREFIX_BYTES = len(PROMPT_PREFIX.encode("utf-8"))


def message_row_bytes(message: SelectedMessage, sender_label: str,
                      chat_title: Optional[str] = None,
                      number: Optional[int] = None) -> bytes:
    row = {
        # Numeric Telegram sender/message IDs are not needed by the model.
        # An encounter-order alias preserves conversational attribution without
        # exporting stable account identifiers to OpenRouter.
        "sender": sender_label,
        "sent_at": message.sent_at.isoformat(),
        "text": message.text,
    }
    if number is not None:
        # Порядковый номер в этом прогоне, НЕ Telegram message_id: модель
        # ссылается им на источник, а ссылку собирает код.
        row["n"] = number
    if chat_title is not None:
        row["chat"] = chat_title
    return canonical_json_bytes(row)


# Строка выпуска несёт порядковый номер `n`, но отбирающий сообщения gateway
# сквозной нумерации не знает — он считает бюджет по одному чату. Поэтому в
# оценке номер берётся заведомо самый длинный: недосчитанные байты вылезли бы
# за MAX_PROMPT_BYTES уже после отбора, и весь суточный дайджест падал бы на
# `prompt exceeds bounded input size`.
NUMBER_BUDGET_SENTINEL = 9_999_999


def _sender_labels(messages: List[SelectedMessage]) -> List[str]:
    labels: Dict[Optional[int], str] = {}
    result = []
    for message in messages:
        if message.sender_id not in labels:
            labels[message.sender_id] = f"participant-{len(labels) + 1}"
        result.append(labels[message.sender_id])
    return result


def _rows(messages: List[SelectedMessage], chat_title: Optional[str] = None) -> List[bytes]:
    rows = []
    for message, sender_label in zip(messages, _sender_labels(messages)):
        rows.append(message_row_bytes(
            message, sender_label, chat_title,
            NUMBER_BUDGET_SENTINEL,
        ))
    return rows


def prompt_size(messages: List[SelectedMessage], chat_title: Optional[str] = None) -> int:
    rows = _rows(messages, chat_title)
    return len(PROMPT_PREFIX.encode("utf-8")) + sum(map(len, rows)) + max(0, len(rows) - 1)


def render_prompt(messages: List[SelectedMessage]) -> str:
    rows = _rows(messages)
    raw = PROMPT_PREFIX.encode("utf-8") + b"\n".join(rows)
    if len(raw) > MAX_PROMPT_BYTES:
        raise ValueError("prompt exceeds bounded input size")
    return raw.decode("utf-8")


def digest_sources(chats: List[DigestChat]) -> Dict[int, str]:
    """Номер сообщения в прогоне → ссылка на него.

    Нумерация сквозная по всем чатам и строится ТЕМ ЖЕ обходом, что и промпт,
    поэтому номер, названный моделью, указывает ровно на то сообщение, которое
    она видела. Чат без префикса (не супергруппа) ссылок не даёт — тогда пункт
    останется без источника, а не получит чужой."""
    sources: Dict[int, str] = {}
    number = 0
    for chat in chats:
        for message in chat.messages:
            number += 1
            if chat.link_prefix:
                sources[number] = f"{chat.link_prefix}/{message.message_id}"
    return sources


def digest_sender_names(chats: List[DigestChat]) -> Dict[str, Dict[str, str]]:
    """Название чата → однозначные participant-N → display name.

    Алиасы строятся тем же обходом, что и промпт. Неизвестное имя, смена
    display name внутри окна или одинаковые названия разных чатов оставляют
    псевдоним как есть: неверная атрибуция хуже менее красивого текста.
    """
    by_title: Dict[str, Dict[str, str]] = {}
    ambiguous_titles = set()
    for chat in chats:
        candidates: Dict[str, set[str]] = {}
        for message, sender_label in zip(
                chat.messages, _sender_labels(chat.messages)):
            if message.sender_name:
                candidates.setdefault(sender_label, set()).add(
                    message.sender_name)
        names = {
            label: next(iter(values))
            for label, values in candidates.items()
            if len(values) == 1
        }
        previous = by_title.get(chat.title)
        if previous is not None and previous != names:
            ambiguous_titles.add(chat.title)
        else:
            by_title[chat.title] = names
    for title in ambiguous_titles:
        by_title.pop(title, None)
    return by_title


def render_digest_prompt(chats: List[DigestChat]) -> str:
    rows: List[bytes] = []
    number = 0
    for chat in chats:
        for message, sender_label in zip(
                chat.messages, _sender_labels(chat.messages)):
            number += 1
            rows.append(message_row_bytes(
                message, sender_label, chat.title, number,
            ))
    raw = PROMPT_PREFIX.encode("utf-8") + b"\n".join(rows)
    if len(raw) > MAX_PROMPT_BYTES:
        raise ValueError("prompt exceeds bounded input size")
    return raw.decode("utf-8")


def truncate_first_to_budget(message: SelectedMessage) -> SelectedMessage:
    """Fit one anomalously large Telegram row without persisting its raw body."""
    if prompt_size([message]) <= MAX_PROMPT_BYTES:
        return message
    suffix = "\n[обрезано]"
    low, high = 0, len(message.text)
    best = ""
    while low <= high:
        middle = (low + high) // 2
        candidate_text = message.text[:middle].rstrip() + suffix
        candidate = SelectedMessage(
            message.message_id, message.sender_id, message.sent_at,
            candidate_text, message.sender_name)
        if prompt_size([candidate]) <= MAX_PROMPT_BYTES:
            best = candidate_text
            low = middle + 1
        else:
            high = middle - 1
    if not best:
        raise ValueError("one Telegram message cannot fit the prompt budget")
    return SelectedMessage(
        message.message_id, message.sender_id, message.sent_at, best,
        message.sender_name)


# Хвост, которым выпуск честно сообщает, что его срезали. Обрезка бывает в
# двух местах — при сборке текста (потолок дайджеста) и перед выгрузкой
# (потолок приёмника), — и обе обязаны выглядеть для Ивана одинаково.
DIGEST_TRUNCATION_NOTE = "\n\n[выпуск обрезан по лимиту]"


def fit_by_lines(text: str, size_of, limit: int) -> Optional[str]:
    """Наибольший префикс текста по строкам, влезающий в limit, с пометкой.

    Режем по строкам, а не по символам: строка здесь — заголовок, абзац или
    ссылка, и обрыв на полуслове дал бы обрубок вместо источника. Поиск
    двоичный — размер монотонен по числу строк. None означает, что не влезла
    даже первая строка: это отказ, а не пустой выпуск."""
    lines = text.split("\n")
    low, high = 1, len(lines)
    best: Optional[str] = None
    while low <= high:
        middle = (low + high) // 2
        candidate = "\n".join(lines[:middle]).rstrip() + DIGEST_TRUNCATION_NOTE
        if size_of(candidate) <= limit:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    return best
