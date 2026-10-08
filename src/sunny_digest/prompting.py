from __future__ import annotations

from typing import Dict, List, Optional

from .layout import markup_plain
from .models import DigestChat, SelectedMessage
from .storage import canonical_json_bytes
from .version import MAX_PROMPT_BYTES, PROMPT_VERSION


DIGEST_TARGET_UTF16_UNITS = 20_000
# Сколько материалов сообщения модель видит на выбор (ревью 0.2.22): строка
# промпта обязана оставаться ограниченной; остальные код просто посчитает.
MAX_PROMPT_MATERIALS = 20
PROMPT_PREFIX = (
    "Ты составляешь утренний дайджест профессиональных Telegram-чатов для "
    "одного человека. Он читает его с телефона: за 15 секунд должен понять, "
    "нужно ли что-то сделать сегодня, за минуту — весь день. Пиши по-русски.\n"
    "\n"
    "Каждое сообщение пронумеровано полем n. Ссылайся на источники ЭТИМИ "
    "номерами — ссылки, даты, дни недели, значки и порядок подставит код. "
    "Сам ссылок, эмодзи и дней недели не пиши.\n"
    "\n"
    "Отбор. Тема попадает в выпуск, если в ней есть решение или консенсус; "
    "просьба, на которую можно откликнуться; дата, срок или событие; сбой "
    "или изменение сервиса; содержательный материал (анонс, релиз, новость); "
    "спор с последствиями, даже незакрытый. Флуд, приветствия, «спасибо», "
    "мемы и оффтоп без итога отбрось. Одна ветка — одна тема, даже если в "
    "ней 40 сообщений. Не больше 4 тем на чат: лишнее помечай low.\n"
    "\n"
    "Поля темы:\n"
    "- title — 20–60 знаков, без точки, ИТОГ, а не тема: «CFO на seed: "
    "fractional до раунда A», а не «Обсуждение CFO». Нерешённое — с "
    "«решения нет». Цифры и имена, которые сами новость, — в заголовок.\n"
    "- summary — одна фраза до 120 знаков, только то, чего нет в title "
    "(особые мнения, условия, «по словам админа»). Пустая строка законна, "
    "если заголовок исчерпывает факт.\n"
    "- importance — action (дата в ближайшие 7 дней, сбой у читателя, "
    "прямая просьба, на которую он может ответить), high (решение клуба, "
    "починка сервиса, крупный анонс с датой), normal, low (мелочь).\n"
    "- state — resolved, open или info.\n"
    "- when — {\"date\": \"YYYY-MM-DD\", \"start\": \"HH:MM\", \"end\": "
    "\"HH:MM\"} ТОЛЬКО если абсолютная дата прямо написана в сообщениях; "
    "«в субботу» оставь словами в title, в when не превращай.\n"
    "- id — короткий идентификатор темы, уникальный на ВЕСЬ выпуск (не "
    "нумеруй темы заново в каждом чате).\n"
    "\n"
    "lead — «Главное»: 2–4 строки до 70 знаков на весь выпуск, каждая со "
    "ссылкой topic_id на тему action или high, сжато до «что мне с этого». "
    "Из одного чата — не больше двух. Нет action и high — пустой список.\n"
    "\n"
    "Ссылки и материалы. В links клади статьи, анонсы, релизы, вакансии: "
    "title — что это, note — одна фраза до 100 знаков, без перечня имён, "
    "ref — сообщение с материалом. Для новостного канала каждая новость — "
    "элемент links с title-фактом «Кто сделал что» до 70 знаков. У "
    "сообщения может быть список materials: номер i и подпись ссылки. "
    "Выбери не больше трёх ГЛАВНЫХ материалов (статья, страница события, "
    "видео, документ); профили людей, главные страницы компаний, Википедию "
    "и соцсети не бери. Для обсуждений обычно 0, для анонса — 1. Остальные "
    "код посчитает и сошлётся на сообщение.\n"
    "\n"
    "Правила:\n"
    "- Не выдумывай: нет довода — так и скажи («доводы в сообщении»), нет "
    "суммы — не называй её.\n"
    "- Числа, суммы, время, названия компаний и моделей — дословно.\n"
    "- Не пиши «обсуждали», «участники поделились», «было отмечено», "
    "«интересная дискуссия», оценок и советов читателю.\n"
    "- Людей называй ролью («админ», «организаторы», «двое участников»); "
    "телефонов, адресов и номеров квартир не пиши.\n"
    "- more — до трёх мелочей чата: text до 60 знаков и ref — номер "
    "сообщения, о котором мелочь.\n"
    "- Чат без важного — пустые topics и links. Пустой раздел лучше "
    "выдуманного.\n"
    f"- Общий объём — до {DIGEST_TARGET_UTF16_UNITS} UTF-16 единиц, цель — "
    "заметно короче.\n"
    "\n"
    "Верни ровно один JSON-объект:\n"
    '{"lead": [{"topic_id": "<id>", "text": "<главное>"}], '
    '"demoted_count": <сколько тем ты отбросил целиком и не вернул>, '
    '"chats": [{"chat": "<название как во входных данных>", '
    '"topics": [{"id": "<id>", "title": "<итог>", "summary": "<суть>", '
    '"importance": "action|high|normal|low", "state": "resolved|open|info", '
    '"when": null, "refs": [<n>], "materials": [{"n": <n>, "i": <i>}]}], '
    '"links": [{"title": "<что это>", "note": "<зачем>", "ref": <n>, '
    '"importance": "high|normal", "materials": [<i>]}], '
    '"more": [{"text": "<мелочь>", "ref": <n>}]}]}\n'
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
    if message.material_urls:
        # Только подписи — видимый текст сообщения; адреса остаются у
        # родителя (задача 235), выбранные по i подставляет код.
        labels = list(message.material_labels) or []
        row["materials"] = [
            {"i": index, "label": (labels[index - 1]
                                   if index <= len(labels) else "ссылка")}
            for index in range(
                1, min(len(message.material_urls), MAX_PROMPT_MATERIALS) + 1)
        ]
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


def digest_material_urls(chats: List[DigestChat]) -> Dict[int, List[str]]:
    """Те же сквозные n, что в промпте; URL остаются у родителя."""
    return {
        number: list(message.material_urls)
        for number, message in enumerate(
            (message for chat in chats for message in chat.messages), start=1)
        if message.material_urls
    }


def digest_message_texts(chats: List[DigestChat]) -> Dict[int, str]:
    """Тексты по тем же сквозным n — только для проверки дат из `when`."""
    return {
        number: message.text
        for number, message in enumerate(
            (message for chat in chats for message in chat.messages), start=1)
    }


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
            candidate_text, message.sender_name, message.material_urls,
            message.material_labels)
        if prompt_size([candidate]) <= MAX_PROMPT_BYTES:
            best = candidate_text
            low = middle + 1
        else:
            high = middle - 1
    if not best:
        raise ValueError("one Telegram message cannot fit the prompt budget")
    return SelectedMessage(
        message.message_id, message.sender_id, message.sent_at, best,
        message.sender_name, message.material_urls, message.material_labels)


# Хвост, которым выпуск честно сообщает, что его срезали. Обрезка бывает в
# двух местах — при сборке текста (потолок дайджеста) и перед выгрузкой
# (потолок приёмника), — и обе обязаны выглядеть для Ивана одинаково.
DIGEST_TRUNCATION_NOTE = "\n\n[выпуск обрезан по лимиту]"


# Пропуск, о котором выпуск обязан сказать вслух. Курсор чата подтягивается к
# нижней границе выпуска, и хвост старше неё в текст не попадает. У чата,
# впервые вошедшего в набор, это его прежняя история — так и задумано. Но у
# живого чата тем же способом может исчезнуть переписка, не влезшая в бюджет
# промпта и провисевшая дольше окна, а тихий скип и есть тот отказ, который
# потом ищут неделями: в wire пропуск не виден вовсе (диапазон объявляется от
# курсора приёмника), в статусе его тоже нет.
DIGEST_SKIP_NOTE_HEAD = "[пропущено старше окна выпуска]"


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def digest_skip_note(rows: List[tuple]) -> str:
    """Строка предупреждения о хвосте, который выпуск не стал читать.

    Это границы Telegram message ID, а не счётчик содержательных сообщений:
    в диапазоне могут быть service/пустые/удалённые записи и дыры ID.
    """
    lines = [DIGEST_SKIP_NOTE_HEAD]
    for title, first, last in rows:
        # Название задаёт админ группы; в выпуске уровня B заметка рендерится
        # v3, и «> Срочно» стало бы цитатой (второе ревью 06.10).
        lines.append(f"{markup_plain(title)}: диапазон ID {first}–{last}")
    return "\n".join(lines)


def prepend_digest_note(digest: str, note: str, limit: int) -> str:
    """Поставить предупреждение ПЕРЕД выпуском, уложившись в потолок.

    Впереди — потому что срезается всегда хвост: предупреждение о пропаже
    не имеет права исчезнуть раньше самого выпуска."""
    text = f"{note}\n\n{digest}" if digest else note
    if _utf16_units(text) <= limit:
        return text
    fitted = fit_by_lines(text, _utf16_units, limit)
    if fitted is None:
        raise ValueError("digest skip note does not fit")
    return fitted


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
