from __future__ import annotations

from typing import Dict, List, Optional

from .models import SelectedMessage
from .storage import canonical_json_bytes
from .version import MAX_PROMPT_BYTES, PROMPT_VERSION


DIGEST_TARGET_UTF16_UNITS = 3_400
PROMPT_PREFIX = (
    "Create a concise Russian-language daily digest of these messages. "
    "Preserve concrete decisions, action items, dates and links. Do not add "
    "facts that are absent. The digest must be at most "
    f"{DIGEST_TARGET_UTF16_UNITS} UTF-16 code units. Return exactly one JSON object "
    "with one string field named digest. "
    f"Prompt version: {PROMPT_VERSION}.\n"
)


def message_row_bytes(message: SelectedMessage, sender_label: str) -> bytes:
    return canonical_json_bytes({
        # Numeric Telegram sender/message IDs are not needed by the model.
        # An encounter-order alias preserves conversational attribution without
        # exporting stable account identifiers to OpenRouter.
        "sender": sender_label,
        "sent_at": message.sent_at.isoformat(),
        "text": message.text,
    })


def _rows(messages: List[SelectedMessage]) -> List[bytes]:
    labels: Dict[Optional[int], str] = {}
    rows = []
    for message in messages:
        if message.sender_id not in labels:
            labels[message.sender_id] = f"participant-{len(labels) + 1}"
        rows.append(message_row_bytes(message, labels[message.sender_id]))
    return rows


def prompt_size(messages: List[SelectedMessage]) -> int:
    rows = _rows(messages)
    return len(PROMPT_PREFIX.encode("utf-8")) + sum(map(len, rows)) + max(0, len(rows) - 1)


def render_prompt(messages: List[SelectedMessage]) -> str:
    rows = _rows(messages)
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
            message.message_id, message.sender_id, message.sent_at, candidate_text)
        if prompt_size([candidate]) <= MAX_PROMPT_BYTES:
            best = candidate_text
            low = middle + 1
        else:
            high = middle - 1
    if not best:
        raise ValueError("one Telegram message cannot fit the prompt budget")
    return SelectedMessage(message.message_id, message.sender_id, message.sent_at, best)
