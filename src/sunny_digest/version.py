APP_VERSION = "0.2.12"
COLLECTOR_VERSION = "0.2.1"
PROMPT_VERSION = "personal-chats-digest-v3"
STATUS_REQUEST_SCHEMA = "sunny.personal-chats.status-request.v2"
GATE_SCHEMA = "sunny.personal-chats.status-gate.v2"
MONITOR_UPLOAD_SCHEMA = "sunny.personal-chats.monitor.v2"
DIGEST_UPLOAD_SCHEMA = "sunny.personal-chats.digest.v2"
RECEIPT_SCHEMA = "sunny.personal-chats.receipt.v2"
# Верхняя граница потолка, который приёмник объявляет в gate. Само
# приложение шлёт ровно столько, сколько разрешил gate, а эта
# константа лишь позволяет принять больший потолок, когда приёмник
# его поднимет вторым шагом выката.
MAX_UPLOAD_BYTES = 128 * 1024
MAX_PROMPT_BYTES = 96 * 1024
# Выпуск делится на несколько сообщений уже в Sunny, поэтому предел
# здесь — не лимит одного сообщения Telegram, а потолок сути за сутки.
MAX_DIGEST_CHARS = 24_000
MAX_SCAN_MESSAGES = 1_000
MAX_SELECTED_CHATS = 16
MAX_MENTION_EVENTS = 10
MAX_MENTION_SNIPPET_UTF16 = 300
DEFAULT_LOOKBACK_HOURS = 72
