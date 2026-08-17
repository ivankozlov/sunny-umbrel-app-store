from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import secrets
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs

from .storage import canonical_json_bytes


MAX_HTTP_BODY_BYTES = 64 * 1024
MAX_IPC_BYTES = 512 * 1024
IPC_CONNECT_TIMEOUT_S = 5
IPC_SEND_TIMEOUT_S = 5
IPC_RESPONSE_TIMEOUT_S = 150
CSRF_COOKIE = "sunny_csrf"


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _one(form: Dict[str, list[str]], key: str) -> str:
    values = form.get(key)
    if not values or len(values) != 1:
        raise ValueError("form field is missing or repeated")
    return values[0]


class IPCClient:
    def __init__(self, socket_path: str, *,
                 connect_timeout: float = IPC_CONNECT_TIMEOUT_S,
                 send_timeout: float = IPC_SEND_TIMEOUT_S,
                 response_timeout: float = IPC_RESPONSE_TIMEOUT_S):
        self.socket_path = socket_path
        self.connect_timeout = connect_timeout
        self.send_timeout = send_timeout
        self.response_timeout = response_timeout

    def request(self, command: str, data: Any = None) -> Dict[str, Any]:
        request: Dict[str, Any] = {"command": command}
        if data is not None:
            request["data"] = data
        raw = canonical_json_bytes(request) + b"\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.connect_timeout)
            connection.connect(self.socket_path)
            connection.settimeout(self.send_timeout)
            connection.sendall(raw)
            connection.settimeout(self.response_timeout)
            with connection.makefile("rb") as stream:
                response_raw = stream.readline(MAX_IPC_BYTES + 1)
        if (not response_raw or len(response_raw) > MAX_IPC_BYTES
                or not response_raw.endswith(b"\n")):
            raise RuntimeError("collector response is unavailable")
        try:
            response = json.loads(response_raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise RuntimeError("collector response is invalid") from None
        if not isinstance(response, dict) or set(response) not in (
                {"ok", "result"}, {"ok", "error_type"}):
            raise RuntimeError("collector response shape is invalid")
        if response.get("ok") is not True:
            error_type = response.get("error_type")
            if not isinstance(error_type, str) or len(error_type) > 80:
                error_type = "CollectorError"
            raise RuntimeError(error_type)
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("collector result is invalid")
        return result


def _layout(content: str, csrf: str, notice: str = "") -> bytes:
    notice_html = f'<div class="notice">{_escape(notice)}</div>' if notice else ""
    reset_html = f"""<details class="reset"><summary>Factory reset / отзыв доступа</summary>
  <form method="post">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="reset">
    <label class="check"><input type="checkbox" name="confirm_reset" value="yes" required>Остановить локальные операции, попытаться завершить Telegram-сессию и удалить все локальные credentials. Если Telegram не подтвердит logout, новая настройка будет заблокирована до ручного завершения устройства.</label>
    <button class="danger" type="submit">Отозвать и удалить</button>
  </form></details>"""
    document = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sunny Personal Chats</title>
  <style>
    :root {{ color-scheme: dark; --ink:#eef3ff; --muted:#97a7c7; --line:#2a3650;
      --panel:rgba(19,27,44,.88); --accent:#ffbd38; --accent2:#ff7a45; }}
    * {{ box-sizing:border-box }}
    body {{ margin:0; min-height:100vh; color:var(--ink); font:15px/1.55 system-ui,sans-serif;
      background:radial-gradient(circle at 12% 0,#243763 0,transparent 34%),
      radial-gradient(circle at 100% 90%,#4d2635 0,transparent 33%),#090f1b; }}
    main {{ width:min(780px,calc(100% - 28px)); margin:40px auto; }}
    .brand {{ display:flex; align-items:center; gap:15px; margin-bottom:24px }}
    .sun {{ width:54px;height:54px;border-radius:18px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      box-shadow:0 12px 35px #ff8c3344; position:relative }}
    .sun:after {{ content:"";position:absolute;inset:16px;border-radius:50%;background:#fff7d1 }}
    h1 {{ font-size:28px;line-height:1.15;margin:0 }} h2 {{ font-size:21px;margin:0 0 8px }}
    p {{ margin:7px 0 16px }} .muted {{ color:var(--muted) }}
    .card {{ border:1px solid var(--line);border-radius:20px;padding:24px;
      background:var(--panel);box-shadow:0 24px 70px #0007;backdrop-filter:blur(12px) }}
    .notice {{ border:1px solid #875f24;background:#3a2b18;color:#ffe3a3;padding:11px 14px;
      border-radius:12px;margin-bottom:16px }}
    form {{ display:grid;gap:15px;margin-top:20px }}
    label {{ display:grid;gap:6px;color:#c9d5ec;font-weight:650 }}
    input,textarea,select {{ width:100%;border:1px solid #40506f;border-radius:11px;padding:11px 12px;
      color:var(--ink);background:#0d1525;font:inherit }} textarea {{ min-height:94px;resize:vertical }}
    input:focus,textarea:focus,select:focus {{ outline:2px solid #ffbd3866;border-color:var(--accent) }}
    button {{ justify-self:start;border:0;border-radius:12px;padding:11px 17px;font:700 15px system-ui;
      color:#18120a;background:linear-gradient(135deg,var(--accent),var(--accent2));cursor:pointer }}
    button.secondary {{ color:var(--ink);background:#283652 }} button.danger {{ color:white;background:#9b3346 }}
    .row {{ display:flex;gap:10px;flex-wrap:wrap }} .row form {{ display:block;margin:0 }}
    dl {{ display:grid;grid-template-columns:minmax(135px,.45fr) 1fr;gap:9px 17px;margin:20px 0 }}
    dt {{ color:var(--muted) }} dd {{ margin:0;overflow-wrap:anywhere }}
    code {{ display:block;padding:12px;border-radius:10px;background:#09101d;color:#d7e5ff;
      white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px }}
    .lock {{ display:inline-flex;align-items:center;gap:7px;border:1px solid #406047;border-radius:999px;
      color:#b9ecc5;background:#14291b;padding:5px 10px;font-size:13px }}
    .warn {{ border-left:3px solid var(--accent2);padding-left:13px;color:#ffd7c8 }}
    .reset {{ margin-top:22px;border-top:1px solid var(--line);padding-top:15px;color:var(--muted) }}
    .reset summary {{ cursor:pointer }}
    .check {{ display:flex;grid-template-columns:none;align-items:flex-start;gap:9px;font-weight:500 }}
    .check input {{ width:auto;margin-top:5px }}
    footer {{ color:#6f809e;text-align:center;margin:18px 0;font-size:12px }}
    @media(max-width:560px) {{ main{{margin:22px auto}} .card{{padding:18px}} dl{{grid-template-columns:1fr;gap:2px}} dd{{margin-bottom:9px}} }}
  </style>
</head>
<body><main>
  <div class="brand"><div class="sun" aria-hidden="true"></div><div>
    <h1>Sunny Personal Chats</h1><div class="muted">1–16 выбранных чатов · локальная Telegram-сессия</div>
  </div></div>
  {notice_html}<section class="card">{content}{reset_html}</section>
  <footer>Сырые сообщения дайджеста не сохраняются. Финальный mention-фрагмент до 300 UTF-16, название чата, отправитель и ссылка durably передаются в Sunny. Setup credentials и VPN subscription URL проходят через web только транзитом.</footer>
</main></body></html>"""
    return document.encode("utf-8")


def _hidden_csrf(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{_escape(csrf)}">'


def _render_recent_runs(rows: Any) -> str:
    """Журнал последних прогонов: время, исход, тип ошибки, счётчики.

    Статус описывает только последний тик и перезаписывается каждую минуту,
    поэтому редкая ошибка исчезала раньше, чем её успевали увидеть. Здесь
    всё служебное и ничего из переписки: тексты, имена чатов и отправители
    сюда не попадают by design. Значения санитизируются так же строго, как
    остальные поля статуса — они приходят по IPC от collector'а."""
    if not isinstance(rows, list) or not rows:
        return ""
    items = []
    for row in rows[-20:]:
        if not isinstance(row, dict):
            continue
        result = row.get("result")
        result = (result if isinstance(result, str)
                  and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", result)
                  else "unknown")
        error = row.get("error_type")
        error = (error if isinstance(error, str)
                 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error)
                 else None)
        at = row.get("at")
        # Валидируем формой, а не длиной: произвольная 19-символьная строка
        # печаталась бы как время. Смещение сохраняем — окно дайджеста задано
        # в локальном времени, и «03:05» без пояса читается неоднозначно.
        at = (at[:25] if isinstance(at, str)
              and re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", at)
              else "—")
        repeated = row.get("repeated")
        repeated = f" ×{int(repeated)}" if isinstance(repeated, int) and repeated > 1 else ""
        failed = row.get("failed_chat_count")
        failed = f", ошибок peer: {int(failed)}" if isinstance(failed, int) and failed else ""
        suffix = f" — {_escape(error)}" if error else ""
        items.append(
            f"<li><code>{_escape(at)}</code> {_escape(result)}{_escape(repeated)}"
            f"{suffix}{_escape(failed)}</li>")
    if not items:
        return ""
    return ("<details><summary>Журнал прогонов</summary><ul class=\"runs\">"
            + "".join(items) + "</ul></details>")


def _safe_failure_notice(status: Dict[str, Any], exc: Exception) -> str:
    # IPC only exposes a bounded exception class name; never reflect its message.
    error_type = (
        str(exc)
        if isinstance(exc, RuntimeError)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", str(exc))
        else type(exc).__name__
    )
    phase = status.get("phase")
    if phase == "authenticated" and error_type == "ValueError":
        return (
            "Проверьте ссылки: HTTPS t.me, по одной ссылке на сообщение в строке, "
            "без повторов и comment-ссылок."
        )
    if phase == "fresh" and error_type in ("ValueError", "SubscriptionFetchError"):
        return (
            "Проверьте поля настройки и VLESS/REALITY subscription URL. "
            "Секретные детали ответа провайдера намеренно скрыты."
        )
    if phase == "chat_locked" and error_type in (
            "ValueError", "SubscriptionFetchError"):
        return (
            "Проверьте новый VLESS/REALITY subscription URL и подтверждение. "
            "Секретные детали ответа провайдера намеренно скрыты."
        )
    if phase == "dialogs_listed" and error_type == "ValueError":
        return "Подтверждение набора устарело или повреждено. Обновите страницу."
    return f"Операция не выполнена ({error_type})."


def render_status(status: Dict[str, Any], csrf: str) -> str:
    phase = status.get("phase")
    if status.get("vpn_migration_required"):
        return """
<h2>Требуется новая настройка VPN</h2>
<p>Эта конфигурация создана версией без обязательного VLESS/REALITY-туннеля.
Telegram-действия заблокированы: прямого подключения приложение не выполняет.</p>
<p class="warn">Выполните factory reset, при необходимости завершите устройство
Sunny Umbrel в Telegram → Settings → Devices, затем настройте приложение заново
и введите subscription URL только в скрытом поле Umbrel.</p>"""
    if phase == "fresh":
        revocation = ""
        if status.get("revocation_required"):
            revocation = f"""
<div class="notice"><strong>Telegram logout не подтверждён.</strong><br>
Немедленно откройте Telegram → Settings → Devices и завершите устройство <strong>Sunny Umbrel</strong>.
Новая настройка заблокирована, пока вы явно не подтвердите ручной отзыв.</div>
<form method="post">{_hidden_csrf(csrf)}
  <input type="hidden" name="action" value="ack_manual_revocation">
  <label class="check"><input type="checkbox" name="confirm_manual_revocation" value="yes" required>Я вручную завершил устройство Sunny Umbrel в Telegram.</label>
  <button class="danger" type="submit">Подтвердить ручной отзыв</button>
</form>"""
        if revocation:
            return f"""
<h2>Требуется ручной отзыв Telegram-сессии</h2>
{revocation}
<p class="muted">Поля новой конфигурации появятся только после подтверждения.</p>"""
        return f"""
<h2>Безопасная первичная настройка</h2>
<p class="muted">Данные уйдут по Unix-сокету прямо в изолированный collector. После выбора групп изменить их можно только полным сбросом.</p>
<form method="post" autocomplete="off">{_hidden_csrf(csrf)}
  <input type="hidden" name="action" value="configure">
  <label>Telegram API ID<input name="telegram_api_id" inputmode="numeric" required></label>
  <label>Telegram API hash<input name="telegram_api_hash" type="password" required autocomplete="new-password"></label>
  <label>VLESS/REALITY subscription URL<input name="vpn_subscription_url" type="password" inputmode="url" required autocomplete="new-password"></label>
  <p class="muted">Ссылка используется один раз и не сохраняется. Ответ может быть списком share-ссылок или Clash YAML; Collector хранит только очищенный VLESS/REALITY TCP/Vision-узел. После фиксации групп маршрут можно заменить без сброса Telegram-сессии и выбранных чатов.</p>
  <label>OpenRouter API key<input name="openrouter_api_key" type="password" required autocomplete="new-password"></label>
  <label>OpenRouter model<input name="openrouter_model" placeholder="provider/model" required></label>
  <label>Sunny receiver host<input name="upload_host" placeholder="sunny.example.net" required></label>
  <label>SSH port<input name="upload_port" inputmode="numeric" value="22" required></label>
  <p class="muted">SSH login фиксирован: <strong>root</strong>. Серверный forced command сразу понижает права до dedicated receiver user.</p>
  <label>Точная строка pinned known_hosts<textarea name="known_host" spellcheck="false" placeholder="host ssh-ed25519 AAAA…" required></textarea></label>
  <label>Согласие действует до (ISO 8601)<input name="consent_expires_at" placeholder="2026-10-01T00:00:00Z" required></label>
  <label class="check"><input type="checkbox" name="confirm_data_scope" value="yes" required>Разрешаю читать текст только выбранных групп для одного дневного запроса в ZDR OpenRouter; durably отправлять в Sunny native mention с названием чата, отправителем, ссылкой и фрагментом до 300 UTF-16; после durable ACK помечать просмотренные сообщения и mentions прочитанными в Telegram.</label>
  <p class="warn">Завершите вход и выбор групп в течение часа. Рестарт collector’а до фиксации групп потребует factory reset и нового входа.</p>
  <p class="warn">Не используйте общий OpenRouter-ключ. Создайте отдельный ключ с небольшим лимитом.</p>
  <button type="submit">Сохранить и продолжить</button>
</form>"""
    if (phase in (
            "configured", "code_sent", "password_required", "authenticated",
            "resolving_links", "dialogs_listed") and not status.get("consent_active")):
        return """
<h2>Согласие истекло</h2>
<p>Настройка и чтение Telegram заблокированы. Выполните factory reset,
затем настройте приложение заново с новым сроком согласия.</p>"""
    if phase == "configured":
        return f"""
<h2>Вход в Telegram</h2><p class="muted">Telegram пришлёт код в уже авторизованное приложение.</p>
<form method="post" autocomplete="off">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="send_code">
  <label>Телефон в международном формате<input name="phone" type="tel" placeholder="+15555550123" required autocomplete="tel"></label>
  <button type="submit">Получить код</button>
</form>"""
    if phase == "code_sent":
        phone = _escape(status.get("phone_masked") or "+***")
        return f"""
<h2>Введите код Telegram</h2><p class="muted">Код отправлен на {phone}. Он не сохраняется.</p>
<form method="post" autocomplete="off">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="submit_code">
  <label>Код<input name="code" inputmode="numeric" pattern="[0-9]+" required autocomplete="one-time-code"></label>
  <button type="submit">Подтвердить</button>
</form>"""
    if phase == "password_required":
        return f"""
<h2>Двухэтапная аутентификация</h2><p class="muted">Пароль передаётся только collector’у и не сохраняется.</p>
<form method="post" autocomplete="off">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="submit_password">
  <label>Пароль Telegram 2FA<input name="password" type="password" required autocomplete="current-password"></label>
  <button type="submit">Завершить вход</button>
</form>"""
    if phase == "authenticated":
        return f"""
<h2>Выбор групп по ссылкам</h2>
<p>Скопируйте ссылку на любое сообщение из каждой нужной группы. Одна ссылка — одна строка, от 1 до 16 строк.</p>
<p class="muted">Поддерживаются обычные публичные и приватные ссылки <strong>t.me</strong>, включая сообщения в forum topics; ссылка на comment в связанной группе не поддерживается. Старые basic groups без ссылки на сообщение выбрать нельзя.</p>
<p class="muted">Для точной привязки выполняется одна setup-операция: Telegram постранично возвращает до 500 последних диалогов, включая последние сообщения в ответах API. Collector использует только peer и название группы, не открывает указанное сообщение отдельно и не сохраняет ссылки или полученные тексты.</p>
<p class="warn">Попытка проверки однократна, даже если сеть оборвётся. Повтор и смена набора потребуют отзыва сессии и полного factory reset.</p>
<form method="post">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="resolve_chat_links">
  <label>Ссылки на сообщения<textarea name="chat_links" spellcheck="false" placeholder="https://t.me/c/1234567890/42&#10;https://t.me/my_group/314" required></textarea></label>
  <button type="submit">Проверить ссылки</button>
</form>"""
    if phase == "resolving_links":
        return """
<h2>Однократная проверка ссылок не завершена</h2>
<p>Collector уже начал получать список диалогов Telegram, но не зафиксировал полный результат. Повторный запрос заблокирован, чтобы не читать список второй раз.</p>
<p class="warn">Выполните factory reset, завершите старое устройство Sunny Umbrel в Telegram и начните настройку заново.</p>"""
    if phase == "dialogs_listed":
        selection_id = _escape(status.get("selection_id") or "")
        options = []
        for row in status.get("dialogs") or []:
            if not isinstance(row, dict):
                continue
            label = f'{row.get("title", "Без названия")} · {row.get("kind", "peer")}'
            options.append(f'<label class="check"><input type="checkbox" name="chat_id" value="{_escape(row.get("chat_id", ""))}" checked>{_escape(label)}</label>')
        return f"""
<h2>Проверьте найденные группы</h2>
<p class="muted">Снимите галочку, если группа не нужна. После подтверждения список будет удалён, а endpoint, модель и все credentials станут неизменяемыми.</p>
<form method="post">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="select_chats">
  <input type="hidden" name="selection_id" value="{selection_id}">
  <div><strong>От 1 до 16 групп</strong>{''.join(options)}</div>
  <label class="check"><input type="checkbox" name="confirm_lock" value="yes" required>Я понимаю, что смена набора групп потребует factory reset и нового входа в Telegram.</label>
  <button type="submit">Зафиксировать группы и создать upload key</button>
</form>"""
    if phase == "chat_locked":
        result = _escape(status.get("last_result") or "ещё не запускался")
        error_value = status.get("last_error_type")
        error = (
            error_value
            if isinstance(error_value, str)
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_value)
            else "CollectorError" if error_value else None
        )
        error_row = f'<dt>Последняя ошибка</dt><dd>{_escape(error)}</dd>' if error else ""
        recent_rows = _render_recent_runs(status.get("recent_runs"))
        repair_state_value = status.get("vpn_repair_state")
        repair_state = (
            repair_state_value
            if isinstance(repair_state_value, str)
            and repair_state_value in {
                "idle", "fetching", "waiting_for_run", "testing",
                "succeeded", "failed",
            }
            else "unavailable"
        )
        repair_attempted_value = status.get("vpn_repair_attempted")
        repair_attempted = (
            repair_attempted_value
            if isinstance(repair_attempted_value, int)
            and not isinstance(repair_attempted_value, bool)
            and 0 <= repair_attempted_value <= 999
            else 0
        )
        repair_error_value = status.get("vpn_repair_error_type")
        repair_error = (
            repair_error_value
            if isinstance(repair_error_value, str)
            and re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_]{0,79}", repair_error_value)
            else "CollectorError" if repair_error_value else "—"
        )
        consent = "активно" if status.get("consent_active") else "истекло"
        chats = "<br>".join(
            f'{_escape(row.get("title"))} <span class="muted">({_escape(row.get("chat_id"))})</span>'
            for row in status.get("chats") or [] if isinstance(row, dict)
        ) or "—"
        activation = ""
        if status.get("activation_required"):
            activation = f"""
<div class="notice"><strong>Нужно отдельное включение.</strong><br>
Первый запуск durably запишет baseline в Sunny, затем пометит все старые unread и mentions выбранных групп прочитанными. Старые mentions не будут отправлены. Только после этого начнётся минутный watcher.</div>
<form method="post">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="activate_monitoring">
  <label class="check"><input type="checkbox" name="confirm_activation" value="yes" required>Включить мониторинг и очистить текущие старые unread/mentions после durable baseline ACK.</label>
  <button type="submit">Включить мониторинг</button>
</form>"""
        return f"""
<div class="lock">● Группы зафиксированы</div><h2 style="margin-top:14px">Collector готов</h2>
<dl>
  <dt>Группы</dt><dd>{chats}</dd>
  <dt>Source ID</dt><dd>{_escape(status.get("source_id"))}</dd>
  <dt>Мониторинг</dt><dd>{_escape(status.get("monitoring_phase") or "не включён")}</dd>
  <dt>Модель</dt><dd>{_escape(status.get("model") or "зафиксирована")}</dd>
  <dt>Receiver</dt><dd>{_escape(status.get("upload_target") or "зафиксирован")}</dd>
  <dt>Согласие</dt><dd>{consent} · до {_escape(status.get("consent_expires_at") or "—")}</dd>
  <dt>Pending monitor</dt><dd>{"да" if status.get("pending_monitor_upload") else "нет"}</dd>
  <dt>Pending digest</dt><dd>{"да" if status.get("pending_digest_upload") else "нет"}</dd>
  <dt>Ошибки peer</dt><dd>{_escape(status.get("failed_chat_count") or 0)}</dd>
  <dt>Последний результат</dt><dd>{result}</dd>{error_row}
  <dt>Проверка нового VPN</dt><dd>{_escape(repair_state)}</dd>
  <dt>Проверено маршрутов</dt><dd>{repair_attempted}</dd>
  <dt>Ошибка замены VPN</dt><dd>{_escape(repair_error)}</dd>
</dl>
{recent_rows}
<p class="muted">Добавьте этот публичный ключ в конфигурацию forced-command receiver’а Sunny:</p>
<code>{_escape(status.get("upload_public_key") or "")}</code>
<p class="muted">Fingerprint: {_escape(status.get("upload_key_fingerprint") or "—")}</p>
{activation}
<details><summary>Проверить и заменить VPN-маршрут</summary>
  <form method="post" autocomplete="off">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="replace_vpn">
    <label>Новый VLESS/REALITY subscription URL<input name="vpn_subscription_url" type="password" inputmode="url" required autocomplete="new-password"></label>
    <p class="muted">Ссылка используется один раз и не сохраняется. Telegram-сессия, выбранные группы, Source ID, upload key и состояние мониторинга сохранятся. Collector проверит connect и авторизацию Telegram через новый SOCKS-маршрут, не читая dialogs или сообщения. При неудаче старый конфиг останется выбранным; если он тоже недоступен, Telegram останется заблокирован.</p>
    <label class="check"><input type="checkbox" name="confirm_vpn_replace" value="yes" required>Проверить новые маршруты подписки и заменить текущий только после успешной Telegram-проверки.</label>
    <button class="secondary" type="submit">Проверить и заменить VPN</button>
  </form>
</details>
<details><summary>Продлить согласие для выбранных групп</summary>
  <form method="post">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="renew_consent">
    <label>Новое окончание (ISO 8601, от 1 часа до 90 дней)<input name="consent_expires_at" placeholder="2026-10-01T00:00:00Z" required></label>
    <label class="check"><input type="checkbox" name="confirm_renew" value="yes" required>Продлеваю тот же scope: дневной текст в ZDR OpenRouter, mention-фрагменты в Sunny и Telegram read-ACK только для уже зафиксированных групп.</label>
    <button class="secondary" type="submit">Продлить согласие</button>
  </form>
</details>
<div class="row">
  <form method="post">{_hidden_csrf(csrf)}<input type="hidden" name="action" value="run_now"><button type="submit">Проверить окно и запустить</button></form>
</div>"""
    return f"""
<h2>Collector недоступен или остановлен</h2>
<p class="muted">Интерфейс намеренно не показывает детали внутренних ошибок. Можно повторить запрос или выполнить полный сброс после проверки контейнера.</p>"""


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler],
                 *, ipc: IPCClient, username: str, password: str):
        super().__init__(address, handler)
        self.ipc = ipc
        self.username = username
        self.password = password


class Handler(BaseHTTPRequestHandler):
    server_version = "SunnyUI"
    sys_version = ""

    @property
    def app(self) -> AppServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, _format: str, *args: Any) -> None:
        # URLs and form bodies must never be copied to logs.
        return

    def _headers(self, status: HTTPStatus, content_type: str = "text/html; charset=utf-8",
                 length: int = 0) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:].encode("ascii"), validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (UnicodeDecodeError, ValueError, binascii.Error):
            return False
        username_ok = secrets.compare_digest(username, self.app.username)
        password_ok = secrets.compare_digest(password, self.app.password)
        return username_ok and password_ok

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        body = b"Authentication required\n"
        self._headers(HTTPStatus.UNAUTHORIZED, "text/plain; charset=utf-8", len(body))
        self.send_header("WWW-Authenticate", 'Basic realm="Sunny Personal Chats", charset="UTF-8"')
        self.end_headers()
        self.wfile.write(body)
        return False

    def _csrf_cookie(self) -> str | None:
        for part in self.headers.get("Cookie", "").split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name == CSRF_COOKIE and len(value) == 64:
                try:
                    bytes.fromhex(value)
                except ValueError:
                    return None
                return value
        return None

    def _page(self, status: Dict[str, Any], notice: str = "") -> None:
        csrf = self._csrf_cookie() or secrets.token_hex(32)
        body = _layout(render_status(status, csrf), csrf, notice)
        self._headers(HTTPStatus.OK, length=len(body))
        self.send_header("Set-Cookie", f"{CSRF_COOKIE}={csrf}; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b"ok\n"
            self._headers(HTTPStatus.OK, "text/plain; charset=utf-8", len(body))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not self._require_auth():
            return
        try:
            status = self.app.ipc.request("status")
            notice = ""
        except Exception:
            status = {"phase": "unavailable"}
            notice = "Collector пока не отвечает. Секретные детали ошибки скрыты."
        self._page(status, notice)

    def _form(self) -> Dict[str, list[str]]:
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise ValueError("invalid content length") from None
        if not 0 <= size <= MAX_HTTP_BODY_BYTES:
            raise ValueError("request body is oversized")
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            raise ValueError("unsupported form encoding")
        raw = self.rfile.read(size)
        try:
            return parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                            strict_parsing=True, max_num_fields=24)
        except (UnicodeDecodeError, ValueError):
            raise ValueError("invalid form") from None

    def do_POST(self) -> None:
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not self._require_auth():
            return
        try:
            form = self._form()
            cookie = self._csrf_cookie()
            token = _one(form, "csrf")
            if cookie is None or not secrets.compare_digest(cookie, token):
                raise PermissionError("CSRF validation failed")
            action = _one(form, "action")
            if action == "configure":
                if _one(form, "confirm_data_scope") != "yes":
                    raise PermissionError("data scope was not confirmed")
                names = (
                    "telegram_api_id", "telegram_api_hash", "vpn_subscription_url",
                    "openrouter_api_key",
                    "openrouter_model", "upload_host", "upload_port",
                    "known_host", "consent_expires_at",
                )
                configure = {name: _one(form, name) for name in names}
                configure["upload_user"] = "root"
                result = self.app.ipc.request("configure", configure)
            elif action == "send_code":
                result = self.app.ipc.request("send_code", _one(form, "phone"))
            elif action == "submit_code":
                result = self.app.ipc.request("submit_code", _one(form, "code"))
            elif action == "submit_password":
                result = self.app.ipc.request("submit_password", _one(form, "password"))
            elif action == "resolve_chat_links":
                links = [
                    line.strip()
                    for line in _one(form, "chat_links").splitlines()
                    if line.strip()
                ]
                if not 1 <= len(links) <= 16:
                    raise ValueError("1 to 16 message links are required")
                result = self.app.ipc.request("resolve_chat_links", links)
            elif action == "select_chats":
                if _one(form, "confirm_lock") != "yes":
                    raise PermissionError("chat lock was not confirmed")
                selected = form.get("chat_id")
                if not selected or not 1 <= len(selected) <= 16:
                    raise ValueError("1 to 16 chats must be selected")
                result = self.app.ipc.request("select_chats", {
                    "selection_id": _one(form, "selection_id"),
                    "chat_ids": selected,
                })
            elif action == "activate_monitoring":
                if _one(form, "confirm_activation") != "yes":
                    raise PermissionError("monitoring activation was not confirmed")
                result = self.app.ipc.request("activate_monitoring")
            elif action == "run_now":
                result = self.app.ipc.request("run_now")
            elif action == "replace_vpn":
                if _one(form, "confirm_vpn_replace") != "yes":
                    raise PermissionError("VPN replacement was not confirmed")
                result = self.app.ipc.request(
                    "replace_vpn", _one(form, "vpn_subscription_url"))
            elif action == "renew_consent":
                if _one(form, "confirm_renew") != "yes":
                    raise PermissionError("consent renewal was not confirmed")
                result = self.app.ipc.request(
                    "renew_consent", _one(form, "consent_expires_at"))
            elif action == "reset":
                if _one(form, "confirm_reset") != "yes":
                    raise PermissionError("reset was not confirmed")
                result = self.app.ipc.request("revoke_and_reset")
            elif action == "ack_manual_revocation":
                if _one(form, "confirm_manual_revocation") != "yes":
                    raise PermissionError("manual revocation was not confirmed")
                result = self.app.ipc.request("acknowledge_manual_revocation")
            else:
                raise ValueError("unknown action")
            if result.get("revocation_required"):
                notice = (
                    "Telegram logout не подтверждён: вручную завершите устройство "
                    "Sunny Umbrel в Telegram → Settings → Devices."
                )
            else:
                notice = "Команда принята."
            self._page(result, notice)
        except Exception as exc:
            try:
                status = self.app.ipc.request("status")
            except Exception:
                status = {"phase": "unavailable"}
            self._page(status, _safe_failure_notice(status, exc))


def serve() -> None:
    host = os.environ.get("SUNNY_WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("SUNNY_WEB_PORT", "8080"))
    socket_path = os.environ.get("SUNNY_IPC_SOCKET", "/data/runtime/control.sock")
    username = os.environ.get("SUNNY_UI_USERNAME", "sunny")
    password = os.environ.get("SUNNY_UI_PASSWORD", "")
    if not password or len(password) > 1024:
        raise RuntimeError("SUNNY_UI_PASSWORD is required")
    server = AppServer((host, port), Handler, ipc=IPCClient(socket_path),
                       username=username, password=password)
    server.serve_forever(poll_interval=0.5)
