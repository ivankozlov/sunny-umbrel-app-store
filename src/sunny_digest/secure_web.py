"""HTTPS-only administrative web boundary for the guardian.

The old ``web`` handler remains a compatibility UI.  This handler accepts no
legacy form commands: every state change reaches guardian through a fresh
WebAuthn ceremony or an already issued, short-lived view lease.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import secrets
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import urlsplit

from .web import IPCClient, MAX_HTTP_BODY_BYTES, _layout, render_status


CSRF_COOKIE = "sunny_secure_csrf"
VIEW_COOKIE = "sunny_secure_view"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_OPERATIONS = frozenset({
    "unlock", "lock", "configure", "activate_monitoring", "renew_consent",
    "extend_chats", "replace_vpn", "revoke_and_reset",
    "acknowledge_manual_revocation", "passkey_add", "passkey_remove",
    "change_passphrase", "view_status", "migration_resume", "select_chats",
})
_VIEW_STEPS = frozenset({
    "send_code", "submit_code", "submit_password", "resolve_chat_links",
    "set_digest_rich", "set_chat_display",
})


def _exact_origin(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("trusted origin is unavailable")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("trusted origin is unavailable")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("trusted origin is unavailable") from exc
    host = parsed.hostname
    if host != host.lower() or any(char in host for char in "*[]"):
        raise ValueError("trusted origin is unavailable")
    netloc = host if port is None else f"{host}:{port}"
    if parsed.netloc != netloc:
        raise ValueError("trusted origin is unavailable")
    return value


def _cookie(headers: str, name: str) -> str | None:
    for item in headers.split(";"):
        key, separator, value = item.strip().partition("=")
        if separator and key == name:
            return value
    return None


def _json_object(raw: bytes) -> Dict[str, Any]:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON has duplicate fields")
            result[key] = value
        return result
    try:
        def no_constants(_):
            raise ValueError("JSON numbers must be finite")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates,
                           parse_constant=no_constants)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("JSON body is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _safe_status(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {"security_state": "unavailable"}
    # Guardian itself chooses the public/redacted shape.  This boundary must
    # never reflect a view token into HTML or JSON.
    return {key: item for key, item in value.items() if key != "view_token"}


def _input(name: str, label: str, kind: str = "text", required: bool = True) -> str:
    return (f'<label>{html.escape(label)}<input name="{html.escape(name)}" '
            f'type="{kind}"' + (" required" if required else "") + "></label>")


def _operation_form(operation: str, title: str, fields: str = "") -> str:
    return (f'<details><summary>{html.escape(title)}</summary><form class="secure-operation" '
            f'data-operation="{html.escape(operation)}">{fields}'
            '<button type="submit">Подтвердить passkey</button></form></details>')


def _content(status: Dict[str, Any], csrf: str) -> str:
    state = status.get("security_state", "unavailable")
    origin = html.escape(status.get("trusted_origin", ""), quote=True)
    result = [f'<div id="secure-root" data-csrf="{csrf}" data-origin="{origin}">']
    if state == "unlocked" and status.get("view_authorized"):
        legacy = render_status(status, csrf)
        legacy = legacy.replace('<input name="openrouter_model" placeholder="provider/model" required>',
                                '<input name="openrouter_model" value="anthropic/claude-opus-5.5" readonly>')
        legacy = legacy.replace("изолированный collector", "guardian")
        legacy = legacy.replace("collector’а", "guardian").replace("collector’у", "guardian")
        legacy = legacy.replace("Collector хранит только очищенный VLESS/REALITY", "Guardian хранит только очищенный VLESS/REALITY")
        legacy = legacy.replace("Collector использует только peer и название группы", "Guardian использует только peer и название группы")
        legacy = legacy.replace(
            'name="confirm_data_scope" value="yes" required>Разрешаю читать текст только выбранных групп для одного дневного запроса в ZDR OpenRouter; durably отправлять в Sunny native mention с названием чата, отправителем, ссылкой и фрагментом до 300 UTF-16; после durable ACK помечать просмотренные сообщения и mentions прочитанными в Telegram.</label>',
            'name="confirm_data_scope" value="yes" required>Разрешаю читать текст выбранных групп для дневного дайджеста в ZDR OpenRouter и отправлять готовый дайджест в Sunny. В утреннем окне сообщения выбранных групп будут помечаться прочитанными раз в сутки, даже если дайджест не удалось доставить. Упоминания отдельно не отправляются.</label>')
        result.append(legacy)
    elif state == "unlocked":
        result.append('<h2>Vault разблокирован</h2><p>Для просмотра настройки подтвердите passkey.</p>')
    elif state in {"locked", "unlock_pending"}:
        result.append('<h2>Vault заблокирован</h2><p>Введите фразу vault и подтвердите passkey. После разблокировки приложение продолжит работу автоматически.</p>')
    elif state == "migration_blocked":
        result.append('<h2>Миграция не завершена</h2><p>Работа с Telegram приостановлена до завершения переноса данных в vault.</p>')
    if state == "uninitialized":
        result.append('<h2>Первый passkey</h2><p>Bootstrap token создаётся только в локальной консоли guardian.</p>'
                      '<form id="bootstrap-form">' + _input("bootstrap_token", "Bootstrap token", "password")
                      + _input("passphrase", "Новая фраза vault (не менее 20 UTF-8 байт)", "password")
                      + _input("name", "Название passkey")
                      + '<label class="check"><input type="checkbox" name="confirm_migration" value="yes">Я подтверждаю миграцию существующих данных.</label>'
                      + '<button type="submit">Зарегистрировать passkey</button></form>')
    elif state == "migration_blocked" and not status.get("configured"):
        result.append('<h2>Завершите bootstrap</h2><p>Vault ещё не создан. Нужен новый console bootstrap token.</p>'
                      '<form id="bootstrap-form">' + _input("bootstrap_token", "Bootstrap token", "password")
                      + _input("passphrase", "Новая фраза vault (не менее 20 UTF-8 байт)", "password")
                      + _input("name", "Название passkey")
                      + '<label class="check"><input type="checkbox" name="confirm_migration" value="yes">Я подтверждаю миграцию существующих данных.</label>'
                      + '<button type="submit">Зарегистрировать passkey</button></form>')
    elif state in {"locked", "unlock_pending", "migration_blocked"}:
        operation = "migration_resume" if state == "migration_blocked" else "unlock"
        result.append(_operation_form(operation, "Разблокировать vault", _input("passphrase", "Фраза vault", "password")))
    elif state == "unlocked":
        rows = status.get("passkeys") if isinstance(status.get("passkeys"), list) else []
        choices = "".join(f'<option value="{html.escape(row.get("credential_id", ""), quote=True)}">{html.escape(row.get("name", "Passkey"))}</option>' for row in rows if isinstance(row, dict) and isinstance(row.get("credential_id"), str) and isinstance(row.get("name"), str))
        result.extend([
            _operation_form("view_status", "Показать защищённый статус"),
            _operation_form("lock", "Заблокировать vault"),
            _operation_form("passkey_add", "Добавить passkey", _input("name", "Название passkey")),
            _operation_form("change_passphrase", "Сменить фразу vault", _input("value", "Новая фраза", "password")),
        ])
        if choices:
            result.append(_operation_form("passkey_remove", "Удалить passkey", f'<label>Passkey<select name="value">{choices}</select></label>'))
    result.append('<p id="security-error" class="notice" hidden role="alert"></p></div><script src="/security.js" defer></script>')
    return "".join(result)


class SecureAppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, ipc, username: str, password: str):
        super().__init__(address, handler)
        self.ipc, self.username, self.password = ipc, username, password


class SecureHandler(BaseHTTPRequestHandler):
    server: SecureAppServer
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, format, *args):
        # Bodies include passphrases and registration assertions; retain no request log.
        return

    def _basic(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:].encode("ascii"), validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (UnicodeDecodeError, ValueError, binascii.Error):
            return False
        return secrets.compare_digest(username, self.server.username) and secrets.compare_digest(password, self.server.password)

    def _headers(self, status: HTTPStatus, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

    def _deny(self, status: HTTPStatus = HTTPStatus.FORBIDDEN) -> None:
        # Rejected POST bodies are not consumed. Close rather than parsing their
        # remaining bytes as another request on a persistent connection.
        self.close_connection = True
        body = b"Request denied\n"
        self._headers(status, "text/plain; charset=utf-8", len(body))
        self.send_header("Connection", "close")
        if status == HTTPStatus.UNAUTHORIZED:
            self.send_header("WWW-Authenticate", 'Basic realm="Sunny Personal Chats", charset="UTF-8"')
        self.end_headers()
        self.wfile.write(body)

    def _status(self, *, view: bool = False) -> Dict[str, Any]:
        token = _cookie(self.headers.get("Cookie", ""), VIEW_COOKIE)
        if view and token and _TOKEN.fullmatch(token):
            return self.server.ipc.request("status", {"view_token": token})
        return self.server.ipc.request("status")

    def _unavailable(self, body: bytes, *, retry: bool = False) -> None:
        self._headers(HTTPStatus.SERVICE_UNAVAILABLE, "text/plain; charset=utf-8", len(body))
        if retry:
            # Signed lock restarts guardian. Retry only GET /, never the mutation.
            self.send_header("Retry-After", "2")
            self.send_header("Refresh", "2; url=/")
        self.end_headers(); self.wfile.write(body)

    def _origin(self) -> str:
        return _exact_origin(self._status().get("trusted_origin"))

    def _csrf(self) -> str:
        cookie = _cookie(self.headers.get("Cookie", ""), CSRF_COOKIE)
        header = self.headers.get("X-Sunny-CSRF", "")
        if not (cookie and _HEX.fullmatch(cookie) and secrets.compare_digest(cookie, header)):
            raise PermissionError("CSRF failed")
        return cookie

    def _json(self) -> Dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("JSON is required")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as exc:
            raise ValueError("content length is invalid") from exc
        if not 0 <= length <= MAX_HTTP_BODY_BYTES:
            raise ValueError("request is too large")
        return _json_object(self.rfile.read(length))

    def _api(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if set(request) != {"command", "data"} or not isinstance(request["command"], str):
            raise ValueError("API request fields are invalid")
        command, data = request["command"], request["data"]
        if command == "operation_begin":
            if not isinstance(data, dict) or set(data) != {"operation", "payload"} or data["operation"] not in _OPERATIONS:
                raise ValueError("operation is invalid")
        elif command == "operation_finish":
            if not isinstance(data, dict) or not {"challenge_id", "credential"} <= set(data) or set(data) - {"challenge_id", "credential", "passphrase"}:
                raise ValueError("finish is invalid")
        elif command == "bootstrap_begin":
            if not isinstance(data, dict) or set(data) != {"token"}:
                raise ValueError("bootstrap is invalid")
        elif command == "registration_finish":
            if not isinstance(data, dict) or not {"challenge_id", "credential", "name"} <= set(data) or set(data) - {"challenge_id", "credential", "name", "passphrase", "confirm_migration"}:
                raise ValueError("registration is invalid")
        elif command == "view_step":
            if not isinstance(data, dict) or set(data) != {"command", "value"} or data["command"] not in _VIEW_STEPS:
                raise ValueError("view step is invalid")
            token = _cookie(self.headers.get("Cookie", ""), VIEW_COOKIE)
            if not token or not _TOKEN.fullmatch(token):
                raise PermissionError("view lease is required")
            return self.server.ipc.request(data["command"], {"value": data["value"], "view_token": token})
        elif command == "run_now":
            if data != {}:
                raise ValueError("run_now is invalid")
            return self.server.ipc.request("run_now", {})
        else:
            raise PermissionError("bare admin command is unavailable")
        return self.server.ipc.request(command, data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b"ok\n"
            self._headers(HTTPStatus.OK, "text/plain; charset=utf-8", len(body)); self.end_headers(); self.wfile.write(body); return
        if self.path == "/security.js":
            if not self._basic(): self._deny(HTTPStatus.UNAUTHORIZED); return
            body = Path(__file__).with_name("security.js").read_bytes()
            self._headers(HTTPStatus.OK, "application/javascript; charset=utf-8", len(body)); self.end_headers(); self.wfile.write(body); return
        if self.path != "/": self._deny(HTTPStatus.NOT_FOUND); return
        if not self._basic(): self._deny(HTTPStatus.UNAUTHORIZED); return
        try:
            status = _safe_status(self._status(view=True))
        except Exception:
            self._unavailable("Сервис временно недоступен. Страница обновится через 2 секунды.\n".encode("utf-8"), retry=True)
            return
        try:
            _exact_origin(status.get("trusted_origin"))
        except ValueError:
            self._unavailable(b"Trusted HTTPS origin is not configured. Configure the fixed "
                              b"guardian origin before using this interface.\n")
            return
        try:
            csrf = _cookie(self.headers.get("Cookie", ""), CSRF_COOKIE)
            csrf = csrf if csrf and _HEX.fullmatch(csrf) else secrets.token_hex(32)
            body = _layout(_content(status, csrf), csrf,
                           allow_reset=status.get("security_state") == "unlocked"
                           and status.get("view_authorized") is True)
        except Exception:
            self._unavailable("Не удалось открыть интерфейс. Обновите страницу.\n".encode("utf-8"))
            return
        self._headers(HTTPStatus.OK, "text/html; charset=utf-8", len(body))
        self.send_header("Set-Cookie", f"{CSRF_COOKIE}={csrf}; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Strict")
        self.end_headers(); self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/api": self._deny(HTTPStatus.NOT_FOUND); return
        if not self._basic(): self._deny(HTTPStatus.UNAUTHORIZED); return
        try:
            origin = self._origin()
            if not secrets.compare_digest(self.headers.get("Origin", ""), origin):
                raise PermissionError("origin is invalid")
            self._csrf()
            result = self._api(self._json())
            view_token = result.pop("view_token", None) if isinstance(result, dict) else None
            body = json.dumps(_safe_status(result), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._headers(HTTPStatus.OK, "application/json; charset=utf-8", len(body))
            if isinstance(view_token, str) and _TOKEN.fullmatch(view_token):
                self.send_header("Set-Cookie", f"{VIEW_COOKIE}={view_token}; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Strict")
            elif isinstance(result, dict) and result.get("security_state") == "locked":
                self.send_header("Set-Cookie", f"{VIEW_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
            self.end_headers(); self.wfile.write(body)
        except Exception:
            self._deny()


def serve() -> None:
    password = os.environ.get("SUNNY_UI_PASSWORD", "")
    if not password or len(password) > 1024:
        raise RuntimeError("SUNNY_UI_PASSWORD is required")
    server = SecureAppServer((os.environ.get("SUNNY_WEB_HOST", "0.0.0.0"), int(os.environ.get("SUNNY_WEB_PORT", "8080"))),
                             SecureHandler, ipc=IPCClient(os.environ.get("SUNNY_IPC_SOCKET", "/data/ipc/admin.sock")),
                             username=os.environ.get("SUNNY_UI_USERNAME", "sunny"), password=password)
    server.serve_forever(poll_interval=0.5)
