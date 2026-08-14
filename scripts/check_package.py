#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "sunny-personal-digest"
PLACEHOLDER = "RELEASE_GATE_MULTIARCH_DIGEST"
EXPECTED_WIRE_VERSION = "0.2.1"
MIHOMO_IMAGE = (
    "docker.io/metacubex/mihomo:v1.19.29@sha256:"
    "e1d7dadaa9368a52d420d65007e0e0d87cb148d292faa67326eda3fef5757f59"
)
MIHOMO_LICENSE_SHA256 = (
    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
)


class Checks:
    def __init__(self):
        self.errors: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def service_block(compose: str, name: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", compose)
    if not match:
        return ""
    return match.group(1)


def telegram_client_guard(gateway: str) -> tuple[bool, bool, bool]:
    """Return mandatory-proxy and application-version facts from the gateway AST."""
    tree = ast.parse(gateway)
    gateway_class = next(
        (node for node in tree.body
         if isinstance(node, ast.ClassDef) and node.name == "TelethonGateway"),
        None,
    )
    if gateway_class is None:
        return False, False, False
    init = next(
        (node for node in gateway_class.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == "__init__"),
        None,
    )
    client = next(
        (node for node in gateway_class.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == "_client"),
        None,
    )
    if init is None or client is None:
        return False, False, False

    positional = list(init.args.posonlyargs) + list(init.args.args)
    defaulted = {
        arg.arg for arg in positional[-len(init.args.defaults):]
    } if init.args.defaults else set()
    mandatory_positional_proxy = (
        any(arg.arg == "proxy" for arg in positional)
        and "proxy" not in defaulted
    )
    mandatory_keyword_proxy = any(
        arg.arg == "proxy" and default is None
        for arg, default in zip(init.args.kwonlyargs, init.args.kw_defaults)
    )
    mandatory_proxy = mandatory_positional_proxy or mandatory_keyword_proxy

    client_calls: list[ast.Call] = []
    for node in ast.walk(client):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "TelegramClient"):
            client_calls.append(node)

    def has_exact_keyword(call: ast.Call, name: str, value: ast.expr) -> bool:
        return any(
            keyword.arg == name and ast.dump(keyword.value) == ast.dump(value)
            for keyword in call.keywords
        )

    proxy_value = ast.Attribute(
        value=ast.Name(id="self", ctx=ast.Load()),
        attr="proxy",
        ctx=ast.Load(),
    )
    app_version_value = ast.Name(id="APP_VERSION", ctx=ast.Load())
    proxy_forwarded = bool(client_calls) and all(
        has_exact_keyword(call, "proxy", proxy_value) for call in client_calls
    )
    app_version_forwarded = bool(client_calls) and all(
        has_exact_keyword(call, "app_version", app_version_value)
        for call in client_calls
    )
    return mandatory_proxy, proxy_forwarded, app_version_forwarded


def _attribute_path(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return ()
    return tuple(reversed(parts))


def _module_function(tree: ast.Module, name: str):
    return next(
        (node for node in tree.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == name),
        None,
    )


def _class_method(tree: ast.Module, class_name: str, method_name: str):
    class_node = next(
        (node for node in tree.body
         if isinstance(node, ast.ClassDef) and node.name == class_name),
        None,
    )
    if class_node is None:
        return None
    return next(
        (node for node in class_node.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == method_name),
        None,
    )


def _module_literal(tree: ast.Module, name: str):
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError):
                return None
    return None


def telegram_probe_guard(
    parent_source: str,
    worker_source: str,
    gateway_source: str,
    mihomo_source: str,
) -> dict[str, bool]:
    """Return fail-closed facts for the killable Telegram authorization probe."""
    parent_tree = ast.parse(parent_source)
    worker_tree = ast.parse(worker_source)
    gateway_tree = ast.parse(gateway_source)
    mihomo_tree = ast.parse(mihomo_source)

    spawn_calls = [
        node for node in ast.walk(parent_tree)
        if isinstance(node, ast.Call)
        and _attribute_path(node.func) == ("asyncio", "create_subprocess_exec")
    ]
    expected_args = (
        ast.Attribute(value=ast.Name(id="sys", ctx=ast.Load()),
                      attr="executable", ctx=ast.Load()),
        ast.Constant(value="-m"),
        ast.Constant(value="sunny_digest.telegram_probe_worker"),
    )
    exact_worker_argv = len(spawn_calls) == 1 and (
        len(spawn_calls[0].args) == len(expected_args)
        and all(ast.dump(actual) == ast.dump(expected)
                for actual, expected in zip(spawn_calls[0].args, expected_args))
    )
    spawn_keywords = {
        keyword.arg: _attribute_path(keyword.value)
        for keyword in spawn_calls[0].keywords
        if keyword.arg is not None
    } if spawn_calls else {}
    exact_pipes = spawn_keywords == {
        "stdin": ("asyncio", "subprocess", "PIPE"),
        "stdout": ("asyncio", "subprocess", "PIPE"),
        "stderr": ("asyncio", "subprocess", "DEVNULL"),
    }
    parent_writes_stdin = any(
        isinstance(node, ast.Call)
        and len(node.args) == 1
        and _attribute_path(node.func)[-2:] == ("stdin", "write")
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "request"
        for node in ast.walk(parent_tree)
    )
    worker_reads_stdin = any(
        isinstance(node, ast.Call)
        and _attribute_path(node.func) == ("sys", "stdin", "buffer", "read")
        for node in ast.walk(worker_tree)
    )

    forbidden_file_calls = {
        "open", "mkstemp", "NamedTemporaryFile", "TemporaryDirectory",
        "read_bytes", "read_text", "write_bytes", "write_text",
    }
    side_channel_free = True
    for tree in (parent_tree, worker_tree):
        for node in ast.walk(tree):
            path = _attribute_path(node)
            if path in (("os", "environ"), ("sys", "argv")):
                side_channel_free = False
            if not isinstance(node, ast.Call):
                continue
            call_path = _attribute_path(node.func)
            if (call_path and call_path[-1] in forbidden_file_calls) or call_path in (
                ("os", "getenv"), ("os", "putenv"),
                ("asyncio", "create_subprocess_shell"),
            ):
                side_channel_free = False
            if any(keyword.arg == "env" for keyword in node.keywords):
                side_channel_free = False
    stdin_only_secrets = (
        exact_worker_argv and exact_pipes and parent_writes_stdin
        and worker_reads_stdin and side_channel_free
    )

    worker_probe = _module_function(worker_tree, "_probe")
    gateway_calls = [
        node for node in ast.walk(worker_probe)
        if isinstance(node, ast.Call)
        and _attribute_path(node.func) == ("TelethonGateway",)
    ] if worker_probe is not None else []
    all_worker_gateway_calls = [
        node for node in ast.walk(worker_tree)
        if isinstance(node, ast.Call)
        and _attribute_path(node.func) == ("TelethonGateway",)
    ]
    direct_client_calls = [
        node for tree in (parent_tree, worker_tree)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _attribute_path(node.func)[-1:] == ("TelegramClient",)
    ]
    expected_proxy = ast.Dict(
        keys=[ast.Constant(value=value) for value in (
            "proxy_type", "addr", "port", "rdns",
        )],
        values=[
            ast.Constant(value="socks5"),
            ast.Name(id="MIHOMO_SOCKS_HOST", ctx=ast.Load()),
            ast.Name(id="MIHOMO_SOCKS_PORT", ctx=ast.Load()),
            ast.Constant(value=True),
        ],
    )
    fixed_loopback_socks = (
        _module_literal(mihomo_tree, "MIHOMO_SOCKS_HOST") == "127.0.0.1"
        and _module_literal(mihomo_tree, "MIHOMO_SOCKS_PORT") == 7891
        and len(gateway_calls) == 1
        and all_worker_gateway_calls == gateway_calls
        and not direct_client_calls
        and len(gateway_calls[0].args) == 3
        and ast.dump(gateway_calls[0].args[2]) == ast.dump(expected_proxy)
        and not gateway_calls[0].keywords
    )

    authorization_method = _class_method(
        gateway_tree, "TelethonGateway", "probe_authorization")
    authorization_calls = {
        _attribute_path(node.func)[-1]
        for node in ast.walk(authorization_method)
        if isinstance(node, ast.Call) and _attribute_path(node.func)
    } if authorization_method is not None else set()
    worker_probe_calls = {
        _attribute_path(node.func)[-1]
        for node in ast.walk(worker_probe)
        if isinstance(node, ast.Call) and _attribute_path(node.func)
    } if worker_probe is not None else set()
    forbidden_probe_calls = {
        "get_messages", "iter_messages", "get_dialogs", "iter_dialogs",
        "get_history", "iter_history", "read_history", "mark_read",
        "send_read_acknowledge", "get_entity", "get_participants",
        "iter_participants", "download_media",
    }
    probe_api_calls = {
        _attribute_path(node.func)[-1]
        for tree in (parent_tree, worker_tree)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attribute_path(node.func)
    }
    authorization_only = (
        authorization_calls == {
            "_client", "connect", "bool", "is_user_authorized",
            "_disconnect_client",
        }
        and worker_probe_calls == {"TelethonGateway", "probe_authorization"}
        and not probe_api_calls.intersection(forbidden_probe_calls)
    )

    direct_literal = any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.upper() == "DIRECT"
        for tree in (parent_tree, worker_tree)
        for node in ast.walk(tree)
    )
    to_thread_call = any(
        isinstance(node, ast.Call)
        and _attribute_path(node.func)[-1:] == ("to_thread",)
        for tree in (parent_tree, worker_tree)
        for node in ast.walk(tree)
    )
    no_thread_or_direct = (
        not to_thread_call and not direct_literal and not direct_client_calls
    )
    return {
        "stdin_only_secrets": stdin_only_secrets,
        "fixed_loopback_socks": fixed_loopback_socks,
        "authorization_only": authorization_only,
        "no_thread_or_direct": no_thread_or_direct,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Umbrel package checks")
    parser.add_argument("--release", action="store_true",
                        help="require enabled manifest and real immutable image digest")
    args = parser.parse_args()
    checks = Checks()

    required = (
        ROOT / "Dockerfile", ROOT / "README.md", ROOT / "SECURITY.md",
        ROOT / "LICENSE", ROOT / "THIRD_PARTY_NOTICES.md",
        ROOT / "LICENSES/Mihomo-GPL-3.0.txt",
        ROOT / "umbrel-app-store.yml", APP / "umbrel-app.yml",
        APP / "docker-compose.yml", APP / "icon.svg",
        ROOT / ".github/workflows/ci.yml", ROOT / ".github/workflows/publish.yml",
        ROOT / "src/sunny_digest/telegram_probe.py",
        ROOT / "src/sunny_digest/telegram_probe_worker.py",
    )
    for path in required:
        checks.require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
    if checks.errors:
        print("\n".join(f"ERROR: {error}" for error in checks.errors), file=sys.stderr)
        return 1

    store = text(ROOT / "umbrel-app-store.yml")
    manifest = text(APP / "umbrel-app.yml")
    compose = text(APP / "docker-compose.yml")
    dockerfile = text(ROOT / "Dockerfile")
    third_party_notices = text(ROOT / "THIRD_PARTY_NOTICES.md")
    requirements_input = text(ROOT / "requirements.in")
    requirements = text(ROOT / "requirements.txt")
    version_source = text(ROOT / "src/sunny_digest/version.py")

    checks.require(re.search(r"(?m)^id: sunny$", store) is not None,
                   "store id must be sunny")
    checks.require(re.search(r"(?m)^name: Sunny$", store) is not None,
                   "store display name must be Sunny")
    checks.require(re.search(r"(?m)^id: sunny-personal-digest$", manifest) is not None,
                   "manifest id must match directory")
    disabled = re.search(r"(?m)^disabled: true$", manifest) is not None
    version_match = re.search(r'(?m)^version: "([0-9]+\.[0-9]+\.[0-9]+)"$', manifest)
    checks.require(version_match is not None, "manifest version must be quoted semver")
    app_runtime_version = re.search(
        r'(?m)^APP_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$',
        version_source,
    )
    wire_version = re.search(
        r'(?m)^COLLECTOR_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$',
        version_source,
    )
    docker_version = re.search(
        r"(?m)^ARG APP_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", dockerfile)
    checks.require(app_runtime_version is not None,
                   "APP_VERSION must be strict semver")
    checks.require(wire_version is not None,
                   "COLLECTOR_VERSION must be strict semver")
    checks.require(docker_version is not None,
                   "Docker APP_VERSION default must be strict semver")
    if wire_version:
        checks.require(wire_version.group(1) == EXPECTED_WIRE_VERSION,
                       "collector wire version changed without a protocol migration")
    if version_match and app_runtime_version and docker_version:
        expected_version = version_match.group(1)
        checks.require(app_runtime_version.group(1) == expected_version,
                       "manifest and APP_VERSION differ")
        checks.require(docker_version.group(1) == expected_version,
                       "manifest and Docker APP_VERSION differ")

    images = re.findall(
        r"(?m)^    image: ghcr\.io/ivankozlov/sunny-personal-digest:"
        r"v([0-9]+\.[0-9]+\.[0-9]+)@sha256:([^\s]+)$",
        compose,
    )
    checks.require(len(images) == 2, "both runtime services must use the pinned GHCR image")
    if len(images) == 2:
        checks.require(images[0] == images[1], "web and collector images must be identical")
        if version_match:
            checks.require(all(version == version_match.group(1) for version, _ in images),
                           "manifest and image versions differ")
        digests = {digest for _, digest in images}
        checks.require(len(digests) == 1, "image digests differ")
        digest = next(iter(digests))
        real_digest = re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        checks.require(digest == PLACEHOLDER or real_digest,
                       "image digest must be the release placeholder or real sha256")
        checks.require(disabled == (digest == PLACEHOLDER),
                       "manifest must be disabled exactly while the digest is a placeholder")
        if args.release:
            checks.require(real_digest,
                           "release image must use a real sha256 digest")
            checks.require(not disabled, "release manifest must be enabled")
    if args.release:
        checks.require(PLACEHOLDER not in compose, "release placeholder remains in Compose")

    forbidden = {
        r"(?m)^\s*privileged:": "privileged containers are forbidden",
        r"(?m)^\s*network_mode:\s*host": "host network is forbidden",
        r"(?m)^\s*ports:": "raw host ports are forbidden",
        r"/var/run/docker\.sock": "Docker socket mount is forbidden",
        r"(?m)^\s*cap_add:": "added Linux capabilities are forbidden",
        r"(?m)^\s*devices:": "device mounts are forbidden",
    }
    for pattern, message in forbidden.items():
        checks.require(re.search(pattern, compose) is None, message)

    web = service_block(compose, "web")
    collector = service_block(compose, "collector")
    checks.require(bool(web) and bool(collector), "web/collector service blocks are required")
    checks.require("/data/runtime:/data/runtime" in web, "web must mount runtime")
    checks.require("/data/config" not in web and "/data/private" not in web,
                   "web must not mount config/private")
    for mount in ("/data/config:/data/config", "/data/private:/data/private",
                  "/data/runtime:/data/runtime"):
        checks.require(mount in collector, f"collector missing mount {mount}")
    for name, block in (("web", web), ("collector", collector)):
        checks.require('user: "1000:1000"' in block, f"{name} must run as uid 1000")
        checks.require("read_only: true" in block, f"{name} rootfs must be read-only")
        checks.require("cap_drop:\n      - ALL" in block, f"{name} must drop all capabilities")
        checks.require("no-new-privileges:true" in block,
                       f"{name} must set no-new-privileges")
        checks.require("pids_limit:" in block and "mem_limit:" in block,
                       f"{name} must have process/memory limits")
    checks.require("SUNNY_UI_PASSWORD: ${APP_PASSWORD}" in web,
                   "second auth must use APP_PASSWORD")
    checks.require("APP_HOST: sunny-personal-digest_web_1" in compose,
                   "app_proxy host is incorrect")

    for ignored in (
            "data/private/*", "data/private/.*", "data/runtime/*",
            "data/runtime/.*", "data/config/pending-upload.json",
            "data/config/.pending-upload.json.*",
            "data/config/pending-monitor-upload.json",
            "data/config/.pending-monitor-upload.json.*"):
        checks.require(f"  - {ignored}" in manifest,
                       f"backupIgnore is missing {ignored}")
    checks.require("deterministicPassword: true" in manifest,
                   "Umbrel must expose the deterministic app password")
    checks.require(re.search(r"(?m)^defaultShell: collector$", manifest) is not None,
                   "Umbrel terminal must default to the collector service")

    docker_images = re.findall(
        r"(?m)^FROM ([^\s]+)(?: AS [A-Za-z0-9_.-]+)?$", dockerfile)
    checks.require(bool(docker_images), "Dockerfile has no base image")
    checks.require(all(re.search(r"@sha256:[0-9a-f]{64}$", image)
                       for image in docker_images),
                   "every Docker base image must be pinned by digest")
    checks.require(
        f"FROM {MIHOMO_IMAGE} AS mihomo" in dockerfile,
        "Mihomo build stage must use the reviewed immutable multi-arch image",
    )
    checks.require("COPY --from=mihomo /mihomo /usr/local/bin/mihomo" in dockerfile,
                   "Mihomo binary must be embedded in the application image")
    checks.require("RUN test -x /usr/local/bin/mihomo" in dockerfile,
                   "Mihomo binary executable bit must be checked during build")
    checks.require('org.opencontainers.image.licenses="MIT AND GPL-3.0-only"' in dockerfile,
                   "image license label must cover the bundled Mihomo binary")
    checks.require("COPY LICENSE /usr/share/licenses/sunny/LICENSE" in dockerfile,
                   "application license must be included in the image")
    checks.require(
        "COPY LICENSES/Mihomo-GPL-3.0.txt /usr/share/licenses/mihomo/LICENSE"
        in dockerfile,
        "complete Mihomo GPL license must be included in the image",
    )
    checks.require(
        "COPY THIRD_PARTY_NOTICES.md /usr/share/doc/sunny/THIRD_PARTY_NOTICES.md"
        in dockerfile,
        "third-party source notice must be included in the image",
    )
    checks.require(
        sha256(ROOT / "LICENSES/Mihomo-GPL-3.0.txt") == MIHOMO_LICENSE_SHA256,
        "Mihomo GPL license text differs from the reviewed upstream tag",
    )
    for marker in (
        MIHOMO_IMAGE,
        "https://github.com/MetaCubeX/mihomo/tree/v1.19.29",
        "LICENSES/Mihomo-GPL-3.0.txt",
        MIHOMO_LICENSE_SHA256,
    ):
        checks.require(marker in third_party_notices,
                       f"third-party notice is missing: {marker}")
    checks.require("--require-hashes" in dockerfile, "pip install must require hashes")
    checks.require("USER 1000:1000" in dockerfile, "image must end as uid 1000")
    checks.require(re.search(r"(?m)^python-socks\[asyncio\]==2\.8\.2$",
                             requirements_input) is not None,
                   "requirements input must pin the Telethon SOCKS transport")
    checks.require(re.search(r"(?m)^python-socks==2\.8\.2\s*\\$",
                             requirements) is not None,
                   "requirements lock must contain the Telethon SOCKS transport")
    checks.require(re.search(r"(?m)^PyYAML==6\.0\.3$",
                             requirements_input) is not None,
                   "requirements input must pin the Clash YAML parser")
    checks.require(re.search(r"(?m)^pyyaml==6\.0\.3\s*\\$",
                             requirements) is not None,
                   "requirements lock must contain the Clash YAML parser")
    requirement_starts = list(re.finditer(
        r"(?m)^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^\s\\]+",
        requirements,
    ))
    checks.require(bool(requirement_starts), "requirements lock is empty")
    for index, match in enumerate(requirement_starts):
        end = requirement_starts[index + 1].start() if index + 1 < len(
            requirement_starts) else len(requirements)
        checks.require("--hash=sha256:" in requirements[match.start():end],
                       f"requirement lacks hashes: {match.group(0)}")

    gateway = text(ROOT / "src/sunny_digest/telegram_gateway.py")
    mandatory_proxy, proxy_forwarded, app_version_forwarded = telegram_client_guard(gateway)
    checks.require("receive_updates=False" in gateway,
                   "Telegram client must disable update reception")
    checks.require("StringSession" in gateway, "Telegram runtime must use StringSession")
    checks.require(mandatory_proxy,
                   "TelethonGateway must require an explicit proxy")
    checks.require(proxy_forwarded,
                   "TelegramClient must receive the explicit app-scoped proxy")
    checks.require(app_version_forwarded,
                   "TelegramClient app_version must use APP_VERSION, not the wire version")
    checks.require("get_entity(" not in gateway and "download_media(" not in gateway,
                   "generic entity resolution/media downloads are forbidden")
    telegram_probe = text(ROOT / "src/sunny_digest/telegram_probe.py")
    telegram_probe_worker = text(
        ROOT / "src/sunny_digest/telegram_probe_worker.py")
    mihomo = text(ROOT / "src/sunny_digest/mihomo.py")
    probe_facts = telegram_probe_guard(
        telegram_probe, telegram_probe_worker, gateway, mihomo)
    for fact, message in {
        "stdin_only_secrets": (
            "Telegram probe secrets must reach the fixed worker only over stdin"),
        "fixed_loopback_socks": (
            "Telegram probe worker must use the exact fixed loopback Mihomo SOCKS"),
        "authorization_only": (
            "Telegram probe may only connect, check authorization, and disconnect"),
        "no_thread_or_direct": (
            "Telegram probe must remain killable and have no DIRECT fallback"),
    }.items():
        checks.require(probe_facts[fact], message)
    openrouter = text(ROOT / "src/sunny_digest/openrouter.py")
    checks.require("asyncio.to_thread" not in openrouter,
                   "blocking OpenRouter work must stay in a killable subprocess")
    checks.require("sunny_digest.openrouter_worker" in openrouter,
                   "OpenRouter subprocess boundary is missing")
    vpn_subscription = text(ROOT / "src/sunny_digest/vpn_subscription.py")
    checks.require("asyncio.to_thread" not in vpn_subscription,
                   "subscription HTTPS work must stay in a killable subprocess")
    checks.require("sunny_digest.vpn_subscription_worker" in vpn_subscription,
                   "subscription subprocess boundary is missing")

    private_markers = ("-----BEGIN OPENSSH PRIVATE KEY-----", "sk-or-v1-")
    for path in ROOT.rglob("*"):
        if (not path.is_file() or path.resolve() == Path(__file__).resolve()
                or path.suffix in (".pyc", ".png")):
            continue
        try:
            body = text(path)
        except UnicodeDecodeError:
            continue
        for marker in private_markers:
            checks.require(marker not in body,
                           f"possible credential marker in {path.relative_to(ROOT)}")

    for secret_name in (".env", ".env.local", "id_ed25519", "telegram.session"):
        checks.require(not (ROOT / secret_name).exists(), f"secret file exists: {secret_name}")

    # Regression guard: a blanket data/ ignore followed by directory negations
    # can accidentally re-include sessions and credentials in `git add .`.
    for relative in (
        ".env.local",
        "nested/.env.production",
        "id_ed25519",
        "client.session",
        "sunny-personal-digest/data/config/settings.json",
        "sunny-personal-digest/data/config/acknowledged.json",
        "sunny-personal-digest/data/config/pending-upload.json",
        "sunny-personal-digest/data/config/.pending-upload.json.crash",
        "sunny-personal-digest/data/config/pending-monitor-upload.json",
        "sunny-personal-digest/data/config/.pending-monitor-upload.json.crash",
        "sunny-personal-digest/data/private/telegram.session.txt",
        "sunny-personal-digest/data/runtime/status.json",
    ):
        ignored = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "--quiet", "--", relative],
            check=False,
        )
        checks.require(ignored.returncode == 0, f"runtime secret path is not ignored: {relative}")

    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        body = text(workflow)
        for action in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s]+)$", body):
            ref = action.rsplit("@", 1)[-1]
            checks.require(re.fullmatch(r"[0-9a-f]{40}", ref) is not None,
                           f"workflow action is not SHA-pinned: {action}")
    publish = text(ROOT / ".github/workflows/publish.yml")
    if version_match:
        checks.require(
            f'        default: "{version_match.group(1)}"' in publish,
            "publish workflow default and manifest versions differ",
        )
    for invariant in (
        "gate:", "needs: gate", "persist-credentials: false",
        "python -m unittest discover", "python scripts/check_package.py",
        "platforms: linux/amd64,linux/arm64", "sbom: true", "provenance: mode=max",
        "Refuse to overwrite an existing version tag",
        "Registry probe failed without an explicit missing-manifest response",
        'grep -Fqx "ERROR: $image: not found"',
        "manifest unknown|404 Not Found|manifest[^[:space:]]* not found",
        "bootstrap_empty_package",
        "BOOTSTRAP_EMPTY_PACKAGE",
        "confirmed one-time bootstrap of an absent package",
        "'/users/ivankozlov/packages/container/sunny-personal-digest/versions?per_page=1'",
        "grep -Fx 'disabled: true' sunny-personal-digest/umbrel-app.yml",
        "github.ref == 'refs/heads/main'",
        "environment: ghcr-release",
        "tonistiigi/binfmt:qemu-v10.2.3@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0",
        "moby/buildkit:v0.31.2@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
        "version: v0.31.1",
    ):
        checks.require(invariant in publish, f"publish workflow missing: {invariant}")
    checks.require("pull_request_target" not in publish,
                   "publish workflow must not run on pull_request_target")
    publish_preamble = publish.split("jobs:", 1)[0]
    gate_job = service_block(publish, "gate")
    publish_job = service_block(publish, "publish")
    checks.require("packages: write" not in publish_preamble,
                   "publish workflow must not grant package writes globally")
    checks.require("packages: write" not in gate_job,
                   "read-only release gate must not write packages")
    checks.require("packages: write" in publish_job,
                   "only the publish job must receive package write access")

    claude = ROOT / "CLAUDE.md"
    checks.require(claude.is_symlink() and claude.readlink() == Path("AGENTS.md"),
                   "CLAUDE.md must be a symlink to AGENTS.md")

    if checks.errors:
        print("\n".join(f"ERROR: {error}" for error in checks.errors), file=sys.stderr)
        return 1
    mode = "release" if args.release else "development"
    print(f"Umbrel package checks passed ({mode} mode)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
