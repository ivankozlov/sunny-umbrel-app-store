from __future__ import annotations

import asyncio
import base64
import binascii
import http.client
import ipaddress
import json
import math
import re
import socket
import sys
import unicodedata
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEndToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    DirectiveToken,
    FlowMappingEndToken,
    FlowMappingStartToken,
    FlowSequenceEndToken,
    FlowSequenceStartToken,
    ScalarToken,
    TagToken,
)

MAX_SUBSCRIPTION_URL = 2048
MAX_SUBSCRIPTION_BYTES = 1024 * 1024
MAX_SUBSCRIPTION_NODES = 64
MAX_NODE_LINE = 4096
MAX_WORKER_RESPONSE_BYTES = 128 * 1024
# v2: воркер отдаёт ещё и имя хоста каждого узла. Резолв затирает его
# IP-литералом, а подписка на диске не хранится — без имени после
# ротации адреса взять новый неоткуда.
WORKER_SCHEMA = "sunny.personal-chats.subscription-worker.v2"
# Ключ, которым имя хоста едет от воркера до записи на диск. В самом
# узле его быть не должно: набор ключей узла сверяется строгим
# множеством, поэтому вызывающий снимает ключ перед валидацией.
ORIGIN_KEY = "origin"
WORKER_TERMINATE_GRACE_S = 2.0
MAX_YAML_NODES = 10_000
MAX_YAML_DEPTH = 32

_DNS_LABEL = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_BASE64_TEXT = re.compile(br"^[A-Za-z0-9+/_=-]+$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_MODERN_FINGERPRINTS = frozenset({
    "android", "chrome", "edge", "firefox", "ios", "random", "randomized",
    "safari",
})
_REQUIRED_QUERY = frozenset({
    "encryption", "security", "sni", "fp", "pbk", "sid", "type", "flow",
})
_OPTIONAL_QUERY = frozenset({"headerType", "spx"})


class SubscriptionFetchError(RuntimeError):
    """A deliberately redacted subscription download error."""


def is_public_unicast_address(address: Any) -> bool:
    """Return whether an already parsed IP is safe for public egress."""
    return (
        isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
        and address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_private
    )


def is_public_unicast_ipv4(address: Any) -> bool:
    return (
        isinstance(address, ipaddress.IPv4Address)
        and is_public_unicast_address(address)
    )


def _has_control(value: str) -> bool:
    return any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    )


def _valid_dns_hostname(value: str) -> bool:
    if (
        not value
        or len(value) > 253
        or value.endswith(".")
        or value.lower() == "localhost"
    ):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    labels = value.split(".")
    return (
        len(labels) >= 2
        and not all(label.isdigit() for label in labels)
        and all(_DNS_LABEL.fullmatch(label) for label in labels)
    )


def validate_subscription_url(value: Any) -> str:
    """Validate a bearer subscription URL without normalizing or exposing it."""
    try:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_SUBSCRIPTION_URL
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
            or "\\" in value
            or "#" in value
            or _PERCENT_ESCAPE.search(value)
            or _has_control(urllib.parse.unquote(value, errors="strict"))
        ):
            raise ValueError
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        try:
            explicit_port = parsed.port
        except ValueError:
            raise ValueError from None
        if explicit_port is not None:
            raise ValueError
        hostname = parsed.hostname
        if hostname is None or not _valid_dns_hostname(hostname):
            raise ValueError
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("subscription URL is invalid") from None
    return value


def _origin(value: str) -> Tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(value)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), 443


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: Tuple[str, str, int]) -> None:
        super().__init__()
        self._allowed_origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            candidate = urllib.parse.urljoin(req.full_url, newurl)
            validate_subscription_url(candidate)
            if _origin(candidate) != self._allowed_origin:
                raise ValueError
        except (TypeError, ValueError, UnicodeError):
            raise SubscriptionFetchError(
                "subscription redirect was rejected"
            ) from None
        return super().redirect_request(req, fp, code, msg, headers, candidate)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the DNS-vetted IP while preserving Host, SNI and TLS checks."""

    def __init__(self, host: str, *, pinned_address: str, **kwargs: Any) -> None:
        address = ipaddress.ip_address(pinned_address)
        if not is_public_unicast_ipv4(address):
            raise ValueError("subscription origin address is invalid")
        self._pinned_address = address.compressed
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address,
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_address: str) -> None:
        super().__init__()
        self._pinned_address = pinned_address

    def https_open(self, request):
        pinned_address = self._pinned_address

        def connection(host, **kwargs):
            return _PinnedHTTPSConnection(
                host, pinned_address=pinned_address, **kwargs,
            )

        return self.do_open(
            connection, request, context=self._context,
        )


def _fetch_https_bytes(
    url: str, timeout_s: float, max_bytes: int, pinned_address: str,
) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain, application/octet-stream;q=0.9",
            "User-Agent": "Sunny-Personal-Chats subscription client",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _PinnedHTTPSHandler(pinned_address),
        _SameOriginRedirectHandler(_origin(url)),
    )
    with opener.open(request, timeout=timeout_s) as response:
        if response.getcode() != 200 or _origin(response.geturl()) != _origin(url):
            raise SubscriptionFetchError("subscription download was rejected")
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                if int(length, 10) > max_bytes:
                    raise SubscriptionFetchError("subscription response is too large")
            except ValueError:
                raise SubscriptionFetchError(
                    "subscription response headers are invalid"
                ) from None
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise SubscriptionFetchError("subscription response is too large")
    return payload


def _decode_base64_wrapped(payload: bytes) -> bytes:
    if any(
        byte not in b" \t\r\n"
        and not chr(byte).isalnum()
        and byte not in b"+/_=-"
        for byte in payload
    ):
        raise ValueError
    compact = b"".join(payload.split())
    if not compact or not _BASE64_TEXT.fullmatch(compact):
        raise ValueError
    if b"=" in compact[:-2] or len(compact) % 4 == 1:
        raise ValueError
    padded = compact + b"=" * (-len(compact) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise ValueError from None


def _decode_query(query: str) -> Dict[str, str]:
    if not query:
        raise ValueError
    result: Dict[str, str] = {}
    pairs = query.split("&")
    if len(pairs) > len(_REQUIRED_QUERY | _OPTIONAL_QUERY):
        raise ValueError
    for pair in pairs:
        if pair.count("=") != 1:
            raise ValueError
        raw_key, raw_value = pair.split("=", 1)
        if (
            not raw_key
            or _PERCENT_ESCAPE.search(raw_key)
            or _PERCENT_ESCAPE.search(raw_value)
        ):
            raise ValueError
        key = urllib.parse.unquote_plus(raw_key)
        value = urllib.parse.unquote_plus(raw_value)
        if key in result or key not in _REQUIRED_QUERY | _OPTIONAL_QUERY:
            raise ValueError
        if not value and key not in ("sid", "spx"):
            raise ValueError
        if _has_control(key) or _has_control(value):
            raise ValueError
        result[key] = value
    if set(result) - _OPTIONAL_QUERY != _REQUIRED_QUERY:
        raise ValueError
    if result.get("headerType", "none") != "none":
        raise ValueError
    spider_x = result.get("spx", "")
    if (
        len(spider_x) > 256
        or (spider_x and not spider_x.startswith("/"))
        or any(ord(character) < 0x21 or ord(character) > 0x7E
               for character in spider_x)
    ):
        raise ValueError
    return result


def _canonical_server(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not _valid_dns_hostname(value):
            raise ValueError from None
        return value.lower()
    if not is_public_unicast_ipv4(address):
        raise ValueError
    return address.compressed


def _parse_node(line: str) -> Dict[str, Any]:
    try:
        if not line or len(line) > MAX_NODE_LINE:
            raise ValueError
        uri, _, _fragment = line.partition("#")
        if _has_control(line) or "\\" in uri or _PERCENT_ESCAPE.search(uri):
            raise ValueError
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme != "vless" or not parsed.netloc:
            raise ValueError
        if parsed.password is not None or parsed.username is None:
            raise ValueError
        canonical_uuid = str(uuid.UUID(parsed.username))
        if parsed.username != canonical_uuid:
            raise ValueError
        if parsed.path not in ("", "/"):
            raise ValueError
        server = _canonical_server(parsed.hostname or "")
        try:
            port = parsed.port
        except ValueError:
            raise ValueError from None
        if port is None or not 1 <= port <= 65535:
            raise ValueError
        query = _decode_query(parsed.query)
        if (
            query["encryption"] != "none"
            or query["security"] != "reality"
            or query["type"] != "tcp"
            or query["flow"] != "xtls-rprx-vision"
            or query["fp"] not in _MODERN_FINGERPRINTS
        ):
            raise ValueError
        sni = query["sni"]
        if (
            not 1 <= len(sni) <= 253
            or _has_control(sni)
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in sni
            )
        ):
            raise ValueError
        public_key = query["pbk"]
        if not 16 <= len(public_key) <= 128 or not _BASE64URL.fullmatch(public_key):
            raise ValueError
        short_id = query["sid"]
        if (
            len(short_id) > 16
            or len(short_id) % 2
            or (short_id != "" and not _HEX.fullmatch(short_id))
        ):
            raise ValueError
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("subscription contains an invalid VLESS/REALITY node") from None

    return {
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": canonical_uuid,
        "network": "tcp",
        "tls": True,
        "servername": sni.lower(),
        "client-fingerprint": query["fp"],
        "reality-opts": {
            "public-key": public_key,
            "short-id": short_id.lower(),
        },
        "flow": "xtls-rprx-vision",
        "udp": False,
    }


def _validate_yaml_tree(node: Node, *, depth: int = 0, count: List[int]) -> None:
    if depth > MAX_YAML_DEPTH:
        raise ValueError
    count[0] += 1
    if count[0] > MAX_YAML_NODES:
        raise ValueError
    if isinstance(node, ScalarNode):
        return
    if isinstance(node, SequenceNode):
        for item in node.value:
            _validate_yaml_tree(item, depth=depth + 1, count=count)
        return
    if isinstance(node, MappingNode):
        seen = set()
        for key, value in node.value:
            if (
                not isinstance(key, ScalarNode)
                or key.tag != "tag:yaml.org,2002:str"
                or not key.value
                or key.value in seen
            ):
                raise ValueError
            seen.add(key.value)
            _validate_yaml_tree(value, depth=depth + 1, count=count)
        return
    raise ValueError


def _yaml_mapping(node: Node) -> Dict[str, Node]:
    if not isinstance(node, MappingNode):
        raise ValueError
    return {key.value: value for key, value in node.value}


def _yaml_string(node: Optional[Node]) -> str:
    if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:str":
        raise ValueError
    return node.value


def _yaml_integer(node: Optional[Node]) -> int:
    if (
        not isinstance(node, ScalarNode)
        or node.tag != "tag:yaml.org,2002:int"
        or not re.fullmatch(r"[1-9][0-9]*", node.value)
    ):
        raise ValueError
    return int(node.value, 10)


def _yaml_boolean(node: Optional[Node]) -> bool:
    if (
        not isinstance(node, ScalarNode)
        or node.tag != "tag:yaml.org,2002:bool"
        or node.value not in ("true", "false")
    ):
        raise ValueError
    return node.value == "true"


def _parse_clash_vless(node: Node) -> Optional[Dict[str, Any]]:
    fields = _yaml_mapping(node)
    node_type = _yaml_string(fields.get("type"))
    if node_type != "vless":
        return None

    network_node = fields.get("network")
    if not isinstance(network_node, ScalarNode):
        raise ValueError
    if network_node.tag != "tag:yaml.org,2002:str":
        raise ValueError
    if network_node.value != "tcp":
        return None

    flow_node = fields.get("flow")
    reality_node = fields.get("reality-opts")
    if flow_node is None and reality_node is None:
        return None
    network = _yaml_string(network_node)
    tls = _yaml_boolean(fields.get("tls"))
    flow = _yaml_string(flow_node)
    if (
        network != "tcp"
        or tls is not True
        or flow != "xtls-rprx-vision"
        or reality_node is None
    ):
        return None

    required = {
        "name", "type", "server", "port", "uuid", "network", "tls",
        "flow", "servername", "reality-opts", "client-fingerprint",
    }
    optional = {"udp", "skip-cert-verify", "encryption"}
    if not required <= set(fields) or set(fields) - required - optional:
        raise ValueError

    name = _yaml_string(fields["name"])
    if not 1 <= len(name) <= 256:
        raise ValueError
    server = _canonical_server(_yaml_string(fields["server"]))
    port = _yaml_integer(fields["port"])
    if not 1 <= port <= 65535:
        raise ValueError
    raw_uuid = _yaml_string(fields["uuid"])
    canonical_uuid = str(uuid.UUID(raw_uuid))
    if raw_uuid != canonical_uuid:
        raise ValueError

    if "udp" in fields:
        _yaml_boolean(fields["udp"])
    if (
        "skip-cert-verify" in fields
        and _yaml_boolean(fields["skip-cert-verify"]) is not False
    ):
        raise ValueError
    if (
        "encryption" in fields
        and _yaml_string(fields["encryption"]) not in ("", "none")
    ):
        raise ValueError

    sni = _yaml_string(fields["servername"])
    if (
        not 1 <= len(sni) <= 253
        or _has_control(sni)
        or any(ord(character) < 0x21 or ord(character) > 0x7E
               for character in sni)
    ):
        raise ValueError
    fingerprint = _yaml_string(fields["client-fingerprint"])
    if fingerprint not in _MODERN_FINGERPRINTS:
        raise ValueError

    reality = _yaml_mapping(fields["reality-opts"])
    if set(reality) - {"public-key", "short-id", "support-x25519mlkem768"}:
        raise ValueError
    if "public-key" not in reality:
        raise ValueError
    if (
        "support-x25519mlkem768" in reality
        and _yaml_boolean(reality["support-x25519mlkem768"]) is not False
    ):
        raise ValueError
    public_key = _yaml_string(reality["public-key"])
    if len(public_key) != 43 or not _BASE64URL.fullmatch(public_key):
        raise ValueError
    try:
        decoded_key = base64.b64decode(
            public_key + "=", altchars=b"-_", validate=True,
        )
    except (binascii.Error, ValueError):
        raise ValueError from None
    if (
        len(decoded_key) != 32
        or base64.urlsafe_b64encode(decoded_key).decode("ascii").rstrip("=")
        != public_key
    ):
        raise ValueError
    short_id = _yaml_string(reality.get("short-id", ScalarNode(
        tag="tag:yaml.org,2002:str", value="",
    )))
    if (
        len(short_id) > 16
        or len(short_id) % 2
        or (short_id and not _HEX.fullmatch(short_id))
    ):
        raise ValueError

    return {
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": canonical_uuid,
        "network": "tcp",
        "tls": True,
        "servername": sni.lower(),
        "client-fingerprint": fingerprint,
        "reality-opts": {
            "public-key": public_key,
            "short-id": short_id.lower(),
        },
        "flow": "xtls-rprx-vision",
        "udp": False,
    }


def _preflight_clash_yaml(text: str) -> None:
    forbidden = (AliasToken, AnchorToken, DirectiveToken, TagToken)
    collection_starts = (
        BlockMappingStartToken, BlockSequenceStartToken,
        FlowMappingStartToken, FlowSequenceStartToken,
    )
    collection_ends = (BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken)
    nodes = 0
    depth = 0
    for token in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(token, forbidden):
            raise ValueError
        if isinstance(token, ScalarToken):
            nodes += 1
        elif isinstance(token, collection_starts):
            nodes += 1
            depth += 1
            if depth > MAX_YAML_DEPTH:
                raise ValueError
        elif isinstance(token, collection_ends):
            depth -= 1
            if depth < 0:
                raise ValueError
        if nodes > MAX_YAML_NODES:
            raise ValueError
    if depth != 0:
        raise ValueError


def _parse_clash_yaml(payload: bytes) -> List[Dict[str, Any]]:
    text = payload.decode("utf-8-sig")
    _preflight_clash_yaml(text)
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if root is None:
        raise ValueError
    _validate_yaml_tree(root, count=[0])
    fields = _yaml_mapping(root)
    proxies = fields.get("proxies")
    if (
        not isinstance(proxies, SequenceNode)
        or not 1 <= len(proxies.value) <= MAX_SUBSCRIPTION_NODES
    ):
        raise ValueError
    nodes = []
    for item in proxies.value:
        node = _parse_clash_vless(item)
        if node is not None:
            nodes.append(node)
    if not nodes:
        raise ValueError
    return nodes


def parse_vless_subscription(payload: bytes) -> List[Dict[str, Any]]:
    """Parse a share-link list or Clash YAML into a narrow Mihomo shape."""
    try:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_SUBSCRIPTION_BYTES:
            raise ValueError
        candidate = payload.strip(b" \t\r\n")
        if not candidate.startswith(b"vless://"):
            try:
                candidate = _decode_base64_wrapped(candidate)
            except ValueError:
                return _parse_clash_yaml(candidate)
        text = candidate.decode("utf-8")
        if any(
            unicodedata.category(character).startswith("C")
            and character not in "\r\n"
            for character in text
        ):
            raise ValueError
        lines = []
        for raw_line in text.split("\n"):
            line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
            if line:
                lines.append(line)
        if not 1 <= len(lines) <= MAX_SUBSCRIPTION_NODES:
            raise ValueError
        return [_parse_node(line) for line in lines]
    except (TypeError, ValueError, UnicodeError, RecursionError, yaml.YAMLError):
        raise ValueError("subscription payload is invalid") from None


def origin_hostname(node: Dict[str, Any]) -> Optional[str]:
    """Имя хоста узла до пиннинга, если адрес задан именем, а не литералом."""
    server = node.get("server")
    if not isinstance(server, str) or not _valid_dns_hostname(server):
        return None
    try:
        ipaddress.ip_address(server)
    except ValueError:
        return server
    return None


def resolve_public_node_servers(
    nodes: List[Dict[str, Any]],
    *,
    resolver: Callable[..., Iterable[Any]] = socket.getaddrinfo,
) -> List[Dict[str, Any]]:
    """Pin every node hostname to a deterministic public A/AAAA result."""
    resolved_nodes: List[Dict[str, Any]] = []
    try:
        for node in nodes:
            server = node["server"]
            try:
                literal = ipaddress.ip_address(server)
            except ValueError:
                answers = resolver(
                    server, int(node["port"]),
                    type=socket.SOCK_STREAM,
                )
                addresses = {
                    ipaddress.ip_address(answer[4][0])
                    for answer in answers
                }
                if (not addresses
                        or any(not is_public_unicast_address(address)
                               for address in addresses)):
                    raise ValueError
                ipv4_addresses = [
                    address for address in addresses
                    if is_public_unicast_ipv4(address)
                ]
                if not ipv4_addresses:
                    raise ValueError
                literal = min(ipv4_addresses, key=int)
            if not is_public_unicast_ipv4(literal):
                raise ValueError
            pinned = dict(node)
            pinned["server"] = literal.compressed
            resolved_nodes.append(pinned)
    except (IndexError, KeyError, TypeError, ValueError, OSError, socket.gaierror):
        raise ValueError("subscription node resolution failed") from None
    return resolved_nodes


def resolve_public_subscription_host(
    url: str,
    *,
    resolver: Callable[..., Iterable[Any]] = socket.getaddrinfo,
) -> str:
    """Return one public IPv4 and reject any non-public DNS result."""
    try:
        hostname = urllib.parse.urlsplit(validate_subscription_url(url)).hostname
        if hostname is None:
            raise ValueError
        answers = resolver(hostname, 443, type=socket.SOCK_STREAM)
        addresses = {
            ipaddress.ip_address(answer[4][0])
            for answer in answers
        }
        if (not addresses
                or any(not is_public_unicast_address(address)
                       for address in addresses)):
            raise ValueError
        ipv4_addresses = [
            address for address in addresses if is_public_unicast_ipv4(address)
        ]
        if not ipv4_addresses:
            raise ValueError
        return min(ipv4_addresses, key=int).compressed
    except (IndexError, KeyError, TypeError, ValueError, OSError, socket.gaierror):
        raise ValueError("subscription origin resolution failed") from None


async def _terminate_worker_inner(process: Any) -> None:
    try:
        process.terminate()
    except ProcessLookupError:
        await process.wait()
        return
    try:
        await asyncio.wait_for(
            process.wait(), timeout=WORKER_TERMINATE_GRACE_S,
        )
    except (asyncio.TimeoutError, ProcessLookupError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()


async def _bounded_worker_exchange(process: Any, request: bytes) -> bytes:
    if process.stdin is None or process.stdout is None:
        raise SubscriptionFetchError("subscription worker pipes are unavailable")
    process.stdin.write(request)
    await process.stdin.drain()
    process.stdin.close()
    try:
        await process.stdin.wait_closed()
    except (AttributeError, BrokenPipeError, ConnectionResetError):
        pass

    chunks = []
    size = 0
    while True:
        chunk = await process.stdout.read(
            min(8192, MAX_WORKER_RESPONSE_BYTES + 1 - size)
        )
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_WORKER_RESPONSE_BYTES:
            raise SubscriptionFetchError("subscription worker response is too large")
    await process.wait()
    return b"".join(chunks)


def _decode_worker_nodes(raw: bytes) -> List[Dict[str, Any]]:
    try:
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {"nodes", "origins"}:
            raise ValueError
        nodes = value["nodes"]
        origins = value["origins"]
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_SUBSCRIPTION_NODES:
            raise ValueError
        if not isinstance(origins, list) or len(origins) != len(nodes):
            raise ValueError
        decoded: List[Dict[str, Any]] = []
        for node, origin in zip(nodes, origins):
            if not isinstance(node, dict):
                raise ValueError
            address = ipaddress.ip_address(node.get("server"))
            if (
                not is_public_unicast_ipv4(address)
                or node.get("server") != address.compressed
            ):
                raise ValueError
            if origin is not None and (
                    not isinstance(origin, str)
                    or not _valid_dns_hostname(origin)):
                raise ValueError
            # Транспортный ключ: снимается вызывающим ДО валидации узла,
            # набор ключей которого сравнивается строгим множеством.
            decoded.append({**node, ORIGIN_KEY: origin})
        return decoded
    except (TypeError, ValueError, UnicodeDecodeError):
        raise SubscriptionFetchError(
            "subscription worker response is invalid"
        ) from None


async def _fetch_with_worker(url: str, timeout_s: float) -> List[Dict[str, Any]]:
    request = json.dumps(
        {"schema": WORKER_SCHEMA, "timeout_s": timeout_s, "url": url},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "sunny_digest.vpn_subscription_worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    exchange = asyncio.create_task(_bounded_worker_exchange(process, request))
    try:
        raw = await asyncio.wait_for(exchange, timeout=timeout_s + 1)
        if process.returncode != 0:
            raise SubscriptionFetchError("subscription worker failed")
        return _decode_worker_nodes(raw)
    except BaseException:
        # Cleanup lives in its own task. Repeated cancellation of the caller
        # cannot interrupt TERM/KILL/reap or the exchange-task drain.
        cleanup = asyncio.create_task(_cleanup_failed_worker(process, exchange))
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError
        raise


async def _cleanup_failed_worker(process: Any, exchange: asyncio.Task[Any]) -> None:
    try:
        await _terminate_worker_inner(process)
    finally:
        if not exchange.done():
            exchange.cancel()
        try:
            await exchange
        except BaseException:
            pass


async def fetch_vless_subscription(
    url: Any,
    *,
    fetcher: Optional[Callable[[str, float, int], bytes]] = None,
    timeout_s: float = 15,
) -> List[Dict[str, Any]]:
    """Download and parse a subscription while redacting every failure."""
    validated = validate_subscription_url(url)
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, (int, float))
        or not math.isfinite(timeout_s)
        or not 0 < timeout_s <= 60
    ):
        raise ValueError("subscription timeout is invalid")
    if fetcher is None:
        try:
            return await _fetch_with_worker(validated, float(timeout_s))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise SubscriptionFetchError("subscription download failed") from None

    try:
        # ``fetcher`` is an in-process test seam. Production always uses the
        # killable worker above, so no bearer-bearing network call can outlive
        # cancellation or reset in a background thread.
        payload = fetcher(validated, timeout_s, MAX_SUBSCRIPTION_BYTES)
        if not isinstance(payload, bytes) or len(payload) > MAX_SUBSCRIPTION_BYTES:
            raise SubscriptionFetchError
    except Exception:
        raise SubscriptionFetchError("subscription download failed") from None
    try:
        parsed = parse_vless_subscription(payload)
    except ValueError:
        raise SubscriptionFetchError("subscription response is invalid") from None
    # Тестовый seam обязан отдавать ту же форму, что и воркер, иначе тесты
    # проверяли бы путь, которого в проде нет.
    return [{**node, ORIGIN_KEY: origin_hostname(node)} for node in parsed]
