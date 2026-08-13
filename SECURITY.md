# Security policy

Do not open a public issue for a vulnerability that could expose a Telegram
session, provider credential, raw message text, or the Sunny upload chain.
Contact the repository owner privately through GitHub instead.

## Trust boundary

The collector's Telegram session authorizes the same account capabilities as
any already-authorized Telegram client. Telegram 2FA protects new logins; it
does not neutralize a stolen live session. Revoke the device named
`Sunny Umbrel` in Telegram immediately if the host or app is suspected to be
compromised.

The design limits ordinary operation to one immutable set of exact group peers,
but host root — or a
container that effectively gains host root — can still copy the session. The
app therefore has no host mounts, Docker socket access, host network, privileged
mode, or backups of `data/private`. Any separately installed Portainer with Docker
socket access is nevertheless part of the trusted computing base: protect it with
strong authentication, expose it only to trusted LAN/Tailscale clients, and stop
it when it is not needed.

Every Telegram client is constructed with a mandatory loopback SOCKS proxy. An
embedded immutable Mihomo binary receives one locally rendered static
VLESS/REALITY TCP/Vision node with a public-IP destination; it has no DIRECT rule,
remote provider, TUN, controller, LAN listener, or ambient proxy. A missing or dead
proxy blocks Telegram before `connect()`. OpenRouter and SSH do not use it. The VPN
setup accepts one HTTPS bearer subscription. Its URL is sent only over stdin to a
bounded killable downloader; raw/base64 share lists and Clash YAML are supported.
Clash YAML is scanned and composed without constructors, and aliases, anchors, tags,
directives, merge/duplicate keys, and unknown VLESS capabilities are rejected. Neither
the raw URL nor provider response is persisted or logged. Subscription origin/node
hostnames are pinned to DNS-vetted public IPv4 addresses. Mihomo config/cache live on collector `tmpfs` and
are erased after the child is physically reaped. Factory reset cannot promise SSD
forensic erasure or revoke the provider token; rotate that token after compromise.

Daily selected-chat text is memory-only. OpenRouter receives chat-local
`participant-N` labels instead of stable Telegram sender/message IDs. Native
mentions are the narrow exception: a durable event may contain a sanitized snippet
of at most 300 UTF-16 units, chat title, sender display name and message link. It is
persisted byte-for-byte until the receiver acknowledges it and is then retained by
Sunny's normal outbox/Telegram delivery path. Media is never downloaded and sender
IDs are not exported. Pending digest and mention payloads are excluded from Umbrel
backups together with their atomic temporary files. Local acknowledged checkpoints
contain only metadata and prevent a rolled-back receiver from causing old messages
to be scanned or delivered again.

Every OpenRouter request forces `provider.zdr=true` and
`provider.data_collection=deny`; a dedicated key, a small spend limit, disabled
account logging/opt-in training, and narrow model/provider policy remain required
defence in depth. Setup has one uninterrupted one-hour monotonic lease. Message-link
resolution durably enters a one-shot phase before Telegram access; an interrupted
attempt or collector restart before chat lock requires factory reset and a new
login. Resolving links uses one bounded setup enumeration of up to 500 recent dialogs.
Telegram may include their latest messages across the paged `getDialogs` responses, but
the collector uses only peer/title metadata, does not fetch or follow the linked
message, and persists neither submitted links nor returned message text. Chat
selection stores `initial_message_id=0` for every selected peer without scanning
its history. A separate explicit activation first durably records the current exact
heads and only then clears pre-existing unread state, without exporting historical
mentions. The first authenticated daily `due=true` gate
independently derives each 72-hour lower boundary from receiver `server_time`, and
rows older than that timestamp are discarded before OpenRouter. Thereafter a
mention-bearing range is marked read only after its bounded event has a durable
receiver receipt; no-mention ranges are checkpointed locally before read-ACK.

## Incident response

1. In Telegram, terminate the `Sunny Umbrel` session.
2. Stop the Umbrel app.
3. Remove the dedicated upload public key from Sunny's receiver.
4. Revoke the dedicated OpenRouter key.
5. Preserve only redacted logs; never publish session or request bodies.
6. Reinstall and provision with fresh keys after the cause is understood.

Factory reset is not proof of remote revocation. Before its first asynchronous wait
it durably records that revocation is required; it then cancels local work and
attempts Telegram logout before deleting credentials. If Telegram does not confirm logout,
the UI keeps a persistent blocking warning: terminate **Sunny Umbrel** manually in
Telegram Settings → Devices, then acknowledge that action in the app. The backed-up
non-secret outstanding-session marker deliberately produces the same warning after
a config-only restore: confirm remote device termination, acknowledge it, and start
a completely new credential epoch. Restored chain metadata is never reused.
