# Security policy

Do not open a public issue for a vulnerability that could expose a Telegram
session, provider credential, raw message text, or the Sunny upload chain.
Contact the repository owner privately through GitHub instead.

## Trust boundary

The `0.3.0` source is a disabled security candidate, not the current `0.2.24`
deployment. Its rollout/acceptance gates are in [SECURITY_ROLLOUT.md](SECURITY_ROLLOUT.md).

Only guardian owns the encrypted vault, Telegram policy and receipt state machine.
The model collector and web have different UIDs, separate namespaces and separately
authorized Unix sockets; neither mounts config/private. Model jobs cannot invoke
Telegram, acknowledge messages, supply a receiver gate or change delivery cursors.
The model role receives the OpenRouter API key and its tunnel key during a job:
compromise can steal those keys and that job's prompt. Cancellation cannot erase
data already copied by a hostile process. A missing cleanup ACK closes the job gate
and requires a fresh locked guardian restart; the ACK itself is not cryptographic
proof that a compromised collector obeyed it.

Model grants carry paired host MONOTONIC/BOOTTIME expiries. A suspend gap invalidates
queued and active grants and requires a fresh receiver gate. The HTTP child checks
again before sending headers/prompt; active work is cancelled and reaped after resume.
These cooperative checks cannot recall a request already accepted by the provider
or stop a hostile collector using a copied model key independently.

The vault uses Argon2id (64 MiB, 3 iterations, 4 lanes) and authenticated Fernet
envelopes. Changing the phrase also rotates the DEK. Its keys are never persisted
in plaintext. A valid older snapshot remains decryptable with its old phrase;
whole-file rollback, historical snapshots, SSD forensic recovery, already stolen
sessions and plaintext pending digest/checkpoint metadata are outside this protection.
The encrypted vault remains excluded from Umbrel backups.

Passkeys protect online admin operations, not offline decryption. Someone holding
both the vault and its phrase can decrypt it without a passkey. WebAuthn requires
UV, exact fixed HTTPS Origin/RP ID, one-use challenges, expiry and operation/payload
binding. Public manifest entries are browser hints: authorization always uses the
decrypted canonical passkeys. Host root, trusted guardian/web compromise, malicious
UI code and deception about a legitimate action remain within the trust boundary.

All role processes and Python workers refuse unknown/nonzero cgroup swap allowance,
set zero soft/hard core limits and verify Linux dumpability is off. One DEK page is
mlock'ed and marked DONTDUMP; other Python/KDF copies are not guaranteed zeroized or
mlock'ed. Native exec resets dumpability: OpenSSH/Mihomo inherit zero core limits,
and secret-bearing native use additionally refuses piped host core handlers.
Private scratch must be owned tmpfs. Host hibernation or physical RAM extraction is
not prevented by cgroup swap limits; host policy is a separate acceptance gate.

The guardian's Telegram session authorizes the same account capabilities as
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
hostnames are pinned to DNS-vetted public IPv4 addresses. Initial setup starts the first
sanitized node before an authorized Telegram session exists. Once chats are locked, the
operator may submit a replacement subscription without resetting private or durable
state. The old node remains byte-exact on disk while bounded candidates are tested in
provider order. Each candidate runs behind Mihomo and must pass only `connect()` plus
`is_user_authorized()` in a killable subprocess before atomic commit; dialogs, messages,
history, peers, and read state are forbidden. API hash and StringSession reach the fixed
worker over stdin, never argv, environment, or a file, and its proxy is the exact
`127.0.0.1:7891` SOCKS endpoint with no direct fallback. Ordinary failure restores the
previous node/runtime; revocation cancels and reaps the candidate without reopening the
old route. Mihomo config/cache live on guardian `tmpfs` and are erased after the child
is physically reaped. Factory reset cannot promise SSD forensic erasure or revoke the
provider token; rotate that token after compromise.

Daily selected-chat text is memory-only. OpenRouter receives chat-local
`participant-N` labels instead of stable Telegram sender/message IDs. Until
2026-09-13 native mentions were the narrow exception: a durable event could contain a
sanitized snippet of at most 300 UTF-16 units, chat title, sender display name and
message link, persisted byte-for-byte until the receiver acknowledged it and then
retained by Sunny's normal outbox/Telegram delivery path. Since `0.2.13` mentions are
neither collected nor forwarded; an undelivered pending mention left by `0.2.12` is
discarded without upload. Media is never downloaded and sender
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
rows older than that timestamp are discarded before OpenRouter. Until 2026-09-13 a
mention-bearing range was then marked read only after its bounded event had a durable
receiver receipt, while a no-mention range was checkpointed locally before read-ACK.
Since `0.2.13` background work contacts Telegram only for monitor-chain service work and
in the receiver-announced 08:00–09:45 Moscow-time window: the daily digest (retried on
every tick of the window until the receiver accepts it), then a read acknowledgement up
to each chat's latest message, checkpointed locally before read-ACK, sent with
`clear_mentions=False`, and limited to three answered attempts and nine ticks per day. The automatic VPN
re-resolve follows from those: its authorization probe runs only after three ticks in
which Telegram did not answer, at most once per 30 minutes. Explicit UI actions (setup,
a new chat link, VPN replacement, logout on reset) contact Telegram on their own.

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
