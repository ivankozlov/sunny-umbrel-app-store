# Sunny Personal Chats — contributor rules

This directory is designed to become the root of the public
`ivankozlov/sunny-umbrel-app-store` repository. It must contain no production
credentials, Telegram sessions, chat content, receiver keys, or rendered
runtime configuration.

## Security invariants

- Runtime reads one immutable set of 1–16 exact group/supergroup `InputPeer`
  values. Setup accepts one message link per group, durably enters a one-shot
  `resolving_links` phase before paged dialog enumeration, and permanently disables lookup
  after either an interrupted attempt or chat selection. Telegram may include
  the latest messages for up to 500 dialogs across those responses; the app may use
  only peer/title metadata and must not persist links or returned message text.
- VPN setup and locked-state repair accept one HTTPS bearer subscription. Its
  raw/base64 share-list or Clash YAML response is parsed in a killable worker;
  YAML constructors, aliases, anchors, tags, directives, merge keys, duplicate
  keys, and unknown VLESS capabilities are rejected. Only freshly built
  allowlisted VLESS/REALITY TCP/Vision nodes may be tested or persisted. Every
  Telegram client remains SOCKS-only with no direct fallback.
- Locked-state VPN repair preserves the Telegram session, immutable chat set,
  receiver generation, and durable monitor/digest state. It downloads before
  taking the run lock, then tests bounded candidates in provider order. Each
  candidate must pass a killable child-process `connect()` plus
  `is_user_authorized()` through the exact loopback Mihomo SOCKS endpoint; the
  probe may not inspect dialogs, messages, history, peers, or read state. API hash
  and StringSession reach that fixed worker only over stdin. The previous node
  remains byte-exact until a candidate succeeds; ordinary failure restores its
  runtime, while reset/revocation stops the candidate and proceeds fail-closed.
  The subscription URL, provider response, rejected candidates, and probe secrets
  are never persisted or logged. Initial setup still starts the first sanitized
  node because no authorized session exists yet; the Telegram login is its first
  end-to-end reachability check, and locked-state repair is not a substitute for
  completing that login.
- Changing the Telegram account, selected chats, OpenRouter key/model, or upload
  endpoint requires factory reset. Before its first await, reset persists a
  blocking revocation warning; it then cancels active work, attempts Telegram
  logout, and deletes the local session, credentials, and their exact atomic
  temporaries. Unconfirmed logout stays blocked until the operator confirms
  manual device revocation in Telegram.
- A non-secret outstanding-session marker is armed before the first Telegram auth
  network request and remains in config backups. Restoring config without private
  session material must require manual device revocation and acknowledgement before
  any new setup; never clear that marker merely because the session file is absent.
- The web service never mounts `data/private` or `data/config`. Setup credentials
  necessarily transit its authenticated form and memory, but it does not persist
  them; its only disk view is redacted runtime state and the narrow Unix socket.
- Daily source text is never written to disk or logs. A native mention may create
  one explicitly consented durable event containing only its chat title, sender
  display name, link and a sanitized snippet of at most 300 UTF-16 units. The
  exact pending event is retained until receiver acknowledgement; no media is
  downloaded and stable sender IDs never leave Umbrel.
- Accepted monitor and digest sequence/hash/cursor state is checkpointed locally
  before pending bytes are deleted. Receiver rollback or chain jumps must fail
  before Telegram access. The two streams remain independent so a failed daily
  digest cannot block mention delivery or read acknowledgements.
- Peer work uses one Telegram client with at most four concurrent whole-peer units;
  each unit gets a 30-second deadline after acquiring the semaphore, results retain
  locked-peer order, and cancellation must cancel and join every sibling before a
  cancellation-resistant disconnect. Only aggregate `TimeoutError` from an already
  active monitor may continue to digest, after reloading durable phase and taking a
  fresh authenticated gate. Baseline, chain/pending failures, and cancellation remain
  fail-closed.
- Every minute run obtains an authenticated remote monitor gate before Telegram
  access. OpenRouter and the daily history scan additionally require
  `digest.due: true`. Consent is checked locally before the gate and against the
  receiver's authenticated clock immediately afterwards, then again around each
  external operation. A slow or skewed Umbrel clock must never extend consent.
- Pre-lock setup is bound to one uninterrupted one-hour monotonic lease. A
  collector restart before chat lock invalidates that lease and must require
  factory reset and a new Telegram login.
- Chat selection must not fetch the linked message or scan selected-peer history:
  every selected chat stores contractual `initial_message_id=0`. A forum-topic
  link selects the whole group, duplicate links to one peer fail closed, and an
  explicit first activation snapshots the
  exact current heads, durably uploads a content-free baseline, and only after its
  receiver receipt clears existing unread state. Historical mentions are never
  exported. The first authenticated daily due gate independently derives the
  72-hour lower boundary per chat from receiver `server_time`, with an exact
  per-row time filter before any text reaches OpenRouter.
- After activation, the watcher scans every message ID after its own frozen
  cursor and detects mentions only from Telegram's native `mentioned` flag. A
  mention-bearing range is marked read only after its event batch has a durable
  receiver receipt; a no-mention range is checkpointed locally before read-ACK.
  Read-ACK always uses the exact peer and a bounded `max_id`.
- Every OpenRouter request must set `provider.zdr=true` and
  `provider.data_collection=deny`; account/key privacy controls remain defence
  in depth and may not replace the per-request guard. Opus must use explicit
  `max_tokens>=16384` so adaptive thinking cannot consume the usable response budget.
- The receiver daily window is exactly 03:00–04:45 inclusive in its authenticated
  IANA timezone, with no same-day catch-up. Sunny `chats` emits one durable
  `missing_daily_digest` per local date; the host watchdog suppresses only that
  duplicate code and must keep alerting every other monitor/digest failure.
- SSH must use the generated dedicated Ed25519 key and the exact pinned
  `known_hosts` entry. Never add `StrictHostKeyChecking=no` or `ssh-keyscan`.
- Do not add host networking, raw ports, Docker socket mounts, `privileged`,
  devices, or added Linux capabilities.

## Verification

Run from this directory:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/check_package.py
python3 -m compileall -q src tests scripts
```

`scripts/check_package.py --release` must remain red until the real public
multi-architecture GHCR digest replaces the release placeholder and the app
manifest is enabled. The publish job stays `main`-only behind the protected
`ghcr-release` Environment; privileged QEMU/BuildKit helpers remain digest-pinned.
The manifest's `defaultShell` stays pinned to `collector`, because VPN and
session diagnostics require the private/config mounts absent from `web`.
