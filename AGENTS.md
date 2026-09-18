# Sunny Personal Chats — contributor rules

This directory is the source snapshot kept in the private `ivankozlov/sunny`
repository and copied to the public `ivankozlov/sunny-umbrel-app-store` only for
explicitly approved releases. Public distribution was withdrawn on 2026-08-14 and
reopened on 2026-08-17; every further release still requires separate approval.
The directory must contain no production credentials, Telegram sessions, chat
content, receiver keys, or rendered runtime configuration.

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
- Telegram and OpenRouter use different egress paths on purpose. Telegram goes
  through the Mihomo SOCKS listener; OpenRouter goes through an ssh forward to
  the DO droplet (`openrouter_tunnel.py`), because in August 2026 no other path
  worked: a direct request from the home network was answered by a filter with
  HTTP 403 `Access denied by security policy`, and through the VLESS tunnel
  Cloudflare answered 403 from all three nodes — while the same request
  succeeded from those nodes themselves and from DO. TLS stays end-to-end: the
  droplet and sshd see the host name, never the body or the key. The
  certificate is verified against `openrouter.ai`, never against the loopback
  address, so occupying the local port cannot capture the request. There is no
  direct fallback: without the tunnel the request fails anyway, and a silent
  bypass would hide it.
- The tunnel key is separate from the upload key, is generated lazily so an
  already-configured instance gets one on upgrade, and is wiped by factory
  reset like every other credential. It authenticates as its own unprivileged
  account, never as the receiver's root: `permitopen` constrains only local
  forward targets while the `port-forwarding` flag also enables reverse
  forwarding, so a root key with those options could open a port on the droplet
  to the outside. The real restriction is an sshd `Match User` block —
  `AllowTcpForwarding local`, `PermitOpen openrouter.ai:443`, no reverse,
  stream-local or agent forwarding, `ForceCommand /bin/false` — installed from the Sunny
  repository root by `deploy/install_openrouter_tunnel.sh` — a droplet-side script that is
  NOT part of this snapshot — dry-run by default, validating the
  config with `sshd -t` before and after replacement and reloading rather than
  restarting. Key-line options duplicate that block so a lost `Match` still
  leaves no shell and no other address. The forward is raised only for the
  request and torn down after; a dead tunnel fails the attempt rather than
  falling back, and keygen lives in the digest path so its failure cannot stop
  the morning read pass or monitor service work (mention monitoring until 2026-09-13).
- The provider rotates its node address on a schedule while the app pins an IP
  literal, so Telegram vanished silently until someone replaced the node by
  hand (13–16.08, again on 19.08). The subscription URL is bearer material and
  is deliberately never stored, so the recovery key is the node's host name,
  which is not a secret: it is written next to the active node, under the same
  lock, and wiped by factory reset together with the stall counter and the
  cooldown. The detector counts a tick as stalled when the receiver gate —
  which reaches the droplet outside the VPN — answered but Telegram did not, in
  any of its forms: an aggregate timeout, a normal return where every chat
  failed on its own timeout, or a fast connection failure. Only the first form
  is a hang; a stale address reassigned to another tenant answers with RST, so
  watching for timeouts alone would miss the very failure this exists for.
  Until `0.2.13` the third form was any exception raised after the gate; the
  minute mention scan answered first on every tick and reset the counter, so
  that was harmless. Without the scan it let OpenRouter, tunnel, keygen, upload,
  or receiver-chain failures accumulate stalls and tear down a live route.
  Since `0.2.13` only a tick that actually went to Telegram may count, and only
  when Telegram answered none of its operations (`_TelegramContact`): `idle`
  ticks never touch the counter (without a Telegram request there is nothing to
  judge), any answered Telegram operation resets it, and a partial success — the
  digest went through, one chat's read acknowledgement did not — must not condemn
  the route. The daily 01:00 UTC rotation is therefore found in the morning
  window. Three fast failures (RST) re-resolve within about 10–15 minutes; a
  hanging route stretches each tick over its operation timeouts (up to 180
  seconds each) and the 300-second pause starts only after the tick ends, so it
  takes about half an hour. Those ticks do not spend read-acknowledgement
  attempts: only a tick where Telegram answered at least one operation does,
  otherwise the nightly rotation would exhaust the limit before the re-resolve
  and push the read pass to the next morning. After three such ticks the app
  re-resolves the name and moves itself, starting the attempt outside the run
  lock it will need.
  The candidate goes through the same path as a manual replacement: it is
  started, proven by a killable SOCKS authorization probe, and only then
  committed; an unchanged address is refused before the route is touched, and
  attempts are rate-limited. A node configured by an older version has no
  stored host name, and one manual replacement is what restores self-healing.
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
- Changing the Telegram account, OpenRouter key/model, or upload endpoint
  requires factory reset. The chat set is the one exception, and only forward:
  it may be EXTENDED without a new epoch, never shrunk or reordered. The server
  decides — `deploy/extend_chat_set.sh` adds the chat to the receiver config,
  seeds a zero cursor in both vectors and marks it pending — and the app merely
  picks up what the gate now announces. A compromised Umbrel therefore cannot
  widen its own access. Accepting the chat needs one message link, because
  `access_hash` is known only to the Telegram client and dialog enumeration
  stays closed after lock; that is the single permitted exception, bound to a
  durable one-shot `resolving_extension` phase entered before the network call
  and refused unless the gate already named that exact chat_id. Since `0.2.13`
  idle ticks no longer raise the VPN (after a restart outside the window there may be
  no route), so the extension raises the route itself
  before entering that phase: a VPN failure must not leave the phase set. Activation is an
  `extension_baseline` covering only the new chats: it continues the monitor
  chain rather than restarting it, so cursors and history of the existing chats
  survive. A baseline is validated against the chat set of the version it was
  created in — checking it against today's set would invalidate history on the
  first extension and wedge the receiver. Before its first await, reset persists a
  blocking revocation warning; it then cancels active work, attempts Telegram
  logout, and deletes the local session, credentials, and their exact atomic
  temporaries. Unconfirmed logout stays blocked until the operator confirms
  manual device revocation in Telegram.
- A non-secret outstanding-session marker is armed before the first Telegram auth
  network request and remains in config backups. Restoring config without private
  session material must require manual device revocation and acknowledgement before
  any new setup; never clear that marker merely because the session file is absent.
- The status file describes only the latest tick and is rewritten every tick
  (every minute until `0.2.13`, every 5 minutes since), so a rare failure used to
  survive exactly one tick and was overwritten before anyone saw it. The morning
  read-acknowledgement outcome (`read_ack_result`, `read_ack_error_type`) is
  carried across ticks for the same reason: the rest of the day is `idle`, and
  without the carry the UI would forget the morning result five minutes later.
  A bounded journal of the last 20 runs — timestamp, result,
  exception type, counters, with consecutive identical outcomes collapsed into a
  repeat count — is kept in the status and rendered in the UI. It carries no
  message text, chat titles, or senders, and is sanitized like every other
  status field.
- The web service never mounts `data/private` or `data/config`. Setup credentials
  necessarily transit its authenticated form and memory, but it does not persist
  them; its only disk view is redacted runtime state and the narrow Unix socket.
- Daily source text is never written to disk or logs. Until 2026-09-13 a native
  mention could create one explicitly consented durable event containing only its
  chat title, sender display name, link and a sanitized snippet of at most 300
  UTF-16 units, retained until receiver acknowledgement. Since `0.2.13` mentions are
  neither scanned nor forwarded (owner's decision): the `mentions` contracts stay in
  `contracts.py`, the receiver, and the Sunny skill only for wire compatibility and
  rollback to `0.2.12` — do not delete them, and do not bring the scan back without
  that decision being reversed. An undelivered pending `mentions` artifact left by
  `0.2.12` is discarded without upload (the receiver sits exactly at the local
  checkpoint and local cursors have not moved yet), while one already accepted is only
  applied locally. A rollback to `0.2.12` rescans that range only until the first
  `0.2.13` morning pass raises the local cursor to each chat's top; after it, those
  mentions are gone for good. No media is downloaded and stable sender IDs never leave Umbrel.
- Daily sender display names stay in the parent process only: OpenRouter and the
  killable worker receive per-chat `participant-N` aliases. The parent restores a
  name only for an unambiguous known alias in that chat; unknown or ambiguous aliases
  remain pseudonymous in the delivered digest.
  Match aliases case-insensitively, with exact token boundaries: task 238 found
  13 capitalized `Participant-N` tokens in the 2026-09-04 issue which the lowercase
  regex did not replace. Never infer an unknown alias or reuse another chat's map.
- Accepted monitor and digest sequence/hash/cursor state is checkpointed locally
  before pending bytes are deleted. Receiver rollback or chain jumps must fail
  before Telegram access: the monitor chain is verified on every tick, before the
  VPN and before deciding whether Telegram is needed at all, and a chain break
  (`ReceiverChainError`) aborts the whole tick. The two streams remain independent
  so an ordinary digest failure cannot block the morning read acknowledgement or
  monitor service work (mention delivery until 2026-09-13), and vice versa.
- Peer work uses one Telegram client with at most four concurrent whole-peer units;
  each unit gets a 30-second deadline after acquiring the semaphore, results retain
  locked-peer order, and cancellation must cancel and join every sibling before a
  cancellation-resistant disconnect. Only aggregate `TimeoutError` from already
  active monitor service work may continue to the morning pass, after reloading
  durable phase and taking a fresh authenticated gate. Baseline, chain/pending
  failures, and cancellation remain fail-closed.
- The scheduler tick is a fixed 300 seconds (`SCHEDULER_TICK_S`;
  `SUNNY_COLLECT_INTERVAL_S` was removed with `0.2.13`). The minute tick that walked
  Telegram around the clock kept the owner's account "online" (confirmed
  2026-09-13), and which request causes that is unknown — so, apart from explicit UI
  actions (setup, a new chat link, VPN replacement with its authorization probe, logout
  on reset), background work must not touch Telegram outside two cases. The automatic
  VPN re-resolve probe is derived from them: it needs three ticks in which Telegram did
  not answer and is rate-limited to once per 30 minutes. Every run obtains an authenticated remote
  gate first; VPN, gateway, and Telegram start only for monitor-chain service work
  (pending artifact, activation, extension — run immediately) or for the morning
  pass, which requires receiver `server_time` inside `[prepare_not_before,
  accept_until]` inclusive plus outstanding work (`due`, a pending digest, or the
  day's read acknowledgement not yet done). Every other tick is `idle`. Five
  minutes also keep the heartbeat inside the healthcheck's 900-second limit.
  OpenRouter and the daily history scan additionally require
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
  exported. EVERY authenticated daily due gate independently derives the lower
  boundary per chat from receiver `server_time` — 72 hours, stretched over the days
  missed since the last accepted issue — with an exact per-row time filter before any
  text reaches OpenRouter. The per-chat cursor is pulled up to that boundary and never
  moves back. While only the first issue (`sequence == 1`) did that, a chat added by
  extension arrived with a zero cursor mid-chain and was read from the beginning of its
  history: on 21–25.08.2026 five consecutive issues retold 2023 conversations, advancing
  by one prompt budget a day, while that chat's fresh messages never reached the issue.
  Pulling the cursor up has a flip side: a LIVE chat can lose a tail that missed the prompt
  budget and then outlived the window, and the wire shows nothing (the range is declared from
  the receiver's cursor). Such a skip must be announced in the issue itself — a
  `[пропущено старше окна выпуска]` header placed FIRST, because trimming always eats the
  tail. A chat still at cursor zero gets no warning: what it skips is its own prior history.
- Until 2026-09-13 the watcher scanned every message ID after its own frozen
  cursor and detected mentions only from Telegram's native `mentioned` flag; a
  mention-bearing range was marked read only after its event batch had a durable
  receiver receipt, while a no-mention range was checkpointed locally before
  read-ACK. Since `0.2.13` the morning pass runs after the digest, once per
  day: it takes each chat's top from exact per-peer `GetPeerDialogs` (no dialog
  listing, no text), raises the local cursor under `state_lock` only forward
  (`max(current, top)`), persists it, and then goes through the shared read-ACK
  retry. A chat still awaiting its extension baseline is skipped — acknowledging it
  first would push its local cursor past the future baseline range — and counts as
  unconfirmed. A fully confirmed day closes at once; a partial or failed pass is
  retried on the next ticks of the window, but at most `MORNING_READ_ACK_MAX_ATTEMPTS`
  (3) times per day key — counting only ticks where Telegram answered something —
  and at most `MORNING_READ_ACK_MAX_TICKS` (9) read-pass ticks in total, because every
  peer failing on a live connection (account-wide FLOOD_WAIT, CHANNEL_PRIVATE for all)
  looks exactly like a dead route from here; after either limit the day closes with
  the last outcome. Without
  the limit one permanently failing chat kept the day open, and every one of the
  window's 22 ticks raised the VPN and went to Telegram — exactly the "online"
  pattern daily mode exists to avoid; a chat whose extension baseline keeps failing
  in the window is therefore acknowledged the next morning. The "done" key
  `(source_id, chat set, digest_date)` and the attempt counter live in memory only:
  a durable mark would need a new `watch_state` field, whose field set stays closed
  for rollback to `0.2.12`, so a restart grants a fresh set of attempts; the chat set
  is part of the key so a chat accepted by extension after the morning pass is still
  acknowledged in the same window.
  Read-ACK always uses the exact peer, a bounded `max_id`, and
  `clear_mentions=False` on every path, including the activation baseline: mentions
  no longer reach Sunny, so clearing the "@" badge would silently hide a mention the
  owner learns about nowhere else. A forum needs a
  second step: `channels.readHistory` — what `send_read_acknowledge` sends — has
  no topic field at all, so it clears the group badge while every topic keeps
  its own unread count burning. Topics are therefore enumerated
  (`messages.getForumTopics`, bounded by `MAX_FORUM_TOPICS`) and closed one by
  one with `messages.readDiscussion`, exactly as official clients do. The
  enumeration also returns the topics' latest messages: only `id` and
  `unread_count` may be read from it, never the text — the same rule that
  governs dialog enumeration during setup. A non-forum answers
  `CHANNEL_FORUM_MISSING`, which is an ordinary answer rather than a failure,
  and a topic that fails to close must not undo the peer acknowledgement:
  otherwise one unreachable topic would make the group re-read forever.
- The model returns structure, never a rendered message: chats, topics with
  summaries, and a separate list of links, each pointing at sources by the
  per-run ordinal `n` printed in the prompt rows. The killable worker returns
  that structure verbatim (`worker.v3`); the digest text and every
  `https://t.me/c/<peer>/<id>` link are assembled in the parent, which is the
  only process holding the ordinal-to-message map. Stable Telegram message IDs
  therefore reach neither OpenRouter nor the subprocess, and an ordinal the
  model invented resolves to nothing and is dropped. The selection budget must
  count the `n` field: the gateway sizes one chat at a time while the assembled
  prompt is numbered across all of them, and bytes missing from the estimate
  overflow the bound after selection, failing the whole day.
- Task 235 (released in `0.2.14`): keep direct HTTP(S) material URLs
  from `MessageEntityUrl` and `MessageEntityTextUrl` in the parent-only
  `SelectedMessage.material_urls`. Decode visible URL offsets against the ORIGINAL
  UTF-16 message, before stripping whitespace. The prompt gets only `material_count`
  in addition to the existing text; the parent inserts source URLs before the
  Telegram permalink for each selected reference. Hidden URL targets must not be
  added to the worker request. TNN deletes messages after 24 hours, so a Telegram
  permalink alone loses access to the material. This adds no Telegram requests;
  links already deleted before the daily fetch cannot be recovered.
- Task 238 (`0.2.15` candidate): each topic uses the earliest available source
  permalink among all `refs` (minimum valid ordinal, not model ordering), retaining
  every direct material URL from those refs. A direct material can itself be a
  Telegram URL; do not discard it as an extra source permalink. The separate links
  section and collector wire version stay unchanged.
- Every chat returning empty lists is an answer, not a failure — the prompt
  explicitly allows "nothing notable today", and the issue then says so in one
  line. An empty `chats` array is a failure: the model walked no chat at all.
- Sections are separated by a blank line because Sunny splits the issue into
  Telegram messages on exactly that boundary, and a chat heading is never left
  dangling at the end of a part. The first part keeps the historical delivery
  key, so an issue delivered before splitting existed is not re-sent.
- The digest ceiling (24 000 UTF-16 units) and the receiver's payload ceiling
  are two different limits, and the text is trimmed by whole lines against both
  — an over-long issue is cut with a visible note, never dropped and never
  refused. The receiver's ceiling arrives in the gate and may be LOWER than
  ours: the app is released first so it can accept a raised ceiling, and only
  then does the receiver raise it. The reverse order fails gate validation and
  takes monitor service work and the read pass (mention monitoring until
  2026-09-13) down with the digest.
- Every OpenRouter request must set `provider.zdr=true` and
  `provider.data_collection=deny`; account/key privacy controls remain defence
  in depth and may not replace the per-request guard. Opus must use explicit
  `max_tokens>=32768` so adaptive thinking cannot consume the usable response
  budget: 16384 was nearly exhausted by it once an issue stopped fitting in one message.
- The receiver daily window is exactly 08:00–09:45 inclusive in the fixed
  `Europe/Moscow` timezone announced in its authenticated gate (until 2026-09-13:
  03:00–04:45 in the owner's current IANA timezone), with no same-day catch-up. The
  app never hard-codes the window: it takes `prepare_not_before`/`accept_until` from
  the gate, so behind an old receiver `0.2.13` would still touch Telegram at night.
  Sunny `chats` emits one durable `missing_daily_digest` per Moscow date after
  09:45 (per local date of the owner's timezone until 2026-09-13); the host watchdog suppresses only that duplicate code and must keep
  alerting every other monitor/digest failure.
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

In the `umbrel/` subtree of the private source repository `ivankozlov/sunny/main`,
`scripts/check_package.py --release` must remain red: the disabled manifest and release
placeholder are the intentional Phase-A state of the source tree. This does not
describe the Store `main`, where the enabling commits live — it carries enabled
`v0.2.14`, with the historical enabled `v0.2.5` still in its history. Distribution was
withdrawn on 2026-08-14 and reopened on 2026-08-17; the public GHCR package now holds
`v0.2.6` through `v0.2.14`, while `v0.2.5` stays deleted. Every release requires
separate approval, a new semver/tag, a real independently verified multi-architecture
digest, and a separate enabling commit; never overwrite the withdrawn `v0.2.5` tag. The publish job stays `main`-only behind
the protected `ghcr-release` Environment;
privileged QEMU/BuildKit helpers remain digest-pinned.
The manifest's `defaultShell` stays pinned to `collector`, because VPN and
session diagnostics require the private/config mounts absent from `web`.
