# Sunny Personal Chats for Umbrel

Umbrel package for a narrowly scoped Telegram user-session client. It was released
through a Community App Store; public distribution was withdrawn on 2026-08-14 and
restored on 2026-08-17.
It is bound to 1–16 immutable groups/supergroups and, since `0.2.13` (2026-09-13),
runs in a daily mode: every 5 minutes it only checks the receiver connection, and it
touches Telegram only in the 08:00–09:45 Moscow-time window announced by the receiver,
where it creates one combined daily digest through OpenRouter and then marks those groups
read up to their latest message once. Mentions are no longer collected or forwarded.

Up to `0.2.12` the collector cleared read state about once a minute and forwarded bounded
native-mention events to Sunny, with the daily digest accepted at 03:00–04:45 in the
owner's timezone. That minute tick kept the owner's account visibly "online" around the
clock, and the status disappeared while the collector was stopped (2026-09-13). Which
request produces the online status was not established, so the owner chose a short
morning window and dropped mentions.

> **Release gate:** install only a commit whose manifest has `disabled: false`
> and whose two Compose services pin the same real immutable multi-architecture
> digest. A checkout with `disabled: true` or
> `RELEASE_GATE_MULTIARCH_DIGEST` is intentionally not installable.

The app/package/image ID remains `sunny-personal-digest` for release continuity;
the v0.2 product name is **Sunny Personal Chats**. v0.2 is a breaking credential
generation and does not migrate the unpublished v0.1 pilot state.

The recorded state of the physical Umbrel on 2026-08-25 was `0.2.11`: eight exact
peers, the receiver generation, durable baseline, session, and active monitoring state
survived the updates and the first chat-set extension. The first nightly issue after the
extension was accepted on 2026-08-21 with all eight chat ranges and delivered in three
parts without error. The first `0.2.11` daily was accepted on 2026-08-26 in two parts
and visibly reported the old-tail skip for the extended chat. Local sender-name
restoration and forum-topic read acknowledgements for the added chat still need
observation; the native-mention smoke test never happened and was dropped together with
mentions on 2026-09-13. The collector was stopped from 2026-09-11 until the next update. The daily-mode
`0.2.13` was released on 2026-09-14, after the DO receiver with the new window and the
Sunny `chats` skill, and the owner updated the device the same night. Its first morning
(2026-09-14) took three failed ticks on the address stale after the nightly rotation, then
re-resolved itself and delivered digest sequence 20 at 08:34 Moscow time. Each step was
separately approved.
Both server steps must precede `0.2.13`: the app takes its window from the gate. Wire
`COLLECTOR_VERSION` remains `0.2.1`.

`0.2.14` was published on 2026-09-14 for direct material links and case-insensitive
sender-name restoration (tasks 235/238). Both architectures were verified anonymously;
Store enable commit `02c9d27` pins index digest
`sha256:161bfed7b9d2e3317cf75b8346676cd3676760e586af0e1ff06641213da2845e`.
The owner confirmed the device update to `0.2.14` on 2026-09-14. Sunny's worker received
the initial URL-line protection in `plain_tg` on 2026-09-14 with separate approval. The running container's
code hash, URL preservation through the outbox path (without sending to Telegram), and
health were verified. Receiver contact succeeded after the update; the gate carries
wire version `0.2.1`, not the app release, so the device version is owner-confirmed.
A review follow-up makes Sunny's URL-line protection case-insensitive for `HTTPS://`
and mixed-case schemes; its runtime hash was verified on 2026-09-18. All nine outbox
parts of the September 15–18 issues were sent, direct URLs survived delivery and
no Participant-N aliases remained. Task 235 is closed; task 238 now also requests
one source permalink per topic.
`0.2.15` was published on 2026-09-18 for task 238: each topic keeps the earliest
available referenced message (minimum valid ordinal, independent of model ref order)
and all deduplicated direct material URLs from the same references. The separate
materials section and wire version `0.2.1` are unchanged. The protected Publish image
workflow built source `ff3bb13` with `APP_VERSION=0.2.15`; anonymous verification
confirmed the public multi-arch index digest
`sha256:bb4ee4a1c6588cfeb75d30bd4da817fcd8a37081f8eb9c5f37ae4f4b9f95f70f`, both
architectures, and their version/source labels. Store enable commit `ab59c4d` pins
that exact index digest. The device Update to `0.2.15` remains pending.
The owner confirmed the daily-mode checks and closed task 244 on 2026-09-14.

The Store repository and the public GHCR package were withdrawn on 2026-08-14 and
restored on 2026-08-17; `0.2.6` through `0.2.15` have public multi-arch images.
**Update** and uninstall/reinstall therefore have a public source again. The device now
runs public `0.2.14` according to the owner; the `0.2.15` device Update is pending.
Its update from `0.2.9` to `0.2.10` exercised the real recreate/pull path and preserved
state. Docker image pruning remains out of bounds without a separate destructive
approval and a concrete need, and a future distribution closure could remove the public
source again. The `umbrel/` subtree of private source
repository `ivankozlov/sunny/main` deliberately remains a disabled, placeholder-pinned
Phase-A candidate; the enabling commit lives only in the Store repository.

## Product contract

- Since `0.2.14` (tasks 235/238), referenced materials retain their direct
  HTTP(S) URLs, including links hidden behind text, before the Telegram permalink.
  This also works in TNN, where messages disappear after 24 hours. The existing
  daily fetch supplies the links; there is no extra polling or local raw-message
  archive. Messages already deleted before that fetch cannot be recovered.
  Known sender aliases are restored regardless of capitalization (`Participant-N`
  as well as `participant-N`); unknown or ambiguous aliases still remain pseudonymous.
- Setup accepts one Telegram message link from each of 1–16 groups, resolves the
  exact accessible peers once, and shows their titles for immutable confirmation.
  A forum-message link selects the whole chat; individual topics are not selected.
- The linked message ID is syntax-only: setup neither fetches that message nor scans
  selected-peer history, and it does not mutate read state. Resolving links uses one
  setup-only paged enumeration of up to 500 recent dialogs; Telegram may include
  their latest messages across the `getDialogs` responses, but the app uses only peer/title metadata
  and persists neither submitted links nor returned message text.
- Link resolution is one-shot even if the network or process fails. An interrupted
  attempt requires factory reset and a fresh Telegram login. Runtime access starts
  only after link confirmation and the user's separate activation.
- First activation captures a frozen head for every exact peer, durably uploads
  a baseline with no mention events, and only after its receiver receipt marks
  existing unread messages through those heads as read. Historical mentions are
  never forwarded. Activation, a chat-set extension, and a pending monitor artifact are
  monitor-chain service work and run on the next tick, outside the morning window.
- Every read acknowledgement, including the activation baseline, uses
  `clear_mentions=False`: mentions are no longer delivered to Sunny, so the "@" badge
  stays lit until the owner opens the chat.
- Since `0.2.13` a tick runs every 5 minutes (fixed in code; `SUNNY_COLLECT_INTERVAL_S`
  is gone). Outside the window a tick only takes the authenticated receiver gate and
  reports `idle`. Inside the window — judged by the receiver's authenticated
  `server_time`, never the Umbrel clock — it first runs the digest and then, once per
  day, marks every chat read up to its latest message. Chat tops come from exact
  per-peer `GetPeerDialogs` requests without listing dialogs or reading text; the local
  cursor only moves forward and is persisted before the read acknowledgement. The two
  streams are independent: a failed digest does not cancel the read pass, and vice versa.
  A failed digest is retried on every tick of the window until the receiver accepts it.
  The read pass closes the day at once when every chat is confirmed; a partial or failed
  pass is retried in the same window, at most three attempts per day (only ticks where
  Telegram answered something count) and at most nine read-pass ticks in total, after which the day
  closes with its last outcome. The "done" mark and the attempt count live in memory, so
  a restart inside the window grants a fresh set of attempts. A chat still awaiting its
  extension baseline is skipped by the morning pass and counts as unconfirmed.
- Until 2026-09-13 scans ran about every 60 seconds and native `message.mentioned` events
  were detected locally without an LLM, carrying only chat title, display sender,
  timestamp, message ID, up to 300 UTF-16 units of text, and an exact link when Telegram
  provided one; a mention-bearing range was marked read only after a durable DO receipt,
  so unread could remain temporarily while Sunny was unavailable. Scans used an ID
  cursor, so a new post-activation mention was still forwarded if another Telegram
  client had read it before the next poll.
  `0.2.13` removed the scan but keeps the `mentions` wire contracts so a rollback to
  `0.2.12` stays possible. An undelivered pending `mentions` artifact left by `0.2.12` is
  discarded without upload; one the receiver already accepted is only applied locally.
- One daily OpenRouter call produces one combined Russian digest for all selected
  chats. OpenRouter and the killable worker see only per-chat `participant-N` aliases;
  the parent keeps sanitized display names in memory and locally restores only an
  unambiguous known alias in the final text. Unknown or ambiguous aliases stay
  pseudonymous. The accepted digest carries only numeric OpenRouter usage/cost fields
  into Sunny's LLM ledger; provider response data and request IDs are not forwarded.
  The monitor and digest hash/cursor chains are independent, so an LLM or daily failure
  cannot stop read handling or monitor service work. The receiver accepts a daily
  only from 08:00 through 09:45 inclusive in the fixed `Europe/Moscow` timezone (until
  2026-09-13: 03:00–04:45 in the owner's current IANA timezone); there is no same-day
  catch-up after that window. Sunny's `missing_daily_digest` fires after 09:45 Moscow time
  and is now the only alert for a dead Telegram route.

## Security model

Telegram API credentials and a user StringSession cannot restrict themselves to
specific chats. Containment is enforced locally and fails closed:

- every Telegram connection uses a mandatory loopback SOCKS endpoint backed by an
  embedded, immutable Mihomo `v1.19.29` binary. The static config contains exactly
  one sanitized VLESS/REALITY TCP/Vision node and no `DIRECT`, provider, proxy group,
  TUN, controller, LAN listener, or ambient proxy setting. OpenRouter and SSH remain
  on the ordinary Umbrel route;
- setup accepts an HTTPS bearer subscription whose response is either a raw/base64
  share-link list or Clash YAML. A killable subprocess pins both the HTTPS origin and
  chosen node to DNS-vetted public IPv4 addresses and receives the URL only over stdin.
  Clash YAML is parsed without constructors/aliases/tags and narrowed to an exact
  allowlist; neither the raw URL nor provider response is persisted. Initial setup
  starts the first sanitized node because no authorized Telegram session exists yet.
  After chat lock, a replacement subscription can be tested in place: candidates are
  tried in provider order through Mihomo and must complete only Telegram `connect()`
  plus `is_user_authorized()` in a killable child process before the active node is
  atomically replaced. The worker receives API/session secrets only over stdin and
  cannot inspect dialogs, messages, history, peers, or read state. An ordinary failed
  replacement restores the previous byte-exact node and runtime. Mihomo config/cache
  live in a random `tmpfs` directory and are erased only after TERM/KILL/reap;
- link resolution durably enters `resolving_links` before its single setup-only
  paged dialog enumeration. The setup must finish within one continuous one-hour monotonic
  lease; an interrupted lookup or collector restart before chat lock requires
  factory reset and a fresh Telegram login;
- locked settings store exact `InputPeer` values. Runtime never calls generic
  entity resolution, receives no push updates, and never downloads media;
- every runtime tick first obtains authenticated `status-v2` from the forced-command
  receiver and verifies the monitor chain position. Without a valid gate there is no
  Telegram access, read acknowledgement, or OpenRouter request; VPN, gateway, and
  Telegram start only for monitor service work or the morning pass;
- a morning pass shares one Telegram connection for the per-peer top snapshot (until
  2026-09-13: for the mention scan) and one connection for batched read acknowledgements.
  At most four whole peer operations run concurrently, each has a 30-second deadline,
  result order remains deterministic, and cancellation joins every sibling before
  disconnect;
- only an aggregate `TimeoutError` from already-active monitor service work may continue
  to the morning pass, and only after a fresh authenticated gate. Baseline,
  receiver-chain breaks (`ReceiverChainError`), pending conflicts, revocation, and
  cancellation remain fail-closed and abort the whole tick;
- every daily run derives each chat's lower boundary from authenticated receiver
  `server_time`, not the Umbrel wall clock: 72 hours, stretched over the days missed
  since the last accepted issue. A chat's cursor is pulled up to that boundary and never
  moves back, so a chat added by extension — a zero cursor mid-chain — starts at the
  window instead of replaying its own history from the beginning;
- when that pull skips unread messages of a live chat, the issue says so in its first
  lines: the wire declares the range from the receiver's cursor and hides the gap
  entirely, so the text is the only honest channel;
- raw daily chat text exists only in collector memory and the ZDR OpenRouter
  request. Every request sets `provider.zdr=true` and
  `provider.data_collection=deny`; Opus uses an explicit `max_tokens=32768` budget;
- bounded mention events were an explicit privacy exception until 2026-09-13: they were
  durable on Umbrel while pending, in DO receiver/inbox/backups, and in Sunny's Telegram
  outbox. `0.2.13` creates none, and already accepted events stay where they are.
  `CONSENT_SCOPE` still names them, because the stored scope is compared exactly; the
  setup and renewal consent labels in `web.py` are separate UI strings that still mention
  them too. Locked runtime health/status never contains titles, snippets, digest
  text, phone, credentials, or session data. During setup, the authenticated UI
  may show a masked phone number and resolved group titles for confirmation;
- two independent sequence/hash/cursor chains reject rollback, gaps, equivocation,
  and cross-stream confusion before Telegram read state advances;
- SSH uses a dedicated generated Ed25519 key, an exact externally verified
  `known_hosts` entry, literal `status-v2` / `monitor-upload-v2` /
  `digest-upload-v2` commands, and no forwarding, PTY, user rc, or password fallback.

Root access to the Umbrel host can still copy the live Telegram StringSession.
Telegram 2FA protects authorization of a new client; it does not make a stolen
authorized session harmless. On suspected compromise terminate the device named
**Sunny Umbrel** in Telegram immediately.

## Container boundary

```text
Umbrel app_proxy (Umbrel login)
        │
        ▼
web :8080 (second Basic Auth with APP_PASSWORD)
        │ narrow JSON IPC over Unix socket
        ▼
collector ── exact Telegram peers
    │      ├── loopback SOCKS → VLESS/REALITY → Telegram only
    │      ├── OpenRouter ZDR (daily raw text only, ssh forward via DO)
    │      └── SSH forced-command receiver (direct)
    │
    ├── /data/config   locked settings, checkpoints, pending final payloads
    ├── /data/private  Telegram session and provider/uploader credentials
    └── /data/runtime  socket, redacted status, heartbeat
```

`web` mounts only `data/runtime`. Credentials necessarily transit through its
authenticated forms and Unix-socket client during setup, but the web container
does not mount or write `data/config` or `data/private`.

Umbrel backups exclude `data/private`, `data/runtime`, both pending payloads, and
their crash-temporary files. Config retains a non-secret outstanding-session marker.
After a config-only restore, terminate or verify the old **Sunny Umbrel** device in
Telegram, acknowledge that action in the UI, and provision a fresh credential epoch.

## Provisioning

1. Create Telegram application credentials at `my.telegram.org`.
2. Prepare an HTTPS subscription containing at least one VLESS/REALITY TCP node with
   `flow=xtls-rprx-vision`; raw/base64 share-link lists and Clash YAML are supported.
   The URL is a bearer secret: paste it only into the Umbrel password field, never
   into chat, Git, logs, or an issue. A standard bounded `spx` parameter in a share
   link is accepted and discarded after validation.
3. Create a dedicated OpenRouter key with a small spending limit. Disable account
   input/output logging and opt-in use of prompts, and narrow the key/model/provider
   allowlist as far as practical.
4. Obtain the DO Ed25519 SSH host-key line through an independent trusted channel.
   Never bootstrap trust with `ssh-keyscan` on the Umbrel.
5. For every explicitly approved public release, complete the repository/image release
   gate below with a new immutable version. Published versions currently have an
   anonymous Community App Store and GHCR pull path.
6. Install **Sunny Personal Chats** only from that verified source. The additional
   username is `sunny`; Umbrel displays the deterministic app password.
7. Enter Telegram/VPN/OpenRouter/SSH settings and consent. VPN-source validation,
   any required subscription download/DNS pinning, Mihomo startup, and SOCKS readiness finish before
   settings are committed and before any Telegram authorization call. Consent covers
   daily selected-chat text sent to ZDR OpenRouter, bounded native-mention events
   sent to Sunny (still named in the scope, though `0.2.13` sends none), and read
   acknowledgements visible on every Telegram client.
8. Finish Telegram login, paste one message link from each of 1–16 groups, then
   verify the resolved titles and lock the exact checkbox set within the same
   one-hour collector process. Do not submit two links from the same group.

Accepted links are ordinary public or private `https://t.me/...` message links,
including forum-topic links; a forum link selects the whole group. Linked-discussion
`comment=` URLs and legacy basic groups without message links are unsupported. The
raw links and referenced message IDs are not retained after resolution.

After lock, the UI displays only public bootstrap data: source UUID, locked chat
IDs/titles, uploader public key/fingerprint, and endpoint metadata. It never displays
the private key or session. Do not activate monitoring until the receiver and Sunny
`chats` topic are ready. Changing the selection, model, endpoint, Telegram account,
OpenRouter key, or upload credentials requires factory reset and a new receiver
generation. Replacing only a failing VLESS/REALITY route uses the locked-page VPN
repair form and preserves all of that state.

### Replacing a failing VPN route after chat lock

Paste a fresh HTTPS VLESS/REALITY subscription into the password field on the locked
status page and explicitly confirm the replacement. The URL is consumed once and is
not written to config, status, or logs. Download happens before the collector pauses
normal runs; candidate testing is bounded and reports only a redacted phase, attempted
count, and fixed error class. A candidate becomes active only after the existing
Telegram session proves authorized through its SOCKS route. Failure keeps the previous
node and does not alter the StringSession, selected chats, source ID, uploader keys,
consent, pending payloads, or accepted monitor/digest checkpoints. Factory reset during
repair cancels and reaps the probe, stops the candidate, and continues revocation
without restarting a route behind the reset boundary.

On explicit activation, baseline upload precedes every read acknowledgement. If the
activation lands inside the morning window and the daily gate is already due, the same
runtime cycle may immediately read up to the trusted 72-hour boundary and call OpenRouter.

## Local verification

From this directory:

```bash
PYTHONPYCACHEPREFIX=/tmp/sunny-umbrel-pycache \
  PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/check_package.py
PYTHONPYCACHEPREFIX=/tmp/sunny-umbrel-pycache \
  python3 -m compileall -q src tests scripts
```

Docker is required for the production image check:

```bash
docker build --platform linux/amd64 -t sunny-personal-digest:local .
```

The real web path can be rendered without credentials with the test-only fake IPC
fixture. Production code still requires the configured Unix socket.

The Umbrel app terminal defaults to the `collector` service. That is intentional:
VPN/session diagnostics need `data/config` and `data/private`, which are absent from
the deliberately narrower `web` container.

```bash
tmpdir="$(mktemp -d)"
PYTHONPATH=src python3 tests/fake_ipc_server.py \
  --socket "$tmpdir/control.sock" --phase fresh

# In another terminal:
SUNNY_IPC_SOCKET="$tmpdir/control.sock" SUNNY_WEB_HOST=127.0.0.1 \
SUNNY_WEB_PORT=18080 SUNNY_UI_USERNAME=sunny SUNNY_UI_PASSWORD=test-only \
PYTHONPATH=src python3 -m sunny_digest.main web
```

Open `http://127.0.0.1:18080/` and authenticate as `sunny` / `test-only`.
Use the fixture phases to inspect login, message-link confirmation, locked, and
activation screens.

## Two-phase GitHub/GHCR release

Anonymous umbrelOS install/update requires both a public Store repository and a
public `ghcr.io/ivankozlov/sunny-personal-digest` image. Both surfaces were closed on
2026-08-14 and reopened on 2026-08-17 by an explicit owner decision; `v0.2.6`
through `v0.2.14` were published and enabled from there. Reopening stays an
explicit, per-release decision — never republish silently.

Every release follows this exact sequence, as `0.2.5` did and `0.2.6`–`0.2.14` did
after it: disabled source first, the protected `Publish image` workflow with
`bootstrap_empty_package=false`, independent public OCI verification for
`linux/amd64` and `linux/arm64`, and only then the exact digest pin plus
`disabled: false`. The `umbrel/` subtree of the private source repository
`ivankozlov/sunny/main` intentionally keeps `disabled: true` and the release
placeholder; the enabling commit lives only in the Store repository. Any further
release must use a new semver/tag and repeat the full sequence.
Wire `COLLECTOR_VERSION` deliberately stays `0.2.1` until an explicit chain migration.
Run `python3 scripts/check_package.py --release` before every enabling commit.

Never overwrite a version tag, use a mutable tag without its digest, or enable the
app before both the repository and image are available through the explicitly approved
distribution path.

## Offline recovery snapshot

The verified owner snapshot is kept in the owner's off-site backup storage, outside
this repository. It contains git bundles/source snapshots and the enabled Store commit
`fed43bacfdb82ebb5bccc17036314db6ce0b2d85`. Its multi-architecture OCI archive
(`sha256:b7a68169b37e884ed2b1cd0d17e24b4278fe1c9119ba2bd36268d6759631cea7`) was removed
on 2026-08-19, once public images for the current versions were available again.
Verify the remaining files against `SHA256SUMS` inside that directory before recovery.

The `v0.2.5` image itself is gone from both GHCR and the snapshot. Do not prune Docker
images on an Umbrel that still runs `v0.2.5` from its local cache — update it to a
version that is present in the registry first.

The snapshot deliberately contains no Umbrel `data/private`, Telegram StringSession,
credentials, or runtime state. Losing app-data therefore requires fresh Telegram
authorization and receiver/key rotation; the source/image snapshot alone is not a
seamless credential backup.

## Rollout boundary

Topic creation, public release, physical Umbrel installation, receiver `--apply`,
Sunny deployment, and activation are separate externally visible or persistent
actions. Each needs its own explicit approval. Activation intentionally clears the
existing unread baseline and, inside the morning window, can trigger a due daily request
immediately.

Until 2026-09-13 the post-activation smoke test was one **new** real mention: durable
receiver receipt before read disappearance, delivery to the Sunny topic **Чаты**, no
duplicate after retry, independent monitor/digest health, and then the first combined
daily digest. The mention part never ran and no longer applies. After a `0.2.13` update,
verify instead: about 12 receiver sessions per hour and no Telegram access outside the
window, the next digest accepted within 08:00–09:45 Moscow time, and a `read_acked`
read-acknowledgement result in the UI. Whether the account stops appearing online outside
the window can only be observed, not tested.

Production has completed setup, receiver rotation, activation, and one chat-set
extension, and now has eight peers. The first daily, while `0.2.3` was installed on
2026-08-14, exposed monitor-timeout starvation before any digest upload; `0.2.4`
shipped that isolation fix and the matching watchdog suppression. The next live run
exposed a separate failure before peer access:
the persisted route reset Telegram initialization. `0.2.5` was then installed; the
replacement subscription passed authorization on the first tested route, preserved
lock/session/baseline/checkpoints and active monitoring, and survived a reboot. The first
structured daily was accepted on 2026-08-20 in two parts without duplicates. The first
post-extension daily was accepted on 2026-08-21 with all eight chat ranges and delivered
in three parts without errors. The physical device was then updated from `0.2.9` through
`0.2.11`; receiver activity continued and the durable state remained aligned. Its first
`0.2.11` daily was accepted on 2026-08-26 in two parts and visibly reported the extended
chat's skipped old tail. Public `0.2.12` adds sanitized numeric OpenRouter usage/cost to
each non-empty daily artifact and is enabled in the Store, but the owner has not yet
confirmed a device update. Public `0.2.13` (daily mode) supersedes it; observe the first
morning issue after the device update, which is also the first usage-bearing artifact; there is deliberately no manual same-day backfill.

## Incident response

Use **Factory reset / revoke access** in the UI when possible. It persists a blocking
revocation marker, cancels local work, attempts Telegram logout, and deletes local
credentials and exact crash-temporary files. If logout is unconfirmed, terminate
**Sunny Umbrel** in Telegram Settings → Devices before provisioning again.

For suspected host compromise:

1. terminate the Telegram device;
2. revoke the dedicated OpenRouter key;
3. revoke the dedicated DO uploader key and disable its receiver gate;
4. stop and investigate the Umbrel, then reprovision with a new source/key epoch.

Changing the Telegram 2FA password alone does not revoke an active MTProto session.
See [SECURITY.md](SECURITY.md) and the private Sunny runbook for disable/rotation details.
