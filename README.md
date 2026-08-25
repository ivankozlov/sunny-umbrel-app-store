# Sunny Personal Chats for Umbrel

Umbrel package for a narrowly scoped Telegram user-session client. It was released
through a Community App Store; public distribution was withdrawn on 2026-08-14 and
restored on 2026-08-17.
It watches 1–16 immutable groups/supergroups, clears read state about once a
minute, forwards bounded native-mention events to Sunny, and creates one combined
daily digest through OpenRouter.

> **Release gate:** install only a commit whose manifest has `disabled: false`
> and whose two Compose services pin the same real immutable multi-architecture
> digest. A checkout with `disabled: true` or
> `RELEASE_GATE_MULTIARCH_DIGEST` is intentionally not installable.

The app/package/image ID remains `sunny-personal-digest` for release continuity;
the v0.2 product name is **Sunny Personal Chats**. v0.2 is a breaking credential
generation and does not migrate the unpublished v0.1 pilot state.

The last recorded state of the physical Umbrel (2026-08-21) is `0.2.10`: eight exact
peers, the receiver generation, durable baseline, session, and active monitoring state
survived the updates and the first chat-set extension. The first nightly issue after the
extension was accepted on 2026-08-21 with all eight chat ranges and delivered in three
parts without error. The first `0.2.10` daily with locally restored sender names,
forum-topic read acknowledgements for the added chat, and a real native-mention event
still need observation. Wire `COLLECTOR_VERSION` remains `0.2.1`.

The Store repository and the public GHCR package were withdrawn on 2026-08-14 and
restored on 2026-08-17; `0.2.6` through `0.2.10` have public multi-arch images.
**Update** and uninstall/reinstall therefore have a public source again. The device now
runs public `0.2.10`; its update from `0.2.9` exercised the real recreate/pull path and
preserved state. Docker image pruning remains out of bounds without a separate destructive
approval and a concrete need, and a future distribution closure could remove the public
source again. The `umbrel/` subtree of private source
repository `ivankozlov/sunny/main` deliberately remains a disabled, placeholder-pinned
Phase-A candidate; the enabling commit lives only in the Store repository.

## Product contract

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
  never forwarded.
- Subsequent scans run about every 60 seconds. Native `message.mentioned` events
  are detected locally without an LLM and contain only chat title, display sender,
  timestamp, message ID, up to 300 UTF-16 units of text, and an exact link when
  Telegram provides one.
- A mention-bearing range is marked read only after a durable DO receipt. If Sunny
  is unavailable, unread may remain temporarily. Scans use an ID cursor, so a new
  post-activation mention is still forwarded if another Telegram client read it
  before the next poll.
- One daily OpenRouter call produces one combined Russian digest for all selected
  chats. OpenRouter and the killable worker see only per-chat `participant-N` aliases;
  the parent keeps sanitized display names in memory and locally restores only an
  unambiguous known alias in the final text. Unknown or ambiguous aliases stay
  pseudonymous. The monitor and digest hash/cursor chains are independent, so an LLM or
  daily failure cannot stop frequent read handling. The receiver accepts a daily
  only from 03:00 through 04:45 in the configured IANA timezone; there is no
  same-day catch-up after that window.

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
  receiver. Without a valid gate there is no Telegram scan, read acknowledgement,
  or OpenRouter request;
- a watcher cycle shares one Telegram connection across every selected peer and
  one connection for batched read acknowledgements. At most four whole peer operations
  run concurrently, each has a 30-second deadline, result order remains deterministic,
  and cancellation joins every sibling before disconnect;
- only an aggregate `TimeoutError` from an already-active monitor may continue to the
  independent digest path, and only after a fresh authenticated gate. Baseline,
  receiver-chain, pending conflicts, and cancellation remain fail-closed;
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
  `provider.data_collection=deny`; Opus uses an explicit `max_tokens=16384` budget;
- bounded mention events are an explicit privacy exception: they are durable on
  Umbrel while pending, in DO receiver/inbox/backups, and in Sunny's Telegram
  outbox. Locked runtime health/status never contains titles, snippets, digest
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
    │      ├── OpenRouter ZDR (daily raw text only, direct)
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
   sent to Sunny, and read acknowledgements visible on every Telegram client.
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
daily gate is already due, the same runtime cycle may immediately scan up to the
trusted 72-hour boundary and call OpenRouter.

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
through `v0.2.10` were published and enabled from there. Reopening stays an
explicit, per-release decision — never republish silently.

Every release follows this exact sequence, as `0.2.5` did and `0.2.6`–`0.2.10` did
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
existing unread baseline and can trigger a due daily request immediately.

After activation, create one **new** real mention for the smoke test. Verify durable
receiver receipt before read disappearance, delivery to the Sunny topic **Чаты**, no
duplicate after retry, independent monitor/digest health, and then the first combined
daily digest.

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
in three parts without errors. The physical device was then updated from `0.2.9` to
`0.2.10`; receiver activity continued and the durable state remained aligned. Observe the
next nightly issue for local sender-name restoration, the added chat's forum-topic read
acknowledgements, and a real native-mention event. There is deliberately no manual
same-day backfill.

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
