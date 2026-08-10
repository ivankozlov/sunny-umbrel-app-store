# Sunny Personal Chats for Umbrel

Community App Store package for a narrowly scoped Telegram user-session client.
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

## Product contract

- Setup lists Telegram groups once and accepts an immutable selection of 1–16.
  A forum is selected as a whole chat; individual topics are not selected.
- Selection itself does not read selected-peer history or mutate read state.
  Runtime access starts only after the user explicitly activates monitoring.
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
  chats. The monitor and digest hash/cursor chains are independent, so an LLM or
  daily failure cannot stop frequent read handling.

## Security model

Telegram API credentials and a user StringSession cannot restrict themselves to
specific chats. Containment is enforced locally and fails closed:

- dialog enumeration is setup-only; the setup must finish within one continuous
  one-hour monotonic lease. A collector restart before chat lock requires factory
  reset and a fresh Telegram login;
- locked settings store exact `InputPeer` values. Runtime never calls generic
  entity resolution, receives no push updates, and never downloads media;
- every runtime tick first obtains authenticated `status-v2` from the forced-command
  receiver. Without a valid gate there is no Telegram scan, read acknowledgement,
  or OpenRouter request;
- a watcher cycle shares one Telegram connection across every selected peer and
  one connection for batched read acknowledgements; one broken peer does not block
  healthy peers;
- the first daily run derives each 72-hour lower boundary from authenticated
  receiver `server_time`, not the Umbrel wall clock. Later runs continue independent
  digest cursors without dropping accumulated backlog;
- raw daily chat text exists only in collector memory and the ZDR OpenRouter
  request. Every request sets `provider.zdr=true` and
  `provider.data_collection=deny`;
- bounded mention events are an explicit privacy exception: they are durable on
  Umbrel while pending, in DO receiver/inbox/backups, and in Sunny's Telegram
  outbox. Health/status never contains titles, snippets, digest text, phone,
  credentials, or session data;
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
    │      ├── OpenRouter ZDR (daily raw text only)
    │      └── SSH forced-command receiver
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
2. Create a dedicated OpenRouter key with a small spending limit. Disable account
   input/output logging and opt-in use of prompts, and narrow the key/model/provider
   allowlist as far as practical.
3. Obtain the DO Ed25519 SSH host-key line through an independent trusted channel.
   Never bootstrap trust with `ssh-keyscan` on the Umbrel.
4. Complete the public repository/image release gate below.
5. Install **Sunny Personal Chats** from the Community App Store. The additional
   username is `sunny`; Umbrel displays the deterministic app password.
6. Enter Telegram/OpenRouter/SSH settings and consent. Consent explicitly covers
   daily selected-chat text sent to ZDR OpenRouter, bounded native-mention events
   sent to Sunny, and read acknowledgements visible on every Telegram client.
7. Finish Telegram login, enumerate groups once, select 1–16 checkboxes, and lock
   the exact set within the same one-hour collector process.

The UI then displays only public bootstrap data: source UUID, locked chat IDs/titles,
uploader public key/fingerprint, and endpoint metadata. It never displays the private
key or session. Do not activate monitoring until the receiver and Sunny `chats` topic
are ready. Changing the selection, model, endpoint, or credentials requires factory
reset and a new receiver generation.

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
Use the fixture phases to inspect login, multi-select, locked, and activation screens.

## Two-phase GitHub/GHCR release

The target repository is
`https://github.com/ivankozlov/sunny-umbrel-app-store`. Both the repository and
`ghcr.io/ivankozlov/sunny-personal-digest` must be public so umbrelOS can clone and
pull without registry credentials.

1. Push a disabled `0.2.0` source commit with the digest placeholder.
2. Run the pinned `Publish image` workflow from `main` through the protected
   `ghcr-release` Environment. `bootstrap_empty_package=true` remains permanently
   limited to the original `0.1.0`; it must be false for `0.2.0`.
3. Verify the public OCI index contains `linux/amd64` and `linux/arm64`.
4. Pin the exact workflow digest in both Compose services, set `disabled: false`,
   and keep manifest/image/runtime versions in lockstep.
5. Run `python3 scripts/check_package.py --release` before the enabling commit.

Never overwrite a version tag, use a mutable tag without its digest, or enable the
app before both the repository and image are public.

## Rollout boundary

Topic creation, public release, physical Umbrel installation, receiver `--apply`,
Sunny deployment, and activation are separate externally visible or persistent
actions. Each needs its own explicit approval. Activation intentionally clears the
existing unread baseline and can trigger a due daily request immediately.

After activation, create one **new** real mention for the smoke test. Verify durable
receiver receipt before read disappearance, delivery to the Sunny topic **Чаты**, no
duplicate after retry, independent monitor/digest health, and then the first combined
daily digest.

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
