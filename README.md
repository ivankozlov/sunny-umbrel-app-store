# Sunny Personal Digest for Umbrel

Community App Store package for a narrowly scoped collector: it reads text from
one explicitly selected Telegram group, creates a daily Russian digest through
OpenRouter, and uploads only the final bounded payload to Sunny over a pinned
SSH forced command.

> **Release gate:** this checkout is intentionally not installable yet. The app
> manifest is disabled and Compose contains a digest placeholder until the
> public `linux/amd64` + `linux/arm64` GHCR image is built and verified.

## Security model

Telegram does not let an API ID/hash or an authorized user session restrict
itself to selected chats. The containment is therefore implemented locally and
fail-closed:

- setup may enumerate dialogs exactly once; only groups/supergroups are shown;
- selection stores one exact `InputPeer` (`kind`, ID, access hash), deletes the
  dialog list, and permanently locks the Telegram session to that peer;
- runtime never calls generic entity resolution, receives no push updates, and
  never downloads media;
- changing the account, chat, model, provider key, or receiver endpoint requires
  factory reset, which first persists a blocking revocation marker, then signals
  cancellation, attempts Telegram logout, and deletes all local credentials, keys,
  and their exact crash-temporary files. If Telegram does not confirm logout, a
  persistent UI warning blocks new setup until the device is terminated manually
  and that action is acknowledged;
- consent expires after at most 90 days. Renewal can only extend consent for the
  already locked peer; it cannot change any credential or endpoint. The
  authenticated receiver clock is checked after the gate, so a slow Umbrel
  clock cannot extend an expired consent window;
- each run asks Sunny's authenticated `status-v1` gate before Telegram or
  OpenRouter. `due: false` means neither service is contacted;
- raw chat text exists only in collector memory. The only durable content is an
  exact final upload payload awaiting acknowledgement. Sender and message IDs are
  replaced with prompt-local `participant-N` labels before OpenRouter;
- after an accepted upload, an atomic local checkpoint records the sequence, hash,
  cursor, and date before pending bytes are deleted. A rolled-back or jumped Sunny
  receiver state is rejected before Telegram is contacted;
- SSH uses a dedicated generated Ed25519 key, exact pinned `known_hosts`, a
  literal `status-v1`/`upload-v1` remote command, and no forwarding or password
  fallback.

Root access to the Umbrel host can still copy the live Telegram StringSession.
Telegram 2FA protects authorization of a new client; it does not make a stolen
authorized session harmless. If the host is suspected compromised, terminate
the device named **Sunny Umbrel** in Telegram immediately.

## Container boundary

```text
Umbrel app_proxy (Umbrel login)
        │
        ▼
web :8080 (second Basic Auth with APP_PASSWORD)
        │  narrow JSON IPC over Unix socket
        ▼
collector ── Telegram exact InputPeer
    │      ├── OpenRouter (selected text, only when due)
    │      └── SSH forced-command receiver
    │
    ├── /data/config   settings, known_hosts, ACK checkpoint, pending final payload
    ├── /data/private  Telegram session, API/provider/upload keys
    └── /data/runtime  socket, redacted status, heartbeat
```

`web` mounts only `data/runtime`. During setup, credentials necessarily transit
through its authenticated form and Unix-socket client, but it never writes them
and never mounts `data/config` or `data/private`. Status contains no provider
keys, session data, raw messages, known-host key, or private upload key.

Umbrel backups exclude `data/private`, `data/runtime`, the exact pending payload,
and its atomic crash-temporary files. Config metadata includes a non-secret
`telegram-session-outstanding` marker that is durably armed before the first
Telegram authorization request. After a config-only restore the missing session
plus that marker creates a blocking warning: terminate/verify **Sunny Umbrel** in
Telegram Settings → Devices, acknowledge that remote action in the UI, and only
then provision a fresh Telegram authorization, OpenRouter key, upload key, and
receiver binding. Never reuse restored chain metadata as a new credential epoch.

## Provisioning

Provision in this order:

1. Create Telegram application credentials at `my.telegram.org`. These identify
   the client application but do **not** limit which chats the user session can
   access.
2. Create a dedicated OpenRouter key with a small spending limit. Do not reuse a
   general-purpose account key.
3. Obtain the DO Ed25519 SSH host-key line through a trusted channel. Never
   bootstrap trust with `ssh-keyscan` from the Umbrel.
4. Publish the collector image and complete the release gate below.
5. Add the public Community App Store URL in Umbrel, then install
   `Sunny Personal Digest`. The additional username is `sunny`; the password is
   the deterministic app password shown by Umbrel.
6. Complete Telegram setup, lock the exact group, then use the displayed public
   bootstrap values to install Sunny's forced-command receiver binding. Until
   this binding exists, the app fails closed before Telegram runtime access.

The setup UI collects API credentials, receiver host/port, the exact pinned
`known_hosts` line, and a consent expiration. SSH login is deliberately fixed to
`root`, matching the installer-owned `/root/.ssh/authorized_keys`; its forced
command immediately executes the receiver as the dedicated non-root service
user. Telegram sends a login code and, when enabled, asks for the 2FA password.

After login, open the dialog list once and select the pilot group. The UI then
shows a canonical source UUID, bootstrap message cursor, upload public key, and
fingerprint. Register exactly that public key in Sunny's receiver configuration.
Until the server binding is installed, runs fail closed before Telegram access
because the authenticated status request cannot succeed.

The bootstrap cursor is the newest selected-peer message strictly before the
72-hour lookback boundary. No raw bootstrap messages are stored. Daily scans use
a server-issued cutoff snapshot and a deterministic 96 KiB prompt budget; text
not included stays behind the cursor for a later due run. Media/service-only
events can advance the cursor without an OpenRouter request.

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

The real web path can be rendered without Telegram credentials by running a
separate read-only fake IPC fixture. This is not a production/demo bypass:
production code still connects to the configured Unix socket.

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
Use `--phase dialogs_listed` or `--phase chat_locked` for the other screens.

## Two-phase GitHub/GHCR release

The target public repository is
`https://github.com/ivankozlov/sunny-umbrel-app-store`. Both that repository and
`ghcr.io/ivankozlov/sunny-personal-digest` must be public so Umbrel can clone and
pull without registry credentials.

1. Push this directory as the repository root. Keep the disabled manifest and
   digest placeholder.
2. Protect the `ghcr-release` GitHub Environment with branch `main` and Ivan as
   required reviewer. Run the pinned `Publish image` workflow with version `0.1.0`.
   The publish job itself is also restricted to `main`. It runs all offline gates,
   refuses to overwrite an existing version tag, builds both
   supported architectures, pushes the tag, emits an SBOM/provenance
   attestation, and prints the immutable manifest digest. Tags are normally
   mutable registry references; the workflow guard and digest pin are both
   intentional protections. GitHub Actions, QEMU, Buildx, and BuildKit inputs are
   pinned; the privileged QEMU/BuildKit helper images use immutable OCI digests.
3. Confirm the GHCR package is public and inspect the manifest architectures.
4. Replace the whole `sha256:RELEASE_GATE_MULTIARCH_DIGEST` fragment in both
   Compose services with the exact workflow output `sha256:<64 hex>`, set
   `disabled: false`, and keep manifest/image/runtime versions in lockstep.
5. Run `python3 scripts/check_package.py --release`. Only then push the enabling
   commit and add the repository URL as an Umbrel Community App Store.

Never use a mutable tag without a digest, enable the app before the image is
public, or let a workflow rewrite the manifest automatically.

## Incident response

Use **Factory reset / отзыв доступа** in the UI when possible. It cancels local
work after first persisting a blocking revocation marker, but cannot retract a
request that OpenRouter already received. If the
UI reports unconfirmed Telegram logout, terminate **Sunny Umbrel** under Telegram
Settings → Devices and explicitly acknowledge that manual action before setup is
allowed again. For suspected host compromise, follow [SECURITY.md](SECURITY.md):
revoke the Telegram session, stop the app, remove the upload key server-side,
revoke the OpenRouter key, and reprovision from scratch.
