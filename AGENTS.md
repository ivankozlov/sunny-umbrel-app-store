# Sunny Personal Digest — contributor rules

This directory is designed to become the root of the public
`ivankozlov/sunny-umbrel-app-store` repository. It must contain no production
credentials, Telegram sessions, chat content, receiver keys, or rendered
runtime configuration.

## Security invariants

- Runtime reads one immutable `InputPeer`. Dialog enumeration is setup-only and
  is permanently disabled for an authorized session after chat selection.
- Changing the Telegram account, selected chat, OpenRouter key/model, or upload
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
- No raw Telegram text is written to disk or logs. The only durable content is
  the final bounded upload payload, kept byte-for-byte until acknowledged.
- Accepted sequence/hash/cursor/date is checkpointed locally before pending bytes
  are deleted. Receiver rollback or chain jumps must fail before Telegram access.
- Every run obtains `due: true` from the remote gate before Telegram or
  OpenRouter access. Consent is checked locally before the gate and against the
  receiver's authenticated clock immediately afterwards, then again before and
  after fetch/LLM and immediately before/during SSH upload. A slow or skewed
  Umbrel clock must never extend consent.
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
