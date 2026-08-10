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

The design limits ordinary operation to one exact peer, but host root — or a
container that effectively gains host root — can still copy the session. The
app therefore has no host mounts, Docker socket access, host network, privileged
mode, or backups of `data/private`. Any separately installed Portainer with Docker
socket access is nevertheless part of the trusted computing base: protect it with
strong authentication, expose it only to trusted LAN/Tailscale clients, and stop
it when it is not needed.

Raw selected-chat text is memory-only. OpenRouter receives prompt-local
`participant-N` labels instead of stable Telegram sender/message IDs. The bounded
final digest is still sensitive derived content while awaiting SSH acknowledgement,
so it is excluded from Umbrel backups together with its atomic temporary files.
The local acknowledged chain checkpoint contains only metadata and prevents a
rolled-back receiver from causing old messages to be read again.

Every OpenRouter request forces `provider.zdr=true` and
`provider.data_collection=deny`; a dedicated key, a small spend limit, disabled
account logging/opt-in training, and narrow model/provider policy remain required
defence in depth. Setup has one uninterrupted one-hour monotonic lease. A collector
restart before chat lock invalidates that lease and requires factory reset and a
new login. Chat selection stores `initial_message_id=0` without reading selected-peer
history; only the first authenticated `due=true` gate derives the 72-hour lower
boundary from receiver `server_time`, and rows older than that timestamp are
discarded before OpenRouter.

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
