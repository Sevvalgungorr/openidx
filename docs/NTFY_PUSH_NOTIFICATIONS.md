# ntfy — Self-Hosted Push Notifications

The notification service has always modeled a `push` channel in
`notification_preferences`, but nothing delivered it. With ntfy
(open source, self-hosted) the push channel works end-to-end **without
Google FCM or Apple APNs in the path** — login approvals and security
alerts reach phones/browsers entirely from your own infrastructure.

## How it works

```
identity/admin service ──POST──►  ntfy server  ◄──subscribe── mobile app /
  (on CreateMultiChannel          (self-hosted)               ntfy app /
   Notification, channel=push)                                browser tab
```

- Each user has a stable, **unguessable topic**:
  `oidx-` + HMAC-SHA256(`NTFY_TOPIC_SECRET`, user_id)[:32]. Knowing a user id
  (or someone else's topic) reveals nothing — the secret is server-side only.
- Clients discover their own topic via
  `GET /api/v1/notifications/push-config` → `{enabled, base_url, topic}` and
  subscribe (the OpenIDX mobile app, the ntfy app, or a WebSocket/SSE
  browser subscription).
- Delivery is **best-effort and asynchronous**: a down ntfy server never
  blocks or fails the in-app notification write. Users can disable push per
  event type in notification preferences as with every other channel.

## Setup

```bash
# 1. Run ntfy (dev compose ships an optional profile)
docker compose -f deployments/docker/docker-compose.yml --profile ntfy up -d ntfy

# 2. Point the services at it
NTFY_BASE_URL=http://ntfy            # in-network URL (or your public HTTPS URL)
NTFY_TOPIC_SECRET=$(openssl rand -hex 32)
NTFY_TOKEN=<ntfy access token>       # optional; required if the server denies
                                     # anonymous publishes (recommended)
```

The channel enables only when **both** `NTFY_BASE_URL` and
`NTFY_TOPIC_SECRET` are set (the secret is what keeps topics unguessable, so
there is deliberately no way to run without it). Rotating the secret rotates
every user's topic; subscribers re-fetch push-config.

## Mobile app subscription

The OpenIDX mobile app subscribes automatically
(`mobile/src/features/notifications/push.ts`, mounted in the authenticated
app group): it fetches push-config with its session token, opens a WebSocket
to `{base}/{topic}/ws`, and shows each message as a local notification
(expo-notifications) — tapping opens the in-app notification list.

- **Foreground-only by design**: the socket closes in the background (RN
  freezes sockets there) and reconnects on return with ntfy's `since=`
  parameter, so messages that arrived while away are caught up and shown.
  True closed-app delivery would require the vendor push services this
  integration deliberately avoids; the in-app list remains the source of
  truth.
- No-ops cleanly when push-config reports `enabled:false` (server without
  ntfy) and on web builds.

## Security notes

- Titles/links are CR/LF-stripped before becoming ntfy headers (no header
  smuggling via notification content).
- The push-config endpoint only ever derives the **caller's own** topic.
- Prefer an access-token-protected ntfy (`NTFY_TOKEN`) so third parties
  can't publish to user topics even if a topic leaks.
