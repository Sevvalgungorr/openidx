# Mobile Ziti + PAM-over-Overlay — Live Infra Runbook

This runbook captures the **live-infrastructure** fixes required to get a mobile
device fully onto the OpenZiti overlay and to reach PAM targets (SSH/RDP)
through the PAM broker. Unlike repo code (which self-heals on redeploy), these
settings live in container configs, the Ziti controller DB, and nginx, so they
are **lost on a rebuild** unless reapplied. Reapply in this order after any
controller/router/broker rebuild.

Context: live host `192.168.31.76`, site `https://openidx.tdv.org`, controller
`ctrl.tdv.org:1280`, router/BrowZer edge `browzer.tdv.org:3022`. Ziti admin
password at `/home/cmit/oidx-runtime/oidx-ziti/ziti_pwd`.

---

## 1. Router advertise address (stuck "connecting" on mobile)

**Symptom:** phone enrolls, gets an API session, but the tunnel stays at
"bağlanıyor"/connecting and never gets an edge-router connection.

**Cause:** the edge router advertised `ziti-router.localtest.me:3022`, which
resolves to `127.0.0.1` on the phone.

**Fix:** in the router's `/persistent/config.yml`, both `tls:3022` advertise
lines must be a publicly-resolvable name the cert SAN covers:

```yaml
# edge listener + link listener advertise
advertise: browzer.tdv.org:3022
```

The router runs with `ZITI_BOOTSTRAP_CONFIG=false`, so the edited file persists
across restarts. Back up before editing:
`cp /persistent/config.yml /tmp/router-config-backup-$(date +%s).yml`, then
`podman restart <router-container>`.

## 2. Auth policy must allow cert (native SDK clients)

**Symptom:** controller log `invalid certificate authentication, not allowed by
auth policy`; remote-access join fails after enrollment.

**Cause:** `openidx-browzer-auth` policy had `cert.allowed: false` (extJwt-only,
intended for BrowZer). Native SDK / ziti-edge-tunnel clients authenticate with a
client cert.

**Fix (mgmt API):** authenticate, then PATCH the policy:

```bash
# inside oidx-ziti-controller
TOKEN=$(curl -sk -X POST "https://localhost:1280/edge/management/v1/authenticate?method=password" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$(cat /path/ziti_pwd)\"}" | jq -r .data.token)
# find policy id, then:
curl -sk -X PATCH "https://localhost:1280/edge/management/v1/auth-policies/<id>" \
  -H "zt-session: $TOKEN" -H 'content-type: application/json' \
  -d '{"primary":{"cert":{"allowed":true}}}'
```

Or move native-SDK identities onto the default policy (which allows cert).

## 3. Broker containers must resolve public names

The PAM broker containers (`pam-ziti-tunnel`, `pam-guacamole-ziti`) share the
netns of the owner `pam-guacd-ziti`. The controller/router are reached by public
name, so the **shared** `/etc/hosts` needs:

```
192.168.31.76 browzer.tdv.org ctrl.tdv.org
```

Add to the owner container's `/etc/hosts` (shared by the netns peers). This is
reapplied by the broker deploy script; verify after a broker rebuild.

## 4. PAM SSH/RDP over overlay: the loopback-intercept trap (now fixed in code)

**Symptom:** Guacamole opens but the SSH/RDP session never connects; guacd log
shows connection refused to `127.0.0.1:<port>`.

**Root cause:** `ziti-edge-tunnel run` (TUN mode) **cannot intercept
`127.0.0.0/8`** — the kernel short-circuits loopback before it reaches the tun
device. guacd dialing the broker's `127.0.0.1:14000` intercept was never
captured.

**Fix (now in repo, PR #595):** the per-entry Ziti service carries an
`intercept.v1` config on a **non-loopback** address `100.64.2.1:<port>`, guacd
dials that address, and provisioning ensures the broker-dialer
edge-router-policy. Because this is now backend code, enabling ziti-reach on a
PAM entry provisions it correctly. The pieces:

- `intercept.v1` config `<service>-intercept` → `100.64.2.1:<interceptPort>`
- `openidx-erp-pam-broker-dialers` edge-router-policy → `#pam-broker-dialers`
  identity on `#all` routers (else `NO_EDGE_ROUTERS_AVAILABLE`)
- `openidx-serp-<service>` service-edge-router-policy → `#all`
- Guacamole connection host = `100.64.2.1` (from `dialTarget()`)

Verify end-to-end (from the broker netns):

```bash
podman exec pam-guacd-ziti sh -c 'nc -w10 100.64.2.1 <port>'
# expect: SSH-2.0-OpenSSH_...   (banner proves overlay reach to target:22)
```

## 5. Guacamole broker URL (login screen instead of session)

**Symptom:** clicking a ziti PAM entry shows the Guacamole **login** screen.

**Cause:** two brokers exist — the normal broker (guacd `10090`) and the ziti
broker (guacd `10091`). Both used the same public `/guacamole` URL, so tokens
minted for the ziti broker were presented to the normal broker (wrong session).

**Fix:**
- nginx: add `location /guacamole-ziti/ { proxy_pass http://127.0.0.1:10091/; ... }`
  in `/home/cmit/oidx-runtime/oidx-tls/nginx.conf` (alongside `/guacamole/`→10090)
- access env (`run-access.sh`): `GUACAMOLE_ZITI_PUBLIC_URL=https://openidx.tdv.org/guacamole-ziti`
- restart access; the ziti broker's client URLs now target its own path.

Guacamole client URL format:
`{publicBaseURL}/#/client/{connID}?token={token}` (token is per-broker; a
mismatch drops you to the login screen).

---

## Quick verification checklist (post-rebuild)

1. Router advertises `browzer.tdv.org:3022` (§1)
2. Native-SDK identities on a cert-allowed auth policy (§2)
3. Broker `/etc/hosts` resolves `browzer.tdv.org`/`ctrl.tdv.org` (§3)
4. Broker tunnel identity `hasEdgeRouterConnection: true`
5. `nc 100.64.2.1:<port>` from broker netns returns the target's SSH/RDP banner (§4)
6. `/guacamole-ziti/` nginx location + `GUACAMOLE_ZITI_PUBLIC_URL` set (§5)
