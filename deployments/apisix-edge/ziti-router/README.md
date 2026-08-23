# OpenZiti edge router — BrowZer WSS configuration

The BrowZer browser runtime connects to the overlay over a **WSS (secure
WebSocket) edge listener** on the router. Two distinct failure modes:
- **`code: 1007 — No WSS-Enabled Routers found`** → the router has no wss listener.
- **`code: 1016 — … Connect to Edge Router [wss://…:3023/ws], certificates issue`**
  → the wss listener presents a cert the browser doesn't trust (the ziti CA cert
  instead of the public `*.tdv.org` cert). Fixed by `transport.wss.identity` below.

This captures the WSS-specific router config that the OpenZiti quickstart image's
bootstrap does **not** generate, so it survives router recreation. Reference:
`config.reference.yml` (the live `/persistent/config.yml`).

## What BrowZer requires on the router

1. **A second `edge` listener bound to `wss`** (alongside the normal `tls` edge
   listener). From `config.reference.yml`:
   ```yaml
   listeners:
     - binding: edge
       address: tls:0.0.0.0:3022          # normal edge (SDK clients, e.g. access-proxy)
       options: { advertise: ziti-router.localtest.me:3022, ... }
     - binding: edge
       address: wss:0.0.0.0:3023          # BrowZer WSS
       options: { advertise: browzer.tdv.org:3023, ... }
     - binding: tunnel
       options: { mode: host }
   ```
   plus the `ws:` options block (writeTimeout/readTimeout/idleTimeout).

2. **A browser-trusted server cert presented ON THE WSS BINDING**, via
   **`transport.wss.identity`** (this is the part that actually makes the wss
   listener present the public cert). On ziti **v1.6.12** the wss listener does
   **NOT** honor `identity.alt_server_certs` for SNI selection — verified: even an
   exact-SAN cert in `alt_server_certs` was ignored and the wss listener kept
   serving the ziti CA cert, so the browser rejected it (`1016`). The wss binding
   reads its cert from `transport.wss.identity`:
   ```yaml
   transport:
     wss:                                 # NOTE: "wss", not "ws" (v1.6.12 rejects transport.ws)
       writeTimeout: 10
       readTimeout: 5
       idleTimeout: 120
       identity:
         server_cert: "/persistent/tdv-fullchain.pem"  # public *.tdv.org cert (presented to browsers)
         key:         "/persistent/tdv-key.pem"
         ca:          "/persistent/router.cas"          # required field; ziti CA bundle is fine
   ```
   Keep `identity.alt_server_certs` too (it satisfies the config-load advertise
   validation for `browzer.tdv.org` and covers the tls edge), but it is
   `transport.wss.identity` that fixes the browser handshake:
   ```yaml
   identity:
     cert:        "router.cert"                       # ziti-CA client identity (enrolled)
     server_cert: "/persistent/router.server.chain.cert"
     key:         "/persistent/router.key"
     ca:          "/persistent/router.cas"
     alt_server_certs:
       - server_cert: "/persistent/tdv-fullchain.pem"
         server_key:  "/persistent/tdv-key.pem"
   ```

   **Ruled out (don't waste time on these):** plain `ws:` listener →
   `transport.ws not supported. use transport.wss`; nginx/LB TLS-terminating in
   front of the wss → ziti requires upstream ALPN that nginx won't forward
   (openziti/ziti#2202, "not planned"); making `identity.server_cert` the public
   cert → breaks the `tls:3022` SDK edge (the access-proxy validates the router
   against the ziti CA).

## Gotcha: the enrolled cert can't carry `browzer.tdv.org`

`ziti router enroll` does **not** honor `edge.csr.sans` — the enrolled server
cert's SANs are auto-derived from `ZITI_ROUTER_ADVERTISED_ADDRESS` + defaults
(`localhost`, the container hostname, `127.0.0.1`, `::1`,
`ziti-router.localtest.me`). So you **cannot** get `browzer.tdv.org` into the
enrolled cert, and the `wss` advertise `browzer.tdv.org:3023` would fail config
load with *"identity is not valid for provided host: browzer.tdv.org"*. That is
exactly why `alt_server_certs` (the real `*.tdv.org` cert) is required — the WSS
listener presents it for the `browzer.tdv.org` SNI; BrowZer validates the overlay
against the ziti CA, the browser validates the WSS TLS against the public cert.

## Identity persistence (so recreate ≠ re-enroll)

Run with `ZITI_HOME=/persistent` and the named volume `oidx_ziti_router_cfg:/persistent`
so the enrolled identity (`router.cert/key/cas/server.chain.cert`) + `config.yml`
+ the alt cert live in the volume. Then **`podman start` (reboot) reuses the
identity** — only a wiped volume forces re-enrollment. (See the parent README's
"router hardening" note.)

## Bring-up / repair

`./setup-router-wss.sh` applies the cert + WSS config to the volume and runs the
router with the canonical command. **Prerequisite (one-time, or if the volume is
wiped):** enroll first —
```bash
# on the controller: issue a token for the edge-router
podman exec oidx-ziti-controller ziti edge re-enroll edge-router oidx-router \
  --jwt-output-file /tmp/oidx-router.jwt
podman cp oidx-ziti-controller:/tmp/oidx-router.jwt /home/cmit/oidx-runtime/oidx-ziti/oidx-router.jwt
chmod 644 /home/cmit/oidx-runtime/oidx-ziti/oidx-router.jwt
# then run once with enrollment on + the /jwt mount (see setup-router-wss.sh --enroll)
```

### Canonical run command (steady state — already enrolled)
```bash
podman run --replace -d --name oidx-ziti-router --network host \
  -e ZITI_HOME=/persistent \
  -e ZITI_CTRL_ADVERTISED_ADDRESS=ziti-controller.localtest.me -e ZITI_CTRL_ADVERTISED_PORT=1280 \
  -e ZITI_ROUTER_ADVERTISED_ADDRESS=ziti-router.localtest.me -e ZITI_ROUTER_PORT=3022 \
  -e ZITI_BOOTSTRAP=true -e ZITI_BOOTSTRAP_ENROLLMENT=false -e ZITI_BOOTSTRAP_CONFIG=false \
  -e PFXLOG_NO_JSON=true \
  -v oidx_ziti_router_cfg:/persistent \
  docker.io/openziti/ziti-router:latest
```
`ZITI_BOOTSTRAP_CONFIG=false` is critical — it stops the bootstrap from
regenerating `config.yml` and wiping the WSS listener / `alt_server_certs`.

## Verify
```bash
ss -ltn | grep 3023                                  # WSS listening
podman exec oidx-ziti-controller ziti edge list edge-routers   # oidx-router online=true
# the wss listener MUST present the public *.tdv.org cert (not the ziti CA cert):
openssl s_client -connect 127.0.0.1:3023 -servername browzer.tdv.org -alpn http/1.1 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer            # expect CN=*.tdv.org, issuer GlobalSign
# end-to-end WS upgrade with chain validation (expect HTTP/1.1 101, ssl_verify=0):
curl -s -o /dev/null -w '%{http_code} verify=%{ssl_verify_result}\n' --resolve browzer.tdv.org:3023:127.0.0.1 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==' --cacert /path/to/tdv-fullchain.pem \
  https://browzer.tdv.org:3023/ws
```
Then load `https://browzer.tdv.org`-fronted apps (psm/netgraph) in a browser and
confirm no `1007`.

## Caveats
- **Cert renewal:** `alt_server_certs` points at a **copy** in the volume
  (`/persistent/tdv-fullchain.pem`). Re-sync it when the GlobalSign `*.tdv.org`
  cert renews, else the WSS TLS cert expires.
- **`:3023` reachability:** the router is host-net and binds `:3023` directly;
  `browzer.tdv.org` must resolve to this box and `:3023` be reachable from clients
  (independent of the APISIX `:443` edge).
- **External ingress / NAT forwarding:** this box has no public IP; the public
  names DNAT through a gateway. The **CI/SDK data-path uses `tls:3022`** (only the
  in-browser BrowZer runtime uses `wss:3023`), so the gateway must forward BOTH
  `:3022` and `:3023` in addition to `:1280` and `:443`. A closed `:3022` forward
  makes CI enroll fine but hang forever on the data channel. See
  [`EXTERNAL-INGRESS.md`](./EXTERNAL-INGRESS.md) for the measured forwarding
  matrix and the 2026-08-17 incident (stale signer key + missing `:3022` forward).
