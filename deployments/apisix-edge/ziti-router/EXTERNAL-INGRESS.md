# Ziti external ingress — NAT gateway port-forwarding (CI/SDK + BrowZer)

This box has **no public IP** of its own. It sits behind a NAT gateway; the
public names resolve to gateway IPs that DNAT (port-forward) selected TCP ports
back to this host, where the controller (APISIX -> controller) and the router
bind directly on `--network host`.

**Measured 2026-08-17** (`dig @8.8.8.8`, TCP connect probes from off-box):

```
ctrl.tdv.org     -> 88.255.52.182
browzer.tdv.org  -> 88.255.52.182     # same gateway
openidx.tdv.org  -> 88.255.52.182
```

## The forwarding matrix that MUST hold on the gateway (88.255.52.182)

| Public port | Forwards to (this host) | Who needs it | Consequence if closed |
| --- | --- | --- | --- |
| **443** | APISIX `:443` (host mode) | browser apps, ZAC-via-APISIX, ctrl mgmt-restricted | web edge dead |
| **1280** | controller edge-client `:1280` | **CI/SDK enroll + auth**, BrowZer bootstrap | enrollment/login fails |
| **3022** | router `tls:0.0.0.0:3022` | **CI/SDK data-path** (ziti-edge-tunnel, access-proxy) | *enroll succeeds, then data channel never connects* |
| 3023 | router `wss:0.0.0.0:3023` | BrowZer **browser** runtime only | BrowZer WSS `1007`; SDK unaffected |

Gateway `88.255.52.190` is a **second** gateway and is unrelated to CI — during
this incident every port on `.190` measured closed. Do not confuse the two:
CI resolves the public names to **`.182`**.

## The incident (root cause, measured — do not re-derive by guessing)

CI reported: overlay name `secops.ziti` resolves, but traffic never reaches
secops and the pipeline step hangs 13+ min. Two **independent** faults were
found, each proven with a live measurement, each with a mutation check:

### Fault A — router had a stale signer key (self-inflicted, fixed)
A controller restart earlier that day rotated the edge JWT signing key. The
router had been up 9 days on its **old enrolled cert**, so it could no longer
verify API-session JWTs:
```
GetApiSession: token is unverifiable: public key not found  (x36,114)
```
Symptom: a freshly-enrolled `ci-clients` identity connected to the router and
was **dropped after ~5.3 s (EOF)**. Fix: restart the router so it re-runs
**enrollment extension** and re-syncs the controller's current signer keys:
```
enrollment extension done  newFingerprint=e2e2e773...  (old 1948146c...)
finished synchronizing api sessions [count: 24]
```
After the restart: `public key not found` = 0, and the same probe identity
stayed **connected indefinitely** (measured 15+ s, no EOF). NOTE: the first
`podman restart` briefly exited(2) in a startup race and left the router DOWN;
a follow-up `podman start` came up clean and completed the enrollment
extension. Prefer `podman start` after a stop, and always re-check
`list edge-routers` shows `online=true` before walking away.

### Fault B — gateway was NOT forwarding router `:3022` (the actual blocker)
Independent of Fault A, the `.182` gateway had **`:3022` closed** while `:1280`
and `:443` were open. So CI could enroll (1280) and authenticate, the
controller told it to dial the router at `browzer.tdv.org:3022`, and that
connection **timed out at the gateway**. That is exactly "name resolves, data
never flows, step hangs". Opening `:3022` on the gateway fixed it — confirmed
live: `88.255.52.182:3022` went `kapali -> ACIK` and CI recovered.

**Correction to an earlier claim in this repo's notes:** a previous pass said
"CI uses wss:3023, so 3022 is only attack surface and can be removed." That was
wrong — it measured only gateway `.190`. The **CI SDK data-path uses `tls:3022`**;
`wss:3023` is for the in-**browser** BrowZer runtime. Do **not** remove the
`:3022` forward. If 3022 is closed on `.182`, CI breaks.

## What the router advertises (why the port names matter)

`/persistent/config.yml` (see `config.reference.yml`):
```yaml
listeners:
  - binding: edge
    address: tls:0.0.0.0:3022
    options: { advertise: browzer.tdv.org:3022, ... }   # SDK/CI data-path
  - binding: edge
    address: wss:0.0.0.0:3023
    options: { advertise: browzer.tdv.org:3023, ... }   # BrowZer browser only
```
The controller hands the **advertise** address to clients. Both advertise
`browzer.tdv.org`, so both `:3022` (SDK) and `:3023` (browser) must be reachable
at `browzer.tdv.org` from the respective client type. The router binds both on
`0.0.0.0` on this host; reachability is purely a gateway-forwarding question.

## Verify external ingress (run from OFF the box, or via a public IP)

```bash
# Public names must point at the CI gateway:
for h in ctrl.tdv.org browzer.tdv.org; do echo "$h -> $(dig +short @8.8.8.8 $h)"; done

# The four ports CI/browser need, on the gateway CI resolves to:
GW=88.255.52.182
for p in 443 1280 3022 3023; do
  timeout 5 bash -c "echo > /dev/tcp/$GW/$p" 2>/dev/null && echo ":$p OPEN" || echo ":$p CLOSED"
done
# Expect: 443 OPEN, 1280 OPEN, 3022 OPEN. 3023 only needed for in-browser BrowZer.

# TLS reaches the router edge on :3022 (ziti-edge ALPN):
openssl s_client -connect $GW:3022 -alpn ziti-edge </dev/null 2>&1 | grep CONNECTED
```

End-to-end (proves data-path, not just TCP): enroll a throwaway `ci-clients`
identity, run `ziti-edge-tunnel`, and confirm the router log shows **no**
`end of file` / `no api session found` / `public key not found` for it and the
tunnel process stays up > 10 s.

## On-box side is NOT the fix for Fault B

The router binds `:3022`/`:3023` correctly on this host (`ss -ltn | grep -E
'3022|3023'` shows both LISTEN) and reports `online=true`. Fault B lives on the
**NAT gateway**, not on this host — the fix is a gateway DNAT/forward rule for
`browzer.tdv.org:3022 -> <this-host>:3022`, not a router or config change here.
