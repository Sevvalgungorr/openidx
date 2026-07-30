# openidx-connect

End-user native-access CLI for OpenIDX PAM (Wave B2). Brokers a short-lived SSH
certificate from OpenIDX and launches your **native `ssh`** client with it, so
operators keep their own tooling, private keys never leave the workstation, and
every session is centrally authorized and audited. Certificates expire in
minutes, so there is **no standing access** on the target host.

## How it works

```
openidx-connect ssh root@db01
```

1. Generates an ephemeral ed25519 keypair locally. The **private key never
   leaves your machine**.
2. Sends the **public** key to the access service (`POST
   /api/v1/access/pam/connect/ssh`), which signs a short-lived SSH user
   certificate with the org's server-side SSH CA and records/audits the
   brokered session.
3. Writes the key + cert to a private temp dir and execs the system `ssh` with
   `-i <key> -o IdentitiesOnly=yes` so the native client authenticates with the
   brokered cert and nothing else.
4. Wipes the temp material on exit.

Because the credential is a certificate the target already trusts (its `sshd`
has `TrustedUserCAKeys` set to the org CA public key), `ssh` "just works".

## Setup on target hosts (one-time)

Fetch the org CA public key and configure `sshd` to trust it:

```
openidx-connect ca > /etc/ssh/openidx_ca.pub
# /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/openidx_ca.pub
```

(If the CA has not been initialized yet, an admin runs `POST
/api/v1/access/pam/ssh-ca/init` once.)

## Configuration

| Flag | Env | Default |
|------|-----|---------|
| `--server` | `OPENIDX_SERVER` | `https://openidx.tdv.org` |
| `--token`  | `OPENIDX_TOKEN`  | (required) |
| `--insecure` | | `false` (dev only — skips TLS verify) |

The bearer token is any valid OpenIDX access token. Wire `OPENIDX_TOKEN` to
your existing token source (SSO/device-code/service token).

## Commands

```
openidx-connect ssh [user@]host [--ttl N] [--reason "..."] [--print] [-- <ssh args>]
openidx-connect ca
```

- `--ttl N`  certificate TTL in minutes (server clamps to its max).
- `--reason` audited reason string.
- `--print`  print the ssh command + material instead of executing (useful for
  scripting or debugging).
- Anything after the host is passed through to `ssh` (e.g. `-L` tunnels,
  remote commands).

## Build

```
go build ./cmd/openidx-connect                 # host platform
GOOS=windows go build ./cmd/openidx-connect     # cross-compile
GOOS=darwin  go build ./cmd/openidx-connect
```

The binary is a single static-ish Go executable with no runtime dependency
beyond the system `ssh` client.
