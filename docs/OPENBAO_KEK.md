# OpenBao — External KEK Source for the PAM Vault

The PAM credential vault envelope-encrypts every secret version under a
key-encryption key (KEK). Until now the KEK could only come from process
environment (`VAULT_KEK`/`VAULT_KEKS` or the `ENCRYPTION_KEY` fallback) —
meaning the root of the vault's crypto lived in container env/manifests.

With OpenBao (the MPL-2.0 **open-source** fork of HashiCorp Vault — Vault
itself is BUSL-licensed now), the KEK material is fetched **once at startup**
from an OpenBao KV-v2 secret over TLS with a scoped token:

```
access/governance/admin service ──(boot, TLS, X-Vault-Token)──► OpenBao KV v2
        │                                                        secret/openidx/vault-kek
        ▼
   in-memory keyring (exactly as before — request paths never touch OpenBao)
```

- The root key **never lives in process env**; OpenBao provides the audit
  trail and rotation workflow around it.
- **Fail-closed**: if OpenBao is configured but unreachable/denied/malformed,
  startup aborts — it never silently falls back to env keys (that would mask
  a mis-configured or compromised OpenBao).
- After boot the vault behaves exactly as before; OpenBao availability does
  not affect request paths.

## Setup

```bash
# 1. Seed the KEK in OpenBao (single-key form)
bao kv put secret/openidx/vault-kek kek="$(openssl rand -base64 32)"
#    ...or the multi-key rotation form:
bao kv put secret/openidx/vault-kek \
  keks="0:<base64-32B>,1:<base64-32B>" active_kek_id=1

# 2. Point the services at it (access-service, governance-service, admin-api)
BAO_ADDR=https://openbao.internal:8200
BAO_TOKEN=<token with read on the path>
BAO_KEK_PATH=secret/openidx/vault-kek
BAO_CACERT=/etc/ssl/openbao-ca.pem   # optional private-CA trust; verification
                                     # is never skipped
```

When all three of `BAO_ADDR`/`BAO_TOKEN`/`BAO_KEK_PATH` are set the OpenBao
source takes precedence; leave any unset and the env-based keys work exactly
as before. Dev compose ships an optional `--profile openbao` dev-mode server
for local testing.

## Key rotation

Write a new entry to `keks` with a fresh id, flip `active_kek_id`, and
rolling-restart the services: new seals use the new KEK while old versions
still open under their original id (the keyring keeps every listed key).
