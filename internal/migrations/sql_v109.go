package migrations

// Migration v109 — SSH certificate authority + session brokering (openidx connect).
//
// The Teleport-shaped need (Wave C1): let a user run `openidx connect <host>`
// and get a SHORT-LIVED, principal-scoped SSH certificate instead of a standing
// key on the box. OpenIDX becomes the SSH CA — hosts trust one CA public key
// (TrustedUserCAKeys) and every login is a fresh, minutes-long, audited cert. No
// key distribution, instant revocation by expiry, and a brokered-session ledger
// that also covers DB/K8s brokering.
//
//   - ssh_ca            one CA keypair per org. The PRIVATE key never lands here;
//     it lives envelope-encrypted in the vault (vault_secret_id).
//     Only the public key (for TrustedUserCAKeys) is stored.
//   - brokered_sessions the ledger of every brokered connection (ssh/db/k8s):
//     who, what target, which principal, cert serial, TTL.
//
// Org-scoped under the v37 FORCE-RLS belt. Additive/idempotent; plain statements.
var sshCASessionBrokerUp = `-- Migration 109: SSH CA + session brokering (openidx connect).

CREATE TABLE IF NOT EXISTS ssh_ca (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,
    key_type        VARCHAR(32) NOT NULL DEFAULT 'ssh-ed25519',
    vault_secret_id UUID NOT NULL,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS brokered_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    user_id      UUID NOT NULL,
    target_type  VARCHAR(16) NOT NULL DEFAULT 'ssh',
    target       VARCHAR(512) NOT NULL,
    principal    VARCHAR(255) NOT NULL,
    cert_serial  BIGINT,
    cert_key_id  VARCHAR(255),
    reason       TEXT,
    status       VARCHAR(16) NOT NULL DEFAULT 'active',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_brokered_sessions_live ON brokered_sessions(org_id, status);
CREATE INDEX IF NOT EXISTS idx_brokered_sessions_user ON brokered_sessions(org_id, user_id);
`

var sshCASessionBrokerDown = `-- Rollback 109: drop the SSH CA + brokered-session ledger.
DROP TABLE IF EXISTS brokered_sessions;
DROP TABLE IF EXISTS ssh_ca;
`
