package migrations

// Migration v125 — RFC 8628 device authorization grant.
//
// The device flow exists for clients that cannot host a browser or take typed
// input: a TV app, a CLI on a headless box, a kiosk. The device asks for a code,
// shows the user a short user_code and a URL, and polls while the user
// authorizes on a second device that does have a browser.
//
// Two secrets with very different properties live in one row:
//
//   - device_code is a bearer credential the client polls with. It is stored as
//     a SHA-256 hash so a database disclosure does not hand the reader a set of
//     live grants to redeem.
//   - user_code is read aloud and typed by a human, so it cannot be long, and it
//     is stored in normalized plaintext because the verification page must look
//     it up from what the user typed. Its defence is entropy plus a short
//     lifetime plus throttling at the verification endpoint, not storage.
//
// The unique constraint on (org_id, user_code) is what makes "look up the code
// the user typed" unambiguous. It covers expired rows too, so a user_code is
// never reissued while its previous owner might still be reading it off a
// screen; the sweep in the issuance path retires old rows.
var deviceCodesUp = `-- Migration 125: RFC 8628 device authorization grant.
CREATE TABLE IF NOT EXISTS oauth_device_codes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 of the device_code handed to the client; never the raw value.
    device_code_hash TEXT        NOT NULL,
    -- Normalized (upper-case, no separators) form of what the user types.
    user_code        VARCHAR(32) NOT NULL,
    client_id        VARCHAR(255) NOT NULL,
    scope            TEXT        NOT NULL DEFAULT '',
    -- pending | approved | denied
    state            VARCHAR(16) NOT NULL DEFAULT 'pending',
    -- Set when a user approves; the subject the eventual token is issued for.
    user_id          UUID,
    org_id           UUID        NOT NULL,
    -- Minimum seconds between polls; raised when a client polls too fast.
    interval_secs    INTEGER     NOT NULL DEFAULT 5,
    last_polled_at   TIMESTAMPTZ,
    -- Set when the device_code is redeemed, so it cannot be redeemed twice.
    consumed_at      TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_codes_hash
    ON oauth_device_codes(device_code_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_codes_user_code
    ON oauth_device_codes(org_id, user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expiry
    ON oauth_device_codes(expires_at);
`

var deviceCodesDown = `-- Migration 125 rollback.
DROP INDEX IF EXISTS idx_device_codes_expiry;
DROP INDEX IF EXISTS idx_device_codes_user_code;
DROP INDEX IF EXISTS idx_device_codes_hash;
DROP TABLE IF EXISTS oauth_device_codes;
`
