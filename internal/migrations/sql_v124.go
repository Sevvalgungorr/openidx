package migrations

// Migration v124 — tag the stored Ziti admin password as secretcrypt "encv1:".
//
// The Ziti controller admin password in system_settings['ziti_connection'] was
// the one secret column encrypted by a private AES-256-GCM helper in
// internal/access instead of internal/common/secretcrypt, so it sat outside KEK
// rotation and outside the rekey tool.
//
// It could not simply be pointed at secretcrypt, because the two formats differ
// only by secretcrypt's version tag, and secretcrypt deliberately passes an
// *untagged* value through Decrypt unchanged so plaintext survives a rollout.
// Handing it a legacy Ziti ciphertext would therefore have returned the base64
// blob as if it were the password — no error, just a wrong secret sent to a
// controller login.
//
// The formats being otherwise byte-identical (base64(nonce||ciphertext),
// AES-256-GCM, no AAD, same ENCRYPTION_KEY) is what makes this a re-tag rather
// than a re-encryption: prefixing the stored string is sufficient, so this
// migration needs no key material and cannot corrupt a value it cannot read.
//
// Idempotent: rows already carrying encv1/encv2 are skipped, so re-running is a
// no-op. Reads tolerate both shapes either way (see zitiSecretCipher), so this
// migration converges the data rather than gating correctness on having run.
var zitiAdminPwTagUp = `-- Migration 124: tag the legacy Ziti admin password ciphertext as encv1.
UPDATE system_settings
SET value = jsonb_set(
        value,
        '{admin_password_enc}',
        to_jsonb('encv1:' || (value->>'admin_password_enc'))
    ),
    updated_at = NOW()
WHERE key = 'ziti_connection'
  AND COALESCE(value->>'admin_password_enc', '') <> ''
  AND value->>'admin_password_enc' NOT LIKE 'encv1:%'
  AND value->>'admin_password_enc' NOT LIKE 'encv2:%';
`

// Down strips an encv1 tag, restoring the pre-migration byte layout.
//
// It deliberately does not touch encv2 values: those were sealed under a KEK
// from the keyring after this migration, so there is no key-free way back to
// the legacy single-key format — and the pre-v124 code could not have read them
// regardless. Rolling back an install that has since rotated to a keyring
// requires the rekey tool, not this statement.
var zitiAdminPwTagDown = `-- Migration 124 rollback: strip the encv1 tag (encv1 only; see note).
UPDATE system_settings
SET value = jsonb_set(
        value,
        '{admin_password_enc}',
        to_jsonb(substring(value->>'admin_password_enc' from 7))
    ),
    updated_at = NOW()
WHERE key = 'ziti_connection'
  AND value->>'admin_password_enc' LIKE 'encv1:%';
`
