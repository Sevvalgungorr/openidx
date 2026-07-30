package migrations

// Migration v115 — vault_secrets.require_step_up.
//
// PAM Wave A (A4): enforce step-up MFA at credential reveal for high-value
// secrets. The step-up challenge/verify flow (internal/oauth/stepup.go) already
// mints a completed stepup_challenges row on success, but nothing on the vault
// reveal path required it — a valid grant alone revealed the secret. This adds a
// per-secret require_step_up flag; internal/vault Reveal refuses (403,
// X-Step-Up-Required) unless the caller completed a step-up challenge within the
// recent window. Additive, defaults false so existing secrets are unchanged.
var vaultRequireStepUpUp = `-- Migration 115: vault_secrets.require_step_up.

ALTER TABLE vault_secrets ADD COLUMN IF NOT EXISTS require_step_up BOOLEAN NOT NULL DEFAULT FALSE;
`

var vaultRequireStepUpDown = `-- Rollback 115: drop the require_step_up column.
ALTER TABLE vault_secrets DROP COLUMN IF EXISTS require_step_up;
`
