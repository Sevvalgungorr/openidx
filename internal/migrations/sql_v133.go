package migrations

// Migration v133 — record the authentication methods used to establish a login
// session, so the OAuth tokens minted from it can emit an `amr` claim.
//
// The middleware already reads `amr` and device auto-trust (migration v132 /
// DEVICE_AUTOTRUST) keys on it, but tokens never carried it. Recording the
// methods on the session at login (pwd, and mfa when a second factor was
// verified) lets GenerateJWT/GenerateIDToken populate `amr` from the session
// the token's `sid` points at — a server-verified signal, never client-supplied.
var sessionsAuthMethodsUp = `-- Migration 133: sessions.auth_methods for the amr claim.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
`

var sessionsAuthMethodsDown = `-- Rollback migration 133.
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_methods;
`
