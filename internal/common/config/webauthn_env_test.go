package config

import "testing"

// TestWebAuthnRPEnvBinding is the regression for the WebAuthn RP ID coming from
// WEBAUTHN_RP_ID / WEBAUTHN_RP_ORIGINS. Without the explicit env bindings the
// RPID silently stayed "localhost" and browsers rejected registration on any
// real domain.
func TestWebAuthnRPEnvBinding(t *testing.T) {
	t.Setenv("WEBAUTHN_RP_ID", "openidx.tdv.org")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://openidx.tdv.org")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")

	cfg, err := Load("test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WebAuthn.RPID != "openidx.tdv.org" {
		t.Fatalf("RPID = %q, want openidx.tdv.org (WEBAUTHN_RP_ID not bound)", cfg.WebAuthn.RPID)
	}
	found := false
	for _, o := range cfg.WebAuthn.RPOrigins {
		if o == "https://openidx.tdv.org" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RPOrigins = %v, want to contain https://openidx.tdv.org", cfg.WebAuthn.RPOrigins)
	}
}
