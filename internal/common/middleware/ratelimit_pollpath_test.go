package middleware

import "testing"

// TestIsPollPath guards the rate-limit exemption for out-of-band status polling.
// These endpoints are token-scoped and polled frequently by design; counting
// them on the shared per-IP tier tripped "Rate limit exceeded" during normal
// push-MFA / QR logins.
func TestIsPollPath(t *testing.T) {
	exempt := []string{
		"/oauth/mfa-push-status/abc-123",
		"/oauth/qr-login/poll",
		"/oauth/qr-login/poll?session_token=x",
		"/api/v1/identity/mfa/push/challenge/abc-123",
		"/api/v1/identity/passwordless/qr-login/poll",
	}
	for _, p := range exempt {
		if !isPollPath(p) {
			t.Errorf("isPollPath(%q) = false, want true (should be exempt)", p)
		}
	}

	// Credential-submitting / other endpoints must NOT be exempt.
	notExempt := []string{
		"/oauth/login",
		"/oauth/mfa-verify",
		"/oauth/token",
		"/api/v1/identity/mfa/push/register",
		"/api/v1/identity/mfa/push/verify",
		"/api/v1/users",
	}
	for _, p := range notExempt {
		if isPollPath(p) {
			t.Errorf("isPollPath(%q) = true, want false (must stay rate-limited)", p)
		}
	}
}
