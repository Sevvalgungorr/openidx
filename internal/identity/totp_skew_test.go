package identity

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestValidateTOTPWithSkew proves the enrollment/verification validator accepts
// a code from the adjacent 30s window (the common clock-drift case) and trims
// whitespace, while still rejecting an unrelated code.
func TestValidateTOTPWithSkew(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "test@openidx.local"})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := key.Secret()
	now := time.Now().UTC()

	gen := func(at time.Time) string {
		code, err := totp.GenerateCode(secret, at)
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		return code
	}

	tests := []struct {
		name string
		code string
		want bool
	}{
		{"current window", gen(now), true},
		{"previous window (-30s)", gen(now.Add(-30 * time.Second)), true},
		{"next window (+30s)", gen(now.Add(30 * time.Second)), true},
		{"whitespace trimmed", "  " + gen(now) + "  ", true},
		{"two windows away is rejected", gen(now.Add(-90 * time.Second)), false},
		{"garbage code rejected", "000000", false},
		{"empty code rejected", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateTOTPWithSkew(tt.code, secret); got != tt.want {
				t.Errorf("validateTOTPWithSkew(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// TestValidateTOTPWithSkew_WrongSecret ensures a code minted from a different
// secret never validates (no cross-secret acceptance from the skew window).
func TestValidateTOTPWithSkew_WrongSecret(t *testing.T) {
	k1, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "a"})
	k2, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "b"})
	code, err := totp.GenerateCodeCustom(k2.Secret(), time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if validateTOTPWithSkew(code, k1.Secret()) {
		t.Error("code from a different secret must not validate")
	}
}
