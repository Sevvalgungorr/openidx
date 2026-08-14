package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// realisticCOSEKey builds an ES256 COSE key of the shape the WebAuthn library
// hands back: a CBOR map with two 32-byte coordinates. The point is that it is
// raw binary, not text.
func realisticCOSEKey(t *testing.T) []byte {
	t.Helper()
	xy := make([]byte, 64)
	if _, err := rand.Read(xy); err != nil {
		t.Fatalf("rand: %v", err)
	}
	key := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	key = append(key, xy[:32]...)
	key = append(key, 0x22, 0x58, 0x20)
	key = append(key, xy[32:]...)
	// Force the two bytes that make this a `text` column problem, so the test
	// is deterministic instead of depending on random data: a NUL byte and an
	// invalid UTF-8 sequence.
	key[11] = 0x00
	key[12] = 0xff
	return key
}

// TestCOSEKeyRoundTripsThroughTextColumn is the regression test for the
// WebAuthn register/finish 500 that survived the org_id fix.
//
// credential.PublicKey is raw CBOR. It was written as string(...) into a
// `text` column, but PostgreSQL's server encoding is UTF8 and `text` accepts
// neither 0x00 nor invalid UTF-8, so the final INSERT failed on EVERY
// registration: the browser reported "Passkey saved" and the API answered 500
// with nothing stored.
//
// The test writes a realistic key and requires it to come back byte-identical,
// because a key that stores but does not round-trip would break every
// subsequent login instead.
func TestCOSEKeyRoundTripsThroughTextColumn(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE mfa_webauthn (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			credential_id TEXT NOT NULL,
			public_key TEXT NOT NULL,
			sign_count BIGINT,
			aaguid VARCHAR(255),
			transports TEXT[],
			name VARCHAR(255),
			backup_eligible BOOLEAN,
			backup_state BOOLEAN,
			attestation_format VARCHAR(255),
			created_at TIMESTAMPTZ DEFAULT now(),
			last_used_at TIMESTAMPTZ,
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		org  = "00000000-0000-0000-0000-0000000000bb"
		user = "11111111-0000-0000-0000-0000000000bb"
	)
	s := &Service{db: db, logger: zap.NewNop()}
	ctxOrg := orgctx.With(ctx, orgctx.Org{ID: org})

	raw := realisticCOSEKey(t)
	if err := s.storeWebAuthnCredential(ctxOrg, &WebAuthnCredential{
		ID:                "dddddddd-0000-0000-0000-000000000001",
		UserID:            user,
		CredentialID:      "cose-round-trip",
		PublicKey:         encodeCOSEKey(raw),
		Transports:        []string{"internal"},
		Name:              "Security Key",
		AttestationFormat: "none",
		CreatedAt:         time.Now(),
	}); err != nil {
		t.Fatalf("storing a real COSE key must not fail: %v", err)
	}

	creds, err := s.getWebAuthnCredentials(ctxOrg, user)
	if err != nil {
		t.Fatalf("getWebAuthnCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d credentials, want 1", len(creds))
	}
	if got := decodeCOSEKey(creds[0].PublicKey); !bytes.Equal(got, raw) {
		t.Fatalf("public key did not round-trip: got %d bytes, want %d", len(got), len(raw))
	}
}

// TestDecodeCOSEKeyTolerateRawRow makes sure the reader never corrupts a value
// it cannot decode. Failing closed here would break logins for any row written
// by another path, which is worse than the bug being fixed.
func TestDecodeCOSEKeyTolerateRawRow(t *testing.T) {
	raw := []byte("not-base64-@@@")
	if got := decodeCOSEKey(string(raw)); !bytes.Equal(got, raw) {
		t.Fatalf("raw row must be returned unchanged, got %q", got)
	}
	key := realisticCOSEKey(t)
	if got := decodeCOSEKey(encodeCOSEKey(key)); !bytes.Equal(got, key) {
		t.Fatal("encode/decode must round-trip")
	}
}
