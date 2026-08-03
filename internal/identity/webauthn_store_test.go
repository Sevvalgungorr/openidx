package identity

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestStoreWebAuthnCredentialSetsOrgID guards the WebAuthn "finish registration"
// 500: mfa_webauthn.org_id is NOT NULL, but storeWebAuthnCredential's INSERT
// omitted org_id, so the final step of every passkey registration failed with
// "failed to store credential" after the browser had already created the
// credential. The store must read the org from context and persist it.
func TestStoreWebAuthnCredentialSetsOrgID(t *testing.T) {
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
		org  = "00000000-0000-0000-0000-0000000000aa"
		user = "11111111-0000-0000-0000-0000000000aa"
	)
	s := &Service{db: db, logger: zap.NewNop()}

	cred := &WebAuthnCredential{
		ID:                "cccccccc-0000-0000-0000-000000000001",
		UserID:            user,
		CredentialID:      "abc123",
		PublicKey:         "pk",
		SignCount:         0,
		AAGUID:            "",
		Transports:        []string{"internal"},
		Name:              "Test Passkey",
		AttestationFormat: "none",
		CreatedAt:         time.Now(),
	}

	// Without an org in context the store must fail loudly rather than violate
	// the NOT NULL constraint with a confusing DB error.
	if err := s.storeWebAuthnCredential(context.Background(), cred); err == nil {
		t.Fatal("expected error when org context is missing, got nil")
	}

	// With an org in context the insert must succeed and persist org_id.
	ctxOrg := orgctx.With(context.Background(), orgctx.Org{ID: org})
	if err := s.storeWebAuthnCredential(ctxOrg, cred); err != nil {
		t.Fatalf("storeWebAuthnCredential: %v", err)
	}

	var gotOrg string
	if err := db.Pool.QueryRow(ctx,
		`SELECT org_id::text FROM mfa_webauthn WHERE id = $1`, cred.ID).Scan(&gotOrg); err != nil {
		t.Fatalf("readback: %v", err)
	}
	if gotOrg != org {
		t.Fatalf("org_id = %q, want %q", gotOrg, org)
	}
}
