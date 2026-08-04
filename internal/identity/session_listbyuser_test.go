package identity

import (
	"context"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestListByUserExcludesRevoked guards BULGU-01: /me/sessions (ListByUser) must
// only return live sessions. It previously filtered expiry but NOT the revoked
// flag, so a user's logged-out/revoked sessions were still listed as active,
// inflating the count and showing sessions the user had already terminated.
func TestListByUserExcludesRevoked(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE sessions (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			client_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			started_at TIMESTAMPTZ DEFAULT now(),
			last_seen_at TIMESTAMPTZ DEFAULT now(),
			expires_at TIMESTAMPTZ NOT NULL,
			org_id UUID NOT NULL,
			revoked BOOLEAN);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		org  = "00000000-0000-0000-0000-0000000000aa"
		user = "11111111-0000-0000-0000-0000000000aa"
	)
	ins := func(id string, revoked bool, expOffset time.Duration) {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO sessions (id,user_id,client_id,ip_address,user_agent,expires_at,org_id,revoked)
			 VALUES ($1,$2,'c1','1.2.3.4','ua', now()+$3, $4, $5)`,
			id, user, expOffset, org, revoked); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	ins("aaaaaaaa-0000-0000-0000-000000000001", false, time.Hour)  // active
	ins("aaaaaaaa-0000-0000-0000-000000000002", true, time.Hour)   // revoked -> excluded
	ins("aaaaaaaa-0000-0000-0000-000000000003", false, -time.Hour) // expired -> excluded

	repo := NewPostgresSessionRepository(db)
	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	sessions, err := repo.ListByUser(octx, user)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("want 1 live session, got %d: %+v", len(sessions), sessions)
	}
	if sessions[0].ID != "aaaaaaaa-0000-0000-0000-000000000001" {
		t.Fatalf("returned the wrong session: %s", sessions[0].ID)
	}
	if sessions[0].Revoked {
		t.Fatalf("live session should not be marked revoked")
	}
}
