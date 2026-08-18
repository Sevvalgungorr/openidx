package governance

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestSubmitReviewDecision_ActuallyRevokes is the regression test for the
// hollow access-review path: SubmitReviewDecision used to only UPDATE
// review_items.decision, so a reviewer clicking "Revoke" relabeled the row while
// the user kept the role — an access review that certifies nothing. It is
// DB-backed because the whole defect lives in whether the underlying access row
// is actually deleted.
func TestSubmitReviewDecision_ActuallyRevokes(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE review_items (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			review_id UUID,
			user_id UUID,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			resource_name TEXT,
			decision VARCHAR(50) NOT NULL DEFAULT 'pending',
			comments TEXT,
			decided_by UUID,
			decided_at TIMESTAMPTZ,
			org_id UUID NOT NULL);
		CREATE TABLE user_roles (
			user_id UUID NOT NULL,
			role_id UUID NOT NULL,
			org_id UUID NOT NULL);
		CREATE TABLE group_memberships (
			user_id UUID NOT NULL,
			group_id UUID NOT NULL,
			org_id UUID NOT NULL);
		CREATE TABLE audit_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			timestamp TIMESTAMPTZ DEFAULT NOW(),
			event_type VARCHAR(100) NOT NULL,
			category VARCHAR(50) NOT NULL,
			action VARCHAR(255) NOT NULL,
			outcome VARCHAR(50) NOT NULL,
			actor_id VARCHAR(255),
			actor_type VARCHAR(50),
			actor_ip VARCHAR(45),
			target_id VARCHAR(255),
			target_type VARCHAR(100),
			resource_id VARCHAR(255),
			details JSONB,
			session_id VARCHAR(255),
			request_id VARCHAR(255),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	reviewID := "dddddddd-0000-0000-0000-000000000001"
	user := "bbbbbbbb-0000-0000-0000-000000000001"
	roleID := "aaaaaaaa-0000-0000-0000-000000000001"
	groupID := "eeeeeeee-0000-0000-0000-000000000001"
	// decided_by is a UUID column in production (the authenticated user id);
	// pass a real UUID, not a display name.
	decidedBy := "99999999-0000-0000-0000-000000000009"

	countUserRole := func() int {
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_id=$2 AND org_id=$3`,
			user, roleID, orgID).Scan(&n); err != nil {
			t.Fatalf("count user_roles: %v", err)
		}
		return n
	}
	itemDecision := func(itemID string) string {
		var d string
		if err := db.Pool.QueryRow(ctx,
			`SELECT decision FROM review_items WHERE id=$1`, itemID).Scan(&d); err != nil {
			t.Fatalf("read decision: %v", err)
		}
		return d
	}

	seedItem := func(itemID, resourceType, resourceID string) {
		if _, err := db.Pool.Exec(ctx, `TRUNCATE review_items, user_roles, group_memberships`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, org_id)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			itemID, reviewID, user, resourceType, resourceID, orgID); err != nil {
			t.Fatalf("seed item: %v", err)
		}
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`,
			user, roleID, orgID); err != nil {
			t.Fatalf("seed user_role: %v", err)
		}
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`,
			user, groupID, orgID); err != nil {
			t.Fatalf("seed group: %v", err)
		}
	}

	t.Run("revoked role decision deletes the assignment", func(t *testing.T) {
		item := "cccccccc-0000-0000-0000-000000000001"
		seedItem(item, "role", roleID)

		if err := s.SubmitReviewDecision(ctx, reviewID, item, ReviewDecisionRevoked, "no longer needed", decidedBy); err != nil {
			t.Fatalf("SubmitReviewDecision: %v", err)
		}
		if got := countUserRole(); got != 0 {
			t.Errorf("role assignment should be gone after revoke, still have %d (hollow revoke)", got)
		}
		if got := itemDecision(item); got != string(ReviewDecisionRevoked) {
			t.Errorf("decision: want revoked, got %q", got)
		}
		// The revocation must also land a governance audit event in the same tx.
		var auditCount int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events WHERE action='access_review.revoked' AND target_id=$1 AND org_id=$2`,
			user, orgID).Scan(&auditCount); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if auditCount != 1 {
			t.Errorf("revocation must land exactly one audit row, got %d", auditCount)
		}
	})

	t.Run("approved decision leaves access intact", func(t *testing.T) {
		item := "cccccccc-0000-0000-0000-000000000002"
		seedItem(item, "role", roleID)

		if err := s.SubmitReviewDecision(ctx, reviewID, item, ReviewDecisionApproved, "looks good", decidedBy); err != nil {
			t.Fatalf("SubmitReviewDecision: %v", err)
		}
		if got := countUserRole(); got != 1 {
			t.Errorf("approved decision must not remove access, have %d", got)
		}
	})

	t.Run("privileged_role item revokes the underlying user_roles row", func(t *testing.T) {
		item := "cccccccc-0000-0000-0000-000000000003"
		seedItem(item, "privileged_role", roleID)

		if err := s.SubmitReviewDecision(ctx, reviewID, item, ReviewDecisionRevoked, "sod", decidedBy); err != nil {
			t.Fatalf("SubmitReviewDecision: %v", err)
		}
		if got := countUserRole(); got != 0 {
			t.Errorf("privileged_role revoke should delete the user_roles row, have %d", got)
		}
	})

	t.Run("batch revoke removes access for each item", func(t *testing.T) {
		item := "cccccccc-0000-0000-0000-000000000004"
		seedItem(item, "role", roleID)

		if err := s.BatchSubmitDecisions(ctx, reviewID, []string{item}, ReviewDecisionRevoked, "bulk", decidedBy); err != nil {
			t.Fatalf("BatchSubmitDecisions: %v", err)
		}
		if got := countUserRole(); got != 0 {
			t.Errorf("batch revoke should delete access, have %d", got)
		}
		if got := itemDecision(item); got != string(ReviewDecisionRevoked) {
			t.Errorf("decision: want revoked, got %q", got)
		}
	})
}
