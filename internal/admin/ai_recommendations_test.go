package admin

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestGenerateRecommendationsPersistsAndLists is the regression guard for QA 9.2:
// the generate endpoint reported {"generated": N} while the list stayed empty
// because every generator query referenced columns the deployed schema does not
// have (mfa_totp.verified, users.last_login, policy_rules.target_applications),
// the INSERT failed type deduction, and all of those errors were swallowed. This
// test seeds a stale account, runs the handler, and asserts a row is actually
// persisted and returned by the list handler — i.e. generated count matches what
// is stored.
func TestGenerateRecommendationsPersistsAndLists(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	seedCtx := orgctx.WithBypassRLS(context.Background())

	const (
		orgID = "00000000-0000-0000-0000-0000000000e9"
		uID   = "22222222-0000-0000-0000-0000000000e1"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	// Isolated org with a single enabled, long-stale user → the stale-account
	// generator must fire and persist exactly one recommendation.
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org E (rec test)', 'org-e-rec-test')`, orgID)
	exec(`INSERT INTO users (id, username, email, enabled, org_id, last_login_at)
		VALUES ($1, 'rec-stale', 'rec-stale@test.local', true, $2, NOW() - INTERVAL '200 days')`, uID, orgID)
	// Clean slate for the recommendations table for this org's types.
	exec(`DELETE FROM ai_recommendations WHERE recommendation_type IN ('stale_account_cleanup','permission_right_sizing','mfa_enrollment','policy_tightening','agent_permission_scoping','compliance_gap')`)

	s := &Service{db: db, logger: zap.NewNop()}

	// --- generate ---
	genW := httptest.NewRecorder()
	genC, _ := gin.CreateTestContext(genW)
	genC.Request = httptest.NewRequest("POST", "/api/v1/recommendations/generate", nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
	genC.Set("roles", []string{"admin"})
	s.handleGenerateRecommendations(genC)

	if genW.Code != 200 {
		t.Fatalf("generate: status = %d, body = %s", genW.Code, genW.Body.String())
	}
	var genResp struct {
		Generated int `json:"generated"`
	}
	if err := json.Unmarshal(genW.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("generate: bad json: %v", err)
	}
	if genResp.Generated < 1 {
		t.Fatalf("generate: expected >=1 generated (stale user seeded), got %d", genResp.Generated)
	}

	// --- the generated count must equal what is actually persisted ---
	var stored int
	if err := db.Pool.QueryRow(orgctx.With(context.Background(), orgctx.Org{ID: orgID}),
		`SELECT COUNT(*) FROM ai_recommendations WHERE status = 'pending'`).Scan(&stored); err != nil {
		t.Fatalf("count stored: %v", err)
	}
	if stored != genResp.Generated {
		t.Fatalf("generate/persist mismatch: reported generated=%d but %d rows persisted (the 9.2 bug)", genResp.Generated, stored)
	}

	// --- list must surface them ---
	listW := httptest.NewRecorder()
	listC, _ := gin.CreateTestContext(listW)
	listC.Request = httptest.NewRequest("GET", "/api/v1/recommendations", nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
	listC.Set("roles", []string{"admin"})
	s.handleListRecommendations(listC)

	if listW.Code != 200 {
		t.Fatalf("list: status = %d, body = %s", listW.Code, listW.Body.String())
	}
	var listResp struct {
		Data  []Recommendation `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(listW.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("list: bad json: %v", err)
	}
	if listResp.Total < genResp.Generated {
		t.Fatalf("list total=%d < generated=%d (generate/list inconsistency)", listResp.Total, genResp.Generated)
	}

	foundStale := false
	for _, r := range listResp.Data {
		if r.RecommendationType == "stale_account_cleanup" {
			foundStale = true
		}
	}
	if !foundStale {
		t.Fatalf("expected a stale_account_cleanup recommendation in the list, got %d entries", len(listResp.Data))
	}

	// --- re-generate is idempotent (no duplicate pending rows) ---
	regenW := httptest.NewRecorder()
	regenC, _ := gin.CreateTestContext(regenW)
	regenC.Request = httptest.NewRequest("POST", "/api/v1/recommendations/generate", nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
	regenC.Set("roles", []string{"admin"})
	s.handleGenerateRecommendations(regenC)
	var regenResp struct {
		Generated int `json:"generated"`
	}
	json.Unmarshal(regenW.Body.Bytes(), &regenResp)
	if regenResp.Generated != 0 {
		t.Fatalf("re-generate should be idempotent, got %d new", regenResp.Generated)
	}
}
