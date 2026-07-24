package governance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Every warehouse read/action endpoint must fail closed (403) without an org
// context — a "who has access to what" query must never run org-wide.
func TestEntitlementWarehouse_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	handlers := map[string]func(*gin.Context){
		"rebuild":    s.handleRebuildEntitlements,
		"list":       s.handleListEntitlements,
		"orphans":    s.handleListOrphanedEntitlements,
		"statistics": s.handleEntitlementStatistics,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/entitlements/"+name, nil)
			h(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s without org context: got %d, want 403", name, w.Code)
			}
		})
	}
}

// The source-insert set must cover all four entitlement sources, and every
// statement must both write org_id and filter the source on org_id — the
// warehouse must never mix tenants.
func TestEntitlementSourceInserts_shape(t *testing.T) {
	t.Parallel()
	if len(entitlementSourceInserts) != 4 {
		t.Fatalf("expected 4 entitlement sources, got %d", len(entitlementSourceInserts))
	}
	wantSources := []string{"user_roles", "group_memberships", "pam_entry_grants", "vault_access_grants"}
	for i, stmt := range entitlementSourceInserts {
		if !strings.Contains(stmt, "INSERT INTO entitlement_warehouse") {
			t.Fatalf("source %d does not insert into the warehouse", i)
		}
		if !strings.Contains(stmt, "org_id = $1") {
			t.Fatalf("source %d (%s) does not filter on org_id", i, wantSources[i])
		}
		if !strings.Contains(stmt, wantSources[i]) {
			t.Fatalf("source %d expected to read from %s", i, wantSources[i])
		}
	}
}

// The route table must register without a gin panic: the static
// /entitlements/orphans and /entitlements/statistics coexist with the base
// /entitlements list route.
func TestEntitlementWarehouse_routesRegisterCleanly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked: %v", r)
		}
	}()
	r := gin.New()
	g := r.Group("/api/v1/governance")
	s := &Service{}
	g.POST("/entitlements/rebuild", s.handleRebuildEntitlements)
	g.GET("/entitlements", s.handleListEntitlements)
	g.GET("/entitlements/orphans", s.handleListOrphanedEntitlements)
	g.GET("/entitlements/statistics", s.handleEntitlementStatistics)
}
