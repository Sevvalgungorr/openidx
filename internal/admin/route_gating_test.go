package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestAdminRouteGating verifies the RegisterRoutes admin gate: every admin
// route rejects a non-admin caller with 403 even when OPA authz is off, while
// the shared application-catalog LIST stays reachable for any authenticated
// user (the end-user Access Requests page depends on it).
func TestAdminRouteGating(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouterWithRoles := func(roles []string) *gin.Engine {
		r := gin.New()
		r.Use(gin.Recovery())
		// Stand in for the auth middleware: populate the caller's roles the same
		// way RequireAdmin reads them.
		r.Use(func(c *gin.Context) {
			c.Set("roles", roles)
			c.Next()
		})
		RegisterRoutes(r.Group("/api/v1"), &Service{})
		return r
	}

	do := func(r *gin.Engine, method, path string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		r.ServeHTTP(w, req)
		return w.Code
	}
	body := func(r *gin.Engine, method, path string) string {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		r.ServeHTTP(w, req)
		return w.Body.String()
	}

	t.Run("non-admin is blocked from admin routes", func(t *testing.T) {
		r := newRouterWithRoles([]string{"user"})
		// A representative sample across the legacy CRUD surface.
		for _, path := range []string{
			"/api/v1/directories",
			"/api/v1/service-accounts",
			"/api/v1/webhooks",
			"/api/v1/analytics/logins",
			"/api/v1/security-alerts",
			"/api/v1/ip-threats",
		} {
			assert.Equal(t, http.StatusForbidden, do(r, http.MethodGet, path),
				"non-admin should be 403 on %s", path)
		}
		// Writes too.
		assert.Equal(t, http.StatusForbidden, do(r, http.MethodPost, "/api/v1/applications"))
	})

	t.Run("application catalog LIST stays open to authenticated users", func(t *testing.T) {
		r := newRouterWithRoles([]string{"user"})
		// The gate must NOT block this route; it reaches the handler (which then
		// fails on the nil DB → 500), so any status other than 403 proves it's
		// ungated.
		assert.NotEqual(t, http.StatusForbidden, do(r, http.MethodGet, "/api/v1/applications"))
	})

	t.Run("admin passes the gate", func(t *testing.T) {
		r := newRouterWithRoles([]string{"admin"})
		// An admin clears RequireAdmin and reaches the handler. The nil-DB handler
		// may itself return 403 for missing org context, so we don't assert on the
		// status code; instead we prove the gate let the caller through by checking
		// the response is NOT the gate's own rejection body.
		assert.NotContains(t, body(r, http.MethodGet, "/api/v1/directories"), "insufficient permissions")
	})
}
