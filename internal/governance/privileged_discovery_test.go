package governance

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The discovered-account aggregator must dedupe multiple privilege sources onto
// one account and remember standing/service flags across sources.
func TestDiscoveredAccount_addSource(t *testing.T) {
	t.Parallel()
	d := &discoveredAccount{userID: "u1"}
	d.addSource("role:admin")
	d.addSource("role:admin") // dedup
	d.addSource("group:Domain Admins")
	if len(d.sources) != 2 {
		t.Fatalf("expected 2 distinct sources, got %d (%v)", len(d.sources), d.sources)
	}
	if !d.sources["role:admin"] || !d.sources["group:Domain Admins"] {
		t.Fatalf("sources missing expected keys: %v", d.sources)
	}
}

// The status-update endpoint must reject any status outside the closed set,
// before any DB work.
func TestHandleUpdatePrivilegedAccountStatus_validation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	for _, body := range []string{``, `{}`, `{"status":"deleted"}`, `{"status":"NEW"}`, `{"status":"foo"}`} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/privileged-accounts/1/status",
			bytes.NewReader([]byte(body)))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		s.handleUpdatePrivilegedAccountStatus(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: got %d, want 400", body, w.Code)
		}
	}
}

// Every canonical status is accepted by the closed-set gate and then fails
// closed on the missing org context (403).
func TestHandleUpdatePrivilegedAccountStatus_validStatuses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	for _, st := range []string{"new", "acknowledged", "onboarded", "ignored", "resolved"} {
		if !privAccountStatuses[st] {
			t.Fatalf("canonical status %q missing from closed set", st)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/privileged-accounts/1/status",
			bytes.NewReader([]byte(`{"status":"`+st+`"}`)))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		s.handleUpdatePrivilegedAccountStatus(c)
		if w.Code == http.StatusBadRequest {
			t.Fatalf("status %q wrongly rejected by the closed-set gate", st)
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %q: expected 403 (no org) after validation, got %d", st, w.Code)
		}
	}
}

// Every discovery read/action endpoint must fail closed (403) without an org
// context — these identity-wide scans must never run unscoped.
func TestPrivilegedDiscovery_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	handlers := map[string]func(*gin.Context){
		"scan":       s.handleRunPrivilegedDiscovery,
		"list":       s.handleListPrivilegedAccounts,
		"statistics": s.handlePrivilegedStatistics,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/privileged-accounts/"+name, nil)
			h(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s without org context: got %d, want 403", name, w.Code)
			}
		})
	}
}

// The route table must not panic on registration — in particular the static
// /privileged-accounts/statistics must coexist with the /:id/status param route.
func TestPrivilegedDiscovery_routesRegisterCleanly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked: %v", r)
		}
	}()
	r := gin.New()
	g := r.Group("/api/v1/governance")
	s := &Service{}
	g.POST("/privileged-accounts/scan", s.handleRunPrivilegedDiscovery)
	g.GET("/privileged-accounts", s.handleListPrivilegedAccounts)
	g.GET("/privileged-accounts/statistics", s.handlePrivilegedStatistics)
	g.POST("/privileged-accounts/:id/status", s.handleUpdatePrivilegedAccountStatus)
}
