package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func init() { gin.SetMode(gin.TestMode) }

// buildSelfHealRouter wires the routes with an injectable role and a captured
// audit call, over a temp state dir.
func buildSelfHealRouter(t *testing.T, roles []string, manageOK bool) (*gin.Engine, *SelfHealHandler, *int) {
	t.Helper()
	audits := 0
	h := NewSelfHealHandler(zap.NewNop(), t.TempDir(), "scripts/selfheal", func(*gin.Context, string, interface{}, interface{}) { audits++ })
	inject := func(c *gin.Context) { c.Set("roles", roles); c.Next() }
	// Minimal stand-ins for the real middlewares.
	adminMW := func(c *gin.Context) {
		r, _ := c.Get("roles")
		for _, x := range r.([]string) {
			if x == "admin" || x == "super_admin" {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin required"})
	}
	manageMW := func(c *gin.Context) {
		if !manageOK {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "selfheal:manage required"})
			return
		}
		c.Next()
	}
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(inject)
	SelfHealRoutes(v1, h, adminMW, manageMW)
	return r, h, &audits
}

func doJSON(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestSelfHealRoutesRegistered(t *testing.T) {
	r, _, _ := buildSelfHealRouter(t, []string{"admin"}, true)
	paths := map[string]bool{}
	for _, rt := range r.Routes() {
		paths[rt.Method+" "+rt.Path] = true
	}
	for _, want := range []string{
		"GET /api/v1/selfheal/status", "GET /api/v1/selfheal/findings", "GET /api/v1/selfheal/history",
		"PUT /api/v1/selfheal/mode", "POST /api/v1/selfheal/kill-switch", "POST /api/v1/selfheal/sweep",
	} {
		if !paths[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}

func TestSelfHealNonAdminForbidden(t *testing.T) {
	r, _, _ := buildSelfHealRouter(t, []string{"user"}, true)
	if w := doJSON(r, "GET", "/api/v1/selfheal/status", ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", w.Code)
	}
	if w := doJSON(r, "PUT", "/api/v1/selfheal/mode", `{"mode":"tier0"}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin mode = %d, want 403", w.Code)
	}
}

func TestSelfHealAdminWithoutManageCannotMutate(t *testing.T) {
	r, _, _ := buildSelfHealRouter(t, []string{"admin"}, false) // manage denied
	if w := doJSON(r, "GET", "/api/v1/selfheal/status", ""); w.Code != http.StatusOK {
		t.Fatalf("admin read = %d, want 200", w.Code)
	}
	if w := doJSON(r, "PUT", "/api/v1/selfheal/mode", `{"mode":"tier0"}`); w.Code != http.StatusForbidden {
		t.Fatalf("admin w/o manage mutate = %d, want 403", w.Code)
	}
}

func TestSelfHealPutModeValidation(t *testing.T) {
	r, h, audits := buildSelfHealRouter(t, []string{"admin"}, true)

	if w := doJSON(r, "PUT", "/api/v1/selfheal/mode", `{"mode":"bogus"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mode = %d, want 400", w.Code)
	}
	// tier1 without confirm -> 400.
	if w := doJSON(r, "PUT", "/api/v1/selfheal/mode", `{"mode":"tier1"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("tier1 no-confirm = %d, want 400", w.Code)
	}
	// tier1 with confirm -> 200 + persisted + audited.
	if w := doJSON(r, "PUT", "/api/v1/selfheal/mode", `{"mode":"tier1","confirm":"tier1"}`); w.Code != http.StatusOK {
		t.Fatalf("tier1 confirmed = %d, want 200", w.Code)
	}
	if m, _ := h.store.Mode(); m != "tier1" {
		t.Fatalf("mode not persisted: %q", m)
	}
	if *audits == 0 {
		t.Fatal("mutation was not audited")
	}
}

func TestSelfHealKillSwitchTogglesAndAudits(t *testing.T) {
	r, h, audits := buildSelfHealRouter(t, []string{"admin"}, true)
	w := doJSON(r, "POST", "/api/v1/selfheal/kill-switch", `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("kill-switch on = %d, want 200", w.Code)
	}
	if on, _ := h.store.KillSwitch(); !on {
		t.Fatal("DISABLE not written")
	}
	if *audits == 0 {
		t.Fatal("kill-switch not audited")
	}
	// And the response body reflects it.
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["kill_switch"] != true {
		t.Fatalf("response body: %v", body)
	}
}
