package governance

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The core matcher: a violation exists only when EVERY name in the conflict set
// is held. Holding a superset is a violation; holding a strict subset is not.
func TestSodAllPresent(t *testing.T) {
	t.Parallel()
	held := map[string]bool{"approver": true, "requester": true, "auditor": true}
	cases := []struct {
		name     string
		conflict []string
		want     bool
	}{
		{"both held", []string{"approver", "requester"}, true},
		{"three held", []string{"approver", "requester", "auditor"}, true},
		{"one missing", []string{"approver", "payments"}, false},
		{"none held", []string{"payments", "treasury"}, false},
		{"single held (degenerate)", []string{"approver"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sodAllPresent(tc.conflict, held); got != tc.want {
				t.Fatalf("sodAllPresent(%v) = %v, want %v", tc.conflict, got, tc.want)
			}
		})
	}
}

// The status-update endpoint must reject any status outside the closed set,
// before any DB work.
func TestHandleUpdateSoDViolationStatus_validation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	for _, body := range []string{``, `{}`, `{"status":"deleted"}`, `{"status":"OPEN"}`, `{"status":"foo"}`} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/sod/violations/1/status",
			bytes.NewReader([]byte(body)))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		s.handleUpdateSoDViolationStatus(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: got %d, want 400", body, w.Code)
		}
	}
}

// A valid status clears the 400 gate and then fails closed on the missing org
// context (403), proving the closed-set check accepts the canonical statuses.
func TestHandleUpdateSoDViolationStatus_validStatusPassesToOrgCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	for _, st := range []string{"open", "acknowledged", "resolved", "waived"} {
		if !sodViolationStatuses[st] {
			t.Fatalf("canonical status %q missing from closed set", st)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/sod/violations/1/status",
			bytes.NewReader([]byte(`{"status":"`+st+`"}`)))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		s.handleUpdateSoDViolationStatus(c)
		if w.Code == http.StatusBadRequest {
			t.Fatalf("status %q wrongly rejected by the closed-set gate", st)
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %q: expected 403 (no org) after validation, got %d", st, w.Code)
		}
	}
}

// Every detective-SoD read/action endpoint must fail closed (403) without an
// organization context — these queries must never run org-wide.
func TestSoDDetective_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}
	handlers := map[string]func(*gin.Context){
		"sweep":      s.handleRunSoDSweep,
		"list":       s.handleListSoDViolations,
		"statistics": s.handleSoDStatistics,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/sod/"+name, nil)
			h(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s without org context: got %d, want 403", name, w.Code)
			}
		})
	}
}
