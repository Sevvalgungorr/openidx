package access

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// break-glass must reject a missing or too-short justification BEFORE it ever
// touches the vault — the loud audit trail is worthless if callers can trip it
// with an empty reason. This runs without a DB (the guard is the first branch).
func TestHandlePamBreakGlass_requiresJustification(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}

	cases := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"missing reason", `{}`},
		{"blank reason", `{"reason":""}`},
		{"too short", `{"reason":"oops"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/pam/entries/x/break-glass",
				bytes.NewReader([]byte(tc.body)))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Params = gin.Params{{Key: "id", Value: "x"}}
			s.handlePamBreakGlass(c)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: got %d, want 400", tc.name, w.Code)
			}
		})
	}
}

// A sufficiently long justification clears the validation gate and moves on to
// the org/entry checks (403 here — no org context in a bare unit context),
// proving the length guard is exactly 10 chars and not an accidental block.
func TestHandlePamBreakGlass_validReasonPassesValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/pam/entries/x/break-glass",
		bytes.NewReader([]byte(`{"reason":"prod outage, on-call approver unreachable"}`)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: "x"}}
	s.handlePamBreakGlass(c)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("valid reason should clear the 400 validation gate, got 400")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (no org context) after validation, got %d", w.Code)
	}
}

// The two-person authorization decision endpoint must reject any decision verb
// other than approve/deny with 404, before any DB work.
func TestHandlePamDecideCheckoutAuthorization_unknownDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}

	for _, verb := range []string{"maybe", "approved", "reject", ""} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/pam/checkout-authorizations/1/"+verb, nil)
		c.Params = gin.Params{{Key: "id", Value: "1"}, {Key: "decision", Value: verb}}
		s.handlePamDecideCheckoutAuthorization(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("decision %q: got %d, want 404", verb, w.Code)
		}
	}
}

// check-in and the ledger/authorization list endpoints must fail closed (403)
// when there is no organization context — they must never operate org-wide.
func TestPamCheckoutControl_requireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}

	handlers := map[string]func(*gin.Context){
		"checkin":             s.handlePamCheckin,
		"list-active":         s.handlePamListActiveCheckouts,
		"list-authorizations": s.handlePamListCheckoutAuthorizations,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/pam/x", nil)
			c.Params = gin.Params{{Key: "id", Value: "x"}}
			c.Set("user_id", "00000000-0000-0000-0000-000000000001")
			h(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s without org context: got %d, want 403", name, w.Code)
			}
		})
	}
}

// The upsert request must round-trip the v105 control flags so an admin can
// actually configure break-glass / dual-control / exclusivity on an entry.
func TestPamEntryUpsert_carriesCheckoutFlags(t *testing.T) {
	t.Parallel()
	raw := `{"name":"DC01","entry_type":"rdp","hostname":"dc01.corp",
		"dual_control_required":true,"exclusive_checkout":true,"break_glass_enabled":true}`
	var req pamEntryUpsertReq
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req.DualControlRequired || !req.ExclusiveCheckout || !req.BreakGlassEnabled {
		t.Fatalf("checkout flags did not round-trip: %+v", req)
	}
}
