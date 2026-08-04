package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestCreateDelegationValidation covers the input guards in
// handleCreateDelegation that run BEFORE any database access. delegate_id and
// scope_id are uuid columns, so non-UUID input must fail closed with a 400
// instead of reaching Postgres and surfacing as a confusing 500. These cases
// use a Service with a nil db on purpose: a valid payload would panic on the
// DB call, which proves the guards return early for every case below.
func TestCreateDelegationValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{logger: zap.NewNop()}

	validUUID := "00000000-0000-0000-0000-000000000001"

	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing fields", `{}`, http.StatusBadRequest},
		{"empty scope_id", `{"delegate_id":"` + validUUID + `","scope_type":"group","scope_id":""}`, http.StatusBadRequest},
		{"non-uuid scope_id", `{"delegate_id":"` + validUUID + `","scope_type":"group","scope_id":"engineering-team"}`, http.StatusBadRequest},
		{"non-uuid delegate_id", `{"delegate_id":"someuser","scope_type":"group","scope_id":"` + validUUID + `"}`, http.StatusBadRequest},
		{"invalid scope_type", `{"delegate_id":"` + validUUID + `","scope_type":"planet","scope_id":"` + validUUID + `"}`, http.StatusBadRequest},
		{"malformed json", `{`, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.POST("/delegations", func(c *gin.Context) {
				c.Set("user_id", validUUID)
				svc.handleCreateDelegation(c)
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/delegations", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("handleCreateDelegation[%s] = %d, want %d (body=%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}
