package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// newTestZitiManagerIntercept mirrors newTestZitiManager but seeds the
// intercept.v1 config type so resolveConfigTypeID stays offline.
func newTestZitiManagerIntercept(t *testing.T, baseURL string) *ZitiManager {
	t.Helper()
	return &ZitiManager{
		logger:          zap.NewNop(),
		mgmtToken:       "fake",
		mgmtClient:      &http.Client{},
		cfg:             &config.Config{ZitiCtrlURL: baseURL},
		initialized:     true,
		configTypeCache: map[string]string{"intercept.v1": "g7cIWbcGg"},
	}
}

// The intercept.v1 config the PAM broker uses must carry a single non-loopback
// address and a single-port range, in the shape ziti-edge-tunnel expects.
func TestCreateInterceptV1ConfigFixedShape(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"icfg-1"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	zm := newTestZitiManagerIntercept(t, srv.URL)
	id, err := zm.CreateInterceptV1ConfigFixed(context.Background(), "pam-x-intercept", "100.64.2.1", 14007)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "icfg-1" {
		t.Fatalf("want config id icfg-1, got %q", id)
	}
	data, _ := gotBody["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("config body missing data object: %+v", gotBody)
	}
	protocols, _ := data["protocols"].([]interface{})
	if len(protocols) != 1 || protocols[0] != "tcp" {
		t.Fatalf("protocols want [tcp], got %+v", data["protocols"])
	}
	addrs, _ := data["addresses"].([]interface{})
	if len(addrs) != 1 || addrs[0] != "100.64.2.1" {
		t.Fatalf("addresses want [100.64.2.1], got %+v", data["addresses"])
	}
	ranges, _ := data["portRanges"].([]interface{})
	if len(ranges) != 1 {
		t.Fatalf("portRanges want 1 entry, got %+v", data["portRanges"])
	}
	pr, _ := ranges[0].(map[string]interface{})
	if pr["low"].(float64) != 14007 || pr["high"].(float64) != 14007 {
		t.Fatalf("portRange want 14007-14007, got %+v", pr)
	}
	if gotBody["configTypeId"] != "g7cIWbcGg" {
		t.Fatalf("configTypeId want intercept.v1 id, got %v", gotBody["configTypeId"])
	}
}

// An existing config with the same name and matching data must be reused
// (no duplicate POST), matching the host.v1 get-or-create-or-update contract.
func TestCreateInterceptV1ConfigFixedReusesExistingByName(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/edge/management/v1/configs" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[{"id":"icfg-existing","name":"pam-x-intercept","data":{"addresses":["100.64.2.1"],"portRanges":[{"low":14007,"high":14007}]}}]}`))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/edge/management/v1/configs" {
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"icfg-new"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	zm := newTestZitiManagerIntercept(t, srv.URL)
	id, err := zm.CreateInterceptV1ConfigFixed(context.Background(), "pam-x-intercept", "100.64.2.1", 14007)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "icfg-existing" {
		t.Fatalf("want reused id icfg-existing, got %q", id)
	}
	if posts != 0 {
		t.Fatalf("must not POST when a matching config exists; posts=%d", posts)
	}
}
