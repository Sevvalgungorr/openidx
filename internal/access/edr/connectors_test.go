package edr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDevicePassing(t *testing.T) {
	cases := []struct {
		d    Device
		want bool
	}{
		{Device{Compliant: true, Risk: RiskLow}, true},
		{Device{Compliant: true, Risk: RiskMedium}, true},
		{Device{Compliant: true, Risk: RiskHigh}, false},
		{Device{Compliant: true, Risk: RiskCritical}, false},
		{Device{Compliant: false, Risk: RiskLow}, false},
		{Device{Compliant: true, Risk: ""}, true},
	}
	for _, tc := range cases {
		if got := tc.d.Passing(); got != tc.want {
			t.Errorf("Passing(compliant=%v risk=%q)=%v want %v", tc.d.Compliant, tc.d.Risk, got, tc.want)
		}
	}
}

func TestNewUnsupportedProvider(t *testing.T) {
	if _, err := New(Config{Provider: "sentinelone"}); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	for _, p := range []string{ProviderCrowdStrike, ProviderIntune, ProviderJamf, ProviderWazuh} {
		if _, err := New(Config{Provider: p}); err != nil {
			t.Errorf("expected %s supported, got %v", p, err)
		}
	}
}

// --- CrowdStrike ---

func TestCrowdStrikeListDevices(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok123"}`))
	})
	mux.HandleFunc("/devices/queries/devices/v1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"resources":["aid-1","aid-2"]}`))
	})
	mux.HandleFunc("/devices/entities/devices/v2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"resources":[
          {"device_id":"aid-1","hostname":"laptop-1","serial_number":"S1","email":"a@corp.com","status":"normal","reduced_functionality_mode":"no","last_seen":"2025-01-01T00:00:00Z"},
          {"device_id":"aid-2","hostname":"laptop-2","serial_number":"S2","email":"b@corp.com","status":"contained","reduced_functionality_mode":"no"}
        ]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newCrowdStrike(Config{Provider: ProviderCrowdStrike, BaseURL: srv.URL, ClientID: "id", ClientSecret: "sec"})
	c.client = srv.Client()

	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	devices, err := c.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	byID := map[string]Device{}
	for _, d := range devices {
		byID[d.ExternalID] = d
	}
	if !byID["aid-1"].Passing() {
		t.Error("normal device should pass")
	}
	if byID["aid-1"].Serial != "S1" || byID["aid-1"].Hostname != "laptop-1" {
		t.Errorf("aid-1 mapping wrong: %+v", byID["aid-1"])
	}
	if byID["aid-2"].Passing() {
		t.Error("contained device should fail (not compliant)")
	}
}

func TestCrowdStrikeBadCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := newCrowdStrike(Config{BaseURL: srv.URL, ClientID: "id", ClientSecret: "bad"})
	c.client = srv.Client()
	if err := c.TestConnection(context.Background()); err == nil {
		t.Fatal("expected auth failure")
	}
}

// --- Intune ---

func TestIntuneListDevices(t *testing.T) {
	// Intune's token endpoint is at login.microsoftonline.com, which we can't
	// intercept by BaseURL. So we drive ListDevices with a pre-seeded client
	// that serves both token and graph from the same test server by overriding
	// the token URL via TenantID pointing at the test host is not possible;
	// instead we test the graph mapping directly through a small shim.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/deviceManagement/managedDevices", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graphtok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"value":[
          {"id":"md-1","deviceName":"win-1","serialNumber":"IS1","emailAddress":"c@corp.com","complianceState":"compliant","lastSyncDateTime":"2025-01-02T00:00:00Z"},
          {"id":"md-2","deviceName":"win-2","serialNumber":"IS2","emailAddress":"d@corp.com","complianceState":"noncompliant"}
        ]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	i := newIntune(Config{Provider: ProviderIntune, BaseURL: srv.URL, TenantID: "t", ClientID: "id", ClientSecret: "sec"})
	i.client = srv.Client()
	// Bypass the real token endpoint by exercising the graph listing with a
	// stub token injected through a tiny wrapper.
	devices, err := i.listWithToken(context.Background(), "graphtok")
	if err != nil {
		t.Fatalf("listWithToken: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	byID := map[string]Device{}
	for _, d := range devices {
		byID[d.ExternalID] = d
	}
	if !byID["md-1"].Passing() {
		t.Error("compliant device should pass")
	}
	if byID["md-1"].Email != "c@corp.com" || byID["md-1"].Serial != "IS1" {
		t.Errorf("md-1 mapping wrong: %+v", byID["md-1"])
	}
	if byID["md-2"].Passing() {
		t.Error("noncompliant device should fail")
	}
}

// --- Jamf ---

func TestJamfListDevices(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"token":"jamftok"}`))
	})
	mux.HandleFunc("/api/v1/computers-inventory", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jamftok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"totalCount":1,"results":[
          {"id":"100","general":{"name":"mac-1","lastContactTime":"2025-01-03T00:00:00Z"},"hardware":{"serialNumber":"JS1"},"userAndLocation":{"email":"e@corp.com"}}
        ]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	j := newJamf(Config{Provider: ProviderJamf, BaseURL: srv.URL, APIUser: "u", APIToken: "t"})
	j.client = srv.Client()

	if err := j.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	devices, err := j.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].Serial != "JS1" || devices[0].Hostname != "mac-1" || devices[0].Email != "e@corp.com" {
		t.Errorf("jamf mapping wrong: %+v", devices[0])
	}
	if !devices[0].Passing() {
		t.Error("managed jamf device should pass")
	}
}

// --- Wazuh ---

func TestWazuhListDevices(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"data":{"token":"wztok"}}`))
	})
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wztok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Agent 000 (the manager itself) must be skipped.
		w.Write([]byte(`{"data":{"affected_items":[
          {"id":"000","name":"wazuh-manager","status":"active"},
          {"id":"001","name":"laptop-1","ip":"10.0.0.5","status":"active","lastKeepAlive":"2026-07-30T00:00:00Z","os":{"name":"Ubuntu","version":"24.04"}},
          {"id":"002","name":"laptop-2","ip":"10.0.0.6","status":"disconnected","lastKeepAlive":"2026-07-28T00:00:00Z","os":{"name":"Windows","version":"11"}},
          {"id":"003","name":"laptop-3","status":"never_connected"}
        ],"total_affected_items":4}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newWazuh(Config{Provider: ProviderWazuh, BaseURL: srv.URL, APIUser: "wazuh", APIToken: "secret"})
	c.client = srv.Client()

	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	devices, err := c.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 3 {
		t.Fatalf("expected 3 devices (manager 000 skipped), got %d", len(devices))
	}
	byID := map[string]Device{}
	for _, d := range devices {
		byID[d.ExternalID] = d
	}
	if !byID["001"].Passing() {
		t.Error("active agent should pass")
	}
	if byID["001"].Hostname != "laptop-1" {
		t.Errorf("agent name should map to hostname, got %+v", byID["001"])
	}
	if byID["002"].Passing() || byID["002"].Risk != RiskHigh {
		t.Errorf("disconnected agent should fail at high risk: %+v", byID["002"])
	}
	if byID["003"].Passing() || byID["003"].Risk != RiskUnknown {
		t.Errorf("never_connected agent should fail as unknown: %+v", byID["003"])
	}
}

func TestWazuhPagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"token":"wztok"}}`))
	})
	pages := 0
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		pages++
		offset := r.URL.Query().Get("offset")
		if offset == "0" {
			// A full page (500 items) forces a second request.
			items := make([]string, 0, 500)
			for i := 1; i <= 500; i++ {
				items = append(items, fmt.Sprintf(`{"id":"%03d","name":"host-%d","status":"active"}`, i, i))
			}
			w.Write([]byte(`{"data":{"affected_items":[` + strings.Join(items, ",") + `],"total_affected_items":501}}`))
			return
		}
		w.Write([]byte(`{"data":{"affected_items":[{"id":"501","name":"host-501","status":"active"}],"total_affected_items":501}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newWazuh(Config{BaseURL: srv.URL, APIUser: "wazuh", APIToken: "secret"})
	c.client = srv.Client()
	devices, err := c.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	// 501 agents minus the skipped manager 000... "000" is id 0; ids here start
	// at 001, so all 501 are endpoints.
	if len(devices) != 501 {
		t.Fatalf("expected 501 devices across pages, got %d", len(devices))
	}
	if pages != 2 {
		t.Fatalf("expected 2 pages fetched, got %d", pages)
	}
}

func TestWazuhBadCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := newWazuh(Config{BaseURL: srv.URL, APIUser: "wazuh", APIToken: "bad"})
	c.client = srv.Client()
	if err := c.TestConnection(context.Background()); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestWazuhRequiresBaseURL(t *testing.T) {
	c := newWazuh(Config{APIUser: "wazuh", APIToken: "secret"})
	if err := c.TestConnection(context.Background()); err == nil {
		t.Fatal("expected error for missing base_url")
	}
}
