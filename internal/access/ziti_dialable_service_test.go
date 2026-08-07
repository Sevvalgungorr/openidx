package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// TestProvisionDialableService is the regression guard for the "Add Service"
// fix: creating a Ziti service from the admin console must provision the FULL
// object graph (host.v1 + intercept.v1 configs, the service, and Bind/Dial/
// service-edge-router policies) so the service is actually dialable. The old
// path created a bare service object with no configs or policies, so nothing
// could ever reach it. This drives a mock controller and asserts every piece is
// created with the right defaults (intercept "<name>.ziti", dial "#<name>-clients").
func TestProvisionDialableService(t *testing.T) {
	var mu sync.Mutex
	createdConfigs := map[string]map[string]interface{}{} // name -> data
	createdServices := []string{}
	policies := map[string]map[string]interface{}{} // name -> body
	serps := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		readJSON := func() map[string]interface{} {
			b, _ := io.ReadAll(r.Body)
			var m map[string]interface{}
			_ = json.Unmarshal(b, &m)
			return m
		}
		switch {
		// GET a specific service (for config-attach): return an object with an
		// empty configs array so EnsureServiceConfig can append.
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/services/"):
			_, _ = w.Write([]byte(`{"data":{"id":"svc-secops","configs":[]}}`))
		// Idempotency lookups: always "not found" so the code creates fresh.
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/configs"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/services"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/service-policies"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/service-edge-router-policies"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/edge-routers"):
			_, _ = w.Write([]byte(`{"data":[]}`))

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/configs"):
			m := readJSON()
			name, _ := m["name"].(string)
			data, _ := m["data"].(map[string]interface{})
			createdConfigs[name] = data
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"cfg-` + name + `"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/services"):
			m := readJSON()
			name, _ := m["name"].(string)
			createdServices = append(createdServices, name)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"svc-` + name + `"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/service-policies"):
			m := readJSON()
			name, _ := m["name"].(string)
			policies[name] = m
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"pol-` + name + `"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/service-edge-router-policies"):
			m := readJSON()
			name, _ := m["name"].(string)
			serps[name] = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"serp-` + name + `"}}`))
		case r.Method == "PATCH":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	defer srv.Close()

	zm := &ZitiManager{
		logger:      zap.NewNop(),
		mgmtToken:   "fake",
		mgmtClient:  &http.Client{},
		cfg:         &config.Config{ZitiCtrlURL: srv.URL},
		initialized: true,
		configTypeCache: map[string]string{
			"host.v1":      "hostTypeID",
			"intercept.v1": "interceptTypeID",
		},
	}

	// No InterceptAddress / DialIdentityRoles → must default to <name>.ziti and #<name>-clients.
	id, err := zm.ProvisionDialableService(context.Background(), DialableServiceSpec{
		Name:       "secops",
		TargetHost: "192.168.152.113",
		TargetPort: 443,
	})
	if err != nil {
		t.Fatalf("ProvisionDialableService: %v", err)
	}
	if id != "svc-secops" {
		t.Fatalf("service id = %q, want svc-secops", id)
	}

	mu.Lock()
	defer mu.Unlock()

	// host.v1 → target
	host := createdConfigs["secops-host"]
	if host == nil || host["address"] != "192.168.152.113" {
		t.Fatalf("host.v1 config missing/wrong: %+v", host)
	}
	// intercept.v1 → default <name>.ziti
	intercept := createdConfigs["secops-intercept"]
	if intercept == nil {
		t.Fatalf("intercept.v1 config not created")
	}
	addrs, _ := intercept["addresses"].([]interface{})
	if len(addrs) != 1 || addrs[0] != "secops.ziti" {
		t.Fatalf("intercept address = %+v, want [secops.ziti]", intercept["addresses"])
	}
	// service created
	if len(createdServices) != 1 || createdServices[0] != "secops" {
		t.Fatalf("services created = %+v, want [secops]", createdServices)
	}
	// Bind policy → routers
	bind := policies["openidx-bind-secops"]
	if bind == nil || bind["type"] != "Bind" {
		t.Fatalf("bind policy missing/wrong: %+v", bind)
	}
	if roles, _ := bind["identityRoles"].([]interface{}); len(roles) != 1 || roles[0] != "#ziti-routers" {
		t.Fatalf("bind identityRoles = %+v, want [#ziti-routers]", bind["identityRoles"])
	}
	// Dial policy → default #<name>-clients
	dial := policies["openidx-dial-secops"]
	if dial == nil || dial["type"] != "Dial" {
		t.Fatalf("dial policy missing/wrong: %+v", dial)
	}
	if roles, _ := dial["identityRoles"].([]interface{}); len(roles) != 1 || roles[0] != "#secops-clients" {
		t.Fatalf("dial identityRoles = %+v, want [#secops-clients]", dial["identityRoles"])
	}
	// service-edge-router-policy present
	if !serps["openidx-serp-secops"] {
		t.Fatalf("service-edge-router-policy openidx-serp-secops not created")
	}
}
