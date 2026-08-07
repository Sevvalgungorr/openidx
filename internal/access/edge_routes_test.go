package access

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

// These tests pin the safety property that makes upstream pools opt-in: a route
// must never end up with an empty or missing upstream because of a pool
// problem. Falling back to the route's single target keeps traffic flowing;
// rendering nothing would black-hole it.

func decodeUpstream(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal route: %v", err)
	}
	up, ok := obj["upstream"].(map[string]interface{})
	if !ok {
		t.Fatalf("route has no upstream: %s", body)
	}
	return up
}

func TestRouteWithoutPoolRendersItsSingleTarget(t *testing.T) {
	r := edgeRoute{name: "App One", fromURL: "https://app.example.test", toURL: "http://10.0.0.9:8080"}
	name, body, err := buildEdgeRoute(r, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("buildEdgeRoute: %v", err)
	}
	if name != "oidx-route-app-one" {
		t.Errorf("route name = %q", name)
	}
	nodes := decodeUpstream(t, body)["nodes"].(map[string]interface{})
	if _, ok := nodes["10.0.0.9:8080"]; !ok {
		t.Errorf("pre-pool behaviour lost: %v", nodes)
	}
}

// The port is implied by the scheme when the target omits it; getting this
// wrong would send https traffic to port 80.
func TestTargetPortDefaultsFromScheme(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://secure.example.test", "secure.example.test:443"},
		{"http://plain.example.test", "plain.example.test:80"},
		{"http://explicit.example.test:8443", "explicit.example.test:8443"},
	} {
		up, err := upstreamFromToURL(tc.url)
		if err != nil {
			t.Fatalf("upstreamFromToURL(%q): %v", tc.url, err)
		}
		nodes := up["nodes"].(map[string]interface{})
		if _, ok := nodes[tc.want]; !ok {
			t.Errorf("%q -> %v, want node %q", tc.url, nodes, tc.want)
		}
	}
}

func TestRouteWithPoolRendersEveryMember(t *testing.T) {
	pools := map[string]*UpstreamPool{
		"pool-1": {
			ID: "pool-1", Name: "web", Algorithm: "roundrobin",
			Members: []UpstreamMember{
				{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
				{Host: "10.0.0.2", Port: 8080, Weight: 3, Enabled: true},
			},
		},
	}
	r := edgeRoute{name: "App", fromURL: "https://app.example.test", toURL: "http://10.0.0.9:8080", poolID: "pool-1"}
	_, body, err := buildEdgeRoute(r, pools, zap.NewNop())
	if err != nil {
		t.Fatalf("buildEdgeRoute: %v", err)
	}
	nodes := decodeUpstream(t, body)["nodes"].(map[string]interface{})
	if len(nodes) != 2 {
		t.Fatalf("expected both pool members, got %v", nodes)
	}
	if nodes["10.0.0.2:8080"] != float64(3) {
		t.Errorf("weight lost through JSON: %v", nodes)
	}
	// The pool replaces to_url entirely; the old single target must not linger.
	if _, ok := nodes["10.0.0.9:8080"]; ok {
		t.Errorf("to_url should not appear once a pool is in effect: %v", nodes)
	}
}

// The important safety case: a pool that cannot serve traffic must not produce
// a route with no backends.
func TestUnusablePoolFallsBackInsteadOfBlackHoling(t *testing.T) {
	pools := map[string]*UpstreamPool{
		"pool-1": {ID: "pool-1", Name: "drained", Members: []UpstreamMember{
			{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: false},
		}},
	}
	r := edgeRoute{name: "App", fromURL: "https://app.example.test", toURL: "http://10.0.0.9:8080", poolID: "pool-1"}
	_, body, err := buildEdgeRoute(r, pools, zap.NewNop())
	if err != nil {
		t.Fatalf("an unusable pool must not fail the route: %v", err)
	}
	nodes := decodeUpstream(t, body)["nodes"].(map[string]interface{})
	if _, ok := nodes["10.0.0.9:8080"]; !ok {
		t.Errorf("expected fallback to the route's own target, got %v", nodes)
	}
}

// A dangling pool reference (deleted pool, stale id) must behave the same way.
func TestUnknownPoolFallsBack(t *testing.T) {
	r := edgeRoute{name: "App", fromURL: "https://app.example.test", toURL: "http://10.0.0.9:8080", poolID: "gone"}
	_, body, err := buildEdgeRoute(r, map[string]*UpstreamPool{}, zap.NewNop())
	if err != nil {
		t.Fatalf("a dangling pool reference must not fail the route: %v", err)
	}
	nodes := decodeUpstream(t, body)["nodes"].(map[string]interface{})
	if _, ok := nodes["10.0.0.9:8080"]; !ok {
		t.Errorf("expected fallback to the route's own target, got %v", nodes)
	}
}

// A route we cannot address must be reported, not rendered as a broken object.
func TestRouteWithoutHostnameIsRefused(t *testing.T) {
	for _, from := range []string{"", "not a url", "https://"} {
		if _, _, err := buildEdgeRoute(edgeRoute{name: "x", fromURL: from, toURL: "http://10.0.0.9:8080"}, nil, zap.NewNop()); err == nil {
			t.Errorf("fromURL %q should be refused", from)
		}
	}
}

// Generated names are namespaced so a reconcile pass never prunes routes it did
// not create.
func TestGeneratedNamesAreNamespaced(t *testing.T) {
	if got := edgeRouteName("My App!"); got != "oidx-route-my-app" {
		t.Errorf("edgeRouteName = %q", got)
	}
	if got := edgeRouteName("***"); got != "oidx-route-unnamed" {
		t.Errorf("a name with no usable characters should still be addressable, got %q", got)
	}
}
