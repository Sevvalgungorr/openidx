package access

import (
	"encoding/json"
	"testing"
)

// These tests pin the translation from an operator's intent ("these are my
// backends") to the upstream object the data plane executes. A mistake here is
// expensive: rendering an upstream with no reachable node black-holes a route,
// and unstable output would make every reconcile pass look like a change.

func intPtr(i int) *int { return &i }

func basePool() UpstreamPool {
	return UpstreamPool{
		ID:        "p1",
		Name:      "web",
		Algorithm: "roundrobin",
		Members: []UpstreamMember{
			{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
			{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
		},
	}
}

func TestBuildUpstreamSpreadsAcrossMembers(t *testing.T) {
	up, err := basePool().BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	nodes, ok := up["nodes"].(map[string]interface{})
	if !ok {
		t.Fatalf("nodes should be a map, got %T", up["nodes"])
	}
	if len(nodes) != 2 {
		t.Fatalf("expected both backends in the upstream, got %v", nodes)
	}
	if _, ok := nodes["10.0.0.1:8080"]; !ok {
		t.Errorf("missing first backend: %v", nodes)
	}
	if up["type"] != "roundrobin" {
		t.Errorf("type = %v, want roundrobin", up["type"])
	}
}

func TestBuildUpstreamHonorsWeights(t *testing.T) {
	p := basePool()
	p.Members[0].Weight = 5
	p.Members[1].Weight = 1
	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	nodes := up["nodes"].(map[string]interface{})
	if nodes["10.0.0.1:8080"] != 5 {
		t.Errorf("weight not carried through: %v", nodes)
	}
}

// A drained member (weight 0) must stay registered: that is how an operator
// takes a backend out of rotation without losing its health state.
func TestDrainedMemberStaysRegistered(t *testing.T) {
	p := basePool()
	p.Members[0].Weight = 0
	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	nodes := up["nodes"].(map[string]interface{})
	if _, ok := nodes["10.0.0.1:8080"]; !ok {
		t.Error("weight 0 should drain, not delete, the member")
	}
	if nodes["10.0.0.1:8080"] != 0 {
		t.Errorf("drained member should carry weight 0, got %v", nodes["10.0.0.1:8080"])
	}
}

// Disabled is different from drained: the member leaves the upstream entirely
// and is not even probed.
func TestDisabledMemberIsExcluded(t *testing.T) {
	p := basePool()
	p.Members[0].Enabled = false
	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	nodes := up["nodes"].(map[string]interface{})
	if _, ok := nodes["10.0.0.1:8080"]; ok {
		t.Error("disabled member must not appear in the upstream")
	}
	if len(nodes) != 1 {
		t.Errorf("expected only the enabled member, got %v", nodes)
	}
}

// The most important failure mode: a pool that cannot serve traffic must be
// reported, not rendered. Rendering an empty upstream would black-hole the
// route; the caller falls back to the route's single to_url instead.
func TestEmptyPoolIsRefusedRatherThanBlackHoled(t *testing.T) {
	for _, tc := range []struct {
		name string
		pool UpstreamPool
	}{
		{"no members at all", UpstreamPool{ID: "p", Name: "empty"}},
		{"every member disabled", UpstreamPool{ID: "p", Name: "off", Members: []UpstreamMember{
			{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: false},
		}}},
		{"member with no host", UpstreamPool{ID: "p", Name: "bad", Members: []UpstreamMember{
			{Host: "   ", Port: 8080, Weight: 1, Enabled: true},
		}}},
		{"member with impossible port", UpstreamPool{ID: "p", Name: "bad", Members: []UpstreamMember{
			{Host: "10.0.0.1", Port: 70000, Weight: 1, Enabled: true},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.pool.BuildUpstream("http", "", ""); err != ErrPoolUnusable {
				t.Fatalf("expected ErrPoolUnusable so the caller can fall back, got %v", err)
			}
		})
	}
}

// The reconciler PUTs the rendered object on every pass. If map iteration order
// leaked into the output, every pass would look like a change and churn the
// data plane.
func TestRenderIsStableAcrossRuns(t *testing.T) {
	p := basePool()
	var first string
	for i := 0; i < 20; i++ {
		up, err := p.BuildUpstream("http", "rewrite", "app.example")
		if err != nil {
			t.Fatalf("BuildUpstream: %v", err)
		}
		b, err := json.Marshal(up)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if i == 0 {
			first = string(b)
			continue
		}
		if string(b) != first {
			t.Fatalf("render is not stable:\n first=%s\n  now =%s", first, b)
		}
	}
}

func TestStickySessionsUseConsistentHashing(t *testing.T) {
	p := basePool()
	p.Algorithm = "chash"
	p.HashOn = "cookie"
	p.HashKey = "session_id"

	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	if up["type"] != "chash" {
		t.Errorf("type = %v, want chash", up["type"])
	}
	if up["hash_on"] != "cookie" || up["key"] != "session_id" {
		t.Errorf("stickiness key not carried: hash_on=%v key=%v", up["hash_on"], up["key"])
	}
}

// An unset or unknown algorithm must not silently become consistent hashing,
// which would pin all traffic to one backend.
func TestUnknownAlgorithmFallsBackToRoundRobin(t *testing.T) {
	for _, alg := range []string{"", "weighted", "least_conn", "garbage"} {
		p := basePool()
		p.Algorithm = alg
		up, err := p.BuildUpstream("http", "", "")
		if err != nil {
			t.Fatalf("BuildUpstream(%q): %v", alg, err)
		}
		if up["type"] != "roundrobin" {
			t.Errorf("algorithm %q rendered as %v, want roundrobin", alg, up["type"])
		}
		if _, ok := up["hash_on"]; ok {
			t.Errorf("algorithm %q must not emit hash settings", alg)
		}
	}
}

func TestHealthChecksAreEmittedWhenEnabled(t *testing.T) {
	p := basePool()
	p.HealthCheckEnabled = true
	p.HealthCheckPath = "/healthz"
	p.HealthyThreshold = 2
	p.UnhealthyThreshold = 3

	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	checks, ok := up["checks"].(map[string]interface{})
	if !ok {
		t.Fatalf("checks missing; a pool without probing cannot evict a dead backend")
	}
	active := checks["active"].(map[string]interface{})
	if active["http_path"] != "/healthz" {
		t.Errorf("http_path = %v", active["http_path"])
	}
	unhealthy := active["unhealthy"].(map[string]interface{})
	if unhealthy["http_failures"] != 3 {
		t.Errorf("unhealthy threshold not carried: %v", unhealthy)
	}
}

func TestHealthChecksAbsentWhenDisabled(t *testing.T) {
	p := basePool()
	p.HealthCheckEnabled = false
	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	if _, ok := up["checks"]; ok {
		t.Error("probing must not be configured when the operator turned it off")
	}
}

// Retrying more times than there are alternatives just repeats a failure.
func TestRetriesAreCappedAtAlternativeCount(t *testing.T) {
	p := basePool() // 2 members -> at most 1 alternative
	p.Retries = intPtr(9)
	up, err := p.BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	if up["retries"] != 1 {
		t.Errorf("retries = %v, want 1 (member count - 1)", up["retries"])
	}
}

func TestRetriesOmittedWhenUnset(t *testing.T) {
	up, err := basePool().BuildUpstream("http", "", "")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	if _, ok := up["retries"]; ok {
		t.Error("unset retries should defer to the data plane default, not force a value")
	}
}

func TestRouteLevelAddressingIsCarried(t *testing.T) {
	up, err := basePool().BuildUpstream("https", "rewrite", "app.example.test")
	if err != nil {
		t.Fatalf("BuildUpstream: %v", err)
	}
	if up["scheme"] != "https" || up["pass_host"] != "rewrite" || up["upstream_host"] != "app.example.test" {
		t.Errorf("route addressing lost: %v", up)
	}
}
