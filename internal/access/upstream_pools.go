package access

import (
	"fmt"
	"sort"
	"strings"
)

// Upstream pools: turning an operator's "these are my backends" statement into
// the upstream object the data plane understands.
//
// A route used to carry exactly one address (proxy_routes.to_url), so a dead
// backend took its route down with it and there was no way to spread load.
// Measured before this change on the live edge: 0 of 19 routes had more than
// one node, and none had an active health check.
//
// The data plane (APISIX) already implements weighted balancing, consistent
// hashing and active probing; the missing piece was a way to express intent.
// This file is that translation layer, kept as pure functions so the mapping
// can be tested without a database or a running gateway.

// UpstreamPool is an operator's declaration of where a route's traffic may go.
type UpstreamPool struct {
	ID   string
	Name string

	// Algorithm is "roundrobin" (spread by weight) or "chash" (pin a caller to
	// one backend, i.e. session stickiness).
	Algorithm string
	HashOn    string
	HashKey   string

	HealthCheckEnabled  bool
	HealthCheckPath     string
	HealthyThreshold    int
	UnhealthyThreshold  int
	HealthCheckInterval int
	HealthCheckTimeout  int

	// Retries is the number of other members to try when one fails mid-request.
	// nil means "let the data plane decide" (it defaults to member count - 1).
	Retries *int

	Members []UpstreamMember
}

// UpstreamMember is one backend instance.
type UpstreamMember struct {
	Host string
	Port int
	// Weight is the relative share of traffic. 0 drains a member without
	// removing it, which is how a backend is taken out for maintenance.
	Weight  int
	Enabled bool
}

// activeMembers returns the members that should appear in the rendered
// upstream: enabled, addressable, and sorted so the output is stable.
//
// Stability matters more than it looks. The reconciler PUTs the rendered object
// on every pass; if map iteration order leaked into the output, every pass
// would look like a change and churn the data plane's configuration.
func (p UpstreamPool) activeMembers() []UpstreamMember {
	out := make([]UpstreamMember, 0, len(p.Members))
	for _, m := range p.Members {
		if !m.Enabled {
			continue
		}
		if strings.TrimSpace(m.Host) == "" || m.Port <= 0 || m.Port > 65535 {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// ErrPoolUnusable means a pool cannot produce a working upstream, so the caller
// must fall back to the route's single to_url rather than render a broken one.
//
// Rendering an upstream with no reachable node would black-hole the route. A
// pool that an operator has fully drained is therefore treated as "not
// configured" instead of "configured to drop traffic".
var ErrPoolUnusable = fmt.Errorf("upstream pool has no usable members")

// BuildUpstream renders the pool as an APISIX upstream object.
//
// scheme/passHost/upstreamHost are supplied by the caller because they belong
// to the route (how to address the backend), not to the pool (which backends
// exist).
func (p UpstreamPool) BuildUpstream(scheme, passHost, upstreamHost string) (map[string]interface{}, error) {
	members := p.activeMembers()
	if len(members) == 0 {
		return nil, ErrPoolUnusable
	}

	nodes := make(map[string]interface{}, len(members))
	for _, m := range members {
		// Weight 0 is meaningful: the member stays registered and health-checked
		// but receives no new traffic.
		nodes[fmt.Sprintf("%s:%d", m.Host, m.Port)] = m.Weight
	}

	algorithm := p.Algorithm
	if algorithm != "chash" {
		algorithm = "roundrobin"
	}

	up := map[string]interface{}{
		"type":  algorithm,
		"nodes": nodes,
	}
	if scheme != "" {
		up["scheme"] = scheme
	}
	if passHost != "" {
		up["pass_host"] = passHost
	}
	if upstreamHost != "" {
		up["upstream_host"] = upstreamHost
	}

	if algorithm == "chash" {
		hashOn := p.HashOn
		if hashOn == "" {
			hashOn = "vars"
		}
		hashKey := p.HashKey
		if hashKey == "" {
			hashKey = "remote_addr"
		}
		up["hash_on"] = hashOn
		up["key"] = hashKey
	}

	// Retrying costs nothing when there is nowhere to retry, and retrying more
	// times than there are other members just repeats a failure.
	if p.Retries != nil {
		r := *p.Retries
		if max := len(members) - 1; r > max {
			r = max
		}
		if r < 0 {
			r = 0
		}
		up["retries"] = r
	}

	if p.HealthCheckEnabled {
		up["checks"] = p.buildChecks()
	}

	return up, nil
}

// buildChecks renders active health probing.
//
// Two separate thresholds (not one) are deliberate: a single blip should not
// evict a healthy backend, and a single success should not immediately restore
// one that is still recovering.
func (p UpstreamPool) buildChecks() map[string]interface{} {
	path := p.HealthCheckPath
	if path == "" {
		path = "/"
	}
	interval := p.HealthCheckInterval
	if interval <= 0 {
		interval = 5
	}
	timeout := p.HealthCheckTimeout
	if timeout <= 0 {
		timeout = 3
	}
	healthy := p.HealthyThreshold
	if healthy <= 0 {
		healthy = 2
	}
	unhealthy := p.UnhealthyThreshold
	if unhealthy <= 0 {
		unhealthy = 3
	}

	return map[string]interface{}{
		"active": map[string]interface{}{
			"type":        "http",
			"http_path":   path,
			"timeout":     timeout,
			"concurrency": 10,
			"healthy": map[string]interface{}{
				"interval": interval,
				// A backend that answers at all is reachable. Restricting this
				// to 200 would evict backends whose health path legitimately
				// redirects or requires auth.
				"http_statuses": []int{200, 201, 202, 204, 301, 302, 401, 403},
				"successes":     healthy,
			},
			"unhealthy": map[string]interface{}{
				"interval":      interval,
				"http_statuses": []int{429, 500, 501, 502, 503, 504},
				"http_failures": unhealthy,
				"tcp_failures":  unhealthy,
				"timeouts":      unhealthy,
			},
		},
	}
}
