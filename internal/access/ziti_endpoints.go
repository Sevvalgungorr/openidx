// Ziti controller endpoint pool — management-API failover across the members
// of an HA controller cluster.
//
// OpenIDX drives the controller through its edge management API. With a single
// controller, that API is a single point of failure for every control-plane
// operation (identity sync, service provisioning, kill-switch severs) even
// though the data plane keeps running. When the operator runs an HA controller
// cluster (Raft), all members serve the same management API behind the same
// PKI and admin credentials, so failing over is safe: this pool tries the
// active endpoint, puts it in cooldown on a network error or 5xx, and rotates
// to the next healthy member. mgmtRequest re-authenticates after a rotation
// because zt-session tokens are minted per controller.
//
// The SDK data-plane context is unaffected: an enrolled identity file carries
// the full controller list and sdk-golang handles its own failover.
package access

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// zitiEndpointCooldown is how long a failed endpoint is skipped before it is
// eligible again. Matches the reconciler/health-monitor cadence so a recovered
// controller is picked back up within one cycle.
const zitiEndpointCooldown = 30 * time.Second

// ZitiEndpointStatus is the wire shape surfaced on /ziti/status.
type ZitiEndpointStatus struct {
	URL     string `json:"url"`
	Active  bool   `json:"active"`
	Healthy bool   `json:"healthy"`
}

// controllerEndpointPool holds the ordered list of controller management base
// URLs. The first entry (ZitiCtrlURL) is the preferred endpoint; extras come
// from ZitiCtrlURLs. All methods are safe for concurrent use.
type controllerEndpointPool struct {
	mu        sync.Mutex
	endpoints []string // validated scheme://host base URLs, preference order
	active    int
	downUntil map[string]time.Time
	cooldown  time.Duration
	now       func() time.Time // injectable for tests
}

// normalizeControllerURL validates a controller URL the same way mgmtURL does
// (http/https scheme + host required) and reduces it to scheme://host so a
// hostile or malformed URL cannot smuggle a path/userinfo into management
// calls (mitigates go/request-forgery, same contract as mgmtURL).
func normalizeControllerURL(raw string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return "", fmt.Errorf("ziti: invalid controller URL %q", raw)
	}
	return base.Scheme + "://" + base.Host, nil
}

// newControllerEndpointPool builds a pool from the primary URL plus an
// optional comma-separated extras list. Invalid or duplicate entries in extras
// are dropped (the primary must be valid). Never returns an empty pool.
func newControllerEndpointPool(primary, extras string) (*controllerEndpointPool, error) {
	first, err := normalizeControllerURL(primary)
	if err != nil {
		return nil, err
	}
	endpoints := []string{first}
	seen := map[string]bool{first: true}
	for _, raw := range strings.Split(extras, ",") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		u, err := normalizeControllerURL(raw)
		if err != nil || seen[u] {
			continue
		}
		seen[u] = true
		endpoints = append(endpoints, u)
	}
	return &controllerEndpointPool{
		endpoints: endpoints,
		downUntil: make(map[string]time.Time),
		cooldown:  zitiEndpointCooldown,
		now:       time.Now,
	}, nil
}

// Current returns the endpoint management calls should use right now: the
// active endpoint if it is not cooling down, otherwise the first healthy one
// (which becomes active). If every endpoint is cooling down, the active one is
// returned anyway — with nothing healthy, failing fast against the preferred
// controller beats returning an error without trying.
func (p *controllerEndpointPool) Current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.healthyLocked(p.endpoints[p.active]) {
		return p.endpoints[p.active]
	}
	for i, ep := range p.endpoints {
		if p.healthyLocked(ep) {
			p.active = i
			return ep
		}
	}
	return p.endpoints[p.active]
}

// MarkDown puts the endpoint in cooldown and, if it was active, rotates to the
// next healthy endpoint. Returns the new current endpoint and whether it
// differs from the one marked down (i.e. a failover actually happened).
func (p *controllerEndpointPool) MarkDown(endpoint string) (string, bool) {
	p.mu.Lock()
	p.downUntil[endpoint] = p.now().Add(p.cooldown)
	p.mu.Unlock()
	next := p.Current()
	return next, next != endpoint
}

// MarkUp clears any cooldown for the endpoint, making it eligible for
// selection again. Selection stays sticky on the current active member — a
// recovered endpoint only takes over when the active one next fails, which
// avoids failback churn (every controller switch costs a re-auth).
func (p *controllerEndpointPool) MarkUp(endpoint string) {
	p.mu.Lock()
	delete(p.downUntil, endpoint)
	p.mu.Unlock()
}

// Size returns the number of endpoints in the pool.
func (p *controllerEndpointPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.endpoints)
}

// Snapshot reports every endpoint with its health/active flags for status
// surfaces.
func (p *controllerEndpointPool) Snapshot() []ZitiEndpointStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]ZitiEndpointStatus, 0, len(p.endpoints))
	for i, ep := range p.endpoints {
		out = append(out, ZitiEndpointStatus{
			URL:     ep,
			Active:  i == p.active,
			Healthy: p.healthyLocked(ep),
		})
	}
	return out
}

func (p *controllerEndpointPool) healthyLocked(endpoint string) bool {
	until, down := p.downUntil[endpoint]
	return !down || p.now().After(until)
}
