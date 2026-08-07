// Package access — admin-facing "behind the scenes" explanation.
//
// The user-facing My Network page deliberately hides the overlay. Administrators
// need the opposite: the real chain, and — when something does not work — which
// link is broken and what to do about it. This file answers one question from
// the console, without anyone opening a CLI:
//
//	"Why can (or can't) this resource be reached?"
//
// It reads the live controller and reports each hop as OK / missing, so an admin
// diagnoses a route the same way they would with `ziti edge policy-advisor`, but
// in the UI and in words that name the fix.
package access

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ChainHop is one link in the path a packet takes from a client to the target.
// Status is deliberately blunt: "ok" | "missing" | "unknown".
type ChainHop struct {
	// Step is the position in the chain (1-based) for ordered rendering.
	Step int `json:"step"`
	// Title is what this hop is, in admin language ("Who may reach it").
	Title string `json:"title"`
	// Detail is the concrete object/value found (or what was looked for).
	Detail string `json:"detail"`
	// Technical is the underlying overlay object name, shown as secondary text
	// so an admin can correlate with the fabric/CLI when they want to.
	Technical string `json:"technical,omitempty"`
	Status    string `json:"status"`
	// Fix, when set, tells the admin exactly what to do to repair this hop.
	Fix string `json:"fix,omitempty"`
}

// ResourceDiagnosis is the full answer for one resource.
type ResourceDiagnosis struct {
	Name string `json:"name"`
	// Reachable is true only when every required hop is present.
	Reachable bool `json:"reachable"`
	// Summary is a one-line plain answer ("Reachable" / what is broken).
	Summary string     `json:"summary"`
	Chain   []ChainHop `json:"chain"`
}

// handleExplainZitiService explains how a Ziti service is wired end to end and
// where the chain breaks. Admin-only: it intentionally exposes fabric internals,
// which is the whole point — admins keep the behind-the-scenes view that end
// users no longer need.
func (s *Service) handleExplainZitiService(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}
	ctx := c.Request.Context()
	if _, err := orgctx.From(ctx); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service name is required"})
		return
	}

	d := s.explainService(ctx, name)
	c.JSON(http.StatusOK, d)
}

// explainService walks the object graph a working service needs, in the order a
// connection actually traverses it, and marks the first broken link.
func (s *Service) explainService(ctx context.Context, name string) ResourceDiagnosis {
	zm := s.ziti()
	d := ResourceDiagnosis{Name: name}

	// Look the service up once; everything else keys off it.
	var svcID string
	if svc, err := zm.GetServiceByName(name); err != nil {
		s.logger.Warn("explain: service lookup failed", zap.String("service", name), zap.Error(err))
	} else if svc != nil {
		svcID = svc.ID
	}

	// Hop 1 — the service object itself.
	svcHop := ChainHop{
		Step: 1, Title: "The resource is defined", Technical: "service " + name,
	}
	if svcID != "" {
		svcHop.Status = "ok"
		svcHop.Detail = name
	} else {
		svcHop.Status = "missing"
		svcHop.Detail = "no resource named " + name
		svcHop.Fix = "Create it from Zero Trust Access → Add Service."
	}
	d.Chain = append(d.Chain, svcHop)

	// Hops 2 & 3 — the two configs that make it dialable: where clients dial,
	// and where the router forwards.
	configs := map[string]bool{}
	if ents, err := zm.listEdgeEntities(ctx, "configs"); err == nil {
		for _, e := range ents {
			configs[e.Name] = true
		}
	} else {
		s.logger.Warn("explain: config list failed", zap.Error(err))
	}

	interceptHop := ChainHop{
		Step: 2, Title: "Clients know the address to dial",
		Technical: "intercept.v1 config " + name + "-intercept",
	}
	if configs[name+"-intercept"] {
		interceptHop.Status = "ok"
		interceptHop.Detail = "the overlay address is published"
	} else {
		interceptHop.Status = "missing"
		interceptHop.Detail = "no dial address is published, so clients cannot resolve it"
		interceptHop.Fix = "Re-save the resource so its address is published."
	}
	d.Chain = append(d.Chain, interceptHop)

	hostHop := ChainHop{
		Step: 3, Title: "The target it forwards to",
		Technical: "host.v1 config " + name + "-host",
	}
	if configs[name+"-host"] {
		hostHop.Status = "ok"
		hostHop.Detail = "a target host and port are set"
	} else {
		hostHop.Status = "missing"
		hostHop.Detail = "no target host/port is set"
		hostHop.Fix = "Set the target host and port on the resource."
	}
	d.Chain = append(d.Chain, hostHop)

	// Hops 4 & 5 — who may reach it, and who carries it.
	var dialRoles, bindRoles []string
	if pols, err := zm.ListServicePolicies(ctx); err == nil {
		for _, p := range pols {
			if !policyCoversService(p.ServiceRoles, name) {
				continue
			}
			switch strings.EqualFold(p.Type, "Dial") {
			case true:
				dialRoles = append(dialRoles, p.IdentityRoles...)
			default:
				if strings.EqualFold(p.Type, "Bind") {
					bindRoles = append(bindRoles, p.IdentityRoles...)
				}
			}
		}
	} else {
		s.logger.Warn("explain: policy list failed", zap.Error(err))
	}

	whoHop := ChainHop{
		Step: 4, Title: "Who may reach it", Technical: "Dial policy",
	}
	if len(dialRoles) > 0 {
		whoHop.Status = "ok"
		whoHop.Detail = "granted to " + strings.Join(dedupe(dialRoles), ", ")
	} else {
		whoHop.Status = "missing"
		whoHop.Detail = "nobody is allowed to reach it yet"
		whoHop.Fix = "Set “Who can reach it” on the resource."
	}
	d.Chain = append(d.Chain, whoHop)

	carryHop := ChainHop{
		Step: 5, Title: "A gateway carries the traffic", Technical: "Bind policy",
	}
	if len(bindRoles) > 0 {
		carryHop.Status = "ok"
		carryHop.Detail = "hosted by " + strings.Join(dedupe(bindRoles), ", ")
	} else {
		carryHop.Status = "missing"
		carryHop.Detail = "no gateway is hosting this resource"
		carryHop.Fix = "Re-save the resource so a gateway picks it up."
	}
	d.Chain = append(d.Chain, carryHop)

	// Hop 6 — a live terminator proves a gateway really registered it.
	termHop := ChainHop{
		Step: 6, Title: "A gateway is connected right now", Technical: "terminator",
	}
	if svcID != "" && s.serviceHasTerminator(ctx, name) {
		termHop.Status = "ok"
		termHop.Detail = "a gateway is online and serving this resource"
	} else {
		termHop.Status = "missing"
		termHop.Detail = "no gateway is currently serving it"
		termHop.Fix = "Check that a gateway is online and can reach the target host."
	}
	d.Chain = append(d.Chain, termHop)

	// Summarize: first broken link wins, so the admin sees one clear next step.
	d.Reachable = true
	for _, h := range d.Chain {
		if h.Status != "ok" {
			d.Reachable = false
			d.Summary = h.Detail
			break
		}
	}
	if d.Reachable {
		d.Summary = "Reachable — every step is in place."
	}
	return d
}

// serviceHasTerminator reports whether a gateway currently serves the service.
func (s *Service) serviceHasTerminator(ctx context.Context, serviceName string) bool {
	ents, err := s.ziti().listEdgeEntities(ctx, "terminators")
	if err != nil {
		s.logger.Warn("explain: terminator list failed", zap.Error(err))
		return false
	}
	for _, e := range ents {
		// Terminator names/ids do not carry the service name, so match on the
		// embedded service reference when present.
		if strings.Contains(strings.ToLower(e.Name), strings.ToLower(serviceName)) {
			return true
		}
	}
	// Fall back to the dedicated terminator query, which resolves the service.
	return s.terminatorExistsForService(ctx, serviceName)
}

// terminatorExistsForService asks the controller for terminators filtered to one
// service, which is authoritative when the list form does not embed the name.
func (s *Service) terminatorExistsForService(ctx context.Context, serviceName string) bool {
	path := `/edge/management/v1/terminators?filter=service.name="` + serviceName + `"`
	data, status, err := s.ziti().mgmtRequest("GET", path, nil)
	if err != nil || status != http.StatusOK {
		return false
	}
	// A non-empty data array means at least one gateway is serving it.
	return strings.Contains(string(data), `"id"`)
}

// policyCoversService reports whether a policy's serviceRoles select this
// service, either by the "#<name>" role attribute or an explicit "@<name>".
func policyCoversService(serviceRoles []string, name string) bool {
	for _, r := range serviceRoles {
		switch r {
		case "#" + name, "@" + name, "#all":
			return true
		}
	}
	return false
}

// dedupe returns the unique values, preserving order, for readable summaries.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
