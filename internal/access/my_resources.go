// Package access — user-facing resource aggregator.
//
// "My Network" answers one question for an end user: *what can I reach, and how
// do I get there?* It deliberately speaks in resources (a name, a target, a
// port, one button) and never in overlay vocabulary — no services, policies,
// intercepts, identities or enrollment tokens leak into this response. The admin
// pages keep the full fabric view; this file is the plain-language projection.
package access

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Resource kinds, chosen to be meaningful to a non-technical user.
const (
	resourceKindWeb     = "web"
	resourceKindDesktop = "remote_desktop"
	resourceKindSSH     = "ssh"
	resourceKindDB      = "database"
)

// How the user actually gets there.
const (
	// reachBrowser: opens directly in the browser. Needs no client and no
	// device enrollment (this is the BrowZer-fronted path).
	reachBrowser = "browser"
	// reachBroker: rendered in the browser by the session broker (Guacamole),
	// so RDP/SSH also need no local client.
	reachBroker = "broker"
)

// Statuses. Every non-ready status MUST carry an action the user can take
// themselves — the UI must never render a dead end.
const (
	statusReady         = "ready"          // click and go
	statusRequestAccess = "request_access" // needs approval first
	statusNeedsSetup    = "needs_setup"    // needs a one-time step by an admin
)

// MyResource is one row on the My Network page. The field names are part of the
// user-facing contract: they describe a journey (from → to), not fabric objects.
type MyResource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`

	// From/To/Port state the path in plain words: "Your browser" → "secops.tdv.org".
	From string `json:"from"`
	To   string `json:"to"`
	Port int    `json:"port"`

	// How the user reaches it (browser | broker).
	How string `json:"how"`

	// Status plus the single action that follows from it.
	Status string `json:"status"`
	// Action is the one primary control the card renders.
	Action MyResourceAction `json:"action"`

	// Note is a short human explanation shown under the card (e.g. why approval
	// is needed). Never contains overlay vocabulary.
	Note string `json:"note,omitempty"`
}

// MyResourceAction is the single primary control on a resource card. Exactly one
// action per resource keeps the page to one obvious click.
type MyResourceAction struct {
	// Label is the button text ("Open", "Connect", "Request access").
	Label string `json:"label"`
	// Kind tells the UI how to perform it: open_url | broker_connect | request.
	Kind string `json:"kind"`
	// URL is set for open_url. Target is the id the UI posts to for the others.
	URL    string `json:"url,omitempty"`
	Target string `json:"target,omitempty"`
}

// handleMyResources returns the resources the calling user can reach, projected
// into plain language. Scoped to the caller's organization, and to what the
// caller is actually entitled to:
//
//   - web routes fronted for the browser (no client, no enrollment);
//   - brokered systems (RDP/SSH) the caller holds a grant for, rendered in the
//     browser by the session broker.
//
// Anything the caller is not entitled to is omitted rather than shown as a
// locked row, except where a self-service request is possible — in which case it
// is surfaced with a "Request access" action so the user stays in control.
func (s *Service) handleMyResources(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	resources := make([]MyResource, 0, 16)
	resources = append(resources, s.browserResources(ctx, org.ID, c)...)
	resources = append(resources, s.brokeredResources(ctx, org.ID, userID, c)...)

	// Stable, human ordering: ready things first, then by name.
	sort.SliceStable(resources, func(i, j int) bool {
		if (resources[i].Status == statusReady) != (resources[j].Status == statusReady) {
			return resources[i].Status == statusReady
		}
		return strings.ToLower(resources[i].Name) < strings.ToLower(resources[j].Name)
	})

	ready := 0
	for _, r := range resources {
		if r.Status == statusReady {
			ready++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"resources": resources,
		"summary": gin.H{
			"total": len(resources),
			"ready": ready,
		},
	})
}

// browserResources lists web apps the user can open straight from the browser.
// These require no client install and no device enrollment, which is what makes
// them the default path for everyone.
func (s *Service) browserResources(ctx context.Context, orgID string, c *gin.Context) []MyResource {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, from_url, COALESCE(allowed_roles, '[]'::jsonb)::text
		  FROM proxy_routes
		 WHERE org_id = $1 AND enabled = true AND browzer_enabled = true
		 ORDER BY name`, orgID)
	if err != nil {
		s.logger.Error("my-resources: browser query failed", zap.Error(err))
		return nil
	}
	defer rows.Close()

	callerRoles := pamCallerRoles(c)
	out := []MyResource{}
	for rows.Next() {
		var id, name, fromURL, allowedRolesJSON string
		if err := rows.Scan(&id, &name, &fromURL, &allowedRolesJSON); err != nil {
			s.logger.Warn("my-resources: browser scan failed", zap.Error(err))
			continue
		}
		// Route-level role restriction mirrors what the proxy enforces at
		// request time, so we never advertise a route the user would be
		// bounced from.
		if !rolesAllow(allowedRolesJSON, callerRoles) {
			continue
		}

		host, port := hostPortFromURL(fromURL)

		// Honesty check. A route can be fully configured and still hand the user
		// a button that fails in the browser — the exact false promise this page
		// exists to remove. DNS alone is not enough: a name can resolve while the
		// path behind it is dead. So probe the published URL and only call it
		// ready when something actually answers.
		//
		// ANY HTTP status counts as reachable, including 401/302: a login prompt
		// or redirect proves the whole path works and the app is simply asking
		// the user to authenticate. Only "nothing answered at all" is a failure.
		r := MyResource{
			ID:     id,
			Name:   name,
			Kind:   resourceKindWeb,
			From:   "Your browser",
			To:     host,
			Port:   port,
			How:    reachBrowser,
			Status: statusReady,
			Action: MyResourceAction{Label: "Open", Kind: "open_url", URL: fromURL},
			Note:   "Opens in this browser. Nothing to install.",
		}
		switch {
		case host != "" && !s.hostResolves(host):
			r.Status = statusNeedsSetup
			r.Action = MyResourceAction{Label: "Report a problem", Kind: "request", Target: id}
			r.Note = "This address is not published yet, so it will not open. Let an administrator know."
		case !s.urlAnswers(fromURL):
			r.Status = statusNeedsSetup
			r.Action = MyResourceAction{Label: "Report a problem", Kind: "request", Target: id}
			r.Note = "This is not responding right now, so it will not open. Let an administrator know."
		}
		out = append(out, r)
	}
	return out
}

// urlAnswers reports whether the published URL responds at all. Any HTTP status
// means the path is live — a 401 or a redirect to a login page is a working
// resource asking the user to sign in, not a broken one. Only a transport-level
// failure (nothing listening, TLS never completes, timeout) marks it unusable.
//
// Certificate validation is skipped deliberately: this is a liveness probe, not
// a trust decision, and internal targets legitimately use private CAs. Results
// are cached briefly so the page stays fast.
func (s *Service) urlAnswers(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	if v, ok := reachCache.Load(rawURL); ok {
		if e, ok := v.(resolveEntry); ok && time.Since(e.at) < reachTTL {
			return e.ok
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), reachTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := reachClient.Do(req)
	ok := err == nil
	if resp != nil {
		resp.Body.Close()
	}
	reachCache.Store(rawURL, resolveEntry{ok: ok, at: time.Now()})
	return ok
}

// hostResolves reports whether a hostname can be resolved. Results are cached
// for a short while so the page stays fast; a lookup failure is treated as
// "not usable yet" rather than an error, because from the user's point of view
// those are the same thing.
func (s *Service) hostResolves(host string) bool {
	if v, ok := resolveCache.Load(host); ok {
		if e, ok := v.(resolveEntry); ok && time.Since(e.at) < resolveTTL {
			return e.ok
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	ok := err == nil && len(addrs) > 0
	resolveCache.Store(host, resolveEntry{ok: ok, at: time.Now()})
	return ok
}

type resolveEntry struct {
	ok bool
	at time.Time
}

var (
	resolveCache sync.Map
	resolveTTL   = 60 * time.Second

	// reachCache memoizes the liveness probe. Kept short so a resource coming
	// back up is reflected quickly, long enough that a page load does not
	// re-probe every row.
	reachCache   sync.Map
	reachTTL     = 60 * time.Second
	reachTimeout = 4 * time.Second

	// reachClient probes internal targets. It does not follow redirects (a 302
	// already proves liveness) and does not verify certificates, because this is
	// a liveness check rather than a trust decision and internal hosts commonly
	// use a private CA.
	reachClient = &http.Client{
		Timeout: reachTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // liveness probe only; no data is read from the response
			DisableKeepAlives: true,
		},
	}
)

// brokeredResources lists systems (RDP/SSH/database) the caller holds a grant
// for. They are rendered in the browser by the session broker, so the user still
// installs nothing. Entries requiring approval are surfaced with a request
// action instead of being hidden, so the user can act on them.
func (s *Service) brokeredResources(ctx context.Context, orgID, userID string, c *gin.Context) []MyResource {
	// Reuse the same grant predicate the PAM list uses, so this page can never
	// show more than the entry list itself would.
	roles := pamCallerRoles(c)
	if roles == nil {
		roles = []string{}
	}
	query := `
		SELECT e.id, e.name, e.entry_type, COALESCE(e.hostname,''), COALESCE(e.port,0),
		       e.require_approval
		  FROM pam_entries e
		 WHERE e.org_id = $1`
	args := []interface{}{orgID, userID, roles}
	if !s.pamCallerIsAdmin(c) {
		query += `
		   AND EXISTS (SELECT 1 FROM pam_entry_grants g
		                WHERE g.entry_id = e.id
		                  AND (g.expires_at IS NULL OR g.expires_at > NOW())
		                  AND ((g.principal_type = 'user' AND g.principal_id = $2)
		                    OR (g.principal_type = 'role' AND g.principal_id = ANY($3))))`
	}
	query += ` ORDER BY e.name`

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("my-resources: brokered query failed", zap.Error(err))
		return nil
	}
	defer rows.Close()

	out := []MyResource{}
	for rows.Next() {
		var id, name, entryType, hostname string
		var port int
		var requireApproval bool
		if err := rows.Scan(&id, &name, &entryType, &hostname, &port, &requireApproval); err != nil {
			s.logger.Warn("my-resources: brokered scan failed", zap.Error(err))
			continue
		}

		r := MyResource{
			ID:   id,
			Name: name,
			Kind: kindForEntryType(entryType),
			From: "Your browser",
			To:   hostname,
			Port: port,
			How:  reachBroker,
			Note: "Opens in this browser through the secure session broker.",
		}
		if requireApproval {
			r.Status = statusRequestAccess
			r.Action = MyResourceAction{Label: "Request access", Kind: "request", Target: id}
			r.Note = "Needs approval before the session can start."
		} else {
			r.Status = statusReady
			r.Action = MyResourceAction{Label: "Connect", Kind: "broker_connect", Target: id}
		}
		out = append(out, r)
	}
	return out
}

// kindForEntryType maps an internal PAM entry type to a user-facing kind.
func kindForEntryType(entryType string) string {
	switch strings.ToLower(entryType) {
	case "rdp", "windows_app_host", "vnc":
		return resourceKindDesktop
	case "ssh":
		return resourceKindSSH
	case "database", "db", "postgres", "mysql", "mssql":
		return resourceKindDB
	default:
		return resourceKindDesktop
	}
}

// rolesAllow reports whether the caller may use a route. An empty restriction
// means "everyone in the organization", matching the proxy's own rule.
func rolesAllow(allowedRolesJSON string, callerRoles []string) bool {
	allowed := parseJSONStringArray(allowedRolesJSON)
	if len(allowed) == 0 {
		return true
	}
	for _, want := range allowed {
		for _, have := range callerRoles {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

// parseJSONStringArray reads a jsonb text array like `["admin","ops"]` without
// pulling in a decoder for such a small shape.
func parseJSONStringArray(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "[]" || s == "null" {
		return nil
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hostPortFromURL extracts the host and port a user would recognise from a
// route's public URL, defaulting to the scheme's port.
func hostPortFromURL(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, 0
	}
	host := u.Hostname()
	port := 0
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	} else if u.Scheme == "https" {
		port = 443
	} else if u.Scheme == "http" {
		port = 80
	}
	return host, port
}
