package access

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// HostingMode constants determine how an access-proxy route is terminated.
const (
	// HostingModeIdentity — access-proxy is the terminator; it injects identity
	// headers before forwarding to the upstream.
	HostingModeIdentity = "identity"
	// HostingModeDirect — the edge router hosts the service via a fixed host.v1
	// config pointing at the route's to_url. Auto-selected for BrowZer routes
	// whose upstream is local/HTTP (the BrowZer WASM path can reach it directly);
	// external HTTPS upstreams auto-select hop instead (see EffectiveMode).
	HostingModeDirect = "direct"
	// HostingModeHop — the edge router hosts a per-app service whose host.v1
	// points at the shared TLS hop nginx; the hop SNI-demuxes and rewrites the
	// HTTP Host for Host-routed/https upstreams the BrowZer runtime cannot
	// address directly (it sends a fixed "Host: unknown"). REQUIRES an https
	// upstream: SNI demux only works when the runtime does WASM-TLS, so a
	// non-https hop route is misconfigured and is skipped (with a warning).
	HostingModeHop = "hop"
)

// isRouterHosted reports whether the edge router hosts the service itself via a
// host.v1 config (direct and hop). The two differ only in the host.v1 target:
// direct points at the route's to_url, hop points at the shared hop nginx addr.
func isRouterHosted(mode string) bool {
	return mode == HostingModeDirect || mode == HostingModeHop
}

// DesiredRoute is the reconciler's view of a ziti-enabled proxy_route.
type DesiredRoute struct {
	ServiceName    string
	ToURL          string
	HostingMode    string
	BrowZerEnabled bool
	// OrgID is the owning org of the route, used for per-org Dial policies when
	// ZitiPerOrgAttributes is on (Wave A2). Empty for install-wide/default-org routes.
	OrgID string
	// HopPort is the per-app hop listen port (base + sorted-index, via
	// assignHopPorts). For hop routes the host.v1 target is hopHost:HopPort so the
	// hop demuxes by PORT (the runtime sends no SNI). Stamped in reconcileOnce.
	HopPort int
}

// EffectiveMode resolves the hosting mode. identity mode is never valid for a
// BrowZer route (its dial policy would grant #access-proxy-clients, not
// #browzer-users → BrowZer error 1003), so a BrowZer route is always promoted
// to a router-hosted mode:
//   - an explicit "hop" or "direct" hosting_mode is honored as-is;
//   - otherwise the mode is auto-selected from the upstream — external HTTPS
//     upstreams need hop (Host rewrite + relaxed upstream TLS, because the
//     BrowZer WASM path sends "Host: unknown" with no SNI), local/HTTP
//     upstreams use direct.
//
// Non-BrowZer routes honor an explicit "direct" and otherwise default to
// "identity" (the access-proxy hosts the terminator).
func (r DesiredRoute) EffectiveMode() string {
	return effectiveHostingMode(r.HostingMode, r.BrowZerEnabled, r.ToURL)
}

// effectiveHostingMode resolves a route's stored hosting_mode to the mode that
// is actually applied. It MUST be the single source of truth used by both the
// Ziti reconciler (host.v1 target, bind/dial roles, hop-port assignment) AND the
// bootstrapper/hop/vhost/APISIX config generators — otherwise a route stored as
// `identity` but auto-promoted to hop gets a hop host.v1 from the reconciler but
// an https (no hop block) target from the generators, so the runtime does TLS to
// a plain-HTTP hop port → BrowZer 1010, and hop-port indices diverge.
func effectiveHostingMode(rawMode string, browzerEnabled bool, toURL string) string {
	if rawMode == HostingModeHop {
		return HostingModeHop
	}
	if browzerEnabled {
		if rawMode == HostingModeDirect {
			return HostingModeDirect
		}
		if needsHopUpstream(toURL) {
			return HostingModeHop
		}
		return HostingModeDirect
	}
	if rawMode == HostingModeDirect {
		return HostingModeDirect
	}
	return HostingModeIdentity
}

// needsHopUpstream reports whether a BrowZer upstream requires hop hosting: an
// https upstream on a non-loopback host. Such upstreams are typically
// Host-routed and/or present a certificate the direct WASM-TLS path can't
// satisfy (it sends "Host: unknown" with no SNI), so the hop must rewrite the
// Host and relax upstream TLS verification. Local or HTTP upstreams use direct.
func needsHopUpstream(toURL string) bool {
	u, err := url.Parse(toURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	return !isLoopbackHost(u.Hostname())
}

// isLoopbackHost reports whether host is empty, "localhost", or a loopback IP.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ParseHopAddr splits a "host:port" hop address, defaulting the port to 8095
// when absent/unparseable, so the reconciler's host.v1 target and the hop
// nginx listen port are always derived identically.
func ParseHopAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 8095
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p == 0 {
		return host, 8095
	}
	return host, p
}

// ZitiReconciler converges Ziti to the DB's desired state. One worker, a
// coalescing trigger channel, and a periodic safety-net tick — so concurrent
// mutation races cannot happen (the reconciler is the only mutator of Ziti).
type ZitiReconciler struct {
	db       *database.PostgresDB
	logger   *zap.Logger
	provider *ZitiProvider // source of the live ZitiManager
	period   time.Duration
	hopAddr  string // host:basePort of the shared hop nginx (parsed into hopHost + base)
	hopHost  string // host portion of hopAddr; cached by reconcileOnce for ensureService

	trigger  chan struct{}         // coalescing: buffered size 1
	runOnce  func(context.Context) // overridable in tests; defaults to reconcileOnce
	mu       sync.Mutex            // serializes runs
	statusMu sync.Mutex            // protects status map
	status   map[string]string     // serviceName -> "synced" | "error: ..."

	// darkServices, when non-empty, models OpenIDX's OWN surfaces as tier'd dark
	// Ziti services (dark-platform spec). Empty by default → no behavior change;
	// access-service main populates it only when a DARK_MODE tier is enabled.
	darkServices []darkService

	// perOrgAttributes mirrors config.ZitiPerOrgAttributes. When true the
	// reconciler additionally emits an org-scoped Dial policy per route so a
	// tenant's users (who carry org-<id>-<group> role attributes, see
	// ziti_user_sync.orgScopedAttr) can only dial their OWN org's services — the
	// overlay half of per-org scoping (Wave A2). Off by default: the install-wide
	// tier dial policies are unchanged, so single-tenant installs behave exactly
	// as before.
	perOrgAttributes bool
}

// darkService is one OpenIDX surface to make overlay-only: a Ziti service named
// `name`, host.v1-hosted at loopback `upstream` (host:port), dialable only by
// the tier attribute `tierAttr` ("enrolled-users" = Tier 1, "device-trusted" =
// Tier 2).
type darkService struct {
	name     string
	upstream string // "127.0.0.1:<port>"
	tierAttr string // "enrolled-users" | "device-trusted"
}

// defaultDarkServices is the canonical tier map for OpenIDX's own surfaces:
// management/data planes are Tier 2 (device-trusted); user self-service and the
// console shell are Tier 1 (any enrolled user). None of these are Tier-0 (the
// enroll/oauth/jwks bootstrap surface must never be darked).
func defaultDarkServices() []darkService {
	return []darkService{
		{"openidx-admin-api", "127.0.0.1:8005", "device-trusted"},
		{"openidx-governance", "127.0.0.1:8002", "device-trusted"},
		{"openidx-audit", "127.0.0.1:8004", "device-trusted"},
		{"openidx-provisioning", "127.0.0.1:8003", "device-trusted"},
		{"openidx-scim", "127.0.0.1:8003", "device-trusted"},
		{"openidx-access", "127.0.0.1:8007", "device-trusted"},
		{"openidx-identity-selfservice", "127.0.0.1:8001", "enrolled-users"},
		{"openidx-console", "127.0.0.1:8443", "enrolled-users"},
	}
}

// SetDarkServices installs the dark-service set (called by access-service main
// only when a DARK_MODE tier is enabled). Nil/empty disables the feature.
func (rec *ZitiReconciler) SetDarkServices(ds []darkService) { rec.darkServices = ds }

// EnableDefaultDarkServices installs the canonical OpenIDX tier map so the
// reconcile loop begins modeling OpenIDX's own surfaces as tier'd overlay-only
// services. Exported entry point for access-service main (darkService is
// internal). Idempotent; no-op semantics until the loop next ticks.
func (rec *ZitiReconciler) EnableDefaultDarkServices() {
	rec.darkServices = defaultDarkServices()
}

// reconcileDarkServices ensures each configured dark surface has a Ziti service
// (host.v1 → its loopback upstream) plus a tier dial policy. It is the identity-
// side + network-side gate that makes an OpenIDX surface overlay-only. Runs only
// when darkServices is non-empty (inert by default). Failures are logged and do
// not abort the pass (convergent — retried next tick).
func (rec *ZitiReconciler) reconcileDarkServices(ctx context.Context, zm *ZitiManager) {
	for _, d := range rec.darkServices {
		host, portStr, ok := strings.Cut(d.upstream, ":")
		if !ok {
			rec.logger.Warn("dark service has malformed upstream", zap.String("svc", d.name), zap.String("upstream", d.upstream))
			continue
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			rec.logger.Warn("dark service has non-numeric port", zap.String("svc", d.name), zap.String("upstream", d.upstream))
			continue
		}
		// Ensure the service + a fixed host.v1 config pointing at the loopback
		// upstream (the router hosts it; the dark service has no public route).
		if existing, _ := zm.GetServiceByName(d.name); existing == nil {
			cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, d.name+"-host", host, port)
			if cerr != nil {
				rec.logger.Warn("dark service host.v1 create failed", zap.String("svc", d.name), zap.Error(cerr))
				continue
			}
			if _, err := zm.createServiceWithConfigID(ctx, d.name, []string{d.name}, cfgID); err != nil {
				rec.logger.Warn("dark service create failed", zap.String("svc", d.name), zap.Error(err))
				continue
			}
		}
		// Bind goes to the routers (host.v1 hosting); Dial to the tier attribute.
		if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
			rec.logger.Warn("dark service: tag routers failed", zap.String("svc", d.name), zap.Error(err))
		}
		if _, err := zm.EnsureServicePolicy(ctx, "openidx-bind-"+d.name, "Bind",
			[]string{"#" + d.name}, []string{"#ziti-routers"}); err != nil {
			rec.logger.Warn("dark bind policy converge failed", zap.String("svc", d.name), zap.Error(err))
		}
		_ = rec.ensureTierDialPolicy(ctx, zm, d.name, d.tierAttr)
		if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+d.name,
			[]string{"#" + d.name}, []string{"#all"}); err != nil {
			rec.logger.Debug("dark serp (may already exist)", zap.String("svc", d.name), zap.Error(err))
		}
	}
}

// NewZitiReconciler creates a ZitiReconciler with a 30-second safety-net
// period. Call Start(ctx) to begin the reconcile loop.
func NewZitiReconciler(db *database.PostgresDB, logger *zap.Logger, provider *ZitiProvider, hopAddr string) *ZitiReconciler {
	rec := &ZitiReconciler{
		db:       db,
		logger:   logger.With(zap.String("component", "ziti-reconciler")),
		provider: provider,
		period:   30 * time.Second,
		hopAddr:  hopAddr,
		trigger:  make(chan struct{}, 1),
		status:   make(map[string]string),
	}
	rec.runOnce = rec.reconcileOnce
	return rec
}

// SetPerOrgAttributes toggles the per-org overlay-scoping behavior (Wave A2).
// When enabled, reconcileRoute also emits an org-scoped Dial policy so a tenant's
// users can only dial their own org's services. Off by default; access-service
// main enables it from config.ZitiPerOrgAttributes. Returns the receiver for
// chaining.
func (rec *ZitiReconciler) SetPerOrgAttributes(on bool) *ZitiReconciler {
	rec.perOrgAttributes = on
	return rec
}

// Enqueue requests a reconcile; coalesces (non-blocking send to a size-1 chan).
func (rec *ZitiReconciler) Enqueue() {
	select {
	case rec.trigger <- struct{}{}:
	default:
	}
}

// Start launches the single worker: drains triggers and ticks periodically.
func (rec *ZitiReconciler) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(rec.period)
		defer ticker.Stop()
		rec.runLocked(ctx) // initial reconcile
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rec.runLocked(ctx)
			case <-rec.trigger:
				rec.runLocked(ctx)
			}
		}
	}()
}

func (rec *ZitiReconciler) runLocked(ctx context.Context) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.runOnce(ctx)
}

// loadDesiredRoutes reads all ziti-enabled routes from the DB (install-wide; RLS bypassed).
func (rec *ZitiReconciler) loadDesiredRoutes(ctx context.Context) ([]DesiredRoute, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	rows, err := rec.db.Pool.Query(ctx,
		//orgscope:ignore install-wide Ziti reconcile; keyed by globally-unique ziti_service_name across all orgs
		`SELECT ziti_service_name, to_url, COALESCE(hosting_mode,'identity'), COALESCE(browzer_enabled,false), COALESCE(org_id::text,'')
		 FROM proxy_routes
		 WHERE ziti_enabled = true AND enabled = true
		   AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DesiredRoute
	for rows.Next() {
		var d DesiredRoute
		if err := rows.Scan(&d.ServiceName, &d.ToURL, &d.HostingMode, &d.BrowZerEnabled, &d.OrgID); err != nil {
			rec.logger.Warn("reconciler: scan route failed", zap.Error(err))
			continue
		}
		// identity mode is never valid for a BrowZer route — the BrowZer runtime
		// dials as #browzer-users, which identity-mode policies don't grant
		// (BrowZer error 1003). EffectiveMode auto-corrects it to direct; warn so
		// operators see the divergence and pick hop explicitly for external/HTTPS
		// upstreams (direct does end-to-end WASM TLS the browser must trust).
		if d.BrowZerEnabled && d.HostingMode == HostingModeIdentity {
			rec.logger.Warn("BrowZer route stored as identity mode; auto-correcting to router-hosted (direct) — set hosting_mode=hop for external/HTTPS upstreams",
				zap.String("svc", d.ServiceName),
				zap.String("effective_mode", d.EffectiveMode()))
		}
		out = append(out, d)
	}
	// Surface mid-iteration errors (e.g. a dropped connection) so a partial read
	// isn't mistaken for the full desired set.
	return out, rows.Err()
}

// hostV1Target returns the address/port the route's host.v1 config should point
// at. Direct mode targets the route's to_url; hop mode targets the shared hop
// nginx at the route's per-app port (stamped in reconcileOnce via assignHopPorts),
// falling back to the base hop addr if HopPort wasn't stamped.
func (rec *ZitiReconciler) hostV1Target(d DesiredRoute) (string, int) {
	if d.EffectiveMode() == HostingModeHop {
		h, base := ParseHopAddr(rec.hopAddr)
		if rec.hopHost != "" {
			h = rec.hopHost
		}
		p := d.HopPort
		if p == 0 {
			p = base
		}
		return h, p
	}
	return parseHostPort(d.ToURL)
}

// ensureService makes sure the Ziti service exists with its role attribute.
// Idempotent: looks up by name, creates the service via CreateService if absent
// (controller-only — the reconciler must NOT write back to proxy_routes/ziti_services;
// the DB is the source of truth), tolerating a create race, then ensures the
// service-name role attribute is set.
func (rec *ZitiReconciler) ensureService(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	if existing, _ := zm.GetServiceByName(d.ServiceName); existing != nil {
		// Converge the host.v1 config of an EXISTING router-hosted service too: the
		// per-app hop port reshuffles when the hop-route set changes (sorted index),
		// so a previously-created config can drift. CreateHostV1ConfigFixed patches
		// the target in place (same config id, still attached), so the route
		// self-heals without manual deletion.
		if isRouterHosted(d.EffectiveMode()) {
			host, port := rec.hostV1Target(d)
			cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, d.ServiceName+"-host", host, port)
			if cerr != nil {
				return cerr
			}
			// Attach the config to the service if it isn't already — a service
			// created elsewhere (e.g. the feature-manager's SDK-mode toggle) exists
			// without it, so the router can't host it (→ 502 via a stale SDK terminator).
			if aerr := zm.EnsureServiceConfig(ctx, existing.ID, cfgID); aerr != nil {
				return aerr
			}
		}
		return rec.ensureServiceAttr(ctx, zm, existing.ID, d.ServiceName)
	}
	// Service does not exist; create it. Use the minimal management-API path
	// (controller-only — the reconciler must NOT write back to proxy_routes/
	// ziti_services; the DB is the source of truth). Direct mode attaches a fixed
	// host.v1 config so the edge router hosts the service itself; identity mode
	// uses a bare service that the access-proxy terminates via SDK Listen.
	var err error
	switch {
	case isRouterHosted(d.EffectiveMode()):
		host, port := rec.hostV1Target(d)
		cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, d.ServiceName+"-host", host, port)
		if cerr != nil {
			return cerr
		}
		_, err = zm.createServiceWithConfigID(ctx, d.ServiceName, []string{d.ServiceName}, cfgID)
	default:
		_, err = zm.CreateService(ctx, d.ServiceName, []string{d.ServiceName})
	}
	if err != nil {
		// Tolerate a race where another actor created it between our GET and POST.
		if again, _ := zm.GetServiceByName(d.ServiceName); again == nil {
			return err
		}
	}
	svc, gerr := zm.GetServiceByName(d.ServiceName)
	if gerr != nil || svc == nil {
		return gerr
	}
	return rec.ensureServiceAttr(ctx, zm, svc.ID, d.ServiceName)
}

// ensureServiceAttr ensures the service carries its name as a role attribute.
func (rec *ZitiReconciler) ensureServiceAttr(ctx context.Context, zm *ZitiManager, svcID, name string) error {
	attrs, err := zm.GetServiceRoleAttributes(ctx, svcID)
	if err != nil {
		return err
	}
	for _, a := range attrs {
		if a == name {
			return nil
		}
	}
	return zm.PatchServiceRoleAttributes(ctx, svcID, append(attrs, name))
}

// ensurePolicies creates bind/dial/service-edge-router policies for identity mode.
// CreateServicePolicy returns an error (often a 400) when the policy already exists;
// that is the idempotent no-op path, so we tolerate and debug-log those errors.
// ensurePolicies ensures the bind/dial/service-edge-router policies for the
// route. Phase 1 = identity mode: Bind is granted to #access-proxy-clients (the
// access-proxy hosts the terminator). Phase 2 (direct mode) must instead grant
// Bind to the edge-router identities so the router hosts via host.v1 — do NOT
// reuse this identity-mode policy set for direct routes.
func (rec *ZitiReconciler) ensurePolicies(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	svcRole := "#" + d.ServiceName
	bindIdentity := "#access-proxy-clients"
	dialIdentity := "#access-proxy-clients"
	if isRouterHosted(d.EffectiveMode()) {
		// The router hosts the service via host.v1, so Bind goes to the routers;
		// BrowZer clients (synced users) dial via #browzer-users.
		if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
			// A persistent failure here means the #ziti-routers Bind matches no
			// router, so the service silently has no host — warn, don't bury it.
			rec.logger.Warn("failed to tag routers with #ziti-routers", zap.Error(err))
		}
		bindIdentity = "#ziti-routers"
		dialIdentity = "#browzer-users"
	}
	// Use EnsureServicePolicy (upsert) rather than CreateServicePolicy so a
	// hosting-mode transition self-heals: a route Ziti-provisioned in identity
	// mode and later flipped to router-hosted (e.g. BrowZer enabled afterwards)
	// has its stale #access-proxy-clients Bind/Dial corrected to
	// #ziti-routers/#browzer-users. Plain create-if-exists left them stale,
	// surfacing as BrowZer error 1003 (service not dialable by #browzer-users).
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-bind-"+d.ServiceName, "Bind",
		[]string{svcRole}, []string{bindIdentity}); err != nil {
		rec.logger.Warn("bind policy converge failed", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, []string{dialIdentity}); err != nil {
		rec.logger.Warn("dial policy converge failed", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+d.ServiceName,
		[]string{svcRole}, []string{"#all"}); err != nil {
		rec.logger.Debug("serp (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}

	// Per-org overlay scoping (Wave A2): when ZitiPerOrgAttributes is on and the
	// route belongs to a specific org, additionally emit a Dial policy that only
	// grants identities carrying this org's role attribute (#org-<id>). Users are
	// tagged with org-<id>-<group> attributes by ziti_user_sync.orgScopedAttr, and
	// the reconciler tags every synced identity of an org with the bare #org-<id>
	// marker, so a tenant can dial only its OWN org's services. Inert when the flag
	// is off — the install-wide Dial policy above is untouched.
	if rec.perOrgAttributes && d.OrgID != "" {
		orgAttr := "#" + orgMarkerAttr(d.OrgID)
		if _, err := zm.EnsureServicePolicy(ctx, "openidx-orgdial-"+d.ServiceName, "Dial",
			[]string{svcRole}, []string{orgAttr}); err != nil {
			rec.logger.Warn("per-org dial policy converge failed",
				zap.String("svc", d.ServiceName), zap.String("org", d.OrgID), zap.Error(err))
		}
	}
	return nil
}

// orgMarkerAttr is the bare per-org role attribute (org-<sanitized-id>) that
// marks every identity belonging to an org, so per-org Dial policies can grant
// "this org's members" without enumerating groups. Mirrors the org- prefix used
// by orgScopedAttr in ziti_user_sync.go.
func orgMarkerAttr(orgID string) string {
	return "org-" + sanitizeAttr(orgID)
}

// ensureTierDialPolicy upserts a Dial policy granting the tier identity role the
// right to dial #<serviceName>. tierAttr is "enrolled-users" (Tier 1: any
// enrolled OpenIDX user) or "device-trusted" (Tier 2: trusted device only) — see
// the dark-platform spec. This is the identity-side gate for making OpenIDX's own
// surfaces overlay-only; Bind is left to the existing #ziti-routers policy. It
// uses EnsureServicePolicy (upsert), so it is idempotent/convergent like the
// #browzer-users dial policy it mirrors.
func (rec *ZitiReconciler) ensureTierDialPolicy(ctx context.Context, zm *ZitiManager, serviceName, tierAttr string) error {
	svcRole := "#" + serviceName
	_, err := zm.EnsureServicePolicy(ctx, serviceName+"-dial-"+tierAttr, "Dial",
		[]string{svcRole}, []string{"#" + tierAttr})
	if err != nil {
		rec.logger.Warn("tier dial policy converge failed",
			zap.String("svc", serviceName), zap.String("tier", tierAttr), zap.Error(err))
	}
	return err
}

// ensureHosting starts hosting for the route. identity mode uses SDK Listen
// (HostService, idempotent). direct mode relies on the host.v1 config created
// in ensureService and the router Bind created in ensurePolicies, so there is
// nothing further to do here — the edge router hosts the service itself.
func (rec *ZitiReconciler) ensureHosting(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	switch {
	case d.EffectiveMode() == HostingModeIdentity:
		host, port := parseHostPort(d.ToURL)
		return zm.HostService(d.ServiceName, host, port)
	case isRouterHosted(d.EffectiveMode()):
		return nil // router hosts via host.v1; see ensureService/ensurePolicies
	default:
		return fmt.Errorf("unknown hosting mode for service %s", d.ServiceName)
	}
}

func (rec *ZitiReconciler) setStatus(svc, s string) {
	rec.statusMu.Lock()
	defer rec.statusMu.Unlock()
	rec.status[svc] = s
}

// StatusSnapshot returns a copy of the per-service converge state
// (serviceName -> "synced" | "error: ..."), for the setup/status API.
func (rec *ZitiReconciler) StatusSnapshot() map[string]string {
	rec.statusMu.Lock()
	defer rec.statusMu.Unlock()
	out := make(map[string]string, len(rec.status))
	for k, v := range rec.status {
		out[k] = v
	}
	return out
}

// reconcileRoute converges one route, error-isolated, recording per-object status.
func (rec *ZitiReconciler) reconcileRoute(ctx context.Context, zm *ZitiManager, d DesiredRoute) {
	steps := []func(context.Context, *ZitiManager, DesiredRoute) error{
		rec.ensureService, rec.ensurePolicies, rec.ensureHosting,
	}
	for _, step := range steps {
		if err := step(ctx, zm, d); err != nil {
			rec.setStatus(d.ServiceName, "error: "+err.Error())
			rec.logger.Warn("reconcile route failed", zap.String("svc", d.ServiceName), zap.Error(err))
			return
		}
	}
	rec.setStatus(d.ServiceName, "synced")
}

// reconcileOnce loads desired routes and converges each. No live manager → skip.
func (rec *ZitiReconciler) reconcileOnce(ctx context.Context) {
	zm := rec.provider.Get()
	if zm == nil || !zm.IsInitialized() {
		rec.logger.Debug("reconcile skipped: no live Ziti manager")
		return
	}
	desired, err := rec.loadDesiredRoutes(ctx)
	if err != nil {
		rec.logger.Warn("reconcile: load desired failed", zap.Error(err))
		return
	}
	// Stamp each hop route's per-app listen port (base + sorted-index). The hop
	// nginx config uses the SAME assignHopPorts over the same service names, so a
	// route's host.v1 port and the hop's listen port are always identical.
	host, base := ParseHopAddr(rec.hopAddr)
	rec.hopHost = host
	var hopNames []string
	for _, d := range desired {
		if d.EffectiveMode() == HostingModeHop {
			hopNames = append(hopNames, d.ServiceName)
		}
	}
	ports := assignHopPorts(hopNames, base)
	for i := range desired {
		if desired[i].EffectiveMode() == HostingModeHop {
			desired[i].HopPort = ports[desired[i].ServiceName]
		}
	}
	for _, d := range desired {
		rec.reconcileRoute(ctx, zm, d)
	}
	// Dark-platform: converge OpenIDX's own surfaces as tier'd overlay-only
	// services. No-op unless a DARK_MODE tier populated darkServices.
	if len(rec.darkServices) > 0 {
		rec.reconcileDarkServices(ctx, zm)
	}
	// Remote-support signaling over Ziti: ensure the access-service (broker) is
	// reachable by enrolled agent identities over the overlay, independent of
	// dark mode. Gated by REMOTE_SUPPORT_OVER_ZITI so it's inert unless opted in.
	if remoteSupportOverZitiEnabled() {
		rec.reconcileRemoteSupportZiti(ctx, zm)
	}
	rec.logger.Info("reconcile pass complete", zap.Int("routes", len(desired)))
}

// remoteSupportZitiService is the Ziti service name agents dial to reach the
// access-service signaling broker over the overlay.
const remoteSupportZitiService = "openidx-access"

// remoteSupportOverZitiEnabled reports whether remote-support signaling should
// be reachable over the Ziti overlay (device leg). Opt-in so deployments that
// don't want it keep the plain-WSS behavior.
func remoteSupportOverZitiEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("REMOTE_SUPPORT_OVER_ZITI"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// reconcileRemoteSupportZiti ensures the access-service signaling broker is an
// overlay service (host.v1 → its loopback 127.0.0.1:8007) that enrolled agent
// identities (role "openidx-agent") may Dial. This lets the device dial the
// remote-support signaling WebSocket over Ziti with no public port. Admin-side
// signaling still terminates at the edge (Option B); only the device leg is
// zero-trust here. Idempotent; failures are logged and retried next pass.
func (rec *ZitiReconciler) reconcileRemoteSupportZiti(ctx context.Context, zm *ZitiManager) {
	const svc = remoteSupportZitiService
	if existing, _ := zm.GetServiceByName(svc); existing == nil {
		cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, svc+"-host", "127.0.0.1", 8007)
		if cerr != nil {
			rec.logger.Warn("remote-support ziti: host.v1 create failed", zap.Error(cerr))
			return
		}
		if _, err := zm.createServiceWithConfigID(ctx, svc, []string{svc}, cfgID); err != nil {
			rec.logger.Warn("remote-support ziti: service create failed", zap.Error(err))
			return
		}
	}
	// Routers host the service (Bind); agent identities may Dial it.
	if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
		rec.logger.Warn("remote-support ziti: tag routers failed", zap.Error(err))
	}
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-bind-"+svc, "Bind",
		[]string{"#" + svc}, []string{"#ziti-routers"}); err != nil {
		rec.logger.Warn("remote-support ziti: bind policy failed", zap.Error(err))
	}
	if _, err := zm.EnsureServicePolicy(ctx, svc+"-dial-openidx-agent", "Dial",
		[]string{"#" + svc}, []string{"#openidx-agent"}); err != nil {
		rec.logger.Warn("remote-support ziti: agent dial policy failed", zap.Error(err))
	}
	// Agent identities need an edge-router-policy or they get zero routers and
	// every dial fails with NO_EDGE_ROUTERS_AVAILABLE. Grant #openidx-agent all
	// routers (the service-edge-router-policy below already scopes the service).
	if err := zm.EnsureEdgeRouterPolicy(ctx, "openidx-agent-all-routers",
		[]string{"#all"}, []string{"#openidx-agent"}); err != nil {
		rec.logger.Warn("remote-support ziti: agent edge-router policy failed", zap.Error(err))
	}
	if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+svc,
		[]string{"#" + svc}, []string{"#all"}); err != nil {
		rec.logger.Debug("remote-support ziti: serp (may exist)", zap.Error(err))
	}
}
