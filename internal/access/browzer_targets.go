// Package access provides BrowZer bootstrapper target configuration management.
// The BrowZer bootstrapper reads targets from a config.json file (via nconf).
// This file generates that config from the database whenever BrowZer targets change.
// It also generates the nginx router config for path-based BrowZer routing.
package access

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	// BrowZerRouterServiceName is the Ziti service name for the path-based router
	BrowZerRouterServiceName = "browzer-router-zt"
	// BrowZerRouterHost is the Docker service name for the router
	BrowZerRouterHost = "browzer-router"
	// BrowZerRouterPort is the port the router listens on
	BrowZerRouterPort = 80
	// DefaultBrowZerDomain is the default domain for path-based BrowZer routing
	DefaultBrowZerDomain = "browzer.localtest.me"
)

// BrowZerTarget represents a single target entry for the bootstrapper
type BrowZerTarget struct {
	VHost        string `json:"vhost"`
	Service      string `json:"service"`
	Path         string `json:"path"`
	Scheme       string `json:"scheme"`
	IDPIssuerURL string `json:"idp_issuer_base_url"`
	IDPClientID  string `json:"idp_client_id"`
}

// BrowZerTargetArray is the top-level structure the bootstrapper expects
type BrowZerTargetArray struct {
	TargetArray []BrowZerTarget `json:"targetArray"`
}

// BrowZerTargetManager handles generation and writing of bootstrapper targets and router config
type BrowZerTargetManager struct {
	db               *database.PostgresDB
	logger           *zap.Logger
	targetsPath      string
	routerConfigPath string
	certsPath        string
	hopConfigPath    string
	hopCertPath      string
	hopKeyPath       string
	hopPort          int
	domain           string
	dnsResolvers     string // nginx resolver addresses (auto-detected from /etc/resolv.conf)
	// Public per-app vhost generation (front nginx). vhostConfigPath is where the
	// generated server blocks are written; bootstrapperPass is the upstream they
	// forward to; vhostSSLCert/Key are the cert paths as seen by the front nginx;
	// oidcCallbacks are the form_post callback suffixes routed to the hop.
	vhostConfigPath  string
	bootstrapperPass string
	vhostSSLCert     string
	vhostSSLKey      string
	oidcCallbacks    []string
	apisixReconciler *APISIXReconciler
	mu               sync.Mutex
}

// NewBrowZerTargetManager creates a new target manager
func NewBrowZerTargetManager(db *database.PostgresDB, logger *zap.Logger, targetsPath string) *BrowZerTargetManager {
	tm := &BrowZerTargetManager{
		db:          db,
		logger:      logger.With(zap.String("component", "browzer_targets")),
		targetsPath: targetsPath,
	}
	tm.dnsResolvers = tm.detectDNSResolvers()
	return tm
}

// detectDNSResolvers reads /etc/resolv.conf to build the nginx resolver string.
// Docker's embedded DNS (127.0.0.11) round-robins queries to external servers,
// so if a public DNS (e.g. 8.8.8.8) returns NXDOMAIN for an internal domain before
// the corporate DNS responds, resolution fails. To fix this, we extract the external
// DNS servers and prefer private/corporate ones that can resolve both internal and
// external domains. If none are found, fall back to 127.0.0.11.
func (tm *BrowZerTargetManager) detectDNSResolvers() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "127.0.0.11"
	}
	defer f.Close()

	var allServers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Docker adds: # ExtServers: [8.8.8.8 8.8.4.4 10.0.0.53]
		if strings.Contains(line, "ExtServers:") {
			start := strings.Index(line, "[")
			end := strings.Index(line, "]")
			if start >= 0 && end > start {
				allServers = strings.Fields(line[start+1 : end])
			}
		}
	}

	// Filter to private/corporate DNS servers (RFC 1918 ranges).
	// These can resolve both internal and external domains, unlike public DNS
	// which returns NXDOMAIN for internal corporate domains.
	var privateServers []string
	for _, s := range allServers {
		if isPrivateIP(s) {
			privateServers = append(privateServers, s)
		}
	}

	var result string
	if len(privateServers) > 0 {
		result = strings.Join(privateServers, " ")
	} else if len(allServers) > 0 {
		// No private servers found — use all (probably no internal domains)
		result = "127.0.0.11 " + strings.Join(allServers, " ")
	} else {
		result = "127.0.0.11"
	}

	tm.logger.Info("Detected DNS resolvers for nginx",
		zap.String("resolvers", result),
		zap.Strings("all_ext_servers", allServers),
		zap.Strings("private_servers", privateServers))
	return result
}

// isPrivateIP returns true if the IP is in RFC 1918 private ranges
// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		(strings.HasPrefix(ip, "172.") && len(ip) > 4 && ip[4] == '.' &&
			ip[3] >= '1' && ip[3] <= '3') // 172.16-31.x.x
}

// SetRouterConfigPath sets the path for the nginx router config file
func (tm *BrowZerTargetManager) SetRouterConfigPath(path string) {
	tm.routerConfigPath = path
}

// SetCertsPath sets the path for the shared BrowZer certificates directory
func (tm *BrowZerTargetManager) SetCertsPath(path string) {
	tm.certsPath = path
}

// SetHopConfigPath sets the path for the nginx hop config file
func (tm *BrowZerTargetManager) SetHopConfigPath(path string) {
	tm.hopConfigPath = path
}

// SetVHostConfigPath sets the path for the generated public per-app nginx vhosts.
func (tm *BrowZerTargetManager) SetVHostConfigPath(path string) {
	tm.vhostConfigPath = path
}

// SetBootstrapperPass sets the upstream the public vhosts forward to (the BrowZer
// bootstrapper), e.g. "https://127.0.0.1:8445".
func (tm *BrowZerTargetManager) SetBootstrapperPass(addr string) {
	tm.bootstrapperPass = addr
}

// SetVHostSSL sets the cert/key paths the public vhosts present (as seen by the
// front nginx container).
func (tm *BrowZerTargetManager) SetVHostSSL(certPath, keyPath string) {
	tm.vhostSSLCert = certPath
	tm.vhostSSLKey = keyPath
}

// SetOIDCCallbacks sets the form_post callback path suffixes (e.g. "signin-oidc")
// routed straight to the hop on hop-mode routes, bypassing the bootstrapper.
func (tm *BrowZerTargetManager) SetOIDCCallbacks(suffixes []string) {
	tm.oidcCallbacks = suffixes
}

// SetAPISIXReconciler wires the APISIX route reconciler so config regeneration
// (toggles) also re-pushes the BrowZer routes to APISIX's Admin API.
func (tm *BrowZerTargetManager) SetAPISIXReconciler(r *APISIXReconciler) { tm.apisixReconciler = r }

// SetHopPort sets the TLS port the shared BrowZer hop server listens on
func (tm *BrowZerTargetManager) SetHopPort(port int) {
	tm.hopPort = port
}

// SetHopCert sets the cert/key paths the shared BrowZer hop server presents.
// When either is empty, GenerateBrowZerHopConfig falls back to the certsPath
// defaults (certsPath/tdv-fullchain.pem and certsPath/tdv-key.pem).
func (tm *BrowZerTargetManager) SetHopCert(certPath, keyPath string) {
	tm.hopCertPath = certPath
	tm.hopKeyPath = keyPath
}

// GetCertsPath returns the configured certificates directory path
func (tm *BrowZerTargetManager) GetCertsPath() string {
	return tm.certsPath
}

// GetDomain returns the current BrowZer domain, falling back to DefaultBrowZerDomain
func (tm *BrowZerTargetManager) GetDomain() string {
	if tm.domain != "" {
		return tm.domain
	}
	return DefaultBrowZerDomain
}

// SetDomain sets the BrowZer domain
func (tm *BrowZerTargetManager) SetDomain(domain string) {
	tm.domain = domain
}

// LoadDomainFromDB reads the browzer_domain_config from system_settings and sets the domain
func (tm *BrowZerTargetManager) LoadDomainFromDB(ctx context.Context) error {
	var configJSON []byte
	err := tm.db.Pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'browzer_domain_config'`).Scan(&configJSON)
	if err != nil {
		tm.logger.Debug("No browzer_domain_config in DB, using default domain", zap.Error(err))
		return nil
	}

	var cfg struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("failed to parse browzer_domain_config: %w", err)
	}

	if cfg.Domain != "" {
		tm.domain = cfg.Domain
		tm.logger.Info("Loaded BrowZer domain from DB", zap.String("domain", cfg.Domain))
	}
	return nil
}

// GetDB returns the database handle
func (tm *BrowZerTargetManager) GetDB() *database.PostgresDB {
	return tm.db
}

// assignHopPorts deterministically maps each hop service name to a listen port,
// base + sorted-index. Both the reconciler (host.v1 target) and the hop nginx
// config (listen port) call this so a route's port is identical on both sides.
func assignHopPorts(serviceNames []string, base int) map[string]int {
	sorted := append([]string(nil), serviceNames...)
	sort.Strings(sorted)
	m := make(map[string]int, len(sorted))
	for i, n := range sorted {
		m[n] = base + i
	}
	return m
}

// browzerRouteInfo holds parsed route information for target/router generation
type browzerRouteInfo struct {
	fromURL     string
	toURL       string
	serviceName string
	hostname    string
	pathPrefix  string
	landingPath string
	hostingMode string
}

// queryBrowZerRoutes fetches all BrowZer-enabled routes from the database
func (tm *BrowZerTargetManager) queryBrowZerRoutes(ctx context.Context) ([]browzerRouteInfo, error) {
	rows, err := tm.db.Pool.Query(ctx,
		//orgscope:ignore install-wide BrowZer bootstrapper config generation; the shared bootstrapper serves every ziti+browzer-enabled route across all orgs into one config file
		`SELECT from_url, to_url, ziti_service_name, COALESCE(landing_path, '/'), COALESCE(hosting_mode, 'identity')
		 FROM proxy_routes
		 WHERE ziti_enabled = true
		   AND browzer_enabled = true
		   AND ziti_service_name IS NOT NULL
		   AND ziti_service_name != ''
		   AND enabled = true
		 ORDER BY priority DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query BrowZer-enabled routes: %w", err)
	}
	defer rows.Close()

	var routes []browzerRouteInfo
	for rows.Next() {
		var fromURL, toURL, serviceName, landingPath, hostingMode string
		if err := rows.Scan(&fromURL, &toURL, &serviceName, &landingPath, &hostingMode); err != nil {
			tm.logger.Warn("Failed to scan route row", zap.Error(err))
			continue
		}

		info := browzerRouteInfo{
			fromURL:     fromURL,
			toURL:       toURL,
			serviceName: serviceName,
			hostname:    fromURL,
			pathPrefix:  "/",
			landingPath: landingPath,
			// Resolve to the EFFECTIVE mode (these are all browzer_enabled), so the
			// generators agree with the Ziti reconciler on hop vs direct — a route
			// stored as identity that auto-promotes to hop must get a hop block,
			// http target scheme, and a hop port aligned with the reconciler's
			// host.v1. Using the raw value caused BrowZer 1010 + port cross-wiring.
			hostingMode: effectiveHostingMode(hostingMode, true, toURL),
		}

		if parsed, err := url.Parse(fromURL); err == nil && parsed.Host != "" {
			info.hostname = parsed.Hostname()
			if parsed.Path != "" && parsed.Path != "/" {
				info.pathPrefix = parsed.Path
			}
		}

		routes = append(routes, info)
	}
	return dedupRoutesByHost(routes, tm.logger), nil
}

// dedupRoutesByHost collapses routes that share a hostname to a single canonical
// route. Ziti/BrowZer is per-host (the bootstrapper demuxes by SNI, APISIX keys
// by host slug, the overlay tunnels the whole host), so multiple routes on one
// host would collide — same APISIX route name (last PUT wins), ambiguous
// same-vhost bootstrapper targets, and divergent hop-port sets. The canonical
// route is the host-root (pathPrefix=="/"); otherwise the first seen, which —
// since queryBrowZerRoutes orders by priority DESC, name — is the highest
// priority. Input order is preserved for the survivors.
func dedupRoutesByHost(routes []browzerRouteInfo, logger *zap.Logger) []browzerRouteInfo {
	type slot struct {
		idx    int
		isRoot bool
	}
	seen := make(map[string]slot, len(routes))
	out := make([]browzerRouteInfo, 0, len(routes))
	for _, r := range routes {
		if r.hostname == "" {
			out = append(out, r)
			continue
		}
		isRoot := r.pathPrefix == "" || r.pathPrefix == "/"
		if s, ok := seen[r.hostname]; ok {
			// Prefer the host-root route over a path-scoped one.
			if isRoot && !s.isRoot {
				out[s.idx] = r
				seen[r.hostname] = slot{idx: s.idx, isRoot: true}
			}
			if logger != nil {
				logger.Warn("collapsing duplicate same-host BrowZer route (Ziti/BrowZer is per-host)",
					zap.String("host", r.hostname), zap.String("dropped_service", r.serviceName))
			}
			continue
		}
		seen[r.hostname] = slot{idx: len(out), isRoot: isRoot}
		out = append(out, r)
	}
	return out
}

// buildBrowZerTargets maps each BrowZer route to a bootstrapper target. Each app
// uses its OWN Ziti service (per-app direct hosting) so the browser dials it
// directly — no shared Host-demux. For direct routes the scheme comes from the
// route's to_url so the runtime's WASM-TLS connects end-to-end. For HOP routes
// the runtime→hop leg is ALWAYS plain http: the WASM runtime sends no SNI and a
// fixed "Host: unknown", so the hop demuxes by PORT (each hop route dials its
// own per-app Ziti service whose host.v1 points at that route's hop port). The
// hop then rewrites the Host and proxies to the (possibly https) upstream.
func buildBrowZerTargets(routes []browzerRouteInfo, domain, idpIssuer, idpClientID string) []BrowZerTarget {
	targets := make([]BrowZerTarget, 0, len(routes))
	for _, r := range routes {
		scheme := "http"
		if parsed, err := url.Parse(r.toURL); err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		if r.hostingMode == HostingModeHop {
			scheme = "http" // runtime → hop leg is plain HTTP (port demux, no SNI/TLS)
		}
		targets = append(targets, BrowZerTarget{
			VHost:        r.hostname,
			Service:      r.serviceName,
			Path:         "/",
			Scheme:       scheme,
			IDPIssuerURL: idpIssuer,
			IDPClientID:  idpClientID,
		})
	}
	return targets
}

// GenerateBrowZerTargets queries the database for all BrowZer-enabled routes
// and builds the target configuration JSON for the bootstrapper. Each route maps
// to its own per-app Ziti service so the browser dials it directly.
func (tm *BrowZerTargetManager) GenerateBrowZerTargets(ctx context.Context) (*BrowZerTargetArray, error) {
	// Get OIDC settings from BrowZer config
	var oidcIssuer, oidcClientID string
	err := tm.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(oidc_issuer, ''), COALESCE(oidc_client_id, '')
		 FROM ziti_browzer_config WHERE enabled = true LIMIT 1`).Scan(&oidcIssuer, &oidcClientID)
	if err != nil {
		tm.logger.Debug("No BrowZer config found, generating empty targets", zap.Error(err))
		return &BrowZerTargetArray{TargetArray: []BrowZerTarget{}}, nil
	}

	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}

	targets := buildBrowZerTargets(routes, tm.GetDomain(), oidcIssuer, oidcClientID)

	tm.logger.Info("Generated BrowZer targets",
		zap.Int("count", len(targets)))
	return &BrowZerTargetArray{TargetArray: targets}, nil
}

// WriteBrowZerTargets generates the target config and writes it to the shared config file.
// The file is written in the nconf config.json format where the targets JSON is a string value.
func (tm *BrowZerTargetManager) WriteBrowZerTargets(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.writeTargetsLocked(ctx)
}

// writeTargetsLocked is the lock-free body of WriteBrowZerTargets. The caller
// must hold tm.mu (so target + router-config regeneration can share one lock).
func (tm *BrowZerTargetManager) writeTargetsLocked(ctx context.Context) error {
	if tm.targetsPath == "" {
		tm.logger.Debug("No targets path configured, skipping write")
		return nil
	}

	targets, err := tm.GenerateBrowZerTargets(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate targets: %w", err)
	}

	// The bootstrapper's nconf expects config.json with the targets as a JSON string value
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("failed to marshal targets: %w", err)
	}

	// Build the nconf config.json format
	configMap := map[string]string{
		"ZITI_BROWZER_BOOTSTRAPPER_TARGETS": string(targetsJSON),
	}
	// Include HOST override so the bootstrapper uses the configured domain
	domain := tm.GetDomain()
	if domain != DefaultBrowZerDomain {
		configMap["ZITI_BROWZER_BOOTSTRAPPER_HOST"] = domain
	}
	configJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := writeFileAtomic(tm.targetsPath, configJSON); err != nil {
		return err
	}

	tm.logger.Info("BrowZer targets written",
		zap.String("path", tm.targetsPath),
		zap.Int("targets", len(targets.TargetArray)))
	return nil
}

// browzerUpstream rewrites a route's to_url into the address the BrowZer router
// container must use to reach the target. When the target is bound to the host
// loopback (a "dark" service published only on 127.0.0.1, reachable over the
// overlay), the router — which runs in its own network namespace — cannot use
// 127.0.0.1 directly; it must use the host-loopback alias for its runtime (e.g.
// slirp4netns exposes the host loopback at 10.0.2.2 with allow_host_loopback).
//
// The alias is configured via BROWZER_HOST_LOOPBACK_ALIAS. When unset (the
// default, e.g. docker-compose where the router shares a bridge with the app),
// to_url is returned unchanged so behavior is identical to before.
func browzerUpstream(toURL string) string {
	alias := os.Getenv("BROWZER_HOST_LOOPBACK_ALIAS")
	if alias == "" {
		return toURL
	}
	parsed, err := url.Parse(toURL)
	if err != nil || parsed.Host == "" {
		return toURL
	}
	switch parsed.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		if port := parsed.Port(); port != "" {
			parsed.Host = alias + ":" + port
		} else {
			parsed.Host = alias
		}
		return parsed.String()
	default:
		return toURL
	}
}

// GenerateBrowZerRouterConfig generates nginx config for path-based and vhost-based BrowZer routing.
// Path-based routes on the default domain get location blocks; routes with unique domains get
// separate server blocks with simple proxy_pass (no sub_filter needed since the app runs at /).
func (tm *BrowZerTargetManager) GenerateBrowZerRouterConfig(ctx context.Context) ([]byte, error) {
	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}

	// Separate path-based routes from vhost routes
	type routeMapping struct {
		pathPrefix string
		upstream   string
		isGuac     bool
	}
	type vhostMapping struct {
		hostname    string
		upstream    string
		landingPath string
	}
	var mappings []routeMapping
	var vhosts []vhostMapping

	domain := tm.GetDomain()
	for _, r := range routes {
		if isRouterHosted(r.hostingMode) {
			continue // per-app direct/hop route: hosted by the edge router (host.v1), not the shared browzer-router
		}
		// Vhost routes: different domain, root path
		if r.hostname != domain {
			vhosts = append(vhosts, vhostMapping{
				hostname:    r.hostname,
				upstream:    browzerUpstream(r.toURL),
				landingPath: r.landingPath,
			})
			continue
		}
		// Skip root path on default domain (not a path-based route)
		if r.pathPrefix == "/" {
			continue
		}

		upstream := browzerUpstream(r.toURL)
		isGuac := false

		// Special case: Guacamole routes use the ZBR proxy for fetch tunnel injection
		if strings.Contains(r.toURL, "guacamole") || strings.Contains(r.serviceName, "guacamole") {
			upstream = "http://guacamole-zbr-proxy:80"
			isGuac = true
		}

		mappings = append(mappings, routeMapping{
			pathPrefix: r.pathPrefix,
			upstream:   upstream,
			isGuac:     isGuac,
		})
	}

	// Check if any route has an external upstream (needs resolver for runtime DNS)
	hasExternal := false
	for _, m := range mappings {
		parsed, _ := url.Parse(m.upstream)
		if parsed != nil && parsed.Scheme == "https" {
			hasExternal = true
			break
		}
	}

	// Build nginx config
	var b strings.Builder
	b.WriteString("# Auto-generated BrowZer router config — do not edit manually\n")
	// WebSocket upgrade map for vhost proxying
	if len(vhosts) > 0 {
		b.WriteString("map $http_upgrade $connection_upgrade {\n")
		b.WriteString("    default upgrade;\n")
		b.WriteString("    ''      close;\n")
		b.WriteString("}\n\n")
	}
	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString("    server_name _;\n")
	b.WriteString("    absolute_redirect off;\n")
	// Use detected DNS resolvers for external upstream resolution at runtime.
	// Without this, nginx resolves hostnames at config load time and crashes if DNS fails.
	// Includes Docker embedded DNS (127.0.0.11) plus host DNS servers from /etc/resolv.conf
	// so internal/corporate domains can be resolved.
	if hasExternal {
		fmt.Fprintf(&b, "    resolver %s valid=30s ipv6=off;\n", tm.dnsResolvers)
	}
	b.WriteString("\n")

	// Generate location blocks for each path-based route
	for _, m := range mappings {
		pathWithSlash := m.pathPrefix
		if !strings.HasSuffix(pathWithSlash, "/") {
			pathWithSlash += "/"
		}

		fmt.Fprintf(&b, "    location %s {\n", pathWithSlash)

		// Generate a safe variable name from the path prefix (e.g. /psm/ -> upstream_psm)
		varName := "upstream_" + strings.ReplaceAll(strings.Trim(m.pathPrefix, "/"), "-", "_")

		if m.isGuac {
			// Guacamole keeps the prefix (it expects /guacamole)
			fmt.Fprintf(&b, "        proxy_pass %s%s;\n", m.upstream, pathWithSlash)
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Host $host;\n")
			b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
			b.WriteString("        proxy_read_timeout 86400s;\n")
			b.WriteString("        proxy_send_timeout 86400s;\n")
			b.WriteString("        proxy_buffering off;\n")
		} else {
			parsed, _ := url.Parse(m.upstream)
			upstreamBase := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
			upstreamPath := strings.TrimSuffix(parsed.Path, "/")
			pathTrimmed := strings.TrimSuffix(pathWithSlash, "/")

			if upstreamPath != "" && upstreamPath != "/" {
				// Upstream has a non-root path (e.g. https://psm.tdv.org/psm).
				// Pass the URI through as-is — nginx forwards /psm/... to upstream /psm/...
				// Use variable-based proxy_pass so nginx resolves DNS at request time,
				// not at startup (prevents crash when external hosts are unreachable).
				fmt.Fprintf(&b, "        set $%s %s;\n", varName, upstreamBase)
				fmt.Fprintf(&b, "        proxy_pass $%s;\n", varName)
				// Rewrite Location headers so redirects stay on BrowZer domain
				fmt.Fprintf(&b, "        proxy_redirect https://%s/ /;\n", parsed.Host)
				fmt.Fprintf(&b, "        proxy_redirect http://%s/ /;\n", parsed.Host)
				b.WriteString("        proxy_http_version 1.1;\n")
				fmt.Fprintf(&b, "        proxy_set_header Host %s;\n", parsed.Host)
				b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
				b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
				b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
				b.WriteString("        proxy_ssl_server_name on;\n")
				b.WriteString("        proxy_ssl_verify off;\n")
				// Rewrite HTML content that references the upstream domain
				b.WriteString("        proxy_set_header Accept-Encoding \"\";\n")
				b.WriteString("        sub_filter_once off;\n")
				b.WriteString("        sub_filter_types text/html application/javascript text/javascript text/css;\n")
				fmt.Fprintf(&b, "        sub_filter 'https://%s' '';\n", parsed.Host)
				fmt.Fprintf(&b, "        sub_filter 'http://%s' '';\n", parsed.Host)
			} else if parsed.Scheme == "https" {
				// External HTTPS app: strip the prefix from ALL requests since the
				// backend doesn't know about the BrowZer path prefix. Rewrite every
				// URI from /prefix/... to /... before proxying.
				// Use variable-based proxy_pass for runtime DNS resolution.
				fmt.Fprintf(&b, "        set $%s %s;\n", varName, upstreamBase)
				fmt.Fprintf(&b, "        rewrite ^%s(/.*)?$ $1 break;\n", pathTrimmed)
				fmt.Fprintf(&b, "        proxy_pass $%s;\n", varName)
				fmt.Fprintf(&b, "        proxy_redirect / %s;\n", pathWithSlash)
				b.WriteString("        proxy_http_version 1.1;\n")
				fmt.Fprintf(&b, "        proxy_set_header Host %s;\n", parsed.Host)
				b.WriteString("        proxy_ssl_server_name on;\n")
				b.WriteString("        proxy_ssl_verify off;\n")
				b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
				b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
				b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
				b.WriteString("        proxy_set_header Accept-Encoding \"\";\n")
				b.WriteString("        sub_filter_once off;\n")
				b.WriteString("        sub_filter_types text/html application/javascript text/javascript text/css;\n")
				fmt.Fprintf(&b, "        sub_filter 'src=\"/' 'src=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'href=\"/' 'href=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(/' 'url(%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter \"url('/\" \"url('%s\";\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(\"/' 'url(\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'action=\"/' 'action=\"%s';\n", pathWithSlash)
			} else {
				// Internal HTTP app: hybrid path handling — rewrite rules strip the
				// prefix for the root page and static assets only. All other paths
				// (API calls, SPA page routes) pass through with the full URI so the
				// backend sees its expected paths (e.g. /apisix/admin/*). sub_filter
				// rewrites HTML asset paths, and the webpack publicPath so async
				// chunks load from the correct prefix.
				fmt.Fprintf(&b, "        rewrite ^%s/?$ / break;\n", pathTrimmed)
				fmt.Fprintf(&b, "        rewrite \"^%s/(.+\\.(?:js|mjs|css|html|htm|png|svg|ico|jpg|jpeg|gif|webp|woff2?|ttf|eot|otf|map|json|txt|xml|webmanifest))$\" /$1 break;\n", pathTrimmed)
				fmt.Fprintf(&b, "        proxy_pass %s;\n", upstreamBase)
				fmt.Fprintf(&b, "        proxy_redirect / %s;\n", pathWithSlash)
				b.WriteString("        proxy_http_version 1.1;\n")
				b.WriteString("        proxy_set_header Host $host;\n")
				b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
				b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
				b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
				b.WriteString("        proxy_set_header Accept-Encoding \"\";\n")
				b.WriteString("        sub_filter_once off;\n")
				b.WriteString("        sub_filter_types text/html application/javascript text/javascript text/css;\n")
				fmt.Fprintf(&b, "        sub_filter 'src=\"/' 'src=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'href=\"/' 'href=\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(/' 'url(%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter \"url('/\" \"url('%s\";\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter 'url(\"/' 'url(\"%s';\n", pathWithSlash)
				fmt.Fprintf(&b, "        sub_filter '.p=\"/\"' '.p=\"%s\"';\n", pathWithSlash)
			}
		}

		// Strip backend CSP headers — BrowZer SDK needs to connect to the Ziti controller
		// and OIDC provider, which restrictive CSP from backend apps would block
		b.WriteString("        proxy_hide_header Content-Security-Policy;\n")
		b.WriteString("        proxy_hide_header Content-Security-Policy-Report-Only;\n")
		b.WriteString("        proxy_hide_header X-Frame-Options;\n")

		b.WriteString("    }\n\n")
	}

	// Landing page listing available services
	b.WriteString("    location / {\n")
	b.WriteString("        default_type text/html;\n")
	b.WriteString("        return 200 '<!DOCTYPE html><html><head><title>OpenIDX BrowZer Services</title>")
	b.WriteString("<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:0 20px}")
	b.WriteString("a{display:block;padding:12px;margin:8px 0;background:#f0f0f0;border-radius:8px;text-decoration:none;color:#333}")
	b.WriteString("a:hover{background:#e0e0e0}</style></head><body>")
	b.WriteString("<h1>OpenIDX BrowZer Services</h1><p>Available services:</p>")
	for _, m := range mappings {
		label := strings.TrimPrefix(m.pathPrefix, "/")
		fmt.Fprintf(&b, "<a href=\"%s\">%s</a>", m.pathPrefix, label)
	}
	b.WriteString("</body></html>';\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	// Generate vhost server blocks for routes with unique domains.
	// These are simple reverse proxies — no sub_filter needed since the app runs at root /.
	for i, vh := range vhosts {
		fmt.Fprintf(&b, "\n# Vhost: %s\n", vh.hostname)
		b.WriteString("server {\n")
		// The first vhost is the default server. BrowZer's WASM runtime fetches the
		// origin over the overlay (dialing browzer-router-zt), and the Host it
		// presents to this router does not always match the vhost name — without a
		// default_server those requests fall through to the static landing block
		// instead of the app. Making the primary app the default routes any
		// otherwise-unmatched Host to it; additional vhosts still match by name.
		if i == 0 {
			b.WriteString("    listen 80 default_server;\n")
		} else {
			b.WriteString("    listen 80;\n")
		}
		fmt.Fprintf(&b, "    server_name %s;\n\n", vh.hostname)
		// Land the bare host on the app's real entry path when it serves under a
		// subpath (e.g. /ui/). Without this, the BrowZer/OIDC round-trip returns
		// to "/", which many apps 404. Exact-match so deeper paths proxy normally.
		// absolute_redirect off keeps the Location relative ("/ui/") — nginx behind
		// the overlay sees http, so an absolute Location would downgrade the https
		// page's scheme and break the BrowZer fetch.
		if lp := vh.landingPath; lp != "" && lp != "/" {
			b.WriteString("    absolute_redirect off;\n")
			fmt.Fprintf(&b, "    location = / { return 302 %s; }\n", lp)
		}
		b.WriteString("    location / {\n")
		fmt.Fprintf(&b, "        proxy_pass %s;\n", vh.upstream)
		b.WriteString("        proxy_http_version 1.1;\n")
		b.WriteString("        proxy_set_header Host $host;\n")
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection $connection_upgrade;\n")
		b.WriteString("        proxy_hide_header Content-Security-Policy;\n")
		b.WriteString("        proxy_hide_header Content-Security-Policy-Report-Only;\n")
		b.WriteString("        proxy_hide_header X-Frame-Options;\n")
		b.WriteString("    }\n")
		b.WriteString("}\n")
	}

	tm.logger.Info("Generated BrowZer router config",
		zap.Int("path_routes", len(mappings)),
		zap.Int("vhost_routes", len(vhosts)))
	return []byte(b.String()), nil
}

// WriteBrowZerRouterConfig generates the nginx router config and writes it to the shared config file.
func (tm *BrowZerTargetManager) WriteBrowZerRouterConfig(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.writeRouterConfigLocked(ctx)
}

// writeRouterConfigLocked is the lock-free body of WriteBrowZerRouterConfig. The
// caller must hold tm.mu.
func (tm *BrowZerTargetManager) writeRouterConfigLocked(ctx context.Context) error {
	if tm.routerConfigPath == "" {
		tm.logger.Debug("No router config path configured, skipping write")
		return nil
	}

	config, err := tm.GenerateBrowZerRouterConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate router config: %w", err)
	}

	if err := writeFileAtomic(tm.routerConfigPath, config); err != nil {
		return err
	}

	tm.logger.Info("BrowZer router config written",
		zap.String("path", tm.routerConfigPath))
	return nil
}

// buildBrowZerHopConfig generates the nginx config for the shared BrowZer hop:
// one plain-HTTP server{} per `hop` route, demuxed by PORT (each route listens
// on base+sorted-index, via assignHopPorts). The BrowZer WASM runtime sends NO
// SNI and a fixed "Host: unknown", so SNI/server_name demux cannot distinguish
// apps — only the port can. Each hop route dials its own per-app Ziti service
// whose host.v1 points at that route's hop port; this block rewrites Host to the
// vhost and proxies to the upstream. The runtime→hop leg is plain HTTP over the
// encrypted overlay (no TLS, no cert). The UPSTREAM may be http OR https
// (proxy_ssl_* is emitted only for https upstreams). Non-hop routes are skipped.
func buildBrowZerHopConfig(routes []browzerRouteInfo, basePort int) string {
	if basePort == 0 {
		basePort = 8095
	}
	var hopNames []string
	for _, r := range routes {
		if r.hostingMode == HostingModeHop {
			hopNames = append(hopNames, r.serviceName)
		}
	}
	ports := assignHopPorts(hopNames, basePort)

	var b strings.Builder
	b.WriteString("# Auto-generated BrowZer hop config — do not edit manually\n")
	for _, r := range routes {
		if r.hostingMode != HostingModeHop {
			continue
		}
		upstreamHTTPS := false
		if parsed, err := url.Parse(r.toURL); err == nil && parsed.Scheme == "https" {
			upstreamHTTPS = true
		}
		fmt.Fprintf(&b, "\nserver {\n")
		fmt.Fprintf(&b, "    listen %d;\n", ports[r.serviceName])
		b.WriteString("    server_name _;\n")
		// Land the bare host on the app's real entry path when it serves under a
		// subpath (e.g. /ui/). The BrowZer/OIDC round-trip returns to "/", which
		// many apps 404; the hop now has the correct Host, so a relative 302 (with
		// absolute_redirect off) sends the browser to the right place.
		if lp := r.landingPath; lp != "" && lp != "/" {
			b.WriteString("    absolute_redirect off;\n")
			fmt.Fprintf(&b, "    location = / { return 302 %s; }\n", lp)
		}
		b.WriteString("    location / {\n")
		// browzerUpstream rewrites a host-loopback upstream (127.0.0.1) to the
		// host-loopback alias (BROWZER_HOST_LOOPBACK_ALIAS, e.g. 10.0.2.2) so a
		// slirp4netns hop container can reach an app bound to the host loopback.
		fmt.Fprintf(&b, "        proxy_pass %s;\n", browzerUpstream(r.toURL))
		if upstreamHTTPS {
			b.WriteString("        proxy_ssl_server_name on;\n")
			fmt.Fprintf(&b, "        proxy_ssl_name %s;\n", r.hostname)
			b.WriteString("        proxy_ssl_verify off;\n")
		}
		// nginx's default proxy_redirect rewrites the upstream's absolute Location
		// (https://<vhost>/...) back to the proxy's own address — and since the
		// BrowZer runtime sends Host: unknown on the overlay leg, that becomes
		// http://unknown:<port>/... and breaks every server-issued redirect (the psm
		// login 302). Off = pass the upstream's correct <vhost> Location through; the
		// browser then re-navigates the overlay vhost.
		b.WriteString("        proxy_redirect off;\n")
		fmt.Fprintf(&b, "        proxy_set_header Host %s;\n", r.hostname)
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		// The browser's page scheme is https regardless of the plain-HTTP hop leg.
		b.WriteString("        proxy_set_header X-Forwarded-Proto https;\n")
		b.WriteString("        proxy_http_version 1.1;\n")
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
		b.WriteString("        proxy_read_timeout 86400s;\n")
		b.WriteString("        proxy_set_header Remote-User $http_remote_user;\n")
		b.WriteString("    }\n}\n")
	}
	return b.String()
}

// GenerateBrowZerHopConfig queries the BrowZer-enabled routes and builds the
// nginx config for the shared hop server. It is lock-free (mirrors
// GenerateBrowZerRouterConfig): it only reads tm.certsPath/tm.hopPort and calls
// queryBrowZerRoutes (which does not take tm.mu), so it is safe to call either
// under tm.mu (as WriteBrowZerHopConfig does) or without it.
func (tm *BrowZerTargetManager) GenerateBrowZerHopConfig(ctx context.Context) ([]byte, error) {
	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return nil, err
	}
	// tm.hopPort is the BASE port; assignHopPorts derives each route's listen port.
	// No cert/TLS at the hop — the runtime→hop leg is plain HTTP over the overlay.
	cfg := buildBrowZerHopConfig(routes, tm.hopPort)
	return []byte(cfg), nil
}

// WriteBrowZerHopConfig generates the nginx hop config and writes it to the
// shared config file. Mirrors WriteBrowZerRouterConfig's locking discipline:
// it holds tm.mu for the duration and calls the lock-free
// GenerateBrowZerHopConfig under that lock (no double-lock).
func (tm *BrowZerTargetManager) WriteBrowZerHopConfig(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.writeHopConfigLocked(ctx)
}

// writeHopConfigLocked writes the hop config; callers must hold tm.mu
// (RegenerateConfigs reuses it under the lock).
func (tm *BrowZerTargetManager) writeHopConfigLocked(ctx context.Context) error {
	if tm.hopConfigPath == "" {
		tm.logger.Debug("No hop config path configured, skipping write")
		return nil
	}
	data, err := tm.GenerateBrowZerHopConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate hop config: %w", err)
	}
	if err := writeFileAtomic(tm.hopConfigPath, data); err != nil {
		return err
	}
	tm.logger.Info("BrowZer hop config written", zap.String("path", tm.hopConfigPath))
	return nil
}

// RegenerateConfigs rewrites BOTH the bootstrapper targets and the nginx router
// config under a single lock, so the two files are always mutually consistent
// and concurrent callers serialize (whichever runs last reflects the latest
// committed proxy_routes state). Always queries install-wide (RLS bypassed),
// matching the shared bootstrapper's all-orgs view.
//
// Call this SYNCHRONOUSLY and AFTER the proxy_routes feature flags are
// committed. The previous fire-and-forget goroutines were spawned mid-toggle,
// before the flag commit, so they raced it and intermittently wrote empty
// (0-route) configs even when the DB was correct.
func (tm *BrowZerTargetManager) RegenerateConfigs(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if err := tm.writeTargetsLocked(ctx); err != nil {
		return err
	}
	if err := tm.writeRouterConfigLocked(ctx); err != nil {
		return err
	}
	if err := tm.writeHopConfigLocked(ctx); err != nil {
		return err
	}
	if err := tm.writeVHostConfigLocked(ctx); err != nil {
		return err
	}
	// When APISIX owns the edge, re-push the BrowZer routes too. Runs under tm.mu
	// (RegenerateConfigs is infrequent + serialized); the reconciler does NOT take
	// tm.mu, so there's no deadlock — Reconcile→queryBrowZerRoutes is lock-free.
	if rec := tm.apisixReconciler; rec != nil {
		if err := rec.Reconcile(ctx); err != nil {
			tm.logger.Warn("APISIX reconcile failed", zap.Error(err))
		}
	}
	// Auto-register each BrowZer app host as a redirect target on the BrowZer
	// OIDC client, so publishing a clientless app no longer needs a manual
	// browzer-client edit (the analog of the access-proxy callback auto-register
	// in the one-click publish flow). Best-effort.
	if err := tm.ensureBrowZerClientRedirects(ctx); err != nil {
		tm.logger.Warn("BrowZer client redirect_uri auto-register failed", zap.Error(err))
	}
	return nil
}

// ensureBrowZerClientRedirects makes sure every BrowZer-enabled route's host is
// an allowed redirect target on the BrowZer OIDC client (https://<host>/,
// .../auth/callback, and the bare origin). Idempotent: only URIs not already
// present are appended. No-op if BrowZer OIDC isn't configured. Caller holds
// tm.mu (RegenerateConfigs); queryBrowZerRoutes is lock-free.
func (tm *BrowZerTargetManager) ensureBrowZerClientRedirects(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	var clientID string
	if err := tm.db.Pool.QueryRow(ctx,
		//orgscope:ignore the BrowZer OIDC client is a single install-wide oauth client shared by every clientless app
		`SELECT COALESCE(oidc_client_id, '') FROM ziti_browzer_config WHERE enabled = true LIMIT 1`).Scan(&clientID); err != nil || clientID == "" {
		return nil // BrowZer OIDC not configured — nothing to register
	}
	routes, err := tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var desired []string
	for _, r := range routes {
		u, perr := url.Parse(r.fromURL)
		if perr != nil || u.Host == "" {
			continue
		}
		base := u.Scheme + "://" + u.Host
		for _, uri := range []string{base + "/", base + "/auth/callback", base} {
			if !seen[uri] {
				seen[uri] = true
				desired = append(desired, uri)
			}
		}
	}
	if len(desired) == 0 {
		return nil
	}
	desiredJSON, _ := json.Marshal(desired)
	// Append only the URIs not already present (correlated subquery reads the
	// pre-update redirect_uris). No unique constraint on the array, so the guard
	// prevents duplicates.
	_, err = tm.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide BrowZer OIDC client shared across orgs; keyed by globally-unique client_id
		`UPDATE oauth_clients SET
			redirect_uris = redirect_uris || (
				SELECT COALESCE(jsonb_agg(e), '[]'::jsonb)
				FROM jsonb_array_elements_text($1::jsonb) e
				WHERE NOT (redirect_uris @> jsonb_build_array(e))
			),
			updated_at = NOW()
		 WHERE client_id = $2`,
		desiredJSON, clientID)
	return err
}

// writeFileAtomic writes data to a file using a temp file + rename pattern for atomicity.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}
	return nil
}
