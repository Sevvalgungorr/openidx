// Package access - OpenZiti integration for Zero Trust network overlay
package access

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ZitiManager handles OpenZiti SDK integration and management API communication
type ZitiManager struct {
	cfg         *config.Config
	logger      *zap.Logger
	db          *database.PostgresDB
	zitiCtx     ziti.Context
	mgmtToken   string
	mgmtClient  *http.Client
	mu          sync.RWMutex
	initialized bool

	// Service hosting: listeners that bind services and forward to upstream
	hostedMu       sync.Mutex
	hostedServices map[string]*hostedService // keyed by service name

	// authFulls counts EventAuthenticationStateFull emissions. The first is the
	// initial login (hosting is driven by HostAllServices at startup); every
	// subsequent one is a reconnect/re-auth that triggers a re-host.
	authFulls atomic.Int32

	// Config type name → ID cache (e.g. "host.v1" → "NH5p4FpGR")
	configTypeCacheMu sync.RWMutex
	configTypeCache   map[string]string

	// pool holds the controller management endpoints (primary + optional HA
	// cluster members from ZitiCtrlURLs) with cooldown-based failover. Nil in
	// tests that construct the struct directly; all callers fall back to
	// cfg.ZitiCtrlURL when unset.
	pool *controllerEndpointPool
}

// hostedService tracks a Ziti service listener that forwards to an upstream target
type hostedService struct {
	listener   edge.Listener
	cancel     context.CancelFunc
	targetHost string
	targetPort int
}

// ZitiServiceInfo represents a Ziti service from the management API
type ZitiServiceInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Attributes     []string `json:"roleAttributes"`
	Protocol       string   `json:"protocol,omitempty"`
	RoleAttributes []string `json:"role_attributes,omitempty"`
	Configs        []string `json:"configs,omitempty"`
}

// ZitiIdentityInfo represents a Ziti identity from the management API
type ZitiIdentityInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Attributes []string `json:"roleAttributes"`
	Enrollment *struct {
		OTT *struct {
			JWT string `json:"jwt"`
		} `json:"ott,omitempty"`
	} `json:"enrollment,omitempty"`
}

// NewZitiManagerWithConn builds a ZitiManager against an explicit connection
// (controller URL / admin creds / identity dir / insecure), overriding whatever
// is in base cfg. Used for the admin-panel runtime connect path so the
// connection can come from DB settings rather than env. base provides all the
// non-Ziti config the manager needs.
// zitiHTTPTimeout bounds every Ziti controller management API call (default 8s)
// so a slow/hung controller can't stall an enroll or a reconcile pass.
func zitiHTTPTimeout(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.ZitiHTTPTimeoutSeconds > 0 {
		return time.Duration(cfg.ZitiHTTPTimeoutSeconds) * time.Second
	}
	return 8 * time.Second
}

func NewZitiManagerWithConn(base *config.Config, ctrlURL, adminUser, adminPwd, identityDir string, insecure bool, db *database.PostgresDB, logger *zap.Logger) (*ZitiManager, error) {
	c := *base // shallow copy; we only override the Ziti connection fields
	c.ZitiEnabled = true
	c.ZitiCtrlURL = ctrlURL
	// An explicit runtime connection targets exactly one controller — drop any
	// env-provided HA extras so failover can't wander back to old endpoints.
	c.ZitiCtrlURLs = ""
	c.ZitiAdminUser = adminUser
	c.ZitiAdminPassword = adminPwd
	c.ZitiIdentityDir = identityDir
	c.ZitiInsecureSkipVerify = insecure
	return NewZitiManager(&c, db, logger)
}

// NewZitiManager creates and initializes the ZitiManager
func NewZitiManager(cfg *config.Config, db *database.PostgresDB, logger *zap.Logger) (*ZitiManager, error) {
	zm := &ZitiManager{
		cfg:             cfg,
		logger:          logger.With(zap.String("component", "ziti")),
		db:              db,
		hostedServices:  make(map[string]*hostedService),
		configTypeCache: make(map[string]string),
	}

	// Controller endpoint pool: primary URL plus optional HA cluster members
	// (ZITI_CTRL_URLS). With one endpoint this degenerates to today's
	// single-controller behavior; with more, management calls fail over.
	pool, err := newControllerEndpointPool(cfg.ZitiCtrlURL, cfg.ZitiCtrlURLs)
	if err != nil {
		return nil, err
	}
	zm.pool = pool
	if pool.Size() > 1 {
		urls := make([]string, 0, pool.Size())
		for _, ep := range pool.Snapshot() {
			urls = append(urls, scrubLogValue(ep.URL))
		}
		zm.logger.Info("Ziti controller HA endpoint pool configured", zap.Strings("endpoints", urls))
	}

	// Build TLS config for Ziti controller management API communication.
	// The management API runs against the Ziti controller's self-signed
	// PKI. If the operator-provided identity directory contains the
	// matching ca.pem, we use it for proper validation (the desired
	// path). If it doesn't AND ziti_insecure_skip_verify is set, we
	// fall back to the dev-loop escape hatch; otherwise we surface the
	// error so production deploys can't silently lose verification.
	// Previously this set InsecureSkipVerify unconditionally, which
	// erased the value of every CA we then bolted on.
	tlsConfig := &tls.Config{}
	caFile := filepath.Join(cfg.ZitiIdentityDir, "ca.pem")
	caLoaded := false
	if caPEM, err := os.ReadFile(caFile); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			tlsConfig.RootCAs = pool
			caLoaded = true
			zm.logger.Info("Loaded Ziti CA certificate", zap.String("file", caFile))
		}
	}
	if !caLoaded {
		if !cfg.ZitiInsecureSkipVerify {
			return nil, fmt.Errorf(
				"ziti CA file not loaded (looked at %s) and ziti_insecure_skip_verify is false; "+
					"provide the controller CA or set ZITI_INSECURE_SKIP_VERIFY=true for dev",
				caFile,
			)
		}
		tlsConfig.InsecureSkipVerify = true
		zm.logger.Warn("Ziti controller TLS verification disabled by configuration (ziti_insecure_skip_verify=true)")
	}

	zm.mgmtClient = &http.Client{
		Timeout:   zitiHTTPTimeout(cfg),
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// Authenticate to management API
	if err := zm.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate to ziti controller: %w", err)
	}
	zm.logger.Info("Authenticated to Ziti controller", zap.String("url", cfg.ZitiCtrlURL))

	// Bootstrap: ensure access-proxy identity and default policies exist
	if err := zm.bootstrap(); err != nil {
		return nil, fmt.Errorf("failed to bootstrap ziti: %w", err)
	}

	// Load access-proxy identity and create SDK context
	identityFile := filepath.Join(cfg.ZitiIdentityDir, "access-proxy.json")
	if _, err := os.Stat(identityFile); err == nil {
		zitiCfg, err := ziti.NewConfigFromFile(identityFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load ziti identity from %s: %w", identityFile, err)
		}

		zitiCtx, err := ziti.NewContext(zitiCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create ziti context: %w", err)
		}
		zm.zitiCtx = zitiCtx
		zm.initialized = true
		zm.logger.Info("Ziti SDK context initialized from identity file", zap.String("file", identityFile))

		// Re-host services whenever the SDK re-authenticates. A dropped/expired
		// edge session can leave terminators registered on the controller but
		// dead — every dial then faults with "no destination for circuit" until
		// a manual restart. The first emission is the initial login (startup
		// HostAllServices covers it); subsequent ones are reconnects, on which we
		// rebind all hosted services to guarantee live terminators.
		zm.zitiCtx.Events().AddAuthenticationStateFullListener(func(_ ziti.Context, _ edge_apis.ApiSession) {
			if zm.authFulls.Add(1) <= 1 {
				return
			}
			zm.logger.Info("Ziti SDK re-authenticated; reconciling hosted services")
			go zm.reconcileHosting()
		})
	} else {
		zm.logger.Warn("Ziti identity file not found, SDK dialing unavailable (management API still functional)",
			zap.String("file", identityFile))
	}

	return zm, nil
}

// ControllerEndpoints reports the management endpoint pool for status
// surfaces. Single-endpoint (or test) managers report their one URL.
func (zm *ZitiManager) ControllerEndpoints() []ZitiEndpointStatus {
	if zm.pool != nil {
		return zm.pool.Snapshot()
	}
	return []ZitiEndpointStatus{{URL: zm.cfg.ZitiCtrlURL, Active: true, Healthy: true}}
}

// IsInitialized returns whether the Ziti SDK context is ready for dialing
func (zm *ZitiManager) IsInitialized() bool {
	zm.mu.RLock()
	defer zm.mu.RUnlock()
	return zm.initialized
}

// Close cleans up Ziti resources
func (zm *ZitiManager) Close() {
	// Stop all hosted services
	zm.hostedMu.Lock()
	for name, hs := range zm.hostedServices {
		zm.logger.Info("Stopping hosted service", zap.String("service", name))
		hs.cancel()
		hs.listener.Close()
	}
	zm.hostedServices = make(map[string]*hostedService)
	zm.hostedMu.Unlock()

	if zm.zitiCtx != nil {
		zm.zitiCtx.Close()
	}
}

// HostService binds a Ziti service and forwards incoming connections to the
// upstream target, creating a terminator so Dial calls can reach the service.
// Establishment is asynchronous and self-retrying (see serveHostedService): the
// call registers intent and returns immediately, so a not-yet-ready router or
// freshly-restarted controller no longer makes hosting fail outright — it keeps
// retrying until a live terminator is registered.
func (zm *ZitiManager) HostService(serviceName, targetHost string, targetPort int) error {
	if !zm.initialized {
		return fmt.Errorf("ziti SDK not initialized, cannot host service")
	}

	zm.hostedMu.Lock()
	if _, exists := zm.hostedServices[serviceName]; exists {
		zm.hostedMu.Unlock()
		zm.logger.Info("Service already hosted", zap.String("service", serviceName))
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	hs := &hostedService{cancel: cancel, targetHost: targetHost, targetPort: targetPort}
	zm.hostedServices[serviceName] = hs
	zm.hostedMu.Unlock()

	go zm.serveHostedService(ctx, hs, serviceName, fmt.Sprintf("%s:%d", targetHost, targetPort))
	return nil
}

// listenEdge opens a Ziti listener (terminator) for a service and asserts the
// edge.Listener type.
func (zm *ZitiManager) listenEdge(serviceName string) (edge.Listener, error) {
	netListener, err := zm.zitiCtx.Listen(serviceName)
	if err != nil {
		return nil, err
	}
	edgeListener, ok := netListener.(edge.Listener)
	if !ok {
		netListener.Close()
		return nil, fmt.Errorf("listener for %q does not implement edge.Listener", serviceName)
	}
	return edgeListener, nil
}

// serveHostedService owns a hosted service's full lifecycle: it (re-)establishes
// the listener with backoff, accepts overlay connections, and rebinds whenever
// the listener fails. This unifies initial hosting and re-hosting — both retry
// Listen until it succeeds, so neither a router that isn't ready yet nor a
// freshly-restarted controller leaves a registered-but-dead terminator (which
// faults every dial with "no destination for circuit" until a manual restart).
func (zm *ZitiManager) serveHostedService(ctx context.Context, hs *hostedService, serviceName, targetAddr string) {
	backoff := time.Second
	const maxBackoff = 15 * time.Second

	for {
		// (Re-)establish the listener, retrying until the SDK/router is ready.
		listener, err := zm.listenEdge(serviceName)
		if err != nil {
			zm.logger.Debug("Listen pending (SDK not ready)",
				zap.String("service", serviceName), zap.Error(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Publish the live listener (bail if stopped mid-establish).
		zm.hostedMu.Lock()
		if cur, exists := zm.hostedServices[serviceName]; !exists || cur != hs {
			zm.hostedMu.Unlock()
			listener.Close()
			return
		}
		hs.listener = listener
		zm.hostedMu.Unlock()

		backoff = time.Second
		zm.logger.Info("Hosting Ziti service",
			zap.String("service", serviceName), zap.String("target", targetAddr))

		// Accept loop — runs until the listener fails or we're stopped.
		for {
			conn, err := listener.AcceptEdge()
			if err == nil {
				go zm.forwardHTTPConnection(conn, targetAddr, serviceName)
				continue
			}
			select {
			case <-ctx.Done():
				listener.Close()
				zm.logger.Info("Stopped hosting service", zap.String("service", serviceName))
				return
			default:
			}
			zm.logger.Warn("Hosted service listener failed; rebinding",
				zap.String("service", serviceName), zap.Error(err))
			listener.Close()
			break // re-establish
		}
	}
}

// StopHostingService stops hosting a specific service
func (zm *ZitiManager) StopHostingService(serviceName string) {
	zm.hostedMu.Lock()
	defer zm.hostedMu.Unlock()

	if hs, exists := zm.hostedServices[serviceName]; exists {
		hs.cancel()
		hs.listener.Close()
		delete(zm.hostedServices, serviceName)
		zm.logger.Info("Stopped hosting service", zap.String("service", serviceName))
	}
}

// HostAllServices loads all Ziti-enabled routes from DB and starts hosting them
func (zm *ZitiManager) HostAllServices(ctx context.Context) {
	if !zm.initialized {
		zm.logger.Warn("Ziti SDK not initialized, skipping service hosting")
		return
	}

	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore startup Ziti service hosting across all orgs; keyed by globally-unique ziti service name
		`SELECT ziti_service_name, to_url FROM proxy_routes
		 WHERE ziti_enabled = true AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		zm.logger.Error("Failed to query Ziti-enabled routes", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var serviceName, toURL string
		if err := rows.Scan(&serviceName, &toURL); err != nil {
			zm.logger.Error("Failed to scan route row", zap.Error(err))
			continue
		}

		// Parse the upstream URL to get host and port
		host, port := parseHostPort(toURL)
		if host == "" || port == 0 {
			zm.logger.Warn("Could not parse upstream for Ziti hosting",
				zap.String("service", serviceName), zap.String("to_url", toURL))
			continue
		}

		if err := zm.HostService(serviceName, host, port); err != nil {
			zm.logger.Error("Failed to host Ziti service",
				zap.String("service", serviceName), zap.Error(err))
		}
	}
}

// serviceHasTerminator reports whether the controller currently has at least one
// terminator for the service — i.e. whether our hosting is actually live. Used
// to reconcile after a reconnect without disturbing healthy terminators.
func (zm *ZitiManager) serviceHasTerminator(serviceName string) bool {
	path := fmt.Sprintf("/edge/management/v1/terminators?filter=%s&limit=1",
		url.QueryEscape(fmt.Sprintf("service.name=\"%s\"", serviceName)))
	respData, status, err := zm.mgmtRequest("GET", path, nil)
	if err != nil || status != http.StatusOK {
		// Unknown — assume present so we don't needlessly rebind on a transient
		// management-API hiccup.
		return true
	}
	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if json.Unmarshal(respData, &resp) != nil {
		return true
	}
	return len(resp.Data) > 0
}

// reconcileHosting re-hosts only the services whose terminator has gone missing.
// Called when the SDK re-authenticates after a reconnect: a dropped session can
// leave a hosted service with no live terminator (every dial then faults with
// "no destination for circuit"). We deliberately do NOT blindly re-Listen every
// service — periodic session refresh also re-authenticates, and force-closing a
// healthy terminator risks a failed rebind turning a working service broken. So
// we only act on services the controller shows as having no terminator.
func (zm *ZitiManager) reconcileHosting() {
	zm.hostedMu.Lock()
	snapshot := make(map[string]*hostedService, len(zm.hostedServices))
	for name, hs := range zm.hostedServices {
		snapshot[name] = hs
	}
	zm.hostedMu.Unlock()

	for name, hs := range snapshot {
		if zm.serviceHasTerminator(name) {
			continue // healthy — leave it alone
		}
		zm.logger.Warn("Hosted service lost its terminator after reconnect; re-hosting",
			zap.String("service", name))

		// Tear down the stale entry (stops its accept goroutine via ctx) and
		// re-host with a fresh, self-retrying listener.
		hs.cancel()
		if hs.listener != nil {
			hs.listener.Close()
		}
		zm.hostedMu.Lock()
		if cur, ok := zm.hostedServices[name]; ok && cur == hs {
			delete(zm.hostedServices, name)
		}
		zm.hostedMu.Unlock()

		if err := zm.HostService(name, hs.targetHost, hs.targetPort); err != nil {
			zm.logger.Error("Failed to re-host service after reconnect",
				zap.String("service", name), zap.Error(err))
		}
	}
}

// forwardHTTPConnection serves HTTP on a Ziti edge connection, injecting identity headers
// from the caller's Ziti identity before forwarding to the upstream target.
func (zm *ZitiManager) forwardHTTPConnection(zitiConn edge.Conn, targetAddr, serviceName string) {
	callerID := zitiConn.SourceIdentifier()

	// BrowZer JS SDK doesn't set SourceIdentifier — resolve via management API
	if callerID == "" {
		callerID = zm.resolveCallerFromSessions(serviceName)
	}

	// Look up user info from the Ziti identity name (which is the OpenIDX user ID)
	var email, name, roles string
	if callerID != "" {
		// Bypass RLS: data-plane edge enrichment runs on a fresh background ctx
		// with no resolved org; keyed by the globally-unique ziti identity (= user id).
		ctx, cancel := context.WithTimeout(orgctx.WithBypassRLS(context.Background()), 5*time.Second)
		defer cancel()
		err := zm.db.Pool.QueryRow(ctx,
			//orgscope:ignore data-plane Ziti edge connection identity enrichment; keyed by globally-unique ziti identity name (= user id)
			`SELECT COALESCE(u.email,''), COALESCE(u.first_name||' '||u.last_name,''), COALESCE(string_agg(r.name,','),'')
			 FROM users u
			 LEFT JOIN user_roles ur ON ur.user_id = u.id
			 LEFT JOIN roles r ON r.id = ur.role_id
			 WHERE u.id = $1
			 GROUP BY u.id`, callerID).Scan(&email, &name, &roles)
		if err != nil {
			zm.logger.Warn("Failed to lookup user for Ziti identity",
				zap.String("caller_id", callerID), zap.Error(err))
		}
	}

	zm.logger.Debug("Accepted Ziti connection with identity",
		zap.String("service", serviceName),
		zap.String("caller_id", callerID),
		zap.String("email", email))

	// Create reverse proxy to upstream
	target, _ := url.Parse("http://" + targetAddr)
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		if callerID != "" {
			req.Header.Set("X-Forwarded-User", callerID)
			req.Header.Set("X-Forwarded-Email", email)
			req.Header.Set("X-Forwarded-Name", strings.TrimSpace(name))
			req.Header.Set("X-Forwarded-Roles", roles)
			req.Header.Set("X-Ziti-Identity", callerID)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		zm.logger.Error("Ziti HTTP proxy error",
			zap.String("service", serviceName), zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
	}

	// Serve HTTP on the single Ziti connection
	server := &http.Server{
		Handler:     proxy,
		ReadTimeout: 30 * time.Second,
	}
	ln := &singleConnListener{ch: make(chan net.Conn, 1)}
	ln.ch <- zitiConn
	server.Serve(ln)
}

// singleConnListener wraps a single net.Conn as a net.Listener for http.Server.Serve
type singleConnListener struct {
	ch   chan net.Conn
	once sync.Once
	addr net.Addr
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok || conn == nil {
		return nil, io.EOF
	}
	l.addr = conn.LocalAddr()
	// Close the channel after first accept so the server stops after this connection
	l.once.Do(func() { close(l.ch) })
	return conn, nil
}

func (l *singleConnListener) Close() error { return nil }
func (l *singleConnListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return &net.TCPAddr{}
}

// resolveCallerFromSessions queries the Ziti management API to find the identity
// mgmtURL joins pathAndQuery onto the validated Ziti controller base URL. It parses
// ZitiCtrlURL and requires an http/https scheme with a host, then rebuilds the base from
// only the scheme+host — so a malformed or hostile controller URL can't redirect management
// calls elsewhere (mitigates go/request-forgery). Callers MUST url.PathEscape any dynamic
// path segment they interpolate into pathAndQuery.
func (zm *ZitiManager) mgmtURL(pathAndQuery string) (string, error) {
	base, err := zm.mgmtBase()
	if err != nil {
		return "", err
	}
	return base + pathAndQuery, nil
}

// mgmtBase resolves the controller base URL for the next management call: the
// endpoint pool's current member when the pool is set (HA), otherwise the
// single configured URL. Either way the value is parsed and rebuilt from
// scheme+host right here, at the site that feeds requests, so a malformed or
// hostile controller URL can't redirect management calls (go/request-forgery).
func (zm *ZitiManager) mgmtBase() (string, error) {
	raw := zm.cfg.ZitiCtrlURL
	if zm.pool != nil {
		raw = zm.pool.Current()
	}
	base, err := url.Parse(raw)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return "", fmt.Errorf("ziti: invalid controller URL")
	}
	return base.Scheme + "://" + base.Host, nil
}

// that created the most recent Dial session for the given service. This is used as
// a fallback when SourceIdentifier() is empty (e.g., BrowZer JS SDK connections).
func (zm *ZitiManager) resolveCallerFromSessions(serviceName string) string {
	if zm.mgmtToken == "" {
		zm.logger.Warn("mgmtToken is empty, cannot resolve BrowZer caller")
		return ""
	}

	// Query Dial sessions (Ziti API doesn't support service.name filter or sort)
	filter := url.QueryEscape(`type="Dial"`)
	reqURL, err := zm.mgmtURL("/edge/management/v1/sessions?filter=" + filter + "&limit=1")
	if err != nil {
		zm.logger.Warn("Failed to build sessions request URL", zap.Error(err))
		return ""
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		zm.logger.Warn("Failed to create sessions request", zap.Error(err))
		return ""
	}
	req.Header.Set("zt-session", zm.mgmtToken)

	resp, err := zm.mgmtClient.Do(req)
	if err != nil {
		zm.logger.Warn("Failed to query Ziti sessions for caller resolution", zap.Error(err))
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	zm.logger.Debug("Sessions API response",
		zap.Int("status", resp.StatusCode),
		zap.String("body", string(body[:min(len(body), 500)])))

	var result struct {
		Data []struct {
			IdentityID string `json:"identityId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Data) == 0 {
		zm.logger.Warn("No sessions found or parse error",
			zap.Error(err), zap.Int("count", len(result.Data)))
		return ""
	}

	zitiIdentityID := result.Data[0].IdentityID

	// Look up the identity name (which is the OpenIDX user ID) from the Ziti identity ID
	identityReqURL, err := zm.mgmtURL("/edge/management/v1/identities/" + url.PathEscape(zitiIdentityID))
	if err != nil {
		return ""
	}
	identReq, err := http.NewRequest("GET", identityReqURL, nil)
	if err != nil {
		return ""
	}
	identReq.Header.Set("zt-session", zm.mgmtToken)

	identResp, err := zm.mgmtClient.Do(identReq)
	if err != nil {
		zm.logger.Warn("Failed to get identity details", zap.Error(err))
		return ""
	}
	defer identResp.Body.Close()

	var identResult struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(identResp.Body).Decode(&identResult); err != nil {
		return ""
	}

	zm.logger.Info("Resolved BrowZer caller from Ziti session",
		zap.String("ziti_identity_id", zitiIdentityID),
		zap.String("user_id", identResult.Data.Name))

	return identResult.Data.Name
}

// parseHostPort extracts host and port from a URL string
func parseHostPort(rawURL string) (string, int) {
	// Handle empty string
	if rawURL == "" {
		return "", 0
	}

	// Handle URLs like http://host:port/path
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", 0
	}

	host := parsed.Hostname()
	if host == "" {
		return "", 0
	}

	portStr := parsed.Port()
	if portStr == "" {
		switch parsed.Scheme {
		case "https":
			return host, 443
		default:
			return host, 80
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0
	}

	return host, port
}

// ---- Management API Authentication ----

func (zm *ZitiManager) authenticate() error {
	base, err := zm.mgmtBase()
	if err != nil {
		return fmt.Errorf("management API auth: %w", err)
	}
	err = zm.authenticateAt(base)
	if err == nil {
		if zm.pool != nil {
			zm.pool.MarkUp(base)
		}
		return nil
	}
	// HA failover: mark the failed member down and try the remaining healthy
	// endpoints once each. zt-session tokens are per controller, so a
	// successful auth against a new member fully re-establishes the session.
	if zm.pool != nil && zm.pool.Size() > 1 {
		tried := map[string]bool{base: true}
		for range zm.pool.Snapshot() {
			next, changed := zm.pool.MarkDown(base)
			if !changed || tried[next] {
				break
			}
			tried[next] = true
			zm.logger.Warn("Ziti controller auth failed; failing over",
				zap.String("from", scrubLogValue(base)), zap.String("to", scrubLogValue(next)), zap.Error(err))
			base = next
			if err = zm.authenticateAt(base); err == nil {
				zm.pool.MarkUp(base)
				return nil
			}
		}
	}
	return err
}

// authenticateAt performs a password authentication against one specific
// controller endpoint and stores the resulting zt-session token.
func (zm *ZitiManager) authenticateAt(base string) error {
	// Re-validate at the request site: parse and rebuild the base from
	// scheme+host only so a malformed or hostile controller URL can't redirect
	// the call (go/request-forgery — same guard the pre-pool mgmtURL applied).
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("management API auth: ziti: invalid controller URL")
	}
	authURL := u.Scheme + "://" + u.Host + "/edge/management/v1/authenticate?method=password"

	body, _ := json.Marshal(map[string]string{
		"username": zm.cfg.ZitiAdminUser,
		"password": zm.cfg.ZitiAdminPassword,
	})

	resp, err := zm.mgmtClient.Post(
		authURL,
		"application/json",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("management API auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("management API auth failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	zm.mu.Lock()
	zm.mgmtToken = result.Data.Token
	zm.mu.Unlock()

	return nil
}

// ---- Bootstrap ----

func (zm *ZitiManager) bootstrap() error {
	zm.logger.Info("Bootstrapping Ziti resources...")

	// 1. Create edge-router-policy: all identities -> all routers (idempotent)
	zm.ensureEdgeRouterPolicy()

	// 2. Create service-edge-router-policy: all services -> all routers (idempotent)
	zm.ensureServiceEdgeRouterPolicy()

	// 3. Create access-proxy identity if it doesn't exist
	if err := zm.ensureAccessProxyIdentity(); err != nil {
		return fmt.Errorf("failed to ensure access-proxy identity: %w", err)
	}

	zm.logger.Info("Ziti bootstrap complete")
	return nil
}

func (zm *ZitiManager) ensureEdgeRouterPolicy() {
	// Check if it already exists
	_, statusCode, _ := zm.mgmtRequest("GET", "/edge/management/v1/edge-router-policies?filter=name=\"openidx-all-routers\"", nil)
	if statusCode == http.StatusOK {
		// Check if data has items
		// For simplicity, try to create and ignore conflict
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-all-routers",
		"edgeRouterRoles": []string{"#all"},
		"identityRoles":   []string{"#all"},
	})
	_, _, err := zm.mgmtRequest("POST", "/edge/management/v1/edge-router-policies", body)
	if err != nil {
		zm.logger.Debug("Edge router policy creation (may already exist)", zap.Error(err))
	}
}

func (zm *ZitiManager) ensureServiceEdgeRouterPolicy() {
	body, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-all-services-all-routers",
		"edgeRouterRoles": []string{"#all"},
		"serviceRoles":    []string{"#all"},
	})
	_, _, err := zm.mgmtRequest("POST", "/edge/management/v1/service-edge-router-policies", body)
	if err != nil {
		zm.logger.Debug("Service edge router policy creation (may already exist)", zap.Error(err))
	}
}

func (zm *ZitiManager) ensureAccessProxyIdentity() error {
	identityFile := filepath.Join(zm.cfg.ZitiIdentityDir, "access-proxy.json")

	// If identity file already exists, we're done
	if _, err := os.Stat(identityFile); err == nil {
		zm.logger.Info("Access-proxy identity file already exists", zap.String("file", identityFile))
		return nil
	}

	// Check if identity exists in controller
	respData, statusCode, err := zm.mgmtRequest("GET",
		"/edge/management/v1/identities?filter=name=\"access-proxy\"", nil)
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK {
		var listResp struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respData, &listResp); err == nil && len(listResp.Data) > 0 {
			// Identity exists but we don't have the file - get enrollment JWT
			identity := listResp.Data[0]
			zm.logger.Info("Access-proxy identity exists in controller", zap.String("id", identity.ID))
			return zm.enrollIdentity(identity.ID, identityFile)
		}
	}

	// Create the identity
	zm.logger.Info("Creating access-proxy identity...")
	createBody, _ := json.Marshal(map[string]interface{}{
		"name":           "access-proxy",
		"type":           "Device",
		"isAdmin":        false,
		"roleAttributes": []string{"access-proxy-clients"},
		"enrollment": map[string]interface{}{
			"ott": true,
		},
	})

	respData, statusCode, err = zm.mgmtRequest("POST", "/edge/management/v1/identities", createBody)
	if err != nil {
		return fmt.Errorf("failed to create access-proxy identity: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating identity", statusCode)
	}

	var createResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &createResp); err != nil {
		return fmt.Errorf("failed to parse identity creation response: %w", err)
	}

	zm.logger.Info("Access-proxy identity created", zap.String("id", createResp.Data.ID))
	return zm.enrollIdentity(createResp.Data.ID, identityFile)
}

func (zm *ZitiManager) enrollIdentity(identityID, outputFile string) error {
	// Get the enrollment JWT
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", identityID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("failed to get identity details (HTTP %d)", statusCode)
	}

	var identityResp struct {
		Data struct {
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &identityResp); err != nil {
		return fmt.Errorf("failed to parse identity response: %w", err)
	}

	// Extract the OTT JWT
	var enrollmentJWT string
	if ott, ok := identityResp.Data.Enrollment["ott"].(map[string]interface{}); ok {
		if jwtStr, ok := ott["jwt"].(string); ok {
			enrollmentJWT = jwtStr
		}
	}

	if enrollmentJWT == "" {
		zm.logger.Warn("No enrollment JWT available (identity may already be enrolled)")
		return nil
	}

	// Ensure directory exists
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Parse the JWT token
	claims, jwtToken, err := enroll.ParseToken(enrollmentJWT)
	if err != nil {
		return fmt.Errorf("failed to parse enrollment JWT: %w", err)
	}

	// Enroll using the SDK
	var keyAlg ziti.KeyAlgVar
	keyAlg.Set("EC")
	flags := enroll.EnrollmentFlags{
		Token:     claims,
		JwtToken:  jwtToken,
		JwtString: enrollmentJWT,
		KeyAlg:    keyAlg,
	}

	zitiCfg, err := enroll.Enroll(flags)
	if err != nil {
		return fmt.Errorf("failed to enroll identity: %w", err)
	}

	// Write the enrolled identity config
	cfgData, err := json.MarshalIndent(zitiCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity config: %w", err)
	}

	if err := os.WriteFile(outputFile, cfgData, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	zm.logger.Info("Access-proxy identity enrolled and saved", zap.String("file", outputFile))
	return nil
}

// ---- Ziti Transport for Reverse Proxy ----

// ZitiTransport returns an http.RoundTripper that dials through the Ziti overlay
func (zm *ZitiManager) ZitiTransport(serviceName string) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			zm.logger.Debug("Dialing through Ziti overlay",
				zap.String("service", serviceName),
				zap.String("original_addr", addr))

			conn, err := zm.zitiCtx.Dial(serviceName)
			if err != nil {
				return nil, fmt.Errorf("ziti dial %q failed: %w", serviceName, err)
			}
			return conn, nil
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// ---- Management API CRUD Operations ----

// CreateService creates a Ziti service via the management API
func (zm *ZitiManager) CreateService(ctx context.Context, name string, attrs []string) (string, error) {
	if attrs == nil {
		attrs = []string{name}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":               name,
		"roleAttributes":     attrs,
		"encryptionRequired": true,
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/services", body)
	if err != nil {
		return "", fmt.Errorf("failed to create ziti service: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating service: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse service response: %w", err)
	}

	zm.logger.Info("Created Ziti service", zap.String("name", name), zap.String("id", resp.Data.ID))
	return resp.Data.ID, nil
}

// DeleteService deletes a Ziti service via the management API
func (zm *ZitiManager) DeleteService(ctx context.Context, zitiID string) error {
	_, statusCode, err := zm.mgmtRequest("DELETE",
		fmt.Sprintf("/edge/management/v1/services/%s", zitiID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d deleting service", statusCode)
	}
	return nil
}

// CreateIdentity creates a Ziti identity via the management API
func (zm *ZitiManager) CreateIdentity(ctx context.Context, name, identityType string, attrs []string) (zitiID string, enrollmentJWT string, err error) {
	if identityType == "" {
		identityType = "Device"
	}
	if attrs == nil {
		attrs = []string{}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":           name,
		"type":           identityType,
		"isAdmin":        false,
		"roleAttributes": attrs,
		"enrollment": map[string]interface{}{
			"ott": true,
		},
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/identities", body)
	if err != nil {
		return "", "", fmt.Errorf("failed to create ziti identity: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", "", fmt.Errorf("unexpected status %d creating identity: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID         string                 `json:"id"`
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", "", fmt.Errorf("failed to parse identity response: %w", err)
	}

	// Extract enrollment JWT
	if ott, ok := resp.Data.Enrollment["ott"].(map[string]interface{}); ok {
		if jwt, ok := ott["jwt"].(string); ok {
			enrollmentJWT = jwt
		}
	}

	// If JWT not in create response, fetch it
	if enrollmentJWT == "" {
		enrollmentJWT, _ = zm.GetIdentityEnrollmentJWT(ctx, resp.Data.ID)
	}

	zm.logger.Info("Created Ziti identity",
		zap.String("name", name),
		zap.String("id", resp.Data.ID),
		zap.Bool("has_jwt", enrollmentJWT != ""))

	return resp.Data.ID, enrollmentJWT, nil
}

// DeleteIdentity deletes a Ziti identity via the management API
func (zm *ZitiManager) DeleteIdentity(ctx context.Context, zitiID string) error {
	_, statusCode, err := zm.mgmtRequest("DELETE",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d deleting identity", statusCode)
	}
	return nil
}

// FindIdentityIDByName returns the controller-side identity ID whose name
// exactly matches the given name, or "" if none is found. Uses the controller's
// server-side name filter so it doesn't depend on identity-list paging.
func (zm *ZitiManager) FindIdentityIDByName(ctx context.Context, name string) string {
	path := fmt.Sprintf(`/edge/management/v1/identities?filter=%s`,
		url.QueryEscape(fmt.Sprintf(`name="%s"`, name)))
	respData, statusCode, err := zm.mgmtRequest("GET", path, nil)
	if err != nil || statusCode != http.StatusOK {
		zm.logger.Warn("FindIdentityIDByName request failed",
			zap.String("name", name), zap.Int("status", statusCode), zap.Error(err))
		return ""
	}
	var resp struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		zm.logger.Warn("FindIdentityIDByName decode failed", zap.String("name", name), zap.Error(err))
		return ""
	}
	for _, id := range resp.Data {
		if id.Name == name {
			return id.ID
		}
	}
	zm.logger.Debug("FindIdentityIDByName no match",
		zap.String("name", name), zap.Int("returned", len(resp.Data)))
	return ""
}

// IsIdentityEnrolled reports whether the controller considers the identity
// fully enrolled. An identity is enrolled iff it has NO pending enrollment
// (the `enrollment` object is empty). This is the live source of truth that the
// DB `ziti_identities.enrolled` flag drifts from: the flag is written false at
// identity creation and nothing flips it true when a device completes
// enrollment out-of-band (native SDK / tunneler). Callers can use this to
// self-heal the stored flag. Returns (false, err) on any controller error so
// callers keep the stored value rather than falsely claiming enrollment.
func (zm *ZitiManager) IsIdentityEnrolled(ctx context.Context, zitiID string) (bool, error) {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return false, err
	}
	if statusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status %d getting identity", statusCode)
	}
	var resp struct {
		Data struct {
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return false, err
	}
	// A pending OTT/CA/updb enrollment means the device has NOT completed
	// enrollment yet. An empty enrollment map means it has.
	return len(resp.Data.Enrollment) == 0, nil
}

// GetIdentityEnrollmentJWT retrieves the enrollment JWT for an identity
func (zm *ZitiManager) GetIdentityEnrollmentJWT(ctx context.Context, zitiID string) (string, error) {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d getting identity", statusCode)
	}

	var resp struct {
		Data struct {
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", err
	}

	if ott, ok := resp.Data.Enrollment["ott"].(map[string]interface{}); ok {
		if jwt, ok := ott["jwt"].(string); ok {
			return jwt, nil
		}
	}

	return "", fmt.Errorf("no enrollment JWT available for identity %s", zitiID)
}

// ReEnrollIdentity refreshes an identity's one-time enrollment token (OTT) so a
// device is handed a NON-expired enrollment JWT, then returns that fresh JWT.
// This is the fix for the stale-JWT bug: the controller keeps a pending OTT with
// a short `expiresAt`; once it lapses, naively reading the stored copy returns a
// long-expired token forever. There are two cases:
//
//   - Unenrolled identity with a pending OTT (the common case here): call
//     POST /enrollments/{id}/refresh with a future expiry, which regenerates the
//     token + JWT. This is what actually mints a usable JWT for a device that
//     never completed enrollment.
//   - Already-enrolled identity (no pending OTT): fall back to
//     POST /identities/{id}/re-enroll to reissue an OTT.
//
// Callers should persist the returned JWT.
func (zm *ZitiManager) ReEnrollIdentity(ctx context.Context, zitiID string) (string, error) {
	// Prefer refreshing a pending OTT enrollment when one exists.
	if enrID := zm.pendingOTTEnrollmentID(ctx, zitiID); enrID != "" {
		expiry := time.Now().Add(7 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
		body, _ := json.Marshal(map[string]interface{}{"expiresAt": expiry})
		_, statusCode, err := zm.mgmtRequest("POST",
			fmt.Sprintf("/edge/management/v1/enrollments/%s/refresh", enrID), body)
		if err != nil {
			return "", fmt.Errorf("ziti enrollment refresh call failed: %w", err)
		}
		if statusCode != http.StatusOK && statusCode != http.StatusAccepted {
			return "", fmt.Errorf("ziti enrollment refresh returned status %d", statusCode)
		}
		return zm.GetIdentityEnrollmentJWT(ctx, zitiID)
	}

	// No pending OTT — the identity is already enrolled; reissue one.
	_, statusCode, err := zm.mgmtRequest("POST",
		fmt.Sprintf("/edge/management/v1/identities/%s/re-enroll", zitiID), nil)
	if err != nil {
		return "", fmt.Errorf("ziti re-enroll call failed: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusCreated && statusCode != http.StatusNoContent {
		return "", fmt.Errorf("ziti re-enroll returned status %d", statusCode)
	}
	return zm.GetIdentityEnrollmentJWT(ctx, zitiID)
}

// pendingOTTEnrollmentID returns the id of an identity's pending OTT enrollment,
// or "" if the identity has none (e.g. already enrolled). Best-effort: any error
// yields "" so the caller falls back to the re-enroll path.
func (zm *ZitiManager) pendingOTTEnrollmentID(ctx context.Context, zitiID string) string {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s/enrollments", zitiID), nil)
	if err != nil || statusCode != http.StatusOK {
		return ""
	}
	var resp struct {
		Data []struct {
			ID     string `json:"id"`
			Method string `json:"method"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return ""
	}
	for _, e := range resp.Data {
		if e.Method == "ott" && e.ID != "" {
			return e.ID
		}
	}
	return ""
}

// CreateServicePolicy creates a Bind or Dial service policy
func (zm *ZitiManager) CreateServicePolicy(ctx context.Context, name, policyType string, serviceRoles, identityRoles []string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":          name,
		"type":          policyType, // "Bind" or "Dial"
		"semantic":      "AnyOf",
		"serviceRoles":  serviceRoles,
		"identityRoles": identityRoles,
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/service-policies", body)
	if err != nil {
		return "", fmt.Errorf("failed to create service policy: %w", err)
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating service policy: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", err
	}

	return resp.Data.ID, nil
}

// GetServicePolicyByName returns the service policy with the exact name, or
// (nil, nil) when none matches.
func (zm *ZitiManager) GetServicePolicyByName(ctx context.Context, name string) (*ZitiServicePolicyInfo, error) {
	q := url.QueryEscape(fmt.Sprintf(`name="%s"`, name))
	respData, statusCode, err := zm.mgmtRequest("GET",
		"/edge/management/v1/service-policies?filter="+q, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing service policies", statusCode)
	}
	var resp struct {
		Data []ZitiServicePolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	return &resp.Data[0], nil
}

// EnsureServicePolicy converges a service policy to the desired type and roles.
// It creates the policy when absent and UPDATES it in place when an existing
// policy of the same name has a different type/serviceRoles/identityRoles.
//
// This is what makes a hosting-mode transition self-heal: when a route flips
// from identity-mode (Bind/Dial granted to #access-proxy-clients) to
// router-hosted (#ziti-routers / #browzer-users) — e.g. when BrowZer is enabled
// on a route that was already Ziti-provisioned in identity mode — the stale
// policy is corrected rather than left untouched (plain create-if-exists would
// silently keep the wrong identity roles, which manifests as BrowZer error 1003).
func (zm *ZitiManager) EnsureServicePolicy(ctx context.Context, name, policyType string, serviceRoles, identityRoles []string) (string, error) {
	existing, err := zm.GetServicePolicyByName(ctx, name)
	if err != nil {
		return "", err
	}
	if existing == nil {
		return zm.CreateServicePolicy(ctx, name, policyType, serviceRoles, identityRoles)
	}
	if existing.Type == policyType &&
		sameRoleSet(existing.ServiceRoles, serviceRoles) &&
		sameRoleSet(existing.IdentityRoles, identityRoles) {
		return existing.ID, nil // already converged
	}
	if err := zm.UpdateServicePolicy(ctx, existing.ID, name, policyType, serviceRoles, identityRoles); err != nil {
		return "", err
	}
	return existing.ID, nil
}

// sameRoleSet reports whether two role slices contain the same elements,
// independent of order (Ziti does not guarantee role ordering on read-back).
func sameRoleSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, r := range a {
		seen[r]++
	}
	for _, r := range b {
		if seen[r] == 0 {
			return false
		}
		seen[r]--
	}
	return true
}

// DeleteServicePolicy deletes a service policy
func (zm *ZitiManager) DeleteServicePolicy(ctx context.Context, zitiID string) error {
	_, statusCode, err := zm.mgmtRequest("DELETE",
		fmt.Sprintf("/edge/management/v1/service-policies/%s", zitiID), nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d deleting service policy", statusCode)
	}
	return nil
}

// UpdateServicePolicy updates an existing service policy on the Ziti controller
func (zm *ZitiManager) UpdateServicePolicy(ctx context.Context, zitiID, name, policyType string, serviceRoles, identityRoles []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"name":          name,
		"type":          policyType,
		"semantic":      "AnyOf",
		"serviceRoles":  serviceRoles,
		"identityRoles": identityRoles,
	})

	_, statusCode, err := zm.mgmtRequest("PUT",
		fmt.Sprintf("/edge/management/v1/service-policies/%s", zitiID), body)
	if err != nil {
		return fmt.Errorf("failed to update service policy: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d updating service policy", statusCode)
	}
	return nil
}

// PatchIdentityRoleAttributes updates the role attributes of a Ziti identity
func (zm *ZitiManager) PatchIdentityRoleAttributes(ctx context.Context, zitiID string, attrs []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"roleAttributes": attrs,
	})

	_, statusCode, err := zm.mgmtRequest("PATCH",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), body)
	if err != nil {
		return fmt.Errorf("failed to patch identity role attributes: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d patching identity", statusCode)
	}
	return nil
}

// GetIdentityRoleAttributes retrieves current role attributes for an identity
func (zm *ZitiManager) GetIdentityRoleAttributes(ctx context.Context, zitiID string) ([]string, error) {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d getting identity", statusCode)
	}

	var resp struct {
		Data struct {
			RoleAttributes []string `json:"roleAttributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return resp.Data.RoleAttributes, nil
}

// ListServices lists all Ziti services from the management API
func (zm *ZitiManager) ListServices(ctx context.Context) ([]ZitiServiceInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/services", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing services", statusCode)
	}

	var resp struct {
		Data []ZitiServiceInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ListIdentities lists all Ziti identities from the management API
func (zm *ZitiManager) ListIdentities(ctx context.Context) ([]ZitiIdentityInfo, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/identities", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing identities", statusCode)
	}

	var resp struct {
		Data []ZitiIdentityInfo `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// resolveConfigTypeID looks up a config type ID by name, with caching.
// Falls back to hardcoded defaults if lookup fails.
func (zm *ZitiManager) resolveConfigTypeID(typeName string) string {
	// Check cache first
	zm.configTypeCacheMu.RLock()
	if id, ok := zm.configTypeCache[typeName]; ok {
		zm.configTypeCacheMu.RUnlock()
		return id
	}
	zm.configTypeCacheMu.RUnlock()

	// Fetch from controller
	respData, status, err := zm.mgmtRequest("GET", "/edge/management/v1/config-types?limit=500", nil)
	if err != nil || status != 200 {
		zm.logger.Warn("failed to fetch config types, using fallback", zap.Error(err))
		return zm.configTypeFallback(typeName)
	}

	var resp struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return zm.configTypeFallback(typeName)
	}

	zm.configTypeCacheMu.Lock()
	for _, ct := range resp.Data {
		zm.configTypeCache[ct.Name] = ct.ID
	}
	zm.configTypeCacheMu.Unlock()

	zm.configTypeCacheMu.RLock()
	id, ok := zm.configTypeCache[typeName]
	zm.configTypeCacheMu.RUnlock()
	if ok {
		return id
	}
	return zm.configTypeFallback(typeName)
}

func (zm *ZitiManager) configTypeFallback(typeName string) string {
	defaults := map[string]string{
		"host.v1":      "NH5p4FpGR",
		"intercept.v1": "g7cIWbcGg",
	}
	if id, ok := defaults[typeName]; ok {
		return id
	}
	return typeName
}

// ---- Route Ziti Setup/Teardown ----

// SetupZitiForRoute creates all Ziti resources needed for a proxy route
func (zm *ZitiManager) SetupZitiForRoute(ctx context.Context, routeID, serviceName, host string, port int) error {
	// 1. Create the Ziti service with host.v1 config so the tunneler knows where to forward.
	// NOTE: this initial marshal is overwritten by svcPayload below before use; the dead
	// literal is kept for now and should be removed in a focused cleanup.
	body, _ := json.Marshal(map[string]interface{}{ //nolint:ineffassign,staticcheck // overwritten by svcPayload below; see note
		"name":               serviceName,
		"roleAttributes":     []string{serviceName},
		"encryptionRequired": true,
		"configs":            []string{}, // will attach config after creating it
	})

	// Create a host.v1 config that tells Ziti where to forward traffic
	configBody, _ := json.Marshal(map[string]interface{}{
		"name":         fmt.Sprintf("openidx-host-%s", serviceName),
		"configTypeId": zm.resolveConfigTypeID("host.v1"),
		"data": map[string]interface{}{
			"protocol":         "tcp",
			"address":          host,
			"port":             port,
			"forwardProtocol":  true,
			"allowedProtocols": []string{"tcp"},
			"forwardAddress":   true,
			"allowedAddresses": []string{host},
			"forwardPort":      true,
			"allowedPortRanges": []map[string]int{
				{"low": port, "high": port},
			},
		},
	})

	configData, configStatus, err := zm.mgmtRequest("POST", "/edge/management/v1/configs", configBody)
	var configID string
	if err == nil && (configStatus == http.StatusCreated || configStatus == http.StatusOK) {
		var configResp struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(configData, &configResp) == nil {
			configID = configResp.Data.ID
			zm.logger.Info("Created host.v1 config", zap.String("id", configID))
		}
	} else {
		zm.logger.Warn("Failed to create host.v1 config, creating service without it",
			zap.Int("status", configStatus), zap.Error(err))
	}

	// Create service, optionally attaching the config
	svcPayload := map[string]interface{}{
		"name":               serviceName,
		"roleAttributes":     []string{serviceName},
		"encryptionRequired": true,
	}
	if configID != "" {
		svcPayload["configs"] = []string{configID}
	}
	body, _ = json.Marshal(svcPayload)

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/services", body)
	if err != nil {
		return fmt.Errorf("failed to create ziti service: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating service: %s", statusCode, string(respData))
	}

	var svcResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &svcResp); err != nil {
		return fmt.Errorf("failed to parse service response: %w", err)
	}
	zitiServiceID := svcResp.Data.ID
	zm.logger.Info("Created Ziti service", zap.String("name", serviceName), zap.String("id", zitiServiceID))

	// 2. Persist to ziti_services table. route_id is a UUID column; internal
	// services (e.g. browzer-router-zt) have no owning route, so pass NULL
	// rather than "" (which errors as invalid uuid, SQLSTATE 22P02).
	var routeIDArg interface{}
	if routeID != "" {
		routeIDArg = routeID
	}
	_, err = zm.db.Pool.Exec(ctx,
		//orgscope:ignore startup/infra Ziti provisioning reachable from cross-org seeded-route reconciliation; keyed by globally-unique ziti service name
		`INSERT INTO ziti_services (ziti_id, name, host, port, route_id) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (name) DO UPDATE SET ziti_id=$1, host=$3, port=$4, route_id=$5, updated_at=NOW()`,
		zitiServiceID, serviceName, host, port, routeIDArg)
	if err != nil {
		zm.logger.Error("Failed to persist ziti service to DB", zap.Error(err))
	}

	// 3. Create Bind policy: access-proxy can host this service
	// Use "#" prefix for role-based matching (the service has roleAttributes=[serviceName])
	bindPolicyID, err := zm.CreateServicePolicy(ctx,
		fmt.Sprintf("openidx-bind-%s", serviceName),
		"Bind",
		[]string{"#" + serviceName},
		[]string{"#access-proxy-clients"})
	if err != nil {
		zm.logger.Warn("Failed to create Bind policy", zap.Error(err))
	} else {
		zm.db.Pool.Exec(ctx,
			//orgscope:ignore startup/infra Ziti provisioning reachable from cross-org seeded-route reconciliation; system policy keyed by globally-unique ziti policy id
			`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, is_system)
			 VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (ziti_id) DO NOTHING`,
			bindPolicyID, fmt.Sprintf("openidx-bind-%s", serviceName), "Bind",
			`["#`+serviceName+`"]`, `["#access-proxy-clients"]`)
	}

	// 4. Create Dial policy: access-proxy can dial this service
	dialPolicyID, err := zm.CreateServicePolicy(ctx,
		fmt.Sprintf("openidx-dial-%s", serviceName),
		"Dial",
		[]string{"#" + serviceName},
		[]string{"#access-proxy-clients"})
	if err != nil {
		zm.logger.Warn("Failed to create Dial policy", zap.Error(err))
	} else {
		zm.db.Pool.Exec(ctx,
			//orgscope:ignore startup/infra Ziti provisioning reachable from cross-org seeded-route reconciliation; system policy keyed by globally-unique ziti policy id
			`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, is_system)
			 VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (ziti_id) DO NOTHING`,
			dialPolicyID, fmt.Sprintf("openidx-dial-%s", serviceName), "Dial",
			`["#`+serviceName+`"]`, `["#access-proxy-clients"]`)
	}

	// 5. Create Service Edge Router Policy so the service is available on all edge routers
	serBody, _ := json.Marshal(map[string]interface{}{
		"name":            fmt.Sprintf("openidx-serp-%s", serviceName),
		"semantic":        "AnyOf",
		"serviceRoles":    []string{"#" + serviceName},
		"edgeRouterRoles": []string{"#all"},
	})
	_, serpStatus, serpErr := zm.mgmtRequest("POST", "/edge/management/v1/service-edge-router-policies", serBody)
	if serpErr != nil || (serpStatus != http.StatusCreated && serpStatus != http.StatusOK) {
		zm.logger.Warn("Failed to create service edge router policy", zap.Error(serpErr), zap.Int("status", serpStatus))
	}

	// 6. Ensure an Edge Router Policy exists so identities can use routers
	erpBody, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-erp-access-proxy",
		"semantic":        "AnyOf",
		"edgeRouterRoles": []string{"#all"},
		"identityRoles":   []string{"#access-proxy-clients"},
	})
	_, erpStatus, erpErr := zm.mgmtRequest("POST", "/edge/management/v1/edge-router-policies", erpBody)
	if erpErr != nil || (erpStatus != http.StatusCreated && erpStatus != http.StatusOK) {
		// May already exist, which is fine
		zm.logger.Debug("Edge router policy creation returned", zap.Int("status", erpStatus))
	}

	// 7. Update the proxy route
	_, err = zm.db.Pool.Exec(ctx,
		//orgscope:ignore startup/infra Ziti provisioning reachable from cross-org seeded-route reconciliation; route keyed by id, ziti service by globally-unique name
		"UPDATE proxy_routes SET ziti_enabled=true, ziti_service_name=$1, updated_at=NOW() WHERE id=$2",
		serviceName, routeID)
	if err != nil {
		return fmt.Errorf("failed to update proxy route: %w", err)
	}

	// 8. Start hosting the service so it has a terminator
	if err := zm.HostService(serviceName, host, port); err != nil {
		zm.logger.Error("Failed to host service (no terminator will exist)",
			zap.String("service", serviceName), zap.Error(err))
		// Don't fail the setup — management resources are created, hosting can be retried
	}

	zm.logger.Info("Ziti setup complete for route",
		zap.String("route_id", routeID),
		zap.String("service", serviceName))
	return nil
}

// TeardownZitiForRoute removes all Ziti resources for a proxy route
// deleteEdgeEntityByName deletes every entity in the given management collection
// (e.g. "configs", "service-edge-router-policies") whose name exactly matches.
// Used by teardown to remove name-keyed objects we don't track in our own DB.
func (zm *ZitiManager) deleteEdgeEntityByName(ctx context.Context, collection, name string) error {
	lookup := fmt.Sprintf("/edge/management/v1/%s?filter=name=%q", collection, name)
	data, status, err := zm.mgmtRequest("GET", lookup, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d listing %s", status, collection)
	}
	var resp struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	for _, e := range resp.Data {
		if e.Name != name || e.ID == "" {
			continue
		}
		_, ds, derr := zm.mgmtRequest("DELETE", fmt.Sprintf("/edge/management/v1/%s/%s", collection, e.ID), nil)
		if derr != nil {
			return derr
		}
		if ds != http.StatusOK && ds != http.StatusNoContent {
			return fmt.Errorf("unexpected status %d deleting %s/%s", ds, collection, e.ID)
		}
	}
	return nil
}

// edgeEntity is the minimal shape of a Ziti management object (service, policy,
// config, serp) used for orphan detection.
type edgeEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// listEdgeEntities returns ALL entities in a management collection. ListServices
// and friends use the default page size (10) and silently truncate; this passes
// an explicit high limit so orphan detection sees everything at our scale.
func (zm *ZitiManager) listEdgeEntities(ctx context.Context, collection string) ([]edgeEntity, error) {
	data, status, err := zm.mgmtRequest("GET",
		"/edge/management/v1/"+collection+"?limit=1000", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing %s", status, collection)
	}
	var resp struct {
		Data []edgeEntity `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// TeardownZitiServiceByName deletes a Ziti service and its associated objects
// (bind/dial service policies, service-edge-router policy, host.v1 config) by
// name. The reconciler creates controller services declaratively WITHOUT a
// ziti_services DB row, so TeardownZitiForRoute (which is DB-driven) cannot see
// them — this name-keyed teardown cleans those (e.g. legacy per-path services).
// Idempotent: missing objects are no-ops.
func (zm *ZitiManager) TeardownZitiServiceByName(ctx context.Context, serviceName string) error {
	zm.StopHostingService(serviceName)
	// All deletes use the name-FILTER endpoint (pagination-safe). The service
	// itself must NOT be looked up via ListServices/GetServiceByName — that is
	// paginated (Ziti defaults to 10), so with many services the lookup misses
	// most of them and they orphan.
	for _, p := range []struct{ col, name string }{
		{"service-policies", "openidx-bind-" + serviceName},
		{"service-policies", "openidx-dial-" + serviceName},
		{"service-edge-router-policies", "openidx-serp-" + serviceName},
		{"configs", serviceName + "-host"},
		{"configs", serviceName + "-intercept"},
		{"services", serviceName},
	} {
		if err := zm.deleteEdgeEntityByName(ctx, p.col, p.name); err != nil {
			zm.logger.Warn("teardown-by-name: delete failed",
				zap.String("collection", p.col), zap.String("name", p.name), zap.Error(err))
		}
	}
	return nil
}

func (zm *ZitiManager) TeardownZitiForRoute(ctx context.Context, routeID string) error {
	// Find service for this route
	var zitiServiceID, serviceName string
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore Ziti teardown reachable from cross-org reconciliation; service keyed by globally-unique ziti service name / route id
		"SELECT ziti_id, name FROM ziti_services WHERE route_id=$1", routeID).Scan(&zitiServiceID, &serviceName)
	if err != nil {
		zm.logger.Debug("No ziti service found for route", zap.String("route_id", routeID))
	} else {
		// Stop hosting the service first
		zm.StopHostingService(serviceName)
		// Delete service policies first
		rows, _ := zm.db.Pool.Query(ctx,
			//orgscope:ignore Ziti teardown reachable from cross-org reconciliation; policies keyed by globally-unique ziti service name
			"SELECT ziti_id FROM ziti_service_policies WHERE name LIKE $1",
			fmt.Sprintf("%%-%s", serviceName))
		if rows != nil {
			for rows.Next() {
				var policyZitiID string
				rows.Scan(&policyZitiID)
				zm.DeleteServicePolicy(ctx, policyZitiID)
			}
			rows.Close()
		}
		zm.db.Pool.Exec(ctx,
			//orgscope:ignore Ziti teardown reachable from cross-org reconciliation; policies keyed by globally-unique ziti service name
			"DELETE FROM ziti_service_policies WHERE name LIKE $1",
			fmt.Sprintf("%%-%s", serviceName))

		// Delete the service
		zm.DeleteService(ctx, zitiServiceID)
		zm.db.Pool.Exec(ctx,
			//orgscope:ignore Ziti teardown reachable from cross-org reconciliation; service keyed by globally-unique ziti service name / route id
			"DELETE FROM ziti_services WHERE route_id=$1", routeID)

		// Remove the name-keyed host.v1 config and service-edge-router policy.
		// These are NOT tracked in ziti_service_policies, so the loop above
		// misses them — without this they orphan on the controller (the
		// openidx-<svc>-host config + openidx-serp-<svc> policy left behind by a
		// route delete or rename).
		if err := zm.deleteEdgeEntityByName(ctx, "configs", serviceName+"-host"); err != nil {
			zm.logger.Warn("teardown: delete host.v1 config", zap.String("svc", serviceName), zap.Error(err))
		}
		if err := zm.deleteEdgeEntityByName(ctx, "service-edge-router-policies", "openidx-serp-"+serviceName); err != nil {
			zm.logger.Warn("teardown: delete service-edge-router policy", zap.String("svc", serviceName), zap.Error(err))
		}
	}

	// Update the route
	_, err = zm.db.Pool.Exec(ctx,
		//orgscope:ignore Ziti teardown reachable from cross-org reconciliation; route keyed by id
		"UPDATE proxy_routes SET ziti_enabled=false, ziti_service_name=NULL, updated_at=NOW() WHERE id=$1",
		routeID)
	if err != nil {
		return fmt.Errorf("failed to update proxy route: %w", err)
	}

	zm.logger.Info("Ziti teardown complete for route", zap.String("route_id", routeID))
	return nil
}

// GetControllerVersion checks connectivity to the Ziti controller
func (zm *ZitiManager) GetControllerVersion(ctx context.Context) (map[string]interface{}, error) {
	respData, statusCode, err := zm.mgmtRequest("GET", "/edge/management/v1/version", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", statusCode)
	}

	var result map[string]interface{}
	json.Unmarshal(respData, &result)
	return result, nil
}

// MgmtRequest is the exported wrapper around the internal management API request helper.
func (zm *ZitiManager) MgmtRequest(method, path string, body []byte) ([]byte, int, error) {
	return zm.mgmtRequest(method, path, body)
}

// ---- Internal helpers ----

func (zm *ZitiManager) mgmtRequest(method, path string, body []byte) ([]byte, int, error) {
	// Build against the validated controller base (scheme/host checked) so a malformed or
	// hostile ZitiCtrlURL can't redirect management calls elsewhere (go/request-forgery).
	base, err := zm.mgmtBase()
	if err != nil {
		return nil, 0, err
	}

	respBody, status, err := zm.mgmtRequestAt(base, method, path, body)

	// HA failover: a transport error or gateway-class 5xx means this cluster
	// member is unusable — put it in cooldown and retry once against the next
	// healthy member (with a fresh auth, since zt-session tokens are minted
	// per controller).
	if zm.pool != nil && (err != nil || status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout) {
		next, changed := zm.pool.MarkDown(base)
		if changed {
			zm.logger.Warn("Ziti controller unreachable; failing over",
				zap.String("from", scrubLogValue(base)), zap.String("to", scrubLogValue(next)),
				zap.Int("status", status), zap.Error(err))
			if authErr := zm.authenticateAt(next); authErr == nil {
				respBody, status, err = zm.mgmtRequestAt(next, method, path, body)
				base = next
			}
		}
	}

	if zm.pool != nil && err == nil && status < http.StatusInternalServerError {
		zm.pool.MarkUp(base)
	}
	return respBody, status, err
}

// mgmtRequestAt performs one management API request against a specific
// controller base URL, with the existing 401 → re-auth → single retry.
func (zm *ZitiManager) mgmtRequestAt(base, method, path string, body []byte) ([]byte, int, error) {
	// Re-validate at the request site: parse and rebuild the base from
	// scheme+host only so a malformed or hostile controller URL can't redirect
	// management calls elsewhere (go/request-forgery — same guard the pre-pool
	// mgmtURL applied per call). Callers MUST url.PathEscape any dynamic path
	// segment they interpolate into path.
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, 0, fmt.Errorf("ziti: invalid controller URL")
	}
	fullURL := u.Scheme + "://" + u.Host + path

	zm.mu.RLock()
	token := zm.mgmtToken
	zm.mu.RUnlock()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, fullURL, reqBody)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("zt-session", token)
	}

	resp, err := zm.mgmtClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("management API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	// Re-authenticate on 401 and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		if err := zm.authenticateAt(base); err != nil {
			return respBody, resp.StatusCode, fmt.Errorf("re-authentication failed: %w", err)
		}

		zm.mu.RLock()
		token = zm.mgmtToken
		zm.mu.RUnlock()

		// Retry
		if body != nil {
			reqBody = bytes.NewReader(body)
		}
		req, _ = http.NewRequest(method, fullURL, reqBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("zt-session", token)

		resp, err = zm.mgmtClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()

		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, resp.StatusCode, err
		}
	}

	return respBody, resp.StatusCode, nil
}

// ---- Methods for Feature Manager and Health Checks ----

// CheckControllerHealth verifies connectivity to the Ziti controller
func (zm *ZitiManager) CheckControllerHealth(ctx context.Context) (bool, error) {
	_, err := zm.GetControllerVersion(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetDB returns the database reference for direct queries
func (zm *ZitiManager) GetDB() *database.PostgresDB {
	return zm.db
}

// EnsureEdgeRouterPolicy creates an edge-router-policy (which routers an
// identity may use) if one with this name doesn't already exist. Idempotent:
// a name match is treated as success. Without such a policy an identity is
// assigned zero routers and every dial fails with NO_EDGE_ROUTERS_AVAILABLE.
func (zm *ZitiManager) EnsureEdgeRouterPolicy(ctx context.Context, name string, edgeRouterRoles, identityRoles []string) error {
	filter := url.QueryEscape(fmt.Sprintf(`name="%s"`, name))
	if data, status, err := zm.mgmtRequest("GET",
		"/edge/management/v1/edge-router-policies?filter="+filter, nil); err == nil && status == http.StatusOK {
		var resp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &resp) == nil && len(resp.Data) > 0 {
			return nil // already exists
		}
	}
	body, _ := json.Marshal(map[string]interface{}{
		"name":            name,
		"semantic":        "AnyOf",
		"edgeRouterRoles": edgeRouterRoles,
		"identityRoles":   identityRoles,
	})
	_, status, err := zm.mgmtRequest("POST", "/edge/management/v1/edge-router-policies", body)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating edge-router policy", status)
	}
	return nil
}

// EnsureServiceEdgeRouterPolicy creates a service-edge-router policy if it doesn't already exist.
func (zm *ZitiManager) EnsureServiceEdgeRouterPolicy(ctx context.Context, name string, serviceRoles, edgeRouterRoles []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"name":            name,
		"semantic":        "AnyOf",
		"serviceRoles":    serviceRoles,
		"edgeRouterRoles": edgeRouterRoles,
	})
	_, status, err := zm.mgmtRequest("POST", "/edge/management/v1/service-edge-router-policies", body)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating service-edge-router policy", status)
	}
	return nil
}

// GetServiceByName retrieves a Ziti service by its name
func (zm *ZitiManager) GetServiceByName(serviceName string) (*ZitiServiceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	services, err := zm.ListServices(ctx)
	if err != nil {
		return nil, err
	}

	for _, svc := range services {
		if svc.Name == serviceName {
			return &svc, nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", serviceName)
}

// GetService retrieves a Ziti service by its ID
func (zm *ZitiManager) GetService(zitiID string) (*ZitiServiceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	services, err := zm.ListServices(ctx)
	if err != nil {
		return nil, err
	}

	for _, svc := range services {
		if svc.ID == zitiID {
			return &svc, nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", zitiID)
}

// TestServiceDial tests if a Ziti service is dialable by attempting a real
// dial from the access-proxy identity. A successful dial proves the whole
// chain: the service exists, a policy grants this identity dial access, an
// edge router is reachable, and a terminator answers. Failures return the
// SDK's error so the caller can see which link is broken (no policy, no
// terminator, router offline, ...).
func (zm *ZitiManager) TestServiceDial(ctx context.Context, serviceName string) (bool, error) {
	if zm.zitiCtx == nil {
		return false, fmt.Errorf("Ziti context not initialized")
	}

	// Check if service exists first for a clearer error than a raw dial failure
	_, err := zm.GetServiceByName(serviceName)
	if err != nil {
		return false, err
	}

	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if until := time.Until(deadline); until > 0 && until < timeout {
			timeout = until
		}
	}
	conn, err := zm.zitiCtx.DialWithOptions(serviceName, &ziti.DialOptions{ConnectTimeout: timeout})
	if err != nil {
		return false, fmt.Errorf("dial %s failed: %w", serviceName, err)
	}
	_ = conn.Close()
	return true, nil
}

// ZitiAuditEvent represents an audit event from Ziti
type ZitiAuditEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Identity  string                 `json:"identity,omitempty"`
	Service   string                 `json:"service,omitempty"`
	Router    string                 `json:"router,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// GetAuditEvents retrieves fabric/edge events from the Ziti controller as audit
// events: identity API-session logins (who authenticated to the overlay, when,
// from where) and service dials/circuits (who reached which service). OpenZiti
// does not expose a single audit feed, so we derive these from the management
// API's api-sessions and sessions collections. The `since` filter bounds results
// to events newer than the caller's cursor. Returns newest-first order per the
// controller default; callers sort/cursor by Timestamp.
func (zm *ZitiManager) GetAuditEvents(ctx context.Context, since *time.Time) ([]ZitiAuditEvent, error) {
	// No management client (not connected / not configured): nothing to fetch.
	if zm == nil || zm.mgmtClient == nil {
		return []ZitiAuditEvent{}, nil
	}
	var out []ZitiAuditEvent

	// API sessions = overlay authentications. Each is "identity X logged into the
	// overlay at T from IP".
	apiSessions, err := zm.listFabricAPISessions(ctx)
	if err != nil {
		zm.logger.Debug("ziti audit: list api-sessions failed", zap.Error(err))
	}
	for _, s := range apiSessions {
		if since != nil && !s.CreatedAt.After(*since) {
			continue
		}
		out = append(out, ZitiAuditEvent{
			ID:        "apisession:" + s.ID,
			Type:      "ziti.api_session.created",
			Timestamp: s.CreatedAt,
			Identity:  s.IdentityName,
			SourceIP:  s.IPAddress,
			Details: map[string]interface{}{
				"identity_id":    s.IdentityID,
				"api_session_id": s.ID,
			},
		})
	}

	// Sessions = service dials (a circuit toward a service). Each is "identity X
	// dialed service Y".
	sessions, err := zm.listFabricSessions(ctx)
	if err != nil {
		zm.logger.Debug("ziti audit: list sessions failed", zap.Error(err))
	}
	for _, s := range sessions {
		if since != nil && !s.CreatedAt.After(*since) {
			continue
		}
		out = append(out, ZitiAuditEvent{
			ID:        "session:" + s.ID,
			Type:      "ziti.service.dialed",
			Timestamp: s.CreatedAt,
			Identity:  s.IdentityName,
			Service:   s.ServiceName,
			Details: map[string]interface{}{
				"session_id":   s.ID,
				"session_type": s.Type,
				"service_id":   s.ServiceID,
			},
		})
	}
	return out, nil
}

// fabricAPISession is the subset of an /edge/management/v1/api-sessions row used
// to derive an overlay-login audit event.
type fabricAPISession struct {
	ID           string
	IdentityID   string
	IdentityName string
	IPAddress    string
	CreatedAt    time.Time
}

func (zm *ZitiManager) listFabricAPISessions(ctx context.Context) ([]fabricAPISession, error) {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/api-sessions?limit=500&sort=createdAt%20desc", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing api-sessions", status)
	}
	var resp struct {
		Data []struct {
			ID         string    `json:"id"`
			IdentityID string    `json:"identityId"`
			IPAddress  string    `json:"ipAddress"`
			CreatedAt  time.Time `json:"createdAt"`
			Identity   struct {
				Name string `json:"name"`
			} `json:"identity"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	out := make([]fabricAPISession, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, fabricAPISession{
			ID: d.ID, IdentityID: d.IdentityID, IdentityName: d.Identity.Name,
			IPAddress: d.IPAddress, CreatedAt: d.CreatedAt,
		})
	}
	return out, nil
}

// fabricSession is the subset of an /edge/management/v1/sessions row used to
// derive a service-dial audit event.
type fabricSession struct {
	ID           string
	Type         string
	ServiceID    string
	ServiceName  string
	IdentityName string
	CreatedAt    time.Time
}

func (zm *ZitiManager) listFabricSessions(ctx context.Context) ([]fabricSession, error) {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/sessions?limit=500&sort=createdAt%20desc", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing sessions", status)
	}
	var resp struct {
		Data []struct {
			ID        string    `json:"id"`
			Type      string    `json:"type"`
			CreatedAt time.Time `json:"createdAt"`
			Service   struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"service"`
			APISession struct {
				Identity struct {
					Name string `json:"name"`
				} `json:"identity"`
			} `json:"apiSession"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	out := make([]fabricSession, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, fabricSession{
			ID: d.ID, Type: d.Type, ServiceID: d.Service.ID, ServiceName: d.Service.Name,
			IdentityName: d.APISession.Identity.Name, CreatedAt: d.CreatedAt,
		})
	}
	return out, nil
}

// CreateService (overloaded) creates a Ziti service with host/port config
func (zm *ZitiManager) CreateServiceWithConfig(ctx context.Context, name, host string, port int) (*ZitiServiceInfo, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	attrs := []string{name, "openidx-managed"}

	zitiID, err := zm.CreateService(ctx, name, attrs)
	if err != nil {
		return nil, err
	}

	// Store in database
	if zm.db != nil && zm.db.Pool != nil {
		id := uuid.New().String()
		_, err = zm.db.Pool.Exec(ctx, `
			INSERT INTO ziti_services (id, ziti_id, name, protocol, host, port, enabled, org_id)
			VALUES ($1, $2, $3, 'tcp', $4, $5, true, $6)
		`, id, zitiID, name, host, port, org.ID)
		if err != nil {
			zm.logger.Warn("Failed to save service to DB", zap.Error(err))
		}
	} else {
		zm.logger.Warn("Database not available, skipping service storage")
	}

	return &ZitiServiceInfo{
		ID:   zitiID,
		Name: name,
	}, nil
}

// CreateHostV1ConfigFixed creates a host.v1 config that points at a FIXED
// upstream. Unlike the forward* form (which makes the dialer choose the target
// and fails BrowZer with "dst_protocol required"), this pins protocol/address/
// port so the edge router hosts the service straight to the upstream. Returns
// the new config's id.
// EnsureServiceConfig makes sure the service references configID, attaching it
// if missing (idempotent). The reconciler's create path attaches the host.v1
// config at create time, but a service that already existed when the reconciler
// first saw it — e.g. one created in SDK/identity mode by the feature-manager's
// BrowZer toggle — has NO config attached, so the edge router cannot host it and
// falls back to a stale SDK terminator (which forwards wrong → 502). This makes
// the reconciler converge the attachment.
func (zm *ZitiManager) EnsureServiceConfig(ctx context.Context, serviceID, configID string) error {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/services/"+serviceID, nil)
	if err != nil {
		return fmt.Errorf("get service for config-attach: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d getting service %s: %s", status, serviceID, string(data))
	}
	var resp struct {
		Data struct {
			Configs []string `json:"configs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse service config list: %w", err)
	}
	for _, c := range resp.Data.Configs {
		if c == configID {
			return nil
		}
	}
	patch, _ := json.Marshal(map[string]interface{}{"configs": append(resp.Data.Configs, configID)})
	if _, ps, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/services/"+serviceID, patch); perr != nil || (ps != http.StatusOK && ps != http.StatusAccepted) {
		return fmt.Errorf("attach config %s to service %s: status %d: %w", configID, serviceID, ps, perr)
	}
	zm.logger.Info("Attached host.v1 config to existing service",
		zap.String("service", serviceID), zap.String("config", configID))
	return nil
}

func (zm *ZitiManager) CreateHostV1ConfigFixed(ctx context.Context, name, host string, port int) (string, error) {
	desiredData := map[string]interface{}{
		"protocol": "tcp",
		"address":  host,
		"port":     port,
	}

	// Ensure (get-or-create-or-update): OpenZiti enforces unique config names, so
	// POSTing an existing name wedges the route. Look it up first. If it exists
	// but its target drifted (e.g. the per-app hop port reshuffled when another
	// hop route was added/removed), PATCH the data so the reconciler self-heals —
	// otherwise a stale port silently breaks the route. A non-200 GET or empty
	// data set is treated as "not found" — fall through to create.
	lookupPath := fmt.Sprintf("/edge/management/v1/configs?filter=name=\"%s\"", name)
	if lookupData, lookupStatus, lookupErr := zm.mgmtRequest("GET", lookupPath, nil); lookupErr == nil && lookupStatus == http.StatusOK {
		var existing struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Data struct {
					Address  string      `json:"address"`
					Port     json.Number `json:"port"`
					Protocol string      `json:"protocol"`
				} `json:"data"`
			} `json:"data"`
		}
		if json.Unmarshal(lookupData, &existing) == nil {
			for _, c := range existing.Data {
				if c.Name != name || c.ID == "" {
					continue
				}
				if c.Data.Address == host && c.Data.Port.String() == strconv.Itoa(port) && c.Data.Protocol == "tcp" {
					zm.logger.Info("Reusing existing host.v1 config", zap.String("name", name), zap.String("id", c.ID))
					return c.ID, nil
				}
				// Drifted target — converge by patching the data in place.
				patch, _ := json.Marshal(map[string]interface{}{"data": desiredData})
				if _, ps, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/configs/"+c.ID, patch); perr == nil && (ps == http.StatusOK || ps == http.StatusAccepted) {
					zm.logger.Info("Updated drifted host.v1 config",
						zap.String("name", name), zap.String("id", c.ID),
						zap.String("address", host), zap.Int("port", port))
					return c.ID, nil
				}
				zm.logger.Warn("failed to patch drifted host.v1 config; reusing as-is",
					zap.String("name", name), zap.String("id", c.ID))
				return c.ID, nil
			}
		}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":         name,
		"configTypeId": zm.resolveConfigTypeID("host.v1"),
		"data":         desiredData,
	})
	data, status, err := zm.mgmtRequest("POST", "/edge/management/v1/configs", body)
	if err != nil {
		return "", fmt.Errorf("create host.v1 config: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating host.v1 config: %s", status, string(data))
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse host.v1 config response: %w", err)
	}
	return resp.Data.ID, nil
}

// CreateInterceptV1ConfigFixed ensures an intercept.v1 config named `name` that
// intercepts tcp `host:port` and returns its id (get-or-create-or-update, like
// CreateHostV1ConfigFixed). The PAM broker's ziti-tunnel uses this to know which
// address to capture off its tun device and carry over the overlay. `host` must
// be a NON-loopback address (see pamZitiInterceptHost): ziti-edge-tunnel runs in
// TUN mode and the kernel short-circuits 127.0.0.0/8 before it reaches the tun
// device, so a loopback intercept never fires.
func (zm *ZitiManager) CreateInterceptV1ConfigFixed(ctx context.Context, name, host string, port int) (string, error) {
	desiredData := map[string]interface{}{
		"protocols": []string{"tcp"},
		"addresses": []string{host},
		"portRanges": []map[string]interface{}{
			{"low": port, "high": port},
		},
	}

	lookupPath := fmt.Sprintf("/edge/management/v1/configs?filter=name=\"%s\"", name)
	if lookupData, lookupStatus, lookupErr := zm.mgmtRequest("GET", lookupPath, nil); lookupErr == nil && lookupStatus == http.StatusOK {
		var existing struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Data struct {
					Addresses  []string `json:"addresses"`
					PortRanges []struct {
						Low  json.Number `json:"low"`
						High json.Number `json:"high"`
					} `json:"portRanges"`
				} `json:"data"`
			} `json:"data"`
		}
		if json.Unmarshal(lookupData, &existing) == nil {
			for _, c := range existing.Data {
				if c.Name != name || c.ID == "" {
					continue
				}
				matches := len(c.Data.Addresses) == 1 && c.Data.Addresses[0] == host &&
					len(c.Data.PortRanges) == 1 &&
					c.Data.PortRanges[0].Low.String() == strconv.Itoa(port) &&
					c.Data.PortRanges[0].High.String() == strconv.Itoa(port)
				if matches {
					zm.logger.Info("Reusing existing intercept.v1 config", zap.String("name", name), zap.String("id", c.ID))
					return c.ID, nil
				}
				// Drifted intercept target — converge by patching in place.
				patch, _ := json.Marshal(map[string]interface{}{"data": desiredData})
				if _, ps, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/configs/"+c.ID, patch); perr == nil && (ps == http.StatusOK || ps == http.StatusAccepted) {
					zm.logger.Info("Updated drifted intercept.v1 config",
						zap.String("name", name), zap.String("id", c.ID),
						zap.String("address", host), zap.Int("port", port))
					return c.ID, nil
				}
				zm.logger.Warn("failed to patch drifted intercept.v1 config; reusing as-is",
					zap.String("name", name), zap.String("id", c.ID))
				return c.ID, nil
			}
		}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":         name,
		"configTypeId": zm.resolveConfigTypeID("intercept.v1"),
		"data":         desiredData,
	})
	data, status, err := zm.mgmtRequest("POST", "/edge/management/v1/configs", body)
	if err != nil {
		return "", fmt.Errorf("create intercept.v1 config: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating intercept.v1 config: %s", status, string(data))
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse intercept.v1 config response: %w", err)
	}
	return resp.Data.ID, nil
}

// createServiceWithConfigID creates an encryption-required service with the
// given role attributes and an attached config id (e.g. a host.v1 config).
func (zm *ZitiManager) createServiceWithConfigID(ctx context.Context, name string, attrs []string, configID string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":               name,
		"roleAttributes":     attrs,
		"encryptionRequired": true,
		"configs":            []string{configID},
	})
	data, status, err := zm.mgmtRequest("POST", "/edge/management/v1/services", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating service: %s", status, string(data))
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse service response: %w", err)
	}
	return resp.Data.ID, nil
}

// EnsureRouterRoleAttribute tags every edge router with the "ziti-routers" role
// attribute (idempotent), so direct-mode Bind policies can grant the routers as
// a stable role (#ziti-routers) instead of by id.
func (zm *ZitiManager) EnsureRouterRoleAttribute(ctx context.Context) error {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/edge-routers?limit=1000", nil)
	if err != nil {
		return fmt.Errorf("list edge routers: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status %d listing edge routers: %s", status, string(data))
	}
	var resp struct {
		Data []struct {
			ID             string   `json:"id"`
			RoleAttributes []string `json:"roleAttributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse edge routers: %w", err)
	}
	for _, r := range resp.Data {
		has := false
		for _, a := range r.RoleAttributes {
			if a == "ziti-routers" {
				has = true
				break
			}
		}
		if has {
			continue
		}
		patch, _ := json.Marshal(map[string]interface{}{
			"roleAttributes": append(r.RoleAttributes, "ziti-routers"),
		})
		if _, s, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/edge-routers/"+r.ID, patch); perr != nil || (s != http.StatusOK && s != http.StatusAccepted) {
			zm.logger.Warn("failed to tag edge router with #ziti-routers", zap.String("router", r.ID), zap.Int("status", s), zap.Error(perr))
		}
	}
	return nil
}
