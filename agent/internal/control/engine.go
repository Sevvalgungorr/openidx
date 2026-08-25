// Package control provides the OpenIDX native-client "engine": a headless
// facade over the agent's existing SSO / enrollment / PAM / posture / Ziti
// capabilities, plus a local control server (see server.go) that a desktop GUI
// talks to.
//
// The Engine facade is deliberately gomobile-friendly: every exported method
// takes and returns only string / []byte / bool / int values and returns a
// (result, error) pair. No generics, channels, maps, slices, or rich structs
// cross the boundary — rich data is marshalled to a JSON string. This lets
// Phase 2 `gomobile bind` the SAME facade for the mobile app with no changes.
package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/sso"
	"github.com/openidx/openidx/agent/internal/ziti"
)

// backend is the seam over the network-touching engine APIs (sso / pam /
// enrollment). Tests inject a fake so the HTTP layer can be exercised without a
// live OpenIDX server. The default implementation (realBackend) calls the
// existing packages verbatim.
type backend interface {
	Login(ctx context.Context, serverURL string) (*sso.Tokens, error)
	Enroll(logger *zap.Logger, serverURL, token, configDir string) (agentID, deviceID, zitiIdentity string, err error)
	PamList(ctx context.Context, serverURL, token string) ([]desktoppam.Entry, error)
	PamConnect(ctx context.Context, serverURL, token, entryID string) (connectURL string, err error)
	PamRequest(ctx context.Context, serverURL, token, entryID, reason string) error
}

// zitiDialer is the seam over the embedded Ziti bridge so tests do not require a
// real enrolled identity. Mirrors *ziti.Dialer.
type zitiDialer interface {
	Bridge(service string) (localAddr string, stop func(), err error)
	Close()
}

// Engine is the headless native-client facade. Construct via NewEngine.
type Engine struct {
	configDir string
	serverURL string
	logger    *zap.Logger

	be         backend
	newDialer  func(identityFile string) (zitiDialer, error)
	loginTimeout time.Duration

	mu           sync.Mutex
	bridges      map[string]*bridge  // active Ziti bridges keyed by service name
	pendingLogin *sso.PendingLogin   // in-flight split login (LoginStart→LoginWait)
}

type bridge struct {
	localAddr string
	stop      func()
	dialer    zitiDialer
}

// NewEngine loads the enrolled server URL from the agent config in configDir and
// returns a ready facade. A missing/unparseable config is tolerated (serverURL
// is left empty); methods that need a server return a clear error at call time,
// so a not-yet-enrolled device can still report Status.
func NewEngine(configDir string, logger *zap.Logger) (*Engine, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	serverURL := ""
	if cfg, err := agent.LoadConfig(configDir); err == nil {
		serverURL = strings.TrimRight(cfg.ServerURL, "/")
	}
	return &Engine{
		configDir:    configDir,
		serverURL:    serverURL,
		logger:       logger,
		be:           realBackend{},
		newDialer:    func(f string) (zitiDialer, error) { return ziti.NewDialer(f) },
		loginTimeout: 5 * time.Minute,
		bridges:      map[string]*bridge{},
	}, nil
}

// ---- gomobile-friendly facade methods ----------------------------------

// statusPayload is the flat status snapshot (JSON-marshalled by Status).
type statusPayload struct {
	Enrolled     bool   `json:"enrolled"`
	AgentID      string `json:"agent_id,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	ServerURL    string `json:"server_url,omitempty"`
	ZitiEnrolled bool   `json:"ziti_enrolled"`
	LoggedIn     bool   `json:"logged_in"`
	UserSub      string `json:"user_sub,omitempty"`
	UserEmail    string `json:"user_email,omitempty"`
	TokenExpiry  int64  `json:"token_expiry,omitempty"`
	TokenExpired bool   `json:"token_expired,omitempty"`
}

// Status reports enrollment state, the logged-in user (from the cached OAuth
// token), and whether a Ziti identity is present, as a JSON string.
func (e *Engine) Status() (string, error) {
	var st statusPayload

	if cfg, err := agent.LoadConfig(e.configDir); err == nil {
		st.Enrolled = cfg.AgentID != ""
		st.AgentID = cfg.AgentID
		st.DeviceID = cfg.DeviceID
		st.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
		st.ZitiEnrolled = cfg.ZitiIdentityFile != "" && fileExists(cfg.ZitiIdentityFile)
	}
	if st.ServerURL == "" {
		st.ServerURL = e.serverURL
	}
	// A bare ziti-identity.json in the config dir also counts.
	if !st.ZitiEnrolled && fileExists(e.zitiIdentityPath()) {
		st.ZitiEnrolled = true
	}

	if tok, err := authstore.Load(e.configDir); err == nil && tok != nil && tok.AccessToken != "" {
		st.LoggedIn = true
		st.TokenExpiry = tok.ExpiresAt
		if tok.ExpiresAt > 0 {
			st.TokenExpired = time.Now().Unix() >= tok.ExpiresAt
		}
		if sub, email, exp, ok := decodeJWTClaims(tok.AccessToken); ok {
			st.UserSub = sub
			st.UserEmail = email
			if st.TokenExpiry == 0 && exp > 0 {
				st.TokenExpiry = exp
			}
		}
	}

	return toJSON(st)
}

type userPayload struct {
	Sub   string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
	Exp   int64  `json:"exp"`
}

// Login runs the interactive browser PKCE flow against the enrolled server,
// caches the tokens, and returns {sub,email,exp} as a JSON string.
func (e *Engine) Login() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.loginTimeout)
	defer cancel()

	tok, err := e.be.Login(ctx, e.serverURL)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	if err := authstore.Save(e.configDir, tok); err != nil {
		return "", fmt.Errorf("saving session: %w", err)
	}
	sub, email, exp, _ := decodeJWTClaims(tok.AccessToken)
	if exp == 0 {
		exp = tok.ExpiresAt
	}
	return toJSON(userPayload{Sub: sub, Email: email, Exp: exp})
}

// LoginStart begins the split loopback login used on mobile, where the engine
// cannot open a browser itself. It binds the loopback + builds the authorize
// URL (via sso.StartLogin) and returns that URL for the caller (the Dart layer)
// to open with url_launcher; the loopback keeps listening. Call LoginWait to
// block for the redirect and finish. Desktop keeps using Login().
func (e *Engine) LoginStart() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	p, err := sso.StartLogin(e.serverURL)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	e.mu.Lock()
	e.pendingLogin = p
	e.mu.Unlock()
	return p.AuthURL(), nil
}

// LoginWait blocks for the loopback callback of an in-flight LoginStart, caches
// the tokens, and returns {sub,email,exp} as a JSON string — the same shape as
// Login(). Errors if no login is in progress.
func (e *Engine) LoginWait() (string, error) {
	e.mu.Lock()
	p := e.pendingLogin
	e.pendingLogin = nil
	e.mu.Unlock()
	if p == nil {
		return "", fmt.Errorf("no login in progress")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.loginTimeout)
	defer cancel()

	tok, err := p.Wait(ctx)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	if err := authstore.Save(e.configDir, tok); err != nil {
		return "", fmt.Errorf("saving session: %w", err)
	}
	sub, email, exp, _ := decodeJWTClaims(tok.AccessToken)
	if exp == 0 {
		exp = tok.ExpiresAt
	}
	return toJSON(userPayload{Sub: sub, Email: email, Exp: exp})
}

// Logout clears the cached OAuth session.
func (e *Engine) Logout() error {
	return authstore.Clear(e.configDir)
}

type enrollPayload struct {
	AgentID      string `json:"agent_id"`
	DeviceID     string `json:"device_id"`
	ServerURL    string `json:"server_url,omitempty"`
	ZitiIdentity string `json:"ziti_identity,omitempty"`
}

// SetServer configures the target/enrollment server URL. Mobile installs have no
// pre-seeded agent config, so the app supplies the server (from the enroll code's
// server field, an enroll deep-link, or manual entry) before calling Enroll. A
// successful Enroll then persists it to the config dir for subsequent launches.
func (e *Engine) SetServer(url string) error {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url == "" {
		return fmt.Errorf("server URL is required")
	}
	e.mu.Lock()
	e.serverURL = url
	e.mu.Unlock()
	return nil
}

// Enroll enrolls this device with the (already-resolved) server using the
// supplied one-time enrollment code/token, and returns the result as JSON. The
// server URL is picked up from config on the next NewEngine; here we reuse the
// currently-loaded serverURL if present, otherwise require it be pre-set via
// config (Phase 0 keeps enrollment server-selection in the config dir).
func (e *Engine) Enroll(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("enrollment code is required")
	}
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured for enrollment — call SetServer first (or use the enroll deep-link)")
	}
	agentID, deviceID, zitiIdentity, err := e.be.Enroll(e.logger, e.serverURL, code, e.configDir)
	if err != nil {
		return "", fmt.Errorf("enrollment failed: %w", err)
	}
	// Refresh the cached serverURL from the freshly-written config.
	if cfg, err := agent.LoadConfig(e.configDir); err == nil {
		e.serverURL = strings.TrimRight(cfg.ServerURL, "/")
	}
	return toJSON(enrollPayload{
		AgentID:      agentID,
		DeviceID:     deviceID,
		ServerURL:    e.serverURL,
		ZitiIdentity: zitiIdentity,
	})
}

type postureCheck struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Score    float64 `json:"score"`
	Message  string `json:"message,omitempty"`
}

type posturePayload struct {
	Compliant bool           `json:"compliant"`
	Passed    int            `json:"passed"`
	Failed    int            `json:"failed"`
	Warned    int            `json:"warned"`
	Errored   int            `json:"errored"`
	RanAt     string         `json:"ran_at"`
	Checks    []postureCheck `json:"checks"`
}

// Posture runs the device's configured compliance checks locally and returns a
// summary JSON. It runs the built-in checks through a fresh engine so it does
// not depend on a reachable report endpoint (RunOnce reports to the server,
// which a GUI-only / offline device may not reach); the summary is what a GUI
// shows the user.
func (e *Engine) Posture() (string, error) {
	registry := checks.NewRegistry()
	registry.Register("os_version", &checks.OSVersionCheck{})
	registry.Register("disk_encryption", &checks.DiskEncryptionCheck{})
	registry.Register("process_running", &checks.ProcessCheck{})
	registry.Register("firewall", &checks.FirewallCheck{})
	registry.Register("screen_lock", &checks.ScreenLockCheck{})
	registry.Register("antivirus", &checks.AntivirusCheck{})
	registry.Register("domain_joined", &checks.DomainCheck{})
	registry.Register("patch_level", &checks.PatchLevelCheck{})
	registry.Register("integrity", &checks.IntegrityCheck{})
	registry.Register("agent_version", &checks.AgentVersionCheck{})

	eng := checks.NewEngine(registry)
	cfg := agent.DefaultServerConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	results := eng.RunChecks(ctx, cfg.Checks)

	out := posturePayload{RanAt: time.Now().UTC().Format(time.RFC3339)}
	for _, r := range results {
		pc := postureCheck{Type: r.CheckType, Severity: r.Severity}
		if r.Result != nil {
			pc.Status = string(r.Result.Status)
			pc.Score = r.Result.Score
			pc.Message = r.Result.Message
			switch r.Result.Status {
			case checks.StatusPass:
				out.Passed++
			case checks.StatusFail:
				out.Failed++
			case checks.StatusWarn:
				out.Warned++
			default:
				out.Errored++
			}
		}
		out.Checks = append(out.Checks, pc)
	}
	out.Compliant = out.Failed == 0 && out.Errored == 0
	return toJSON(out)
}

// PamList returns the caller's launchable PAM connections as a JSON array.
func (e *Engine) PamList() (string, error) {
	token, err := e.userToken()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entries, err := e.be.PamList(ctx, e.serverURL, token)
	if err != nil {
		return "", fmt.Errorf("listing PAM entries: %w", err)
	}
	if entries == nil {
		entries = []desktoppam.Entry{}
	}
	return toJSON(entries)
}

// PamConnect launches a brokered session for entryID and returns the connect
// URL the GUI opens in the browser.
func (e *Engine) PamConnect(entryID string) (string, error) {
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return "", fmt.Errorf("entry_id is required")
	}
	token, err := e.userToken()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	url, err := e.be.PamConnect(ctx, e.serverURL, token, entryID)
	if err != nil {
		return "", fmt.Errorf("connecting PAM entry: %w", err)
	}
	return url, nil
}

// PamRequest files an access request for an approval-gated entry.
func (e *Engine) PamRequest(entryID, reason string) error {
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return fmt.Errorf("entry_id is required")
	}
	token, err := e.userToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return e.be.PamRequest(ctx, e.serverURL, token, entryID, reason)
}

// ZitiDial brings up (or reuses) a loopback bridge to the named Ziti service and
// returns the local 127.0.0.1:port address a plain-TCP client connects to. The
// bridge is kept alive until ZitiClose(service) is called.
func (e *Engine) ZitiDial(service string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", fmt.Errorf("service is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if b, ok := e.bridges[service]; ok {
		return b.localAddr, nil // idempotent: reuse the existing bridge
	}

	identityFile := e.zitiIdentityPath()
	if cfg, err := agent.LoadConfig(e.configDir); err == nil && cfg.ZitiIdentityFile != "" {
		identityFile = cfg.ZitiIdentityFile
	}
	if !fileExists(identityFile) {
		return "", fmt.Errorf("no Ziti identity at %s: enroll a Ziti identity first", identityFile)
	}

	d, err := e.newDialer(identityFile)
	if err != nil {
		return "", fmt.Errorf("load ziti identity: %w", err)
	}
	localAddr, stop, err := d.Bridge(service)
	if err != nil {
		d.Close()
		return "", fmt.Errorf("bridge %q: %w", service, err)
	}
	e.bridges[service] = &bridge{localAddr: localAddr, stop: stop, dialer: d}
	return localAddr, nil
}

// ZitiClose tears down the loopback bridge for the named service.
func (e *Engine) ZitiClose(service string) error {
	service = strings.TrimSpace(service)
	e.mu.Lock()
	b, ok := e.bridges[service]
	if ok {
		delete(e.bridges, service)
	}
	e.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active bridge for service %q", service)
	}
	if b.stop != nil {
		b.stop()
	}
	if b.dialer != nil {
		b.dialer.Close()
	}
	return nil
}

// closeAll stops every active bridge (called on server shutdown).
func (e *Engine) closeAll() {
	e.mu.Lock()
	bridges := e.bridges
	e.bridges = map[string]*bridge{}
	e.mu.Unlock()
	for _, b := range bridges {
		if b.stop != nil {
			b.stop()
		}
		if b.dialer != nil {
			b.dialer.Close()
		}
	}
}

// ---- internal helpers (never cross the gomobile boundary) --------------

// userToken loads the cached OAuth access token, erroring if not signed in.
func (e *Engine) userToken() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	tok, err := authstore.Load(e.configDir)
	if err != nil {
		return "", fmt.Errorf("loading session: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return "", errNotAuthenticated
	}
	return tok.AccessToken, nil
}

func (e *Engine) zitiIdentityPath() string {
	return filepath.Join(e.configDir, "ziti-identity.json")
}

// errNotAuthenticated is returned when a token-requiring method is called
// before Login. The server maps it to HTTP 401.
var errNotAuthenticated = fmt.Errorf("not authenticated: sign in first")

func toJSON(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// decodeJWTClaims best-effort-decodes the sub/email/exp claims from a JWT
// access token without verifying the signature (display-only; the server
// authorizes for real). Returns ok=false if the token is not a decodable JWT.
func decodeJWTClaims(token string) (sub, email string, exp int64, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", 0, false
	}
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Exp               int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", 0, false
	}
	email = claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}
	return claims.Sub, email, claims.Exp, true
}
