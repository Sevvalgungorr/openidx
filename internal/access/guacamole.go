// Package access - Apache Guacamole integration for clientless remote access (SSH/RDP/VNC/Telnet)
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// ErrSharingUnsupported is returned by ShareActiveConnection when the Guacamole
// server does not support connection sharing (non-2xx or missing endpoint).
var ErrSharingUnsupported = errors.New("guacamole: connection sharing not supported by this server")

// GuacamoleClient communicates with the Apache Guacamole REST API to manage connections
type GuacamoleClient struct {
	baseURL string
	// publicBaseURL is the browser-facing base for connect URLs handed back to the
	// client (e.g. https://openidx.tdv.org:8443/guacamole behind a reverse proxy).
	// baseURL stays the server-side/internal endpoint the access service dials for
	// the REST API. Falls back to baseURL when unset.
	publicBaseURL string
	username      string
	password      string
	authToken     string
	dataSource    string
	httpClient    *resilience.ResilientHTTPClient
	db            *database.PostgresDB
	logger        *zap.Logger
	// tokenCipher encrypts the pooled Guacamole session token at rest (write-only
	// DB copy; the in-memory pool holds plaintext for reuse).
	tokenCipher *secretcrypt.Cipher

	// Connection pool
	pool           *ConnectionPool
	activeSessions int

	// perUserIdentities enables the per-user broker identity path (PAM hardening):
	// broker sessions under a standing non-admin per-user Guacamole account instead
	// of handing the admin token to the browser. From cfg.GuacamolePerUserIdentities.
	perUserIdentities bool
	// component is the broker label ("guacamole" | "guacamole-ziti"), used as the
	// guacamole_users.broker discriminator so each broker keeps its own account set.
	component string
}

// GuacConnection represents a Guacamole connection
type GuacConnection struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	RouteID               string            `json:"route_id"`
	GuacamoleConnectionID string            `json:"guacamole_connection_id"`
	Protocol              string            `json:"protocol"`
	Hostname              string            `json:"hostname"`
	Port                  int               `json:"port"`
	Parameters            map[string]string `json:"parameters"`
	VaultSecretID         string            `json:"vault_secret_id,omitempty"`
	InjectUsername        string            `json:"inject_username,omitempty"`
	RequireApproval       bool              `json:"require_approval"`
	RecordSession         bool              `json:"record_session"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// ConnectionPool manages reusable Guacamole connection tokens
type ConnectionPool struct {
	maxConnections int
	idleTimeout    time.Duration
	connections    map[string]*PooledConnection
}

// PooledConnection represents a pooled Guacamole connection token
type PooledConnection struct {
	Token        string    `json:"token"`
	ConnectionID string    `json:"connection_id"`
	UserID       string    `json:"user_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	UseCount     int       `json:"use_count"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxConnections int, idleTimeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		maxConnections: maxConnections,
		idleTimeout:    idleTimeout,
		connections:    make(map[string]*PooledConnection),
	}
}

// NewGuacamoleClient creates and authenticates the "direct" PAM session broker
// client (guacd dials targets directly) from the GUACAMOLE_* config.
func NewGuacamoleClient(cfg *config.Config, db *database.PostgresDB, logger *zap.Logger) (*GuacamoleClient, error) {
	return newGuacamoleClient(cfg, db, logger, "guacamole",
		cfg.GuacamoleURL, cfg.GuacamolePublicURL, cfg.GuacamoleAdminUser, cfg.GuacamoleAdminPassword)
}

// NewGuacamoleZitiClient creates and authenticates the dedicated OpenZiti PAM
// session broker client (guacd colocated with a ziti-tunnel) from the
// GUACAMOLE_ZITI_* config. Entries with reach_mode='ziti' are launched through
// this broker so guacd reaches the target over the overlay.
func NewGuacamoleZitiClient(cfg *config.Config, db *database.PostgresDB, logger *zap.Logger) (*GuacamoleClient, error) {
	return newGuacamoleClient(cfg, db, logger, "guacamole-ziti",
		cfg.GuacamoleZitiURL, cfg.GuacamoleZitiPublicURL, cfg.GuacamoleZitiAdminUser, cfg.GuacamoleZitiAdminPassword)
}

// guacHTTPTimeout bounds every Guacamole REST call (default 8s) so a slow/hung
// broker can't stall a user's PAM connect.
func guacHTTPTimeout(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.GuacamoleHTTPTimeoutSeconds > 0 {
		return time.Duration(cfg.GuacamoleHTTPTimeoutSeconds) * time.Second
	}
	return 8 * time.Second
}

// guacBreaker returns a circuit breaker so a persistently failing broker fails
// fast (on 5xx/timeouts; 4xx pass through) instead of hanging every request.
func guacBreaker(component string, logger *zap.Logger) *resilience.CircuitBreaker {
	return resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
		Name:         "guacamole-" + component,
		Threshold:    5,
		ResetTimeout: 15 * time.Second,
		Logger:       logger.With(zap.String("component", "guacamole-circuit-breaker")),
	})
}

// newGuacamoleClient is the shared constructor for a Guacamole broker client at
// an explicit URL/credential (so the direct and ziti brokers are independent
// endpoints with independent admin credentials).
func newGuacamoleClient(cfg *config.Config, db *database.PostgresDB, logger *zap.Logger, component, baseURL, publicBaseURL, adminUser, adminPassword string) (*GuacamoleClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("%s URL is not configured", component)
	}
	if publicBaseURL == "" {
		publicBaseURL = baseURL
	}

	tokenCipher, err := secretcrypt.New(cfg.EncryptionKey)
	if err != nil {
		logger.Warn("Guacamole pool tokens will NOT be encrypted at rest; set a 32-byte ENCRYPTION_KEY to enable", zap.Error(err))
		tokenCipher = secretcrypt.NewNoop()
	}

	gc := &GuacamoleClient{
		baseURL:           strings.TrimRight(baseURL, "/"),
		publicBaseURL:     strings.TrimRight(publicBaseURL, "/"),
		username:          adminUser,
		password:          adminPassword,
		httpClient:        resilience.NewResilientHTTPClient(&http.Client{Timeout: guacHTTPTimeout(cfg)}, guacBreaker(component, logger)),
		db:                db,
		logger:            logger.With(zap.String("component", component)),
		tokenCipher:       tokenCipher,
		perUserIdentities: cfg.GuacamolePerUserIdentities,
		component:         component,
	}

	// Authenticate to get a token
	if err := gc.authenticate(adminUser, adminPassword); err != nil {
		return nil, fmt.Errorf("failed to authenticate to %s: %w", component, err)
	}

	gc.logger.Info("Authenticated to Apache Guacamole", zap.String("url", gc.baseURL))
	return gc, nil
}

func (gc *GuacamoleClient) authenticate(username, password string) error {
	data := url.Values{
		"username": {username},
		"password": {password},
	}

	req, err := http.NewRequest(http.MethodPost, gc.baseURL+"/api/tokens", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("guacamole auth request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := gc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("guacamole auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("guacamole auth failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AuthToken  string `json:"authToken"`
		DataSource string `json:"dataSource"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode guacamole auth response: %w", err)
	}

	gc.authToken = result.AuthToken
	gc.dataSource = result.DataSource
	return nil
}

// apiRequest makes an authenticated request to the Guacamole API
func (gc *GuacamoleClient) apiRequest(method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reqBody = strings.NewReader(string(data))
	}

	apiURL := fmt.Sprintf("%s/api/session/data/%s%s?token=%s",
		gc.baseURL, gc.dataSource, path, gc.authToken)

	req, err := http.NewRequest(method, apiURL, reqBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gc.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("guacamole API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	// Re-authenticate on 403 and retry once
	if resp.StatusCode == http.StatusForbidden {
		if err := gc.authenticate(gc.username, gc.password); err != nil {
			return respBody, resp.StatusCode, fmt.Errorf("re-authentication failed: %w", err)
		}

		apiURL = fmt.Sprintf("%s/api/session/data/%s%s?token=%s",
			gc.baseURL, gc.dataSource, path, gc.authToken)
		if body != nil {
			data, _ := json.Marshal(body)
			reqBody = strings.NewReader(string(data))
		}
		req, _ = http.NewRequest(method, apiURL, reqBody)
		req.Header.Set("Content-Type", "application/json")

		resp, err = gc.httpClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(resp.Body)
	}

	return respBody, resp.StatusCode, nil
}

// CreateConnection creates a new connection in Guacamole
func (gc *GuacamoleClient) CreateConnection(name, protocol, hostname string, port int, params map[string]string) (string, error) {
	if params == nil {
		params = make(map[string]string)
	}
	params["hostname"] = hostname
	params["port"] = fmt.Sprintf("%d", port)

	// Set protocol-specific defaults
	switch protocol {
	case "ssh":
		if _, ok := params["color-scheme"]; !ok {
			params["color-scheme"] = "green-black"
		}
		if _, ok := params["font-size"]; !ok {
			params["font-size"] = "14"
		}
	case "rdp":
		if _, ok := params["security"]; !ok {
			params["security"] = "nla"
		}
		if _, ok := params["ignore-cert"]; !ok {
			params["ignore-cert"] = "true"
		}
	case "vnc":
		// VNC defaults are fine
	}

	body := map[string]interface{}{
		"name":       name,
		"protocol":   protocol,
		"parameters": params,
		"attributes": map[string]string{
			"max-connections":          "10",
			"max-connections-per-user": "3",
		},
	}

	respData, statusCode, err := gc.apiRequest("POST", "/connections", body)
	if err != nil {
		return "", fmt.Errorf("failed to create guacamole connection: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status %d creating guacamole connection: %s", statusCode, string(respData))
	}

	var resp struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse guacamole connection response: %w", err)
	}

	gc.logger.Info("Created Guacamole connection",
		zap.String("name", name),
		zap.String("protocol", protocol),
		zap.String("identifier", resp.Identifier))

	return resp.Identifier, nil
}

// DeleteConnection removes a connection from Guacamole
func (gc *GuacamoleClient) DeleteConnection(connID string) error {
	_, statusCode, err := gc.apiRequest("DELETE", "/connections/"+connID, nil)
	if err != nil {
		return fmt.Errorf("failed to delete guacamole connection: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent && statusCode != http.StatusNotFound {
		return fmt.Errorf("unexpected status %d deleting guacamole connection", statusCode)
	}

	gc.logger.Info("Deleted Guacamole connection", zap.String("identifier", connID))
	return nil
}

// UpdateConnection updates an existing Guacamole connection
func (gc *GuacamoleClient) UpdateConnection(connID, name, protocol, hostname string, port int, params map[string]string) error {
	if params == nil {
		params = make(map[string]string)
	}
	params["hostname"] = hostname
	params["port"] = fmt.Sprintf("%d", port)

	body := map[string]interface{}{
		"identifier": connID,
		"name":       name,
		"protocol":   protocol,
		"parameters": params,
	}

	_, statusCode, err := gc.apiRequest("PUT", "/connections/"+connID, body)
	if err != nil {
		return fmt.Errorf("failed to update guacamole connection: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d updating guacamole connection", statusCode)
	}

	return nil
}

// GetConnectionURLForClient is GetConnectionURL but binds the session token to
// the end-user's client IP, so the broker (with RemoteIpValve enabled) records
// the real client — not the access service — as the session's remote host.
// Every session is still brokered as the shared admin account; only the
// recorded source address changes. Falls back to the shared-token URL when the
// client IP is unknown or a fresh token can't be minted.
func (gc *GuacamoleClient) GetConnectionURLForClient(connID, clientIP string) string {
	if clientIP != "" {
		if token, err := gc.mintSessionToken(clientIP); err == nil && token != "" {
			return fmt.Sprintf("%s/#/client/%s?token=%s", gc.publicBaseURL, connID, token)
		} else if err != nil {
			gc.logger.Warn("GetConnectionURLForClient: token mint failed; using shared token",
				zap.Error(err))
		}
	}
	return gc.GetConnectionURL(connID)
}

// mintSessionTokenAs authenticates to Guacamole as an arbitrary account (the
// per-user broker identity), tagging the request with the end-user's client IP
// via X-Forwarded-For so the broker's RemoteIpValve attributes the resulting
// session to the real client. Returns a fresh auth token scoped to that
// account's permissions (distinct from the long-lived shared gc.authToken).
// A blank clientIP omits the header (management calls, e.g. share-key minting).
func (gc *GuacamoleClient) mintSessionTokenAs(username, password, clientIP string) (string, error) {
	data := url.Values{"username": {username}, "password": {password}}
	req, err := http.NewRequest(http.MethodPost, gc.baseURL+"/api/tokens", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := gc.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("guacamole token mint: HTTP %d", resp.StatusCode)
	}
	var result struct {
		AuthToken string `json:"authToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.AuthToken == "" {
		return "", fmt.Errorf("guacamole token mint: empty/invalid response")
	}
	return result.AuthToken, nil
}

// mintSessionToken mints a token as the broker admin (legacy shared path).
func (gc *GuacamoleClient) mintSessionToken(clientIP string) (string, error) {
	return gc.mintSessionTokenAs(gc.username, gc.password, clientIP)
}

// GetConnectionURLForUser mints a browser token as the per-user account and
// returns the connect URL. The token can reach only connections that account
// holds READ on — never the admin API. Returns "" on failure so callers can
// degrade to the shared-admin URL.
func (gc *GuacamoleClient) GetConnectionURLForUser(connID, guacUser, guacPassword, clientIP string) string {
	tok, err := gc.mintSessionTokenAs(guacUser, guacPassword, clientIP)
	if err != nil || tok == "" {
		gc.logger.Warn("GetConnectionURLForUser: per-user token mint failed",
			zap.String("guac_user", guacUser), zap.Error(err))
		return ""
	}
	return fmt.Sprintf("%s/#/client/%s?token=%s", gc.publicBaseURL, connID, tok)
}

// GetConnectionURL returns the URL to open a Guacamole connection in the browser
func (gc *GuacamoleClient) GetConnectionURL(connID string) string {
	// The Guacamole client URL format: /#/client/{base64(connID + \0 + c + \0 + dataSource)}
	// Simplified: just return the base URL with connection reference
	return fmt.Sprintf("%s/#/client/%s?token=%s", gc.publicBaseURL, connID, gc.authToken)
}

// ---- Database operations for tracking Guacamole connections ----

// SaveGuacConnection persists a Guacamole connection mapping to the database
func (gc *GuacamoleClient) SaveGuacConnection(ctx context.Context, routeID, connID, protocol, hostname string, port int, params map[string]string) error {
	paramsJSON, _ := json.Marshal(params)

	_, err := gc.db.Pool.Exec(ctx,
		`INSERT INTO guacamole_connections (route_id, guacamole_connection_id, protocol, hostname, port, parameters, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		 ON CONFLICT (route_id) DO UPDATE SET
		   guacamole_connection_id=$2, protocol=$3, hostname=$4, port=$5, parameters=$6, updated_at=NOW()`,
		routeID, connID, protocol, hostname, port, paramsJSON)
	if err != nil {
		return fmt.Errorf("failed to save guacamole connection mapping: %w", err)
	}
	return nil
}

// DeleteGuacConnectionByRoute removes the Guacamole connection mapping for a route
func (gc *GuacamoleClient) DeleteGuacConnectionByRoute(ctx context.Context, routeID string) error {
	var connID string
	err := gc.db.Pool.QueryRow(ctx,
		"SELECT guacamole_connection_id FROM guacamole_connections WHERE route_id=$1", routeID).
		Scan(&connID)
	if err != nil {
		return nil // no connection to delete
	}

	// Delete from Guacamole
	gc.DeleteConnection(connID)

	// Delete from database
	gc.db.Pool.Exec(ctx, "DELETE FROM guacamole_connections WHERE route_id=$1", routeID)
	return nil
}

// ListGuacConnections returns all tracked Guacamole connections
func (gc *GuacamoleClient) ListGuacConnections(ctx context.Context) ([]GuacConnection, error) {
	rows, err := gc.db.Pool.Query(ctx,
		`SELECT id, route_id, guacamole_connection_id, protocol, hostname, port, parameters, created_at, updated_at
		 FROM guacamole_connections ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query guacamole connections: %w", err)
	}
	defer rows.Close()

	var conns []GuacConnection
	for rows.Next() {
		var c GuacConnection
		var paramsJSON []byte
		err := rows.Scan(&c.ID, &c.RouteID, &c.GuacamoleConnectionID, &c.Protocol,
			&c.Hostname, &c.Port, &paramsJSON, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			gc.logger.Warn("Failed to scan guacamole connection row", zap.Error(err))
			continue
		}
		if paramsJSON != nil {
			json.Unmarshal(paramsJSON, &c.Parameters)
		}
		if c.Parameters == nil {
			c.Parameters = make(map[string]string)
		}
		conns = append(conns, c)
	}

	if conns == nil {
		conns = []GuacConnection{}
	}
	return conns, nil
}

// ---- Pure helpers ----

// buildInjectedParams assembles the Guacamole connection parameters for a brokered
// session: the credential goes to password (or private-key for ssh_key secrets), the
// username from the connection config, and guacd recording params when recording is on.
func buildInjectedParams(secretType, injectUsername string, cred []byte, record bool, recordingPath, recordingName string) map[string]string {
	params := map[string]string{}
	if len(cred) > 0 {
		if injectUsername != "" {
			params["username"] = injectUsername
		}
		if secretType == "ssh_key" {
			params["private-key"] = string(cred)
		} else {
			params["password"] = string(cred)
		}
	}
	if record {
		params["recording-path"] = recordingPath
		params["recording-name"] = recordingName
		params["recording-include-keys"] = "true"
	}
	return params
}

// ---- HTTP Handlers ----

// handleListGuacamoleConnections lists all Guacamole connections
func (s *Service) handleListGuacamoleConnections(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	conns, err := s.guacamoleClient.ListGuacConnections(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to list guacamole connections", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"connections": conns})
}

// handleGuacamoleConnect returns the URL to connect to a Guacamole session for a
// route, applying credential injection, approval gating, and session recording
// as configured on the guacamole_connections row (PAM M3, Task 7).
func (s *Service) handleGuacamoleConnect(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	routeID := c.Param("routeId")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()
	org, orgErr := orgctx.From(ctx)
	if orgErr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Load the connection row including PAM config columns.
	var connectionPK, connID, protocol, hostname, secretID, injectUser string
	var port int
	var requireApproval, recordSession, requireModerator bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, guacamole_connection_id, protocol, hostname, port,
		        COALESCE(vault_secret_id::text,''), COALESCE(inject_username,''),
		        require_approval, record_session, require_moderator
		 FROM guacamole_connections WHERE route_id=$1`, routeID).
		Scan(&connectionPK, &connID, &protocol, &hostname, &port,
			&secretID, &injectUser, &requireApproval, &recordSession, &requireModerator)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no Guacamole connection found for this route"})
		return
	}

	// Approval gate — single-use, atomic consume.
	if requireApproval {
		ok, err := s.checkAndConsumeApproval(ctx, connectionPK, userID)
		if err != nil {
			s.logger.Error("handleGuacamoleConnect: checkAndConsumeApproval failed",
				zap.String("connection_id", connectionPK), zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval"})
			return
		}
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval"})
			return
		}
	}

	// Moderation gate (PAM C3) — the session must not start until a moderator
	// has joined to watch it live (Teleport-style four-eyes). Unlike the
	// approval gate (decided before the session and consumed here), moderation
	// is a live-presence requirement: block the connect until a moderator has
	// claimed the pending moderation row for this (connection, requester).
	if requireModerator {
		ok, err := s.checkModerationActive(ctx, connectionPK, userID)
		if err != nil {
			s.logger.Error("handleGuacamoleConnect: checkModerationActive failed",
				zap.String("connection_id", connectionPK), zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires an active moderator"})
			return
		}
		if !ok {
			// No moderator has joined yet. Signal the client to request
			// moderation (POST .../moderation) and poll until active.
			c.Header("X-Moderation-Required", "true")
			c.JSON(http.StatusPreconditionRequired, gin.H{
				"error":               "session requires a moderator to join before it can start",
				"moderation_required": true,
			})
			return
		}
	}

	// Build server-side injected params — credential never leaves the server.
	var cred []byte
	var secretType string
	if secretID != "" && s.vaultSvc != nil {
		bctx := orgctx.WithBypassRLS(ctx)
		var err error
		cred, err = s.vaultSvc.Use(bctx, secretID)
		if err != nil {
			s.logger.Warn("handleGuacamoleConnect: vault credential unavailable",
				zap.String("secret_id", secretID), zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "credential unavailable"})
			return
		}

		// Determine which connection parameter to inject based on the secret type.
		// ssh_key → private-key; anything else (password, api_key, …) → password.
		//orgscope:ignore vault_secrets SELECT under bypass-RLS context to determine injection field
		_ = s.db.Pool.QueryRow(bctx,
			`SELECT type FROM vault_secrets WHERE id=$1`, secretID).Scan(&secretType)
	}

	recPath := s.config.GuacamoleRecordingPath
	recName := fmt.Sprintf("%s-%d", connID, time.Now().UnixMilli())
	// recFile is the full filesystem path to the recording artifact that guacd
	// will write. guacd itself receives dir (recording-path) + name (recording-name)
	// separately so that it can rotate/suffix files correctly; we compute the
	// joined path here so the session ledger row stores the exact file to purge
	// rather than the directory root (which would cause RemoveAll to wipe the
	// entire recordings directory — data-loss bug fixed in v60).
	recFile := filepath.Join(recPath, recName)
	params := buildInjectedParams(secretType, injectUser, cred, recordSession, recPath, recName)

	// Zero the plaintext credential slice immediately after buildInjectedParams copies
	// it into the params map. The string values in params are independent copies; we
	// accept that caveat (same approach as M1/M2b elsewhere in this package).
	for i := range cred {
		cred[i] = 0
	}

	if secretID != "" && s.vaultSvc != nil {
		s.logAuditEvent(c, "guacamole_credential_injected", routeID, "guacamole_connection",
			map[string]interface{}{
				"route_id":  routeID,
				"secret_id": secretID,
				"user_id":   userID,
				// Credential value intentionally omitted from audit.
			})
	}

	// Recording side-effects — guacd-native session recording.
	if recordSession {
		if _, err := s.recordGuacSession(ctx, org.ID, connectionPK, userID, recFile); err != nil {
			s.logger.Warn("handleGuacamoleConnect: recordGuacSession failed (best-effort)",
				zap.String("connection_id", connectionPK), zap.Error(err))
		}
	}

	// Push injected params to Guacamole only when there is something to inject.
	if len(params) > 0 {
		if err := s.guacamoleClient.UpdateConnection(connID, connID, protocol, hostname, port, params); err != nil {
			s.logger.Error("handleGuacamoleConnect: UpdateConnection failed",
				zap.String("conn_id", connID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "prepare session"})
			return
		}
	}

	connectURL, _ := s.connectURLForBroker(ctx, s.guacamoleClient, org.ID, userID, connID, realClientIP(c))
	c.JSON(http.StatusOK, gin.H{
		"connect_url":   connectURL,
		"connection_id": connID,
		"route_id":      routeID,
	})
}

// handleSetGuacCredential sets the credential/approval/recording config on an existing guacamole_connections row.
// PUT /guacamole/connections/:routeId/credential (admin-only)
func (s *Service) handleSetGuacCredential(c *gin.Context) {
	routeID := c.Param("routeId")

	var req struct {
		VaultSecretID   string `json:"vault_secret_id"`
		InjectUsername  string `json:"inject_username"`
		RequireApproval bool   `json:"require_approval"`
		RecordSession   bool   `json:"record_session"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Verify the route belongs to this org (guacamole_connections has no org_id; scope via proxy_routes).
	var exists bool
	err = s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM guacamole_connections gc
		              JOIN proxy_routes pr ON pr.id = gc.route_id
		              WHERE gc.route_id = $1 AND pr.org_id = $2)`,
		routeID, org.ID).Scan(&exists)
	if err != nil {
		s.logger.Error("handleSetGuacCredential: route lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up connection"})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "guacamole connection not found for this route"})
		return
	}

	// Validate the vault secret exists in this org (RLS-scoped — request context already carries org_id).
	if req.VaultSecretID != "" {
		var secretExists bool
		//orgscope:ignore RLS on vault_secrets is enforced via the request context's app.org_id setting
		err = s.db.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM vault_secrets WHERE id = $1)`,
			req.VaultSecretID).Scan(&secretExists)
		if err != nil {
			s.logger.Error("handleSetGuacCredential: vault secret lookup failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate vault secret"})
			return
		}
		if !secretExists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "vault secret not found"})
			return
		}
	}

	// guacamole_connections has no org_id; uniqueness is enforced by route_id.
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE guacamole_connections
		    SET vault_secret_id  = NULLIF($1, '')::uuid,
		        inject_username  = $2,
		        require_approval = $3,
		        record_session   = $4,
		        updated_at       = NOW()
		  WHERE route_id = $5`,
		req.VaultSecretID, req.InjectUsername, req.RequireApproval, req.RecordSession, routeID)
	if err != nil {
		s.logger.Error("handleSetGuacCredential: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update connection credential"})
		return
	}

	userID, _ := c.Get("user_id")
	s.logAuditEvent(c, "guacamole_credential_set", routeID, "guacamole_connection", map[string]interface{}{
		"route_id":         routeID,
		"inject_username":  req.InjectUsername,
		"require_approval": req.RequireApproval,
		"record_session":   req.RecordSession,
		"has_secret":       req.VaultSecretID != "",
		"user_id":          userID,
	})

	c.JSON(http.StatusOK, gin.H{"message": "connection credential updated"})
}

// provisionGuacamoleForRoute creates a Guacamole connection when a remote-access route is created/updated
func (s *Service) provisionGuacamoleForRoute(ctx context.Context, route *ProxyRoute) error {
	if s.guacamoleClient == nil {
		return nil
	}

	// Only provision for remote access route types
	if route.RouteType != "ssh" && route.RouteType != "rdp" && route.RouteType != "vnc" && route.RouteType != "telnet" {
		return nil
	}

	if route.RemoteHost == "" || route.RemotePort == 0 {
		return fmt.Errorf("remote_host and remote_port are required for %s routes", route.RouteType)
	}

	connName := fmt.Sprintf("openidx-%s-%s", route.RouteType, route.Name)
	params := map[string]string{}

	connID, err := s.guacamoleClient.CreateConnection(connName, route.RouteType, route.RemoteHost, route.RemotePort, params)
	if err != nil {
		return fmt.Errorf("failed to create guacamole connection: %w", err)
	}

	// Save mapping
	if err := s.guacamoleClient.SaveGuacConnection(ctx, route.ID, connID, route.RouteType, route.RemoteHost, route.RemotePort, params); err != nil {
		return fmt.Errorf("failed to save guacamole connection mapping: %w", err)
	}

	// Update route with connection ID
	if org, oerr := orgctx.From(ctx); oerr == nil {
		s.db.Pool.Exec(ctx,
			"UPDATE proxy_routes SET guacamole_connection_id=$1, updated_at=NOW() WHERE id=$2 AND org_id=$3",
			connID, route.ID, org.ID)
	}

	s.logger.Info("Provisioned Guacamole connection for route",
		zap.String("route_id", route.ID),
		zap.String("connection_id", connID),
		zap.String("protocol", route.RouteType))

	return nil
}

// deprovisionGuacamoleForRoute removes the Guacamole connection when a route is deleted
func (s *Service) deprovisionGuacamoleForRoute(ctx context.Context, routeID string) {
	if s.guacamoleClient == nil {
		return
	}

	if err := s.guacamoleClient.DeleteGuacConnectionByRoute(ctx, routeID); err != nil {
		s.logger.Warn("Failed to deprovision guacamole connection",
			zap.String("route_id", routeID), zap.Error(err))
	}
}

// ---- Connection Pooling Methods ----

// GetPooledConnection returns a reusable connection token from the pool
func (gc *GuacamoleClient) GetPooledConnection(ctx context.Context, connID, userID string) (*PooledConnection, error) {
	if gc.pool == nil {
		gc.pool = NewConnectionPool(100, 15*time.Minute)
	}

	key := connID + ":" + userID

	// Check for existing pooled connection
	if conn, exists := gc.pool.connections[key]; exists {
		if time.Now().Before(conn.ExpiresAt) && time.Since(conn.LastUsedAt) < gc.pool.idleTimeout {
			conn.LastUsedAt = time.Now()
			conn.UseCount++
			gc.logger.Debug("Reusing pooled connection",
				zap.String("connection_id", connID),
				zap.Int("use_count", conn.UseCount))
			return conn, nil
		}
		// Expired or idle, remove from pool
		delete(gc.pool.connections, key)
	}

	// Create new connection token
	token, err := gc.createConnectionToken(connID)
	if err != nil {
		return nil, err
	}

	conn := &PooledConnection{
		Token:        token,
		ConnectionID: connID,
		UserID:       userID,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		UseCount:     1,
		ExpiresAt:    time.Now().Add(30 * time.Minute),
	}

	// Save to pool
	gc.pool.connections[key] = conn

	// Persist to database for durability
	gc.savePooledConnection(ctx, conn)

	gc.logger.Debug("Created new pooled connection",
		zap.String("connection_id", connID))

	return conn, nil
}

func (gc *GuacamoleClient) createConnectionToken(connID string) (string, error) {
	// For Guacamole, we use the auth token which is already obtained
	// The actual connection URL will include the token
	return gc.authToken, nil
}

func (gc *GuacamoleClient) savePooledConnection(ctx context.Context, conn *PooledConnection) {
	// Encrypt the session token in the at-rest DB copy. The in-memory pool keeps
	// the plaintext for reuse; this column is never read back (write-only), so a
	// DB dump can't yield usable session tokens.
	encToken, err := gc.tokenCipher.Encrypt(conn.Token)
	if err != nil {
		gc.logger.Warn("Failed to encrypt pooled connection token", zap.Error(err))
		return
	}
	_, err = gc.db.Pool.Exec(ctx, `
		INSERT INTO guacamole_connection_pool (connection_id, token, user_id, created_at, last_used_at, use_count, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (connection_id) DO UPDATE SET
			token = $2, last_used_at = $5, use_count = $6, expires_at = $7
	`, conn.ConnectionID, encToken, conn.UserID, conn.CreatedAt, conn.LastUsedAt, conn.UseCount, conn.ExpiresAt)
	if err != nil {
		gc.logger.Warn("Failed to save pooled connection", zap.Error(err))
	}
}

// CleanupExpiredConnections removes expired connections from the pool
func (gc *GuacamoleClient) CleanupExpiredConnections(ctx context.Context) int {
	if gc.pool == nil {
		return 0
	}

	now := time.Now()
	removed := 0

	for key, conn := range gc.pool.connections {
		if now.After(conn.ExpiresAt) || now.Sub(conn.LastUsedAt) > gc.pool.idleTimeout {
			delete(gc.pool.connections, key)
			removed++
		}
	}

	// Also cleanup database
	gc.db.Pool.Exec(ctx, `DELETE FROM guacamole_connection_pool WHERE expires_at < NOW()`)

	if removed > 0 {
		gc.logger.Info("Cleaned up expired connections", zap.Int("removed", removed))
	}

	return removed
}

// GetActiveSessionCount returns the number of active sessions
func (gc *GuacamoleClient) GetActiveSessionCount() int {
	return gc.activeSessions
}

// ---- Health Check Methods ----

// CheckHealth verifies Guacamole server connectivity
func (gc *GuacamoleClient) CheckHealth(ctx context.Context) (bool, error) {
	resp, err := gc.httpClient.Get(gc.baseURL + "/api")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500, nil
}

// IsAuthenticated returns whether the client has a valid auth token
func (gc *GuacamoleClient) IsAuthenticated() bool {
	return gc.authToken != ""
}

// ListConnections returns all connections from Guacamole API
func (gc *GuacamoleClient) ListConnections(ctx context.Context) ([]GuacConnection, error) {
	respData, statusCode, err := gc.apiRequest("GET", "/connections", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list connections: HTTP %d", statusCode)
	}

	var connectionsMap map[string]struct {
		Identifier string `json:"identifier"`
		Name       string `json:"name"`
		Protocol   string `json:"protocol"`
	}
	if err := json.Unmarshal(respData, &connectionsMap); err != nil {
		return nil, err
	}

	var connections []GuacConnection
	for _, c := range connectionsMap {
		connections = append(connections, GuacConnection{
			ID:       c.Identifier,
			Name:     c.Name,
			Protocol: c.Protocol,
		})
	}

	return connections, nil
}

// GetConnection returns a specific connection from Guacamole
func (gc *GuacamoleClient) GetConnection(ctx context.Context, connID string) (*GuacConnection, error) {
	respData, statusCode, err := gc.apiRequest("GET", "/connections/"+connID, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("connection not found: HTTP %d", statusCode)
	}

	var conn struct {
		Identifier string            `json:"identifier"`
		Name       string            `json:"name"`
		Protocol   string            `json:"protocol"`
		Parameters map[string]string `json:"parameters"`
	}
	if err := json.Unmarshal(respData, &conn); err != nil {
		return nil, err
	}

	return &GuacConnection{
		ID:         conn.Identifier,
		Name:       conn.Name,
		Protocol:   conn.Protocol,
		Parameters: conn.Parameters,
	}, nil
}

// ValidateConnection checks if a connection is valid and can be used
func (gc *GuacamoleClient) ValidateConnection(ctx context.Context, connID string) (bool, error) {
	_, err := gc.GetConnection(ctx, connID)
	if err != nil {
		return false, err
	}
	return true, nil
}

// CreateConnection (context version) creates a new connection with context
func (gc *GuacamoleClient) CreateConnectionCtx(ctx context.Context, name, protocol string, params map[string]string) (string, error) {
	hostname := params["hostname"]
	portStr := params["port"]
	port := 22
	fmt.Sscanf(portStr, "%d", &port)

	return gc.CreateConnection(name, protocol, hostname, port, params)
}

// DeleteConnection (context version) deletes a connection with context
func (gc *GuacamoleClient) DeleteConnectionCtx(ctx context.Context, connID string) error {
	return gc.DeleteConnection(connID)
}

// GuacamoleSession represents a Guacamole session history entry
type GuacamoleSession struct {
	ConnectionID    string     `json:"connection_id"`
	ConnectionName  string     `json:"connection_name"`
	Protocol        string     `json:"protocol"`
	Username        string     `json:"username"`
	RemoteIP        string     `json:"remote_ip"`
	StartTime       time.Time  `json:"start_time"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	DurationSeconds int        `json:"duration_seconds,omitempty"`
}

// GuacActiveSession represents an active Guacamole connection from the
// activeConnections REST endpoint. The map key (active-connection UUID) is
// promoted into the Identifier field.
type GuacActiveSession struct {
	Identifier           string `json:"identifier"`
	ConnectionIdentifier string `json:"connectionIdentifier"`
	Username             string `json:"username"`
	RemoteHost           string `json:"remoteHost"`
	StartDate            int64  `json:"startDate"`
	// OpenIDXUser is the real end user who launched the session, resolved from
	// OpenIDX's own ledger. Guacamole only knows the shared broker account, so
	// Username above is always that account; this surfaces the actual user.
	OpenIDXUser string `json:"openidx_user,omitempty"`
}

// realClientIP returns the end-user's client address as seen through OpenIDX's
// own reverse proxies: the left-most X-Forwarded-For entry (the original
// client), then X-Real-IP, then gin's ClientIP().
func realClientIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := strings.TrimSpace(c.GetHeader("X-Real-IP")); xr != "" {
		return xr
	}
	return c.ClientIP()
}

// ListActiveSessions returns all currently active Guacamole connections.
// GET /api/session/data/<dataSource>/activeConnections
// The response is a JSON object keyed by active-connection UUID; we flatten
// it into a slice and set Identifier = key.
func (gc *GuacamoleClient) ListActiveSessions(ctx context.Context) ([]GuacActiveSession, error) {
	respData, statusCode, err := gc.apiRequest("GET", "/activeConnections", nil)
	if err != nil {
		return nil, fmt.Errorf("guacamole ListActiveSessions request failed: %w", err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("guacamole ListActiveSessions: unexpected HTTP %d", statusCode)
	}

	var raw map[string]struct {
		ConnectionIdentifier string `json:"connectionIdentifier"`
		Username             string `json:"username"`
		RemoteHost           string `json:"remoteHost"`
		StartDate            int64  `json:"startDate"`
	}
	if err := json.Unmarshal(respData, &raw); err != nil {
		return nil, fmt.Errorf("guacamole ListActiveSessions: failed to parse response: %w", err)
	}

	sessions := make([]GuacActiveSession, 0, len(raw))
	for id, entry := range raw {
		sessions = append(sessions, GuacActiveSession{
			Identifier:           id,
			ConnectionIdentifier: entry.ConnectionIdentifier,
			Username:             entry.Username,
			RemoteHost:           entry.RemoteHost,
			StartDate:            entry.StartDate,
		})
	}
	return sessions, nil
}

// TerminateSession force-terminates an active Guacamole connection by its
// active-connection UUID using the JSON Patch remove operation:
// PATCH /api/session/data/<dataSource>/activeConnections
// Body: [{"op":"remove","path":"/<activeConnID>"}]
func (gc *GuacamoleClient) TerminateSession(ctx context.Context, activeConnID string) error {
	body := []map[string]string{
		{"op": "remove", "path": "/" + activeConnID},
	}
	_, statusCode, err := gc.apiRequest("PATCH", "/activeConnections", body)
	if err != nil {
		return fmt.Errorf("guacamole TerminateSession request failed: %w", err)
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("guacamole TerminateSession: unexpected HTTP %d", statusCode)
	}
	gc.logger.Info("Terminated Guacamole active session",
		zap.String("active_conn_id", activeConnID))
	return nil
}

// ShareActiveConnection mints a read-only sharing link for an active Guacamole
// connection. It follows the Guacamole 1.x sharing-profile approach:
//
//  1. Resolve the active connection's underlying connectionIdentifier from the
//     activeConnID (active-connection UUID) by calling ListActiveSessions.
//  2. POST a read-only sharing profile to /sharingProfiles bound to that
//     connectionIdentifier. If the endpoint returns 404 (feature absent on this
//     Guacamole build/version) or any non-2xx, ErrSharingUnsupported is returned
//     so callers can downgrade gracefully.
//  3. Construct the client share URL using Guacamole's standard client-id
//     encoding for a sharing profile:
//     base64(<sharingProfileIdentifier> + "\x00" + "s" + "\x00" + <dataSource>)
//     giving /#/client/<clientID>?token=<authToken>.
//
// ShareActiveConnection mints a read-only monitor link for a live privileged
// session. Read-only monitoring in Guacamole works via a sharing profile
// (read-only=true) + a one-time share KEY obtained from the active connection's
// sharingCredentials endpoint. That endpoint is restricted to the user who owns
// the active session — and OpenIDX brokers every PAM session as this same admin
// user, so it legitimately owns the tunnel and may mint the key. The returned
// URL (…/#/?key=<key>) authenticates the viewer into the shared, read-only view;
// the key is valid only while the underlying session is active.
//
// Returns ErrSharingUnsupported when the Guacamole server lacks sharing profiles
// (< 1.3 / feature disabled).
func (gc *GuacamoleClient) ShareActiveConnection(ctx context.Context, activeConnID string) (string, error) {
	// Step 1 — resolve the underlying connection for this active session.
	sessions, err := gc.ListActiveSessions(ctx)
	if err != nil {
		return "", fmt.Errorf("guacamole ShareActiveConnection: list active sessions: %w", err)
	}
	var connIdentifier string
	for _, s := range sessions {
		if s.Identifier == activeConnID {
			connIdentifier = s.ConnectionIdentifier
			break
		}
	}
	if connIdentifier == "" {
		return "", fmt.Errorf("guacamole ShareActiveConnection: active connection %q not found (session may have ended)", activeConnID)
	}

	// Step 2 — get-or-create a read-only sharing profile for the connection.
	profileID, err := gc.getOrCreateReadOnlyShareProfile(ctx, connIdentifier)
	if err != nil {
		return "", err
	}

	// Step 3 — mint a one-time read-only share key for the active session.
	key, err := gc.mintShareKey(ctx, activeConnID, profileID)
	if err != nil {
		return "", err
	}

	// Step 4 — the viewer opens the app with ?key=<key>; Guacamole authenticates
	// via the sharing key and auto-connects to the read-only shared view.
	monitorURL := fmt.Sprintf("%s/#/?key=%s", gc.publicBaseURL, url.QueryEscape(key))

	gc.logger.Info("Guacamole read-only monitor link created",
		zap.String("active_conn_id", activeConnID),
		zap.String("connection_identifier", connIdentifier),
		zap.String("sharing_profile_id", profileID))

	return monitorURL, nil
}

// ShareActiveConnectionForOwner is ShareActiveConnection for the per-user path:
// the sharingCredentials endpoint is restricted to the session OWNER, so under
// per-user identities the admin token would 403. It creates the read-only profile
// as admin, then mints the share key using a token minted AS the owner account.
func (gc *GuacamoleClient) ShareActiveConnectionForOwner(ctx context.Context, activeConnID, ownerGuacUser, ownerPw string) (string, error) {
	sessions, err := gc.ListActiveSessions(ctx)
	if err != nil {
		return "", fmt.Errorf("guacamole ShareActiveConnectionForOwner: list active sessions: %w", err)
	}
	var connIdentifier string
	for _, s := range sessions {
		if s.Identifier == activeConnID {
			connIdentifier = s.ConnectionIdentifier
			break
		}
	}
	if connIdentifier == "" {
		return "", fmt.Errorf("guacamole ShareActiveConnectionForOwner: active connection %q not found (session may have ended)", activeConnID)
	}

	profileID, err := gc.getOrCreateReadOnlyShareProfile(ctx, connIdentifier) // admin token
	if err != nil {
		return "", err
	}
	ownerToken, err := gc.mintSessionTokenAs(ownerGuacUser, ownerPw, "")
	if err != nil {
		return "", fmt.Errorf("guacamole ShareActiveConnectionForOwner: owner token mint: %w", err)
	}
	key, err := gc.mintShareKeyAsOwner(ctx, ownerToken, activeConnID, profileID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/#/?key=%s", gc.publicBaseURL, url.QueryEscape(key)), nil
}

// mintShareKeyAsOwner mints the one-time read-only share key using the session
// owner's token (sharingCredentials is owner-restricted).
func (gc *GuacamoleClient) mintShareKeyAsOwner(ctx context.Context, ownerToken, activeConnID, profileID string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/session/data/%s/activeConnections/%s/sharingCredentials/%s?token=%s",
		gc.baseURL, gc.dataSource, url.PathEscape(activeConnID), url.PathEscape(profileID), url.QueryEscape(ownerToken))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := gc.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("guacamole mintShareKeyAsOwner: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("guacamole mintShareKeyAsOwner: HTTP %d", resp.StatusCode)
	}
	var creds struct {
		Values struct {
			Key string `json:"key"`
		} `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil || creds.Values.Key == "" {
		return "", fmt.Errorf("guacamole mintShareKeyAsOwner: no share key returned")
	}
	return creds.Values.Key, nil
}

// getOrCreateReadOnlyShareProfile returns the identifier of a read-only sharing
// profile for the given connection, creating one if absent. The name is
// per-connection (profile names are global in Guacamole), and re-creating an
// existing profile returns 400 "already exists" — which must be reused, not
// treated as a failure. Returns ErrSharingUnsupported when the sharingProfiles
// endpoint is absent (Guacamole < 1.3).
func (gc *GuacamoleClient) getOrCreateReadOnlyShareProfile(ctx context.Context, connIdentifier string) (string, error) {
	profileName := "openidx-readonly-share-" + connIdentifier

	if id, err := gc.findSharingProfile(ctx, profileName, connIdentifier); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}

	body := map[string]interface{}{
		"name":                        profileName,
		"primaryConnectionIdentifier": connIdentifier,
		"parameters":                  map[string]string{"read-only": "true"},
	}
	respData, statusCode, err := gc.apiRequest("POST", "/sharingProfiles", body)
	if err != nil {
		return "", fmt.Errorf("guacamole getOrCreateReadOnlyShareProfile: create failed: %w", err)
	}
	if statusCode == http.StatusNotFound {
		return "", ErrSharingUnsupported
	}
	if statusCode < 200 || statusCode >= 300 {
		// Likely a create race — fall back to lookup.
		if id, lerr := gc.findSharingProfile(ctx, profileName, connIdentifier); lerr == nil && id != "" {
			return id, nil
		}
		return "", ErrSharingUnsupported
	}
	var created struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(respData, &created); err != nil || created.Identifier == "" {
		return "", ErrSharingUnsupported
	}
	return created.Identifier, nil
}

// findSharingProfile returns the identifier of an existing sharing profile named
// name whose primary connection is primaryConnID, or "" if none. Returns
// ErrSharingUnsupported when the endpoint is absent (404).
func (gc *GuacamoleClient) findSharingProfile(ctx context.Context, name, primaryConnID string) (string, error) {
	respData, statusCode, err := gc.apiRequest("GET", "/sharingProfiles", nil)
	if err != nil {
		return "", fmt.Errorf("guacamole findSharingProfile: list failed: %w", err)
	}
	if statusCode == http.StatusNotFound {
		return "", ErrSharingUnsupported
	}
	if statusCode < 200 || statusCode >= 300 {
		return "", nil // can't list — caller will attempt create
	}
	var profiles map[string]struct {
		Identifier                  string `json:"identifier"`
		Name                        string `json:"name"`
		PrimaryConnectionIdentifier string `json:"primaryConnectionIdentifier"`
	}
	if err := json.Unmarshal(respData, &profiles); err != nil {
		return "", nil
	}
	for _, p := range profiles {
		if p.Name == name && p.PrimaryConnectionIdentifier == primaryConnID {
			return p.Identifier, nil
		}
	}
	return "", nil
}

// mintShareKey requests a one-time read-only share key for an active connection
// via GET /activeConnections/{id}/sharingCredentials/{profileID}. The key is
// valid only while the underlying session stays active.
func (gc *GuacamoleClient) mintShareKey(ctx context.Context, activeConnID, profileID string) (string, error) {
	path := fmt.Sprintf("/activeConnections/%s/sharingCredentials/%s",
		url.PathEscape(activeConnID), url.PathEscape(profileID))
	respData, statusCode, err := gc.apiRequest("GET", path, nil)
	if err != nil {
		return "", fmt.Errorf("guacamole mintShareKey: request failed: %w", err)
	}
	if statusCode < 200 || statusCode >= 300 {
		return "", fmt.Errorf("guacamole mintShareKey: HTTP %d", statusCode)
	}
	var creds struct {
		Values struct {
			Key string `json:"key"`
		} `json:"values"`
	}
	if err := json.Unmarshal(respData, &creds); err != nil {
		return "", fmt.Errorf("guacamole mintShareKey: decode: %w", err)
	}
	if creds.Values.Key == "" {
		return "", fmt.Errorf("guacamole mintShareKey: no share key returned")
	}
	return creds.Values.Key, nil
}

// GetSessionHistory retrieves session history from Guacamole
func (gc *GuacamoleClient) GetSessionHistory(ctx context.Context, since *time.Time) ([]GuacamoleSession, error) {
	// Guacamole history API endpoint
	respData, statusCode, err := gc.apiRequest("GET", "/history/connections", nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get session history: HTTP %d", statusCode)
	}

	var historyEntries []struct {
		ConnectionIdentifier string `json:"connectionIdentifier"`
		ConnectionName       string `json:"connectionName"`
		Protocol             string `json:"protocol"`
		Username             string `json:"username"`
		RemoteHost           string `json:"remoteHost"`
		StartDate            int64  `json:"startDate"`
		EndDate              int64  `json:"endDate"`
	}

	if err := json.Unmarshal(respData, &historyEntries); err != nil {
		// If parsing fails, return empty slice
		return []GuacamoleSession{}, nil
	}

	var sessions []GuacamoleSession
	for _, entry := range historyEntries {
		startTime := time.Unix(entry.StartDate/1000, 0)

		// Filter by since if provided
		if since != nil && startTime.Before(*since) {
			continue
		}

		session := GuacamoleSession{
			ConnectionID:   entry.ConnectionIdentifier,
			ConnectionName: entry.ConnectionName,
			Protocol:       entry.Protocol,
			Username:       entry.Username,
			RemoteIP:       entry.RemoteHost,
			StartTime:      startTime,
		}

		if entry.EndDate > 0 {
			endTime := time.Unix(entry.EndDate/1000, 0)
			session.EndTime = &endTime
			session.DurationSeconds = int(endTime.Sub(startTime).Seconds())
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}
