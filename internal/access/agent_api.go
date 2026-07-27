// Package access provides agent enrollment, reporting, and configuration API endpoints.
package access

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// AgentAPIHandler handles HTTP endpoints for agent communication.
type AgentAPIHandler struct {
	logger        *zap.Logger
	db            *database.PostgresDB
	zm            *ZitiManager
	playIntegrity *PlayIntegrityVerifier
}

// NewAgentAPIHandler constructs an AgentAPIHandler with the given logger, database, and ZitiManager.
func NewAgentAPIHandler(logger *zap.Logger, db *database.PostgresDB, zm *ZitiManager) *AgentAPIHandler {
	return &AgentAPIHandler{
		logger: logger,
		db:     db,
		zm:     zm,
	}
}

// SetPlayIntegrityVerifier installs the Play Integrity verifier used by
// HandleReport. Optional — when nil (or unconfigured) HandleReport stores
// agent-supplied tokens unchanged and emits a warning audit so admins know
// they're trusting unverified attestations.
func (h *AgentAPIHandler) SetPlayIntegrityVerifier(v *PlayIntegrityVerifier) {
	h.playIntegrity = v
}

// logAuditEvent emits a structured audit log entry for an agent lifecycle event.
// The log line uses the "AUDIT" message with consistent fields so that log
// aggregation pipelines (e.g. Loki, Elasticsearch) can index and query them.
func (h *AgentAPIHandler) logAuditEvent(action, agentID, outcome, detail string) {
	h.logger.Info("AUDIT",
		zap.String("service", "access-service"),
		zap.String("category", "agent_lifecycle"),
		zap.String("action", action),
		zap.String("agent_id", agentID),
		zap.String("outcome", outcome),
		zap.String("detail", detail),
		zap.Time("timestamp", time.Now().UTC()),
	)
}

// logAuditEventToDB persists an audit record to unified_audit_events when the DB
// is available. Errors are logged as warnings so they never block the caller.
func (h *AgentAPIHandler) logAuditEventToDB(ctx context.Context, action, agentID, outcome, detail string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	details := map[string]interface{}{
		"agent_id": agentID,
		"outcome":  outcome,
		"detail":   detail,
	}
	detailsJSON, _ := json.Marshal(details)
	// user_id must be NULL for agent-lifecycle events: an agent_id is not a
	// users.id, and unified_audit_events.user_id has an FK to users, so passing
	// the agent_id here fails the constraint (the event was silently dropped).
	// The agent_id is preserved in details.agent_id above.
	_, err := h.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, source, event_type, user_id, details, created_at)
		VALUES ($1, 'access-service', $2, NULL, $3, NOW())
	`, uuid.New().String(), action, detailsJSON)
	if err != nil {
		h.logger.Warn("logAuditEventToDB: failed to persist audit event",
			zap.String("action", action),
			zap.String("agent_id", agentID),
			zap.Error(err))
	}
}

// RegisterAgentRoutes registers ALL agent API routes onto the provided router
// group. Callers that want to apply different middleware to the public
// (token / device-credential authenticated) and admin (JWT authenticated)
// surfaces should use RegisterAgentPublicRoutes and RegisterAgentAdminRoutes
// instead. Kept for backward compatibility with tests and earlier callers.
func (h *AgentAPIHandler) RegisterAgentRoutes(r *gin.RouterGroup) {
	h.RegisterAgentPublicRoutes(r)
	h.RegisterAgentAdminRoutes(r)
}

// RegisterAgentPublicRoutes registers endpoints that agents reach BEFORE they
// have a tenant JWT: enrollment (carries an enrollment token), posture report
// (carries X-Agent-ID + auth token), and config (same). These MUST NOT be
// mounted behind the JWKS Auth middleware, since agents authenticate via their
// own credentials.
func (h *AgentAPIHandler) RegisterAgentPublicRoutes(r *gin.RouterGroup) {
	r.POST("/agent/enroll", h.HandleEnroll)
	r.POST("/agent/report", h.HandleReport)
	r.GET("/agent/config", h.HandleConfig)
}

// RegisterAgentAdminRoutes registers endpoints that REQUIRE a valid OpenIDX
// OAuth JWT: enrollment-token CRUD, agent listing / approve / revoke, the
// OAuth-based agent enrollment used by mobile clients, and Android QR /
// APK-info admin helpers. Mount behind middleware.Auth.
func (h *AgentAPIHandler) RegisterAgentAdminRoutes(r *gin.RouterGroup) {
	r.POST("/agent/enroll/oauth", h.HandleEnrollOAuth)
	r.POST("/agent/tokens", h.HandleGenerateToken)
	r.GET("/agent/tokens", h.HandleListTokens)
	r.DELETE("/agent/tokens/:token_id", h.HandleRevokeToken)
	r.GET("/agents", h.HandleListAgents)
	r.DELETE("/agents/:agent_id", h.HandleRevokeAgent)
	r.POST("/agents/:agent_id/approve", h.HandleApproveAgent)
	r.POST("/agent/qr", h.HandleGenerateQR)
	r.GET("/agent/apk-info", h.HandleAPKInfo)
}

// enrollRequest is the optional JSON body accepted by HandleEnroll.
type enrollRequest struct {
	Token          string `json:"token"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Platform       string `json:"platform"`
	FormFactor     string `json:"form_factor"`
	ManagementMode string `json:"management_mode"` // device_owner | profile_owner | unmanaged
	// DeviceFingerprint is a stable per-machine identifier (e.g. Windows
	// MachineGuid, else a hostname-derived fallback). When present, enrollment
	// reuses the existing agent_id/auth_token for that device instead of minting
	// a new row on every install — so one physical machine maps to one agent.
	DeviceFingerprint string `json:"device_fingerprint"`
}

// enrollResponse is returned by HandleEnroll on success.
type enrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
}

// normalizePlatform maps caller-supplied platform strings to the canonical set
// stored in enrolled_agents.platform. Anything unrecognized becomes "unknown"
// so the column stays well-formed and downstream platform-filtered queries
// remain predictable.
func normalizePlatform(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "linux":
		return "linux"
	case "darwin", "macos":
		return "macos"
	case "windows":
		return "windows"
	case "android":
		return "android"
	case "ios":
		return "ios"
	default:
		return "unknown"
	}
}

// normalizeFormFactor returns the canonical form_factor or "" if unknown so
// callers can leave it unset rather than persist garbage.
func normalizeFormFactor(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "desktop", "laptop", "phone", "tablet", "kiosk", "server":
		return strings.ToLower(strings.TrimSpace(f))
	default:
		return ""
	}
}

// normalizeManagementMode maps the Android management posture to the
// canonical enum stored in enrolled_agents.management_mode. Unknown /
// empty input becomes "" so the column stays NULL rather than holding
// a garbage value (a legacy Go-agent enroll doesn't send this field).
func normalizeManagementMode(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "device_owner", "profile_owner", "unmanaged":
		return strings.ToLower(strings.TrimSpace(m))
	default:
		return ""
	}
}

// issuedAgentCredentials carries everything the caller (HandleEnroll /
// HandleEnrollOAuth) needs to assemble a response after the agent record is
// persisted.
type issuedAgentCredentials struct {
	AgentID     string
	DeviceID    string
	AuthToken   string
	Status      string
	ZitiJWT     string
	ZitiService string
}

// issueAgentCredentials performs the credential-minting half of enrollment
// shared by every enrollment path:
//
//  1. Generate agent_id / device_id / auth_token.
//  2. Persist the enrolled_agents row with platform, form_factor, method, etc.
//  3. Optionally provision a Ziti identity (returning its JWT).
//
// It does NOT validate enrollment tokens or OAuth JWTs; that lives in the
// HTTP handlers, which decide whether to call this helper at all.
func (h *AgentAPIHandler) issueAgentCredentials(
	ctx context.Context,
	req enrollRequest,
	method string,
	enrolledByUserID string,
) issuedAgentCredentials {
	agentID := "agent-" + uuid.New().String()[:8]
	deviceID := "device-" + uuid.New().String()[:8]
	authToken := uuid.New().String()
	authTokenHash := sha256Hex(authToken)
	status := "active"

	platform := normalizePlatform(req.Platform)
	if platform == "unknown" && req.OS != "" {
		platform = normalizePlatform(req.OS)
	}
	formFactor := normalizeFormFactor(req.FormFactor)
	managementMode := normalizeManagementMode(req.ManagementMode)
	isDeviceOwner := managementMode == "device_owner"

	metadata, _ := json.Marshal(map[string]string{
		"hostname":        req.Hostname,
		"os":              req.OS,
		"arch":            req.Arch,
		"platform":        platform,
		"form_factor":     formFactor,
		"management_mode": managementMode,
	})

	if h.db != nil && h.db.Pool != nil {
		// Stable-identity path: if this device has enrolled before (same
		// device_fingerprint), reuse its agent_id/device_id and just rotate the
		// auth token + refresh metadata, instead of creating a duplicate row.
		// This makes re-installs / upgrades idempotent — one physical machine
		// stays one agent. Falls through to a fresh INSERT when the device is
		// new or sends no fingerprint (legacy clients).
		if fp := strings.TrimSpace(req.DeviceFingerprint); fp != "" {
			var existingAgentID, existingDeviceID string
			err := h.db.Pool.QueryRow(ctx, `
                SELECT agent_id, device_id FROM enrolled_agents
                WHERE device_fingerprint = $1
            `, fp).Scan(&existingAgentID, &existingDeviceID)
			if err == nil && existingAgentID != "" {
				_, upErr := h.db.Pool.Exec(ctx, `
                    UPDATE enrolled_agents
                       SET auth_token_hash = $2, status = 'active', metadata = $3,
                           platform = COALESCE(NULLIF($4,''), platform),
                           form_factor = COALESCE(NULLIF($5,''), form_factor),
                           enrollment_method = COALESCE(NULLIF($6,''), enrollment_method),
                           management_mode = COALESCE(NULLIF($7,''), management_mode),
                           is_device_owner = $8, last_seen_at = NOW()
                     WHERE agent_id = $1
                `, existingAgentID, authTokenHash, metadata,
					platform, formFactor, method, managementMode, isDeviceOwner)
				if upErr != nil {
					h.logger.Error("Failed to refresh existing agent enrollment", zap.Error(upErr))
				} else {
					h.logger.Info("Re-enrolled existing device (stable identity)",
						zap.String("agent_id", existingAgentID), zap.String("fingerprint", fp))
					reused := issuedAgentCredentials{
						AgentID:   existingAgentID,
						DeviceID:  existingDeviceID,
						AuthToken: authToken,
						Status:    "active",
					}
					// Provision a Ziti identity on re-enroll too, if the device
					// doesn't have one yet (e.g. it first enrolled before overlay
					// was enabled). Without this, a returning device would never
					// get an overlay identity and remote-support-over-Ziti would
					// stay off for it.
					h.ensureAgentZitiIdentity(ctx, existingAgentID, &reused)
					return reused
				}
			}
		}

		// Use NULLIF so empty string columns don't leak past the platform check;
		// platform stays NULL for legacy callers that omit it.
		var userIDArg interface{}
		if enrolledByUserID != "" {
			userIDArg = enrolledByUserID
		}
		var fpArg interface{}
		if fp := strings.TrimSpace(req.DeviceFingerprint); fp != "" {
			fpArg = fp
		}
		_, err := h.db.Pool.Exec(ctx, `
            INSERT INTO enrolled_agents (
                agent_id, device_id, status, auth_token_hash,
                enrolled_at, compliance_status, metadata,
                platform, form_factor, enrollment_method, enrolled_by_user_id,
                management_mode, is_device_owner, device_fingerprint
            )
            VALUES ($1,$2,$3,$4, NOW(), 'unknown', $5,
                    NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), $9,
                    NULLIF($10,''), $11, $12)
        `, agentID, deviceID, status, authTokenHash, metadata,
			platform, formFactor, method, userIDArg,
			managementMode, isDeviceOwner, fpArg)
		if err != nil {
			h.logger.Error("Failed to persist agent enrollment", zap.Error(err))
		}
	}

	result := issuedAgentCredentials{
		AgentID:   agentID,
		DeviceID:  deviceID,
		AuthToken: authToken,
		Status:    status,
	}

	h.ensureAgentZitiIdentity(ctx, agentID, &result)
	return result
}

// ensureAgentZitiIdentity provisions a Ziti (OpenZiti) identity for the agent
// tagged "openidx-agent" and stamps it on the enrolled_agents row, returning the
// enrollment JWT on the result. No-op when overlay is disabled, the Ziti manager
// is absent, the credential isn't active, or the agent already has an identity.
// Called on both fresh enroll and fingerprint re-enroll so a returning device
// (that first enrolled before overlay was on) still gets an identity.
func (h *AgentAPIHandler) ensureAgentZitiIdentity(ctx context.Context, agentID string, result *issuedAgentCredentials) {
	if result.Status != "active" || h.zm == nil {
		return
	}
	if !agentZitiOverlayEnabled() {
		h.logger.Debug("Ziti overlay for agents disabled; enrolling over HTTPS only "+
			"(set ZITI_AGENT_OVERLAY_ENABLED=true when the controller is reachable from agents)",
			zap.String("agent_id", agentID))
		return
	}
	// If the agent already has a Ziti identity, decide based on whether it has
	// actually completed enrollment. A common case: the identity was created on a
	// prior enroll but the device never consumed the one-time-token (e.g. it
	// couldn't reach the controller), so the OTT is still pending. In that case we
	// must re-hand the device the pending JWT, otherwise it can never enroll. If
	// the identity is already enrolled (no pending OTT), leave it alone.
	if h.db != nil && h.db.Pool != nil {
		var existing string
		if err := h.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(ziti_identity_id,'') FROM enrolled_agents WHERE agent_id = $1`,
			agentID).Scan(&existing); err == nil && existing != "" {
			// The agent has an identity, so it can route the base API over the
			// overlay: always advertise the service, even when already enrolled.
			result.ZitiService = remoteSupportZitiService
			if jwt, jerr := h.zm.GetIdentityEnrollmentJWT(ctx, existing); jerr == nil && jwt != "" {
				result.ZitiJWT = jwt
				h.logger.Info("Re-issued pending Ziti enrollment JWT for agent",
					zap.String("agent_id", agentID), zap.String("ziti_id", existing))
			}
			return
		}
	}
	zitiID, zitiJWT, err := h.zm.CreateIdentity(ctx, agentID, "Device", []string{"openidx-agent"})
	if err != nil {
		// The DB row lost its ziti_identity_id but an identity with this name
		// still exists in the controller (orphan). Delete it and recreate so the
		// device gets a fresh, un-enrolled JWT it can enroll with.
		if strings.Contains(err.Error(), "duplicate value") {
			if orphanID := h.findZitiIdentityByName(ctx, agentID); orphanID != "" {
				if delErr := h.zm.DeleteIdentity(ctx, orphanID); delErr == nil {
					zitiID, zitiJWT, err = h.zm.CreateIdentity(ctx, agentID, "Device", []string{"openidx-agent"})
				} else {
					h.logger.Warn("Failed to delete orphan Ziti identity",
						zap.String("agent_id", agentID), zap.Error(delErr))
				}
			}
		}
		if err != nil {
			h.logger.Warn("Failed to create Ziti identity for agent",
				zap.String("agent_id", agentID), zap.Error(err))
			return
		}
	}
	if h.db != nil && h.db.Pool != nil {
		h.db.Pool.Exec(ctx,
			"UPDATE enrolled_agents SET ziti_identity_id = $1 WHERE agent_id = $2",
			zitiID, agentID)
	}
	result.ZitiJWT = zitiJWT
	result.ZitiService = remoteSupportZitiService
	h.logger.Info("Ziti identity created for agent",
		zap.String("agent_id", agentID), zap.String("ziti_id", zitiID))
}

// findZitiIdentityByName returns the controller-side identity ID whose name
// matches agentID, or "" if none. Used to reclaim an orphaned identity when the
// DB lost the mapping but the controller still holds it. Queries the controller
// with a name filter so it doesn't depend on identity-list paging.
func (h *AgentAPIHandler) findZitiIdentityByName(ctx context.Context, agentID string) string {
	if h.zm == nil {
		return ""
	}
	return h.zm.FindIdentityIDByName(ctx, agentID)
}

// agentZitiOverlayEnabled reports whether newly-enrolled agents should be issued
// a Ziti (OpenZiti) enrollment JWT. This requires the controller to be reachable
// FROM THE AGENT'S NETWORK and to advertise a publicly-resolvable address whose
// cert matches the enrollment signer — a deployment fact only the operator knows.
//
// Defaults to false: a local-dev controller (e.g. advertising a *.localtest.me /
// localhost address, or with its edge port unpublished) cannot complete a remote
// one-time-token enrollment, and handing agents an unusable JWT only surfaces a
// confusing "crypto/rsa: verification error" on every enroll. The agent works
// fully over HTTPS without it. Operators running a publicly-reachable controller
// opt in with ZITI_AGENT_OVERLAY_ENABLED=true.
func agentZitiOverlayEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ZITI_AGENT_OVERLAY_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// HandleEnroll validates the Authorization header, validates the enrollment token
// against agent_enrollment_tokens, persists the new agent to the database,
// optionally creates a Ziti identity, and returns enrollment credentials.
// When the DB is unavailable, it falls back to accepting any non-empty token (dev mode).
func (h *AgentAPIHandler) HandleEnroll(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(401, gin.H{"error": "enrollment token required"})
		return
	}
	// Strip "Bearer " prefix
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	// Parse optional device info from request body.
	var enrollReq enrollRequest
	c.ShouldBindJSON(&enrollReq)

	// Validate enrollment token against the database when configured. The token
	// itself is consumed (marked used) before credentials are minted so a
	// failure to mint cannot leak a still-usable token.
	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		incomingHash := sha256Hex(token)

		var tokenID string
		var expiresAt time.Time
		var usedAt *time.Time
		var revoked bool
		var reusable bool
		err := h.db.Pool.QueryRow(ctx, `
			SELECT id, expires_at, used_at, revoked, reusable
			FROM agent_enrollment_tokens
			WHERE token_hash = $1
		`, incomingHash).Scan(&tokenID, &expiresAt, &usedAt, &revoked, &reusable)
		if err != nil {
			h.logger.Warn("HandleEnroll: enrollment token not found", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid enrollment token"})
			return
		}
		if revoked {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "enrollment token has been revoked"})
			return
		}
		if time.Now().UTC().After(expiresAt) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "enrollment token has expired"})
			return
		}
		// Single-use enforcement is skipped for reusable (fleet/MDM) tokens.
		if !reusable && usedAt != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "enrollment token has already been used"})
			return
		}

		if !reusable {
			// Mark single-use tokens consumed (agent_id stamped post-issue).
			if _, err = h.db.Pool.Exec(ctx, `
				UPDATE agent_enrollment_tokens SET used_at = NOW() WHERE id = $1
			`, tokenID); err != nil {
				h.logger.Warn("HandleEnroll: failed to mark token as used",
					zap.String("token_id", tokenID), zap.Error(err))
			}
		}

		creds := h.issueAgentCredentials(ctx, enrollReq, "token", "")

		// Track the most recent enrolling agent (single-use tokens only; a
		// reusable token enrolls many, so this field is left for the last one).
		if !reusable {
			_, _ = h.db.Pool.Exec(ctx,
				`UPDATE agent_enrollment_tokens SET used_by_agent = $1 WHERE id = $2`,
				creds.AgentID, tokenID)
		}

		writeEnrollResponse(c, creds, "token")
		h.logAuditEvent("agent.enrolled", creds.AgentID, "success", "method=token")
		h.logAuditEventToDB(ctx, "agent.enrolled", creds.AgentID, "success", "method=token")
		return
	}

	// Dev mode: no DB, accept any non-empty token.
	creds := h.issueAgentCredentials(c.Request.Context(), enrollReq, "token", "")
	writeEnrollResponse(c, creds, "token")
	h.logAuditEvent("agent.enrolled", creds.AgentID, "success", "method=token (no-db)")
}

// writeEnrollResponse serializes the agent credentials into the standard
// enrollment response shape that all enrollment paths share.
func writeEnrollResponse(c *gin.Context, creds issuedAgentCredentials, method string) {
	response := gin.H{
		"agent_id":          creds.AgentID,
		"device_id":         creds.DeviceID,
		"auth_token":        creds.AuthToken,
		"status":            creds.Status,
		"enrollment_method": method,
		"enrolled_at":       time.Now().UTC().Format(time.RFC3339),
	}
	if creds.ZitiJWT != "" {
		response["ziti_jwt"] = creds.ZitiJWT
	}
	// Tell the agent which Ziti service fronts the base agent API so it can route
	// config/report/consent over the overlay. Advertised whenever the agent has a
	// Ziti identity (even when re-enrolling without a fresh JWT), so a device that
	// enrolled its identity earlier still learns the service to dial.
	if creds.ZitiService != "" {
		response["ziti_service"] = creds.ZitiService
	}
	c.JSON(http.StatusOK, response)
}

// HandleEnrollOAuth enrolls an agent on behalf of an authenticated OpenIDX
// user. The route MUST sit behind middleware.Auth so that c.Get("user_id")
// returns the OIDC subject of a valid JWT. The agent inherits the user's
// identity for governance lookups (compliance per-user, BYOD flows, etc.).
func (h *AgentAPIHandler) HandleEnrollOAuth(c *gin.Context) {
	userIDRaw, ok := c.Get("user_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id missing from auth context"})
		return
	}
	userID, _ := userIDRaw.(string)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id missing from auth context"})
		return
	}

	var enrollReq enrollRequest
	_ = c.ShouldBindJSON(&enrollReq)

	creds := h.issueAgentCredentials(c.Request.Context(), enrollReq, "oauth", userID)

	// Converge the two device registries: a user-bound enrollment means we know
	// which OpenIDX user owns this machine, so mirror it into the IAM
	// device-trust registry (known_devices) and link the agent row to it. This
	// is the join point that lets device trust (IAM) and device compliance
	// (Ziti posture) be reconciled per physical device. Best-effort: a failure
	// here never blocks enrollment.
	h.linkAgentToKnownDevice(c, creds.AgentID, creds.DeviceID, userID, enrollReq)

	writeEnrollResponse(c, creds, "oauth")

	h.logAuditEvent("agent.enrolled", creds.AgentID, "success", "method=oauth user="+userID)
	h.logAuditEventToDB(c.Request.Context(), "agent.enrolled", creds.AgentID, "success", "method=oauth user="+userID)
}

// linkAgentToKnownDevice upserts a known_devices row for a user-bound agent
// enrollment and links the enrolled_agents row to it (migration v80's
// known_device_id). The fingerprint is namespaced as "agent:<device_id>" so it
// never collides with a browser fingerprint, and the row starts untrusted —
// trust is granted separately by an admin or MDM. No-op (logged) when the
// tenant can't be resolved or the DB is absent.
func (h *AgentAPIHandler) linkAgentToKnownDevice(c *gin.Context, agentID, deviceID, userID string, req enrollRequest) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		h.logger.Debug("agent device link: no tenant context; skipping known_devices mirror",
			zap.String("agent_id", agentID))
		return
	}

	fingerprint := "agent:" + deviceID
	name := req.Hostname
	if name == "" {
		if p := normalizePlatform(req.Platform); p != "unknown" {
			name = p + " agent"
		} else {
			name = "OpenIDX agent"
		}
	}
	userAgent := strings.TrimSpace(strings.Join([]string{req.OS, req.Arch, req.Platform}, " "))

	var knownDeviceID string
	err = h.db.Pool.QueryRow(ctx, `
		INSERT INTO known_devices (id, user_id, fingerprint, name, ip_address, user_agent, trusted, device_type, created_at, org_id)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, false, 'agent', NOW(), $6)
		ON CONFLICT (user_id, fingerprint) DO UPDATE
		SET name = EXCLUDED.name, ip_address = EXCLUDED.ip_address,
		    user_agent = EXCLUDED.user_agent, last_seen_at = NOW(), org_id = EXCLUDED.org_id
		RETURNING id`,
		userID, fingerprint, name, c.ClientIP(), userAgent, org.ID,
	).Scan(&knownDeviceID)
	if err != nil {
		h.logger.Warn("agent device link: known_devices upsert failed",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	if _, err := h.db.Pool.Exec(ctx,
		`UPDATE enrolled_agents SET known_device_id = $1 WHERE agent_id = $2`,
		knownDeviceID, agentID); err != nil {
		h.logger.Warn("agent device link: enrolled_agents update failed",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	h.logger.Info("Linked enrolled agent to IAM known device",
		zap.String("agent_id", agentID), zap.String("known_device_id", knownDeviceID))
}

// sha256Hex returns the lowercase hex-encoded SHA-256 digest of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// agentReport is the JSON body accepted by HandleReport.
type agentReport struct {
	AgentID  string        `json:"agent_id"`
	DeviceID string        `json:"device_id"`
	Results  []checkResult `json:"results"`
}

// checkResult represents a single posture check sent by the agent.
type checkResult struct {
	CheckType string            `json:"check_type"`
	Severity  string            `json:"severity"`
	Result    checkResultDetail `json:"result"`
	RanAt     string            `json:"ran_at"`
}

// checkResultDetail carries the outcome of a posture check.
type checkResultDetail struct {
	Status      string                 `json:"status"`
	Score       float64                `json:"score"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
}

// severityWeight maps severity levels to their scoring weights.
var severityWeight = map[string]float64{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// enforcementAction returns the enforcement action for a given severity and status.
func enforcementAction(severity, status string) string {
	if status != "fail" {
		return "none"
	}
	switch severity {
	case "critical":
		return "revoke"
	case "high":
		return "grace"
	case "medium":
		return "alert"
	default:
		return "none"
	}
}

// bridgeDevicePostureResult mirrors one agent posture result into
// device_posture_results — the table the access-proxy posture enforcement reads
// (agents only write agent_posture_results, so without this every posture check
// fails closed for lack of data). It keys on the enrolling user's Ziti identity
// (ziti_identities.id, a uuid), because the enforcement reader resolves posture
// by the session user's identity, so the bridged row is the one it looks up.
// Best-effort: a failure is logged and never fails the agent report.
func (h *AgentAPIHandler) bridgeDevicePostureResult(ctx context.Context, agentID, checkType, status string, detailsJSON []byte) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	// Bypass RLS: public agent-report callback carries no tenant context; the
	// reads/writes key on the agent's own globally-unique identity.
	ctx = orgctx.WithBypassRLS(ctx)
	var identityID string
	//orgscope:ignore posture bridge resolves the reporting agent's own Ziti identity by globally-unique agent_id (data plane)
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT zi.id::text FROM ziti_identities zi
		JOIN enrolled_agents ea ON ea.enrolled_by_user_id = zi.user_id
		WHERE ea.agent_id = $1 LIMIT 1`, agentID).Scan(&identityID); err != nil {
		h.logger.Debug("posture bridge: no Ziti identity for agent's enrolling user",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	var checkID, orgID string
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT id::text, COALESCE(org_id::text, '') FROM posture_checks
		WHERE check_type = $1 AND enabled ORDER BY id LIMIT 1`, checkType).Scan(&checkID, &orgID); err != nil {
		h.logger.Debug("posture bridge: no enabled posture_check for check_type",
			zap.String("check_type", checkType), zap.Error(err))
		return
	}
	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO device_posture_results (id, identity_id, check_id, passed, details, checked_at, expires_at, org_id)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW() + INTERVAL '24 hours', NULLIF($5,'')::uuid)
		ON CONFLICT (identity_id, check_id) DO UPDATE SET
			passed = EXCLUDED.passed, details = EXCLUDED.details,
			checked_at = NOW(), expires_at = EXCLUDED.expires_at`,
		identityID, checkID, status == "pass", string(detailsJSON), orgID); err != nil {
		h.logger.Warn("posture bridge: failed to write device_posture_results",
			zap.String("agent_id", agentID), zap.String("check_type", checkType), zap.Error(err))
	}
}

// HandleReport accepts a status report from an enrolled agent, persists posture
// results, updates the agent's compliance score, and returns 202 Accepted.
func (h *AgentAPIHandler) HandleReport(c *gin.Context) {
	var report agentReport
	if err := json.NewDecoder(c.Request.Body).Decode(&report); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse body"})
		return
	}

	// Prefer agent_id from the JSON body; fall back to the header.
	agentID := report.AgentID
	if agentID == "" {
		agentID = c.GetHeader("X-Agent-ID")
	}

	h.logger.Info("agent report received",
		zap.String("agent_id", agentID),
		zap.Int("result_count", len(report.Results)),
	)

	type actionEntry struct {
		CheckType string `json:"check_type"`
		Action    string `json:"action"`
	}

	var (
		enforcementActions []actionEntry
		weightSum          float64
		scoreSum           float64
		hasCriticalFail    bool
		hasHighFail        bool
	)

	for _, r := range report.Results {
		// Server-side Play Integrity verification — rewrite r when the
		// posture-check result is a play_integrity token so the persisted
		// row records the decoded verdict (and the strict pass/fail
		// that the policy decided) instead of the opaque agent-supplied
		// token. Other check types pass through untouched.
		if r.CheckType == "play_integrity" {
			r = h.verifyPlayIntegrityResult(c.Request.Context(), agentID, r)
		}

		action := enforcementAction(r.Severity, r.Result.Status)
		enforcementActions = append(enforcementActions, actionEntry{
			CheckType: r.CheckType,
			Action:    action,
		})

		if action == "revoke" {
			hasCriticalFail = true
		}
		if action == "grace" {
			hasHighFail = true
		}

		w := severityWeight[r.Severity]
		if w == 0 {
			w = 1
		}
		weightSum += w
		scoreSum += w * r.Result.Score

		// Persist each posture check result to the database.
		if h.db != nil && h.db.Pool != nil {
			ctx := c.Request.Context()
			detailsJSON, _ := json.Marshal(r.Result.Details)
			enforced := action != "none"
			_, dbErr := h.db.Pool.Exec(ctx, `
				INSERT INTO agent_posture_results
					(agent_id, check_type, status, score, severity, details, message,
					 reported_at, expires_at, enforced, enforcement_action)
				VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW() + INTERVAL '24 hours', $8, $9)
			`, agentID, r.CheckType, r.Result.Status, r.Result.Score, r.Severity,
				string(detailsJSON), r.Result.Message, enforced, action)
			h.bridgeDevicePostureResult(ctx, agentID, r.CheckType, r.Result.Status, detailsJSON)
			if dbErr != nil {
				h.logger.Warn("Failed to persist posture result",
					zap.String("agent_id", agentID),
					zap.String("check_type", r.CheckType),
					zap.Error(dbErr))
			}
		}
	}

	// Compute weighted compliance score (0.0–1.0 range expected from agents).
	var complianceScore float64
	if weightSum > 0 {
		complianceScore = scoreSum / weightSum
	}

	// Determine compliance status.
	complianceStatus := "unknown"
	switch {
	case hasCriticalFail:
		complianceStatus = "non_compliant"
	case hasHighFail:
		complianceStatus = "grace_period"
	case complianceScore >= 0.8:
		complianceStatus = "compliant"
	}

	// Update enrolled_agents with the latest compliance information.
	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		now := time.Now().UTC()
		_, dbErr := h.db.Pool.Exec(ctx, `
			UPDATE enrolled_agents
			SET compliance_score = $1,
			    compliance_status = $2,
			    last_seen_at = $3,
			    last_report_at = $3
			WHERE agent_id = $4
		`, complianceScore, complianceStatus, now, agentID)
		if dbErr != nil {
			h.logger.Warn("Failed to update agent compliance",
				zap.String("agent_id", agentID),
				zap.Error(dbErr))
		}
	}

	h.logAuditEvent("agent.report", agentID, "success", fmt.Sprintf("score=%.2f", complianceScore))
	h.logAuditEventToDB(c.Request.Context(), "agent.report", agentID, "success", fmt.Sprintf("score=%.2f", complianceScore))

	// Drive the phone's Ziti tier from posture: a compliant report grants the
	// `device-trusted` attribute (Tier-2: remote/PAM + admin surfaces), a failing
	// one removes it (back to the Tier-1 minimum). Flag-gated + best-effort so it
	// never fails the report and is inert unless explicitly enabled.
	h.applyPostureDeviceTrust(c.Request.Context(), agentID, complianceStatus)

	c.JSON(http.StatusAccepted, gin.H{
		"status":              "accepted",
		"compliance_score":    complianceScore,
		"enforcement_actions": enforcementActions,
	})
}

// applyPostureDeviceTrust upgrades/downgrades an enrolled device's Ziti tier from
// its latest posture verdict. When posture is compliant the phone's Ziti identity
// gains the `device-trusted` role attribute (the Tier-2 gate the reconciler's
// dial policies require for remote/PAM + admin surfaces); when it is not, the
// attribute is removed so the device falls back to the Tier-1 minimum.
//
// Controlled by config.PostureDeviceTrustGate:
//   - "off"     : no-op (default; posture recorded but never touches Ziti attrs).
//   - "observe" : log the decision but do not modify attributes.
//   - "enforce" : add/remove the attribute on the controller.
//
// Best-effort: any lookup/patch error is logged and swallowed so an agent report
// always succeeds. Idempotent: only patches when the attribute set changes.
func (h *AgentAPIHandler) applyPostureDeviceTrust(ctx context.Context, agentID, complianceStatus string) {
	if h.zm == nil || h.zm.cfg == nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(h.zm.cfg.PostureDeviceTrustGate))
	if mode == "" || mode == "off" {
		return
	}
	if h.db == nil || h.db.Pool == nil {
		return
	}

	// Resolve the reporting agent's Ziti identity (controller id) via its
	// enrolling user, exactly like the posture bridge does.
	rctx := orgctx.WithBypassRLS(ctx)
	var zitiID string
	//orgscope:ignore posture->tier gate resolves the reporting agent's own Ziti identity by globally-unique agent_id (data plane)
	if err := h.db.Pool.QueryRow(rctx, `
		SELECT zi.ziti_id FROM ziti_identities zi
		JOIN enrolled_agents ea ON ea.enrolled_by_user_id = zi.user_id
		WHERE ea.agent_id = $1 LIMIT 1`, agentID).Scan(&zitiID); err != nil {
		h.logger.Debug("posture tier: no Ziti identity for agent's enrolling user",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	// Compliant (no critical/high posture failure) earns device-trust.
	wantTrusted := complianceStatus == "compliant"

	attrs, err := h.zm.GetIdentityRoleAttributes(rctx, zitiID)
	if err != nil {
		h.logger.Debug("posture tier: read identity attributes failed",
			zap.String("ziti_id", sanitizeForLog(zitiID)), zap.Error(err))
		return
	}
	next, changed := deviceTrustAttrs(attrs, wantTrusted)
	if !changed {
		return // already in the desired state
	}

	if mode == "observe" {
		h.logger.Info("posture tier (observe): would change device-trust",
			zap.String("agent_id", agentID),
			zap.String("ziti_id", sanitizeForLog(zitiID)),
			zap.Bool("grant", wantTrusted),
			zap.String("compliance", complianceStatus))
		return
	}

	if err := h.zm.PatchIdentityRoleAttributes(rctx, zitiID, next); err != nil {
		h.logger.Warn("posture tier: patch identity attributes failed",
			zap.String("ziti_id", sanitizeForLog(zitiID)), zap.Error(err))
		return
	}
	h.logger.Info("posture tier: device-trust updated",
		zap.String("agent_id", agentID),
		zap.String("ziti_id", sanitizeForLog(zitiID)),
		zap.Bool("granted", wantTrusted),
		zap.String("compliance", complianceStatus))
}

// deviceTrustAttrs returns the desired role-attribute set after granting or
// revoking the `device-trusted` attribute, plus whether a change is needed. It
// is pure so the tier decision is unit-testable without a controller: given the
// current attributes and whether trust is wanted, it adds/removes exactly the one
// attribute and reports changed=false when the set already matches (idempotent).
func deviceTrustAttrs(attrs []string, wantTrusted bool) (next []string, changed bool) {
	const trustAttr = "device-trusted"
	has := false
	next = make([]string, 0, len(attrs)+1)
	for _, a := range attrs {
		if a == trustAttr {
			has = true
			if !wantTrusted {
				continue // drop it when downgrading
			}
		}
		next = append(next, a)
	}
	if wantTrusted && !has {
		next = append(next, trustAttr)
	}
	return next, has != wantTrusted
}

// verifyPlayIntegrityResult is invoked by HandleReport for every check
// result whose check_type is "play_integrity". It:
//
//  1. Extracts the agent-supplied integrity token from result.details.
//  2. Calls Google's decodeIntegrityToken via the configured verifier.
//  3. Replaces the token in result.details with the decoded verdict
//     (we never persist the raw token — it's a one-shot bearer credential
//     against Google's API).
//  4. Overrides result.status to pass/fail based on the policy stored in
//     posture_checks.parameters for this check_type.
//
// When the verifier isn't configured (dev mode), the original result is
// returned with a `verified=false` marker added to details and an audit
// event so admins notice they're trusting unverified attestations.
func (h *AgentAPIHandler) verifyPlayIntegrityResult(
	ctx context.Context,
	agentID string,
	r checkResult,
) checkResult {
	// Pull the agent-supplied token out of the details map. Anything else
	// in the bag (nonce, version info) is preserved.
	token := ""
	if rawTok, ok := r.Result.Details["token"]; ok {
		if s, ok := rawTok.(string); ok {
			token = s
		}
	}

	// Always strip the raw token from what we persist; it's bearer-style
	// credential material against Google's API and has no value to anyone
	// looking at posture history later.
	delete(r.Result.Details, "token")

	if !h.playIntegrity.Enabled() {
		r.Result.Details["verified"] = false
		r.Result.Details["verifier_status"] = "disabled"
		h.logAuditEvent("agent.play_integrity.unverified", agentID, "warning",
			"verifier not configured")
		return r
	}

	if token == "" {
		r.Result.Details["verified"] = false
		r.Result.Details["verifier_status"] = "missing_token"
		r.Result.Status = "error"
		r.Result.Score = 0
		return r
	}

	verdict, err := h.playIntegrity.Verify(ctx, token)
	if err != nil {
		h.logger.Warn("play integrity verify failed",
			zap.String("agent_id", agentID), zap.Error(err))
		r.Result.Details["verified"] = false
		r.Result.Details["verifier_status"] = "rejected"
		r.Result.Details["verifier_error"] = err.Error()
		r.Result.Status = "fail"
		r.Result.Score = 0
		h.logAuditEvent("agent.play_integrity.rejected", agentID, "denied", err.Error())
		h.logAuditEventToDB(ctx, "agent.play_integrity.rejected", agentID, "denied", err.Error())
		return r
	}

	// Persist the decoded verdict so admins can audit later. Each verdict
	// field becomes its own map entry to keep the on-disk shape flat and
	// queryable.
	r.Result.Details["verified"] = true
	r.Result.Details["verifier_status"] = "ok"
	r.Result.Details["app_recognition_verdict"] = verdict.AppRecognitionVerdict
	r.Result.Details["device_recognition_verdict"] = verdict.DeviceRecognitionVerdict
	r.Result.Details["app_licensing_verdict"] = verdict.AccountActivity
	r.Result.Details["package_name"] = verdict.PackageName
	r.Result.Details["nonce"] = verdict.Nonce
	r.Result.Details["request_timestamp_ms"] = verdict.RequestTimestampMillis

	// Evaluate the policy stored against this check_type. Default policy is
	// the empty one (everything passes) so admins explicitly opt into
	// strictness by editing posture_checks.parameters.
	policy := h.loadIntegrityPolicy(ctx)
	if !policy.Pass(verdict) {
		r.Result.Status = "fail"
		r.Result.Score = 0
		r.Result.Details["policy_failed"] = true
		h.logAuditEvent("agent.play_integrity.policy_failed", agentID, "denied", "")
		h.logAuditEventToDB(ctx, "agent.play_integrity.policy_failed", agentID, "denied", "")
	} else {
		r.Result.Status = "pass"
		r.Result.Score = 1
	}
	return r
}

// loadIntegrityPolicy reads parameters from posture_checks for the
// play_integrity check_type and parses them as an IntegrityPolicy. Returns
// the zero policy on any error so a misconfigured DB row doesn't lock out
// every agent reporting today.
func (h *AgentAPIHandler) loadIntegrityPolicy(ctx context.Context) IntegrityPolicy {
	if h.db == nil || h.db.Pool == nil {
		return IntegrityPolicy{}
	}
	// Bypass RLS: install-wide posture policy loaded during an agent callback
	// that carries no tenant context.
	ctx = orgctx.WithBypassRLS(ctx)
	var raw []byte
	err := h.db.Pool.QueryRow(ctx,
		//orgscope:ignore agent posture-report verification; loads the install-wide play_integrity policy by check_type during an agent callback that carries no tenant context
		`
        SELECT COALESCE(parameters, '{}'::jsonb)
          FROM posture_checks
         WHERE check_type = 'play_integrity'
         LIMIT 1
    `).Scan(&raw)
	if err != nil {
		return IntegrityPolicy{}
	}
	var p IntegrityPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		h.logger.Warn("loadIntegrityPolicy: malformed parameters JSON", zap.Error(err))
		return IntegrityPolicy{}
	}
	return p
}

// agentCheck represents a single posture check in the agent configuration.
type agentCheck struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CheckType string `json:"check_type,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// agentConfigResponse is returned by HandleConfig. KioskPolicy is filled in
// for Android (and future iOS) clients when an enabled kiosk_policies row is
// assigned to the agent or a tag it carries; omitted otherwise so legacy
// (Go) agents that don't understand the field stay happy.
//
// RemoteSupport is filled when an admin has started a session targeting
// this agent but the agent hasn't connected to the signaling channel yet
// (or has reconnected mid-session). The agent uses this block to know
// where to dial the signaling WebSocket.
type agentConfigResponse struct {
	Checks            []agentCheck            `json:"checks"`
	ReportInterval    string                  `json:"report_interval"`
	EnforcementPolicy string                  `json:"enforcement_policy,omitempty"`
	KioskPolicy       *kioskPolicyRow         `json:"kiosk_policy,omitempty"`
	RemoteSupport     *agentRemoteSupportInfo `json:"remote_support,omitempty"`
}

// agentRemoteSupportInfo tells an agent how to join an in-flight session.
// Recording is the wire signal the device uses to upgrade its consent
// banner: when true, the foreground service shows "OpenIDX admin is
// recording this device" instead of the standard "viewing / controlling"
// text.
type agentRemoteSupportInfo struct {
	SessionID  string          `json:"session_id"`
	Mode       string          `json:"mode"`
	WSPath     string          `json:"ws_path"`
	ICEServers json.RawMessage `json:"ice_servers,omitempty"`
	Recording  bool            `json:"recording"`
	// ConsentRequired tells the device it must Allow the session before the
	// admin can view/control; ConsentStatus is the current decision
	// ('pending'|'granted'|'denied'). ConsentPath is where the device POSTs its
	// grant/deny decision.
	ConsentRequired bool   `json:"consent_required"`
	ConsentStatus   string `json:"consent_status,omitempty"`
	ConsentPath     string `json:"consent_path,omitempty"`
	// ZitiService, when non-empty, is the Ziti overlay service the device should
	// dial to reach the signaling broker (zero-trust, no public port). The
	// device opens the same WSPath over that overlay connection. Empty = dial
	// the public WSS via ServerURL (same-LAN / edge fallback).
	ZitiService string `json:"ziti_service,omitempty"`
	// Transport selects the media path: "webrtc" (P2P, default) or "relay"
	// (VP8 frames streamed through the broker over this WS — full-Ziti, no STUN).
	Transport string `json:"transport,omitempty"`
}

// zitiServiceForAgent returns the Ziti overlay service the device should dial
// for remote-support signaling, or "" to use the public WSS. Non-empty only
// when REMOTE_SUPPORT_OVER_ZITI is enabled AND this agent has a provisioned Ziti
// identity (so it can actually dial the overlay).
func (h *AgentAPIHandler) zitiServiceForAgent(ctx context.Context, agentID string) string {
	if !remoteSupportOverZitiEnabled() || h.db == nil || h.db.Pool == nil {
		return ""
	}
	var zitiID string
	err := h.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(ziti_identity_id,'') FROM enrolled_agents WHERE agent_id = $1`,
		agentID).Scan(&zitiID)
	if err != nil || zitiID == "" {
		return ""
	}
	return remoteSupportZitiService
}

// remoteSupportPollInterval is the shortened /agent/config poll cadence used
// while a remote-support session is in flight, so the device notices consent
// prompts and (dis)connect transitions within seconds instead of waiting out
// the normal posture reporting interval.
const remoteSupportPollInterval = "5s"

// baselinePollInterval is the /agent/config cadence used when NO remote-support
// session is active. It must stay short enough that a device notices a NEWLY
// created support session on its own — otherwise, after one session ends the
// interval would revert to a long posture cadence and the operator would have
// to restart the agent before a second session could ever connect. 30s trades
// a little extra config traffic for "just works" reconnects.
const baselinePollInterval = "30s"

// defaultAgentConfig returns the built-in fallback configuration used when no
// agent ID is provided or the database is unavailable.
func defaultAgentConfig() agentConfigResponse {
	return agentConfigResponse{
		Checks: []agentCheck{
			{Name: "os_version", Enabled: true},
			{Name: "disk_encryption", Enabled: true},
			{Name: "process_running", Enabled: true},
		},
		ReportInterval:    baselinePollInterval,
		EnforcementPolicy: "monitor",
	}
}

// StartGracePeriodEnforcer runs a background goroutine that periodically
// checks for expired grace periods and escalates to suspended status.
func (h *AgentAPIHandler) StartGracePeriodEnforcer(ctx context.Context, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.enforceExpiredGracePeriods(ctx)
			}
		}
	}()
	h.logger.Info("Grace period enforcer started", zap.Duration("interval", interval))
}

func (h *AgentAPIHandler) enforceExpiredGracePeriods(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}

	// Find agents with expired grace periods
	rows, err := h.db.Pool.Query(ctx, `
		UPDATE enrolled_agents
		SET status = 'suspended', compliance_status = 'non_compliant'
		WHERE compliance_status = 'grace_period'
		AND last_report_at < NOW() - INTERVAL '24 hours'
		RETURNING agent_id, ziti_identity_id
	`)
	if err != nil {
		h.logger.Error("Failed to enforce grace periods", zap.Error(err))
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var agentID string
		var zitiID *string
		if err := rows.Scan(&agentID, &zitiID); err != nil {
			continue
		}
		h.logger.Warn("Agent suspended: grace period expired",
			zap.String("agent_id", agentID))
		h.logAuditEvent("agent.suspended", agentID, "enforced", "grace period expired")
		h.logAuditEventToDB(ctx, "agent.suspended", agentID, "enforced", "grace period expired")
		count++
	}
	if count > 0 {
		h.logger.Info("Grace period enforcement complete", zap.Int("suspended", count))
	}
}

// HandleConfig returns the agent configuration, taking into account the agent's enrollment status when an X-Agent-ID header (or query parameter) is supplied.
//
// Status-based behaviour:
//   - revoked  → 403 Forbidden
//   - suspended → empty check list, long report interval
//   - pending  → minimal config (os_version only, 1 h interval)
//   - active   → full config built from enabled posture_checks rows
//
// defaultConfigWithSupport returns the default agent config but ALSO embeds an
// in-flight remote-support session pointer (with consent fields) if one is
// active for the agent. Used by the config early-return paths (posture-check
// query error, or no enabled checks) so a device without posture checks can
// still learn about a support session and grant/deny attended-support consent.
func (h *AgentAPIHandler) defaultConfigWithSupport(ctx context.Context, agentID string) agentConfigResponse {
	cfg := defaultAgentConfig()
	if info, ok := findActiveSessionForAgent(ctx, h.db, agentID); ok {
		cfg.RemoteSupport = &agentRemoteSupportInfo{
			SessionID:       info.SessionID,
			Mode:            info.Mode,
			WSPath:          "/api/v1/access/agent/remote-support/sessions/" + info.SessionID + "/ws",
			ICEServers:      info.ICEServers,
			Recording:       info.Recording,
			ConsentRequired: info.ConsentRequired,
			ConsentStatus:   info.ConsentStatus,
			ConsentPath:     "/api/v1/access/agent/remote-support/sessions/" + info.SessionID + "/consent",
			ZitiService:     h.zitiServiceForAgent(ctx, agentID),
			Transport:       info.Transport,
		}
		// Fast-poll while a support session is in flight (see HandleConfig).
		cfg.ReportInterval = remoteSupportPollInterval
	}
	return cfg
}

// Falls back to defaultAgentConfig when no agent ID is given or the DB is nil.
func (h *AgentAPIHandler) HandleConfig(c *gin.Context) {
	// 1. Resolve agent ID from header or query param.
	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		agentID = c.Query("agent_id")
	}

	// 2. Fall back to defaults when no agent ID or DB unavailable.
	if agentID == "" || h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, defaultAgentConfig())
		return
	}

	ctx := c.Request.Context()

	// 3. Query enrolled_agents for the agent's current status AND platform so
	//    we can filter posture_checks to the rows applicable to this client.
	var status string
	var platform *string
	err := h.db.Pool.QueryRow(ctx,
		`SELECT status, platform FROM enrolled_agents WHERE agent_id = $1`, agentID,
	).Scan(&status, &platform)
	if err != nil {
		// Agent not found or DB error — return defaults.
		h.logger.Warn("HandleConfig: could not fetch agent status",
			zap.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusOK, defaultAgentConfig())
		return
	}
	agentPlatform := ""
	if platform != nil {
		agentPlatform = *platform
	}

	// 4. Build response based on status.
	switch status {
	case "revoked":
		h.logAuditEvent("agent.config_denied", agentID, "denied", "agent revoked")
		h.logAuditEventToDB(ctx, "agent.config_denied", agentID, "denied", "agent revoked")
		c.JSON(http.StatusForbidden, gin.H{"error": "agent has been revoked"})
		return

	case "suspended":
		cfg := agentConfigResponse{
			Checks:            []agentCheck{},
			ReportInterval:    "24h",
			EnforcementPolicy: "block",
		}
		c.JSON(http.StatusOK, cfg)
		return

	case "pending":
		cfg := agentConfigResponse{
			Checks: []agentCheck{
				{Name: "os_version", Enabled: true, CheckType: "os_version", Severity: "low"},
			},
			ReportInterval:    "1h",
			EnforcementPolicy: "monitor",
		}
		c.JSON(http.StatusOK, cfg)
		return

	case "active":
		// 5. Query enabled posture checks ordered by severity, filtered to the
		//    agent's platform when one was recorded at enrollment. platforms
		//    is a JSONB array (see migration 202605150002); the ? operator
		//    tests array membership. When platform is unset (legacy Go agents
		//    enrolled before 202605150001), fall back to returning every
		//    enabled check.
		query := `SELECT check_type, parameters, severity
		            FROM posture_checks
		           WHERE enabled = true
		           ORDER BY severity`
		args := []interface{}{}
		if agentPlatform != "" {
			query = `SELECT check_type, parameters, severity
			           FROM posture_checks
			          WHERE enabled = true
			            AND (platforms IS NULL OR platforms ? $1 OR platforms ? 'any')
			          ORDER BY severity`
			args = []interface{}{agentPlatform}
		}
		rows, queryErr := h.db.Pool.Query(ctx, query, args...)
		if queryErr != nil {
			h.logger.Warn("HandleConfig: could not query posture_checks",
				zap.String("agent_id", agentID), zap.Error(queryErr))
			c.JSON(http.StatusOK, h.defaultConfigWithSupport(ctx, agentID))
			return
		}
		defer rows.Close()

		var checks []agentCheck
		for rows.Next() {
			var checkType, severity string
			var parametersJSON []byte
			if scanErr := rows.Scan(&checkType, &parametersJSON, &severity); scanErr != nil {
				h.logger.Warn("HandleConfig: failed to scan posture_check row", zap.Error(scanErr))
				continue
			}
			checks = append(checks, agentCheck{
				Name:      checkType,
				Enabled:   true,
				CheckType: checkType,
				Severity:  severity,
			})
		}
		if rows.Err() != nil {
			h.logger.Warn("HandleConfig: rows iteration error", zap.Error(rows.Err()))
		}

		// Fall back to a defaults-shaped config when no enabled checks exist —
		// but STILL embed an in-flight remote-support session pointer if one is
		// active, otherwise a device with no posture checks could never learn it
		// has a support session (and, for attended support, could never grant
		// consent). checks stays empty; the rest of the config is the default.
		if len(checks) == 0 {
			c.JSON(http.StatusOK, h.defaultConfigWithSupport(ctx, agentID))
			return
		}

		cfg := agentConfigResponse{
			Checks:            checks,
			ReportInterval:    baselinePollInterval,
			EnforcementPolicy: "enforce",
		}

		// Embed the effective kiosk policy (Phase 3). Errors during
		// resolution are non-fatal — they don't break the rest of config
		// delivery, just leave the kiosk_policy field unset.
		if kp, kpErr := resolveEffectiveKioskPolicy(ctx, h.db, agentID); kpErr == nil && kp != nil {
			cfg.KioskPolicy = kp
		} else if kpErr != nil {
			h.logger.Warn("HandleConfig: kiosk policy resolution failed",
				zap.String("agent_id", agentID), zap.Error(kpErr))
		}

		// Phase 4: embed an in-flight remote-support session pointer if one
		// exists for this agent so the device knows where to dial signaling.
		if info, ok := findActiveSessionForAgent(ctx, h.db, agentID); ok {
			cfg.RemoteSupport = &agentRemoteSupportInfo{
				SessionID:       info.SessionID,
				Mode:            info.Mode,
				WSPath:          "/api/v1/access/agent/remote-support/sessions/" + info.SessionID + "/ws",
				ICEServers:      info.ICEServers,
				Recording:       info.Recording,
				ConsentRequired: info.ConsentRequired,
				ConsentStatus:   info.ConsentStatus,
				ConsentPath:     "/api/v1/access/agent/remote-support/sessions/" + info.SessionID + "/consent",
				ZitiService:     h.zitiServiceForAgent(ctx, agentID),
				Transport:       info.Transport,
			}
			// Fast-poll while a support session is in flight so the device
			// picks up the (dis)connect + consent transitions in seconds
			// instead of waiting out the normal posture interval.
			cfg.ReportInterval = remoteSupportPollInterval
		}

		c.JSON(http.StatusOK, cfg)
		return

	default:
		// Unknown status — return defaults.
		c.JSON(http.StatusOK, defaultAgentConfig())
	}
}

// agentRecord holds the fields returned by HandleListAgents.
type agentRecord struct {
	AgentID          string     `json:"agent_id"`
	DeviceID         string     `json:"device_id"`
	Hostname         string     `json:"hostname"`
	Platform         string     `json:"platform"`
	Status           string     `json:"status"`
	ComplianceStatus string     `json:"compliance_status"`
	ComplianceScore  float64    `json:"compliance_score"`
	LastSeenAt       *time.Time `json:"last_seen_at"`
	EnrolledAt       *time.Time `json:"enrolled_at"`
}

// HandleListAgents returns a JSON array of all enrolled agents (admin endpoint).
// When the database is unavailable it returns an empty array.
func (h *AgentAPIHandler) HandleListAgents(c *gin.Context) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []agentRecord{})
		return
	}

	ctx := c.Request.Context()
	rows, err := h.db.Pool.Query(ctx, `
		SELECT agent_id, device_id,
		       COALESCE(metadata->>'hostname',''), COALESCE(platform, metadata->>'platform',''),
		       status, compliance_status, compliance_score, last_seen_at, enrolled_at
		FROM enrolled_agents
		ORDER BY last_seen_at DESC NULLS LAST, enrolled_at DESC
	`)
	if err != nil {
		h.logger.Error("HandleListAgents: failed to query enrolled_agents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list agents"})
		return
	}
	defer rows.Close()

	agents := []agentRecord{}
	for rows.Next() {
		var rec agentRecord
		if scanErr := rows.Scan(
			&rec.AgentID,
			&rec.DeviceID,
			&rec.Hostname,
			&rec.Platform,
			&rec.Status,
			&rec.ComplianceStatus,
			&rec.ComplianceScore,
			&rec.LastSeenAt,
			&rec.EnrolledAt,
		); scanErr != nil {
			h.logger.Warn("HandleListAgents: failed to scan row", zap.Error(scanErr))
			continue
		}
		agents = append(agents, rec)
	}
	if rows.Err() != nil {
		h.logger.Warn("HandleListAgents: rows iteration error", zap.Error(rows.Err()))
	}

	c.JSON(http.StatusOK, agents)
}

// HandleRevokeAgent sets an agent's status to 'revoked' and optionally removes
// its Ziti identity.
func (h *AgentAPIHandler) HandleRevokeAgent(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()

		// Fetch the Ziti identity ID before revoking so we can remove it.
		var zitiIdentityID string
		_ = h.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(ziti_identity_id, '') FROM enrolled_agents WHERE agent_id = $1`,
			agentID,
		).Scan(&zitiIdentityID)

		_, err := h.db.Pool.Exec(ctx,
			`UPDATE enrolled_agents SET status = 'revoked' WHERE agent_id = $1`,
			agentID,
		)
		if err != nil {
			h.logger.Error("HandleRevokeAgent: failed to update status",
				zap.String("agent_id", agentID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke agent"})
			return
		}

		// Remove Ziti identity if available.
		if h.zm != nil && zitiIdentityID != "" {
			if delErr := h.zm.DeleteIdentity(ctx, zitiIdentityID); delErr != nil {
				h.logger.Warn("HandleRevokeAgent: failed to delete Ziti identity",
					zap.String("agent_id", agentID),
					zap.String("ziti_identity_id", zitiIdentityID),
					zap.Error(delErr))
			}
		}
	} else if h.zm != nil {
		// No DB but ZitiManager present — best-effort removal using agentID as identity name.
		if delErr := h.zm.DeleteIdentity(context.Background(), agentID); delErr != nil {
			h.logger.Warn("HandleRevokeAgent: failed to delete Ziti identity (no db)",
				zap.String("agent_id", agentID), zap.Error(delErr))
		}
	}

	h.logger.Info("Agent revoked", zap.String("agent_id", agentID))
	h.logAuditEvent("agent.revoked", agentID, "success", "admin action")
	h.logAuditEventToDB(c.Request.Context(), "agent.revoked", agentID, "success", "admin action")
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "agent_id": agentID})
}

// HandleApproveAgent transitions an agent from 'pending' to 'active' and
// optionally creates a Ziti identity, returning a ziti_jwt if available.
func (h *AgentAPIHandler) HandleApproveAgent(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	response := gin.H{"status": "active", "agent_id": agentID}

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		tag, err := h.db.Pool.Exec(ctx,
			`UPDATE enrolled_agents SET status = 'active' WHERE agent_id = $1 AND status = 'pending'`,
			agentID,
		)
		if err != nil {
			h.logger.Error("HandleApproveAgent: failed to update status",
				zap.String("agent_id", agentID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve agent"})
			return
		}

		// If no rows were updated the agent either doesn't exist or is not pending.
		if tag.RowsAffected() == 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "agent not found or not in pending state"})
			return
		}

		// Create Ziti identity for the newly approved agent.
		if h.zm != nil {
			zitiID, zitiJWT, zitiErr := h.zm.CreateIdentity(ctx, agentID, "Device", []string{"openidx-agent"})
			if zitiErr != nil {
				h.logger.Warn("HandleApproveAgent: failed to create Ziti identity",
					zap.String("agent_id", agentID), zap.Error(zitiErr))
			} else {
				h.db.Pool.Exec(ctx,
					`UPDATE enrolled_agents SET ziti_identity_id = $1 WHERE agent_id = $2`,
					zitiID, agentID)
				response["ziti_jwt"] = zitiJWT
			}
		}
	}

	h.logger.Info("Agent approved", zap.String("agent_id", agentID))
	h.logAuditEvent("agent.approved", agentID, "success", "admin action")
	h.logAuditEventToDB(c.Request.Context(), "agent.approved", agentID, "success", "admin action")
	c.JSON(http.StatusOK, response)
}

// enrollmentTokenRecord is the response shape for list-tokens.
type enrollmentTokenRecord struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at"`
	Revoked     bool       `json:"revoked"`
}

// generateTokenRequest is the optional body for HandleGenerateToken.
type generateTokenRequest struct {
	Description string `json:"description"`
	CreatedBy   string `json:"created_by"`
	// Reusable mints a fleet/MDM bootstrap token: multi-use and long-lived
	// (not consumed on enroll). Use for GPO/Intune silent rollout.
	Reusable bool `json:"reusable"`
}

// HandleGenerateToken creates a new enrollment token, stores its SHA-256 hash,
// and returns the plaintext token to the caller exactly once.
func (h *AgentAPIHandler) HandleGenerateToken(c *gin.Context) {
	var req generateTokenRequest
	// Ignore parse errors — all fields are optional.
	_ = c.ShouldBindJSON(&req)

	plaintext := uuid.New().String()
	hash := sha256Hex(plaintext)
	// Reusable (fleet) tokens are long-lived; single-use tokens expire in 24h.
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	if req.Reusable {
		expiresAt = time.Now().UTC().AddDate(10, 0, 0)
	}

	var tokenID string

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		err := h.db.Pool.QueryRow(ctx, `
			INSERT INTO agent_enrollment_tokens (token_hash, description, created_by, expires_at, reusable)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id
		`, hash, req.Description, req.CreatedBy, expiresAt, req.Reusable).Scan(&tokenID)
		if err != nil {
			h.logger.Error("HandleGenerateToken: failed to insert token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}
	} else {
		// Dev mode — generate a local ID without DB persistence.
		tokenID = uuid.New().String()
	}

	h.logger.Info("Enrollment token generated", zap.String("token_id", tokenID))
	h.logAuditEvent("token.generated", tokenID, "success", "")
	h.logAuditEventToDB(c.Request.Context(), "token.generated", tokenID, "success", "")

	c.JSON(http.StatusOK, gin.H{
		"token":      plaintext,
		"id":         tokenID,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

// androidAPKPath is the on-disk location served by HandleAPKDownload and
// hashed by HandleAPKInfo. Resolved at request time so the file can be
// replaced without restarting the access service.
const androidAPKPath = "deployments/android/openidx-agent.apk"

// generateQRRequest is the body accepted by HandleGenerateQR. ServerURL must
// be the externally-reachable OpenIDX base URL the device will use during
// Android Enterprise provisioning to download the APK and POST /agent/enroll.
type generateQRRequest struct {
	Description  string `json:"description"`
	TTLMinutes   int    `json:"ttl_minutes"`
	ServerURL    string `json:"server_url"`
	PackageName  string `json:"package_name"`
	ReceiverName string `json:"receiver_name"`
}

// HandleGenerateQR creates a one-shot enrollment token and assembles the
// Android Enterprise QR provisioning payload that bundles it. The plaintext
// token is returned alongside the payload so admins can also distribute it
// out-of-band (link, email).
//
// The payload format follows the Android Enterprise spec
// (PROVISIONING_DEVICE_ADMIN_*) so that scanning the QR during factory-reset
// setup installs our APK and triggers OpenIDXDeviceAdminReceiver with the
// extras bundle that drives auto-enrollment.
func (h *AgentAPIHandler) HandleGenerateQR(c *gin.Context) {
	var req generateQRRequest
	_ = c.ShouldBindJSON(&req)

	if req.TTLMinutes <= 0 {
		req.TTLMinutes = 60 // 1h default — long enough to scan and provision.
	}
	if req.ServerURL == "" {
		req.ServerURL = "https://" + c.Request.Host
	}
	if req.PackageName == "" {
		req.PackageName = "com.openidx.agent"
	}
	if req.ReceiverName == "" {
		req.ReceiverName = req.PackageName + "/.admin.OpenIDXDeviceAdminReceiver"
	}

	plaintext := uuid.New().String()
	hash := sha256Hex(plaintext)
	expiresAt := time.Now().UTC().Add(time.Duration(req.TTLMinutes) * time.Minute)
	description := req.Description
	if description == "" {
		description = "Android enrollment QR"
	}

	var tokenID string
	createdBy := ""
	if v, ok := c.Get("user_id"); ok {
		if s, _ := v.(string); s != "" {
			createdBy = s
		}
	}

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		err := h.db.Pool.QueryRow(ctx, `
			INSERT INTO agent_enrollment_tokens (token_hash, description, created_by, expires_at)
			VALUES ($1,$2,$3,$4)
			RETURNING id
		`, hash, description, createdBy, expiresAt).Scan(&tokenID)
		if err != nil {
			h.logger.Error("HandleGenerateQR: failed to insert token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate QR token"})
			return
		}
	} else {
		tokenID = uuid.New().String()
	}

	// Look up the APK SHA-256 so the payload's signature-checksum field is
	// honest. Android refuses to provision if the downloaded APK doesn't match.
	apkURL := strings.TrimRight(req.ServerURL, "/") + "/downloads/openidx-agent.apk"
	apkChecksum := ""
	if sum, err := computeAPKSHA256URLSafe(androidAPKPath); err == nil {
		apkChecksum = sum
	}

	payload := map[string]interface{}{
		"android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":            req.ReceiverName,
		"android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": apkURL,
		"android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM":        apkChecksum,
		"android.app.extra.PROVISIONING_SKIP_ENCRYPTION":                        false,
		"android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED":          true,
		"android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": map[string]string{
			"openidx_server_url":       req.ServerURL,
			"openidx_enrollment_token": plaintext,
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	h.logAuditEvent("token.qr_generated", tokenID, "success", description)
	h.logAuditEventToDB(c.Request.Context(), "token.qr_generated", tokenID, "success", description)

	c.JSON(http.StatusOK, gin.H{
		"id":              tokenID,
		"token":           plaintext,
		"expires_at":      expiresAt.Format(time.RFC3339),
		"server_url":      req.ServerURL,
		"apk_url":         apkURL,
		"apk_checksum":    apkChecksum,
		"qr_payload":      payload,
		"qr_payload_json": string(payloadBytes),
	})
}

// HandleAPKInfo reports the version + checksum of the currently-hosted Android
// agent APK so external installers (CI publishing, MDM relays) can verify
// they have the latest build.
func (h *AgentAPIHandler) HandleAPKInfo(c *gin.Context) {
	checksum, err := computeAPKSHA256URLSafe(androidAPKPath)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "APK not yet published",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"package": "com.openidx.agent",
		"sha256":  checksum,
		"url":     "/downloads/openidx-agent.apk",
	})
}

// HandleAPKDownload serves the hosted Android agent APK. Mounted publicly so
// Android Enterprise provisioning can fetch it during factory-reset setup,
// before any auth context exists.
func (h *AgentAPIHandler) HandleAPKDownload(c *gin.Context) {
	c.Header("Content-Type", "application/vnd.android.package-archive")
	c.Header("Cache-Control", "public, max-age=60")
	c.File(androidAPKPath)
}

// computeAPKSHA256URLSafe returns the URL-safe base64 SHA-256 (no padding) of
// the file at path. This is the exact format Android Enterprise expects for
// PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM.
func computeAPKSHA256URLSafe(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// HandleListTokens returns all enrollment tokens without their hashes.
func (h *AgentAPIHandler) HandleListTokens(c *gin.Context) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []enrollmentTokenRecord{})
		return
	}

	ctx := c.Request.Context()
	rows, err := h.db.Pool.Query(ctx, `
		SELECT id, COALESCE(description, ''), created_at, expires_at, used_at, revoked
		FROM agent_enrollment_tokens
		ORDER BY created_at DESC
	`)
	if err != nil {
		h.logger.Error("HandleListTokens: failed to query tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tokens"})
		return
	}
	defer rows.Close()

	tokens := []enrollmentTokenRecord{}
	for rows.Next() {
		var rec enrollmentTokenRecord
		if scanErr := rows.Scan(
			&rec.ID,
			&rec.Description,
			&rec.CreatedAt,
			&rec.ExpiresAt,
			&rec.UsedAt,
			&rec.Revoked,
		); scanErr != nil {
			h.logger.Warn("HandleListTokens: failed to scan row", zap.Error(scanErr))
			continue
		}
		tokens = append(tokens, rec)
	}
	if rows.Err() != nil {
		h.logger.Warn("HandleListTokens: rows iteration error", zap.Error(rows.Err()))
	}

	c.JSON(http.StatusOK, tokens)
}

// HandleRevokeToken sets a token's revoked flag to true.
func (h *AgentAPIHandler) HandleRevokeToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	if tokenID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token_id is required"})
		return
	}

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		_, err := h.db.Pool.Exec(ctx,
			`UPDATE agent_enrollment_tokens SET revoked = true WHERE id = $1`,
			tokenID,
		)
		if err != nil {
			h.logger.Error("HandleRevokeToken: failed to revoke token",
				zap.String("token_id", tokenID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token"})
			return
		}
	}

	h.logger.Info("Enrollment token revoked", zap.String("token_id", tokenID))
	h.logAuditEvent("token.revoked", tokenID, "success", "admin action")
	h.logAuditEventToDB(c.Request.Context(), "token.revoked", tokenID, "success", "admin action")
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "id": tokenID})
}
