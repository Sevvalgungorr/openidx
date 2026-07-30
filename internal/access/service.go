// Package access provides the identity-aware reverse proxy (Zero Trust Access) for OpenIDX
package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/vault"
)

// ProxyRoute represents a configured proxy route
type ProxyRoute struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	Description           string            `json:"description,omitempty"`
	FromURL               string            `json:"from_url"`
	ToURL                 string            `json:"to_url"`
	PreserveHost          bool              `json:"preserve_host"`
	RequireAuth           bool              `json:"require_auth"`
	AllowedRoles          []string          `json:"allowed_roles,omitempty"`
	AllowedGroups         []string          `json:"allowed_groups,omitempty"`
	PolicyIDs             []string          `json:"policy_ids,omitempty"`
	IdleTimeout           int               `json:"idle_timeout"`
	AbsoluteTimeout       int               `json:"absolute_timeout"`
	CORSAllowedOrigins    []string          `json:"cors_allowed_origins,omitempty"`
	CustomHeaders         map[string]string `json:"custom_headers,omitempty"`
	Enabled               bool              `json:"enabled"`
	Priority              int               `json:"priority"`
	ZitiEnabled           bool              `json:"ziti_enabled"`
	ZitiServiceName       string            `json:"ziti_service_name,omitempty"`
	IDPId                 string            `json:"idp_id,omitempty"`
	RouteType             string            `json:"route_type"`
	RemoteHost            string            `json:"remote_host,omitempty"`
	RemotePort            int               `json:"remote_port,omitempty"`
	ReverifyInterval      int               `json:"reverify_interval"`
	PostureCheckIDs       []string          `json:"posture_check_ids,omitempty"`
	InlinePolicy          string            `json:"inline_policy,omitempty"`
	RequireDeviceTrust    bool              `json:"require_device_trust"`
	AllowedCountries      []string          `json:"allowed_countries,omitempty"`
	MaxRiskScore          int               `json:"max_risk_score"`
	GuacamoleConnectionID string            `json:"guacamole_connection_id,omitempty"`
	LandingPath           string            `json:"landing_path,omitempty"`
	HostingMode           string            `json:"hosting_mode,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// normalizeHostingMode validates a hosting_mode value from the API. An empty
// value defaults to identity (the reconciler then auto-selects hop/direct for
// BrowZer routes — see ZitiReconciler EffectiveMode). Returns ok=false for any
// other value so the handler can reject it with a 400.
func normalizeHostingMode(mode string) (string, bool) {
	switch mode {
	case "":
		return HostingModeIdentity, true
	case HostingModeIdentity, HostingModeDirect, HostingModeHop:
		return mode, true
	default:
		return "", false
	}
}

// ProxySession represents an active proxy session
type ProxySession struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	RouteID           string    `json:"route_id,omitempty"`
	SessionToken      string    `json:"-"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Email             string    `json:"email"`
	Name              string    `json:"name"`
	Roles             []string  `json:"roles"`
	StartedAt         time.Time `json:"started_at"`
	LastActiveAt      time.Time `json:"last_active_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Revoked           bool      `json:"revoked"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	RiskScore         int       `json:"risk_score,omitempty"`
	AuthMethods       []string  `json:"auth_methods,omitempty"`
	Location          string    `json:"location,omitempty"`
	DeviceTrusted     bool      `json:"device_trusted,omitempty"`
}

// Service provides access proxy operations
type Service struct {
	db                   *database.PostgresDB
	redis                *database.RedisClient
	config               *config.Config
	logger               *zap.Logger
	governanceURL        string
	auditURL             string
	sessionSecret        []byte
	oauthIssuer          string
	oauthInternalURL     string // Docker-internal URL for server-to-server calls
	oauthJWKSURL         string
	idpCipher            *secretcrypt.Cipher // decrypts identity_providers.client_secret at rest
	zitiProvider         *ZitiProvider
	zitiReconciler       *ZitiReconciler
	guacamoleClient      *GuacamoleClient // "direct" PAM broker (guacd dials targets directly)
	guacamoleZitiClient  *GuacamoleClient // dedicated OpenZiti PAM broker (guacd + ziti-tunnel)
	featureManager       *FeatureManager
	auditService         *UnifiedAuditService
	browzerTargetManager *BrowZerTargetManager
	healthEngine         *HealthEngine
	apisixConfigPath     string
	agentHandler         *AgentAPIHandler
	remoteSupportHandler *RemoteSupportHandler
	vaultSvc             *vault.Service
	// guacRecordingRing seals guacd recordings at rest (PAM A1). Nil when
	// encryption is unconfigured — the recording download handler then streams
	// plaintext unchanged. Same keyring the sealer worker uses.
	guacRecordingRing *recordingKeyring
}

// handleAgentAPKDownload serves the hosted Android agent APK without auth so
// Android Enterprise provisioning can fetch it during factory-reset setup.
// Delegates to AgentAPIHandler so the path constant lives in one place.
func (s *Service) handleAgentAPKDownload(c *gin.Context) {
	if s.agentHandler == nil {
		c.JSON(503, gin.H{"error": "agent handler not initialized"})
		return
	}
	s.agentHandler.HandleAPKDownload(c)
}

// SetGuacamoleClient sets the "direct" PAM broker (guacd dials targets directly).
func (s *Service) SetGuacamoleClient(gc *GuacamoleClient) {
	s.guacamoleClient = gc
	if s.featureManager != nil {
		s.featureManager.SetGuacamoleClient(gc)
	}
	if s.auditService != nil {
		s.auditService.SetGuacamoleClient(gc)
	}
}

// SetGuacamoleZitiClient wires the dedicated OpenZiti PAM broker. Entries with
// reach_mode='ziti' launch through this broker (its guacd is colocated with a
// ziti-tunnel that carries the target hop over the overlay).
func (s *Service) SetGuacamoleZitiClient(gc *GuacamoleClient) { s.guacamoleZitiClient = gc }

// brokerFor returns the Guacamole broker client a launch should use for the
// given reach mode: the dedicated Ziti broker for 'ziti', otherwise the direct
// broker. Returns nil when the required broker is not configured — the caller
// fails closed rather than dialing a target the wrong way.
func (s *Service) brokerFor(reachMode string) *GuacamoleClient {
	if reachMode == "ziti" {
		return s.guacamoleZitiClient
	}
	return s.guacamoleClient
}

// ziti returns the live OpenZiti manager (nil when disconnected, or when no
// provider was wired — e.g. bare Service construction in tests). All call
// sites read through this accessor so the manager can be swapped at runtime.
func (s *Service) ziti() *ZitiManager {
	if s.zitiProvider == nil {
		return nil
	}
	return s.zitiProvider.Get()
}

// ZitiProvider exposes the shared provider (for the connect/disconnect handlers).
func (s *Service) ZitiProvider() *ZitiProvider { return s.zitiProvider }

// SetZitiProvider wires the shared provider and fans it to the child services so
// a runtime Swap is visible everywhere.
func (s *Service) SetZitiProvider(p *ZitiProvider) {
	s.zitiProvider = p
	if s.featureManager != nil {
		s.featureManager.SetZitiProvider(p)
	}
	if s.auditService != nil {
		s.auditService.SetZitiProvider(p)
	}
}

// SetZitiManager installs a manager into the shared provider (compat shim for
// boot/tests). Creates+fans a provider if one isn't wired yet.
func (s *Service) SetZitiManager(zm *ZitiManager) {
	if s.zitiProvider == nil {
		s.SetZitiProvider(NewZitiProvider())
	}
	s.zitiProvider.Store(zm)
}

// SetFeatureManager sets the feature manager for the service
func (s *Service) SetFeatureManager(fm *FeatureManager) {
	s.featureManager = fm
	if s.zitiProvider != nil {
		fm.SetZitiProvider(s.zitiProvider)
	}
	if s.guacamoleClient != nil {
		fm.SetGuacamoleClient(s.guacamoleClient)
	}
}

// SetZitiReconciler wires the Ziti reconciler so mutation handlers can request
// a converge after changing desired state. No-op safe when nil.
func (s *Service) SetZitiReconciler(r *ZitiReconciler) { s.zitiReconciler = r }

// enqueueReconcile asks the reconciler to converge, if one is running.
func (s *Service) enqueueReconcile() {
	if s.zitiReconciler != nil {
		s.zitiReconciler.Enqueue()
	}
}

// appTileClientID is the deterministic client_id of the Applications launcher
// tile that mirrors a proxy route, so the route appears on the admin console's
// Applications page (which reads `applications`, not `proxy_routes`). Matches
// the one-click publish flow's convention (app_publish.go).
func appTileClientID(routeID string) string { return "proxy-app-" + routeID }

// upsertAppTile keeps a proxy route's Applications launcher tile in sync, so a
// route created or edited directly under Proxy Routes shows on the Applications
// page with working row actions — instead of needing a tile backfilled by hand.
// Same upsert shape the one-click publish flow produces. Best-effort: a tile
// failure must not fail the route mutation.
func (s *Service) upsertAppTile(ctx context.Context, routeID, name, description, fromURL, landingPath string, orgID string) {
	baseURL := strings.TrimRight(fromURL, "/")
	if landingPath == "" {
		landingPath = "/"
	}
	baseURL += landingPath
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled, org_id)
		VALUES ($1, $2, $3, $4, 'proxy', 'proxy', $5, '{}', true, $6)
		ON CONFLICT (client_id) DO UPDATE SET
			name = EXCLUDED.name, description = EXCLUDED.description,
			base_url = EXCLUDED.base_url, enabled = true, updated_at = NOW()`,
		uuid.New().String(), appTileClientID(routeID), name, description, baseURL, orgID)
	if err != nil {
		s.logger.Warn("upsert app tile failed", zap.String("route_id", routeID), zap.Error(err))
	}
}

// deleteAppTile removes the Applications launcher tile for a deleted proxy route.
func (s *Service) deleteAppTile(ctx context.Context, routeID string) {
	if _, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore tile cleanup deletes the route's launcher tile by its globally-unique synthetic client_id
		`DELETE FROM applications WHERE client_id = $1`, appTileClientID(routeID)); err != nil {
		s.logger.Warn("delete app tile failed", zap.String("route_id", routeID), zap.Error(err))
	}
}

// refreshBrowZerEdge reconverges the clientless edge to the current DB state:
// it regenerates the bootstrapper/hop/vhost configs (which also reconciles the
// APISIX BrowZer routes, pruning any keyed to a now-absent or renamed host) and
// triggers a Ziti reconcile. Call after a route mutation (create/update/delete)
// so a deleted route's edge wiring is removed and a renamed route's wiring is
// re-keyed under the new host instead of stranded under the old one.
func (s *Service) refreshBrowZerEdge(ctx context.Context) {
	if s.browzerTargetManager != nil {
		if err := s.browzerTargetManager.RegenerateConfigs(ctx); err != nil {
			s.logger.Warn("refreshBrowZerEdge: regenerate configs failed", zap.Error(err))
		}
	}
	s.enqueueReconcile()
}

// SetHealthEngine wires the relations/integrity doctor engine.
func (s *Service) SetHealthEngine(e *HealthEngine) { s.healthEngine = e }

// SetBrowZerTargetManager sets the BrowZer target manager
func (s *Service) SetBrowZerTargetManager(btm *BrowZerTargetManager) {
	s.browzerTargetManager = btm
}

// SetAPISIXConfigPath sets the path to the APISIX standalone config file
func (s *Service) SetAPISIXConfigPath(path string) {
	s.apisixConfigPath = path
}

// SetAuditService sets the unified audit service
func (s *Service) SetAuditService(as *UnifiedAuditService) {
	s.auditService = as
	if s.zitiProvider != nil {
		as.SetZitiProvider(s.zitiProvider)
	}
	if s.guacamoleClient != nil {
		as.SetGuacamoleClient(s.guacamoleClient)
	}
}

// SetVaultService wires the in-process PAM credential vault.
func (s *Service) SetVaultService(v *vault.Service) { s.vaultSvc = v }

// NewService creates a new access proxy service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	secret := cfg.AccessSessionSecret
	if len(secret) < 32 {
		secret = secret + strings.Repeat("0", 32-len(secret))
	}

	// Derive internal OAuth URL from JWKS URL for server-to-server calls
	// JWKS URL is like http://oauth-service:8006/.well-known/jwks.json
	oauthInternal := cfg.OAuthIssuer
	if cfg.OAuthJWKSURL != "" {
		if parsed, err := url.Parse(cfg.OAuthJWKSURL); err == nil {
			oauthInternal = parsed.Scheme + "://" + parsed.Host
		}
	}

	alog := logger.With(zap.String("service", "access"))
	encKey := ""
	if cfg != nil {
		encKey = cfg.EncryptionKey
	}
	idpCipher, err := secretcrypt.New(encKey)
	if err != nil {
		alog.Warn("IdP client secrets will NOT be decrypted (plaintext at rest); set a 32-byte ENCRYPTION_KEY", zap.Error(err))
		idpCipher = secretcrypt.NewNoop()
	}

	return &Service{
		db:               db,
		redis:            redis,
		config:           cfg,
		logger:           alog,
		governanceURL:    cfg.GovernanceURL,
		auditURL:         cfg.AuditURL,
		sessionSecret:    []byte(secret[:32]),
		oauthIssuer:      cfg.OAuthIssuer,
		oauthInternalURL: oauthInternal,
		oauthJWKSURL:     cfg.OAuthJWKSURL,
		idpCipher:        idpCipher,
	}
}

// RegisterRoutes registers all access proxy routes
func RegisterRoutes(router *gin.Engine, svc *Service, authMiddleware ...gin.HandlerFunc) {
	// Auth flow endpoints (no auth required)
	auth := router.Group("/access/.auth")
	{
		auth.GET("/login", svc.handleLogin)
		auth.GET("/callback", svc.handleCallback)
		auth.GET("/logout", svc.handleLogout)
		auth.GET("/session", svc.handleSessionInfo)
		auth.GET("/idps", svc.handleIDPDiscovery)
	}

	// Admin API for route management (requires auth)
	api := router.Group("/api/v1/access")
	// WebSocket auth promotion MUST run before the bearer auth middleware:
	// browsers cannot set an Authorization header on a WebSocket, so the token
	// rides as a `bearer.<jwt>` subprotocol. This copies it into the header so the
	// standard auth middleware validates it exactly like any other request (and
	// makes WS auth independent of edge/APISIX behavior).
	api.Use(promoteWebSocketBearer)
	if len(authMiddleware) > 0 {
		api.Use(authMiddleware...)
	}
	{
		api.GET("/routes", svc.handleListRoutes)
		api.POST("/routes", svc.handleCreateRoute)
		api.GET("/routes/:id", svc.handleGetRoute)
		api.PUT("/routes/:id", svc.handleUpdateRoute)
		api.DELETE("/routes/:id", svc.handleDeleteRoute)
		api.GET("/sessions", svc.handleListSessions)
		api.DELETE("/sessions/:id", svc.handleRevokeSession)

		// Unified Zero Trust Access overview (resource spine + coverage gaps).
		api.GET("/overview", svc.handleAccessOverview)

		// OpenZiti management endpoints
		api.GET("/ziti/status", svc.handleZitiStatus)
		// Guided network setup: checklist + install advisor + per-route advice
		api.GET("/ziti/setup/status", svc.handleZitiSetupStatus)
		api.GET("/ziti/reconciler/status", svc.handleZitiReconcilerStatus)
		// Ziti management mutations are admin-only: creating identities/services
		// mints overlay-join credentials and reconfigures the zero-trust fabric,
		// so a plain authenticated tenant user must NOT reach them. GET reads stay
		// open to any authenticated user (org-scoped lists/status), and genuine
		// data-plane POSTs (device posture self-report, posture evaluate) stay open
		// because a device submits its own posture. `adminOnly` is the shared gate.
		adminOnly := svc.requireAdminRole()

		// Runtime connection control (admin-only): configure + connect/disconnect
		// the OpenZiti controller from the admin panel with no restart.
		api.GET("/ziti/settings", adminOnly, svc.handleGetZitiSettings)
		api.PUT("/ziti/settings", adminOnly, svc.handlePutZitiSettings)
		api.POST("/ziti/settings/test", adminOnly, svc.handleTestZitiSettings)
		api.POST("/ziti/connect", adminOnly, svc.handleZitiConnect)
		api.POST("/ziti/disconnect", adminOnly, svc.handleZitiDisconnect)
		api.GET("/ziti/services", svc.handleListZitiServices)
		api.POST("/ziti/services", adminOnly, svc.handleCreateZitiService)
		api.DELETE("/ziti/services/:id", adminOnly, svc.handleDeleteZitiService)
		api.GET("/ziti/identities", svc.handleListZitiIdentities)
		api.POST("/ziti/identities", adminOnly, svc.handleCreateZitiIdentity)
		api.DELETE("/ziti/identities/:id", adminOnly, svc.handleDeleteZitiIdentity)
		// Enrollment JWT is a bearer network-join credential — admin-only read.
		api.GET("/ziti/identities/:id/enrollment-jwt", adminOnly, svc.handleGetEnrollmentJWT)
		api.POST("/ziti/routes/:id/enable", adminOnly, svc.handleEnableZitiOnRoute)
		api.POST("/ziti/routes/:id/disable", adminOnly, svc.handleDisableZitiOnRoute)

		// Phase 2: Fabric & Router management
		api.GET("/ziti/fabric/overview", svc.handleGetFabricOverview)
		api.GET("/ziti/fabric/routers", svc.handleListEdgeRouters)
		api.GET("/ziti/fabric/routers/:id", svc.handleGetEdgeRouter)
		api.GET("/ziti/fabric/health", svc.handleGetHealth)
		api.POST("/ziti/fabric/reconnect", adminOnly, svc.handleReconnect)
		api.GET("/ziti/fabric/metrics", svc.handleGetMetrics)
		api.GET("/ziti/fabric/service-policies", svc.handleListServicePolicies)

		// Ziti service connectivity test (diagnostic dial; read-like)
		api.POST("/ziti/services/:id/test", svc.handleTestZitiService)

		// Edge router policy CRUD
		api.GET("/ziti/edge-router-policies", svc.handleListEdgeRouterPolicies)
		api.POST("/ziti/edge-router-policies", adminOnly, svc.handleCreateEdgeRouterPolicy)
		api.PUT("/ziti/edge-router-policies/:id", adminOnly, svc.handleUpdateEdgeRouterPolicy)
		api.DELETE("/ziti/edge-router-policies/:id", adminOnly, svc.handleDeleteEdgeRouterPolicy)

		// Service policy CRUD
		api.POST("/ziti/service-policies", adminOnly, svc.handleCreateServicePolicy)
		api.PUT("/ziti/service-policies/:id", adminOnly, svc.handleUpdateServicePolicy)
		api.DELETE("/ziti/service-policies/:id", adminOnly, svc.handleDeleteServicePolicy)

		// Identity attribute management
		api.PATCH("/ziti/identities/:id/attributes", adminOnly, svc.handlePatchIdentityAttributes)

		// User-to-Ziti identity sync
		api.GET("/ziti/sync/status", svc.handleGetSyncStatus)
		api.GET("/ziti/sync/unsynced", svc.handleGetUnsyncedUsers)
		api.GET("/ziti/sync/user-map", svc.handleGetUserZitiMap)
		api.GET("/ziti/sync/my-identity", svc.handleGetMyZitiIdentity)
		api.POST("/ziti/sync/users", adminOnly, svc.handleSyncAllUsers)
		api.POST("/ziti/sync/users/:userId", adminOnly, svc.handleSyncSingleUser)
		api.POST("/ziti/sync/groups", adminOnly, svc.handleSyncAllGroups)
		api.POST("/ziti/sync/device-trust/:userId", adminOnly, svc.handleSyncDeviceTrust)

		// Enriched device management (unified view)
		api.GET("/devices/enriched", svc.handleGetEnrichedDevices)

		// Cross-pillar user correlation (IAM ⇄ PAM ⇄ Ziti): one map of
		// everything a user can reach, and one switch that severs it all.
		api.GET("/users/:id/access-map", adminOnly, svc.handleUserAccessMap)
		api.POST("/users/:id/kill-switch", adminOnly, svc.handleUserKillSwitch)

		// Cross-pillar device correlation: a user's devices with IAM trust +
		// Ziti compliance/posture side by side, and a device-scoped revoke.
		api.GET("/users/:id/devices", adminOnly, svc.handleUserDevices)
		api.POST("/users/:id/devices/:agentId/revoke", adminOnly, svc.handleRevokeUserDevice)
		// Self-service: the caller's own correlated devices (compliance visibility).
		api.GET("/my-devices", svc.handleMyDevices)

		// Phase 3: Posture checks (definitions are admin-managed; device
		// self-report + evaluate are data-plane and stay open).
		api.GET("/ziti/posture/checks", svc.handleListPostureChecks)
		api.POST("/ziti/posture/checks", adminOnly, svc.handleCreatePostureCheck)
		api.PUT("/ziti/posture/checks/:id", adminOnly, svc.handleUpdatePostureCheck)
		api.DELETE("/ziti/posture/checks/:id", adminOnly, svc.handleDeletePostureCheck)
		api.GET("/ziti/posture/identities/:id", svc.handleGetIdentityPosture)
		api.POST("/ziti/posture/identities/:id/evaluate", svc.handleEvaluateIdentityPosture)
		api.GET("/ziti/posture/summary", svc.handleGetPostureSummary)
		api.POST("/ziti/posture/device", svc.handleSubmitDevicePosture)

		// EDR/MDM posture sources (CrowdStrike/Intune/Jamf) — ingest external
		// device compliance into the Ziti-bound posture pipeline.
		api.GET("/ziti/posture/edr", adminOnly, svc.handleListEDRSources)
		api.POST("/ziti/posture/edr", adminOnly, svc.handleCreateEDRSource)
		api.GET("/ziti/posture/edr/:id", adminOnly, svc.handleGetEDRSource)
		api.DELETE("/ziti/posture/edr/:id", adminOnly, svc.handleDeleteEDRSource)
		api.POST("/ziti/posture/edr/:id/test", adminOnly, svc.handleTestEDRSource)
		api.POST("/ziti/posture/edr/:id/sync", adminOnly, svc.handleSyncEDRSource)

		// MCP / AI-agent gateway (Wave D1). Admin manages servers + per-tool
		// allowlists; the invoke endpoint authenticates the AGENT's own token
		// (not the admin session), so it lives outside adminOnly.
		api.GET("/mcp/servers", adminOnly, svc.handleListMCPServers)
		api.POST("/mcp/servers", adminOnly, svc.handleCreateMCPServer)
		api.DELETE("/mcp/servers/:id", adminOnly, svc.handleDeleteMCPServer)
		api.POST("/mcp/servers/:id/policies", adminOnly, svc.handleAddMCPToolPolicy)
		// Agent-facing gateway: POST /api/v1/access/mcp/:server/tools/:tool.
		api.POST("/mcp/:server/tools/:tool", svc.handleMCPInvoke)

		// Phase 3: Policy sync
		api.GET("/ziti/policy-sync", svc.handleListPolicySyncStates)
		api.POST("/ziti/policy-sync", adminOnly, svc.handleSyncGovernancePolicy)
		api.POST("/ziti/policy-sync/:id/trigger", adminOnly, svc.handleTriggerPolicySync)
		api.DELETE("/ziti/policy-sync/:id", adminOnly, svc.handleDeletePolicySyncState)

		// Config types & configs management
		api.GET("/ziti/config-types", svc.handleListConfigTypes)
		api.GET("/ziti/configs", svc.handleListConfigs)
		api.POST("/ziti/configs", adminOnly, svc.handleCreateConfig)
		api.PUT("/ziti/configs/:id", adminOnly, svc.handleUpdateConfig)
		api.DELETE("/ziti/configs/:id", adminOnly, svc.handleDeleteConfig)

		// Auth policies & JWT signers management
		api.GET("/ziti/auth-policies", svc.handleListAuthPolicies)
		api.POST("/ziti/auth-policies", adminOnly, svc.handleCreateAuthPolicy)
		api.PUT("/ziti/auth-policies/:id", adminOnly, svc.handleUpdateAuthPolicy)
		api.DELETE("/ziti/auth-policies/:id", adminOnly, svc.handleDeleteAuthPolicy)
		api.GET("/ziti/jwt-signers", svc.handleListJWTSigners)
		api.POST("/ziti/jwt-signers", adminOnly, svc.handleCreateJWTSigner)
		api.PUT("/ziti/jwt-signers/:id", adminOnly, svc.handleUpdateJWTSigner)
		api.DELETE("/ziti/jwt-signers/:id", adminOnly, svc.handleDeleteJWTSigner)

		// Terminators management
		api.GET("/ziti/terminators", svc.handleListTerminators)
		api.GET("/ziti/terminators/:id", svc.handleGetTerminator)
		api.DELETE("/ziti/terminators/:id", adminOnly, svc.handleDeleteTerminator)

		// Ziti session visibility
		api.GET("/ziti/sessions", svc.handleListZitiSessions)
		api.DELETE("/ziti/sessions/:id", adminOnly, svc.handleDeleteZitiSession)
		api.POST("/ziti/sessions/batch-terminate", adminOnly, svc.handleBatchDeleteZitiSessions)

		// AI-driven network intelligence: behavioral baselines over live fabric
		// sessions, anomaly ledger, fused identity risk scores, policy-hygiene
		// recommendations, and quarantine response. Analysis mutates the
		// ledger/baselines and quarantine rewrites identity attributes, so
		// those are admin-only; reads stay open to authenticated users.
		api.GET("/ziti/ai/insights", svc.handleZitiAIInsights)
		api.POST("/ziti/ai/analyze", adminOnly, svc.handleZitiAIAnalyze)
		api.GET("/ziti/ai/anomalies", svc.handleListZitiAnomalies)
		api.POST("/ziti/ai/anomalies/:id/status", adminOnly, svc.handleUpdateZitiAnomalyStatus)
		api.GET("/ziti/ai/identity-risk", svc.handleZitiIdentityRisk)
		api.GET("/ziti/ai/recommendations", svc.handleZitiAIRecommendations)
		api.POST("/ziti/ai/identities/:id/quarantine", adminOnly, svc.handleQuarantineZitiIdentity)
		api.POST("/ziti/ai/identities/:id/unquarantine", adminOnly, svc.handleUnquarantineZitiIdentity)
		// Controller version / OpenZiti v2.0 feature detection
		api.GET("/ziti/controller/features", svc.handleZitiControllerFeatures)

		// Phase 5: Certificates
		api.GET("/ziti/certificates", svc.handleListCertificates)
		api.GET("/ziti/certificates/expiry-alerts", svc.handleGetCertExpiryAlerts)
		api.POST("/ziti/certificates/:id/rotate", adminOnly, svc.handleRotateCertificate)

		// BrowZer management endpoints
		api.GET("/ziti/browzer/status", svc.handleBrowZerStatus)
		api.POST("/ziti/browzer/enable", adminOnly, svc.handleEnableBrowZer)
		api.POST("/ziti/browzer/disable", adminOnly, svc.handleDisableBrowZer)
		api.POST("/ziti/browzer/services/:id/enable", adminOnly, svc.handleEnableBrowZerOnService)
		api.POST("/ziti/browzer/services/:id/disable", adminOnly, svc.handleDisableBrowZerOnService)

		// BrowZer bootstrapper management panel endpoints
		api.GET("/ziti/browzer/management", svc.handleBrowZerManagement)
		api.POST("/ziti/browzer/certificates", adminOnly, svc.handleBrowZerCertUpload)
		api.DELETE("/ziti/browzer/certificates", adminOnly, svc.handleBrowZerCertRevert)
		api.PUT("/ziti/browzer/domain", adminOnly, svc.handleBrowZerDomainChange)
		api.POST("/ziti/browzer/restart", adminOnly, svc.handleBrowZerRestart)

		// Platform certificate management
		api.GET("/certificates/platform", svc.handleGetPlatformCert)
		api.POST("/certificates/platform", adminOnly, svc.handleUploadPlatformCert)
		api.DELETE("/certificates/platform", adminOnly, svc.handleRevertPlatformCert)
		api.POST("/certificates/apisix/enable", adminOnly, svc.handleEnableAPISIXSSL)
		api.POST("/certificates/apisix/disable", adminOnly, svc.handleDisableAPISIXSSL)
		api.GET("/certificates/status", svc.handleGetCertStatus)

		// Forward-auth endpoint for APISIX
		api.POST("/auth/decide", svc.handleAuthDecide)
		api.GET("/auth/decide", svc.handleAuthDecide)

		// Policy DSL validation
		api.POST("/routes/validate-policy", svc.handleValidatePolicy)

		// Guacamole remote access
		api.GET("/guacamole/connections", svc.handleListGuacamoleConnections)
		api.POST("/guacamole/connections/:routeId/connect", svc.handleGuacamoleConnect)
		api.PUT("/guacamole/connections/:routeId/credential", svc.requireAdminRole(), svc.handleSetGuacCredential)

		// Guacamole end-user self-service (PAM finalization): brokered-connection
		// catalog + the caller's own session-request status. Static paths avoid
		// the /connections/:routeId and /session-requests/:id wildcard conflicts.
		api.GET("/guacamole/my-connections", svc.handleListMyGuacConnections)
		api.GET("/guacamole/my-session-requests", svc.handleListMyGuacSessionRequests)

		// Guacamole pre-session approval lifecycle (Task 4 — PAM M3)
		api.POST("/guacamole/connections/:routeId/request", svc.handleRequestGuacSession)
		api.POST("/guacamole/session-requests/:id/approve", svc.requireAdminRole(), svc.handleApproveGuacSession)
		api.POST("/guacamole/session-requests/:id/deny", svc.requireAdminRole(), svc.handleDenyGuacSession)
		api.GET("/guacamole/session-requests", svc.requireAdminRole(), svc.handleListGuacSessionRequests)

		// Guacamole active-session management (Task 5 — PAM M3)
		api.GET("/guacamole/sessions", svc.requireAdminRole(), svc.handleListActiveGuacSessions)
		api.POST("/guacamole/sessions/:id/terminate", svc.requireAdminRole(), svc.handleTerminateGuacSession)
		api.POST("/guacamole/sessions/:id/legal-hold", svc.requireAdminRole(), svc.handlePlaceGuacLegalHold)
		api.DELETE("/guacamole/sessions/:id/legal-hold", svc.requireAdminRole(), svc.handleReleaseGuacLegalHold)
		api.GET("/guacamole/sessions/:id/legal-holds", svc.requireAdminRole(), svc.handleListGuacLegalHolds)

		// Guacamole transcript download (Task 3 — PAM M4)
		api.GET("/guacamole/sessions/:id/transcript", svc.requireAdminRole(), svc.handleGetGuacTranscript)

		// Guacamole session recording download (PAM A1). Streams the raw guacd
		// recording, transparently decrypting it when the file was sealed
		// (encrypted at rest) by the recording sealer. Plaintext recordings
		// stream through unchanged, so this works whether or not encryption is
		// configured.
		api.GET("/guacamole/sessions/:id/recording", svc.requireAdminRole(), svc.handleGetGuacRecording)

		// Guacamole live monitor — read-only connection sharing (Task 4 — PAM M4)
		api.POST("/guacamole/sessions/:id/share", svc.requireAdminRole(), svc.handleShareGuacSession)

		// Guacamole session history — DB-backed session rows + transcript availability
		// (admin console W1.3). Static path avoids the /sessions/:id wildcard conflict.
		api.GET("/guacamole/session-history", svc.requireAdminRole(), svc.handleListGuacSessionHistory)

		// PAM connection manager (Devolutions RDM parity): folder tree +
		// typed entries with vault-backed secrets, per-entry ACL, favorites,
		// passwordless launch (server-side credential injection), approval
		// gate, audited reveal, session ledger, and RDM import.
		api.GET("/pam/entry-types", svc.handlePamListEntryTypes)
		api.GET("/pam/folders", svc.handlePamListFolders)
		api.POST("/pam/folders", svc.requireAdminRole(), svc.handlePamCreateFolder)
		api.PUT("/pam/folders/:id", svc.requireAdminRole(), svc.handlePamUpdateFolder)
		api.DELETE("/pam/folders/:id", svc.requireAdminRole(), svc.handlePamDeleteFolder)
		api.GET("/pam/entries", svc.handlePamListEntries)
		api.POST("/pam/entries", svc.requireAdminRole(), svc.handlePamCreateEntry)
		api.GET("/pam/entries/:id", svc.handlePamGetEntry)
		// Update allows non-admins holding an `edit` grant (checked in-handler).
		api.PUT("/pam/entries/:id", svc.handlePamUpdateEntry)
		api.DELETE("/pam/entries/:id", svc.requireAdminRole(), svc.handlePamDeleteEntry)
		api.POST("/pam/entries/:id/favorite", svc.handlePamFavoriteEntry)
		api.DELETE("/pam/entries/:id/favorite", svc.handlePamUnfavoriteEntry)
		api.POST("/pam/entries/:id/connect", svc.handlePamConnect)
		api.GET("/pam/entries/:id/ws", svc.handlePamWSConnect)
		api.POST("/pam/entries/:id/reveal", svc.handlePamRevealEntry)
		api.POST("/pam/entries/:id/request", svc.handlePamRequestAccess)

		// v105 checkout controls — break-glass, dual-control (two-person rule),
		// exclusivity. Break-glass and check-in share the reveal authorization
		// surface (in-handler); the second-person authorization queue and the
		// live-checkout ledger are admin-only.
		api.POST("/pam/entries/:id/break-glass", svc.handlePamBreakGlass)
		api.POST("/pam/entries/:id/checkin", svc.handlePamCheckin)
		api.GET("/pam/checkout-authorizations", svc.requireAdminRole(), svc.handlePamListCheckoutAuthorizations)
		api.POST("/pam/checkout-authorizations/:id/:decision", svc.requireAdminRole(), svc.handlePamDecideCheckoutAuthorization)
		api.GET("/pam/checkouts/active", svc.requireAdminRole(), svc.handlePamListActiveCheckouts)

		// Privilege graph (C1) — the unified-architecture moat. Admin-only: it
		// exposes effective-access blast radius across IAM+IGA+PAM.
		api.GET("/pam/privilege-graph/secret/:id", svc.requireAdminRole(), svc.handleSecretPrivilegeGraph)
		api.GET("/pam/privilege-graph/entry/:id", svc.requireAdminRole(), svc.handleEntryPrivilegeGraph)
		api.GET("/pam/privilege-graph/user/:id", svc.requireAdminRole(), svc.handleUserPrivilegeGraph)

		// v109 SSH certificate authority + session brokering (`openidx connect`).
		// CA init/rotate is admin-only; anyone authenticated may request a
		// short-lived cert (host-side AuthorizedPrincipals still gates the
		// login). The brokered-session ledger list is admin-only.
		api.POST("/pam/ssh-ca/init", svc.requireAdminRole(), svc.handleInitSSHCA)
		api.GET("/pam/ssh-ca", svc.handleGetSSHCA)
		api.POST("/pam/connect/ssh", svc.handleSSHConnect)
		api.POST("/pam/brokered-sessions", svc.handleBrokerSession)
		api.GET("/pam/brokered-sessions", svc.requireAdminRole(), svc.handleListBrokeredSessions)
		api.POST("/pam/brokered-sessions/:id/end", svc.handleEndBrokeredSession)

		// Quick Links — admin-curated, user-searchable support/collaboration launcher.
		api.GET("/quick-links/my", svc.handleMyQuickLinks)
		api.GET("/quick-links", svc.requireAdminRole(), svc.handleListQuickLinks)
		api.POST("/quick-links", svc.requireAdminRole(), svc.handleCreateQuickLink)
		api.PUT("/quick-links/:id", svc.requireAdminRole(), svc.handleUpdateQuickLink)
		api.DELETE("/quick-links/:id", svc.requireAdminRole(), svc.handleDeleteQuickLink)
		api.GET("/pam/entries/:id/grants", svc.requireAdminRole(), svc.handlePamListEntryGrants)
		api.POST("/pam/entries/:id/grants", svc.requireAdminRole(), svc.handlePamAddEntryGrant)
		api.DELETE("/pam/entries/:id/grants/:grantId", svc.requireAdminRole(), svc.handlePamRemoveEntryGrant)
		api.GET("/pam/entry-requests", svc.requireAdminRole(), svc.handlePamListRequests)
		api.POST("/pam/entry-requests/:id/approve", svc.requireAdminRole(), svc.handlePamApproveRequest)
		api.POST("/pam/entry-requests/:id/deny", svc.requireAdminRole(), svc.handlePamDenyRequest)
		api.GET("/pam/my-entry-requests", svc.handlePamListMyRequests)
		api.GET("/pam/sessions", svc.requireAdminRole(), svc.handlePamListSessions)
		api.POST("/pam/sessions/:id/end", svc.handlePamEndSession)
		api.POST("/pam/import/rdm", svc.requireAdminRole(), svc.handlePamImportRDM)

		// PAM OpenZiti reach mode — per-entry zero-trust target hop toggle,
		// broker capability probe, and the tunneler binding list.
		api.GET("/pam/broker/status", svc.handlePamBrokerStatus)
		api.GET("/pam/broker/ziti-bindings", svc.requireAdminRole(), svc.handlePamZitiBindings)
		api.POST("/pam/entries/:id/ziti/enable", svc.requireAdminRole(), svc.handlePamEnableZiti)
		api.POST("/pam/entries/:id/ziti/disable", svc.requireAdminRole(), svc.handlePamDisableZiti)

		// Temporary access links for support/vendor access
		// PAM vendor access to internal SSH/RDP/VNC hosts is a privileged
		// operation — gate management to admins, matching the guacamole PAM
		// routes above. (The public token-redemption route is registered
		// separately on the root router, without auth.)
		api.GET("/temp-access", adminOnly, svc.handleListTempAccess)
		api.POST("/temp-access", adminOnly, svc.handleCreateTempAccess)
		api.GET("/temp-access/:id", adminOnly, svc.handleGetTempAccess)
		api.DELETE("/temp-access/:id", adminOnly, svc.handleRevokeTempAccess)
		api.GET("/temp-access/:id/usage", adminOnly, svc.handleGetTempAccessUsage)

		// Quick service creation (route + Ziti + BrowZer in one call)
		api.POST("/services/quick-create", svc.handleQuickCreate)

		// Service feature management endpoints
		api.GET("/services/:id/features", svc.handleGetServiceFeatures)
		api.GET("/services/:id/status", svc.handleGetServiceStatus)
		api.GET("/services/status", svc.handleGetAllServicesStatus)
		api.POST("/services/:id/features/ziti/enable", svc.handleEnableZitiFeature)
		api.POST("/services/:id/features/ziti/disable", svc.handleDisableZitiFeature)
		api.POST("/services/:id/features/browzer/enable", svc.handleEnableBrowZerFeature)
		api.POST("/services/:id/features/browzer/disable", svc.handleDisableBrowZerFeature)
		api.POST("/services/:id/features/guacamole/enable", svc.handleEnableGuacamoleFeature)
		api.POST("/services/:id/features/guacamole/disable", svc.handleDisableGuacamoleFeature)

		// Health check endpoints
		api.GET("/health/integrations", svc.handleHealthIntegrations)
		api.GET("/health/ziti", svc.handleHealthZiti)
		api.GET("/health/guacamole", svc.handleHealthGuacamole)
		api.GET("/health/browzer", svc.handleHealthBrowZer)
		api.GET("/services/:id/health", svc.handleHealthService)

		// Connection test endpoints
		api.POST("/services/:id/test-connection", svc.handleTestConnection)
		api.GET("/services/:id/test-history", svc.handleGetConnectionTestHistory)

		// Ziti discovery and import
		api.GET("/ziti/discover", svc.handleDiscoverZitiServices)
		api.POST("/ziti/import", svc.handleImportZitiService)
		api.POST("/ziti/import/bulk", svc.handleBulkImportZitiServices)
		api.GET("/ziti/unmanaged/count", svc.handleGetUnmanagedServicesCount)

		// App publishing (register, discover, classify, publish). These are
		// admin management routes — registering an internal app and publishing
		// it as a proxy route exposes infrastructure — so they carry the shared
		// `adminOnly` gate like every sibling management surface (ziti/*,
		// guacamole credentials, temp-access). Without it any authenticated
		// user could register/discover/publish/delete apps.
		api.GET("/apps", adminOnly, svc.handleListApps)
		api.POST("/apps", adminOnly, svc.handleRegisterApp)
		api.GET("/apps/:appId", adminOnly, svc.handleGetApp)
		api.DELETE("/apps/:appId", adminOnly, svc.handleDeleteApp)
		api.POST("/apps/:appId/discover", adminOnly, svc.handleStartDiscovery)
		api.GET("/apps/:appId/paths", adminOnly, svc.handleListDiscoveredPaths)
		api.PUT("/apps/:appId/paths/:pathId", adminOnly, svc.handleUpdatePathClassification)
		api.POST("/apps/:appId/publish", adminOnly, svc.handlePublishPaths)
		api.POST("/apps/:appId/publish-app", adminOnly, svc.handlePublishApp)
		api.POST("/apps/:appId/consolidate", adminOnly, svc.handleConsolidateApp)
		api.GET("/apps/:appId/ziti-services", adminOnly, svc.handleGetAppZitiServices)

		// Relations & Integrity Doctor
		api.GET("/health/relations", svc.handleHealthRelations)
		api.POST("/health/fix/:checkId", svc.handleHealthFix)

		// Unified audit log
		api.GET("/audit/unified", svc.handleGetUnifiedAuditEvents)
		api.GET("/audit/unified/services/:id", svc.handleGetServiceAuditEvents)
		api.POST("/audit/unified/sync", svc.handleSyncExternalAuditEvents)
		api.GET("/audit/unified/summary", svc.handleGetAuditEventsSummary)

		// Agent admin surface (enrollment-token CRUD, agent list / approve /
		// revoke, OAuth-based mobile enrollment, Android QR helpers). Inherits
		// the auth middleware applied to `api`.
		agentHandler := NewAgentAPIHandler(svc.logger, svc.db, svc.ziti())
		agentHandler.RegisterAgentAdminRoutes(api)
		agentHandler.StartGracePeriodEnforcer(context.Background(), 5*time.Minute)
		svc.agentHandler = agentHandler

		// Server-side Play Integrity verification (Phase 1+ Android client).
		// When unconfigured, NewPlayIntegrityVerifier returns (nil, nil) and
		// HandleReport persists agent-supplied tokens unverified — fine for
		// dev, flagged as a production warning by the config validator.
		if svc.config != nil {
			verifier, err := NewPlayIntegrityVerifier(
				context.Background(),
				svc.logger,
				[]byte(svc.config.PlayIntegrityServiceAccountJSON),
				svc.config.PlayIntegrityPackageName,
			)
			if err != nil {
				svc.logger.Warn("play integrity verifier init failed; running unverified",
					zap.Error(err))
			} else if verifier != nil {
				agentHandler.SetPlayIntegrityVerifier(verifier)
				svc.logger.Info("Play Integrity verifier enabled",
					zap.String("package", svc.config.PlayIntegrityPackageName))
			}
		}

		// Kiosk policy admin surface (Phase 3). Audits ride the agent handler
		// so kiosk + enrollment events appear together in unified_audit_events.
		kioskHandler := NewKioskAPIHandler(svc.logger, svc.db, agentHandler)
		kioskHandler.RegisterKioskAdminRoutes(api)

		// Remote-support session admin + signaling broker (Phase 4). Admin
		// HTTP + WS endpoints land here behind auth; the agent-side WS is
		// mounted on the public group below.
		remoteSupport := NewRemoteSupportHandler(svc.logger, svc.db, agentHandler)
		remoteSupport.RegisterRemoteSupportAdminRoutes(api)
		remoteSupport.StartJanitor(context.Background(), 5*time.Minute, time.Minute)
		if svc.guacamoleClient != nil {
			remoteSupport.SetGuacamoleClient(svc.guacamoleClient)
		}

		// Recording storage backend. Preference: S3 over filesystem so a
		// production deployment that configures both gets durability
		// and lifecycle management for free. Soft-disabled when neither
		// is set — start-session ignores `record: true` and the upload
		// endpoints respond 503 with a clear error.
		if svc.config != nil {
			var store recordingStore
			if svc.config.RecordingsS3Endpoint != "" && svc.config.RecordingsS3Bucket != "" {
				s3Store, s3Err := newS3RecordingStore(s3RecordingConfig{
					Endpoint:        svc.config.RecordingsS3Endpoint,
					Bucket:          svc.config.RecordingsS3Bucket,
					Region:          svc.config.RecordingsS3Region,
					Prefix:          svc.config.RecordingsS3Prefix,
					AccessKeyID:     svc.config.RecordingsS3AccessKey,
					SecretAccessKey: svc.config.RecordingsS3SecretKey,
					UseSSL:          svc.config.RecordingsS3UseSSL,
				})
				if s3Err != nil {
					svc.logger.Warn("S3 recording store init failed; will try filesystem fallback",
						zap.Error(s3Err))
				} else {
					store = s3Store
					svc.logger.Info("Remote-support recording enabled (S3)",
						zap.String("endpoint", svc.config.RecordingsS3Endpoint),
						zap.String("bucket", svc.config.RecordingsS3Bucket))
				}
			}
			if store == nil && svc.config.RecordingsStoragePath != "" {
				// Build the encryption keyring from config. Multi-key form
				// (recordings_encryption_keys) takes precedence for rotation;
				// the single-key form maps to id 0. Either may be empty for
				// plaintext-on-disk. A configured-but-malformed key is a
				// fail-closed error so a typo doesn't silently degrade to
				// plaintext.
				ring, ringErr := newRecordingKeyring(
					svc.config.RecordingsEncryptionKeys,
					svc.config.RecordingsEncryptionActiveKeyID,
					svc.config.RecordingsEncryptionKey,
				)
				keyConfigured := svc.config.RecordingsEncryptionKeys != "" || svc.config.RecordingsEncryptionKey != ""
				if ringErr != nil {
					svc.logger.Warn("recording encryption keyring invalid; filesystem store NOT enabled — fix the key config",
						zap.Error(ringErr))
				} else if keyConfigured && (ring == nil || !ring.Enabled()) {
					svc.logger.Warn("filesystem recording store NOT enabled — encryption key config present but produced an empty keyring")
				} else {
					fsStore, fsErr := newFilesystemRecordingStore(svc.config.RecordingsStoragePath, ring)
					if fsErr != nil {
						svc.logger.Warn("filesystem recording store init failed; recording disabled",
							zap.Error(fsErr))
					} else {
						store = fsStore
						svc.logger.Info("Remote-support recording enabled (filesystem)",
							zap.String("path", svc.config.RecordingsStoragePath),
							zap.Bool("encrypted_at_rest", ring.Enabled()))
					}
				}
			}
			if store != nil {
				remoteSupport.SetRecordingStore(store)
				remoteSupport.SetDefaultRetentionDays(svc.config.RecordingsDefaultRetentionDays)
				remoteSupport.SetGuacRecordingsRoot(svc.config.GuacamoleRecordingPath)
				// PAM A1: seal guacd's plaintext on-disk recordings at rest via
				// the same keyring. Built independently of the WebRTC store's
				// ring above (which is out of scope here and absent under the S3
				// backend) because guac recordings are always local files. Nil /
				// disabled ring → sealer inert (recordings stay plaintext).
				if guacRing, gErr := newRecordingKeyring(
					svc.config.RecordingsEncryptionKeys,
					svc.config.RecordingsEncryptionActiveKeyID,
					svc.config.RecordingsEncryptionKey,
				); gErr != nil {
					svc.logger.Warn("guac recording keyring invalid; guac recordings NOT sealed — fix the key config",
						zap.Error(gErr))
				} else if guacRing.Enabled() {
					remoteSupport.SetGuacRecordingRing(guacRing)
					svc.guacRecordingRing = guacRing
					svc.logger.Info("Guacamole recording encryption-at-rest enabled (PAM A1)")
				}
				// Sweep every hour. Cheap query — predicate index on
				// recording_finalized_at WHERE recording_purged_at IS NULL.
				remoteSupport.StartRecordingRetentionEnforcer(context.Background(), time.Hour)
			}
		}

		// Per-session TURN credential minter. Soft-disabled when the
		// shared secret / URIs aren't configured — callers can still
		// supply ice_servers explicitly on start-session.
		if svc.config != nil {
			var turnURIs []string
			for _, raw := range strings.Split(svc.config.TurnURIs, ",") {
				if t := strings.TrimSpace(raw); t != "" {
					turnURIs = append(turnURIs, t)
				}
			}
			minter := NewTurnMinter(TurnConfig{
				URIs:         turnURIs,
				StaticSecret: svc.config.TurnStaticSecret,
				Realm:        svc.config.TurnRealm,
				TTL:          time.Duration(svc.config.TurnCredentialTTLSeconds) * time.Second,
			})
			if minter != nil {
				remoteSupport.SetTurnMinter(minter)
				svc.logger.Info("TURN credential minter enabled",
					zap.Int("uris", len(turnURIs)),
					zap.String("realm", minter.Realm()))
			}
		}

		svc.remoteSupportHandler = remoteSupport
	}

	// Public agent surface: enrollment (carries an enrollment token), posture
	// report (carries X-Agent-ID + auth token), config (same). These run
	// OUTSIDE the JWT auth middleware because the agent doesn't have a tenant
	// JWT yet — its own credentials authenticate the request.
	if svc.agentHandler != nil {
		publicAgent := router.Group("/api/v1/access")
		svc.agentHandler.RegisterAgentPublicRoutes(publicAgent)
		// Agent-side remote-support WebSocket — authenticated via the same
		// X-Agent-ID + X-Auth-Token pattern as /agent/report.
		if svc.remoteSupportHandler != nil {
			svc.remoteSupportHandler.RegisterRemoteSupportPublicRoutes(publicAgent)
		}
	}

	// Tier-0 "dark platform" enroll door: the ONLY access-service route that
	// stays public when the platform goes dark. Trades an entitlement (session
	// bearer / enrollment token) for a one-time Ziti enrollment JWT so a native
	// client can join the overlay. It authenticates the request itself (verifies
	// the bearer against JWKS, or validates the enrollment token), so it sits
	// OUTSIDE the JWT middleware like the agent routes. Rate-limited + audited.
	// See docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md §4.
	router.POST("/api/v1/access/enroll",
		middleware.RateLimit(20, time.Minute), // tight per-IP budget for the public gate
		svc.handleEnroll)

	// Public APK download for Android Enterprise provisioning. The device
	// fetches this during factory-reset setup, before any auth context exists.
	router.GET("/downloads/openidx-agent.apk", svc.handleAgentAPKDownload)

	// Temp access public endpoint (no auth - uses token)
	router.GET("/temp-access/:token", svc.handleUseTempAccess)

	// Catch-all reverse proxy (must be last)
	router.NoRoute(svc.handleProxy)
}

// ---- Route CRUD ----

func (s *Service) handleListRoutes(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        COALESCE(landing_path, '/'),
		        COALESCE(hosting_mode, 'identity'),
		        created_at, updated_at
		 FROM proxy_routes WHERE org_id = $3 ORDER BY priority DESC, name ASC LIMIT $1 OFFSET $2`, limit, offset, org.ID)
	if err != nil {
		s.logger.Error("Failed to list routes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list routes"})
		return
	}
	defer rows.Close()

	routes := []ProxyRoute{}
	for rows.Next() {
		var r ProxyRoute
		var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
		var remotePort *int
		var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte
		err := rows.Scan(&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
			&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
			&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
			&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
			&idpID, &r.RouteType, &remoteHost, &remotePort,
			&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
			&r.RequireDeviceTrust, &allowedCountries,
			&r.MaxRiskScore, &guacConnID,
			&r.LandingPath, &r.HostingMode,
			&r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			s.logger.Error("Failed to scan route", zap.Error(err))
			continue
		}
		if desc != nil {
			r.Description = *desc
		}
		if zitiServiceName != nil {
			r.ZitiServiceName = *zitiServiceName
		}
		if idpID != nil {
			r.IDPId = *idpID
		}
		if remoteHost != nil {
			r.RemoteHost = *remoteHost
		}
		if remotePort != nil {
			r.RemotePort = *remotePort
		}
		if inlinePolicy != nil {
			r.InlinePolicy = *inlinePolicy
		}
		if guacConnID != nil {
			r.GuacamoleConnectionID = *guacConnID
		}
		if err := json.Unmarshal(allowedRoles, &r.AllowedRoles); err != nil && allowedRoles != nil {
			s.logger.Warn("Failed to unmarshal allowed_roles", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(allowedGroups, &r.AllowedGroups); err != nil && allowedGroups != nil {
			s.logger.Warn("Failed to unmarshal allowed_groups", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(policyIDs, &r.PolicyIDs); err != nil && policyIDs != nil {
			s.logger.Warn("Failed to unmarshal policy_ids", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins); err != nil && corsOrigins != nil {
			s.logger.Warn("Failed to unmarshal cors_allowed_origins", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(customHeaders, &r.CustomHeaders); err != nil && customHeaders != nil {
			s.logger.Warn("Failed to unmarshal custom_headers", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs); err != nil && postureCheckIDs != nil {
			s.logger.Warn("Failed to unmarshal posture_check_ids", zap.String("route_id", r.ID), zap.Error(err))
		}
		if err := json.Unmarshal(allowedCountries, &r.AllowedCountries); err != nil && allowedCountries != nil {
			s.logger.Warn("Failed to unmarshal allowed_countries", zap.String("route_id", r.ID), zap.Error(err))
		}
		if r.AllowedRoles == nil {
			r.AllowedRoles = []string{}
		}
		if r.AllowedGroups == nil {
			r.AllowedGroups = []string{}
		}
		if r.PolicyIDs == nil {
			r.PolicyIDs = []string{}
		}
		if r.CORSAllowedOrigins == nil {
			r.CORSAllowedOrigins = []string{}
		}
		if r.CustomHeaders == nil {
			r.CustomHeaders = map[string]string{}
		}
		if r.PostureCheckIDs == nil {
			r.PostureCheckIDs = []string{}
		}
		if r.AllowedCountries == nil {
			r.AllowedCountries = []string{}
		}
		routes = append(routes, r)
	}

	// Get total count
	var total int
	s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM proxy_routes WHERE org_id = $1", org.ID).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"routes": routes,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *Service) handleCreateRoute(c *gin.Context) {
	var req struct {
		Name               string            `json:"name" binding:"required"`
		Description        string            `json:"description"`
		FromURL            string            `json:"from_url" binding:"required"`
		ToURL              string            `json:"to_url" binding:"required"`
		PreserveHost       bool              `json:"preserve_host"`
		RequireAuth        *bool             `json:"require_auth"`
		AllowedRoles       []string          `json:"allowed_roles"`
		AllowedGroups      []string          `json:"allowed_groups"`
		PolicyIDs          []string          `json:"policy_ids"`
		IdleTimeout        int               `json:"idle_timeout"`
		AbsoluteTimeout    int               `json:"absolute_timeout"`
		CORSAllowedOrigins []string          `json:"cors_allowed_origins"`
		CustomHeaders      map[string]string `json:"custom_headers"`
		Enabled            *bool             `json:"enabled"`
		Priority           int               `json:"priority"`
		IDPId              string            `json:"idp_id"`
		RouteType          string            `json:"route_type"`
		RemoteHost         string            `json:"remote_host"`
		RemotePort         int               `json:"remote_port"`
		ReverifyInterval   int               `json:"reverify_interval"`
		PostureCheckIDs    []string          `json:"posture_check_ids"`
		InlinePolicy       string            `json:"inline_policy"`
		RequireDeviceTrust bool              `json:"require_device_trust"`
		AllowedCountries   []string          `json:"allowed_countries"`
		MaxRiskScore       int               `json:"max_risk_score"`
		LandingPath        string            `json:"landing_path"`
		HostingMode        string            `json:"hosting_mode"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	landingPath := strings.TrimSpace(req.LandingPath)
	if landingPath == "" {
		landingPath = "/"
	}

	hostingMode, ok := normalizeHostingMode(req.HostingMode)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hosting_mode (expected identity, direct, or hop)"})
		return
	}

	id := uuid.New().String()
	requireAuth := true
	if req.RequireAuth != nil {
		requireAuth = *req.RequireAuth
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.IdleTimeout == 0 {
		req.IdleTimeout = 900
	}
	if req.AbsoluteTimeout == 0 {
		req.AbsoluteTimeout = 43200
	}
	if req.RouteType == "" {
		req.RouteType = "http"
	}
	if req.MaxRiskScore == 0 {
		req.MaxRiskScore = 100
	}

	// Validate inline policy if provided
	if req.InlinePolicy != "" {
		if err := ValidatePolicy(req.InlinePolicy); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid inline policy: %s", err.Error())})
			return
		}
	}

	rolesJSON, _ := json.Marshal(req.AllowedRoles)
	groupsJSON, _ := json.Marshal(req.AllowedGroups)
	policyJSON, _ := json.Marshal(req.PolicyIDs)
	corsJSON, _ := json.Marshal(req.CORSAllowedOrigins)
	headersJSON, _ := json.Marshal(req.CustomHeaders)
	postureJSON, _ := json.Marshal(req.PostureCheckIDs)
	countriesJSON, _ := json.Marshal(req.AllowedCountries)

	var idpID *string
	if req.IDPId != "" {
		idpID = &req.IDPId
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_routes (id, name, description, from_url, to_url, preserve_host,
		  require_auth, allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		  cors_allowed_origins, custom_headers, enabled, priority,
		  idp_id, route_type, remote_host, remote_port,
		  reverify_interval, posture_check_ids, inline_policy,
		  require_device_trust, allowed_countries, max_risk_score, landing_path, hosting_mode, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		         $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)`,
		id, req.Name, req.Description, req.FromURL, req.ToURL, req.PreserveHost,
		requireAuth, rolesJSON, groupsJSON, policyJSON, req.IdleTimeout, req.AbsoluteTimeout,
		corsJSON, headersJSON, enabled, req.Priority,
		idpID, req.RouteType, req.RemoteHost, req.RemotePort,
		req.ReverifyInterval, postureJSON, req.InlinePolicy,
		req.RequireDeviceTrust, countriesJSON, req.MaxRiskScore, landingPath, hostingMode, org.ID)
	if err != nil {
		s.logger.Error("Failed to create route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create route"})
		return
	}

	// Auto-provision Guacamole connection for remote access routes
	route := &ProxyRoute{
		ID: id, Name: req.Name, RouteType: req.RouteType,
		RemoteHost: req.RemoteHost, RemotePort: req.RemotePort,
	}
	if err := s.provisionGuacamoleForRoute(c.Request.Context(), route); err != nil {
		s.logger.Warn("Guacamole provisioning failed", zap.Error(err))
	}

	// Mirror the route as an Applications launcher tile so it shows on the
	// Applications page (which reads `applications`) with working row actions.
	s.upsertAppTile(c.Request.Context(), id, req.Name, req.Description, req.FromURL, landingPath, org.ID)

	s.logAuditEvent(c, "proxy_route_created", id, "proxy_route", map[string]interface{}{
		"name":       req.Name,
		"from_url":   req.FromURL,
		"to_url":     req.ToURL,
		"route_type": req.RouteType,
	})

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "route created"})
}

func (s *Service) handleGetRoute(c *gin.Context) {
	route, err := s.getRouteByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		s.logger.Error("Failed to get route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get route"})
		return
	}
	c.JSON(http.StatusOK, route)
}

func (s *Service) handleUpdateRoute(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name               *string           `json:"name"`
		Description        *string           `json:"description"`
		FromURL            *string           `json:"from_url"`
		ToURL              *string           `json:"to_url"`
		PreserveHost       *bool             `json:"preserve_host"`
		RequireAuth        *bool             `json:"require_auth"`
		AllowedRoles       []string          `json:"allowed_roles"`
		AllowedGroups      []string          `json:"allowed_groups"`
		PolicyIDs          []string          `json:"policy_ids"`
		IdleTimeout        *int              `json:"idle_timeout"`
		AbsoluteTimeout    *int              `json:"absolute_timeout"`
		CORSAllowedOrigins []string          `json:"cors_allowed_origins"`
		CustomHeaders      map[string]string `json:"custom_headers"`
		Enabled            *bool             `json:"enabled"`
		Priority           *int              `json:"priority"`
		IDPId              *string           `json:"idp_id"`
		RouteType          *string           `json:"route_type"`
		RemoteHost         *string           `json:"remote_host"`
		RemotePort         *int              `json:"remote_port"`
		ReverifyInterval   *int              `json:"reverify_interval"`
		PostureCheckIDs    []string          `json:"posture_check_ids"`
		InlinePolicy       *string           `json:"inline_policy"`
		RequireDeviceTrust *bool             `json:"require_device_trust"`
		AllowedCountries   []string          `json:"allowed_countries"`
		MaxRiskScore       *int              `json:"max_risk_score"`
		LandingPath        *string           `json:"landing_path"`
		HostingMode        *string           `json:"hosting_mode"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update
	existing, err := s.getRouteByID(c.Request.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get route"})
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.FromURL != nil {
		existing.FromURL = *req.FromURL
	}
	if req.ToURL != nil {
		existing.ToURL = *req.ToURL
	}
	if req.PreserveHost != nil {
		existing.PreserveHost = *req.PreserveHost
	}
	if req.RequireAuth != nil {
		existing.RequireAuth = *req.RequireAuth
	}
	if req.AllowedRoles != nil {
		existing.AllowedRoles = req.AllowedRoles
	}
	if req.AllowedGroups != nil {
		existing.AllowedGroups = req.AllowedGroups
	}
	if req.PolicyIDs != nil {
		existing.PolicyIDs = req.PolicyIDs
	}
	if req.IdleTimeout != nil {
		existing.IdleTimeout = *req.IdleTimeout
	}
	if req.AbsoluteTimeout != nil {
		existing.AbsoluteTimeout = *req.AbsoluteTimeout
	}
	if req.CORSAllowedOrigins != nil {
		existing.CORSAllowedOrigins = req.CORSAllowedOrigins
	}
	if req.CustomHeaders != nil {
		existing.CustomHeaders = req.CustomHeaders
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}
	if req.IDPId != nil {
		existing.IDPId = *req.IDPId
	}
	if req.RouteType != nil {
		existing.RouteType = *req.RouteType
	}
	if req.RemoteHost != nil {
		existing.RemoteHost = *req.RemoteHost
	}
	if req.RemotePort != nil {
		existing.RemotePort = *req.RemotePort
	}
	if req.ReverifyInterval != nil {
		existing.ReverifyInterval = *req.ReverifyInterval
	}
	if req.PostureCheckIDs != nil {
		existing.PostureCheckIDs = req.PostureCheckIDs
	}
	if req.InlinePolicy != nil {
		existing.InlinePolicy = *req.InlinePolicy
		if existing.InlinePolicy != "" {
			if err := ValidatePolicy(existing.InlinePolicy); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid inline policy: %s", err.Error())})
				return
			}
		}
	}
	if req.RequireDeviceTrust != nil {
		existing.RequireDeviceTrust = *req.RequireDeviceTrust
	}
	if req.AllowedCountries != nil {
		existing.AllowedCountries = req.AllowedCountries
	}
	if req.MaxRiskScore != nil {
		existing.MaxRiskScore = *req.MaxRiskScore
	}
	if req.LandingPath != nil {
		existing.LandingPath = strings.TrimSpace(*req.LandingPath)
	}
	if existing.LandingPath == "" {
		existing.LandingPath = "/"
	}
	if req.HostingMode != nil {
		mode, ok := normalizeHostingMode(*req.HostingMode)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hosting_mode (expected identity, direct, or hop)"})
			return
		}
		existing.HostingMode = mode
	}

	rolesJSON, _ := json.Marshal(existing.AllowedRoles)
	groupsJSON, _ := json.Marshal(existing.AllowedGroups)
	policyJSON, _ := json.Marshal(existing.PolicyIDs)
	corsJSON, _ := json.Marshal(existing.CORSAllowedOrigins)
	headersJSON, _ := json.Marshal(existing.CustomHeaders)
	postureJSON, _ := json.Marshal(existing.PostureCheckIDs)
	countriesJSON, _ := json.Marshal(existing.AllowedCountries)

	var idpID *string
	if existing.IDPId != "" {
		idpID = &existing.IDPId
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE proxy_routes SET name=$1, description=$2, from_url=$3, to_url=$4,
		  preserve_host=$5, require_auth=$6, allowed_roles=$7, allowed_groups=$8,
		  policy_ids=$9, idle_timeout=$10, absolute_timeout=$11, cors_allowed_origins=$12,
		  custom_headers=$13, enabled=$14, priority=$15,
		  idp_id=$16, route_type=$17, remote_host=$18, remote_port=$19,
		  reverify_interval=$20, posture_check_ids=$21, inline_policy=$22,
		  require_device_trust=$23, allowed_countries=$24, max_risk_score=$25,
		  landing_path=$26, hosting_mode=$27, updated_at=NOW()
		 WHERE id=$28 AND org_id=$29`,
		existing.Name, existing.Description, existing.FromURL, existing.ToURL,
		existing.PreserveHost, existing.RequireAuth, rolesJSON, groupsJSON,
		policyJSON, existing.IdleTimeout, existing.AbsoluteTimeout, corsJSON,
		headersJSON, existing.Enabled, existing.Priority,
		idpID, existing.RouteType, existing.RemoteHost, existing.RemotePort,
		existing.ReverifyInterval, postureJSON, existing.InlinePolicy,
		existing.RequireDeviceTrust, countriesJSON, existing.MaxRiskScore,
		existing.LandingPath, existing.HostingMode, id, org.ID)
	if err != nil {
		s.logger.Error("Failed to update route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update route"})
		return
	}

	// Re-key the clientless edge for Ziti routes: a from_url (host) or hosting-
	// mode change must move the APISIX BrowZer route + bootstrapper target to the
	// new host and prune the old, instead of stranding the wiring under the old
	// host name. No-op for non-Ziti routes.
	if existing.ZitiEnabled {
		s.refreshBrowZerEdge(c.Request.Context())
	}

	// Keep the Applications launcher tile in sync (name/description/base_url),
	// and backfill one for a route created before tiles were auto-created.
	s.upsertAppTile(c.Request.Context(), id, existing.Name, existing.Description, existing.FromURL, existing.LandingPath, org.ID)

	c.JSON(http.StatusOK, gin.H{"message": "route updated"})
}

func (s *Service) handleDeleteRoute(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Deprovision Guacamole connection before deleting route
	s.deprovisionGuacamoleForRoute(c.Request.Context(), id)

	// Tear down the route's Ziti service + policies + name-keyed edge configs
	// BEFORE removing the row — the row delete alone leaves them orphaned on the
	// controller (there is no FK cascade to ziti_services). No-ops if the route
	// has no Ziti service.
	if zm := s.ziti(); zm != nil {
		if err := zm.TeardownZitiForRoute(c.Request.Context(), id); err != nil {
			s.logger.Warn("ziti teardown on route delete failed", zap.String("route_id", id), zap.Error(err))
		}
	}

	result, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM proxy_routes WHERE id=$1 AND org_id=$2", id, org.ID)
	if err != nil {
		s.logger.Error("Failed to delete route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete route"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	// Prune the deleted route's BrowZer edge wiring (APISIX route + bootstrapper
	// target) and reconcile, and remove its Applications launcher tile.
	s.refreshBrowZerEdge(c.Request.Context())
	s.deleteAppTile(c.Request.Context(), id)

	s.logAuditEvent(c, "proxy_route_deleted", id, "proxy_route", nil)
	c.JSON(http.StatusOK, gin.H{"message": "route deleted"})
}

// ---- Session management ----

func (s *Service) handleListSessions(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, user_id, route_id, ip_address, user_agent, started_at, last_active_at, expires_at, revoked
		 FROM proxy_sessions WHERE revoked=false AND expires_at > NOW() AND org_id = $1
		 ORDER BY last_active_at DESC LIMIT 100`, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()

	sessions := []ProxySession{}
	for rows.Next() {
		var sess ProxySession
		var routeID *string
		err := rows.Scan(&sess.ID, &sess.UserID, &routeID, &sess.IPAddress, &sess.UserAgent,
			&sess.StartedAt, &sess.LastActiveAt, &sess.ExpiresAt, &sess.Revoked)
		if err != nil {
			continue
		}
		if routeID != nil {
			sess.RouteID = *routeID
		}
		sessions = append(sessions, sess)
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (s *Service) handleRevokeSession(c *gin.Context) {
	id := c.Param("id")
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	_, err = s.db.Pool.Exec(c.Request.Context(),
		"UPDATE proxy_sessions SET revoked=true WHERE id=$1 AND org_id=$2", id, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
		return
	}

	// Also remove from Redis
	s.redis.Client.Del(c.Request.Context(), "proxy_session:"+id)

	c.JSON(http.StatusOK, gin.H{"message": "session revoked"})
}

// ---- OAuth Login Flow ----

// callbackScheme returns the external URL scheme for building OAuth callback /
// redirect URLs. Behind a TLS-terminating proxy (nginx/APISIX) the public
// request is HTTPS but reaches this service as HTTP, so honor X-Forwarded-Proto
// first; fall back to the request's own TLS state, then http. Without this the
// emitted redirect_uri is http:// and won't match the public https:// URL.
func callbackScheme(c *gin.Context) string {
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		if i := strings.IndexByte(proto, ','); i >= 0 { // may be a list; take the first
			proto = proto[:i]
		}
		if p := strings.TrimSpace(proto); p != "" {
			return p
		}
	}
	if c.Request != nil && c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func (s *Service) handleLogin(c *gin.Context) {
	// Check if a specific IDP is requested
	if idpID := c.Query("idp"); idpID != "" && idpID != "default" {
		s.handleLoginWithIDP(c, idpID)
		return
	}

	// Generate PKCE code verifier and challenge
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)
	state := generateState()

	// Store verifier and original URL in Redis
	redirectURL := c.Query("redirect_url")
	if redirectURL == "" {
		redirectURL = "/access/.auth/session"
	}

	sessionData, _ := json.Marshal(map[string]string{
		"verifier":     verifier,
		"redirect_url": redirectURL,
	})
	s.redis.Client.Set(c.Request.Context(), "access_oauth_state:"+state, sessionData, 10*time.Minute)

	// Build OAuth authorization URL
	// Determine the callback host: prefer the request Host (preserves port from pass_host),
	// then X-Forwarded-Host, then extract from redirect_url.
	callbackHost := c.Request.Host
	if callbackHost == "" || callbackHost == fmt.Sprintf("access-service:%d", s.config.Port) {
		callbackHost = c.GetHeader("X-Forwarded-Host")
	}
	if callbackHost == "" {
		// Extract host from redirect_url if it's a full URL (e.g., http://demo.localtest.me:8088/)
		if parsed, err := url.Parse(redirectURL); err == nil && parsed.Host != "" {
			callbackHost = parsed.Host
		}
	}
	if callbackHost == "" {
		callbackHost = fmt.Sprintf("%s:%d", s.config.AccessProxyDomain, s.config.Port)
	}
	callbackURL := fmt.Sprintf("%s://%s/access/.auth/callback", callbackScheme(c), callbackHost)

	authURL := fmt.Sprintf("%s/oauth/authorize?client_id=access-proxy&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&scope=openid+profile+email",
		s.oauthIssuer,
		url.QueryEscape(callbackURL),
		url.QueryEscape(challenge),
		url.QueryEscape(state))

	c.Redirect(http.StatusFound, authURL)
}

func (s *Service) handleCallback(c *gin.Context) {
	// If login_session is present, the OAuth service is asking us to show a login form
	loginSession := c.Query("login_session")
	if loginSession != "" {
		s.serveLoginPage(c, loginSession)
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	// Retrieve stored state
	stateData, err := s.redis.Client.Get(c.Request.Context(), "access_oauth_state:"+state).Bytes()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state"})
		return
	}
	s.redis.Client.Del(c.Request.Context(), "access_oauth_state:"+state)

	var storedState struct {
		Verifier    string `json:"verifier"`
		RedirectURL string `json:"redirect_url"`
		IDPID       string `json:"idp_id"`
		IDPIssuer   string `json:"idp_issuer"`
	}
	json.Unmarshal(stateData, &storedState)

	// If this callback is from an external IDP, delegate to multi-IDP handler
	if storedState.IDPID != "" && storedState.IDPID != "default" {
		s.handleCallbackWithIDP(c, storedState.IDPID, storedState.IDPIssuer, storedState.Verifier, storedState.RedirectURL)
		return
	}

	// Exchange code for tokens (callback URL must match what was sent to the authorize endpoint)
	callbackHost := c.Request.Host
	if callbackHost == "" || callbackHost == fmt.Sprintf("access-service:%d", s.config.Port) {
		callbackHost = c.GetHeader("X-Forwarded-Host")
	}
	if callbackHost == "" {
		if parsed, err := url.Parse(storedState.RedirectURL); err == nil && parsed.Host != "" {
			callbackHost = parsed.Host
		}
	}
	if callbackHost == "" {
		callbackHost = fmt.Sprintf("%s:%d", s.config.AccessProxyDomain, s.config.Port)
	}
	callbackURL := fmt.Sprintf("%s://%s/access/.auth/callback", callbackScheme(c), callbackHost)

	tokenResp, err := s.exchangeCode(c.Request.Context(), code, storedState.Verifier, callbackURL)
	if err != nil {
		s.logger.Error("Failed to exchange code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	// Parse the access token to extract user info
	claims, err := s.parseTokenClaims(tokenResp.AccessToken)
	if err != nil {
		s.logger.Error("Failed to parse token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse token"})
		return
	}

	// Create proxy session
	session, err := s.createSession(c, claims, tokenResp.AccessToken)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Set session cookie with SameSite=Lax for CSRF protection
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "_openidx_proxy_session",
		Value:    session.SessionToken,
		MaxAge:   session.AbsoluteTimeout(),
		Path:     "/",
		Secure:   s.config.IsProduction(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	s.logAuditEvent(c, "proxy_session_created", session.UserID, "session", map[string]interface{}{
		"session_id": session.ID,
		"email":      session.Email,
	})

	// Redirect to original URL
	redirectURL := storedState.RedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	c.Redirect(http.StatusFound, redirectURL)
}

func (s *Service) serveLoginPage(c *gin.Context, loginSession string) {
	oauthURL := s.oauthIssuer
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenIDX - Sign In</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:12px;padding:2.5rem;width:100%%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,.3)}
h1{font-size:1.5rem;text-align:center;margin-bottom:.5rem;color:#f8fafc}
.subtitle{text-align:center;color:#94a3b8;margin-bottom:2rem;font-size:.875rem}
label{display:block;font-size:.875rem;color:#94a3b8;margin-bottom:.375rem}
input{width:100%%;padding:.75rem 1rem;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:1rem;margin-bottom:1rem;outline:none;transition:border-color .2s}
input:focus{border-color:#3b82f6}
button{width:100%%;padding:.75rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:#2563eb}
button:disabled{opacity:.6;cursor:not-allowed}
.error{background:#7f1d1d;border:1px solid #991b1b;color:#fca5a5;padding:.75rem;border-radius:8px;margin-bottom:1rem;font-size:.875rem;display:none}
.mfa-section{display:none}
.logo{text-align:center;margin-bottom:1.5rem;font-size:2rem}
</style>
</head>
<body>
<div class="card">
<div class="logo">&#x1f510;</div>
<h1>OpenIDX Access</h1>
<p class="subtitle">Sign in to continue to your application</p>
<div id="error" class="error"></div>
<form id="loginForm">
<div id="credentials-section">
<label for="username">Username or Email</label>
<input type="text" id="username" name="username" required autocomplete="username" autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
</div>
<div id="mfa-section" class="mfa-section">
<label for="mfa_code">MFA Verification Code</label>
<input type="text" id="mfa_code" name="mfa_code" placeholder="Enter 6-digit code" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6">
</div>
<button type="submit" id="submitBtn">Sign In</button>
</form>
</div>
<script>
const loginSession = %q;
const oauthURL = %q;
let mfaSession = '';

document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const errEl = document.getElementById('error');
  errEl.style.display = 'none';
  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.textContent = 'Signing in...';

  try {
    if (mfaSession) {
      const resp = await fetch(oauthURL + '/oauth/mfa/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mfa_session: mfaSession, code: document.getElementById('mfa_code').value})
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error_description || data.error || 'MFA verification failed');
      }
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
        return;
      }
    } else {
      const resp = await fetch(oauthURL + '/oauth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
          login_session: loginSession
        })
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error_description || data.error || 'Authentication failed');
      }
      if (data.mfa_required) {
        mfaSession = data.mfa_session;
        document.getElementById('credentials-section').style.display = 'none';
        document.getElementById('mfa-section').style.display = 'block';
        document.getElementById('mfa_code').focus();
        btn.disabled = false;
        btn.textContent = 'Verify';
        return;
      }
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
        return;
      }
    }
  } catch(err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
  btn.disabled = false;
  btn.textContent = mfaSession ? 'Verify' : 'Sign In';
});
</script>
</body>
</html>`, loginSession, oauthURL)

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

func (s *Service) handleLogout(c *gin.Context) {
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err == nil && cookie != "" {
		// Find and revoke session
		var sessionID string
		err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(c.Request.Context()),
			//orgscope:ignore proxy data-plane logout; session looked up by globally-unique session_token hash, pre-org-resolution
			"SELECT id FROM proxy_sessions WHERE session_token=$1", hashToken(cookie)).Scan(&sessionID)
		if err == nil {
			s.db.Pool.Exec(orgctx.WithBypassRLS(c.Request.Context()),
				//orgscope:ignore proxy data-plane logout; revoke by primary key resolved from the unique session_token above
				"UPDATE proxy_sessions SET revoked=true WHERE id=$1", sessionID)
			s.redis.Client.Del(c.Request.Context(), "proxy_session:"+hashToken(cookie))
		}
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "_openidx_proxy_session",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   s.config.IsProduction(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := c.Query("redirect_url")
	if redirectURL == "" {
		redirectURL = "/access/.auth/login"
	}
	c.Redirect(http.StatusFound, redirectURL)
}

func (s *Service) handleSessionInfo(c *gin.Context) {
	session := s.getSessionFromRequest(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no active session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":    session.UserID,
		"email":      session.Email,
		"name":       session.Name,
		"roles":      session.Roles,
		"expires_at": session.ExpiresAt,
	})
}

// ---- Reverse Proxy ----

func (s *Service) handleProxy(c *gin.Context) {
	// Find matching route by host header
	host := c.Request.Host
	route, err := s.findRouteByHost(c.Request.Context(), host)
	if err != nil || route == nil {
		// No matching route - return 404
		c.JSON(http.StatusNotFound, gin.H{"error": "no proxy route configured for this host"})
		return
	}

	if !route.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "route is disabled"})
		return
	}

	// Check authentication
	var session *ProxySession
	if route.RequireAuth {
		session = s.getSessionFromRequest(c)
		// Enforce the route's idle timeout on the cookie session: if it has been
		// idle longer than idle_timeout, revoke it and re-auth. (Bearer tokens
		// carry their own JWT expiry, so this only applies to the cookie path.)
		if session != nil && isIdleExpired(route, session, time.Now()) {
			s.revokeIdleProxySession(c, session)
			s.logAuditEvent(c, "proxy_session_idle_expired", route.ID, "proxy_route", map[string]interface{}{
				"user_id":      session.UserID,
				"idle_timeout": route.IdleTimeout,
			})
			session = nil
		}
		if session == nil {
			// Also check for Bearer token
			session = s.getSessionFromBearer(c)
		}
		if session == nil {
			// Redirect to login
			loginURL := fmt.Sprintf("/access/.auth/login?redirect_url=%s",
				url.QueryEscape(c.Request.URL.String()))
			c.Redirect(http.StatusFound, loginURL)
			return
		}

		// Check roles
		if len(route.AllowedRoles) > 0 && !hasAnyRole(session.Roles, route.AllowedRoles) {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  "insufficient_roles",
				"user_id": session.UserID,
				"path":    c.Request.URL.Path,
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		// Context-aware access evaluation
		accessCtx, ctxErr := s.buildAccessContext(c, route, session)
		if ctxErr != nil {
			s.logger.Error("Failed to build access context", zap.Error(ctxErr))
			c.JSON(http.StatusForbidden, gin.H{"error": "context evaluation failed"})
			return
		}
		decision := s.evaluateAccessContext(accessCtx)
		if !decision.Allowed {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  decision.Reason,
				"user_id": session.UserID,
				"path":    c.Request.URL.Path,
			})
			if decision.StepUpRequired {
				c.Header("X-Step-Up-Required", "true")
			}
			c.JSON(http.StatusForbidden, gin.H{"error": decision.Reason})
			return
		}
		session.RiskScore = decision.RiskScore

		// Evaluate governance policies
		if len(route.PolicyIDs) > 0 {
			allowed, err := s.evaluatePolicies(c, route, session)
			if err != nil {
				s.logger.Error("Policy evaluation failed", zap.Error(err))
				// Fail closed
				c.JSON(http.StatusForbidden, gin.H{"error": "policy evaluation failed"})
				return
			}
			if !allowed {
				s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
					"reason":  "policy_denied",
					"user_id": session.UserID,
					"path":    c.Request.URL.Path,
				})
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied by policy"})
				return
			}
		}

		// Update session activity (also slides the idle-timeout window)
		s.updateSessionActivity(c, session)
	}

	// Proxy the request
	target, err := url.Parse(route.ToURL)
	if err != nil {
		s.logger.Error("Invalid upstream URL", zap.String("to_url", route.ToURL), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid upstream configuration"})
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Use Ziti transport if the route has Ziti enabled and ZitiManager is available
	if route.ZitiEnabled && route.ZitiServiceName != "" && s.ziti() != nil && s.ziti().IsInitialized() {
		proxy.Transport = s.ziti().ZitiTransport(route.ZitiServiceName)
		s.logger.Debug("Proxying through Ziti overlay",
			zap.String("service", route.ZitiServiceName),
			zap.String("route", route.Name))
	}

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, c.Request.URL.Path)
		req.URL.RawQuery = c.Request.URL.RawQuery

		if route.PreserveHost {
			req.Host = c.Request.Host
		} else {
			req.Host = target.Host
		}

		// Inject identity headers
		if session != nil {
			req.Header.Set("X-Forwarded-User", session.UserID)
			req.Header.Set("X-Forwarded-Email", session.Email)
			req.Header.Set("X-Forwarded-Name", session.Name)
			req.Header.Set("X-Forwarded-Roles", strings.Join(session.Roles, ","))
		}

		req.Header.Set("X-Forwarded-For", c.ClientIP())
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Real-IP", c.ClientIP())

		// Custom headers
		for k, v := range route.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.logger.Error("Proxy error", zap.String("route", route.Name), zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(gin.H{"error": "upstream unavailable"})
	}

	// Log successful proxy
	if session != nil {
		s.logAuditEvent(c, "proxy_access_allowed", route.ID, "proxy_route", map[string]interface{}{
			"user_id":  session.UserID,
			"path":     c.Request.URL.Path,
			"method":   c.Request.Method,
			"upstream": route.ToURL,
		})
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

// ---- Helper methods ----

func (s *Service) getRouteByID(ctx context.Context, id string) (*ProxyRoute, error) {
	// Scope to the request's org when present. The proxy data-plane and the
	// continuous-verification background sweep call this with no org context;
	// route id is a globally-unique primary key, so the by-id lookup is safe and
	// the org filter is applied only for request-path (admin) callers.
	orgFilter := ""
	args := []interface{}{id}
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgFilter = " AND org_id=$2"
		args = append(args, org.ID)
	}

	var r ProxyRoute
	var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
	var remotePort *int
	var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        COALESCE(landing_path, '/'),
		        COALESCE(hosting_mode, 'identity'),
		        created_at, updated_at
		 FROM proxy_routes WHERE id=$1`+orgFilter, args...).Scan(
		&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
		&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
		&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
		&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
		&idpID, &r.RouteType, &remoteHost, &remotePort,
		&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
		&r.RequireDeviceTrust, &allowedCountries,
		&r.MaxRiskScore, &guacConnID,
		&r.LandingPath, &r.HostingMode,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if desc != nil {
		r.Description = *desc
	}
	if zitiServiceName != nil {
		r.ZitiServiceName = *zitiServiceName
	}
	if idpID != nil {
		r.IDPId = *idpID
	}
	if remoteHost != nil {
		r.RemoteHost = *remoteHost
	}
	if remotePort != nil {
		r.RemotePort = *remotePort
	}
	if inlinePolicy != nil {
		r.InlinePolicy = *inlinePolicy
	}
	if guacConnID != nil {
		r.GuacamoleConnectionID = *guacConnID
	}
	if err := json.Unmarshal(allowedRoles, &r.AllowedRoles); err != nil && allowedRoles != nil {
		s.logger.Warn("Failed to unmarshal allowed_roles", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedGroups, &r.AllowedGroups); err != nil && allowedGroups != nil {
		s.logger.Warn("Failed to unmarshal allowed_groups", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(policyIDs, &r.PolicyIDs); err != nil && policyIDs != nil {
		s.logger.Warn("Failed to unmarshal policy_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins); err != nil && corsOrigins != nil {
		s.logger.Warn("Failed to unmarshal cors_allowed_origins", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(customHeaders, &r.CustomHeaders); err != nil && customHeaders != nil {
		s.logger.Warn("Failed to unmarshal custom_headers", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs); err != nil && postureCheckIDs != nil {
		s.logger.Warn("Failed to unmarshal posture_check_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedCountries, &r.AllowedCountries); err != nil && allowedCountries != nil {
		s.logger.Warn("Failed to unmarshal allowed_countries", zap.String("route_id", r.ID), zap.Error(err))
	}
	if r.AllowedRoles == nil {
		r.AllowedRoles = []string{}
	}
	if r.AllowedGroups == nil {
		r.AllowedGroups = []string{}
	}
	if r.PolicyIDs == nil {
		r.PolicyIDs = []string{}
	}
	if r.CORSAllowedOrigins == nil {
		r.CORSAllowedOrigins = []string{}
	}
	if r.CustomHeaders == nil {
		r.CustomHeaders = map[string]string{}
	}
	if r.PostureCheckIDs == nil {
		r.PostureCheckIDs = []string{}
	}
	if r.AllowedCountries == nil {
		r.AllowedCountries = []string{}
	}
	return &r, nil
}

// EnsureZitiServicesForRoutes checks for Ziti-enabled proxy routes that don't have
// a corresponding Ziti service on the controller and creates them. This handles
// routes seeded via init-db.sql that need Ziti resources provisioned on first boot.
func (s *Service) EnsureZitiServicesForRoutes(ctx context.Context, zm *ZitiManager) {
	if zm == nil {
		return
	}

	// Wait for Ziti controller to be fully ready
	time.Sleep(15 * time.Second)

	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore startup infra provisioning across all orgs; reconciles Ziti controller services for every ziti-enabled route on boot
		`SELECT pr.id, pr.ziti_service_name, pr.to_url, COALESCE(pr.browzer_enabled, false)
		 FROM proxy_routes pr
		 WHERE pr.ziti_enabled = true
		   AND pr.ziti_service_name IS NOT NULL
		   AND pr.ziti_service_name != ''
		   AND NOT EXISTS (SELECT 1 FROM ziti_services zs WHERE zs.name = pr.ziti_service_name)`)
	if err != nil {
		s.logger.Error("Failed to query routes needing Ziti setup", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var routeID, serviceName, toURL string
		var browzerEnabled bool
		if err := rows.Scan(&routeID, &serviceName, &toURL, &browzerEnabled); err != nil {
			s.logger.Error("Failed to scan route", zap.Error(err))
			continue
		}

		host, port := parseHostPort(toURL)
		if host == "" || port == 0 {
			s.logger.Warn("Could not parse upstream for Ziti setup",
				zap.String("service", serviceName), zap.String("to_url", toURL))
			continue
		}

		// Check if the service already exists on the Ziti controller
		existingSvc, _ := zm.GetServiceByName(serviceName)
		if existingSvc != nil {
			s.logger.Info("Ziti service already exists, ensuring hosting",
				zap.String("service", serviceName))
			// Ensure it's being hosted
			zm.HostService(serviceName, host, port)
			// Add browzer-enabled if needed
			if browzerEnabled {
				s.ensureBrowZerAttribute(ctx, zm, existingSvc.ID)
			}
			continue
		}

		s.logger.Info("Creating Ziti service for seeded route",
			zap.String("route_id", routeID),
			zap.String("service", serviceName),
			zap.String("target", fmt.Sprintf("%s:%d", host, port)))

		if err := zm.SetupZitiForRoute(ctx, routeID, serviceName, host, port); err != nil {
			s.logger.Error("Failed to setup Ziti for seeded route",
				zap.String("service", serviceName), zap.Error(err))
			continue
		}

		// Add browzer-enabled attribute if route has browzer_enabled=true
		if browzerEnabled {
			svc, _ := zm.GetServiceByName(serviceName)
			if svc != nil {
				s.ensureBrowZerAttribute(ctx, zm, svc.ID)
			}
		}

		s.logger.Info("Ziti service created for seeded route", zap.String("service", serviceName))
	}
}

// ensureBrowZerAttribute adds the "browzer-enabled" role attribute to a Ziti service if not present
func (s *Service) ensureBrowZerAttribute(ctx context.Context, zm *ZitiManager, zitiServiceID string) {
	attrs, err := zm.GetServiceRoleAttributes(ctx, zitiServiceID)
	if err != nil {
		s.logger.Warn("Failed to get service role attributes", zap.Error(err))
		return
	}
	for _, a := range attrs {
		if a == "browzer-enabled" {
			return // already has it
		}
	}
	attrs = append(attrs, "browzer-enabled")
	if err := zm.PatchServiceRoleAttributes(ctx, zitiServiceID, attrs); err != nil {
		s.logger.Error("Failed to add browzer-enabled attribute", zap.Error(err))
	} else {
		s.logger.Info("Added browzer-enabled attribute to service", zap.String("ziti_id", zitiServiceID))
	}
}

// EnsureBrowZerRouterService creates the browzer-router-zt Ziti service with all required policies
// and ensures it's hosted. All operations are idempotent; safe to call on every startup.
// browzerRouterHostPort returns where the access-proxy dials the BrowZer
// path/vhost router: the configured BROWZER_ROUTER_HOST/PORT, else the compose
// defaults (browzer-router:80).
func (s *Service) browzerRouterHostPort() (string, int) {
	host, port := BrowZerRouterHost, BrowZerRouterPort
	if s.config != nil {
		if s.config.BrowZerRouterHost != "" {
			host = s.config.BrowZerRouterHost
		}
		if s.config.BrowZerRouterPort != 0 {
			port = s.config.BrowZerRouterPort
		}
	}
	return host, port
}

func (s *Service) EnsureBrowZerRouterService(ctx context.Context, zm *ZitiManager) {
	if zm == nil {
		return
	}

	routerHost, routerPort := s.browzerRouterHostPort()
	s.logger.Info("Ensuring BrowZer router Ziti service",
		zap.String("service", BrowZerRouterServiceName),
		zap.String("host", routerHost),
		zap.Int("port", routerPort))

	// 1. Create or find the service
	var serviceID string
	err := zm.SetupZitiForRoute(ctx, "", BrowZerRouterServiceName, routerHost, routerPort)
	if err != nil {
		s.logger.Debug("SetupZitiForRoute returned (service may already exist)", zap.Error(err))
	}

	// Look up the service ID (it should exist now, either just created or from a previous run)
	svc, svcErr := zm.GetServiceByName(BrowZerRouterServiceName)
	if svcErr != nil || svc == nil {
		// GetServiceByName iterates ListServices which can be unreliable; try DB fallback
		var dbZitiID string
		if dbErr := zm.GetDB().Pool.QueryRow(ctx,
			//orgscope:ignore startup infra provisioning; the BrowZer router is an install-wide Ziti service identified by its globally-unique name
			"SELECT ziti_id FROM ziti_services WHERE name=$1", BrowZerRouterServiceName).Scan(&dbZitiID); dbErr == nil {
			serviceID = dbZitiID
			s.logger.Info("Found router service ID from DB", zap.String("ziti_id", serviceID))
		} else {
			s.logger.Warn("Could not find browzer-router-zt service ID from API or DB", zap.Error(svcErr))
		}
	} else {
		serviceID = svc.ID
	}

	// 2. Ensure all role attributes are present
	if serviceID != "" {
		attrs, attrErr := zm.GetServiceRoleAttributes(ctx, serviceID)
		if attrErr == nil {
			needPatch := false
			for _, need := range []string{BrowZerRouterServiceName, "browzer-enabled"} {
				found := false
				for _, a := range attrs {
					if a == need {
						found = true
						break
					}
				}
				if !found {
					attrs = append(attrs, need)
					needPatch = true
				}
			}
			if needPatch {
				if patchErr := zm.PatchServiceRoleAttributes(ctx, serviceID, attrs); patchErr != nil {
					s.logger.Error("Failed to patch router service attributes", zap.Error(patchErr))
				} else {
					s.logger.Info("Updated router service role attributes", zap.Strings("attrs", attrs))
				}
			}
		}
	}

	// 3. Ensure bind/dial service policies (idempotent — will get 400 if they exist)
	bindName := fmt.Sprintf("openidx-bind-%s", BrowZerRouterServiceName)
	if _, bErr := zm.CreateServicePolicy(ctx, bindName, "Bind",
		[]string{"#" + BrowZerRouterServiceName}, []string{"#access-proxy-clients"}); bErr != nil {
		s.logger.Debug("Bind policy (may already exist)", zap.Error(bErr))
	}
	dialName := fmt.Sprintf("openidx-dial-%s", BrowZerRouterServiceName)
	if _, dErr := zm.CreateServicePolicy(ctx, dialName, "Dial",
		[]string{"#" + BrowZerRouterServiceName}, []string{"#access-proxy-clients"}); dErr != nil {
		s.logger.Debug("Dial policy (may already exist)", zap.Error(dErr))
	}

	// 4. Ensure service-edge-router policy (allows edge routers to handle this service)
	serpName := fmt.Sprintf("openidx-serp-%s", BrowZerRouterServiceName)
	if serpErr := zm.EnsureServiceEdgeRouterPolicy(ctx, serpName,
		[]string{"#" + BrowZerRouterServiceName}, []string{"#all"}); serpErr != nil {
		s.logger.Debug("Service-edge-router policy (may already exist)", zap.Error(serpErr))
	}

	// 5. Wait for SDK to discover the service, then host it
	s.logger.Info("Waiting for Ziti SDK to discover browzer-router-zt service...")
	time.Sleep(10 * time.Second)

	if hostErr := zm.HostService(BrowZerRouterServiceName, routerHost, routerPort); hostErr != nil {
		s.logger.Error("Failed to host BrowZer router Ziti service", zap.Error(hostErr))
	} else {
		s.logger.Info("BrowZer router Ziti service hosted successfully")
	}
}

// handleQuickCreate creates a proxy route with Ziti and BrowZer enabled in a single API call.
// This eliminates the multi-step process of creating a route, enabling Ziti, and enabling BrowZer separately.
func (s *Service) handleQuickCreate(c *gin.Context) {
	var req struct {
		Name           string   `json:"name" binding:"required"`
		TargetURL      string   `json:"target_url" binding:"required"`
		Domain         string   `json:"domain" binding:"required"`
		PathPrefix     string   `json:"path_prefix"`
		ZitiEnabled    bool     `json:"ziti_enabled"`
		BrowzerEnabled bool     `json:"browzer_enabled"`
		AllowedRoles   []string `json:"allowed_roles"`
		AllowedGroups  []string `json:"allowed_groups"`
		RouteType      string   `json:"route_type"`
		RequireAuth    *bool    `json:"require_auth"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// BrowZer implies Ziti
	if req.BrowzerEnabled {
		req.ZitiEnabled = true
	}

	if req.RouteType == "" {
		req.RouteType = "http"
	}
	requireAuth := true
	if req.RequireAuth != nil {
		requireAuth = *req.RequireAuth
	}

	// Validate path_prefix if set
	if req.PathPrefix != "" && !strings.HasPrefix(req.PathPrefix, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path_prefix must start with /"})
		return
	}

	// Build from_url from domain + optional path prefix
	fromURL := "http://" + req.Domain
	if req.PathPrefix != "" {
		fromURL += req.PathPrefix
	}

	// Create the proxy route
	routeID := uuid.New().String()
	rolesJSON, _ := json.Marshal(req.AllowedRoles)
	groupsJSON, _ := json.Marshal(req.AllowedGroups)

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_routes (id, name, from_url, to_url, require_auth, enabled, priority,
		  route_type, allowed_roles, allowed_groups,
		  idle_timeout, absolute_timeout, max_risk_score,
		  allowed_countries, cors_allowed_origins, custom_headers, policy_ids, posture_check_ids, org_id)
		 VALUES ($1, $2, $3, $4, $5, true, 0,
		         $6, $7, $8,
		         900, 43200, 100,
		         '[]', '[]', '{}', '[]', '[]', $9)`,
		routeID, req.Name, fromURL, req.TargetURL, requireAuth,
		req.RouteType, rolesJSON, groupsJSON, org.ID)
	if err != nil {
		s.logger.Error("Failed to create route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create route"})
		return
	}

	s.logger.Info("Quick-create: route created", zap.String("route_id", routeID), zap.String("name", req.Name))

	// Get user ID from context
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}

	result := gin.H{
		"id":      routeID,
		"name":    req.Name,
		"domain":  req.Domain,
		"message": "route created",
	}

	// Enable Ziti if requested
	if req.ZitiEnabled && s.featureManager != nil {
		// Parse target URL to get host/port for Ziti
		host, port := parseHostPort(req.TargetURL)
		serviceName := fmt.Sprintf("openidx-%s", req.Name)

		zitiConfig := &FeatureConfig{
			ZitiServiceName: serviceName,
			ZitiHost:        host,
			ZitiPort:        port,
		}

		if err := s.featureManager.EnableFeature(c.Request.Context(), routeID, FeatureZiti, zitiConfig, userID); err != nil {
			s.logger.Error("Quick-create: failed to enable Ziti", zap.Error(err))
			result["ziti_error"] = err.Error()
		} else {
			result["ziti_enabled"] = true
			result["ziti_service_name"] = serviceName
			s.logger.Info("Quick-create: Ziti enabled", zap.String("service", serviceName))
		}
	}

	// Enable BrowZer if requested (Ziti must have succeeded)
	if req.BrowzerEnabled && s.featureManager != nil && result["ziti_error"] == nil {
		if err := s.featureManager.EnableFeature(c.Request.Context(), routeID, FeatureBrowZer, &FeatureConfig{}, userID); err != nil {
			s.logger.Error("Quick-create: failed to enable BrowZer", zap.Error(err))
			result["browzer_error"] = err.Error()
		} else {
			result["browzer_enabled"] = true
			s.logger.Info("Quick-create: BrowZer enabled")
		}

		if req.PathPrefix != "" {
			result["path_prefix"] = req.PathPrefix
			result["note"] = fmt.Sprintf("Path-based BrowZer routing: %s%s → router → backend", req.Domain, req.PathPrefix)
		} else {
			result["note"] = fmt.Sprintf("For Docker Compose: add '%s' as a network alias to the browzer-bootstrapper service", req.Domain)
		}
	}

	s.logAuditEvent(c, "service_quick_created", routeID, "proxy_route", map[string]interface{}{
		"name":            req.Name,
		"domain":          req.Domain,
		"path_prefix":     req.PathPrefix,
		"ziti_enabled":    req.ZitiEnabled,
		"browzer_enabled": req.BrowzerEnabled,
	})

	c.JSON(http.StatusCreated, result)
}

func (s *Service) findRouteByHost(ctx context.Context, host string) (*ProxyRoute, error) {
	// Try exact match first, then wildcard
	var r ProxyRoute
	var desc, zitiServiceName, idpID, remoteHost, inlinePolicy, guacConnID *string
	var remotePort *int
	var allowedRoles, allowedGroups, policyIDs, corsOrigins, customHeaders, postureCheckIDs, allowedCountries []byte

	// Match from_url containing the host.
	// Bypass RLS: route resolution runs before the org is known — the host IS
	// what resolves the tenant. Hosts are globally unique across tenants (a
	// subdomain maps to exactly one org), so the priority-ordered LIMIT 1 stays
	// unambiguous even with cross-org visibility.
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore proxy data-plane route resolution; the reverse proxy matches an inbound request to its route by host before any user/org is resolved
		`SELECT id, name, description, from_url, to_url, preserve_host, require_auth,
		        allowed_roles, allowed_groups, policy_ids, idle_timeout, absolute_timeout,
		        cors_allowed_origins, custom_headers, enabled, priority,
		        COALESCE(ziti_enabled, false), ziti_service_name,
		        idp_id, COALESCE(route_type, 'http'), remote_host, remote_port,
		        COALESCE(reverify_interval, 0), posture_check_ids, inline_policy,
		        COALESCE(require_device_trust, false), allowed_countries,
		        COALESCE(max_risk_score, 100), guacamole_connection_id,
		        created_at, updated_at
		 FROM proxy_routes WHERE from_url LIKE '%' || $1 || '%' AND enabled=true
		 ORDER BY priority DESC LIMIT 1`, host).Scan(
		&r.ID, &r.Name, &desc, &r.FromURL, &r.ToURL, &r.PreserveHost,
		&r.RequireAuth, &allowedRoles, &allowedGroups, &policyIDs,
		&r.IdleTimeout, &r.AbsoluteTimeout, &corsOrigins, &customHeaders,
		&r.Enabled, &r.Priority, &r.ZitiEnabled, &zitiServiceName,
		&idpID, &r.RouteType, &remoteHost, &remotePort,
		&r.ReverifyInterval, &postureCheckIDs, &inlinePolicy,
		&r.RequireDeviceTrust, &allowedCountries,
		&r.MaxRiskScore, &guacConnID,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if desc != nil {
		r.Description = *desc
	}
	if zitiServiceName != nil {
		r.ZitiServiceName = *zitiServiceName
	}
	if idpID != nil {
		r.IDPId = *idpID
	}
	if remoteHost != nil {
		r.RemoteHost = *remoteHost
	}
	if remotePort != nil {
		r.RemotePort = *remotePort
	}
	if inlinePolicy != nil {
		r.InlinePolicy = *inlinePolicy
	}
	if guacConnID != nil {
		r.GuacamoleConnectionID = *guacConnID
	}
	if err := json.Unmarshal(allowedRoles, &r.AllowedRoles); err != nil && allowedRoles != nil {
		s.logger.Warn("Failed to unmarshal allowed_roles", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedGroups, &r.AllowedGroups); err != nil && allowedGroups != nil {
		s.logger.Warn("Failed to unmarshal allowed_groups", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(policyIDs, &r.PolicyIDs); err != nil && policyIDs != nil {
		s.logger.Warn("Failed to unmarshal policy_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(corsOrigins, &r.CORSAllowedOrigins); err != nil && corsOrigins != nil {
		s.logger.Warn("Failed to unmarshal cors_allowed_origins", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(customHeaders, &r.CustomHeaders); err != nil && customHeaders != nil {
		s.logger.Warn("Failed to unmarshal custom_headers", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(postureCheckIDs, &r.PostureCheckIDs); err != nil && postureCheckIDs != nil {
		s.logger.Warn("Failed to unmarshal posture_check_ids", zap.String("route_id", r.ID), zap.Error(err))
	}
	if err := json.Unmarshal(allowedCountries, &r.AllowedCountries); err != nil && allowedCountries != nil {
		s.logger.Warn("Failed to unmarshal allowed_countries", zap.String("route_id", r.ID), zap.Error(err))
	}
	if r.AllowedRoles == nil {
		r.AllowedRoles = []string{}
	}
	if r.AllowedGroups == nil {
		r.AllowedGroups = []string{}
	}
	if r.PolicyIDs == nil {
		r.PolicyIDs = []string{}
	}
	if r.CORSAllowedOrigins == nil {
		r.CORSAllowedOrigins = []string{}
	}
	if r.CustomHeaders == nil {
		r.CustomHeaders = map[string]string{}
	}
	if r.PostureCheckIDs == nil {
		r.PostureCheckIDs = []string{}
	}
	if r.AllowedCountries == nil {
		r.AllowedCountries = []string{}
	}
	return &r, nil
}

func (s *Service) createSession(c *gin.Context, claims map[string]interface{}, accessToken string) (*ProxySession, error) {
	id := uuid.New().String()
	token := generateSessionToken()
	tokenHash := hashToken(token)

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	expiresAt := time.Now().Add(12 * time.Hour)

	// Proxy data-plane login: the session belongs to the org of the route the user
	// authenticated against. The org is taken from context when present, with a
	// default-org fallback so the data-plane never fails to mint a session.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(c.Request.Context()); oerr == nil {
		orgID = org.ID
	}

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO proxy_sessions (id, user_id, session_token, ip_address, user_agent, expires_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, userID, tokenHash, c.ClientIP(), c.Request.UserAgent(), expiresAt, orgID)
	if err != nil {
		return nil, err
	}

	// Store session data in Redis for fast access
	sessionData, _ := json.Marshal(map[string]interface{}{
		"id":          id,
		"user_id":     userID,
		"email":       email,
		"name":        name,
		"roles":       roles,
		"token":       accessToken,
		"expires":     expiresAt.Unix(),
		"last_active": time.Now().Unix(),
	})
	s.redis.Client.Set(c.Request.Context(), "proxy_session:"+tokenHash, sessionData, 12*time.Hour)

	return &ProxySession{
		ID:           id,
		UserID:       userID,
		SessionToken: token,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Email:        email,
		Name:         name,
		Roles:        roles,
		StartedAt:    time.Now(),
		LastActiveAt: time.Now(),
		ExpiresAt:    expiresAt,
	}, nil
}

func (sess *ProxySession) AbsoluteTimeout() int {
	return int(time.Until(sess.ExpiresAt).Seconds())
}

func (s *Service) getSessionFromRequest(c *gin.Context) *ProxySession {
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err != nil || cookie == "" {
		return nil
	}

	tokenHash := hashToken(cookie)
	data, err := s.redis.Client.Get(c.Request.Context(), "proxy_session:"+tokenHash).Bytes()
	if err != nil {
		return nil
	}

	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil
	}

	// Check expiry
	expires, _ := sessionData["expires"].(float64)
	if time.Now().Unix() > int64(expires) {
		return nil
	}

	var roles []string
	if r, ok := sessionData["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	var lastActive time.Time
	if la, ok := sessionData["last_active"].(float64); ok && la > 0 {
		lastActive = time.Unix(int64(la), 0)
	}

	return &ProxySession{
		ID:           fmt.Sprint(sessionData["id"]),
		UserID:       fmt.Sprint(sessionData["user_id"]),
		Email:        fmt.Sprint(sessionData["email"]),
		Name:         fmt.Sprint(sessionData["name"]),
		Roles:        roles,
		LastActiveAt: lastActive,
	}
}

// isIdleExpired reports whether a cookie-backed proxy session has been idle
// longer than the route's idle_timeout. Returns false when the route sets no
// idle_timeout (<= 0) or the session carries no last-active stamp (older
// sessions predating this field ride their absolute expiry). Pure + unit-tested.
func isIdleExpired(route *ProxyRoute, session *ProxySession, now time.Time) bool {
	if route == nil || route.IdleTimeout <= 0 || session == nil || session.LastActiveAt.IsZero() {
		return false
	}
	return now.Sub(session.LastActiveAt) > time.Duration(route.IdleTimeout)*time.Second
}

func (s *Service) getSessionFromBearer(c *gin.Context) *ProxySession {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// SECURITY (P0-1): verify the bearer's signature + expiry against the OAuth
	// JWKS before trusting any claim. A forged/unsigned token must yield no
	// session — the request then falls through to unauthenticated handling,
	// exactly as a missing cookie does. Never build a ProxySession from
	// unverified claims. If JWKS is unconfigured, verification fails → no
	// session (fail-closed: bearer auth is unavailable, never forgeable).
	claims, err := middleware.VerifyBearerToken(s.oauthJWKSURL, token)
	if err != nil {
		s.logger.Debug("bearer token rejected", zap.Error(err))
		return nil
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	return &ProxySession{
		UserID: userID,
		Email:  email,
		Name:   name,
		Roles:  roles,
	}
}

func (s *Service) updateSessionActivity(c *gin.Context, session *ProxySession) {
	ctx := c.Request.Context()

	// Throttle: the blob's last_active only needs freshness within a fraction of
	// idle_timeout, so skip the per-request heartbeat if it was stamped within the
	// last 30s. Keeps the hot path from doing an extra DB write + three Redis ops
	// on every proxied request; the idle window still slides with <=30s lag.
	// (session.LastActiveAt was just read from the blob by getSessionFromRequest;
	// bearer sessions have it zero, so they skip the throttle and no-op below on
	// the empty id / absent cookie.)
	if !session.LastActiveAt.IsZero() && time.Since(session.LastActiveAt) < 30*time.Second {
		return
	}

	s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore proxy data-plane activity heartbeat; updates the active session by its primary key on every proxied request
		"UPDATE proxy_sessions SET last_active_at=NOW() WHERE id=$1", session.ID)

	// Slide the idle window: refresh the Redis blob's last_active, preserving the
	// remaining absolute TTL so absolute expiry (the "expires" field) still applies
	// independently. Best-effort — a failure just means the next request re-reads a
	// slightly stale last_active.
	cookie, err := c.Cookie("_openidx_proxy_session")
	if err != nil || cookie == "" {
		return
	}
	key := "proxy_session:" + hashToken(cookie)
	data, err := s.redis.Client.Get(ctx, key).Bytes()
	if err != nil {
		return
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return
	}
	m["last_active"] = time.Now().Unix()
	ttl := s.redis.Client.TTL(ctx, key).Val()
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if nb, mErr := json.Marshal(m); mErr == nil {
		s.redis.Client.Set(ctx, key, nb, ttl)
	}
}

// revokeIdleProxySession tears down an idle-expired cookie session: it deletes
// the Redis blob and marks the proxy_sessions row revoked (both best-effort).
func (s *Service) revokeIdleProxySession(c *gin.Context, session *ProxySession) {
	if cookie, err := c.Cookie("_openidx_proxy_session"); err == nil && cookie != "" {
		s.redis.Client.Del(c.Request.Context(), "proxy_session:"+hashToken(cookie))
	}
	if session != nil && session.ID != "" {
		s.db.Pool.Exec(orgctx.WithBypassRLS(c.Request.Context()),
			//orgscope:ignore data-plane revoke of the idle session by its primary key
			"UPDATE proxy_sessions SET revoked=true WHERE id=$1", session.ID)
	}
}

func (s *Service) evaluatePolicies(c *gin.Context, route *ProxyRoute, session *ProxySession) (bool, error) {
	for _, policyID := range route.PolicyIDs {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"user_id":            session.UserID,
			"roles":              session.Roles,
			"ip":                 c.ClientIP(),
			"time":               time.Now().Format(time.RFC3339),
			"path":               c.Request.URL.Path,
			"method":             c.Request.Method,
			"route":              route.Name,
			"risk_score":         session.RiskScore,
			"device_trusted":     session.DeviceTrusted,
			"auth_methods":       session.AuthMethods,
			"location":           session.Location,
			"device_fingerprint": session.DeviceFingerprint,
		})

		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost,
			fmt.Sprintf("%s/api/v1/governance/policies/%s/evaluate", s.governanceURL, policyID),
			bytes.NewReader(reqBody))
		if err != nil {
			return false, fmt.Errorf("failed to build evaluate request for policy %s: %w", policyID, err)
		}
		req.Header.Set("Content-Type", "application/json")
		// Service-to-service auth: governance requires a user JWT on /evaluate;
		// the proxy has no user JWT to forward, so it presents the shared
		// internal-service secret instead. Without this the call is 401'd and
		// the policy check fails closed (denies all traffic to the route).
		if s.config.InternalServiceToken != "" {
			req.Header.Set("X-Internal-Token", s.config.InternalServiceToken)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate policy %s: %w", policyID, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// A non-200 (e.g. 401 from a missing/mismatched internal token) is a
		// misconfiguration, not a policy decision. Surface it as an error so it
		// fails closed *visibly* in the logs rather than masquerading as a deny.
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("policy %s evaluate returned %d: %s", policyID, resp.StatusCode, string(body))
		}

		var result struct {
			Allowed        bool `json:"allowed"`
			StepUpRequired bool `json:"step_up_required"`
		}
		json.Unmarshal(body, &result)

		if !result.Allowed {
			if result.StepUpRequired {
				c.Header("X-Step-Up-Required", "true")
			}
			return false, nil
		}
	}
	return true, nil
}

// exchangeCode exchanges an authorization code for tokens
func (s *Service) exchangeCode(ctx context.Context, code, verifier, redirectURI string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"access-proxy"},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(s.oauthInternalURL+"/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// parseTokenClaims decodes JWT claims WITHOUT verifying the signature or expiry.
//
// SECURITY: only call this on a token obtained over a trusted back channel — i.e.
// one just returned by a server-to-server code exchange against our own OAuth
// token endpoint (handleCallback) or an external IdP's token endpoint
// (multi_idp), per OIDC Core §3.1.3.7. NEVER call it on a client-supplied bearer:
// that is the P0-1 unsigned-JWT auth bypass. The bearer path
// (getSessionFromBearer) uses middleware.VerifyBearerToken, which verifies the
// signature + expiry against the OAuth JWKS — use that for any client token.
func (s *Service) parseTokenClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	return claims, nil
}

func (s *Service) logAuditEvent(c *gin.Context, action, targetID, targetType string, details map[string]interface{}) {
	if s.auditURL == "" {
		return
	}

	event := map[string]interface{}{
		"event_type":  "authorization",
		"category":    "access_proxy",
		"action":      action,
		"outcome":     "success",
		"target_id":   targetID,
		"target_type": targetType,
		"actor_ip":    c.ClientIP(),
		"details":     details,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	if action == "proxy_access_denied" {
		event["outcome"] = "failure"
	}

	body, _ := json.Marshal(event)
	go func() {
		resp, err := http.Post(s.auditURL+"/api/v1/audit/events", "application/json", bytes.NewReader(body))
		if err != nil {
			s.logger.Warn("Failed to log audit event", zap.Error(err))
			return
		}
		resp.Body.Close()
	}()
}

// Utility functions

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func hasAnyRole(userRoles, requiredRoles []string) bool {
	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		roleSet[r] = true
	}
	for _, r := range requiredRoles {
		if roleSet[r] {
			return true
		}
	}
	return false
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
