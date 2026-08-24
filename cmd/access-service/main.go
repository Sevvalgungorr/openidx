// Package main is the entry point for the Zero Trust Access Proxy Service
// Access Service provides identity-aware reverse proxying with policy enforcement
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/apikeys"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/server"
	"github.com/openidx/openidx/internal/vault"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

// dialGuacBrokerWithRetry authenticates to a Guacamole broker, retrying with a
// bounded linear backoff (2,4,6,8,10s ~= 30s max) so a broker that is still
// coming up — e.g. after a co-restart — doesn't leave the client permanently
// nil and every PAM launch through it 503ing until the next service restart.
// Returns nil only after exhausting retries; launches then fail until the
// broker recovers (unchanged from before, just after a real retry window).
func dialGuacBrokerWithRetry(broker string, log *zap.Logger, mk func() (*access.GuacamoleClient, error)) *access.GuacamoleClient {
	var gc *access.GuacamoleClient
	var err error
	for attempt := 1; attempt <= 5; attempt++ {
		if gc, err = mk(); err == nil {
			return gc
		}
		log.Warn("Guacamole broker not ready; retrying",
			zap.String("broker", broker), zap.Int("attempt", attempt), zap.Int("max", 5), zap.Error(err))
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	log.Error("Guacamole broker init failed after retries -- launches via this broker unavailable until it recovers",
		zap.String("broker", broker), zap.Error(err))
	return nil
}

func main() {
	// Initialize logger
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Zero Trust Access Proxy Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("access-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Validate production security settings (blocking)
	if err := config.ValidateProductionConfig(cfg, log); err != nil {
		log.Fatal("Production security validation failed", zap.Error(err))
	}

	// Dark-platform: if a DARK_MODE tier is enabled, refuse to start unless the
	// service binds loopback-only. A "dark" service that is actually reachable on
	// a public interface is a false posture, so fail closed rather than advertise
	// overlay-only reach we aren't enforcing.
	if err := cfg.ValidateDarkModeBind(); err != nil {
		log.Fatal("Dark-mode bind validation failed", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("access-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	} else {
		defer shutdownTracer(context.Background())
	}

	// Initialize database connection
	db, err := database.NewPostgres(cfg.DatabaseURL, database.PostgresTLSConfig{
		SSLMode:     cfg.DatabaseSSLMode,
		SSLRootCert: cfg.DatabaseSSLRootCert,
		SSLCert:     cfg.DatabaseSSLCert,
		SSLKey:      cfg.DatabaseSSLKey,
	})
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Initialize Redis connection
	// Export DB pool saturation gauges (openidx_db_connections{state=...}).
	metrics.NewTracedPool(db.Pool, "access-service").StartPoolStatsCollector(context.Background())

	redis, err := database.NewRedisFromConfig(database.RedisConfig{
		URL:                cfg.RedisURL,
		SentinelEnabled:    cfg.RedisSentinelEnabled,
		SentinelMasterName: cfg.RedisSentinelMasterName,
		SentinelAddresses:  cfg.GetRedisSentinelAddresses(),
		SentinelPassword:   cfg.RedisSentinelPassword,
		Password:           cfg.GetRedisPassword(),
		TLSEnabled:         cfg.RedisTLSEnabled,
		TLSCACert:          cfg.RedisTLSCACert,
		TLSCert:            cfg.RedisTLSCert,
		TLSKey:             cfg.RedisTLSKey,
		TLSSkipVerify:      cfg.RedisTLSSkipVerify,
	})
	if err != nil {
		log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redis.Close()

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.New()
	// Restrict which proxy hops gin trusts when resolving the client IP from
	// X-Forwarded-For. Default trusts all proxies, making c.ClientIP() spoofable
	// (bypasses device-trust known-IP auto-approve, geo-block, spoofs audit IPs).
	middleware.ConfigureTrustedProxies(router, log)
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("access-service"))
	router.Use(middleware.SecurityHeadersForEnv(cfg.IsProduction()))
	router.Use(logger.GinMiddleware(log))
	if cfg.EnableRateLimit {
		router.Use(middleware.DistributedRateLimit(redis.Client, middleware.RateLimitConfig{
			Requests:     cfg.RateLimitRequests,
			Window:       time.Duration(cfg.RateLimitWindow) * time.Second,
			AuthRequests: cfg.RateLimitAuthRequests,
			AuthWindow:   time.Duration(cfg.RateLimitAuthWindow) * time.Second,
			PerUser:      cfg.RateLimitPerUser,
		}, log))
	}

	// CSRF protection for cookie-authenticated proxy sessions
	router.Use(middleware.CSRFProtection(middleware.CSRFConfig{
		Enabled:       cfg.CSRFEnabled,
		TrustedDomain: cfg.CSRFTrustedDomain,
	}, log))

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
	router.Use(middleware.PrometheusMetrics("access-service"))
	router.Use(api.StandardVersionMiddleware())

	// Resolve the tenant for every request and attach it to the request
	// context (v1.7.0 #2). Resolution at this point in the chain runs
	// before route-level auth, so it sees the gateway-set X-Org-Slug
	// header or falls back to the default org; the JWT-claim path
	// activates when resolution moves behind auth later in v1.7.0.
	// DefaultOrgFallback keeps single-tenant installs on the default
	// org — the final v1.7.0 PR flips it off.
	orgLookup := organization.NewOrgLookup(organization.NewService(db, redis, cfg, log))
	router.Use(middleware.TenantResolver(orgLookup, middleware.TenantResolverConfig{
		DefaultOrgFallback:     cfg.DefaultOrgFallback,
		DefaultOrgID:           cfg.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
		OnPlatformCrossOrg:     audit.CrossOrgAuditor(db.Pool, log),
	}))

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewReadReplicaChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Register standard health check endpoints
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /access/health and /access/ready endpoints for backward compatibility
	router.GET("/access/health", healthService.Handler())
	router.GET("/access/ready", healthService.ReadyHandler())

	// Initialize access proxy service
	accessService := access.NewService(db, redis, cfg, log)

	// Construct in-process vault (fail-closed): access-service issues its own
	// guacamole.credential_injected audit events so the vault Auditor is nil here.
	vaultRing, err := vault.KeyringFromConfig(vault.KeyConfig{
		KEK: cfg.VaultKEK, KEKs: cfg.VaultKEKs, ActiveKEKID: cfg.VaultActiveKEKID,
		EncryptionKey: cfg.EncryptionKey,
		Bao: vault.BaoConfig{Addr: cfg.BaoAddr, Token: cfg.BaoToken,
			SecretPath: cfg.BaoKEKPath, CACertFile: cfg.BaoCACert},
	})
	if err != nil {
		log.Fatal("vault keyring unavailable (fail-closed)", zap.Error(err))
	}
	vaultSvc, err := vault.NewService(db, vaultRing, nil,
		time.Duration(cfg.VaultRevealLeaseTTLSeconds)*time.Second, log)
	if err != nil {
		log.Fatal("vault service init failed", zap.Error(err))
	}
	accessService.SetVaultService(vaultSvc)

	// Background context for long-running goroutines
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Initialize BrowZer Target Manager for dynamic bootstrapper config
	var browzerTargetManager *access.BrowZerTargetManager
	if cfg.BrowZerTargetsPath != "" {
		browzerTargetManager = access.NewBrowZerTargetManager(db, log, cfg.BrowZerTargetsPath)
		if cfg.BrowZerRouterConfigPath != "" {
			browzerTargetManager.SetRouterConfigPath(cfg.BrowZerRouterConfigPath)
		}
		if cfg.BrowZerCertsPath != "" {
			browzerTargetManager.SetCertsPath(cfg.BrowZerCertsPath)
		}
		browzerTargetManager.SetHopConfigPath(cfg.BrowZerHopConfigPath)
		browzerTargetManager.SetHopCert(cfg.BrowZerHopCertPath, cfg.BrowZerHopKeyPath)
		_, hopPort := access.ParseHopAddr(cfg.ZitiBrowZerHopAddr)
		browzerTargetManager.SetHopPort(hopPort)
		// Public per-app vhost generation (front nginx).
		browzerTargetManager.SetVHostConfigPath(cfg.BrowZerVHostConfigPath)
		browzerTargetManager.SetBootstrapperPass(cfg.BrowZerBootstrapperAddr)
		browzerTargetManager.SetVHostSSL(cfg.BrowZerVHostSSLCert, cfg.BrowZerVHostSSLKey)
		browzerTargetManager.SetOIDCCallbacks(access.SplitCSV(cfg.BrowZerOIDCCallbackPaths))
		// Load configured domain from DB
		if err := browzerTargetManager.LoadDomainFromDB(bgCtx); err != nil {
			log.Warn("Failed to load BrowZer domain config", zap.Error(err))
		}
		accessService.SetBrowZerTargetManager(browzerTargetManager)
		log.Info("BrowZer Target Manager initialized",
			zap.String("targets_path", cfg.BrowZerTargetsPath),
			zap.String("router_config_path", cfg.BrowZerRouterConfigPath),
			zap.String("certs_path", cfg.BrowZerCertsPath),
			zap.String("domain", browzerTargetManager.GetDomain()))
	}

	// APISIX edge (opt-in): push BrowZer public routes to APISIX's Admin API
	// instead of generating nginx vhosts. Independent of the Ziti reconciler.
	if cfg.APISIXEdgeEnabled && browzerTargetManager != nil {
		apisixClient := access.NewAPISIXClient(cfg.APISIXAdminURL, cfg.APISIXAdminKey)
		_, apisixHopPort := access.ParseHopAddr(cfg.ZitiBrowZerHopAddr)
		apisixRec := access.NewAPISIXReconciler(db, log, apisixClient, browzerTargetManager,
			access.APISIXRouteOpts(cfg.APISIXBootstrapperNode, apisixHopPort, access.SplitCSV(cfg.BrowZerOIDCCallbackPaths)))
		browzerTargetManager.SetAPISIXReconciler(apisixRec)
		go func() {
			if err := apisixRec.Reconcile(bgCtx); err != nil {
				log.Warn("initial APISIX reconcile failed", zap.Error(err))
			} else {
				log.Info("APISIX edge routes reconciled")
			}
		}()
		log.Info("APISIX edge enabled (pushing BrowZer routes to Admin API)")
	}

	// Initialize APISIX SSL management
	if cfg.APISIXConfigPath != "" {
		accessService.SetAPISIXConfigPath(cfg.APISIXConfigPath)
		log.Info("APISIX SSL management initialized", zap.String("config_path", cfg.APISIXConfigPath))
	}

	// Initialize Feature Manager for unified service management
	featureManager := access.NewFeatureManager(db, log)
	if browzerTargetManager != nil {
		featureManager.SetBrowZerTargetManager(browzerTargetManager)
	}
	accessService.SetFeatureManager(featureManager)
	log.Info("Feature Manager initialized")

	// Initialize Unified Audit Service
	auditService := access.NewUnifiedAuditService(db, log)
	accessService.SetAuditService(auditService)
	log.Info("Unified Audit Service initialized")

	// Shared Ziti provider: the admin panel connects/reconnects/disconnects the
	// OpenZiti controller at runtime by swapping the manager held here. Wired to
	// all three services BEFORE routes are registered so the settings handlers
	// and every read site see the same provider.
	zitiProvider := access.NewZitiProvider()
	accessService.SetZitiProvider(zitiProvider)

	// Wire the Relations & Integrity Doctor engine. Must run after the
	// browzerTargetManager and zitiProvider setters above, since registerChecks
	// captures svc.db / svc.browzerTargetManager / svc.zitiProvider / svc.logger.
	// Checks are lazy (nothing is dialed at construction).
	accessService.SetHealthEngine(access.NewHealthEngine(accessService))

	// Initialize Apache Guacamole client if configured
	if cfg.GuacamoleURL != "" {
		log.Info("Initializing Apache Guacamole integration (direct PAM broker)...", zap.String("url", cfg.GuacamoleURL))
		gc := dialGuacBrokerWithRetry("direct", log, func() (*access.GuacamoleClient, error) {
			return access.NewGuacamoleClient(cfg, db, log)
		})
		if gc != nil {
			accessService.SetGuacamoleClient(gc)
			featureManager.SetGuacamoleClient(gc)
			auditService.SetGuacamoleClient(gc)
			log.Info("Apache Guacamole integration ready (direct PAM broker)")
		}
	}

	// Dedicated OpenZiti PAM broker — a second Guacamole whose guacd is colocated
	// with a ziti-tunnel, so entries with reach_mode='ziti' reach their target
	// over the overlay. Independent endpoint + admin credential from the direct
	// broker, so a connection is chosen per-entry (the Ziti enable/disable toggle)
	// and routed to the matching broker at connect time.
	if cfg.GuacamoleZitiURL != "" {
		log.Info("Initializing dedicated OpenZiti PAM broker...", zap.String("url", cfg.GuacamoleZitiURL))
		zgc := dialGuacBrokerWithRetry("ziti", log, func() (*access.GuacamoleClient, error) {
			return access.NewGuacamoleZitiClient(cfg, db, log)
		})
		if zgc != nil {
			accessService.SetGuacamoleZitiClient(zgc)
			log.Info("Dedicated OpenZiti PAM broker ready")
		}
	}

	// Per-user Guacamole identities: sweep stale per-connection grants + deprovision
	// accounts for disabled/removed users. Only started when the feature is enabled.
	if cfg.GuacamolePerUserIdentities {
		accessService.StartGuacGrantSweeper(context.Background())
		log.Info("Per-user Guacamole identities enabled; grant sweeper started")
	}

	// Start the EDR/MDM posture ingestion worker: polls configured EDR/MDM
	// sources (CrowdStrike/Intune/Jamf) and feeds device compliance into the
	// Ziti-bound posture pipeline. Idle until a source is configured.
	accessService.StartEDRIngestionWorker(context.Background())

	// Start the network revocation worker: severs live Ziti circuits for users
	// the governance service revoked (access-review/certification/JIT expiry).
	accessService.StartNetworkRevocationWorker(context.Background())

	// Start the JIT network grant worker: adds time-bound Ziti attributes when a
	// network_service access request is fulfilled (Wave B1).
	accessService.StartNetworkGrantWorker(context.Background())

	// Start continuous session verification if enabled
	if cfg.ContinuousVerifyEnabled {
		log.Info("Starting continuous session verifier", zap.Int("interval_seconds", cfg.ContinuousVerifyInterval))
		accessService.StartContinuousVerification(bgCtx, cfg.ContinuousVerifyInterval)
	}

	// Cross-pillar lifecycle enforcement: revoke live PAM access (vault
	// leases, JIT elevations, Guacamole sessions) of users disabled through
	// any path — the PAM counterpart of the Ziti deprovision sweep.
	accessService.StartLifecycleEnforcement(bgCtx, 30*time.Second)

	// Resolve the OpenZiti connection: persisted admin-panel settings win, else
	// env (cfg.Ziti*). Lets a box that booted disabled be connected later from
	// the panel with no restart, and vice-versa.
	bootCtx := orgctx.WithBypassRLS(context.Background())
	zCtrlURL, zUser, zPwd, zDir, zInsecure, zEnabled, zErr := access.ResolveBootZitiConn(
		bootCtx, db, cfg.EncryptionKey,
		cfg.ZitiCtrlURL, cfg.ZitiAdminUser, cfg.ZitiAdminPassword, cfg.ZitiIdentityDir,
		cfg.ZitiEnabled, cfg.ZitiInsecureSkipVerify)
	if zErr != nil {
		log.Error("Failed to resolve Ziti connection settings", zap.Error(zErr))
	}
	if zEnabled {
		log.Info("OpenZiti integration enabled, initializing ZitiManager...")
		zm, err := access.NewZitiManagerWithConn(cfg, zCtrlURL, zUser, zPwd, zDir, zInsecure, db, log)
		// In production, an enabled Ziti is a hard dependency: retry a bounded number of
		// times (the controller may still be coming up) and fail fast rather than
		// silently disabling it. In non-production keep the existing best-effort behavior
		// (single attempt, warn, continue) so a dev box without Ziti still boots.
		for attempt := 1; err != nil && cfg.IsProduction() && attempt < 5; attempt++ {
			log.Warn("ZitiManager init failed, retrying", zap.Int("attempt", attempt), zap.Int("max", 5), zap.Error(err))
			time.Sleep(3 * time.Second)
			zm, err = access.NewZitiManagerWithConn(cfg, zCtrlURL, zUser, zPwd, zDir, zInsecure, db, log)
		}
		if err != nil {
			if cfg.IsProduction() {
				log.Fatal("Ziti enabled but ZitiManager failed to initialize after retries", zap.Error(err))
			}
			log.Error("Failed to initialize ZitiManager -- Ziti features disabled", zap.Error(err))
		} else {
			// Start background monitors on a context owned by the provider slot
			// so a runtime reconnect can cancel them.
			// Bypass RLS: the Ziti/BrowZer startup + monitors host services and
			// read proxy_routes/ziti_services install-wide, with no request org.
			zitiCtx, zitiCancel := context.WithCancel(orgctx.WithBypassRLS(context.Background()))
			zitiProvider.Swap(zm, zitiCancel)
			zm.StartHealthMonitor(zitiCtx)
			zm.StartCertificateMonitor(zitiCtx)
			zm.StartUserSyncPoller(zitiCtx)
			zm.StartPostureResultExpiryChecker(zitiCtx)

			// BrowZer bootstrap + bootstrapper-target/router-config generation are
			// independent of WHO hosts the Ziti services (reconciler vs imperative),
			// so they run in BOTH modes. Only imperative hosting is reconciler-gated.
			if cfg.BrowZerEnabled {
				log.Info("Bootstrapping BrowZer configuration...")
				if err := zm.BootstrapBrowZer(zitiCtx, cfg.OAuthIssuer, cfg.OAuthJWKSURL, cfg.BrowZerClientID); err != nil {
					log.Error("BrowZer bootstrap failed -- BrowZer features disabled", zap.Error(err))
				} else {
					log.Info("BrowZer bootstrap complete")
				}
			}

			writeBrowZerConfigs := func() {
				if browzerTargetManager != nil {
					if err := browzerTargetManager.WriteBrowZerTargets(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer targets", zap.Error(err))
					} else {
						log.Info("Initial BrowZer targets file generated")
					}
					if err := browzerTargetManager.WriteBrowZerRouterConfig(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer router config", zap.Error(err))
					} else {
						log.Info("Initial BrowZer router config generated")
					}
					if err := browzerTargetManager.WriteBrowZerHopConfig(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer hop config", zap.Error(err))
					} else {
						log.Info("Initial BrowZer hop config generated")
					}
					if err := browzerTargetManager.WriteBrowZerVHostConfig(zitiCtx); err != nil {
						log.Warn("Failed to write initial BrowZer public vhost config", zap.Error(err))
					} else {
						log.Info("Initial BrowZer public vhost config generated")
					}
				}
			}

			if cfg.ZitiReconcilerEnabled {
				reconciler := access.NewZitiReconciler(db, log, zitiProvider, cfg.ZitiBrowZerHopAddr).
					SetPerOrgAttributes(cfg.ZitiPerOrgAttributes)
				// Dark-platform: when a DARK_MODE tier is enabled, the reconciler
				// also models OpenIDX's OWN surfaces as tier'd overlay-only Ziti
				// services (host.v1 → loopback, tier dial policy). Inert otherwise.
				if cfg.DarkModeTier1 || cfg.DarkModeTier2 {
					reconciler.EnableDefaultDarkServices()
					log.Info("dark-platform: reconciler will model OpenIDX surfaces as tier'd dark services",
						zap.Bool("tier1", cfg.DarkModeTier1), zap.Bool("tier2", cfg.DarkModeTier2))
				}
				// Process-lifetime context, NOT zitiCtx: an admin-panel reconnect
				// Swaps the provider slot and cancels zitiCtx, which used to kill
				// the reconciler loop for good. The loop is cheap and no-ops while
				// no live manager is present, so it simply rides across swaps.
				reconciler.Start(orgctx.WithBypassRLS(context.Background()))
				accessService.SetZitiReconciler(reconciler)
				// The admin-console one-click toggle must defer to the reconciler too:
				// only write proxy_routes flags, never imperatively provision Ziti.
				featureManager.SetReconcilerEnabled(true)
				log.Info("Ziti reconciler started (default; ZITI_RECONCILER=false for legacy imperative hosting)")
				// The reconciler creates/hosts the per-app Ziti services; we still
				// (re)generate the bootstrapper targets so the browser dials them.
				go writeBrowZerConfigs()
			} else {
				// Imperative path: the access-proxy SDK hosts the services.
				zm.HostAllServices(zitiCtx)
				go func() {
					accessService.EnsureZitiServicesForRoutes(zitiCtx, zm)
					accessService.EnsureBrowZerRouterService(zitiCtx, zm)
					writeBrowZerConfigs()
				}()
			}

			log.Info("OpenZiti integration ready (health + certificate monitors started, services hosted)")
		}
	} else {
		log.Info("OpenZiti integration disabled (set ZITI_ENABLED=true to enable)")
	}

	// Start background audit event sync (every 5 minutes)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		// Initial sync after 30 seconds
		time.Sleep(30 * time.Second)
		if err := auditService.SyncExternalAuditEvents(bgCtx); err != nil {
			log.Warn("Initial external audit sync failed", zap.Error(err))
		} else {
			log.Info("Initial external audit sync completed")
		}

		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				if err := auditService.SyncExternalAuditEvents(bgCtx); err != nil {
					log.Warn("External audit sync failed", zap.Error(err))
				}
			}
		}
	}()
	log.Info("Background audit sync scheduled (every 5 minutes)")

	// Register routes with an auth middleware ALWAYS attached — never with a
	// bare (unauthenticated) group. Production hard-blocks and accepts both OAuth
	// JWTs and minted API keys / service-account PATs; development uses SoftAuth,
	// which still verifies and attaches a bearer identity (so user_id flows to the
	// handlers) but does not hard-block unauthenticated local calls. Registering
	// the group with no middleware in dev previously left the entire
	// /api/v1/access surface unauthenticated (see the PAM endpoint-control fix).
	if cfg.Environment != "development" {
		apiKeyService := apikeys.NewService(db, redis, log)
		access.RegisterRoutes(router, accessService, middleware.AuthWithAPIKey(cfg.OAuthJWKSURL, apiKeyService.MiddlewareValidator()))
	} else if cfg.AccessAPIRequireAuth {
		// Dev mode but the box is reachable off-localhost: force the same
		// hard-blocking auth as production so the data API refuses anonymous
		// callers, while keeping the rest of dev-mode ergonomics. The Tier-0
		// enroll door / agent / APK / temp-access routes sit outside this group
		// and stay public.
		apiKeyService := apikeys.NewService(db, redis, log)
		log.Warn("ACCESS_API_REQUIRE_AUTH=true: forcing hard auth on /api/v1/access data API despite APP_ENV=development")
		access.RegisterRoutes(router, accessService, middleware.AuthWithAPIKey(cfg.OAuthJWKSURL, apiKeyService.MiddlewareValidator()))
	} else {
		access.RegisterRoutes(router, accessService, middleware.SoftAuth(cfg.OAuthJWKSURL))
	}

	// Create HTTP server
	port := cfg.Port
	if port == 0 {
		port = 8007
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.BindAddr, port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Build shutdownables list
	var shutdownables []server.Shutdownable
	shutdownables = append(shutdownables, server.CloseDB(db))
	shutdownables = append(shutdownables, server.CloseRedis(redis))
	if shutdownTracer != nil {
		shutdownables = append(shutdownables, server.CloseTracer(shutdownTracer))
	}

	// Create graceful manager
	graceful := server.New(server.Config{
		Server:          httpServer,
		Logger:          log,
		Shutdownables:   shutdownables,
		ShutdownTimeout: cfg.ShutdownTimeout(),
	})

	// PAM C2: leader-gated privileged-session risk scorer. No-op when the gate
	// is "off" (default); "observe" audits what would be suspended; "enforce"
	// terminates risky sessions. Started after the Guacamole clients are wired
	// so it can terminate live connections.
	access.NewPAMSessionRiskScorer(accessService, 60*time.Second, cfg.PAMSessionRiskGate, cfg.PAMSessionRiskThreshold, log).
		Start(orgctx.WithBypassRLS(context.Background()))

	// Start server in goroutine
	go func() {
		log.Info("Starting Access Proxy service", zap.Int("port", port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()
}
