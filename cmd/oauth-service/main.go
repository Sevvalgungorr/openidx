// Package main is the entry point for the OAuth/OIDC Service
// OAuth Service provides OAuth 2.0 and OpenID Connect capabilities
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/apikeys"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	"github.com/openidx/openidx/internal/directory"
	"github.com/openidx/openidx/internal/email"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/oauth"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/server"
	"github.com/openidx/openidx/internal/webhooks"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

func main() {
	// Initialize logger
	log := logger.New()
	defer log.Sync()

	log.Info("Starting OAuth/OIDC Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("oauth-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Validate production security settings (blocking)
	if err := config.ValidateProductionConfig(cfg, log); err != nil {
		log.Fatal("Production security validation failed", zap.Error(err))
	}

	// Dark-platform: refuse to start on a public bind when a DARK_MODE tier is on
	// (a "dark" service must be reachable only over the OpenZiti overlay).
	if err := cfg.ValidateDarkModeBind(); err != nil {
		log.Fatal("Dark-mode bind validation failed", zap.Error(err))
	}

	cfg.LogSecurityWarnings(log)

	// Initialize tracing
	tracingCfg := tracing.ConfigFromEnv("oauth-service", cfg.Environment)
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
	metrics.NewTracedPool(db.Pool, "oauth-service").StartPoolStatsCollector(context.Background())

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
	router.Use(otelgin.Middleware("oauth-service"))
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

	// Enable CORS for OAuth endpoints
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
	router.Use(middleware.PrometheusMetrics("oauth-service"))
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

	// Initialize Identity service
	identityService := identity.NewService(db, redis, cfg, log)

	// Wire the email service so the OAuth flows that depend on it work:
	// magic-link login delivery and email OTP challenges both call through the
	// identity service. Emails are enqueued to a shared Redis queue; this
	// service also drains it so it can deliver its own mail without depending
	// on another service being up.
	emailService := email.NewService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, redis, log)
	identityService.SetEmailService(emailService)

	// Wire the directory service so LDAP / Active Directory users can log in
	// against their directory (bind check) at /oauth/login. Without this,
	// directory-sourced users fall through to a local bcrypt check against the
	// sync-time placeholder hash and can never authenticate ("invalid username
	// or password"). We construct the directory service for auth only and do NOT
	// call Start() — the sync scheduler is owned by identity-service; here we
	// just need the per-directory bind (AuthenticateUser).
	dirService := directory.NewService(db, log)
	identityService.SetDirectoryService(dirService)

	// Initialize risk service (conditional access)
	riskService := risk.NewService(db, redis, log)

	// Initialize webhook service
	webhookSecretCipher, err := secretcrypt.New(cfg.EncryptionKey)
	if err != nil {
		log.Warn("webhook signing secrets will NOT be encrypted at rest; set a 32-byte ENCRYPTION_KEY to enable", zap.Error(err))
		webhookSecretCipher = secretcrypt.NewNoop()
	}
	webhookService := webhooks.NewService(db, redis, log, webhookSecretCipher)
	ctx, cancelWorkers := context.WithCancel(context.Background())
	go webhookService.ProcessDeliveries(ctx)
	go webhookService.ProcessRetries(ctx)
	go emailService.ProcessQueue(ctx)
	defer cancelWorkers()

	// Initialize OAuth service
	oauthService, err := oauth.NewService(db, redis, cfg, log, identityService)
	if err != nil {
		log.Fatal("Failed to initialize OAuth service", zap.Error(err))
	}
	oauthService.SetRiskService(riskService)
	oauthService.SetWebhookService(webhookService)

	// Start background session expiry worker
	oauthService.StartSessionWorker(ctx)

	// SSF/CAEP transmitter: drain the SET outbox and push signed security event
	// tokens to subscribed receivers. Idle until a stream is configured.
	oauthService.StartSSFPushWorker(ctx)

	// The client-management API (/api/v1/oauth/clients) is ALWAYS authenticated
	// — it creates/modifies OAuth clients, so it must never be reachable
	// unauthenticated, including in development. The interactive OIDC flow
	// endpoints (consent, step-up) are authenticated only outside development,
	// preserving the friction-free local login flow.
	// Accept both OAuth JWTs and minted API keys / service-account PATs on the
	// authenticated surfaces (client-management API, and the flow endpoints
	// outside development).
	apiKeyService := apikeys.NewService(db, redis, log)
	authMW := middleware.AuthWithAPIKey(cfg.OAuthJWKSURL, apiKeyService.MiddlewareValidator())
	var flowAuth []gin.HandlerFunc
	if cfg.Environment != "development" {
		flowAuth = append(flowAuth, authMW)
	}
	oauth.RegisterRoutes(router, oauthService, authMW, flowAuth...)

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewReadReplicaChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Register standard health check endpoints (/health/live, /health/ready, /health)
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Create HTTP server
	port := cfg.Port
	if port == 0 {
		port = 8006
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.BindAddr, port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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

	// Start server in goroutine
	go func() {
		log.Info("Starting OAuth service", zap.Int("port", port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()
}
