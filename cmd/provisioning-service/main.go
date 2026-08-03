// Package main is the entry point for the Provisioning Service
// Provisioning Service handles SCIM 2.0, user lifecycle, and directory sync
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/health"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/opa"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/provisioning"
	"github.com/openidx/openidx/internal/server"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

func main() {
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Provisioning Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("provisioning-service")
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
	tracingCfg := tracing.ConfigFromEnv("provisioning-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	}

	// When OPA authz is enabled, fail fast if the policy engine isn't reachable at
	// boot in production; warn and continue in dev so a slightly-late OPA doesn't
	// crash-loop the stack. Guard matches the actual OPA-usage condition below
	// (cfg.EnableOPAAuthz) so a deploy that doesn't use OPA never blocks on it.
	if cfg.EnableOPAAuthz && cfg.OPAURL != "" {
		opaCtx, opaCancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := health.WaitForDependency(opaCtx, log, "opa", 10, 3*time.Second, health.ProbeOPA(cfg.OPAURL, 2*time.Second)); err != nil {
			if cfg.IsProduction() {
				log.Fatal("OPA policy engine not reachable at startup", zap.Error(err))
			}
			log.Warn("OPA policy engine not reachable at startup; continuing (non-production)", zap.Error(err))
		}
		opaCancel()
	}

	db, err := database.NewPostgres(cfg.DatabaseURL, database.PostgresTLSConfig{
		SSLMode:     cfg.DatabaseSSLMode,
		SSLRootCert: cfg.DatabaseSSLRootCert,
		SSLCert:     cfg.DatabaseSSLCert,
		SSLKey:      cfg.DatabaseSSLKey,
	})
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}

	// Export DB pool saturation gauges (openidx_db_connections{state=...}).
	metrics.NewTracedPool(db.Pool, "provisioning-service").StartPoolStatsCollector(context.Background())

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

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	// Restrict which proxy hops gin trusts when resolving the client IP from
	// X-Forwarded-For. Default trusts all proxies, making c.ClientIP() spoofable
	// (bypasses device-trust known-IP auto-approve, geo-block, spoofs audit IPs).
	middleware.ConfigureTrustedProxies(router, log)
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("provisioning-service"))
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
	router.Use(metrics.Middleware("provisioning-service"))

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// API versioning middleware
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

	provisioningService := provisioning.NewService(db, redis, cfg, log)

	// Start the outbound-SCIM provisioning worker: it drains the outbox and
	// pushes user/group changes to configured downstream SaaS targets. Idle
	// (no-op) until an operator configures a target app.
	provisioningService.StartOutboundWorker(context.Background())

	// Register routes (with optional OPA authorization)
	var opaMiddleware []gin.HandlerFunc
	if cfg.EnableOPAAuthz {
		opaClient := opa.NewClient(cfg.OPAURL, log)
		opaMiddleware = append(opaMiddleware, middleware.OPAAuthz(opaClient, log, cfg.IsDevelopment()))
	}
	provisioning.RegisterRoutes(router, provisioningService, opaMiddleware...)

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewReadReplicaChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Register standard health check endpoints
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	httpServer := &http.Server{
		Addr:         cfg.ListenAddr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup graceful shutdown manager
	shutdownables := []server.Shutdownable{
		server.CloseDB(db),
		server.CloseRedis(redis),
	}
	if shutdownTracer != nil {
		shutdownables = append(shutdownables, server.CloseTracer(shutdownTracer))
	}

	graceful := server.New(server.Config{
		Server:          httpServer,
		Logger:          log,
		Shutdownables:   shutdownables,
		ShutdownTimeout: cfg.ShutdownTimeout(),
	})

	go func() {
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	graceful.Start()

	log.Info("Server exited")
}
