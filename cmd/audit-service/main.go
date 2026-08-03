// Package main is the entry point for the Audit Service
// Audit Service handles logging, compliance reporting, and SIEM integration
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/api"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/tlsutil"
	"github.com/openidx/openidx/internal/common/tracing"
	newhealth "github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/organization"
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

	log.Info("Starting Audit Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("audit-service")
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
	tracingCfg := tracing.ConfigFromEnv("audit-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
	} else {
		defer shutdownTracer(context.Background())
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
	defer db.Close()

	// Initialize Redis connection (used for distributed rate limiting)
	// Export DB pool saturation gauges (openidx_db_connections{state=...}).
	metrics.NewTracedPool(db.Pool, "audit-service").StartPoolStatsCollector(context.Background())

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
		log.Warn("Failed to connect to Redis, rate limiting will fail open", zap.Error(err))
	} else {
		defer redis.Close()
	}

	// Initialize Elasticsearch client (best-effort — audit works without ES)
	var es *database.ElasticsearchClient
	if cfg.ElasticsearchURL != "" {
		es, err = database.NewElasticsearchFromConfig(database.ElasticsearchConfig{
			URL:      cfg.ElasticsearchURL,
			Username: cfg.ElasticsearchUsername,
			Password: cfg.ElasticsearchPassword,
			TLS:      cfg.ElasticsearchTLS,
			CACert:   cfg.ElasticsearchCACert,
		})
		if err != nil {
			log.Warn("Elasticsearch unavailable, full-text search disabled", zap.Error(err))
		}
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
	router.Use(otelgin.Middleware("audit-service"))
	router.Use(middleware.SecurityHeadersForEnv(cfg.IsProduction()))
	router.Use(logger.GinMiddleware(log))
	if cfg.EnableRateLimit {
		var redisClient *goredis.Client
		if redis != nil {
			redisClient = redis.Client
		}
		router.Use(middleware.DistributedRateLimit(redisClient, middleware.RateLimitConfig{
			Requests:     cfg.RateLimitRequests,
			Window:       time.Duration(cfg.RateLimitWindow) * time.Second,
			AuthRequests: cfg.RateLimitAuthRequests,
			AuthWindow:   time.Duration(cfg.RateLimitAuthWindow) * time.Second,
			PerUser:      cfg.RateLimitPerUser,
		}, log))
	}
	router.Use(middleware.PrometheusMetrics("audit-service"))
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

	auditService := audit.NewService(db, es, cfg, log)
	if es != nil {
		if err := auditService.InitElasticsearch(); err != nil {
			log.Warn("Failed to initialize ES index, search may not work", zap.Error(err))
		}
		// Backfill any audit event the fire-and-forget ES write missed.
		auditService.StartESReconciler(context.Background())
	}

	// SIEM forwarder: stream the unified audit trail to an external SIEM
	// (syslog/CEF/Splunk HEC). No-op unless AUDIT_SIEM_ENABLED=true.
	auditService.StartSIEMForwarder(context.Background())

	// Start the usage metering aggregator: rolls up Ziti fabric events into daily
	// per-org/service/identity counters (Wave A4, the MSP billing substrate).
	auditService.StartUsageMetering(context.Background())

	// Initialize EventStreamer with WebSocket origin validation
	streamConfig := audit.StreamConfigFromAppConfig(cfg)
	eventStreamer := audit.NewEventStreamerWithConfig(log, auditService, streamConfig)
	// Enable JWT auth on the stream (WebSocket subprotocol + REST middleware).
	eventStreamer.SetJWKSURL(cfg.OAuthJWKSURL)

	// The audit trail is sensitive security data: every READ/report/export/stream
	// route must be authenticated. Only the internal server-to-server ingestion
	// endpoint (POST /events) is intentionally left open (network-isolated) — see
	// RegisterRoutes. Historically NONE of the audit routes had auth, so the whole
	// trail was readable/streamable unauthenticated.
	var auditAuth []gin.HandlerFunc
	if cfg.OAuthJWKSURL != "" {
		auditAuth = append(auditAuth, middleware.Auth(cfg.OAuthJWKSURL))
	} else if cfg.IsProduction() {
		log.Error("OAUTH_JWKS_URL is not set — the audit trail read/export/stream routes would be UNAUTHENTICATED in production. Refusing to serve them open; set OAUTH_JWKS_URL.")
		os.Exit(1)
	} else {
		log.Warn("OAUTH_JWKS_URL not set — audit read/export/stream routes are UNAUTHENTICATED (dev only). Set OAUTH_JWKS_URL to enable auth.")
	}

	// Register standard audit routes
	audit.RegisterRoutes(router, auditService, auditAuth...)
	audit.RegisterReportRoutes(router.Group("/api/v1/audit"), auditService, auditAuth...)

	// Register WebSocket streaming routes with origin validation
	eventStreamer.RegisterRoutes(router.Group("/api/v1/audit"))

	// Log the WebSocket origin configuration
	log.Info("Audit WebSocket streamer initialized",
		zap.Int("allowed_origins_count", len(streamConfig.AllowedOrigins)),
		zap.Bool("security_logging_enabled", streamConfig.EnableSecurityLogging),
		zap.Int("max_message_size", streamConfig.MaxMessageSize))

	// Initialize health service with database check
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewReadReplicaChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Add Elasticsearch check if configured (optional dependency)
	if es != nil {
		healthService.RegisterCheck(&elasticsearchChecker{client: es})
	}

	// Register standard health check endpoints (/health/live, /health/ready, /health)
	healthService.RegisterStandardRoutes(router, "")

	// Keep legacy /ready endpoint for backward compatibility
	router.GET("/ready", healthService.ReadyHandler())

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         cfg.ListenAddr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Build shutdownables list
	var shutdownables []server.Shutdownable
	shutdownables = append(shutdownables, server.CloseDB(db))
	if redis != nil {
		shutdownables = append(shutdownables, server.CloseRedis(redis))
	}
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
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()
}

// elasticsearchChecker implements health.HealthChecker for Elasticsearch
type elasticsearchChecker struct {
	client *database.ElasticsearchClient
}

func (e *elasticsearchChecker) Name() string {
	return "elasticsearch"
}

func (e *elasticsearchChecker) IsCritical() bool {
	return false // Elasticsearch is optional for audit service
}

func (e *elasticsearchChecker) Check(ctx context.Context) newhealth.ComponentStatus {
	start := time.Now()

	err := e.client.Ping()
	latency := time.Since(start)

	if err != nil {
		return newhealth.ComponentStatus{
			Status:    "down",
			LatencyMS: float64(latency.Milliseconds()),
			Details:   fmt.Sprintf("ping failed: %v", err),
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	status := "up"
	details := ""
	if latency > 500*time.Millisecond {
		status = "degraded"
		details = fmt.Sprintf("high latency: %s", latency.String())
	}

	return newhealth.ComponentStatus{
		Status:    status,
		LatencyMS: float64(latency.Milliseconds()),
		Details:   details,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}
