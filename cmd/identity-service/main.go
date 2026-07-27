// Package main is the entry point for the Identity Service
// Identity Service handles authentication, session management, and SSO
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/openidx/openidx/internal/ai"
	"github.com/openidx/openidx/internal/api"
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
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/portal"
	"github.com/openidx/openidx/internal/profiling"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/server"
	"github.com/openidx/openidx/internal/sms"
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

	log.Info("Starting Identity Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	// Load configuration
	cfg, err := config.Load("identity-service")
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
	tracingCfg := tracing.ConfigFromEnv("identity-service", cfg.Environment)
	shutdownTracer, err := tracing.Init(context.Background(), tracingCfg, log)
	if err != nil {
		log.Warn("Failed to initialize tracing", zap.Error(err))
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

	// Run auto-migrations if enabled
	if cfg.AutoMigrate {
		log.Info("Running auto-migrations")
		migrations.MustAutoMigrate(context.Background(), db.Pool, log)
	}

	// Initialize Redis connection
	// Export DB pool saturation gauges (openidx_db_connections{state=...}).
	metrics.NewTracedPool(db.Pool, "identity-service").StartPoolStatsCollector(context.Background())

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

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(otelgin.Middleware("identity-service"))
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
	// Use new Prometheus metrics middleware
	router.Use(metrics.Middleware("identity-service"))

	// Metrics endpoint
	router.GET("/metrics", metrics.Handler())

	// Register pprof endpoints in development mode
	profiling.RegisterWithEngine(router, cfg.IsDevelopment())

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

	// Initialize directory service for LDAP sync
	dirService := directory.NewService(db, log)
	if redis != nil {
		dirService.SetRedis(redis.Client) // leader-gate the sync tick across replicas
	}
	if err := dirService.Start(context.Background()); err != nil {
		log.Error("Directory service failed to start", zap.Error(err))
	}

	// Initialize email service
	emailService := email.NewService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, redis, log)

	// Initialize webhook service
	webhookSecretCipher, err := secretcrypt.New(cfg.EncryptionKey)
	if err != nil {
		log.Warn("webhook signing secrets will NOT be encrypted at rest; set a 32-byte ENCRYPTION_KEY to enable", zap.Error(err))
		webhookSecretCipher = secretcrypt.NewNoop()
	}
	webhookService := webhooks.NewService(db, redis, log, webhookSecretCipher)

	// Initialize risk/anomaly service
	riskService := risk.NewService(db, redis, log)

	// Initialize SMS service
	smsConfig := sms.Config{
		Provider:           cfg.SMS.Provider,
		Enabled:            cfg.SMS.Enabled,
		MessagePrefix:      cfg.SMS.MessagePrefix,
		TwilioSID:          cfg.SMS.TwilioSID,
		TwilioToken:        cfg.SMS.TwilioToken,
		TwilioFrom:         cfg.SMS.TwilioFrom,
		AWSRegion:          cfg.SMS.AWSRegion,
		AWSAccessKey:       cfg.SMS.AWSAccessKey,
		AWSSecretKey:       cfg.SMS.AWSSecretKey,
		WebhookURL:         cfg.SMS.WebhookURL,
		WebhookAPIKey:      cfg.SMS.WebhookAPIKey,
		NetGSMUserCode:     cfg.SMS.NetGSMUserCode,
		NetGSMPassword:     cfg.SMS.NetGSMPassword,
		NetGSMHeader:       cfg.SMS.NetGSMHeader,
		IletiMerkeziKey:    cfg.SMS.IletiMerkeziKey,
		IletiMerkeziSecret: cfg.SMS.IletiMerkeziSecret,
		IletiMerkeziSender: cfg.SMS.IletiMerkeziSender,
		VerimorUsername:    cfg.SMS.VerimorUsername,
		VerimorPassword:    cfg.SMS.VerimorPassword,
		VerimorSourceAddr:  cfg.SMS.VerimorSourceAddr,
		TurkcellUsername:   cfg.SMS.TurkcellUsername,
		TurkcellPassword:   cfg.SMS.TurkcellPassword,
		TurkcellSender:     cfg.SMS.TurkcellSender,
		VodafoneAPIKey:     cfg.SMS.VodafoneAPIKey,
		VodafoneSecret:     cfg.SMS.VodafoneSecret,
		VodafoneSender:     cfg.SMS.VodafoneSender,
		TurkTelekomAPIKey:  cfg.SMS.TurkTelekomAPIKey,
		TurkTelekomSecret:  cfg.SMS.TurkTelekomSecret,
		TurkTelekomSender:  cfg.SMS.TurkTelekomSender,
		MutlucellUsername:  cfg.SMS.MutlucellUsername,
		MutlucellPassword:  cfg.SMS.MutlucellPassword,
		MutlucellAPIKey:    cfg.SMS.MutlucellAPIKey,
		MutlucellSender:    cfg.SMS.MutlucellSender,
	}
	smsService, err := sms.NewService(smsConfig, log)
	if err != nil {
		log.Error("Failed to initialize SMS service, falling back to mock", zap.Error(err))
		smsService, _ = sms.NewService(sms.DefaultConfig(), log)
	}

	// Start background workers
	bgCtx, cancelWorkers := context.WithCancel(context.Background())
	go emailService.ProcessQueue(bgCtx)
	go webhookService.ProcessDeliveries(bgCtx)
	go webhookService.ProcessRetries(bgCtx)

	// Initialize identity service
	identityService := identity.NewService(db, redis, cfg, log)
	identityService.SetDirectoryService(dirService)
	identityService.SetEmailService(emailService)
	identityService.SetWebhookService(webhookService)
	identityService.SetAnomalyDetector(&anomalyDetectorAdapter{riskService: riskService})
	identityService.SetRiskService(riskService)
	identityService.SetSMSProvider(smsService)

	// Start SMS config watcher (polls DB every 30s for admin console changes)
	go identityService.StartSMSConfigWatcher(bgCtx, 30*time.Second)

	// Start role expiration checker (cleans up expired time-bound role assignments)
	identityService.StartRoleExpirationChecker(bgCtx)

	// Initialize portal service (with the optional local AI client for
	// plain-language security insights; template output when disabled)
	portalService := portal.NewService(db, log)
	portalService.SetAIClient(ai.NewClient(cfg, log))

	// Initialize notification service
	notifService := notifications.NewService(db, log)

	// Register routes
	identity.RegisterRoutes(router, identityService)

	// Portal and notification routes need auth middleware to identify the caller
	portalGroup := router.Group("/api/v1/identity")
	portalGroup.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
	portal.RegisterRoutes(portalGroup, portalService)

	notifGroup := router.Group("/api/v1/identity")
	notifGroup.Use(middleware.SoftAuth(cfg.OAuthJWKSURL))
	notifications.RegisterRoutes(notifGroup, notifService)

	// Initialize health service with database and Redis checks
	healthService := newhealth.NewHealthService(log)
	healthService.SetVersion(Version)
	healthService.RegisterCheck(newhealth.NewPostgresChecker(db))
	healthService.RegisterCheck(newhealth.NewReadReplicaChecker(db))
	healthService.RegisterCheck(newhealth.NewRedisChecker(redis))

	// Register standard health check endpoints (/health, /health/ready, /health/live)
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

	// Setup graceful shutdown manager with all components
	shutdownables := []server.Shutdownable{
		server.CloseDB(db),
		server.CloseRedis(redis),
		server.CancelContext(cancelWorkers),
		server.NewShutdownFunc("directory", func(ctx context.Context) error {
			dirService.Stop()
			return nil
		}),
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

	// Start server in goroutine
	go func() {
		log.Info("Server listening", zap.Int("port", cfg.Port))
		if err := tlsutil.ListenAndServe(httpServer, cfg.TLS, log); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	graceful.Start()

	log.Info("Server exited")
}

// anomalyDetectorAdapter adapts risk.Service to identity.AnomalyDetector interface
type anomalyDetectorAdapter struct {
	riskService *risk.Service
}

func (a *anomalyDetectorAdapter) RunAnomalyCheck(ctx context.Context, userID, ip, userAgent string, lat, lon float64) interface{} {
	return a.riskService.RunAnomalyCheck(ctx, userID, ip, userAgent, lat, lon)
}

func (a *anomalyDetectorAdapter) CheckIPThreatList(ctx context.Context, ip string) (bool, string) {
	return a.riskService.CheckIPThreatList(ctx, ip)
}
