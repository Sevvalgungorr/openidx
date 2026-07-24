// Package config provides configuration management for OpenIDX services
package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// sslmodeRe extracts the sslmode from a DATABASE_URL (URL "?sslmode=" or DSN
// "sslmode=" form).
var sslmodeRe = regexp.MustCompile(`sslmode=([a-zA-Z-]+)`)

// Built-in default admin passwords. They exist only so the local docker stack
// boots without extra config; ValidateProduction rejects them when the
// corresponding integration is enabled, so a prod deploy can't ship with a
// credential that is published in this source tree.
const (
	defaultZitiAdminPassword      = "openidx_ziti_admin"
	defaultGuacamoleAdminPassword = "guacadmin"
)

// Config holds all configuration for the application
type Config struct {
	// Service identification
	ServiceName string `mapstructure:"service_name"`
	Environment string `mapstructure:"environment"`
	Port        int    `mapstructure:"port"`
	// BindAddr is the interface the HTTP server binds. Empty (default) means all
	// interfaces (":<port>", today's behavior); "127.0.0.1" binds loopback-only,
	// which is how a service goes "dark" (overlay-only reach). See the
	// dark-platform spec: docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md.
	BindAddr string `mapstructure:"bind_addr"`
	LogLevel string `mapstructure:"log_level"`

	// ShutdownTimeoutSeconds bounds the graceful-shutdown drain window for the
	// HTTP server. Non-positive falls back to 30s (see ShutdownTimeout).
	ShutdownTimeoutSeconds int `mapstructure:"shutdown_timeout_seconds"`

	// Database connections
	DatabaseURL      string `mapstructure:"database_url"`
	RedisURL         string `mapstructure:"redis_url"`
	ElasticsearchURL string `mapstructure:"elasticsearch_url"`

	// OPA configuration
	OPAURL         string `mapstructure:"opa_url"`
	EnableOPAAuthz bool   `mapstructure:"enable_opa_authz"`

	// OAuth / OIDC settings
	OAuthIssuer  string `mapstructure:"oauth_issuer"`
	OAuthJWKSURL string `mapstructure:"oauth_jwks_url"`

	// Security settings
	JWTSecret          string `mapstructure:"jwt_secret"`
	EncryptionKey      string `mapstructure:"encryption_key"`
	CORSAllowedOrigins string `mapstructure:"cors_allowed_origins"`

	// Feature flags
	EnableMFA          bool `mapstructure:"enable_mfa"`
	EnableAuditLogging bool `mapstructure:"enable_audit_logging"`
	EnableRateLimit    bool `mapstructure:"enable_rate_limit"`

	// Rate limiting
	RateLimitRequests     int  `mapstructure:"rate_limit_requests"`
	RateLimitWindow       int  `mapstructure:"rate_limit_window"`
	RateLimitAuthRequests int  `mapstructure:"rate_limit_auth_requests"`
	RateLimitAuthWindow   int  `mapstructure:"rate_limit_auth_window"`
	RateLimitPerUser      bool `mapstructure:"rate_limit_per_user"`

	// SMTP configuration (for email notifications)
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password"`
	SMTPFrom     string `mapstructure:"smtp_from"`

	// Access Proxy settings
	GovernanceURL string `mapstructure:"governance_url"`
	AuditURL      string `mapstructure:"audit_url"`

	// InternalServiceToken is a shared secret for trusted service-to-service
	// calls (the access-proxy authenticating its policy /evaluate call to the
	// governance service). Empty disables the internal-auth path, leaving only
	// user JWT auth. Set the same value on every service that participates.
	InternalServiceToken string `mapstructure:"internal_service_token"`
	AccessSessionSecret  string `mapstructure:"access_session_secret"`
	AccessProxyDomain    string `mapstructure:"access_proxy_domain"`

	// AccessAppsDomain is the wildcard base domain that one-click published
	// apps live under (e.g. "apps.tdv.org" → "<slug>.apps.tdv.org"). When set,
	// publishing an app as a one-click tile derives its public host from this.
	// Empty disables the slug default (a public_host must be given explicitly).
	AccessAppsDomain string `mapstructure:"access_apps_domain"`

	// Multi-tenancy: the wildcard domain tenants live under
	// (e.g. "openidx.io" for acme.openidx.io). When set, the gateway
	// derives the X-Org-Slug header from the request's subdomain.
	// Empty (the default) disables subdomain tenant resolution.
	TenantBaseDomain string `mapstructure:"tenant_base_domain"`

	// DCRInitialAccessToken gates RFC 7591 dynamic client registration. Empty
	// (default) leaves registration open; set it to require a bearer initial
	// access token on POST /oauth/register.
	DCRInitialAccessToken string `mapstructure:"dcr_initial_access_token"`

	// SSFReceiverIssuer / SSFReceiverJWKSURL trust an upstream SSF transmitter
	// for inbound SET (RFC 8417) validation on POST /ssf/events. Empty leaves the
	// receiver accepting only OpenIDX-issued SETs.
	SSFReceiverIssuer  string `mapstructure:"ssf_receiver_issuer"`
	SSFReceiverJWKSURL string `mapstructure:"ssf_receiver_jwks_url"`

	// ZitiPerOrgAttributes, when true, namespaces a user's Ziti group role
	// attributes by their org (org-<org_id>-<group>) so two tenants' identically
	// named groups don't collide on the overlay (Wave A2, the MSP-channel
	// prerequisite). Off by default: single-tenant installs keep bare group
	// names and their existing service policies unchanged.
	ZitiPerOrgAttributes bool `mapstructure:"ziti_per_org_attributes"`

	// DefaultOrgFallback, when true, makes the TenantResolver attach the
	// install's default org to any request that resolves no tenant signal
	// (single-tenant compatibility). v1.7.0 ships with this OFF: a request
	// that carries no org is rejected (400) rather than silently scoped to
	// the default org. Single-tenant installs set DEFAULT_ORG_FALLBACK=true.
	DefaultOrgFallback bool `mapstructure:"default_org_fallback"`

	// DefaultOrgID is the org UUID handed out when DefaultOrgFallback is on.
	// Defaults to the canonical default-org UUID (migration v25).
	DefaultOrgID string `mapstructure:"default_org_id"`

	// DarkModeTier1/Tier2 gate the "dark platform" posture: when a tier is dark,
	// its services bind loopback-only (BindAddr) and their public edge routes are
	// dropped, so they are reachable only over the OpenZiti overlay. Default
	// false = today's public behavior. Tier 0 (login/JWKS/enroll) is ALWAYS
	// public — there is deliberately no flag to dark it (that would brick
	// bootstrap). See docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md.
	DarkModeTier1 bool `mapstructure:"dark_mode_tier1"`
	DarkModeTier2 bool `mapstructure:"dark_mode_tier2"`

	// DevAdminBypass, when true, treats every caller as admin across the
	// access-service admin surface (the inline PAM admin check and the
	// requireAdminRole gate) — a local-development convenience so a single
	// unauthenticated dev caller isn't 403'd / hidden from all entries. It is
	// an EXPLICIT opt-in (env DEV_ADMIN_BYPASS, default false) and is
	// deliberately NOT implied by APP_ENV=development: a box left in dev mode
	// must still keep the admin surface behind identity rather than exposing it
	// (read inventory AND mutations) to anonymous callers.
	DevAdminBypass bool `mapstructure:"dev_admin_bypass"`

	// AccessAPIRequireAuth forces the access-service data API (/api/v1/access/*)
	// onto the hard-blocking auth middleware even when APP_ENV=development. In dev
	// the group otherwise uses SoftAuth, which verifies a bearer when present but
	// does NOT reject anonymous callers — leaving the whole data surface (PAM
	// inventory, sessions, etc.) readable without a token. Set this (env
	// ACCESS_API_REQUIRE_AUTH=true) on any box reachable off-localhost so a
	// dev-mode install still refuses unauthenticated data reads. The Tier-0 public
	// door (POST /api/v1/access/enroll), agent enroll/report, APK download and
	// temp-access links are registered outside this group and stay reachable.
	// Default false preserves today's local-dev ergonomics. Production
	// (APP_ENV!=development) always hard-blocks regardless of this flag.
	AccessAPIRequireAuth bool `mapstructure:"access_api_require_auth"`

	// OpenZiti configuration
	ZitiEnabled            bool   `mapstructure:"ziti_enabled"`
	ZitiReconcilerEnabled  bool   `mapstructure:"ziti_reconciler"`
	ZitiCtrlURL            string `mapstructure:"ziti_ctrl_url"`
	ZitiAdminUser          string `mapstructure:"ziti_admin_user"`
	ZitiAdminPassword      string `mapstructure:"ziti_admin_password"`
	ZitiIdentityDir        string `mapstructure:"ziti_identity_dir"`
	ZitiInsecureSkipVerify bool   `mapstructure:"ziti_insecure_skip_verify"`
	// ZitiHTTPTimeoutSeconds bounds every Ziti controller management API call so a
	// slow/hung controller can't stall an enroll/reconcile. Default 8s (env
	// ZITI_HTTP_TIMEOUT_SECONDS). Calls also run through a circuit breaker.
	ZitiHTTPTimeoutSeconds int `mapstructure:"ziti_http_timeout_seconds"`
	// Browser-facing URL of the controller-hosted ZAC console. When empty the
	// URL is derived from the controller URL (<ctrl>/zac/); set explicitly when
	// the browser reaches the controller on a different host/port than the
	// access-service does (e.g. compose port mappings).
	ZitiConsoleURL string `mapstructure:"ziti_console_url"`

	// Continuous verification
	ContinuousVerifyEnabled  bool `mapstructure:"continuous_verify_enabled"`
	ContinuousVerifyInterval int  `mapstructure:"continuous_verify_interval"`

	// GeoIP service (optional)
	GeoIPServiceURL string `mapstructure:"geoip_service_url"`

	// Apache Guacamole integration (the "direct" PAM session broker — guacd
	// dials targets directly).
	GuacamoleURL           string `mapstructure:"guacamole_url"`
	GuacamoleAdminUser     string `mapstructure:"guacamole_admin_user"`
	GuacamoleAdminPassword string `mapstructure:"guacamole_admin_password"`
	GuacamoleRecordingPath string `mapstructure:"guacamole_recording_path"`
	// GuacamolePublicURL is the browser-facing base for the direct broker (behind a
	// reverse proxy, e.g. https://openidx.tdv.org:8443/guacamole). Used only for the
	// connect URL handed to the client; GuacamoleURL stays the internal REST endpoint.
	// Falls back to GuacamoleURL when unset.
	GuacamolePublicURL string `mapstructure:"guacamole_public_url"`

	// Dedicated OpenZiti PAM session broker — a second Guacamole whose guacd is
	// colocated with a ziti-tunnel, so entries with reach_mode='ziti' reach their
	// target over the overlay (guacd → loopback → ziti-tunnel → edge-router).
	// When unset, ziti-reach entries fall back to the direct broker only if it can
	// see the loopback ports (normally it can't — keep them on separate brokers).
	GuacamoleZitiURL           string `mapstructure:"guacamole_ziti_url"`
	GuacamoleZitiAdminUser     string `mapstructure:"guacamole_ziti_admin_user"`
	GuacamoleZitiAdminPassword string `mapstructure:"guacamole_ziti_admin_password"`
	// GuacamoleZitiPublicURL — browser-facing base for the ziti broker (as above).
	GuacamoleZitiPublicURL string `mapstructure:"guacamole_ziti_public_url"`

	// GuacamoleHTTPTimeoutSeconds bounds every REST call to the Guacamole broker
	// so a slow/hung broker can't stall a user's PAM connect. Default 8s (env
	// GUACAMOLE_HTTP_TIMEOUT_SECONDS). Calls also run through a circuit breaker.
	GuacamoleHTTPTimeoutSeconds int `mapstructure:"guacamole_http_timeout_seconds"`

	// GuacamolePerUserIdentities gates the per-user Guacamole broker identity path
	// (PAM hardening). When true, PAM sessions broker under a standing non-admin
	// per-user Guacamole account granted READ on only the target connection, and
	// the browser token is minted as that account (never the admin token). When
	// false (default) the legacy shared-admin token path is used; even when true
	// it falls back to the shared path on any provisioning error. Env
	// GUACAMOLE_PER_USER_IDENTITIES.
	GuacamolePerUserIdentities bool `mapstructure:"guacamole_per_user_identities"`

	// BrowZer configuration (browser-native Ziti participation)
	BrowZerEnabled          bool   `mapstructure:"browzer_enabled"`
	BrowZerClientID         string `mapstructure:"browzer_client_id"`
	BrowZerTargetsPath      string `mapstructure:"browzer_targets_path"`
	BrowZerRouterConfigPath string `mapstructure:"browzer_router_config_path"`
	BrowZerHopConfigPath    string `mapstructure:"browzer_hop_config_path"`
	BrowZerHopCertPath      string `mapstructure:"browzer_hop_cert_path"`
	BrowZerHopKeyPath       string `mapstructure:"browzer_hop_key_path"`
	BrowZerCertsPath        string `mapstructure:"browzer_certs_path"`
	// Public per-app vhost generation (front nginx). The access-service renders
	// one TLS server block per BrowZer route into BrowZerVHostConfigPath; the
	// front nginx includes it and reloads. Forwards to BrowZerBootstrapperAddr.
	// SSL cert/key are the paths AS SEEN BY the front nginx container.
	// OIDCCallbackPaths are the external-IdP form_post callback suffixes routed to
	// the hop on hop-mode routes (comma-separated).
	BrowZerVHostConfigPath   string `mapstructure:"browzer_vhost_config_path"`
	BrowZerBootstrapperAddr  string `mapstructure:"browzer_bootstrapper_addr"`
	BrowZerVHostSSLCert      string `mapstructure:"browzer_vhost_ssl_cert"`
	BrowZerVHostSSLKey       string `mapstructure:"browzer_vhost_ssl_key"`
	BrowZerOIDCCallbackPaths string `mapstructure:"browzer_oidc_callback_paths"`
	// Host:port the access-proxy dials for the browzer-router-zt Ziti service —
	// where the BrowZer path/vhost router (nginx) runs. Defaults to the Docker
	// service name "browzer-router":80; override for non-compose topologies
	// (e.g. a native deploy running the router on 127.0.0.1:<port>).
	BrowZerRouterHost string `mapstructure:"browzer_router_host"`
	BrowZerRouterPort int    `mapstructure:"browzer_router_port"`
	// Host:port of the shared TLS hop nginx that "hop"-mode Ziti services target
	// via their host.v1 config. The hop SNI-demuxes and proxies to the real
	// upstream. Defaults to 127.0.0.1:8095.
	ZitiBrowZerHopAddr string `mapstructure:"ziti_browzer_hop_addr"`
	APISIXConfigPath   string `mapstructure:"apisix_config_path"`

	// APISIX edge (opt-in). When APISIXEdgeEnabled, the access-service pushes
	// BrowZer routes to APISIX's Admin API instead of generating nginx vhosts.
	APISIXEdgeEnabled      bool   `mapstructure:"apisix_edge_enabled"`
	APISIXAdminURL         string `mapstructure:"apisix_admin_url"`
	APISIXAdminKey         string `mapstructure:"apisix_admin_key"`
	APISIXBootstrapperNode string `mapstructure:"apisix_bootstrapper_node"`

	// RequireDeviceTrustForClientless gates clientless (BrowZer) OIDC logins on
	// device trust: an untrusted device is refused a BrowZer session and a
	// device-trust request is filed. Off by default (opt-in). Per-device, not
	// per-route (BrowZer's data path can't carry per-route device trust).
	RequireDeviceTrustForClientless bool `mapstructure:"require_device_trust_for_clientless"`

	// WebAuthn configuration
	WebAuthn WebAuthnConfig `mapstructure:"webauthn"`

	// Push MFA configuration
	PushMFA PushMFAConfig `mapstructure:"push_mfa"`

	// SMS MFA configuration
	SMS SMSConfig `mapstructure:"sms"`

	// Adaptive MFA / Risk-based authentication
	AdaptiveMFA AdaptiveMFAConfig `mapstructure:"adaptive_mfa"`

	// Audit Stream WebSocket configuration
	AuditStreamAllowedOrigins string `mapstructure:"audit_stream_allowed_origins"`

	// Redis Sentinel configuration
	RedisSentinelEnabled    bool   `mapstructure:"redis_sentinel_enabled"`
	RedisSentinelMasterName string `mapstructure:"redis_sentinel_master_name"`
	RedisSentinelAddresses  string `mapstructure:"redis_sentinel_addresses"`
	RedisSentinelPassword   string `mapstructure:"redis_sentinel_password"`

	// CSRF protection
	CSRFEnabled       bool   `mapstructure:"csrf_enabled"`
	CSRFTrustedDomain string `mapstructure:"csrf_trusted_domain"`

	// DebugOTPInResponse controls whether OTP codes are included in API responses.
	// NEVER enable this in production as it exposes verification codes in logs/browser.
	// Default: false (auto-enabled only in development mode with explicit opt-in)
	DebugOTPInResponse bool `mapstructure:"debug_otp_in_response"`

	// TLS configuration for inter-service communication
	TLS TLSConfig `mapstructure:"tls"`

	// Database TLS configuration
	DatabaseSSLMode     string `mapstructure:"database_ssl_mode"`      // disable, require, verify-ca, verify-full
	DatabaseSSLRootCert string `mapstructure:"database_ssl_root_cert"` // Path to CA certificate
	DatabaseSSLCert     string `mapstructure:"database_ssl_cert"`      // Path to client certificate (mTLS)
	DatabaseSSLKey      string `mapstructure:"database_ssl_key"`       // Path to client private key (mTLS)

	// Redis TLS configuration
	RedisTLSEnabled    bool   `mapstructure:"redis_tls_enabled"`
	RedisTLSCACert     string `mapstructure:"redis_tls_ca_cert"`     // CA cert path
	RedisTLSCert       string `mapstructure:"redis_tls_cert"`        // Client cert path (mTLS)
	RedisTLSKey        string `mapstructure:"redis_tls_key"`         // Client key path (mTLS)
	RedisTLSSkipVerify bool   `mapstructure:"redis_tls_skip_verify"` // For dev only

	// Elasticsearch auth and TLS
	ElasticsearchUsername string `mapstructure:"elasticsearch_username"`
	ElasticsearchPassword string `mapstructure:"elasticsearch_password"`
	ElasticsearchTLS      bool   `mapstructure:"elasticsearch_tls"`
	ElasticsearchCACert   string `mapstructure:"elasticsearch_ca_cert"`
	AutoMigrate           bool   `mapstructure:"auto_migrate"`

	// Play Integrity (Phase 1+ Android agent attestation). When both
	// PlayIntegrityServiceAccountJSON and PlayIntegrityPackageName are set
	// the access service verifies Play Integrity tokens server-side via
	// Google's decodeIntegrityToken API. When unset, agent-reported tokens
	// are persisted unverified — useful for dev, dangerous in prod.
	PlayIntegrityServiceAccountJSON string `mapstructure:"play_integrity_service_account_json"`
	PlayIntegrityPackageName        string `mapstructure:"play_integrity_package_name"`

	// TURN credentials for Phase 4 remote-support. When TurnURIs and
	// TurnStaticSecret are set the access service mints short-lived TURN
	// credentials per session (coturn-style use-auth-secret). Unset leaves
	// admins to supply ICE servers per session via the start-session API.
	TurnURIs                 string `mapstructure:"turn_uris"`                   // comma-separated turn:/turns: URIs
	TurnStaticSecret         string `mapstructure:"turn_static_secret"`          // matches the TURN server's static-auth-secret
	TurnRealm                string `mapstructure:"turn_realm"`                  // optional
	TurnCredentialTTLSeconds int    `mapstructure:"turn_credential_ttl_seconds"` // default 7200

	// Remote-support recording (Phase 4 follow-up). When unset, recording
	// is disabled even if admins request it on start-session. Storage
	// preference:
	//   1. S3 (or S3-compatible: MinIO, R2, Wasabi, B2) when
	//      RecordingsS3Endpoint and RecordingsS3Bucket are set.
	//   2. Filesystem when RecordingsStoragePath is set.
	//   3. Disabled otherwise.
	RecordingsStoragePath string `mapstructure:"recordings_storage_path"`

	RecordingsS3Endpoint  string `mapstructure:"recordings_s3_endpoint"` // e.g., "s3.amazonaws.com", "play.min.io", custom host:port
	RecordingsS3Bucket    string `mapstructure:"recordings_s3_bucket"`
	RecordingsS3Region    string `mapstructure:"recordings_s3_region"`
	RecordingsS3Prefix    string `mapstructure:"recordings_s3_prefix"` // optional key prefix inside the bucket
	RecordingsS3AccessKey string `mapstructure:"recordings_s3_access_key"`
	RecordingsS3SecretKey string `mapstructure:"recordings_s3_secret_key"`
	RecordingsS3UseSSL    bool   `mapstructure:"recordings_s3_use_ssl"` // default true; set false for local MinIO dev

	// Recording retention default. Resolves at the bottom of the lookup
	// chain — session override → per-org policy → this value → hard 90d.
	RecordingsDefaultRetentionDays int `mapstructure:"recordings_default_retention_days"`

	// Optional master key for filesystem-backend encryption at rest. When
	// set, chunks are AES-GCM encrypted with HKDF-derived per-session keys
	// before they hit disk. Base64-encoded 32 raw bytes (any other length
	// is rejected at startup). Unset means the filesystem backend writes
	// plaintext — fine for dev, the S3 backend should rely on bucket-level
	// SSE-S3 / SSE-KMS instead.
	//
	// Single-key form. When RecordingsEncryptionKeys (plural) is unset,
	// this key is loaded as key-id 0 and used for both reads and writes.
	RecordingsEncryptionKey string `mapstructure:"recordings_encryption_key"`

	// Multi-key form for key rotation. Comma-separated "id:base64key"
	// entries, where id is 0-255. New recordings encrypt under
	// RecordingsEncryptionActiveKeyID; recordings written under any other
	// listed id still decrypt. Retire an old key by removing its entry
	// once every recording it protected has been purged.
	//   e.g. "1:<base64-32B>,2:<base64-32B>" with active_key_id=2
	RecordingsEncryptionKeys        string `mapstructure:"recordings_encryption_keys"`
	RecordingsEncryptionActiveKeyID int    `mapstructure:"recordings_encryption_active_key_id"`

	// Vault (PAM credential vault) key-encryption keys. Same shape as the
	// recordings keyring. When all three are empty the vault falls back to
	// EncryptionKey as KEK id 0 (raw 32-byte string, not base64). If that is
	// also unusable the vault service fails closed and does not register.
	VaultKEK                   string `mapstructure:"vault_kek"`
	VaultKEKs                  string `mapstructure:"vault_keks"`
	VaultActiveKEKID           int    `mapstructure:"vault_active_kek_id"`
	VaultRevealLeaseTTLSeconds int    `mapstructure:"vault_reveal_lease_ttl_seconds"`

	// Credentials rotation scheduler configuration
	CredentialsRotationSchedulerIntervalSeconds int `mapstructure:"credentials_rotation_scheduler_interval_seconds"`
	CredentialsRotationDefaultLength            int `mapstructure:"credentials_rotation_default_length"`
}

// TLSConfig holds TLS configuration for service-to-service encryption
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`   // Enable TLS for the HTTP server
	CertFile string `mapstructure:"cert_file"` // Path to TLS certificate file
	KeyFile  string `mapstructure:"key_file"`  // Path to TLS private key file
	CAFile   string `mapstructure:"ca_file"`   // Path to CA certificate for client verification (optional)
}

// WebAuthnConfig holds WebAuthn/FIDO2 configuration
type WebAuthnConfig struct {
	RPID      string   `mapstructure:"rp_id"`      // Relying Party ID (e.g., "example.com")
	RPOrigins []string `mapstructure:"rp_origins"` // Allowed origins
	Timeout   int      `mapstructure:"timeout"`    // Timeout in seconds (default: 60)
}

// PushMFAConfig holds Push MFA configuration
type PushMFAConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// FCMServerKey is the legacy FCM server key. DEPRECATED: Google decommissioned
	// the legacy HTTP and XMPP APIs in 2024; it is unused. Configure the HTTP v1
	// credentials below instead.
	FCMServerKey string `mapstructure:"fcm_server_key"`
	// FCMCredentialsFile is the path to a Firebase service-account JSON used for
	// FCM HTTP v1 (OAuth2 bearer token). Required for Android/web push.
	FCMCredentialsFile string `mapstructure:"fcm_credentials_file"`
	// FCMProjectID is the Firebase project ID for the v1 endpoint. Defaults to the
	// project_id found in the credentials file when left empty.
	FCMProjectID     string `mapstructure:"fcm_project_id"`
	APNSKeyID        string `mapstructure:"apns_key_id"`       // Apple Push Notification Service key ID
	APNSTeamID       string `mapstructure:"apns_team_id"`      // Apple team ID
	APNSKeyPath      string `mapstructure:"apns_key_path"`     // Path to APNS .p8 key file (token auth)
	APNSBundleID     string `mapstructure:"apns_bundle_id"`    // APNS bundle identifier (e.g., "com.openidx.app")
	APNSProduction   bool   `mapstructure:"apns_production"`   // Use the production APNS host (default: sandbox)
	ChallengeTimeout int    `mapstructure:"challenge_timeout"` // Timeout in seconds (default: 60)
	AutoApprove      bool   `mapstructure:"auto_approve"`      // Auto-approve for development (NEVER use in production)
}

// SMSConfig holds SMS MFA configuration
type SMSConfig struct {
	Enabled       bool   `mapstructure:"enabled"`         // Enable SMS MFA
	Provider      string `mapstructure:"provider"`        // twilio, aws_sns, netgsm, ileti_merkezi, verimor, turkcell, vodafone, turk_telekom, mutlucell, webhook, mock
	TwilioSID     string `mapstructure:"twilio_sid"`      // Twilio Account SID
	TwilioToken   string `mapstructure:"twilio_token"`    // Twilio Auth Token
	TwilioFrom    string `mapstructure:"twilio_from"`     // Twilio From Number
	AWSRegion     string `mapstructure:"aws_region"`      // AWS Region for SNS
	AWSAccessKey  string `mapstructure:"aws_access_key"`  // AWS Access Key (optional, uses IAM role if empty)
	AWSSecretKey  string `mapstructure:"aws_secret_key"`  // AWS Secret Key (optional, uses IAM role if empty)
	WebhookURL    string `mapstructure:"webhook_url"`     // Custom webhook URL for SMS delivery
	WebhookAPIKey string `mapstructure:"webhook_api_key"` // API key for webhook authentication
	MessagePrefix string `mapstructure:"message_prefix"`  // Prefix for OTP messages (default: "OpenIDX")
	OTPLength     int    `mapstructure:"otp_length"`      // Length of OTP code (default: 6)
	OTPExpiry     int    `mapstructure:"otp_expiry"`      // OTP expiry in seconds (default: 300)
	MaxAttempts   int    `mapstructure:"max_attempts"`    // Max verification attempts (default: 3)

	// Turkish SMS gateway providers
	NetGSMUserCode     string `mapstructure:"netgsm_usercode"`     // NetGSM user code
	NetGSMPassword     string `mapstructure:"netgsm_password"`     // NetGSM password
	NetGSMHeader       string `mapstructure:"netgsm_header"`       // NetGSM sender header (message originator)
	IletiMerkeziKey    string `mapstructure:"iletimerkezi_key"`    // İleti Merkezi API key
	IletiMerkeziSecret string `mapstructure:"iletimerkezi_secret"` // İleti Merkezi API secret
	IletiMerkeziSender string `mapstructure:"iletimerkezi_sender"` // İleti Merkezi sender name
	VerimorUsername    string `mapstructure:"verimor_username"`    // Verimor username (908501234567 format)
	VerimorPassword    string `mapstructure:"verimor_password"`    // Verimor API password
	VerimorSourceAddr  string `mapstructure:"verimor_source_addr"` // Verimor sender ID
	TurkcellUsername   string `mapstructure:"turkcell_username"`   // Turkcell Mesajüssü username
	TurkcellPassword   string `mapstructure:"turkcell_password"`   // Turkcell Mesajüssü password
	TurkcellSender     string `mapstructure:"turkcell_sender"`     // Turkcell sender name
	VodafoneAPIKey     string `mapstructure:"vodafone_api_key"`    // Vodafone API key (OAuth2 client_id)
	VodafoneSecret     string `mapstructure:"vodafone_secret"`     // Vodafone API secret (OAuth2 client_secret)
	VodafoneSender     string `mapstructure:"vodafone_sender"`     // Vodafone sender address
	TurkTelekomAPIKey  string `mapstructure:"turktelekom_api_key"` // Türk Telekom API key
	TurkTelekomSecret  string `mapstructure:"turktelekom_secret"`  // Türk Telekom API secret
	TurkTelekomSender  string `mapstructure:"turktelekom_sender"`  // Türk Telekom sender name
	MutlucellUsername  string `mapstructure:"mutlucell_username"`  // Mutlucell username
	MutlucellPassword  string `mapstructure:"mutlucell_password"`  // Mutlucell password
	MutlucellAPIKey    string `mapstructure:"mutlucell_api_key"`   // Mutlucell API key
	MutlucellSender    string `mapstructure:"mutlucell_sender"`    // Mutlucell sender name
}

// AdaptiveMFAConfig holds adaptive/risk-based MFA configuration
type AdaptiveMFAConfig struct {
	Enabled                   bool `mapstructure:"enabled"`                      // Enable adaptive MFA
	NewDeviceRiskScore        int  `mapstructure:"new_device_risk_score"`        // Risk score for new device (default: 30)
	NewLocationRiskScore      int  `mapstructure:"new_location_risk_score"`      // Risk score for new location (default: 20)
	ImpossibleTravelRiskScore int  `mapstructure:"impossible_travel_risk_score"` // Risk score for impossible travel (default: 50)
	BlockedIPRiskScore        int  `mapstructure:"blocked_ip_risk_score"`        // Risk score for blocked IP (default: 40)
	FailedLoginRiskScore      int  `mapstructure:"failed_login_risk_score"`      // Risk score per recent failed login (default: 10)
	TrustedBrowserDays        int  `mapstructure:"trusted_browser_days"`         // Days to trust a browser (default: 30)
	LowRiskThreshold          int  `mapstructure:"low_risk_threshold"`           // Below this: skip MFA (default: 30)
	MediumRiskThreshold       int  `mapstructure:"medium_risk_threshold"`        // Below this: standard MFA (default: 50)
	HighRiskThreshold         int  `mapstructure:"high_risk_threshold"`          // Below this: strong MFA (default: 70)
	// Above high_risk_threshold: step-up auth + admin notification
}

// Load reads configuration from file and environment variables
func Load(serviceName string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v, serviceName)

	// Read from config file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("/etc/openidx")

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Read from environment variables
	v.SetEnvPrefix("OPENIDX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Also support non-prefixed env vars for common settings
	bindEnvVars(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	cfg.ServiceName = serviceName

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper, serviceName string) {
	// Service defaults
	v.SetDefault("environment", "development")
	v.SetDefault("log_level", "info")
	v.SetDefault("shutdown_timeout_seconds", 30)

	// Port defaults per service
	ports := map[string]int{
		"identity-service":     8001,
		"governance-service":   8002,
		"provisioning-service": 8003,
		"audit-service":        8004,
		"admin-api":            8005,
		"oauth-service":        8006,
		"access-service":       8007,
		"gateway-service":      8008,
	}
	if port, ok := ports[serviceName]; ok {
		v.SetDefault("port", port)
	} else {
		v.SetDefault("port", 8080)
	}

	// Bind address + dark-mode flags. Defaults preserve today's public behavior:
	// empty bind_addr = all interfaces; dark tiers off.
	v.SetDefault("bind_addr", "")
	v.SetDefault("dark_mode_tier1", false)
	v.SetDefault("dark_mode_tier2", false)
	v.SetDefault("dev_admin_bypass", false)
	v.SetDefault("access_api_require_auth", false)

	// Database defaults
	v.SetDefault("database_url", "postgres://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable")
	v.SetDefault("redis_url", "redis://:redis_secret@localhost:6379")
	v.SetDefault("elasticsearch_url", "http://localhost:9200")

	// OPA defaults
	v.SetDefault("opa_url", "http://localhost:8281")
	v.SetDefault("enable_opa_authz", false)

	// Feature flag defaults
	v.SetDefault("enable_mfa", true)
	v.SetDefault("enable_audit_logging", true)
	v.SetDefault("enable_rate_limit", true)

	// Rate limiting defaults
	v.SetDefault("rate_limit_requests", 100)
	v.SetDefault("rate_limit_window", 60)
	v.SetDefault("rate_limit_auth_requests", 20)
	v.SetDefault("rate_limit_auth_window", 60)
	v.SetDefault("rate_limit_per_user", false)

	// OAuth / OIDC defaults
	v.SetDefault("oauth_issuer", "http://localhost:8006")
	v.SetDefault("oauth_jwks_url", "http://localhost:8006/.well-known/jwks.json")

	// Access Proxy defaults
	v.SetDefault("governance_url", "http://localhost:8002")
	v.SetDefault("audit_url", "http://localhost:8004")
	v.SetDefault("access_session_secret", "change-me-in-production-32bytes!")
	v.SetDefault("access_proxy_domain", "localhost")

	// Multi-tenancy: empty disables subdomain-based tenant resolution.
	v.SetDefault("tenant_base_domain", "")
	v.SetDefault("dcr_initial_access_token", "")
	v.SetDefault("ssf_receiver_issuer", "")
	v.SetDefault("ssf_receiver_jwks_url", "")
	v.SetDefault("ziti_per_org_attributes", false)
	// v1.7.0: tenant isolation is enforced by default — no silent default-org
	// fallback. Single-tenant installs opt back in with DEFAULT_ORG_FALLBACK=true.
	v.SetDefault("default_org_fallback", false)
	v.SetDefault("default_org_id", "00000000-0000-0000-0000-000000000010")

	// OpenZiti defaults
	v.SetDefault("ziti_enabled", false)
	// Desired-state reconciler is the default control path (DB as source of
	// truth, self-healing); set ZITI_RECONCILER=false to fall back to the
	// legacy imperative hosting path.
	v.SetDefault("ziti_reconciler", true)
	v.SetDefault("ziti_ctrl_url", "https://ziti-controller:1280")
	v.SetDefault("ziti_admin_user", "admin")
	v.SetDefault("ziti_admin_password", defaultZitiAdminPassword)
	v.SetDefault("ziti_identity_dir", "/ziti")
	v.SetDefault("ziti_insecure_skip_verify", false)
	v.SetDefault("ziti_console_url", "")

	// Continuous verification defaults
	v.SetDefault("continuous_verify_enabled", false)
	v.SetDefault("continuous_verify_interval", 30)

	// Guacamole defaults
	v.SetDefault("guacamole_url", "")
	v.SetDefault("guacamole_admin_user", "guacadmin")
	v.SetDefault("guacamole_admin_password", defaultGuacamoleAdminPassword)
	v.SetDefault("guacamole_recording_path", "/var/lib/openidx/recordings/guacamole")
	v.SetDefault("guacamole_public_url", "")
	v.SetDefault("guacamole_ziti_url", "")
	v.SetDefault("guacamole_ziti_admin_user", "guacadmin")
	v.SetDefault("guacamole_ziti_admin_password", defaultGuacamoleAdminPassword)
	v.SetDefault("guacamole_ziti_public_url", "")
	v.SetDefault("guacamole_per_user_identities", false)
	v.SetDefault("guacamole_http_timeout_seconds", 8)
	v.SetDefault("ziti_http_timeout_seconds", 8)

	// BrowZer defaults
	v.SetDefault("browzer_enabled", false)
	v.SetDefault("browzer_client_id", "browzer-client")
	v.SetDefault("browzer_router_host", "browzer-router")
	v.SetDefault("browzer_router_port", 80)
	v.SetDefault("ziti_browzer_hop_addr", "127.0.0.1:8095")
	v.SetDefault("browzer_bootstrapper_addr", "https://127.0.0.1:8445")
	v.SetDefault("browzer_vhost_ssl_cert", "/etc/nginx/tdv-fullchain.pem")
	v.SetDefault("browzer_vhost_ssl_key", "/etc/nginx/tdv-key.pem")
	// Empty by default: when BrowZer's WSS overlay works, its service worker
	// tunnels the app's external-IdP form_post callback over the overlay, so the
	// app's session cookie stays in the overlay's context. A direct edge bypass
	// for the callback (set this to e.g. "signin-oidc,signout-callback-oidc") then
	// becomes HARMFUL — the cookie set on the direct path isn't seen on overlay
	// requests, causing a login loop. Only set it as a fallback when the SW can't
	// intercept the form_post (e.g. WSS unavailable).
	v.SetDefault("browzer_oidc_callback_paths", "")

	// APISIX edge defaults
	v.SetDefault("apisix_edge_enabled", false)
	v.SetDefault("require_device_trust_for_clientless", false)
	v.SetDefault("apisix_admin_url", "http://127.0.0.1:9180")
	v.SetDefault("apisix_bootstrapper_node", "127.0.0.1:8445")

	// CORS defaults
	v.SetDefault("cors_allowed_origins", "*")

	// WebAuthn defaults
	v.SetDefault("webauthn.rp_id", "localhost")
	v.SetDefault("webauthn.rp_origins", []string{"http://localhost:3000", "http://localhost:8080"})
	v.SetDefault("webauthn.timeout", 60)

	// Push MFA defaults
	v.SetDefault("push_mfa.enabled", true)
	v.SetDefault("push_mfa.challenge_timeout", 60)
	v.SetDefault("push_mfa.auto_approve", false)
	v.SetDefault("push_mfa.apns_production", false)

	// SMS MFA defaults
	v.SetDefault("sms.enabled", false)
	v.SetDefault("sms.provider", "mock")
	v.SetDefault("sms.message_prefix", "OpenIDX")
	v.SetDefault("sms.otp_length", 6)
	v.SetDefault("sms.otp_expiry", 300)
	v.SetDefault("sms.max_attempts", 3)

	// Redis Sentinel defaults
	v.SetDefault("redis_sentinel_enabled", false)
	v.SetDefault("redis_sentinel_master_name", "mymaster")
	v.SetDefault("redis_sentinel_addresses", "")
	v.SetDefault("redis_sentinel_password", "")

	// Database TLS defaults
	v.SetDefault("database_ssl_mode", "disable")
	v.SetDefault("database_ssl_root_cert", "")
	v.SetDefault("database_ssl_cert", "")
	v.SetDefault("database_ssl_key", "")

	// Redis TLS defaults
	v.SetDefault("redis_tls_enabled", false)
	v.SetDefault("redis_tls_ca_cert", "")
	v.SetDefault("redis_tls_cert", "")
	v.SetDefault("redis_tls_key", "")
	v.SetDefault("redis_tls_skip_verify", false)

	// Elasticsearch auth/TLS defaults
	v.SetDefault("elasticsearch_username", "")
	v.SetDefault("elasticsearch_password", "")
	v.SetDefault("elasticsearch_tls", false)
	v.SetDefault("elasticsearch_ca_cert", "")

	// CSRF defaults: enabled by default. Operators who don't want CSRF
	// protection on a single-page test box still have an explicit opt-out
	// (CSRF_ENABLED=false), but the secure-by-default posture means no
	// production deployment can forget to flip the bit.
	v.SetDefault("csrf_enabled", true)
	v.SetDefault("csrf_trusted_domain", "")

	// Debug OTP defaults (NEVER enable in production)
	v.SetDefault("debug_otp_in_response", false)

	// TLS defaults (disabled by default for backward compatibility)
	v.SetDefault("tls.enabled", false)
	v.SetDefault("tls.cert_file", "")
	v.SetDefault("tls.key_file", "")
	v.SetDefault("tls.ca_file", "")

	// Adaptive MFA defaults
	v.SetDefault("adaptive_mfa.enabled", true)
	v.SetDefault("adaptive_mfa.new_device_risk_score", 30)
	v.SetDefault("adaptive_mfa.new_location_risk_score", 20)
	v.SetDefault("adaptive_mfa.impossible_travel_risk_score", 50)
	v.SetDefault("adaptive_mfa.blocked_ip_risk_score", 40)
	v.SetDefault("adaptive_mfa.failed_login_risk_score", 10)
	v.SetDefault("adaptive_mfa.trusted_browser_days", 30)
	v.SetDefault("adaptive_mfa.low_risk_threshold", 30)
	v.SetDefault("adaptive_mfa.medium_risk_threshold", 50)
	v.SetDefault("adaptive_mfa.high_risk_threshold", 70)

	// Audit Stream WebSocket defaults (development-friendly)
	v.SetDefault("audit_stream_allowed_origins", "")

	// Vault (PAM credential vault) defaults
	v.SetDefault("vault_reveal_lease_ttl_seconds", 300)

	// Credentials rotation defaults
	v.SetDefault("credentials_rotation_scheduler_interval_seconds", 60)
	v.SetDefault("credentials_rotation_default_length", 24)
}

func bindEnvVars(v *viper.Viper) {
	// Common environment variable mappings
	envMappings := map[string]string{
		"database_url":                                    "DATABASE_URL",
		"redis_url":                                       "REDIS_URL",
		"elasticsearch_url":                               "ELASTICSEARCH_URL",
		"opa_url":                                         "OPA_URL",
		"environment":                                     "APP_ENV",
		"log_level":                                       "LOG_LEVEL",
		"port":                                            "PORT",
		"bind_addr":                                       "SERVICE_BIND_ADDR",
		"dark_mode_tier1":                                 "DARK_MODE_TIER1",
		"dark_mode_tier2":                                 "DARK_MODE_TIER2",
		"dev_admin_bypass":                                "DEV_ADMIN_BYPASS",
		"access_api_require_auth":                         "ACCESS_API_REQUIRE_AUTH",
		"shutdown_timeout_seconds":                        "SHUTDOWN_TIMEOUT_SECONDS",
		"oauth_issuer":                                    "OAUTH_ISSUER",
		"tenant_base_domain":                              "TENANT_BASE_DOMAIN",
		"dcr_initial_access_token":                        "DCR_INITIAL_ACCESS_TOKEN",
		"ssf_receiver_issuer":                             "SSF_RECEIVER_ISSUER",
		"ssf_receiver_jwks_url":                           "SSF_RECEIVER_JWKS_URL",
		"ziti_per_org_attributes":                         "ZITI_PER_ORG_ATTRIBUTES",
		"default_org_fallback":                            "DEFAULT_ORG_FALLBACK",
		"default_org_id":                                  "DEFAULT_ORG_ID",
		"oauth_jwks_url":                                  "OAUTH_JWKS_URL",
		"governance_url":                                  "GOVERNANCE_URL",
		"audit_url":                                       "AUDIT_URL",
		"internal_service_token":                          "INTERNAL_SERVICE_TOKEN",
		"access_session_secret":                           "ACCESS_SESSION_SECRET",
		"access_proxy_domain":                             "ACCESS_PROXY_DOMAIN",
		"access_apps_domain":                              "ACCESS_APPS_DOMAIN",
		"ziti_enabled":                                    "ZITI_ENABLED",
		"ziti_reconciler":                                 "ZITI_RECONCILER",
		"ziti_ctrl_url":                                   "ZITI_CTRL_URL",
		"ziti_admin_user":                                 "ZITI_ADMIN_USER",
		"ziti_admin_password":                             "ZITI_ADMIN_PASSWORD",
		"ziti_identity_dir":                               "ZITI_IDENTITY_DIR",
		"ziti_insecure_skip_verify":                       "ZITI_INSECURE_SKIP_VERIFY",
		"ziti_console_url":                                "ZITI_CONSOLE_URL",
		"continuous_verify_enabled":                       "CONTINUOUS_VERIFY_ENABLED",
		"continuous_verify_interval":                      "CONTINUOUS_VERIFY_INTERVAL",
		"geoip_service_url":                               "GEOIP_SERVICE_URL",
		"guacamole_url":                                   "GUACAMOLE_URL",
		"guacamole_admin_user":                            "GUACAMOLE_ADMIN_USER",
		"guacamole_admin_password":                        "GUACAMOLE_ADMIN_PASSWORD",
		"guacamole_recording_path":                        "GUACAMOLE_RECORDING_PATH",
		"guacamole_public_url":                            "GUACAMOLE_PUBLIC_URL",
		"guacamole_ziti_url":                              "GUACAMOLE_ZITI_URL",
		"guacamole_ziti_admin_user":                       "GUACAMOLE_ZITI_ADMIN_USER",
		"guacamole_ziti_admin_password":                   "GUACAMOLE_ZITI_ADMIN_PASSWORD",
		"guacamole_ziti_public_url":                       "GUACAMOLE_ZITI_PUBLIC_URL",
		"guacamole_per_user_identities":                   "GUACAMOLE_PER_USER_IDENTITIES",
		"guacamole_http_timeout_seconds":                  "GUACAMOLE_HTTP_TIMEOUT_SECONDS",
		"ziti_http_timeout_seconds":                       "ZITI_HTTP_TIMEOUT_SECONDS",
		"browzer_enabled":                                 "BROWZER_ENABLED",
		"browzer_client_id":                               "BROWZER_CLIENT_ID",
		"browzer_targets_path":                            "BROWZER_TARGETS_PATH",
		"browzer_router_config_path":                      "BROWZER_ROUTER_CONFIG_PATH",
		"browzer_hop_config_path":                         "BROWZER_HOP_CONFIG_PATH",
		"browzer_hop_cert_path":                           "BROWZER_HOP_CERT_PATH",
		"browzer_hop_key_path":                            "BROWZER_HOP_KEY_PATH",
		"browzer_certs_path":                              "BROWZER_CERTS_PATH",
		"browzer_router_host":                             "BROWZER_ROUTER_HOST",
		"browzer_router_port":                             "BROWZER_ROUTER_PORT",
		"ziti_browzer_hop_addr":                           "BROWZER_HOP_ADDR",
		"browzer_vhost_config_path":                       "BROWZER_VHOST_CONFIG_PATH",
		"browzer_bootstrapper_addr":                       "BROWZER_BOOTSTRAPPER_ADDR",
		"browzer_vhost_ssl_cert":                          "BROWZER_VHOST_SSL_CERT",
		"browzer_vhost_ssl_key":                           "BROWZER_VHOST_SSL_KEY",
		"browzer_oidc_callback_paths":                     "BROWZER_OIDC_CALLBACK_PATHS",
		"apisix_config_path":                              "APISIX_CONFIG_PATH",
		"apisix_edge_enabled":                             "APISIX_EDGE_ENABLED",
		"require_device_trust_for_clientless":             "OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS",
		"apisix_admin_url":                                "APISIX_ADMIN_URL",
		"apisix_admin_key":                                "APISIX_ADMIN_KEY",
		"apisix_bootstrapper_node":                        "APISIX_BOOTSTRAPPER_NODE",
		"enable_opa_authz":                                "ENABLE_OPA_AUTHZ",
		"jwt_secret":                                      "JWT_SECRET",
		"encryption_key":                                  "ENCRYPTION_KEY",
		"vault_kek":                                       "VAULT_KEK",
		"vault_keks":                                      "VAULT_KEKS",
		"vault_active_kek_id":                             "VAULT_ACTIVE_KEK_ID",
		"vault_reveal_lease_ttl_seconds":                  "VAULT_REVEAL_LEASE_TTL_SECONDS",
		"credentials_rotation_scheduler_interval_seconds": "CREDENTIALS_ROTATION_SCHEDULER_INTERVAL_SECONDS",
		"credentials_rotation_default_length":             "CREDENTIALS_ROTATION_DEFAULT_LENGTH",
		"smtp_host":                                       "SMTP_HOST",
		"smtp_port":                                       "SMTP_PORT",
		"smtp_username":                                   "SMTP_USERNAME",
		"smtp_password":                                   "SMTP_PASSWORD",
		"smtp_from":                                       "SMTP_FROM",
		"sms.enabled":                                     "SMS_ENABLED",
		"sms.provider":                                    "SMS_PROVIDER",
		"sms.twilio_sid":                                  "TWILIO_ACCOUNT_SID",
		"sms.twilio_token":                                "TWILIO_AUTH_TOKEN",
		"sms.twilio_from":                                 "TWILIO_FROM_NUMBER",
		"sms.aws_region":                                  "AWS_REGION",
		"sms.aws_access_key":                              "AWS_ACCESS_KEY_ID",
		"sms.aws_secret_key":                              "AWS_SECRET_ACCESS_KEY",
		"sms.webhook_url":                                 "SMS_WEBHOOK_URL",
		"sms.webhook_api_key":                             "SMS_WEBHOOK_API_KEY",
		"push_mfa.fcm_credentials_file":                   "PUSH_MFA_FCM_CREDENTIALS_FILE",
		"push_mfa.fcm_project_id":                         "PUSH_MFA_FCM_PROJECT_ID",
		"push_mfa.apns_key_id":                            "PUSH_MFA_APNS_KEY_ID",
		"push_mfa.apns_team_id":                           "PUSH_MFA_APNS_TEAM_ID",
		"push_mfa.apns_key_path":                          "PUSH_MFA_APNS_KEY_PATH",
		"push_mfa.apns_bundle_id":                         "PUSH_MFA_APNS_BUNDLE_ID",
		"push_mfa.apns_production":                        "PUSH_MFA_APNS_PRODUCTION",
		// Turkish SMS providers
		"sms.netgsm_usercode":               "NETGSM_USERCODE",
		"sms.netgsm_password":               "NETGSM_PASSWORD",
		"sms.netgsm_header":                 "NETGSM_HEADER",
		"sms.iletimerkezi_key":              "ILETIMERKEZI_API_KEY",
		"sms.iletimerkezi_secret":           "ILETIMERKEZI_API_SECRET",
		"sms.iletimerkezi_sender":           "ILETIMERKEZI_SENDER",
		"sms.verimor_username":              "VERIMOR_USERNAME",
		"sms.verimor_password":              "VERIMOR_PASSWORD",
		"sms.verimor_source_addr":           "VERIMOR_SOURCE_ADDR",
		"sms.turkcell_username":             "TURKCELL_SMS_USERNAME",
		"sms.turkcell_password":             "TURKCELL_SMS_PASSWORD",
		"sms.turkcell_sender":               "TURKCELL_SMS_SENDER",
		"sms.vodafone_api_key":              "VODAFONE_SMS_API_KEY",
		"sms.vodafone_secret":               "VODAFONE_SMS_SECRET",
		"sms.vodafone_sender":               "VODAFONE_SMS_SENDER",
		"sms.turktelekom_api_key":           "TURKTELEKOM_SMS_API_KEY",
		"sms.turktelekom_secret":            "TURKTELEKOM_SMS_SECRET",
		"sms.turktelekom_sender":            "TURKTELEKOM_SMS_SENDER",
		"sms.mutlucell_username":            "MUTLUCELL_USERNAME",
		"sms.mutlucell_password":            "MUTLUCELL_PASSWORD",
		"sms.mutlucell_api_key":             "MUTLUCELL_API_KEY",
		"sms.mutlucell_sender":              "MUTLUCELL_SENDER",
		"database_ssl_mode":                 "DATABASE_SSL_MODE",
		"database_ssl_root_cert":            "DATABASE_SSL_ROOT_CERT",
		"database_ssl_cert":                 "DATABASE_SSL_CERT",
		"database_ssl_key":                  "DATABASE_SSL_KEY",
		"redis_tls_enabled":                 "REDIS_TLS_ENABLED",
		"redis_tls_ca_cert":                 "REDIS_TLS_CA_CERT",
		"redis_tls_cert":                    "REDIS_TLS_CERT",
		"redis_tls_key":                     "REDIS_TLS_KEY",
		"redis_tls_skip_verify":             "REDIS_TLS_SKIP_VERIFY",
		"elasticsearch_username":            "ELASTICSEARCH_USERNAME",
		"elasticsearch_password":            "ELASTICSEARCH_PASSWORD",
		"elasticsearch_tls":                 "ELASTICSEARCH_TLS",
		"elasticsearch_ca_cert":             "ELASTICSEARCH_CA_CERT",
		"redis_sentinel_enabled":            "REDIS_SENTINEL_ENABLED",
		"redis_sentinel_master_name":        "REDIS_SENTINEL_MASTER_NAME",
		"redis_sentinel_addresses":          "REDIS_SENTINEL_ADDRESSES",
		"redis_sentinel_password":           "REDIS_SENTINEL_PASSWORD",
		"csrf_enabled":                      "CSRF_ENABLED",
		"csrf_trusted_domain":               "CSRF_TRUSTED_DOMAIN",
		"debug_otp_in_response":             "DEBUG_OTP_IN_RESPONSE",
		"tls.enabled":                       "TLS_ENABLED",
		"tls.cert_file":                     "TLS_CERT_FILE",
		"tls.key_file":                      "TLS_KEY_FILE",
		"tls.ca_file":                       "TLS_CA_FILE",
		"adaptive_mfa.enabled":              "ADAPTIVE_MFA_ENABLED",
		"enable_rate_limit":                 "ENABLE_RATE_LIMIT",
		"rate_limit_requests":               "RATE_LIMIT_REQUESTS",
		"rate_limit_window":                 "RATE_LIMIT_WINDOW",
		"rate_limit_auth_requests":          "RATE_LIMIT_AUTH_REQUESTS",
		"rate_limit_auth_window":            "RATE_LIMIT_AUTH_WINDOW",
		"rate_limit_per_user":               "RATE_LIMIT_PER_USER",
		"audit_stream_allowed_origins":      "AUDIT_STREAM_ALLOWED_ORIGINS",
		"recordings_storage_path":           "RECORDINGS_STORAGE_PATH",
		"recordings_default_retention_days": "RECORDINGS_DEFAULT_RETENTION_DAYS",
		"recordings_encryption_key":         "RECORDINGS_ENCRYPTION_KEY",
		"recordings_s3_endpoint":            "RECORDINGS_S3_ENDPOINT",
		"recordings_s3_bucket":              "RECORDINGS_S3_BUCKET",
		"recordings_s3_region":              "RECORDINGS_S3_REGION",
		"recordings_s3_prefix":              "RECORDINGS_S3_PREFIX",
		"recordings_s3_access_key":          "RECORDINGS_S3_ACCESS_KEY",
		"recordings_s3_secret_key":          "RECORDINGS_S3_SECRET_KEY",
		"recordings_s3_use_ssl":             "RECORDINGS_S3_USE_SSL",
	}

	for key, env := range envMappings {
		v.BindEnv(key, env)
	}
}

func validate(cfg *Config) error {
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("database_url is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

// ListenAddr is the address the HTTP server binds. An empty BindAddr yields
// ":<port>" (all interfaces — today's behavior); BindAddr "127.0.0.1" yields
// "127.0.0.1:<port>" (loopback-only, i.e. "dark": reachable only over the
// OpenZiti overlay). See the dark-platform spec.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.BindAddr, c.Port)
}

// DarkModeEnabled reports whether any dark-platform tier is active. When true the
// service is meant to be reachable ONLY over the OpenZiti overlay, so it must
// bind loopback rather than a public interface.
func (c *Config) DarkModeEnabled() bool {
	return c.DarkModeTier1 || c.DarkModeTier2
}

// isLoopbackBindAddr reports whether a BindAddr keeps the listener on the local
// host only. Empty ("all interfaces") and 0.0.0.0/:: are explicitly NOT loopback.
func isLoopbackBindAddr(addr string) bool {
	switch strings.TrimSpace(addr) {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

// ValidateDarkModeBind fails closed when a dark tier is enabled but the service
// would still bind a public interface. A dark service that is actually reachable
// from the internet is a silent security hole (the whole point is overlay-only
// reach), so we refuse to start rather than advertise a false posture. Returns
// nil when no dark tier is set (today's default) or when BindAddr is loopback.
func (c *Config) ValidateDarkModeBind() error {
	if !c.DarkModeEnabled() {
		return nil
	}
	if !isLoopbackBindAddr(c.BindAddr) {
		return fmt.Errorf("dark mode enabled (tier1=%v tier2=%v) but SERVICE_BIND_ADDR=%q is not loopback; "+
			"set SERVICE_BIND_ADDR=127.0.0.1 so the service is reachable only over the OpenZiti overlay",
			c.DarkModeTier1, c.DarkModeTier2, c.BindAddr)
	}
	return nil
}

// GetRedisSentinelAddresses returns the sentinel addresses as a slice
func (c *Config) GetRedisSentinelAddresses() []string {
	if c.RedisSentinelAddresses == "" {
		return nil
	}
	addrs := strings.Split(c.RedisSentinelAddresses, ",")
	result := make([]string, 0, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a != "" {
			result = append(result, a)
		}
	}
	return result
}

// GetRedisPassword extracts the password from the Redis URL for Sentinel mode
func (c *Config) GetRedisPassword() string {
	// Redis URL format: redis://:password@host:port
	url := c.RedisURL
	if idx := strings.Index(url, "://"); idx >= 0 {
		url = url[idx+3:]
	}
	if idx := strings.Index(url, "@"); idx >= 0 {
		userInfo := url[:idx]
		if idx2 := strings.Index(userInfo, ":"); idx2 >= 0 {
			return userInfo[idx2+1:]
		}
	}
	return ""
}

// GetCORSOrigins returns CORS allowed origins as a slice
func (c *Config) GetCORSOrigins() []string {
	if c.CORSAllowedOrigins == "*" {
		return []string{"*"}
	}
	return strings.Split(c.CORSAllowedOrigins, ",")
}

// GetAuditStreamAllowedOrigins returns audit stream WebSocket allowed origins as a slice.
// If the config is empty, returns a same-origin policy (only the host itself).
// Supports comma-separated values and wildcard subdomains (e.g., *.example.com).
func (c *Config) GetAuditStreamAllowedOrigins() []string {
	if c.AuditStreamAllowedOrigins == "" {
		// Default to same-origin policy - only allow connections from the same host
		return nil // nil indicates same-origin only
	}
	if c.AuditStreamAllowedOrigins == "*" {
		return []string{"*"}
	}
	origins := strings.Split(c.AuditStreamAllowedOrigins, ",")
	result := make([]string, 0, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o != "" {
			result = append(result, o)
		}
	}
	return result
}

// ShutdownTimeout returns the configured graceful-shutdown timeout, defaulting to
// 30s when unset or non-positive.
func (c *Config) ShutdownTimeout() time.Duration {
	if c.ShutdownTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.ShutdownTimeoutSeconds) * time.Second
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development" || c.Environment == "dev"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production" || c.Environment == "prod"
}

// ProductionWarnings returns a list of configuration issues that should be
// addressed before deploying to production. Returns nil if no issues found.
func (c *Config) ProductionWarnings() []string {
	if !c.IsProduction() {
		return nil
	}
	var warnings []string
	if c.JWTSecret == "" || strings.Contains(strings.ToLower(c.JWTSecret), "change") {
		warnings = append(warnings, "jwt_secret uses a default or placeholder value")
	}
	if c.EncryptionKey == "" || strings.Contains(strings.ToLower(c.EncryptionKey), "change") {
		warnings = append(warnings, "encryption_key uses a default or placeholder value")
	}
	if strings.Contains(c.AccessSessionSecret, "change-me") {
		warnings = append(warnings, "access_session_secret uses the default placeholder")
	}
	if c.CORSAllowedOrigins == "*" {
		warnings = append(warnings, "cors_allowed_origins is wildcard '*'; set specific origins for production")
	}
	if !c.CSRFEnabled {
		warnings = append(warnings, "csrf_enabled is false; enable CSRF protection for production deployments")
	}
	if m := c.effectiveDatabaseSSLMode(); m == "" || m == "disable" {
		warnings = append(warnings, "database sslmode is 'disable' (from DATABASE_URL or database_ssl_mode); use 'verify-full' for production")
	}
	if !c.RedisTLSEnabled {
		warnings = append(warnings, "redis_tls_enabled is false; enable TLS for Redis in production")
	}
	if !c.TLS.Enabled {
		warnings = append(warnings, "tls.enabled is false; enable inter-service TLS for production")
	}
	return warnings
}

// effectiveDatabaseSSLMode returns the sslmode that will actually govern the DB
// connection. The value embedded in DatabaseURL wins, because the pool is built
// from that URL verbatim (pgxpool.ParseConfig); the standalone DatabaseSSLMode
// field is only a fallback for when the URL omits it. This prevents a passing
// production gate while DATABASE_URL carries sslmode=disable.
func (c *Config) effectiveDatabaseSSLMode() string {
	if m := sslmodeRe.FindStringSubmatch(c.DatabaseURL); len(m) == 2 {
		return m[1]
	}
	return c.DatabaseSSLMode
}

// ValidateProduction performs critical security validation for production deployments.
// Returns an error if any critical security misconfigurations are detected that MUST
// be fixed before production deployment. This is called automatically at service startup
// in production mode and will block server startup if validation fails.
func (c *Config) ValidateProduction() error {
	if !c.IsProduction() {
		return nil
	}

	var criticalIssues []string

	// Critical: Insecure session secrets can lead to session hijacking
	if c.AccessSessionSecret == "" || strings.Contains(c.AccessSessionSecret, "change-me") {
		criticalIssues = append(criticalIssues,
			"access_session_secret must be set to a secure random value (at least 32 bytes)")
	}

	// Critical: JWT signing key must be secure
	if c.JWTSecret == "" || strings.Contains(strings.ToLower(c.JWTSecret), "change") {
		criticalIssues = append(criticalIssues,
			"jwt_secret must be set to a secure random value (at least 32 bytes)")
	}

	// Critical: Encryption key for sensitive data
	if c.EncryptionKey == "" || strings.Contains(strings.ToLower(c.EncryptionKey), "change") {
		criticalIssues = append(criticalIssues,
			"encryption_key must be set to a secure random value (at least 32 bytes)")
	}

	// Critical: the PAM vault must have an explicit KEK in production. vault
	// KeyringFromConfig falls back to ENCRYPTION_KEY when neither VAULT_KEK nor
	// VAULT_KEKS is set; that silently couples the vault's key-encryption key to
	// the general encryption key, defeating independent rotation/scoping of the
	// most sensitive secret store. Require an explicit vault KEK in production.
	if c.VaultKEK == "" && c.VaultKEKs == "" {
		criticalIssues = append(criticalIssues,
			"vault_kek or vault_keks must be set in production; do not rely on the ENCRYPTION_KEY fallback for the vault key-encryption key")
	}

	// Critical: Wildcard CORS in production allows any origin
	if c.CORSAllowedOrigins == "*" {
		criticalIssues = append(criticalIssues,
			"cors_allowed_origins cannot be wildcard '*' in production; specify allowed origins")
	}

	// Critical: CSRF protection must be enabled in production
	if !c.CSRFEnabled {
		criticalIssues = append(criticalIssues,
			"csrf_enabled must be true in production to prevent CSRF attacks")
	}

	// Critical: Database connections must use TLS in production. Check the
	// EFFECTIVE sslmode — the one in DATABASE_URL (what pgx actually connects
	// with) wins over the standalone database_ssl_mode field, so a URL carrying
	// sslmode=disable can't slip past a field set to 'require'.
	if m := c.effectiveDatabaseSSLMode(); m == "" || m == "disable" {
		criticalIssues = append(criticalIssues,
			"database sslmode must be 'require', 'verify-ca', or 'verify-full' in production (not 'disable') — set it in DATABASE_URL and/or database_ssl_mode")
	}

	// Critical: Redis connections must use TLS in production
	if !c.RedisTLSEnabled {
		criticalIssues = append(criticalIssues,
			"redis_tls_enabled must be true in production")
	}

	// Critical: if Elasticsearch is configured in production, it must be authenticated
	// (the compose ES now runs with xpack.security on). No ES URL ⇒ ES unused ⇒ no check.
	if c.ElasticsearchURL != "" && (c.ElasticsearchUsername == "" || c.ElasticsearchPassword == "") {
		criticalIssues = append(criticalIssues,
			"elasticsearch_username and elasticsearch_password must be set in production when elasticsearch_url is configured")
	}

	// Critical: Inter-service TLS must be enabled in production
	if !c.TLS.Enabled {
		criticalIssues = append(criticalIssues,
			"tls.enabled must be true in production for inter-service encryption")
	}

	// Critical: Audit stream WebSocket must have origin validation in production
	auditOrigins := c.GetAuditStreamAllowedOrigins()
	if len(auditOrigins) == 0 && c.AuditStreamAllowedOrigins == "" {
		criticalIssues = append(criticalIssues,
			"audit_stream_allowed_origins must be configured in production; set specific origins for WebSocket audit stream")
	}
	if c.AuditStreamAllowedOrigins == "*" {
		criticalIssues = append(criticalIssues,
			"audit_stream_allowed_origins cannot be wildcard '*' in production; specify allowed WebSocket origins")
	}

	// Critical: OTP debug mode must NEVER be enabled in production
	if c.DebugOTPInResponse {
		criticalIssues = append(criticalIssues,
			"debug_otp_in_response must be false in production; OTP codes must never be exposed in API responses")
	}

	// Critical: TLS skip-verify flags must NEVER be true in production.
	// These flags exist as dev-loop escape hatches against self-signed
	// certs in a local docker stack; in production they erase the entire
	// trust chain on the link they cover.
	if c.RedisTLSSkipVerify {
		criticalIssues = append(criticalIssues,
			"redis_tls_skip_verify must be false in production; setting it to true disables Redis server-cert validation")
	}
	if c.ZitiInsecureSkipVerify {
		criticalIssues = append(criticalIssues,
			"ziti_insecure_skip_verify must be false in production; setting it to true disables Ziti controller TLS validation")
	}

	// Critical: the published default admin passwords must be overridden in
	// production. These defaults exist only so the local docker stack boots
	// without extra config; leaving them lets anyone who read the source log
	// into the Ziti controller / Guacamole with a known credential. Only guard
	// components that are actually enabled.
	if c.ZitiEnabled && c.ZitiAdminPassword == defaultZitiAdminPassword {
		criticalIssues = append(criticalIssues,
			"ziti_admin_password is the built-in default; set ZITI_ADMIN_PASSWORD to a unique secret in production")
	}
	if c.GuacamoleURL != "" && c.GuacamoleAdminPassword == defaultGuacamoleAdminPassword {
		criticalIssues = append(criticalIssues,
			"guacamole_admin_password is the built-in default; set GUACAMOLE_ADMIN_PASSWORD to a unique secret in production")
	}

	if len(criticalIssues) > 0 {
		return fmt.Errorf("production security validation failed:\n  - %s",
			strings.Join(criticalIssues, "\n  - "))
	}

	return nil
}

// DebugOTPsEnabled returns true only if explicitly enabled via config.
// This replaces the unsafe IsDevelopment() check for OTP exposure.
func (c *Config) DebugOTPsEnabled() bool {
	return c.DebugOTPInResponse
}
