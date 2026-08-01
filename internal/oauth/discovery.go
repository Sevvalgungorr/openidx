// Package oauth provides OpenID Connect Discovery functionality
package oauth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// DiscoveryDocument represents the OpenID Connect Discovery document
// Implements OpenID Connect Discovery 1.0 §3
type DiscoveryDocument struct {
	// Required fields
	Issuer                           string   `json:"issuer"`                                // Required
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`                // Required
	TokenEndpoint                    string   `json:"token_endpoint"`                        // Required
	JWKSURI                          string   `json:"jwks_uri"`                              // Required
	ResponseTypesSupported           []string `json:"response_types_supported"`              // Required
	SubjectTypesSupported            []string `json:"subject_types_supported"`               // Required
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"` // Required

	// Optional but recommended fields
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`                     // Optional
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`                 // Optional
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`                      // Optional
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"` // Optional
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`                      // Optional
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`                 // Optional

	// Additional OpenID Connect fields
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`                 // Optional
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"` // Optional
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`                         // Optional
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`                            // Optional

	// Session management
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"` // Optional

	// Front-channel logout
	FrontchannelLogoutSupported        bool `json:"frontchannel_logout_supported,omitempty"`         // Optional
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"` // Optional

	// Back-channel logout
	BackchannelLogoutSupported        bool `json:"backchannel_logout_supported,omitempty"`         // Optional
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"` // Optional

	// Additional OAuth 2.0 features
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`    // Optional
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"` // Optional

	// Request parameters
	RequestObjectSigningAlgValuesSupported    []string            `json:"request_object_signing_alg_values_supported,omitempty"`    // Optional
	RequestObjectEncryptionAlgValuesSupported []string            `json:"request_object_encryption_alg_values_supported,omitempty"` // Optional
	RequestObjectEncryptionEncValuesSupported []string            `json:"request_object_encryption_enc_values_supported,omitempty"` // Optional
	UserInfoSigningAlgValuesSupported         []string            `json:"userinfo_signing_alg_values_supported,omitempty"`          // Optional
	UserInfoEncryptionAlgValuesSupported      []string            `json:"userinfo_encryption_alg_values_supported,omitempty"`       // Optional
	UserInfoEncryptionEncValuesSupported      []string            `json:"userinfo_encryption_enc_values_supported,omitempty"`       // Optional
	ACRValuesSupported                        []string            `json:"acr_values_supported,omitempty"`                           // Optional
	SubjectTypeAliasesSupported               []string            `json:"subject_type_aliases_supported,omitempty"`                 // Optional
	SubjectTypeAliases                        map[string][]string `json:"subject_type_aliases,omitempty"`                           // Optional
	IDTokenEncryptionAlgValuesSupported       []string            `json:"id_token_encryption_alg_values_supported,omitempty"`       // Optional
	IDTokenEncryptionEncValuesSupported       []string            `json:"id_token_encryption_enc_values_supported,omitempty"`       // Optional

	// TLS client certificate bound access tokens
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"` // Optional

	// JWT Secured Authorization Request (JAR)
	AuthorizationRequestIssuersSupported      []string `json:"authorization_request_issuers_supported,omitempty"`       // Optional
	AuthorizationEncryptionAlgValuesSupported []string `json:"authorization_encryption_alg_values_supported,omitempty"` // Optional
	AuthorizationEncryptionEncValuesSupported []string `json:"authorization_encryption_enc_values_supported,omitempty"` // Optional
	AuthorizationSigningAlgValuesSupported    []string `json:"authorization_signing_alg_values_supported,omitempty"`    // Optional

	// Pushed Authorization Requests (PAR)
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"` // Optional
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"` // Optional

	// Mutual TLS Client Certificate-Bound Access Tokens
	MTLSEndpointAliases map[string]string `json:"mtls_endpoint_aliases,omitempty"` // Optional

	// Custom extensions
	ServiceDocumentation string   `json:"service_documentation,omitempty"` // Optional
	UILocalesSupported   []string `json:"ui_locales_supported,omitempty"`  // Optional
	OpPolicyURI          string   `json:"op_policy_uri,omitempty"`         // Optional
	OpTOSURI             string   `json:"op_tos_uri,omitempty"`            // Optional
}

// DiscoveryHandler handles OpenID Connect Discovery requests
type DiscoveryHandler struct {
	issuer   string
	logger   *zap.Logger
	document *DiscoveryDocument
}

// NewDiscoveryHandler creates a new discovery handler
func NewDiscoveryHandler(issuer string, logger *zap.Logger) *DiscoveryHandler {
	doc := buildDiscoveryDocument(issuer)

	return &DiscoveryHandler{
		issuer:   issuer,
		logger:   logger.With(zap.String("component", "discovery")),
		document: doc,
	}
}

// buildDiscoveryDocument constructs the OpenID Connect Discovery document
func buildDiscoveryDocument(issuer string) *DiscoveryDocument {
	return &DiscoveryDocument{
		// Required fields per OpenID Connect Discovery 1.0
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize",
		TokenEndpoint:         issuer + "/oauth/token",
		JWKSURI:               issuer + "/.well-known/jwks.json",
		RegistrationEndpoint:  issuer + "/oauth/register",
		// Authorization Code Flow only. The implicit and hybrid entries that
		// used to be listed here were never implemented — the comments calling
		// them "deprecated but supported" were half right.
		ResponseTypesSupported: []string{
			"code",
		},
		SubjectTypesSupported: []string{
			"public", // Same subject for all clients (default). "pairwise" is
			// advertised by the live discovery (service.handleDiscovery) only when
			// OIDCPairwiseSubjects is enabled — see discoverySubjectTypes — so this
			// static builder (used in tests/tools) lists the always-true default.
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256", // RSA with SHA-256 (recommended)
			"RS384", // RSA with SHA-384
			"RS512", // RSA with SHA-512
		},

		// Optional but recommended fields
		UserInfoEndpoint: issuer + "/oauth/userinfo",
		ScopesSupported: []string{
			"openid",         // Required for OIDC
			"profile",        // Standard profile claims
			"email",          // Email claims
			"phone",          // Phone claims
			"address",        // Address claims
			"offline_access", // Refresh token
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic", // HTTP Basic authentication (recommended)
			"client_secret_post",  // POST body authentication
			"none",                // Public clients (no authentication)
		},
		ClaimsSupported: []string{
			// Standard OIDC claims
			"sub",       // Subject (required)
			"iss",       // Issuer
			"aud",       // Audience
			"exp",       // Expiration time
			"iat",       // Issued at time
			"auth_time", // Authentication time
			"nonce",     // Nonce
			"acr",       // Authentication context reference
			"amr",       // Authentication methods references
			"azp",       // Authorized party
			// Profile claims
			"name",               // Full name
			"given_name",         // Given name
			"family_name",        // Family name
			"middle_name",        // Middle name
			"nickname",           // Nickname
			"preferred_username", // Preferred username
			"profile",            // Profile URL
			"picture",            // Picture URL
			"website",            // Website URL
			"gender",             // Gender
			"birthdate",          // Birthdate
			"zoneinfo",           // Timezone
			"locale",             // Locale
			"updated_at",         // Last update time
			// Email claims
			"email",          // Email address
			"email_verified", // Email verified status
			// Phone claims
			"phone_number",          // Phone number
			"phone_number_verified", // Phone verified status
			// Address claims
			"address", // Address object
			// Custom OpenIDX claims
			"roles",   // User roles
			"groups",  // User groups
			"sid",     // Session ID
			"at_hash", // Access token hash
			"c_hash",  // Code hash
		},
		GrantTypesSupported: []string{
			"authorization_code", // Authorization code flow (recommended)
			"refresh_token",      // Refresh token
			"client_credentials", // Client credentials
			"password",           // Resource owner password credentials (not recommended)
			"urn:ietf:params:oauth:grant-type:token-exchange", // RFC 8693 token exchange
		},
		CodeChallengeMethodsSupported: []string{
			"S256", // SHA-256 — the only advertised PKCE method. "plain" offers no
			// protection against code interception and is not advertised; the
			// authorize endpoint also rejects it in production.
		},
		DisplayValuesSupported: []string{
			"page",  // Default
			"popup", // Popup window
			"touch", // Touch-optimized
			"wap",   // WAP page
		},
		ClaimTypesSupported: []string{
			"normal",      // Normal claim (default)
			"aggregated",  // Aggregated claim
			"distributed", // Distributed claim
		},
		TokenEndpointAuthSigningAlgValuesSupported: []string{
			"RS256", // RSA with SHA-256
			"RS384", // RSA with SHA-384
			"RS512", // RSA with SHA-512
			"HS256", // HMAC with SHA-256
			"HS384", // HMAC with SHA-384
			"HS512", // HMAC with SHA-512
		},
		RequestObjectSigningAlgValuesSupported: []string{
			"none",  // No signature (not recommended)
			"RS256", // RSA with SHA-256
			"RS384", // RSA with SHA-384
			"RS512", // RSA with SHA-512
			"HS256", // HMAC with SHA-256
			"HS384", // HMAC with SHA-384
			"HS512", // HMAC with SHA-512
		},
		UserInfoSigningAlgValuesSupported: []string{
			"none",  // No signature (default)
			"RS256", // RSA with SHA-256
			"RS384", // RSA with SHA-384
			"RS512", // RSA with SHA-512
		},
		ACRValuesSupported: []string{
			"0", // No authentication performed
			"1", // Basic authentication
			"2", // Multi-factor authentication
		},

		// Session management
		EndSessionEndpoint: issuer + "/oauth/logout",

		// Back-channel logout (supported)
		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: true,

		// Front-channel logout (not currently supported)
		FrontchannelLogoutSupported:        false,
		FrontchannelLogoutSessionSupported: false,

		// OAuth 2.0 Token Revocation (RFC 7009)
		RevocationEndpoint: issuer + "/oauth/revoke",

		// OAuth 2.0 Token Introspection (RFC 7662)
		IntrospectionEndpoint: issuer + "/oauth/introspect",

		// TLS client certificate bound access tokens (not currently supported)
		TLSClientCertificateBoundAccessTokens: false,

		// Mutual TLS endpoint aliases (not currently supported)
		MTLSEndpointAliases: nil,

		// Custom extensions
		ServiceDocumentation: "https://docs.openidx.org",
		UILocalesSupported: []string{
			"en", // English
			"es", // Spanish
			"fr", // French
			"de", // German
			"ja", // Japanese
			"zh", // Chinese
		},
	}
}

// HandleDiscovery handles GET /.well-known/openid-configuration requests
// Implements OpenID Connect Discovery 1.0 §4
func (h *DiscoveryHandler) HandleDiscovery(c *gin.Context) {
	// CORS is handled by the APISIX gateway for all routes
	c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}

	h.logger.Debug("Serving OpenID Connect Discovery document",
		zap.String("issuer", h.issuer))

	c.JSON(http.StatusOK, h.document)
}

// ValidateDiscoveryDocument validates that the discovery document contains
// all required fields per OpenID Connect Discovery 1.0
func ValidateDiscoveryDocument(doc *DiscoveryDocument) error {
	if doc.Issuer == "" {
		return errors.New("missing required field: issuer")
	}
	if doc.AuthorizationEndpoint == "" {
		return errors.New("missing required field: authorization_endpoint")
	}
	if doc.TokenEndpoint == "" {
		return errors.New("missing required field: token_endpoint")
	}
	if doc.JWKSURI == "" {
		return errors.New("missing required field: jwks_uri")
	}
	if len(doc.ResponseTypesSupported) == 0 {
		return errors.New("missing required field: response_types_supported")
	}
	if len(doc.SubjectTypesSupported) == 0 {
		return errors.New("missing required field: subject_types_supported")
	}
	if len(doc.IDTokenSigningAlgValuesSupported) == 0 {
		return errors.New("missing required field: id_token_signing_alg_values_supported")
	}
	return nil
}

// errors shim for this package
var (
	// ErrInvalidDiscoveryDocument is returned when the discovery document is invalid
	ErrInvalidDiscoveryDocument = errors.New("invalid_discovery_document")
)
