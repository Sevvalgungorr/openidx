// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// JWKSKey represents a single key from the JWKS endpoint
type JWKSKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

// jwksKeyCache stores parsed RSA public keys.
//
// It keeps the last successfully fetched key set and the time of that fetch so
// that, when a refresh fails (the OAuth/JWKS endpoint or the shared database is
// down), we can SERVE STALE keys rather than reject otherwise-valid tokens. This
// is the Tier 0 availability belt: token verification survives a JWKS/DB outage
// for up to jwksMaxStale past the normal TTL. See jwks_metrics.go.
type jwksKeyCache struct {
	keys          map[string]*rsa.PublicKey
	expiresAt     time.Time // freshness horizon: keys are "fresh" until this time
	lastRefreshOK time.Time // when we last fetched a valid key set (for staleness math)
	mu            sync.RWMutex
}

// Global JWKS cache with 1 hour freshness TTL.
var globalJWKSCache = &jwksKeyCache{
	keys: make(map[string]*rsa.PublicKey),
}

// jwksTTL is how long a fetched key set is considered fresh before we try to
// refresh it. jwksMaxStale is how long past that we will keep serving the cached
// keys when refresh fails; beyond it we stop trusting the stale set and fail
// verification (a signing key could have been rotated + retired by then).
//
// Rationale: OAuth signing keys rotate on the order of days/weeks with a long
// verification grace (internal/oauth/signer.go), so serving keys a few hours
// stale is safe and keeps every already-issued token verifiable through a
// database outage. Both are overridable for tests / tuning.
var (
	jwksTTL      = envDuration("JWKS_TTL", time.Hour)
	jwksMaxStale = envDuration("JWKS_MAX_STALE", 12*time.Hour)
)

// envDuration reads a Go duration (e.g. "1h", "30m") from env, falling back to
// def on empty/unparseable input.
func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// fetchJWKS fetches and parses JWKS from the given URL
func fetchJWKS(jwksURL string) (map[string]*rsa.PublicKey, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[key.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA signing keys found in JWKS")
	}

	return keys, nil
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// refreshJWKSLocked attempts to fetch a fresh key set and update the cache.
// It MUST be called with globalJWKSCache.mu held for writing.
//
// On success it swaps in the new keys, extends the freshness TTL, records the
// refresh time, and returns nil. On failure it does NOT clear the existing keys
// (serve-stale): the caller decides whether the still-cached keys are within the
// max-stale window and may be used. Metrics are emitted for both outcomes.
func refreshJWKSLocked(jwksURL string) error {
	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		jwksRefreshFailuresTotal.Inc()
		return err
	}
	globalJWKSCache.keys = keys
	now := time.Now()
	globalJWKSCache.expiresAt = now.Add(jwksTTL)
	globalJWKSCache.lastRefreshOK = now
	jwksRefreshSuccessTotal.Inc()
	return nil
}

// staleUsableLocked reports whether the currently cached key set, though past
// its freshness TTL, is still within the max-stale window and may be served.
// MUST be called with the cache mutex held (read or write).
func staleUsableLocked() bool {
	if len(globalJWKSCache.keys) == 0 {
		return false
	}
	// lastRefreshOK zero means we never successfully fetched — nothing to trust.
	if globalJWKSCache.lastRefreshOK.IsZero() {
		return false
	}
	return time.Since(globalJWKSCache.expiresAt) <= jwksMaxStale
}

// noteServeStaleLocked records staleness metrics when a stale key is served.
func noteServeStaleLocked() {
	jwksServeStaleTotal.Inc()
	jwksStaleSeconds.Set(time.Since(globalJWKSCache.lastRefreshOK).Seconds())
}

// getSigningKey retrieves the RSA public key for token validation.
//
// Availability contract (Tier 0): a valid, already-issued token MUST keep
// verifying through a JWKS/database outage. Order of preference:
//  1. fresh cache hit;
//  2. successful refresh;
//  3. SERVE STALE — if refresh fails but a previously-fetched key set is still
//     within JWKS_MAX_STALE, use it rather than rejecting the token.
//
// Only when there is no usable (fresh or stale) key set do we surface the error.
func getSigningKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	// Fast path: fresh cache hit.
	globalJWKSCache.mu.RLock()
	if time.Now().Before(globalJWKSCache.expiresAt) {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			globalJWKSCache.mu.RUnlock()
			return key, nil
		}
	}
	globalJWKSCache.mu.RUnlock()

	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	// Double-check after acquiring the write lock.
	if time.Now().Before(globalJWKSCache.expiresAt) {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			return key, nil
		}
	}

	if err := refreshJWKSLocked(jwksURL); err != nil {
		// Refresh failed. Serve stale if we still have a trustworthy cached set.
		if staleUsableLocked() {
			if key, ok := globalJWKSCache.keys[kid]; ok {
				noteServeStaleLocked()
				return key, nil
			}
			// Stale set is usable but doesn't contain this kid: the token was
			// signed by a key we've never seen. That is a real verification
			// failure, not an availability issue — surface it.
			return nil, fmt.Errorf("key with kid %s not found in JWKS (issuer unreachable; served from stale cache): %w", kid, err)
		}
		return nil, fmt.Errorf("JWKS refresh failed and no usable cached keys: %w", err)
	}

	if key, ok := globalJWKSCache.keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

// getFirstSigningKey returns the first RSA signing key from JWKS (for tokens
// without kid). It follows the same fresh → refresh → serve-stale availability
// contract as getSigningKey.
func getFirstSigningKey(jwksURL string) (*rsa.PublicKey, error) {
	globalJWKSCache.mu.RLock()
	if time.Now().Before(globalJWKSCache.expiresAt) && len(globalJWKSCache.keys) > 0 {
		for _, key := range globalJWKSCache.keys {
			globalJWKSCache.mu.RUnlock()
			return key, nil
		}
	}
	globalJWKSCache.mu.RUnlock()

	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	if time.Now().Before(globalJWKSCache.expiresAt) && len(globalJWKSCache.keys) > 0 {
		for _, key := range globalJWKSCache.keys {
			return key, nil
		}
	}

	if err := refreshJWKSLocked(jwksURL); err != nil {
		if staleUsableLocked() {
			noteServeStaleLocked()
			for _, key := range globalJWKSCache.keys {
				return key, nil
			}
		}
		return nil, fmt.Errorf("JWKS refresh failed and no usable cached keys: %w", err)
	}

	for _, key := range globalJWKSCache.keys {
		return key, nil
	}

	return nil, fmt.Errorf("no signing keys found in JWKS")
}

// VerifyBearerToken validates a bearer JWT against the OAuth JWKS and returns
// its claims. It enforces the same guarantees as Auth(): an RS256 algorithm pin
// (rejecting "none"/HS256 and alg-confusion), a kid→JWKS signing-key lookup via
// the shared 1-hour key cache, and a required, unexpired exp. It is for services
// that authenticate a bearer OUTSIDE the Auth() middleware (e.g. the access
// reverse proxy resolving a forwarded bearer). Any verification failure returns
// an error; callers MUST treat a non-nil error as "unauthenticated" and build no
// session from it.
func VerifyBearerToken(jwksURL, tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" {
			return nil, fmt.Errorf("token missing alg header")
		}
		if alg != "RS256" {
			return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("token method is not RSA despite alg header")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}
		return getSigningKey(jwksURL, kid)
	})
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token missing exp")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}

// CORS returns a middleware that handles CORS headers
func CORS(allowedOrigins ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		// Allow requests with no Origin header (non-browser requests like health checks)
		if origin == "" {
			c.Next()
			return
		}
		allowed := false
		if len(allowedOrigins) == 0 || (len(allowedOrigins) == 1 && allowedOrigins[0] == "*") {
			c.Header("Access-Control-Allow-Origin", "*")
			allowed = true
		} else {
			for _, o := range allowedOrigins {
				if o == origin {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Vary", "Origin")
					allowed = true
					break
				}
			}
		}
		if !allowed {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID, X-Total-Count")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// APIKeyValidator validates API keys and returns key info
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, rawKey string) (*APIKeyInfo, error)
}

// APIKeyInfo holds validated API key information
type APIKeyInfo struct {
	KeyID            string
	UserID           string
	ServiceAccountID string
	Scopes           []string
	// OrgID is the organization the key belongs to. The auth path
	// sets the request's org_id from it — the API-key analog of the
	// JWT org_id claim — so the tenant resolver scopes API-key callers
	// to the key's org.
	OrgID string
}

// Auth validates JWT tokens via JWKS
func Auth(jwksURL string) gin.HandlerFunc {
	return AuthWithAPIKey(jwksURL, nil)
}

// AuthWithAPIKey validates JWT tokens via JWKS, with optional API key support
func AuthWithAPIKey(jwksURL string, apiKeyValidator APIKeyValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]

		// Check if this is an API key (starts with "oidx_")
		if strings.HasPrefix(tokenString, "oidx_") && apiKeyValidator != nil {
			keyInfo, err := apiKeyValidator.ValidateAPIKey(c.Request.Context(), tokenString)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": fmt.Sprintf("invalid API key: %v", err),
				})
				return
			}
			// Set context from API key
			if keyInfo.UserID != "" {
				c.Set("user_id", keyInfo.UserID)
			}
			if keyInfo.ServiceAccountID != "" {
				c.Set("service_account_id", keyInfo.ServiceAccountID)
			}
			// Carry the key's org so the tenant resolver scopes the
			// request to it — the API-key analog of the JWT org_id
			// claim. Falls back to the default org when unset, matching
			// the JWT path below.
			if keyInfo.OrgID != "" {
				c.Set("org_id", keyInfo.OrgID)
			} else {
				c.Set("org_id", "00000000-0000-0000-0000-000000000010")
			}
			c.Set("api_key_id", keyInfo.KeyID)
			c.Set("scopes", keyInfo.Scopes)
			c.Set("auth_method", "api_key")
			// API keys get admin role for service accounts
			if keyInfo.ServiceAccountID != "" {
				c.Set("roles", []string{"service_account"})
			}
			c.Next()
			return
		}

		// Parse the token with key function that fetches from JWKS
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// CRITICAL: Explicitly verify algorithm to prevent "none" algorithm attacks
			// Reject tokens without explicit algorithm header
			alg, ok := token.Header["alg"].(string)
			if !ok || alg == "" {
				return nil, fmt.Errorf("token missing alg header or alg is not a string")
			}

			// Only allow RS256 algorithm - reject "none", HS256, or any other algorithm
			if alg != "RS256" {
				return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
			}

			// Double-check the method type matches our expectation
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("token method is not RSA despite alg header")
			}

			// Get the key ID from token header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("token missing kid header")
			}

			// Fetch the signing key from JWKS
			return getSigningKey(jwksURL, kid)
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("invalid token: %v", err),
			})
			return
		}

		// Validate token
		if token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token claims",
			})
			return
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "token expired",
				})
				return
			}
		}

		// Set user context
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}

		// Extract session ID from sid claim
		if sid, ok := claims["sid"].(string); ok && sid != "" {
			c.Set("session_id", sid)
		}

		// Extract roles
		if roles, ok := claims["roles"].([]interface{}); ok {
			roleStrings := make([]string, len(roles))
			for i, role := range roles {
				roleStrings[i] = fmt.Sprint(role)
			}
			c.Set("roles", roleStrings)
		}
		// Extract amr (authentication methods references) so downstream can tell
		// whether the session actually completed MFA. Tokens don't emit it yet
		// (so this is absent → treated as no-MFA); wiring it here keeps
		// DEVICE_AUTOTRUST correct-by-construction once amr is issued on MFA login.
		if amr, ok := claims["amr"].([]interface{}); ok {
			amrStrings := make([]string, len(amr))
			for i, m := range amr {
				amrStrings[i] = fmt.Sprint(m)
			}
			c.Set("amr", amrStrings)
		}

		// Extract org_id from claims, default to default org
		if orgID, ok := claims["org_id"].(string); ok && orgID != "" {
			c.Set("org_id", orgID)
		} else {
			c.Set("org_id", DefaultOrgID)
		}

		c.Next()
	}
}

// SoftAuth parses JWT if present but does not block unauthenticated requests.
// Used in dev mode so endpoints can optionally identify the caller.
func SoftAuth(jwksURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.Next()
			return
		}

		token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
			// CRITICAL: Explicitly verify algorithm to prevent "none" algorithm attacks
			alg, ok := token.Header["alg"].(string)
			if !ok || alg == "" {
				return nil, fmt.Errorf("token missing alg header")
			}
			// Only allow RS256 algorithm
			if alg != "RS256" {
				return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
			}
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("token method is not RSA despite alg header")
			}
			kid, _ := token.Header["kid"].(string)
			if kid != "" {
				return getSigningKey(jwksURL, kid)
			}
			// No kid header - use the first available RSA key
			return getFirstSigningKey(jwksURL)
		})

		if err != nil || token == nil || !token.Valid {
			c.Next()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.Next()
			return
		}

		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}
		// Extract session ID from sid claim
		if sid, ok := claims["sid"].(string); ok && sid != "" {
			c.Set("session_id", sid)
		}
		if roles, ok := claims["roles"].([]interface{}); ok {
			roleStrings := make([]string, len(roles))
			for i, role := range roles {
				roleStrings[i] = fmt.Sprint(role)
			}
			c.Set("roles", roleStrings)
		}
		// Extract amr (authentication methods references) so downstream can tell
		// whether the session actually completed MFA. Tokens don't emit it yet
		// (so this is absent → treated as no-MFA); wiring it here keeps
		// DEVICE_AUTOTRUST correct-by-construction once amr is issued on MFA login.
		if amr, ok := claims["amr"].([]interface{}); ok {
			amrStrings := make([]string, len(amr))
			for i, m := range amr {
				amrStrings[i] = fmt.Sprint(m)
			}
			c.Set("amr", amrStrings)
		}
		if orgID, ok := claims["org_id"].(string); ok && orgID != "" {
			c.Set("org_id", orgID)
		} else {
			c.Set("org_id", DefaultOrgID)
		}

		c.Next()
	}
}

// RequireRoles ensures the user has at least one of the specified roles
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "no roles found",
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format",
			})
			return
		}

		// Check if user has any of the required roles
		for _, required := range roles {
			for _, userRole := range userRolesList {
				if userRole == required {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "insufficient permissions",
		})
	}
}

// PermissionEntry represents a resolved permission for a user
type PermissionEntry struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	ScopeType string `json:"scope_type,omitempty"`
	ScopeID   string `json:"scope_id,omitempty"`
}

// PermissionResolver loads the user's effective permissions from their roles via Redis cache.
// Must run after Auth/SoftAuth so that "roles" and "user_id" are set in the context.
func PermissionResolver(db *pgxpool.Pool, redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesRaw, exists := c.Get("roles")
		if !exists {
			c.Next()
			return
		}
		roleNames, ok := rolesRaw.([]string)
		if !ok || len(roleNames) == 0 {
			c.Next()
			return
		}

		// Resolve permissions within the caller's org: role names are
		// per-tenant (the same "admin" role exists in many orgs), so the
		// cache key MUST include the org or one tenant's perms would leak
		// to another. Falls back to the default org when unresolved,
		// matching the milestone's DefaultOrgFallback semantics.
		orgID := "00000000-0000-0000-0000-000000000010"
		if org, err := orgctx.From(c.Request.Context()); err == nil && org.ID != "" {
			orgID = org.ID
		}

		sortedRoles := make([]string, len(roleNames))
		copy(sortedRoles, roleNames)
		sort.Strings(sortedRoles)
		cacheKey := "perms:" + orgID + ":" + strings.Join(sortedRoles, ",")

		// Try Redis cache
		if redisClient != nil {
			cached, err := redisClient.Get(c.Request.Context(), cacheKey).Result()
			if err == nil && cached != "" {
				var perms []PermissionEntry
				if json.Unmarshal([]byte(cached), &perms) == nil {
					c.Set("permissions", perms)
					c.Next()
					return
				}
			}
		}

		// Cache miss: query DB.
		//
		// role_permissions is RLS-FORCE'd and the pool derives app.org_id from the
		// acquire context's orgctx marker at checkout. This middleware runs before
		// the tenant GUC is established, so a bare-context query sets no app.org_id
		// and RLS hides EVERY row — perms resolve to null and RequirePermission then
		// 403s every caller. This read is already scoped to the caller's org by the
		// explicit r.org_id = $2 predicate, so WithBypassRLS (a legitimately
		// org-scoped/install-wide read) is the correct, leak-free fix.
		resolveCtx := orgctx.WithBypassRLS(c.Request.Context())
		rows, err := db.Query(resolveCtx, `
			SELECT DISTINCT p.resource, p.action
			FROM permissions p
			JOIN role_permissions rp ON p.id = rp.permission_id
			JOIN roles r ON r.id = rp.role_id
			WHERE r.name = ANY($1) AND r.org_id = $2
		`, roleNames, orgID)
		if err != nil {
			c.Next()
			return
		}
		defer rows.Close()

		var perms []PermissionEntry
		for rows.Next() {
			var pe PermissionEntry
			if err := rows.Scan(&pe.Resource, &pe.Action); err == nil {
				perms = append(perms, pe)
			}
		}

		// Also resolve admin delegations for this user
		userIDRaw, _ := c.Get("user_id")
		userID, _ := userIDRaw.(string)
		if userID != "" {
			// Same RLS reasoning as the role_permissions read above: scoped by the
			// explicit delegate_id = $1 predicate, so bypass is safe and necessary.
			delegRows, err := db.Query(resolveCtx, `
				SELECT permissions, scope_type, scope_id::text
				FROM admin_delegations
				WHERE delegate_id = $1 AND enabled = true
				AND (expires_at IS NULL OR expires_at > NOW())
			`, userID)
			if err == nil {
				defer delegRows.Close()
				for delegRows.Next() {
					var permsJSON []byte
					var scopeType, scopeID string
					if delegRows.Scan(&permsJSON, &scopeType, &scopeID) == nil {
						var delegPerms []string
						if json.Unmarshal(permsJSON, &delegPerms) == nil {
							for _, dp := range delegPerms {
								parts := strings.SplitN(dp, ":", 2)
								if len(parts) == 2 {
									perms = append(perms, PermissionEntry{
										Resource:  parts[0],
										Action:    parts[1],
										ScopeType: scopeType,
										ScopeID:   scopeID,
									})
								}
							}
						}
					}
				}
			}
		}

		// Cache in Redis for 5 minutes
		if redisClient != nil {
			if data, err := json.Marshal(perms); err == nil {
				redisClient.Set(c.Request.Context(), cacheKey, string(data), 5*time.Minute)
			}
		}

		c.Set("permissions", perms)
		c.Next()
	}
}

// RequirePermission checks that the user has a specific permission via their roles.
func RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permsRaw, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("missing permission: %s:%s", resource, action),
			})
			return
		}

		perms, ok := permsRaw.([]PermissionEntry)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid permissions format",
			})
			return
		}

		for _, p := range perms {
			if p.Resource == resource && p.Action == action {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("missing permission: %s:%s", resource, action),
		})
	}
}

// RateLimit implements a simple rate limiter
func RateLimit(requests int, window time.Duration) gin.HandlerFunc {
	type clientInfo struct {
		count     int
		resetTime time.Time
	}
	var mu sync.Mutex
	clients := make(map[string]*clientInfo)

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		mu.Lock()
		info, exists := clients[clientIP]
		if !exists || now.After(info.resetTime) {
			clients[clientIP] = &clientInfo{
				count:     1,
				resetTime: now.Add(window),
			}
			mu.Unlock()
			c.Next()
			return
		}

		if info.count >= requests {
			retryAfter := int(info.resetTime.Sub(now).Seconds())
			mu.Unlock()
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		info.count++
		mu.Unlock()
		c.Next()
	}
}

// Timeout adds a timeout to the request context
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		c.Next()

		if ctx.Err() == context.DeadlineExceeded && !c.Writer.Written() {
			c.JSON(http.StatusGatewayTimeout, gin.H{
				"error": "request timeout",
			})
		}
	}
}

// FetchJWKS fetches a JWKS from the given URL and returns the appropriate signing key for the token.
// This is used for verifying ID tokens from external identity providers.
func FetchJWKS(jwksURL string, token *jwt.Token) (interface{}, error) {
	// CRITICAL: Explicitly verify algorithm to prevent "none" algorithm attacks
	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "" {
		return nil, fmt.Errorf("token missing alg header")
	}
	// Only allow RS256 algorithm
	if alg != "RS256" {
		return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
	}
	// Verify signing method is RSA
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("token method is not RSA despite alg header")
	}

	kid, _ := token.Header["kid"].(string)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint %s returned status %d", jwksURL, resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue
		}
		return pubKey, nil
	}

	return nil, fmt.Errorf("no matching RSA signing key found in JWKS")
}

// Recovery returns a middleware that recovers from panics
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
			}
		}()
		c.Next()
	}
}
