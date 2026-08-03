// Package governance provides access governance and compliance functionality
package governance

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// AccessReview represents an access certification review
type AccessReview struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Type          ReviewType   `json:"type"`
	Status        ReviewStatus `json:"status"`
	ReviewerID    string       `json:"reviewer_id"`
	Scope         ReviewScope  `json:"scope"`
	StartDate     time.Time    `json:"start_date"`
	EndDate       time.Time    `json:"end_date"`
	CreatedAt     time.Time    `json:"created_at"`
	CompletedAt   *time.Time   `json:"completed_at,omitempty"`
	TotalItems    int          `json:"total_items"`
	ReviewedItems int          `json:"reviewed_items"`
}

// ReviewType defines the type of access review
type ReviewType string

const (
	ReviewTypeUserAccess        ReviewType = "user_access"
	ReviewTypeRoleAssignment    ReviewType = "role_assignment"
	ReviewTypeApplicationAccess ReviewType = "application_access"
	ReviewTypePrivilegedAccess  ReviewType = "privileged_access"
)

// ReviewStatus defines the status of an access review
type ReviewStatus string

const (
	ReviewStatusPending    ReviewStatus = "pending"
	ReviewStatusInProgress ReviewStatus = "in_progress"
	ReviewStatusCompleted  ReviewStatus = "completed"
	ReviewStatusExpired    ReviewStatus = "expired"
	ReviewStatusCanceled   ReviewStatus = "canceled"
)

// ReviewScope defines what's included in the review
type ReviewScope struct {
	Users        []string `json:"users,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// ReviewItem represents a single item to be reviewed
type ReviewItem struct {
	ID           string         `json:"id"`
	ReviewID     string         `json:"review_id"`
	UserID       string         `json:"user_id"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	ResourceName string         `json:"resource_name"`
	Decision     ReviewDecision `json:"decision"`
	DecidedBy    string         `json:"decided_by,omitempty"`
	DecidedAt    *time.Time     `json:"decided_at,omitempty"`
	Comments     string         `json:"comments,omitempty"`
}

// ReviewDecision represents the decision made on a review item
type ReviewDecision string

const (
	ReviewDecisionPending  ReviewDecision = "pending"
	ReviewDecisionApproved ReviewDecision = "approved"
	ReviewDecisionRevoked  ReviewDecision = "revoked"
	ReviewDecisionFlagged  ReviewDecision = "flagged"
)

// Policy represents an access policy
type Policy struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Type        PolicyType   `json:"type"`
	Rules       []PolicyRule `json:"rules"`
	Enabled     bool         `json:"enabled"`
	Priority    int          `json:"priority"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// PolicyType defines the type of policy
type PolicyType string

const (
	PolicyTypeSoD               PolicyType = "separation_of_duty"
	PolicyTypeRiskBased         PolicyType = "risk_based"
	PolicyTypeTimebound         PolicyType = "timebound"
	PolicyTypeLocation          PolicyType = "location"
	PolicyTypeConditionalAccess PolicyType = "conditional_access"
)

// PolicyRule defines a rule within a policy
type PolicyRule struct {
	ID        string                 `json:"id"`
	Condition map[string]interface{} `json:"condition"`
	Effect    string                 `json:"effect"`
	Priority  int                    `json:"priority"`
}

// Service provides governance operations
type Service struct {
	db       *database.PostgresDB
	redis    *database.RedisClient
	config   *config.Config
	logger   *zap.Logger
	vaultSvc *vault.Service

	jwksCacheMu     sync.RWMutex
	jwksCachedKey   *rsa.PublicKey
	jwksCacheExpiry time.Time
}

// SetVaultService injects the in-process vault used for JIT credential checkout.
func (s *Service) SetVaultService(v *vault.Service) { s.vaultSvc = v }

// NewService creates a new governance service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: logger.With(zap.String("service", "governance")),
	}
}

// openIDXAuthMiddleware validates OpenIDX OAuth JWT tokens for governance service
func (s *Service) openIDXAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Internal service-to-service path: the access-proxy authenticates its
		// policy /evaluate call with a shared secret instead of a user JWT.
		// Scoped to the evaluate endpoints (constant-time compare) so a leaked
		// token can't drive user-facing governance operations. The org is
		// resolved by the global TenantResolver (X-Org-ID / default fallback).
		if tok := s.config.InternalServiceToken; tok != "" &&
			strings.HasSuffix(c.Request.URL.Path, "/evaluate") &&
			subtle.ConstantTimeCompare([]byte(c.GetHeader("X-Internal-Token")), []byte(tok)) == 1 {
			c.Set("user_id", "svc:internal")
			c.Next()
			return
		}

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

		// Parse JWT token with signature validation
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// CRITICAL SECURITY: Explicitly verify RS256 algorithm to prevent algorithm confusion attacks
			// Checking for exact method prevents "none" algorithm bypass and other algorithm substitution attacks
			if token.Method != jwt.SigningMethodRS256 {
				s.logger.Warn("Invalid signing method", zap.String("expected", "RS256"), zap.Any("received", token.Header["alg"]))
				return nil, fmt.Errorf("invalid signing method: expected RS256, got %v", token.Header["alg"])
			}

			// Fetch the public key from OAuth service
			key, err := s.getOAuthPublicKey()
			if err != nil {
				s.logger.Error("Failed to get OAuth public key", zap.Error(err))
				return nil, err
			}
			return key, nil
		})

		if err != nil {
			s.logger.Warn("JWT parsing failed", zap.Error(err), zap.String("token_prefix", tokenString[:min(50, len(tokenString))]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
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

		// Validate issuer
		if iss, ok := claims["iss"].(string); ok {
			expectedIssuer := s.config.OAuthIssuer
			if expectedIssuer == "" {
				expectedIssuer = "http://localhost:8006"
			}
			if iss != expectedIssuer {
				s.logger.Warn("Invalid token issuer", zap.String("expected", expectedIssuer), zap.String("actual", iss))
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token issuer",
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

		c.Next()
	}
}

// getOAuthPublicKey fetches the OAuth service's public key for token validation
// with caching using a 5-minute TTL to avoid fetching on every request
func (s *Service) getOAuthPublicKey() (*rsa.PublicKey, error) {
	// Check cache with read lock
	s.jwksCacheMu.RLock()
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		key := s.jwksCachedKey
		s.jwksCacheMu.RUnlock()
		return key, nil
	}
	s.jwksCacheMu.RUnlock()

	// Cache miss: acquire write lock
	s.jwksCacheMu.Lock()
	defer s.jwksCacheMu.Unlock()

	// Double-check: another goroutine may have populated the cache
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		return s.jwksCachedKey, nil
	}

	jwksURL := s.config.OAuthJWKSURL
	if jwksURL == "" {
		jwksURL = "http://oauth-service:8006/.well-known/jwks.json"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	// Use the first RSA key
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			pubKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				return nil, err
			}
			s.jwksCachedKey = pubKey
			s.jwksCacheExpiry = time.Now().Add(5 * time.Minute)
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("no valid RSA signing keys found in JWKS")
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
// with strict security validation to prevent key confusion attacks
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	// SECURITY: Validate modulus bounds
	// Minimum 2048-bit key = 256 bytes, maximum 4096-bit = 512 bytes (reasonable upper bound)
	if len(nBytes) < 256 {
		return nil, fmt.Errorf("RSA key too small: %d bytes (minimum 2048 bits required)", len(nBytes)*8)
	}
	if len(nBytes) > 512 {
		return nil, fmt.Errorf("RSA key too large: %d bytes (maximum 4096 bits allowed)", len(nBytes)*8)
	}

	// SECURITY: Ensure modulus is odd and has the high bit set (valid RSA modulus)
	// The most significant bit must be 1 for proper RSA key formatting
	if nBytes[0]&0x80 == 0 {
		return nil, fmt.Errorf("invalid RSA modulus: high bit not set")
	}

	n := new(big.Int).SetBytes(nBytes)

	// SECURITY: Validate modulus is positive and odd (fundamental RSA requirements)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("invalid RSA modulus: must be positive")
	}
	// An RSA modulus is n = p*q, the product of two large primes — so it is
	// composite (never prime) and odd. The previous code ran ProbablyPrime(n)
	// here, which rejects EVERY valid RSA key and made all governance JWT
	// verification fail (401 on every endpoint). Validate oddness instead, which
	// is the actual invariant of a well-formed RSA modulus.
	if n.Bit(0) == 0 {
		return nil, fmt.Errorf("invalid RSA modulus: must be odd")
	}

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	// SECURITY: Validate exponent bounds and prevent overflow
	// Standard RSA exponents: 65537 (0x10001) is most common, 3 is also used
	// Maximum reasonable exponent is 2^31-1 to prevent integer overflow issues
	if len(eBytes) > 8 {
		return nil, fmt.Errorf("RSA exponent too large: %d bytes (maximum 8)", len(eBytes))
	}

	e := uint64(0)
	for _, b := range eBytes {
		e = e<<8 + uint64(b)
		// Check for overflow during accumulation
		if e > 0x7FFFFFFF {
			return nil, fmt.Errorf("RSA exponent overflow: value too large")
		}
	}

	// SECURITY: Validate exponent is within reasonable bounds
	// Minimum exponent is 3 (smallest valid RSA exponent)
	// Maximum is 2^31-1 (Fermat primes like 65537 are ideal)
	if e < 3 {
		return nil, fmt.Errorf("RSA exponent too small: %d (minimum 3)", e)
	}
	if e > 0x7FFFFFFF {
		return nil, fmt.Errorf("RSA exponent too large: %d (maximum 2^31-1)", e)
	}

	// SECURITY: Warn on non-standard exponents (65537 is the cryptographic standard)
	if e != 65537 && e != 3 {
		// Log warning but allow - some systems use other exponents
		// In production, this should be logged
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// CreateAccessReview creates a new access review campaign
func (s *Service) CreateAccessReview(ctx context.Context, review *AccessReview) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Creating access review", zap.String("name", review.Name))

	if review.ID == "" {
		review.ID = uuid.New().String()
	}
	now := time.Now()
	review.CreatedAt = now
	review.Status = ReviewStatusPending

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO access_reviews (id, name, description, type, status, reviewer_id,
		                           start_date, end_date, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, review.ID, review.Name, review.Description, review.Type, review.Status,
		review.ReviewerID, review.StartDate, review.EndDate, review.CreatedAt, org.ID)

	return err
}

// GetAccessReview retrieves an access review by ID
func (s *Service) GetAccessReview(ctx context.Context, reviewID string) (*AccessReview, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var review AccessReview
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, type, status, reviewer_id,
		       start_date, end_date, created_at, completed_at
		FROM access_reviews WHERE id = $1 AND org_id = $2
	`, reviewID, org.ID).Scan(
		&review.ID, &review.Name, &review.Description, &review.Type, &review.Status,
		&review.ReviewerID, &review.StartDate, &review.EndDate, &review.CreatedAt, &review.CompletedAt,
	)
	return &review, err
}

// ListAccessReviews retrieves all access reviews, optionally filtered by status
func (s *Service) ListAccessReviews(ctx context.Context, offset, limit int, status string) ([]AccessReview, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	var total int
	countArgs := []interface{}{org.ID}
	countQuery := "SELECT COUNT(*) FROM access_reviews WHERE org_id = $1"

	if status != "" {
		countQuery += " AND status = $2"
		countArgs = append(countArgs, status)
	}

	err = s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	baseQuery := `
		SELECT ar.id, ar.name, ar.description, ar.type, ar.status, ar.reviewer_id,
		       ar.start_date, ar.end_date, ar.created_at, ar.completed_at,
		       COUNT(ri.id) as total_items,
		       COUNT(CASE WHEN ri.decision != 'pending' THEN 1 END) as reviewed_items
		FROM access_reviews ar
		LEFT JOIN review_items ri ON ar.id = ri.review_id AND ri.org_id = ar.org_id
		WHERE ar.org_id = $1
	`

	args := []interface{}{org.ID}
	paramIdx := 2

	if status != "" {
		baseQuery += " AND ar.status = $" + strconv.Itoa(paramIdx)
		args = append(args, status)
		paramIdx++
	}

	baseQuery += `
		GROUP BY ar.id, ar.name, ar.description, ar.type, ar.status, ar.reviewer_id,
		         ar.start_date, ar.end_date, ar.created_at, ar.completed_at
		ORDER BY ar.created_at DESC
		OFFSET $` + strconv.Itoa(paramIdx) + ` LIMIT $` + strconv.Itoa(paramIdx+1)
	args = append(args, offset, limit)

	rows, err := s.db.Pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var reviews []AccessReview
	for rows.Next() {
		var r AccessReview
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Type, &r.Status,
			&r.ReviewerID, &r.StartDate, &r.EndDate, &r.CreatedAt, &r.CompletedAt,
			&r.TotalItems, &r.ReviewedItems,
		); err != nil {
			return nil, 0, err
		}
		reviews = append(reviews, r)
	}

	return reviews, total, nil
}

// SubmitReviewDecision submits a decision for a review item
func (s *Service) SubmitReviewDecision(ctx context.Context, itemID string, decision ReviewDecision, comments string, decidedBy string) error {
	s.logger.Info("Submitting review decision",
		zap.String("item_id", itemID),
		zap.String("decision", string(decision)))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	now := time.Now()

	// Recording the decision and enforcing it must be atomic: a review item
	// marked "revoked" while the user keeps the access is exactly the silent
	// hole access reviews exist to close. Wrap both in one transaction so a
	// failed revocation rolls the decision back instead of leaving it hollow.
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE review_items
		SET decision = $2, comments = $3, decided_by = $4, decided_at = $5
		WHERE id = $1 AND org_id = $6
	`, itemID, decision, comments, decidedBy, now, org.ID)
	if err != nil {
		return err
	}

	// Only enforce when a matching item was actually updated.
	var revokedUserID string
	if decision == ReviewDecisionRevoked && tag.RowsAffected() > 0 {
		revokedUserID, err = s.revokeReviewItemAccess(ctx, tx, itemID, org.ID, decidedBy)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Redis is not transactional with Postgres, so invalidate the revoked user's
	// sessions only after the revocation has committed.
	if revokedUserID != "" {
		s.killUserSessions(ctx, revokedUserID)
	}
	return nil
}

// revokeReviewItemAccess removes the underlying access a review item points at,
// running inside the caller's transaction, and records a governance audit event
// for the revocation in the same transaction so the trail commits atomically
// with the change. Shared by the single- and batch-decision paths so a
// "revoked" decision always removes access and is always audited. It returns the
// affected user's id (empty when the item has no concrete (user, resource)
// target) so the caller can invalidate that user's sessions after commit.
func (s *Service) revokeReviewItemAccess(ctx context.Context, tx pgx.Tx, itemID, orgID, decidedBy string) (string, error) {
	var resourceType string
	var userID, resourceID *string
	if err := tx.QueryRow(ctx, `
		SELECT resource_type, user_id, resource_id FROM review_items WHERE id = $1 AND org_id = $2
	`, itemID, orgID).Scan(&resourceType, &userID, &resourceID); err != nil {
		return "", fmt.Errorf("load review item %s for revocation: %w", itemID, err)
	}
	if userID == nil || resourceID == nil {
		return "", nil
	}
	if err := revokeResourceAssignment(ctx, tx, resourceType, *userID, *resourceID, orgID); err != nil {
		return "", fmt.Errorf("revoke access for review item %s: %w", itemID, err)
	}

	// Hand a circuit-severance intent to the access-service so this revoke also
	// severs the user's live overlay circuits (Wave B2). Best-effort; the DB
	// removal above + attribute reconcile already deny new dials.
	s.enqueueNetworkRevocation(ctx, *userID, orgID, "access_review")

	// Audit the revocation in the same transaction: if the revoke rolls back, so
	// does its audit row. actor = the reviewer, target = the affected user.
	details, _ := json.Marshal(map[string]any{
		"review_item_id": itemID,
		"resource_type":  resourceType,
		"resource_id":    *resourceID,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
		VALUES (gen_random_uuid(), 'access', 'governance', 'access_review.revoked', 'success', $1, '0.0.0.0', $2, 'user', $3, NOW(), $4)
	`, decidedBy, *userID, string(details), orgID); err != nil {
		return "", fmt.Errorf("audit access-review revocation for item %s: %w", itemID, err)
	}

	return *userID, nil
}

// killUserSessions forces a user to re-authenticate by setting the user-wide
// token-revocation marker the auth middleware checks, so a live session cannot
// keep using access an access review just revoked. Best-effort: the revocation
// has already committed, so a Redis hiccup must not fail the request. Guards a
// missing Redis (e.g. in tests) rather than panicking.
func (s *Service) killUserSessions(ctx context.Context, userID string) {
	if s.redis == nil || s.redis.Client == nil {
		return
	}
	if err := s.redis.Client.Set(ctx, auth.UserRevocationKey(userID), time.Now().Unix(), 24*time.Hour).Err(); err != nil {
		s.logger.Warn("failed to invalidate sessions after access-review revocation",
			zap.String("user_id", userID), zap.Error(err))
	}
}

// CreatePolicy creates a new policy
func (s *Service) CreatePolicy(ctx context.Context, policy *Policy) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Creating policy", zap.String("name", policy.Name))

	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO policies (id, name, description, type, enabled, priority, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, policy.ID, policy.Name, policy.Description, policy.Type, policy.Enabled,
		policy.Priority, policy.CreatedAt, policy.UpdatedAt, org.ID)
	if err != nil {
		return err
	}

	// Persist policy rules
	for _, rule := range policy.Rules {
		if rule.ID == "" {
			rule.ID = uuid.New().String()
		}
		ruleCondition, _ := json.Marshal(rule.Condition)
		ruleActions, _ := json.Marshal(map[string]interface{}{"effect": rule.Effect, "priority": rule.Priority})
		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO policy_rules (id, policy_id, rule_type, conditions, actions, created_at, org_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, rule.ID, policy.ID, rule.Effect, ruleCondition, ruleActions, time.Now(), org.ID)
		if err != nil {
			s.logger.Error("Failed to insert policy rule", zap.Error(err))
		}
	}

	return nil
}

// GetPolicy retrieves a policy by ID
func (s *Service) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var policy Policy
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, type, enabled, priority, created_at, updated_at
		FROM policies WHERE id = $1 AND org_id = $2
	`, policyID, org.ID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Type,
		&policy.Enabled, &policy.Priority, &policy.CreatedAt, &policy.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	// Load the policy's rules — without this policy.Rules is empty and every
	// EvaluatePolicy silently returns "allow" (the evaluators loop over no rules).
	rules, rerr := s.loadPolicyRules(ctx, policy.ID, org.ID)
	if rerr != nil {
		s.logger.Warn("Failed to load rules for policy", zap.String("policy_id", policy.ID), zap.Error(rerr))
	}
	policy.Rules = rules
	return &policy, nil
}

// loadPolicyRules loads a policy's rules, mapping the on-disk schema
// (rule_type, conditions, actions) back onto the PolicyRule the evaluators
// expect. The write side (CreatePolicy/UpdatePolicy) stores rule.Effect in
// rule_type, rule.Condition in the conditions JSONB, and {effect, priority} in
// the actions JSONB — so we read them back from exactly there. Shared by
// GetPolicy and ListPolicies so the evaluators always see the rules.
func (s *Service) loadPolicyRules(ctx context.Context, policyID, orgID string) ([]PolicyRule, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, rule_type, conditions, actions
		FROM policy_rules
		WHERE policy_id = $1 AND org_id = $2
		ORDER BY (actions->>'priority')::int DESC NULLS LAST, created_at
	`, policyID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PolicyRule
	for rows.Next() {
		var rule PolicyRule
		var ruleType string
		var conditionJSON, actionsJSON []byte
		if err := rows.Scan(&rule.ID, &ruleType, &conditionJSON, &actionsJSON); err != nil {
			s.logger.Warn("Failed to scan policy rule", zap.Error(err))
			continue
		}
		if len(conditionJSON) > 0 {
			if err := json.Unmarshal(conditionJSON, &rule.Condition); err != nil {
				s.logger.Warn("Failed to parse rule condition", zap.String("rule_id", rule.ID), zap.Error(err))
			}
		}
		// rule_type carries the effect; the actions JSONB carries the canonical
		// {effect, priority} the write side persisted. Prefer actions.effect
		// when present, else fall back to rule_type.
		rule.Effect = ruleType
		if len(actionsJSON) > 0 {
			var actions struct {
				Effect   string `json:"effect"`
				Priority int    `json:"priority"`
			}
			if err := json.Unmarshal(actionsJSON, &actions); err != nil {
				s.logger.Warn("Failed to parse rule actions", zap.String("rule_id", rule.ID), zap.Error(err))
			} else {
				if actions.Effect != "" {
					rule.Effect = actions.Effect
				}
				rule.Priority = actions.Priority
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ListPolicies retrieves all policies
func (s *Service) ListPolicies(ctx context.Context, offset, limit int) ([]Policy, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	var total int
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM policies WHERE org_id = $1", org.ID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, type, enabled, priority, created_at, updated_at
		FROM policies
		WHERE org_id = $1
		ORDER BY priority DESC, created_at DESC
		OFFSET $2 LIMIT $3
	`, org.ID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Type,
			&p.Enabled, &p.Priority, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		policies = append(policies, p)
	}

	// Load rules for each policy (shared with GetPolicy).
	for i := range policies {
		rules, err := s.loadPolicyRules(ctx, policies[i].ID, org.ID)
		if err != nil {
			s.logger.Warn("Failed to load rules for policy", zap.String("policy_id", policies[i].ID), zap.Error(err))
			continue
		}
		policies[i].Rules = rules
	}

	return policies, total, nil
}

// UpdatePolicy updates an existing policy
func (s *Service) UpdatePolicy(ctx context.Context, policyID string, policy *Policy) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Updating policy", zap.String("policy_id", policyID))

	now := time.Now()
	policy.UpdatedAt = now

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE policies
		SET name = $2, description = $3, type = $4, enabled = $5, priority = $6, updated_at = $7
		WHERE id = $1 AND org_id = $8
	`, policyID, policy.Name, policy.Description, policy.Type, policy.Enabled, policy.Priority, now, org.ID)
	if err != nil {
		return err
	}

	// Delete old rules and re-insert new ones
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM policy_rules WHERE policy_id = $1 AND org_id = $2", policyID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to delete old policy rules: %w", err)
	}
	for _, rule := range policy.Rules {
		if rule.ID == "" {
			rule.ID = uuid.New().String()
		}
		ruleCondition, _ := json.Marshal(rule.Condition)
		ruleActions, _ := json.Marshal(map[string]interface{}{"effect": rule.Effect, "priority": rule.Priority})
		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO policy_rules (id, policy_id, rule_type, conditions, actions, created_at, org_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, rule.ID, policyID, rule.Effect, ruleCondition, ruleActions, time.Now(), org.ID)
		if err != nil {
			s.logger.Error("Failed to insert policy rule", zap.Error(err))
		}
	}

	return nil
}

// DeletePolicy deletes a policy
func (s *Service) DeletePolicy(ctx context.Context, policyID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Deleting policy", zap.String("policy_id", policyID))

	// Delete associated rules first
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM policy_rules WHERE policy_id = $1 AND org_id = $2", policyID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to delete policy rules: %w", err)
	}
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM policies WHERE id = $1 AND org_id = $2", policyID, org.ID)
	return err
}

// EvaluatePolicy evaluates a policy against a request
func (s *Service) EvaluatePolicy(ctx context.Context, policyID string, request map[string]interface{}) (bool, error) {
	s.logger.Debug("Evaluating policy", zap.String("policy_id", policyID))

	// Get the policy
	policy, err := s.GetPolicy(ctx, policyID)
	if err != nil {
		return false, err
	}

	// If policy is disabled, allow by default
	if !policy.Enabled {
		return true, nil
	}

	// Basic rule evaluation based on policy type
	switch policy.Type {
	case PolicyTypeSoD:
		// Separation of Duty: check if user has conflicting roles
		return s.evaluateSoDPolicy(ctx, policy, request)
	case PolicyTypeTimebound:
		// Timebound: check if current time is within allowed window
		return s.evaluateTimeboundPolicy(ctx, policy, request)
	case PolicyTypeLocation:
		// Location-based: check if request IP is from allowed location
		return s.evaluateLocationPolicy(ctx, policy, request)
	case PolicyTypeRiskBased:
		// Risk-based: evaluate risk score
		return s.evaluateRiskBasedPolicy(ctx, policy, request)
	case PolicyTypeConditionalAccess:
		// Conditional access: device trust, geo-fencing, step-up auth
		return s.evaluateConditionalAccessPolicy(ctx, policy, request)
	default:
		return true, nil
	}
}

func (s *Service) evaluateSoDPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Get user roles from request
	userRoles, ok := request["roles"].([]interface{})
	if !ok {
		return true, nil // No roles to check
	}

	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		if role, ok := r.(string); ok {
			roleSet[strings.ToLower(role)] = true
		}
	}

	// Check conflict pairs from policy rules (data-driven)
	for _, rule := range policy.Rules {
		conflicting, ok := rule.Condition["conflicting_roles"]
		if !ok {
			continue
		}
		conflictList, ok := conflicting.([]interface{})
		if !ok || len(conflictList) < 2 {
			continue
		}
		allPresent := true
		var conflictNames []string
		for _, cr := range conflictList {
			roleName, ok := cr.(string)
			if !ok {
				allPresent = false
				break
			}
			conflictNames = append(conflictNames, roleName)
			if !roleSet[strings.ToLower(roleName)] {
				allPresent = false
				break
			}
		}
		if allPresent {
			s.logger.Warn("SoD policy violation detected",
				zap.String("policy_id", policy.ID),
				zap.Strings("conflicting_roles", conflictNames))
			return false, nil
		}
	}

	return true, nil
}

func (s *Service) evaluateTimeboundPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	now := time.Now()
	hour := now.Hour()
	weekday := now.Weekday()

	// Defaults
	startHour := 9
	endHour := 18
	allowedDays := map[time.Weekday]bool{
		time.Monday: true, time.Tuesday: true, time.Wednesday: true,
		time.Thursday: true, time.Friday: true,
	}

	// Parse from policy rules if available
	for _, rule := range policy.Rules {
		if sh, ok := rule.Condition["start_hour"].(float64); ok {
			startHour = int(sh)
		}
		if eh, ok := rule.Condition["end_hour"].(float64); ok {
			endHour = int(eh)
		}
		if days, ok := rule.Condition["allowed_days"].([]interface{}); ok {
			allowedDays = map[time.Weekday]bool{}
			for _, d := range days {
				if dayStr, ok := d.(string); ok {
					switch strings.ToLower(dayStr) {
					case "monday":
						allowedDays[time.Monday] = true
					case "tuesday":
						allowedDays[time.Tuesday] = true
					case "wednesday":
						allowedDays[time.Wednesday] = true
					case "thursday":
						allowedDays[time.Thursday] = true
					case "friday":
						allowedDays[time.Friday] = true
					case "saturday":
						allowedDays[time.Saturday] = true
					case "sunday":
						allowedDays[time.Sunday] = true
					}
				}
			}
		}
	}

	// Day check
	if !allowedDays[weekday] {
		s.logger.Info("Timebound policy: access outside allowed days",
			zap.String("policy_id", policy.ID))
		return false, nil
	}

	// Business hours check
	if hour < startHour || hour >= endHour {
		s.logger.Info("Timebound policy: access outside business hours",
			zap.String("policy_id", policy.ID))
		return false, nil
	}

	return true, nil
}

func (s *Service) evaluateLocationPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Check if IP is from allowed locations
	ip, ok := request["ip"].(string)
	if !ok {
		return true, nil // No IP to check
	}

	// Parse allowed IP prefixes from policy rules, fall back to private ranges
	allowedPrefixes := []string{}
	for _, rule := range policy.Rules {
		if prefixes, ok := rule.Condition["allowed_ip_prefixes"].([]interface{}); ok {
			for _, p := range prefixes {
				if prefix, ok := p.(string); ok {
					allowedPrefixes = append(allowedPrefixes, prefix)
				}
			}
		}
	}
	if len(allowedPrefixes) == 0 {
		allowedPrefixes = []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"}
	}

	for _, prefix := range allowedPrefixes {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true, nil
		}
	}

	s.logger.Warn("Location policy: access from unauthorized IP",
		zap.String("policy_id", policy.ID),
		zap.String("ip", ip))
	return false, nil
}

func (s *Service) evaluateRiskBasedPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	// Calculate risk score based on various factors
	riskScore := 0

	// Check for new device
	if isNewDevice, ok := request["is_new_device"].(bool); ok && isNewDevice {
		riskScore += 30
	}

	// Check for unusual location
	if isUnusualLocation, ok := request["is_unusual_location"].(bool); ok && isUnusualLocation {
		riskScore += 25
	}

	// Check for failed attempts
	if failedAttempts, ok := request["failed_attempts"].(float64); ok {
		riskScore += int(failedAttempts) * 10
	}

	// Parse threshold from policy rules, fall back to 50
	threshold := 50
	for _, rule := range policy.Rules {
		if t, ok := rule.Condition["risk_threshold"].(float64); ok {
			threshold = int(t)
			break
		}
	}
	if riskScore >= threshold {
		s.logger.Warn("Risk-based policy: high risk score",
			zap.String("policy_id", policy.ID),
			zap.Int("risk_score", riskScore),
			zap.Int("threshold", threshold))
		return false, nil
	}

	return true, nil
}

func (s *Service) evaluateConditionalAccessPolicy(ctx context.Context, policy *Policy, request map[string]interface{}) (bool, error) {
	for _, rule := range policy.Rules {
		// Check require_mfa condition
		if requireMFA, ok := rule.Condition["require_mfa"].(bool); ok && requireMFA {
			authMethods, _ := request["auth_methods"].([]interface{})
			hasMFA := false
			for _, m := range authMethods {
				if method, ok := m.(string); ok && (method == "totp" || method == "step_up_mfa" || method == "webauthn") {
					hasMFA = true
					break
				}
			}
			if !hasMFA {
				s.logger.Warn("Conditional access: MFA required but not present",
					zap.String("policy_id", policy.ID))
				return false, nil
			}
		}

		// Check device_trust_required condition
		if deviceTrustRequired, ok := rule.Condition["device_trust_required"].(bool); ok && deviceTrustRequired {
			deviceTrusted, _ := request["device_trusted"].(bool)
			if !deviceTrusted {
				s.logger.Warn("Conditional access: trusted device required",
					zap.String("policy_id", policy.ID))
				return false, nil
			}
		}

		// Check allowed_locations condition (country codes)
		if allowedStr, ok := rule.Condition["allowed_locations"].(string); ok && allowedStr != "" {
			location, _ := request["location"].(string)
			allowed := false
			for _, loc := range strings.Split(allowedStr, ",") {
				loc = strings.TrimSpace(loc)
				if strings.Contains(strings.ToUpper(location), strings.ToUpper(loc)) {
					allowed = true
					break
				}
			}
			if !allowed {
				s.logger.Warn("Conditional access: location not allowed",
					zap.String("policy_id", policy.ID),
					zap.String("location", location))
				return false, nil
			}
		}

		// Check blocked_locations condition (country codes)
		if blockedStr, ok := rule.Condition["blocked_locations"].(string); ok && blockedStr != "" {
			location, _ := request["location"].(string)
			for _, loc := range strings.Split(blockedStr, ",") {
				loc = strings.TrimSpace(loc)
				if strings.Contains(strings.ToUpper(location), strings.ToUpper(loc)) {
					s.logger.Warn("Conditional access: location blocked",
						zap.String("policy_id", policy.ID),
						zap.String("location", location))
					return false, nil
				}
			}
		}

		// Check max_risk_score condition
		if maxScoreStr, ok := rule.Condition["max_risk_score"].(string); ok && maxScoreStr != "" {
			maxScore := 100
			fmt.Sscanf(maxScoreStr, "%d", &maxScore)
			riskScore := 0
			if rs, ok := request["risk_score"].(float64); ok {
				riskScore = int(rs)
			}
			if riskScore > maxScore {
				s.logger.Warn("Conditional access: risk score too high",
					zap.String("policy_id", policy.ID),
					zap.Int("risk_score", riskScore),
					zap.Int("max_allowed", maxScore))
				return false, nil
			}
		}

		// Check effect — if step_up_mfa, check if step-up has been done
		if rule.Effect == "step_up_mfa" {
			authMethods, _ := request["auth_methods"].([]interface{})
			hasStepUp := false
			for _, m := range authMethods {
				if method, ok := m.(string); ok && method == "step_up_mfa" {
					hasStepUp = true
					break
				}
			}
			if !hasStepUp {
				s.logger.Info("Conditional access: step-up MFA required",
					zap.String("policy_id", policy.ID))
				return false, nil
			}
		}
	}

	return true, nil
}

// UpdateAccessReview updates an existing access review
func (s *Service) UpdateAccessReview(ctx context.Context, reviewID string, update *AccessReview) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Updating access review", zap.String("review_id", reviewID))

	// Check if review exists and is not completed
	existing, err := s.GetAccessReview(ctx, reviewID)
	if err != nil {
		return err
	}

	if existing.Status == ReviewStatusCompleted {
		return ErrReviewCompleted
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE access_reviews
		SET name = $2, description = $3, start_date = $4, end_date = $5
		WHERE id = $1 AND org_id = $6
	`, reviewID, update.Name, update.Description, update.StartDate, update.EndDate, org.ID)

	return err
}

// UpdateReviewStatus updates the status of an access review
func (s *Service) UpdateReviewStatus(ctx context.Context, reviewID string, newStatus ReviewStatus) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Updating review status",
		zap.String("review_id", reviewID),
		zap.String("new_status", string(newStatus)))

	// Get current review
	review, err := s.GetAccessReview(ctx, reviewID)
	if err != nil {
		return err
	}

	// Validate status transition
	if !isValidStatusTransition(review.Status, newStatus) {
		return ErrInvalidStatusTransition
	}

	// Start transaction
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Update status
	var completedAt *time.Time
	if newStatus == ReviewStatusCompleted {
		now := time.Now()
		completedAt = &now
	}

	_, err = tx.Exec(ctx, `
		UPDATE access_reviews
		SET status = $2, completed_at = $3
		WHERE id = $1 AND org_id = $4
	`, reviewID, newStatus, completedAt, org.ID)
	if err != nil {
		return err
	}

	// If starting review, populate review items
	if newStatus == ReviewStatusInProgress && review.Status == ReviewStatusPending {
		if err := s.populateReviewItems(ctx, tx, review); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// ListReviewItems returns the items for a specific review
func (s *Service) ListReviewItems(ctx context.Context, reviewID string, offset, limit int, decisionFilter string) ([]ReviewItem, int, error) {
	s.logger.Debug("Listing review items", zap.String("review_id", reviewID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Build query based on filter
	baseQuery := `
		SELECT ri.id, ri.review_id, ri.user_id, ri.resource_type, ri.resource_id,
		       COALESCE(ri.resource_name, ''), ri.decision,
		       COALESCE(ri.decided_by::text, ''), ri.decided_at, COALESCE(ri.comments, ''),
		       COALESCE(u.first_name || ' ' || u.last_name, u.username, '') as user_name,
		       COALESCE(u.email, '') as user_email
		FROM review_items ri
		LEFT JOIN users u ON ri.user_id = u.id AND u.org_id = ri.org_id
		WHERE ri.review_id = $1 AND ri.org_id = $2
	`
	countQuery := "SELECT COUNT(*) FROM review_items WHERE review_id = $1 AND org_id = $2"

	args := []interface{}{reviewID, org.ID}
	countArgs := []interface{}{reviewID, org.ID}

	if decisionFilter != "" {
		baseQuery += " AND ri.decision = $3"
		countQuery += " AND decision = $3"
		args = append(args, decisionFilter)
		countArgs = append(countArgs, decisionFilter)
	}

	baseQuery += " ORDER BY ri.created_at DESC OFFSET $" + strconv.Itoa(len(args)+1) + " LIMIT $" + strconv.Itoa(len(args)+2)
	args = append(args, offset, limit)

	// Get total count
	var total int
	err = s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get items
	rows, err := s.db.Pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []ReviewItem
	for rows.Next() {
		var item ReviewItem
		var userName, userEmail string
		if err := rows.Scan(
			&item.ID, &item.ReviewID, &item.UserID, &item.ResourceType, &item.ResourceID,
			&item.ResourceName, &item.Decision, &item.DecidedBy, &item.DecidedAt, &item.Comments,
			&userName, &userEmail,
		); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}

	return items, total, nil
}

// BatchSubmitDecisions submits decisions for multiple review items
func (s *Service) BatchSubmitDecisions(ctx context.Context, reviewID string, itemIDs []string, decision ReviewDecision, comments string, decidedBy string) error {
	s.logger.Info("Batch submitting decisions",
		zap.String("review_id", reviewID),
		zap.Int("item_count", len(itemIDs)),
		zap.String("decision", string(decision)))

	if len(itemIDs) == 0 {
		return nil
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	now := time.Now()

	// Use a transaction for batch update
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Update each item, and for revocations remove the underlying access in the
	// same transaction — otherwise a batch "revoke" only relabels rows.
	var revokedUserIDs []string
	for _, itemID := range itemIDs {
		tag, err := tx.Exec(ctx, `
			UPDATE review_items
			SET decision = $2, comments = $3, decided_by = $4, decided_at = $5
			WHERE id = $1 AND review_id = $6 AND org_id = $7
		`, itemID, decision, comments, decidedBy, now, reviewID, org.ID)
		if err != nil {
			return err
		}
		if decision == ReviewDecisionRevoked && tag.RowsAffected() > 0 {
			uid, err := s.revokeReviewItemAccess(ctx, tx, itemID, org.ID, decidedBy)
			if err != nil {
				return err
			}
			if uid != "" {
				revokedUserIDs = append(revokedUserIDs, uid)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Invalidate revoked users' sessions after the batch has committed.
	for _, uid := range revokedUserIDs {
		s.killUserSessions(ctx, uid)
	}
	return nil
}

// populateReviewItems generates review items when a review is started
func (s *Service) populateReviewItems(ctx context.Context, tx pgx.Tx, review *AccessReview) error {
	s.logger.Info("Populating review items", zap.String("review_id", review.ID))

	switch review.Type {
	case ReviewTypeUserAccess:
		// Get all users and their role assignments
		return s.populateUserAccessItems(ctx, tx, review.ID)
	case ReviewTypeRoleAssignment:
		// Get all role assignments
		return s.populateRoleAssignmentItems(ctx, tx, review.ID)
	case ReviewTypeApplicationAccess:
		// Get all application access
		return s.populateApplicationAccessItems(ctx, tx, review.ID)
	case ReviewTypePrivilegedAccess:
		// Get privileged role assignments (admin, etc.)
		return s.populatePrivilegedAccessItems(ctx, tx, review.ID)
	default:
		return nil
	}
}

func (s *Service) populateUserAccessItems(ctx context.Context, tx pgx.Tx, reviewID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Get all user-role assignments
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ur.user_id, r.id as role_id, r.name as role_name
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		JOIN users u ON ur.user_id = u.id
		WHERE u.enabled = true AND u.org_id = $1 AND ur.org_id = $1 AND r.org_id = $1
	`, org.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, roleID, roleName string
		if err := rows.Scan(&userID, &roleID, &roleName); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision, org_id)
			VALUES (gen_random_uuid(), $1, $2, 'role', $3, $4, 'pending', $5)
		`, reviewID, userID, roleID, roleName, org.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) populateRoleAssignmentItems(ctx context.Context, tx pgx.Tx, reviewID string) error {
	// Same as user access for now
	return s.populateUserAccessItems(ctx, tx, reviewID)
}

func (s *Service) populateApplicationAccessItems(ctx context.Context, tx pgx.Tx, reviewID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Get all users with their group memberships (groups often map to app access)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT gm.user_id, g.id as group_id, g.name as group_name
		FROM group_memberships gm
		JOIN groups g ON gm.group_id = g.id
		JOIN users u ON gm.user_id = u.id
		WHERE u.enabled = true AND u.org_id = $1 AND gm.org_id = $1 AND g.org_id = $1
	`, org.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, groupID, groupName string
		if err := rows.Scan(&userID, &groupID, &groupName); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision, org_id)
			VALUES (gen_random_uuid(), $1, $2, 'group', $3, $4, 'pending', $5)
		`, reviewID, userID, groupID, groupName, org.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) populatePrivilegedAccessItems(ctx context.Context, tx pgx.Tx, reviewID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Get privileged role assignments (admin, manager, etc.)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ur.user_id, r.id as role_id, r.name as role_name
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		JOIN users u ON ur.user_id = u.id
		WHERE u.enabled = true
		AND r.name IN ('admin', 'manager', 'auditor')
		AND u.org_id = $1 AND ur.org_id = $1 AND r.org_id = $1
	`, org.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, roleID, roleName string
		if err := rows.Scan(&userID, &roleID, &roleName); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO review_items (id, review_id, user_id, resource_type, resource_id, resource_name, decision, org_id)
			VALUES (gen_random_uuid(), $1, $2, 'privileged_role', $3, $4, 'pending', $5)
		`, reviewID, userID, roleID, roleName, org.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func isValidStatusTransition(current, next ReviewStatus) bool {
	transitions := map[ReviewStatus][]ReviewStatus{
		ReviewStatusPending:    {ReviewStatusInProgress, ReviewStatusCanceled},
		ReviewStatusInProgress: {ReviewStatusCompleted, ReviewStatusCanceled},
		ReviewStatusCompleted:  {},
		ReviewStatusExpired:    {},
		ReviewStatusCanceled:   {},
	}

	allowed, ok := transitions[current]
	if !ok {
		return false
	}

	for _, s := range allowed {
		if s == next {
			return true
		}
	}
	return false
}

// Custom errors
var (
	ErrReviewCompleted         = &ServiceError{Message: "cannot modify completed review"}
	ErrInvalidStatusTransition = &ServiceError{Message: "invalid status transition"}
)

type ServiceError struct {
	Message string
}

func (e *ServiceError) Error() string {
	return e.Message
}

// RegisterRoutes registers governance service routes
func RegisterRoutes(router *gin.Engine, svc *Service, extraMiddleware ...gin.HandlerFunc) {
	gov := router.Group("/api/v1/governance")
	gov.Use(svc.openIDXAuthMiddleware())
	for _, mw := range extraMiddleware {
		gov.Use(mw)
	}
	{
		// Access reviews
		gov.GET("/reviews", svc.handleListReviews)
		gov.POST("/reviews", svc.handleCreateReview)
		gov.GET("/reviews/:id", svc.handleGetReview)
		gov.PUT("/reviews/:id", svc.handleUpdateReview)
		gov.PATCH("/reviews/:id/status", svc.handleUpdateReviewStatus)
		gov.GET("/reviews/:id/items", svc.handleListReviewItems)
		gov.POST("/reviews/:id/items/:itemId/decision", svc.handleSubmitDecision)
		gov.POST("/reviews/:id/items/batch-decision", svc.handleBatchDecision)

		// Policies
		gov.GET("/policies", svc.handleListPolicies)
		gov.POST("/policies", svc.handleCreatePolicy)
		gov.GET("/policies/:id", svc.handleGetPolicy)
		gov.PUT("/policies/:id", svc.handleUpdatePolicy)
		gov.DELETE("/policies/:id", svc.handleDeletePolicy)
		gov.POST("/policies/:id/evaluate", svc.handleEvaluatePolicy)

		// Detective segregation-of-duties: sweep existing assignments for toxic
		// combinations and manage the violation register (dashboard). The
		// preventive control (evaluateSoDPolicy) blocks new grants; this finds
		// what already exists.
		gov.POST("/sod/sweep", svc.handleRunSoDSweep)
		gov.GET("/sod/violations", svc.handleListSoDViolations)
		gov.POST("/sod/violations/:id/status", svc.handleUpdateSoDViolationStatus)
		gov.GET("/sod/statistics", svc.handleSoDStatistics)

		// Privileged-account discovery: sweep the identity store for the
		// privileged population (standing admin grants, privileged groups,
		// service accounts, dormant privileged accounts) and track each to
		// onboarding. The discovery substrate for PAM/JIT.
		gov.POST("/privileged-accounts/scan", svc.handleRunPrivilegedDiscovery)
		gov.GET("/privileged-accounts", svc.handleListPrivilegedAccounts)
		gov.GET("/privileged-accounts/statistics", svc.handlePrivilegedStatistics)
		gov.POST("/privileged-accounts/:id/status", svc.handleUpdatePrivilegedAccountStatus)

		// Entitlement warehouse: one "who has access to what" surface unioning
		// every entitlement source, with orphaned-entitlement detection (owner
		// disabled/missing). The access-certification substrate.
		gov.POST("/entitlements/rebuild", svc.handleRebuildEntitlements)
		gov.GET("/entitlements", svc.handleListEntitlements)
		gov.GET("/entitlements/orphans", svc.handleListOrphanedEntitlements)
		gov.GET("/entitlements/statistics", svc.handleEntitlementStatistics)

		// Access request workflows
		gov.GET("/requests", svc.handleListAccessRequests)
		gov.POST("/requests", svc.handleCreateAccessRequest)
		gov.GET("/requests/:id", svc.handleGetAccessRequest)
		gov.POST("/requests/:id/approve", svc.handleApproveRequest)
		gov.POST("/requests/:id/deny", svc.handleDenyRequest)
		gov.POST("/requests/:id/cancel", svc.handleCancelRequest)
		gov.POST("/requests/:id/credential", svc.handleRetrieveCredential)
		gov.POST("/requests/:id/return", svc.handleReturnCredential)
		gov.GET("/my-approvals", svc.handleListPendingApprovals)

		// Approval policies
		gov.GET("/approval-policies", svc.handleListApprovalPolicies)
		gov.POST("/approval-policies", svc.handleCreateApprovalPolicy)
		gov.PUT("/approval-policies/:id", svc.handleUpdateApprovalPolicy)
		gov.DELETE("/approval-policies/:id", svc.handleDeleteApprovalPolicy)

		// Certification campaigns
		gov.GET("/campaigns", svc.handleListCampaigns)
		gov.POST("/campaigns", svc.handleCreateCampaign)
		gov.GET("/campaigns/:id", svc.handleGetCampaign)
		gov.PUT("/campaigns/:id", svc.handleUpdateCampaign)
		gov.DELETE("/campaigns/:id", svc.handleDeleteCampaign)
		gov.POST("/campaigns/:id/run", svc.handleRunCampaign)
		gov.GET("/campaigns/:id/runs", svc.handleGetCampaignRuns)

		// ABAC Policies
		gov.GET("/abac-policies", svc.handleListABACPolicies)
		gov.POST("/abac-policies", svc.handleCreateABACPolicy)
		gov.GET("/abac-policies/:id", svc.handleGetABACPolicy)
		gov.PUT("/abac-policies/:id", svc.handleUpdateABACPolicy)
		gov.DELETE("/abac-policies/:id", svc.handleDeleteABACPolicy)
		gov.POST("/abac-policies/evaluate", svc.handleEvaluateABACPolicies)
	}
}

// HTTP Handlers

func (s *Service) handleListReviews(c *gin.Context) {
	status := c.Query("status")

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

	reviews, total, err := s.ListAccessReviews(c.Request.Context(), offset, limit, status)
	if err != nil {
		s.logger.Error("failed to list access reviews", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, reviews)
}

func (s *Service) handleCreateReview(c *gin.Context) {
	var review AccessReview
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.CreateAccessReview(c.Request.Context(), &review); err != nil {
		s.logger.Error("failed to create access review", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, review)
}

func (s *Service) handleGetReview(c *gin.Context) {
	review, err := s.GetAccessReview(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "review not found"})
		return
	}
	c.JSON(200, review)
}

func (s *Service) handleUpdateReview(c *gin.Context) {
	var review AccessReview
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateAccessReview(c.Request.Context(), c.Param("id"), &review); err != nil {
		if err == ErrReviewCompleted {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("failed to update access review", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, review)
}

func (s *Service) handleUpdateReviewStatus(c *gin.Context) {
	var req struct {
		Status ReviewStatus `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateReviewStatus(c.Request.Context(), c.Param("id"), req.Status); err != nil {
		if err == ErrInvalidStatusTransition {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("failed to update review status", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	// Return updated review
	review, _ := s.GetAccessReview(c.Request.Context(), c.Param("id"))
	c.JSON(200, review)
}

func (s *Service) handleListReviewItems(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	decisionFilter := c.Query("decision")

	items, total, err := s.ListReviewItems(c.Request.Context(), c.Param("id"), offset, limit, decisionFilter)
	if err != nil {
		s.logger.Error("failed to list review items", zap.String("review_id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, items)
}

// authorizeReviewDecision enforces that the caller may decide items in the
// given access review. Access reviews are a SOX/ISO detective control: only the
// ASSIGNED reviewer (access_reviews.reviewer_id) or an administrator may record
// or override a decision. The governance route group is authenticated but not
// admin-gated, so without this check any authenticated org user could approve or
// revoke any review item (self-approve their own access, or silently rubber-stamp
// someone else's certification). Returns true if authorized; otherwise it writes
// the HTTP error and returns false.
func (s *Service) authorizeReviewDecision(c *gin.Context, reviewID string) bool {
	if isAdmin, _ := auth.HasRoleInContext(c, auth.RoleAdmin); isAdmin {
		return true
	}
	userID, _ := c.Get("user_id")
	callerID, _ := userID.(string)
	if callerID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return false
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return false
	}

	var reviewerID string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COALESCE(reviewer_id::text, '') FROM access_reviews WHERE id = $1 AND org_id = $2`,
		reviewID, org.ID).Scan(&reviewerID)
	if err != nil {
		// Not found (or scoped out) — do not leak which; treat as forbidden.
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized to decide this review"})
		return false
	}
	if reviewerID == "" || reviewerID != callerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the assigned reviewer or an administrator may decide this review"})
		return false
	}
	return true
}

func (s *Service) handleBatchDecision(c *gin.Context) {
	var req struct {
		ItemIDs  []string       `json:"item_ids"`
		Decision ReviewDecision `json:"decision"`
		Comments string         `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if !s.authorizeReviewDecision(c, c.Param("id")) {
		return
	}

	userID, exists := c.Get("user_id")
	decidedBy := ""
	if exists {
		if str, ok := userID.(string); ok {
			decidedBy = str
		}
	}

	if err := s.BatchSubmitDecisions(c.Request.Context(), c.Param("id"), req.ItemIDs, req.Decision, req.Comments, decidedBy); err != nil {
		s.logger.Error("failed to batch submit decisions", zap.String("review_id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "submitted", "count": len(req.ItemIDs)})
}

func (s *Service) handleSubmitDecision(c *gin.Context) {
	var req struct {
		Decision ReviewDecision `json:"decision"`
		Comments string         `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "user not authenticated"})
		return
	}
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(500, gin.H{"error": "invalid user ID format"})
		return
	}
	if !s.authorizeReviewDecision(c, c.Param("id")) {
		return
	}
	if err := s.SubmitReviewDecision(c.Request.Context(), c.Param("itemId"), req.Decision, req.Comments, userIDStr); err != nil {
		s.logger.Error("failed to submit review decision", zap.String("item_id", c.Param("itemId")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"status": "submitted"})
}

func (s *Service) handleListPolicies(c *gin.Context) {
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

	policies, total, err := s.ListPolicies(c.Request.Context(), offset, limit)
	if err != nil {
		s.logger.Error("failed to list policies", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, policies)
}

func (s *Service) handleCreatePolicy(c *gin.Context) {
	var policy Policy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.CreatePolicy(c.Request.Context(), &policy); err != nil {
		s.logger.Error("failed to create policy", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, policy)
}

func (s *Service) handleGetPolicy(c *gin.Context) {
	policy, err := s.GetPolicy(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(200, policy)
}

func (s *Service) handleUpdatePolicy(c *gin.Context) {
	var policy Policy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.UpdatePolicy(c.Request.Context(), c.Param("id"), &policy); err != nil {
		s.logger.Error("failed to update policy", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, policy)
}

func (s *Service) handleDeletePolicy(c *gin.Context) {
	if err := s.DeletePolicy(c.Request.Context(), c.Param("id")); err != nil {
		s.logger.Error("failed to delete policy", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(204, nil)
}

func (s *Service) handleEvaluatePolicy(c *gin.Context) {
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	allowed, err := s.EvaluatePolicy(c.Request.Context(), c.Param("id"), req)
	if err != nil {
		s.logger.Error("failed to evaluate policy", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	// For conditional access policies, check if step-up MFA should be suggested
	response := gin.H{"allowed": allowed}
	if !allowed {
		policy, pErr := s.GetPolicy(c.Request.Context(), c.Param("id"))
		if pErr == nil && policy.Type == PolicyTypeConditionalAccess {
			for _, rule := range policy.Rules {
				if rule.Effect == "step_up_mfa" {
					response["step_up_required"] = true
					break
				}
			}
		}
	}
	c.JSON(200, response)
}

// --- Certification Campaigns ---

// ScheduledCampaign represents a scheduled certification campaign
type ScheduledCampaign struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Type             string     `json:"type"`
	Schedule         string     `json:"schedule"`
	ReviewerStrategy string     `json:"reviewer_strategy"`
	ReviewerID       *string    `json:"reviewer_id,omitempty"`
	ReviewerRole     *string    `json:"reviewer_role,omitempty"`
	AutoRevoke       bool       `json:"auto_revoke"`
	GracePeriodDays  int        `json:"grace_period_days"`
	DurationDays     int        `json:"duration_days"`
	Status           string     `json:"status"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`
	NextRunAt        *time.Time `json:"next_run_at,omitempty"`
	CreatedBy        *string    `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// CampaignRun represents a single execution of a campaign
type CampaignRun struct {
	ID               string     `json:"id"`
	CampaignID       string     `json:"campaign_id"`
	ReviewID         *string    `json:"review_id,omitempty"`
	Status           string     `json:"status"`
	StartedAt        time.Time  `json:"started_at"`
	Deadline         time.Time  `json:"deadline"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	TotalItems       int        `json:"total_items"`
	ReviewedItems    int        `json:"reviewed_items"`
	AutoRevokedItems int        `json:"auto_revoked_items"`
	CreatedAt        time.Time  `json:"created_at"`
}

// computeNextRunAt calculates the next run time based on the campaign schedule
func computeNextRunAt(schedule string, from time.Time) *time.Time {
	var next time.Time
	switch schedule {
	case "quarterly":
		next = from.AddDate(0, 0, 90)
	case "semi_annual":
		next = from.AddDate(0, 0, 180)
	case "annual":
		next = from.AddDate(0, 0, 365)
	default:
		// "once" or unknown schedule -> no next run
		return nil
	}
	return &next
}

// CreateCampaign inserts a new certification campaign
func (s *Service) CreateCampaign(ctx context.Context, campaign *ScheduledCampaign) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Creating certification campaign", zap.String("name", campaign.Name))

	if campaign.ID == "" {
		campaign.ID = uuid.New().String()
	}
	now := time.Now()
	campaign.CreatedAt = now
	campaign.UpdatedAt = now
	if campaign.Status == "" {
		campaign.Status = "active"
	}
	campaign.NextRunAt = computeNextRunAt(campaign.Schedule, now)

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO certification_campaigns (id, name, description, type, schedule, reviewer_strategy,
			reviewer_id, reviewer_role, auto_revoke, grace_period_days, duration_days,
			status, next_run_at, created_by, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`, campaign.ID, campaign.Name, campaign.Description, campaign.Type, campaign.Schedule,
		campaign.ReviewerStrategy, campaign.ReviewerID, campaign.ReviewerRole,
		campaign.AutoRevoke, campaign.GracePeriodDays, campaign.DurationDays,
		campaign.Status, campaign.NextRunAt, campaign.CreatedBy, campaign.CreatedAt, campaign.UpdatedAt, org.ID)

	return err
}

// ListCampaigns retrieves campaigns with pagination and optional status filter
func (s *Service) ListCampaigns(ctx context.Context, offset, limit int, status string) ([]ScheduledCampaign, int, error) {
	var total int
	countQuery := "SELECT COUNT(*) FROM certification_campaigns"
	countArgs := []interface{}{}

	if status != "" {
		countQuery += " WHERE status = $1"
		countArgs = append(countArgs, status)
	}

	err := s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	baseQuery := `
		SELECT id, name, description, type, schedule, reviewer_strategy,
		       reviewer_id, reviewer_role, auto_revoke, grace_period_days, duration_days,
		       status, last_run_at, next_run_at, created_by, created_at, updated_at
		FROM certification_campaigns
	`

	args := []interface{}{}
	paramIdx := 1

	if status != "" {
		baseQuery += " WHERE status = $" + strconv.Itoa(paramIdx)
		args = append(args, status)
		paramIdx++
	}

	baseQuery += " ORDER BY created_at DESC OFFSET $" + strconv.Itoa(paramIdx) + " LIMIT $" + strconv.Itoa(paramIdx+1)
	args = append(args, offset, limit)

	rows, err := s.db.Pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var campaigns []ScheduledCampaign
	for rows.Next() {
		var c ScheduledCampaign
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Description, &c.Type, &c.Schedule, &c.ReviewerStrategy,
			&c.ReviewerID, &c.ReviewerRole, &c.AutoRevoke, &c.GracePeriodDays, &c.DurationDays,
			&c.Status, &c.LastRunAt, &c.NextRunAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		campaigns = append(campaigns, c)
	}

	return campaigns, total, nil
}

// GetCampaign retrieves a single certification campaign by ID
func (s *Service) GetCampaign(ctx context.Context, id string) (*ScheduledCampaign, error) {
	var c ScheduledCampaign
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, type, schedule, reviewer_strategy,
		       reviewer_id, reviewer_role, auto_revoke, grace_period_days, duration_days,
		       status, last_run_at, next_run_at, created_by, created_at, updated_at
		FROM certification_campaigns WHERE id = $1
	`, id).Scan(
		&c.ID, &c.Name, &c.Description, &c.Type, &c.Schedule, &c.ReviewerStrategy,
		&c.ReviewerID, &c.ReviewerRole, &c.AutoRevoke, &c.GracePeriodDays, &c.DurationDays,
		&c.Status, &c.LastRunAt, &c.NextRunAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateCampaign updates an existing certification campaign
func (s *Service) UpdateCampaign(ctx context.Context, campaign *ScheduledCampaign) error {
	s.logger.Info("Updating certification campaign", zap.String("id", campaign.ID))

	now := time.Now()
	campaign.UpdatedAt = now
	campaign.NextRunAt = computeNextRunAt(campaign.Schedule, now)

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE certification_campaigns
		SET name = $2, description = $3, type = $4, schedule = $5, reviewer_strategy = $6,
		    reviewer_id = $7, reviewer_role = $8, auto_revoke = $9, grace_period_days = $10,
		    duration_days = $11, status = $12, next_run_at = $13, updated_at = $14
		WHERE id = $1
	`, campaign.ID, campaign.Name, campaign.Description, campaign.Type, campaign.Schedule,
		campaign.ReviewerStrategy, campaign.ReviewerID, campaign.ReviewerRole,
		campaign.AutoRevoke, campaign.GracePeriodDays, campaign.DurationDays,
		campaign.Status, campaign.NextRunAt, campaign.UpdatedAt)

	return err
}

// DeleteCampaign deletes a certification campaign and its runs
func (s *Service) DeleteCampaign(ctx context.Context, id string) error {
	s.logger.Info("Deleting certification campaign", zap.String("id", id))

	// Delete associated campaign runs first
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM campaign_runs WHERE campaign_id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete campaign runs: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx, "DELETE FROM certification_campaigns WHERE id = $1", id)
	return err
}

// RunCampaign triggers a single run of a certification campaign
func (s *Service) RunCampaign(ctx context.Context, campaignID string) (*CampaignRun, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Running certification campaign", zap.String("campaign_id", campaignID))

	campaign, err := s.GetCampaign(ctx, campaignID)
	if err != nil {
		return nil, fmt.Errorf("campaign not found: %w", err)
	}

	now := time.Now()

	// Determine reviewer ID for the access review
	reviewerID := ""
	if campaign.ReviewerStrategy == "specific_user" && campaign.ReviewerID != nil {
		reviewerID = *campaign.ReviewerID
	} else if campaign.ReviewerStrategy == "role" && campaign.ReviewerRole != nil {
		// Look up first user with matching role to act as primary reviewer
		err := s.db.Pool.QueryRow(ctx, `
			SELECT u.id FROM users u
			JOIN user_roles ur ON u.id = ur.user_id
			JOIN roles r ON ur.role_id = r.id
			WHERE r.name = $1 AND u.enabled = true
			AND u.org_id = $2 AND ur.org_id = $2 AND r.org_id = $2
			LIMIT 1
		`, *campaign.ReviewerRole, org.ID).Scan(&reviewerID)
		if err != nil {
			s.logger.Warn("No user found for reviewer role, using empty reviewer",
				zap.String("role", *campaign.ReviewerRole), zap.Error(err))
		}
	}

	// Create an access review for this campaign run
	reviewName := fmt.Sprintf("%s - %s", campaign.Name, now.Format("2006-01-02 15:04"))
	reviewType := ReviewType(campaign.Type)
	deadline := now.AddDate(0, 0, campaign.DurationDays)

	review := &AccessReview{
		Name:        reviewName,
		Description: fmt.Sprintf("Auto-generated review from campaign: %s", campaign.Name),
		Type:        reviewType,
		ReviewerID:  reviewerID,
		StartDate:   now,
		EndDate:     deadline,
	}

	if err := s.CreateAccessReview(ctx, review); err != nil {
		return nil, fmt.Errorf("failed to create access review: %w", err)
	}

	// Start the review to populate items
	if err := s.UpdateReviewStatus(ctx, review.ID, ReviewStatusInProgress); err != nil {
		s.logger.Warn("Failed to start review for campaign run",
			zap.String("review_id", review.ID), zap.Error(err))
	}

	// Count total items generated
	var totalItems int
	_ = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM review_items WHERE review_id = $1 AND org_id = $2", review.ID, org.ID).Scan(&totalItems)

	// Create campaign run
	run := &CampaignRun{
		ID:         uuid.New().String(),
		CampaignID: campaignID,
		ReviewID:   &review.ID,
		Status:     "in_progress",
		StartedAt:  now,
		Deadline:   deadline,
		TotalItems: totalItems,
		CreatedAt:  now,
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO campaign_runs (id, campaign_id, review_id, status, started_at, deadline,
			total_items, reviewed_items, auto_revoked_items, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, run.ID, run.CampaignID, run.ReviewID, run.Status, run.StartedAt,
		run.Deadline, run.TotalItems, run.ReviewedItems, run.AutoRevokedItems, run.CreatedAt, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create campaign run: %w", err)
	}

	// Update campaign last_run_at and next_run_at
	nextRunAt := computeNextRunAt(campaign.Schedule, now)
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE certification_campaigns
		SET last_run_at = $2, next_run_at = $3, updated_at = $4
		WHERE id = $1
	`, campaignID, now, nextRunAt, now)
	if err != nil {
		s.logger.Error("Failed to update campaign run timestamps", zap.Error(err))
	}

	return run, nil
}

// GetCampaignRuns retrieves all runs for a specific campaign
func (s *Service) GetCampaignRuns(ctx context.Context, campaignID string) ([]CampaignRun, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, campaign_id, review_id, status, started_at, deadline,
		       completed_at, total_items, reviewed_items, auto_revoked_items, created_at
		FROM campaign_runs
		WHERE campaign_id = $1
		ORDER BY created_at DESC
	`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []CampaignRun
	for rows.Next() {
		var r CampaignRun
		if err := rows.Scan(
			&r.ID, &r.CampaignID, &r.ReviewID, &r.Status, &r.StartedAt, &r.Deadline,
			&r.CompletedAt, &r.TotalItems, &r.ReviewedItems, &r.AutoRevokedItems, &r.CreatedAt,
		); err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}

	return runs, nil
}

// --- Campaign HTTP Handlers ---

func (s *Service) handleListCampaigns(c *gin.Context) {
	status := c.Query("status")

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

	campaigns, total, err := s.ListCampaigns(c.Request.Context(), offset, limit, status)
	if err != nil {
		s.logger.Error("failed to list campaigns", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, campaigns)
}

func (s *Service) handleCreateCampaign(c *gin.Context) {
	var campaign ScheduledCampaign
	if err := c.ShouldBindJSON(&campaign); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Set created_by from auth context if available
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			campaign.CreatedBy = &uid
		}
	}

	if err := s.CreateCampaign(c.Request.Context(), &campaign); err != nil {
		s.logger.Error("failed to create campaign", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, campaign)
}

func (s *Service) handleGetCampaign(c *gin.Context) {
	campaign, err := s.GetCampaign(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "campaign not found"})
		return
	}
	c.JSON(200, campaign)
}

func (s *Service) handleUpdateCampaign(c *gin.Context) {
	var campaign ScheduledCampaign
	if err := c.ShouldBindJSON(&campaign); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	campaign.ID = c.Param("id")

	if err := s.UpdateCampaign(c.Request.Context(), &campaign); err != nil {
		s.logger.Error("failed to update campaign", zap.String("id", campaign.ID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, campaign)
}

func (s *Service) handleDeleteCampaign(c *gin.Context) {
	if err := s.DeleteCampaign(c.Request.Context(), c.Param("id")); err != nil {
		s.logger.Error("failed to delete campaign", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(204, nil)
}

func (s *Service) handleRunCampaign(c *gin.Context) {
	run, err := s.RunCampaign(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.logger.Error("failed to run campaign", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, run)
}

func (s *Service) handleGetCampaignRuns(c *gin.Context) {
	runs, err := s.GetCampaignRuns(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.logger.Error("failed to get campaign runs", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, runs)
}

// --- Campaign Scheduler ---

// StartCampaignScheduler runs a background loop that checks for campaigns due to run
// and for campaign runs that have exceeded their deadline.
func (s *Service) StartCampaignScheduler(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	// Leader-gated: trigger due campaigns + deadline checks once per interval
	// cluster-wide (avoids launching each campaign N times across replicas).
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "governance:campaign-scheduler", 1*time.Hour, func(ctx context.Context) {
		s.checkCampaignSchedules(ctx)
		s.checkCampaignDeadlines(ctx)
	})
	<-ctx.Done()
}

// checkCampaignSchedules finds active campaigns whose next_run_at has passed and triggers them.
func (s *Service) checkCampaignSchedules(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, org_id FROM certification_campaigns
		WHERE status = 'active' AND next_run_at IS NOT NULL AND next_run_at <= NOW()
	`)
	if err != nil {
		s.logger.Error("Failed to query due campaigns", zap.Error(err))
		return
	}
	defer rows.Close()

	type dueCampaign struct {
		id    string
		orgID string
	}
	var due []dueCampaign
	for rows.Next() {
		var c dueCampaign
		if err := rows.Scan(&c.id, &c.orgID); err != nil {
			s.logger.Error("Failed to scan campaign ID", zap.Error(err))
			continue
		}
		due = append(due, c)
	}

	// certification_campaigns/campaign_runs are org-scoped (v69). The SELECT above
	// runs under WithBypassRLS (set in StartCampaignScheduler) so it sees due
	// campaigns across all orgs; each campaign is then run under its own org so the
	// access reviews and campaign_run rows it generates land in the right tenant and
	// satisfy the FORCE-RLS WITH CHECK belt.
	for _, c := range due {
		s.logger.Info("Scheduler triggering campaign run", zap.String("campaign_id", c.id))
		runCtx := orgctx.With(ctx, orgctx.Org{ID: c.orgID})
		if _, err := s.RunCampaign(runCtx, c.id); err != nil {
			s.logger.Error("Scheduler failed to run campaign",
				zap.String("campaign_id", c.id), zap.Error(err))
		}
	}
}

// checkCampaignDeadlines finds in-progress campaign runs past their deadline and marks them expired.
// If the parent campaign has auto_revoke enabled, it counts unreviewed items as auto-revoked.
func (s *Service) checkCampaignDeadlines(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT cr.id, cr.campaign_id, cr.review_id
		FROM campaign_runs cr
		WHERE cr.status = 'in_progress' AND cr.deadline < NOW()
	`)
	if err != nil {
		s.logger.Error("Failed to query expired campaign runs", zap.Error(err))
		return
	}
	defer rows.Close()

	type expiredRun struct {
		runID      string
		campaignID string
		reviewID   *string
	}
	var expiredRuns []expiredRun
	for rows.Next() {
		var er expiredRun
		if err := rows.Scan(&er.runID, &er.campaignID, &er.reviewID); err != nil {
			s.logger.Error("Failed to scan expired campaign run", zap.Error(err))
			continue
		}
		expiredRuns = append(expiredRuns, er)
	}

	now := time.Now()
	for _, er := range expiredRuns {
		s.logger.Info("Marking campaign run as expired",
			zap.String("run_id", er.runID), zap.String("campaign_id", er.campaignID))

		// Check if the campaign has auto_revoke enabled
		campaign, cErr := s.GetCampaign(ctx, er.campaignID)
		if cErr != nil {
			s.logger.Error("Failed to get campaign for expired run",
				zap.String("campaign_id", er.campaignID), zap.Error(cErr))
			continue
		}

		autoRevokedCount := 0
		if campaign.AutoRevoke && er.reviewID != nil {
			// Count pending (unreviewed) items and mark them as revoked
			var pending int
			err := s.db.Pool.QueryRow(ctx,
				//orgscope:ignore cross-org background deadline sweep; keyed by globally-unique review_id
				"SELECT COUNT(*) FROM review_items WHERE review_id = $1 AND decision = 'pending'",
				*er.reviewID).Scan(&pending)
			if err == nil && pending > 0 {
				//orgscope:ignore cross-org background deadline sweep; keyed by globally-unique review_id
				_, updateErr := s.db.Pool.Exec(ctx, `
					UPDATE review_items
					SET decision = 'revoked', comments = 'Auto-revoked: campaign deadline expired', decided_at = $2
					WHERE review_id = $1 AND decision = 'pending'
				`, *er.reviewID, now)
				if updateErr != nil {
					s.logger.Error("Failed to auto-revoke pending items",
						zap.String("review_id", *er.reviewID), zap.Error(updateErr))
				} else {
					autoRevokedCount = pending
				}
			}

			// Also mark the access review itself as expired
			//orgscope:ignore cross-org background deadline sweep; keyed by globally-unique review_id
			_, _ = s.db.Pool.Exec(ctx, `
				UPDATE access_reviews SET status = 'expired', completed_at = $2 WHERE id = $1
			`, *er.reviewID, now)
		}

		// Count reviewed items for the run
		var reviewedItems int
		if er.reviewID != nil {
			_ = s.db.Pool.QueryRow(ctx,
				//orgscope:ignore cross-org background deadline sweep; keyed by globally-unique review_id
				"SELECT COUNT(*) FROM review_items WHERE review_id = $1 AND decision != 'pending'",
				*er.reviewID).Scan(&reviewedItems)
		}

		// Mark the campaign run as expired
		_, err := s.db.Pool.Exec(ctx, `
			UPDATE campaign_runs
			SET status = 'expired', completed_at = $2, reviewed_items = $3, auto_revoked_items = $4
			WHERE id = $1
		`, er.runID, now, reviewedItems, autoRevokedCount)
		if err != nil {
			s.logger.Error("Failed to mark campaign run as expired",
				zap.String("run_id", er.runID), zap.Error(err))
		}
	}
}

// --- ABAC (Attribute-Based Access Control) Policies ---

// ABACPolicy represents an attribute-based access control policy
type ABACPolicy struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Conditions   []ABACCondition `json:"conditions"`
	Effect       string          `json:"effect"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// ABACCondition represents a single condition within an ABAC policy
type ABACCondition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

// ABACEvaluationRequest represents a request to evaluate ABAC policies
type ABACEvaluationRequest struct {
	UserAttributes map[string]interface{} `json:"user_attributes"`
	ResourceType   string                 `json:"resource_type"`
	ResourceID     string                 `json:"resource_id"`
}

// ABACEvaluationResult represents the result of an ABAC policy evaluation
type ABACEvaluationResult struct {
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
}

// CreateABACPolicy creates a new ABAC policy
func (s *Service) CreateABACPolicy(ctx context.Context, policy *ABACPolicy) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("Creating ABAC policy", zap.String("name", policy.Name))

	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO abac_policies (id, name, description, resource_type, resource_id, conditions, effect, priority, enabled, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, policy.ID, policy.Name, policy.Description, policy.ResourceType, policy.ResourceID,
		conditionsJSON, policy.Effect, policy.Priority, policy.Enabled, policy.CreatedAt, policy.UpdatedAt, org.ID)
	if err != nil {
		return fmt.Errorf("failed to insert ABAC policy: %w", err)
	}

	return nil
}

// ListABACPolicies retrieves ABAC policies with optional resource type filter
func (s *Service) ListABACPolicies(ctx context.Context, resourceType string, offset, limit int) ([]ABACPolicy, int, error) {
	var total int
	var countQuery string
	var countArgs []interface{}

	if resourceType != "" {
		countQuery = "SELECT COUNT(*) FROM abac_policies WHERE resource_type = $1"
		countArgs = append(countArgs, resourceType)
	} else {
		countQuery = "SELECT COUNT(*) FROM abac_policies"
	}

	err := s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count ABAC policies: %w", err)
	}

	var query string
	var queryArgs []interface{}

	if resourceType != "" {
		query = `
			SELECT id, name, description, resource_type, resource_id, conditions, effect, priority, enabled, created_at, updated_at
			FROM abac_policies
			WHERE resource_type = $1
			ORDER BY priority DESC, created_at DESC
			OFFSET $2 LIMIT $3
		`
		queryArgs = []interface{}{resourceType, offset, limit}
	} else {
		query = `
			SELECT id, name, description, resource_type, resource_id, conditions, effect, priority, enabled, created_at, updated_at
			FROM abac_policies
			ORDER BY priority DESC, created_at DESC
			OFFSET $1 LIMIT $2
		`
		queryArgs = []interface{}{offset, limit}
	}

	rows, err := s.db.Pool.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query ABAC policies: %w", err)
	}
	defer rows.Close()

	var policies []ABACPolicy
	for rows.Next() {
		var p ABACPolicy
		var conditionsJSON []byte
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.ResourceType, &p.ResourceID,
			&conditionsJSON, &p.Effect, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan ABAC policy: %w", err)
		}
		if len(conditionsJSON) > 0 {
			if err := json.Unmarshal(conditionsJSON, &p.Conditions); err != nil {
				s.logger.Warn("Failed to parse ABAC conditions", zap.String("policy_id", p.ID), zap.Error(err))
			}
		}
		policies = append(policies, p)
	}

	return policies, total, nil
}

// GetABACPolicy retrieves a single ABAC policy by ID
func (s *Service) GetABACPolicy(ctx context.Context, id string) (*ABACPolicy, error) {
	var p ABACPolicy
	var conditionsJSON []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, resource_type, resource_id, conditions, effect, priority, enabled, created_at, updated_at
		FROM abac_policies WHERE id = $1
	`, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.ResourceType, &p.ResourceID,
		&conditionsJSON, &p.Effect, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("ABAC policy not found")
		}
		return nil, fmt.Errorf("failed to get ABAC policy: %w", err)
	}
	if len(conditionsJSON) > 0 {
		if err := json.Unmarshal(conditionsJSON, &p.Conditions); err != nil {
			s.logger.Warn("Failed to parse ABAC conditions", zap.String("policy_id", p.ID), zap.Error(err))
		}
	}
	return &p, nil
}

// UpdateABACPolicy updates an existing ABAC policy
func (s *Service) UpdateABACPolicy(ctx context.Context, policy *ABACPolicy) error {
	s.logger.Info("Updating ABAC policy", zap.String("policy_id", policy.ID))

	now := time.Now()
	policy.UpdatedAt = now

	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	result, err := s.db.Pool.Exec(ctx, `
		UPDATE abac_policies
		SET name = $2, description = $3, resource_type = $4, resource_id = $5,
			conditions = $6, effect = $7, priority = $8, enabled = $9, updated_at = $10
		WHERE id = $1
	`, policy.ID, policy.Name, policy.Description, policy.ResourceType, policy.ResourceID,
		conditionsJSON, policy.Effect, policy.Priority, policy.Enabled, now)
	if err != nil {
		return fmt.Errorf("failed to update ABAC policy: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("ABAC policy not found")
	}

	return nil
}

// DeleteABACPolicy deletes an ABAC policy by ID
func (s *Service) DeleteABACPolicy(ctx context.Context, id string) error {
	s.logger.Info("Deleting ABAC policy", zap.String("policy_id", id))

	result, err := s.db.Pool.Exec(ctx, "DELETE FROM abac_policies WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete ABAC policy: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("ABAC policy not found")
	}
	return nil
}

// EvaluateABACPolicies evaluates all matching ABAC policies for a given request
func (s *Service) EvaluateABACPolicies(ctx context.Context, req ABACEvaluationRequest) ABACEvaluationResult {
	s.logger.Info("Evaluating ABAC policies",
		zap.String("resource_type", req.ResourceType),
		zap.String("resource_id", req.ResourceID))

	// Query all enabled ABAC policies matching the resource type, ordered by priority DESC
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, conditions, effect, priority
		FROM abac_policies
		WHERE enabled = true
			AND resource_type IN ($1, '*')
			AND (resource_id IS NULL OR resource_id = '' OR resource_id = $2)
		ORDER BY priority DESC
	`, req.ResourceType, req.ResourceID)
	if err != nil {
		// Fail closed: a policy decision point that cannot read its policies must
		// deny, not allow. Returning "allowed" here would tell any enforcement
		// point consuming this decision to permit the action precisely when the
		// evaluation could not run.
		s.logger.Error("Failed to query ABAC policies for evaluation; failing closed", zap.Error(err))
		return ABACEvaluationResult{Allowed: false, Reason: "policy evaluation error, failing closed"}
	}
	defer rows.Close()

	var denyMatch *ABACEvaluationResult
	var allowMatch *ABACEvaluationResult

	for rows.Next() {
		var policyID, name, effect string
		var conditionsJSON []byte
		var priority int
		if err := rows.Scan(&policyID, &name, &conditionsJSON, &effect, &priority); err != nil {
			s.logger.Warn("Failed to scan ABAC policy during evaluation", zap.Error(err))
			continue
		}

		var conditions []ABACCondition
		if len(conditionsJSON) > 0 {
			if err := json.Unmarshal(conditionsJSON, &conditions); err != nil {
				s.logger.Warn("Failed to parse ABAC conditions during evaluation", zap.String("policy_id", policyID), zap.Error(err))
				continue
			}
		}

		// Evaluate all conditions — all must match for the policy to apply
		allMatch := true
		for _, cond := range conditions {
			if !evaluateABACCondition(cond, req.UserAttributes) {
				allMatch = false
				break
			}
		}

		if allMatch {
			if effect == "deny" {
				denyMatch = &ABACEvaluationResult{
					Allowed:  false,
					Reason:   fmt.Sprintf("denied by policy: %s", name),
					PolicyID: policyID,
				}
				// Deny takes immediate precedence
				break
			}
			if allowMatch == nil && effect == "allow" {
				allowMatch = &ABACEvaluationResult{
					Allowed:  true,
					Reason:   fmt.Sprintf("allowed by policy: %s", name),
					PolicyID: policyID,
				}
			}
		}
	}

	// Deny overrides allow
	if denyMatch != nil {
		return *denyMatch
	}

	// If at least one allow policy matched, return allowed
	if allowMatch != nil {
		return *allowMatch
	}

	// Default: allowed (fail-open in dev mode)
	return ABACEvaluationResult{Allowed: true, Reason: "no matching policies, default allow"}
}

// evaluateABACCondition evaluates a single ABAC condition against user attributes
func evaluateABACCondition(cond ABACCondition, attrs map[string]interface{}) bool {
	attrVal, exists := attrs[cond.Attribute]
	if !exists {
		return false
	}

	switch cond.Operator {
	case "eq":
		return fmt.Sprintf("%v", attrVal) == fmt.Sprintf("%v", cond.Value)

	case "neq":
		return fmt.Sprintf("%v", attrVal) != fmt.Sprintf("%v", cond.Value)

	case "in":
		return evalIn(attrVal, cond.Value)

	case "not_in":
		return !evalIn(attrVal, cond.Value)

	case "gt":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a > b

	case "gte":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a >= b

	case "lt":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a < b

	case "lte":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a <= b

	case "between":
		return evalBetween(attrVal, cond.Value)

	case "contains":
		return strings.Contains(fmt.Sprintf("%v", attrVal), fmt.Sprintf("%v", cond.Value))

	default:
		return false
	}
}

// evalIn checks if attrVal is one of the values in the list
func evalIn(attrVal interface{}, condValue interface{}) bool {
	list, ok := condValue.([]interface{})
	if !ok {
		return false
	}
	attrStr := fmt.Sprintf("%v", attrVal)
	for _, v := range list {
		if fmt.Sprintf("%v", v) == attrStr {
			return true
		}
	}
	return false
}

// evalBetween checks if attrVal is between [min, max]
func evalBetween(attrVal interface{}, condValue interface{}) bool {
	list, ok := condValue.([]interface{})
	if !ok || len(list) != 2 {
		return false
	}
	a, minOk := toFloat64(attrVal)
	minVal, minValOk := toFloat64(list[0])
	maxVal, maxValOk := toFloat64(list[1])
	if !minOk || !minValOk || !maxValOk {
		return false
	}
	return a >= minVal && a <= maxVal
}

// toFloat64Pair converts two values to float64 for numeric comparison
func toFloat64Pair(a, b interface{}) (float64, float64, bool) {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	return af, bf, aOk && bOk
}

// toFloat64 converts a value to float64
func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case json.Number:
		f, err := val.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	default:
		// Try converting via string representation
		f, err := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
		return f, err == nil
	}
}

// --- ABAC HTTP Handlers ---

func (s *Service) handleCreateABACPolicy(c *gin.Context) {
	var policy ABACPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if policy.Name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	if policy.ResourceType == "" {
		c.JSON(400, gin.H{"error": "resource_type is required"})
		return
	}
	if policy.Effect != "allow" && policy.Effect != "deny" {
		c.JSON(400, gin.H{"error": "effect must be 'allow' or 'deny'"})
		return
	}
	if err := s.CreateABACPolicy(c.Request.Context(), &policy); err != nil {
		s.logger.Error("failed to create ABAC policy", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, policy)
}

func (s *Service) handleListABACPolicies(c *gin.Context) {
	resourceType := c.Query("resource_type")

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

	policies, total, err := s.ListABACPolicies(c.Request.Context(), resourceType, offset, limit)
	if err != nil {
		s.logger.Error("failed to list ABAC policies", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, policies)
}

func (s *Service) handleGetABACPolicy(c *gin.Context) {
	policy, err := s.GetABACPolicy(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "ABAC policy not found"})
		return
	}
	c.JSON(200, policy)
}

func (s *Service) handleUpdateABACPolicy(c *gin.Context) {
	var policy ABACPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	policy.ID = c.Param("id")
	if err := s.UpdateABACPolicy(c.Request.Context(), &policy); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "ABAC policy not found"})
			return
		}
		s.logger.Error("failed to update ABAC policy", zap.String("id", policy.ID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, policy)
}

func (s *Service) handleDeleteABACPolicy(c *gin.Context) {
	if err := s.DeleteABACPolicy(c.Request.Context(), c.Param("id")); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "ABAC policy not found"})
			return
		}
		s.logger.Error("failed to delete ABAC policy", zap.String("id", c.Param("id")), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(204, nil)
}

func (s *Service) handleEvaluateABACPolicies(c *gin.Context) {
	var req ABACEvaluationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.ResourceType == "" {
		c.JSON(400, gin.H{"error": "resource_type is required"})
		return
	}
	result := s.EvaluateABACPolicies(c.Request.Context(), req)
	c.JSON(200, result)
}
