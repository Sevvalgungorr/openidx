package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// RateLimitConfig configures the distributed rate limiter
type RateLimitConfig struct {
	// Default rate limit (requests per window)
	Requests int
	// Default window duration
	Window time.Duration
	// Auth-sensitive paths get a stricter limit
	AuthRequests int
	// Auth window duration
	AuthWindow time.Duration
	// Whether to also track per-user (when user_id is in context)
	PerUser bool
	// AuthFailOpen controls behavior on auth-sensitive paths when the Redis
	// backend is unavailable (nil client or error). The default (false) fails
	// CLOSED — auth requests are rejected with 503 so brute-force protection
	// can't silently disappear during a Redis outage. Non-auth paths always
	// fail open to preserve availability. Set true only if you explicitly
	// prefer login availability over rate-limit enforcement during outages.
	AuthFailOpen bool
}

// authPaths are paths that get the stricter auth rate limit tier (and, by
// default, fail closed when the limiter backend is unavailable). Matched by
// prefix, so e.g. "/oauth/magic-link" also covers "/oauth/magic-link-verify".
var authPaths = []string{
	"/oauth/login",
	"/oauth/mfa-verify",
	"/oauth/mfa-send-otp",
	"/oauth/stepup-verify",
	"/oauth/magic-link",
	"/oauth/authorize/callback",
	"/oauth/token",
	"/api/v1/identity/users/login",
	"/api/v1/identity/users/forgot-password",
	"/api/v1/identity/users/reset-password",
}

// skipPaths are paths exempt from rate limiting
var skipPaths = []string{
	"/health",
	"/metrics",
	"/ready",
}

// pollPaths are status-polling endpoints that a client legitimately hits many
// times while waiting for an out-of-band action to complete (push-MFA approval
// on the phone, QR-login approval, device-code authorization). They are matched
// by prefix and exempt from the shared per-IP counter.
//
// Why this is safe: each of these reads a specific, unguessable server-issued
// token (challenge_id / session_token / device_code) and only reveals that
// one flow's status; there is nothing to brute-force by polling. Counting them
// on the shared per-IP tier, by contrast, meant a single push login (polled
// every ~2s for up to a minute of waiting for the user to tap "approve") burned
// ~30 requests, so a few colleagues logging in from the same office NAT tripped
// "Rate limit exceeded" during normal use. The credential-submitting steps
// (/oauth/login, /oauth/mfa-verify, /oauth/token, ...) remain on the strict auth
// tier; only the read-only status polls are exempt.
var pollPaths = []string{
	"/oauth/mfa-push-status/",
	"/oauth/qr-login/poll",
	"/api/v1/identity/mfa/push/challenge/",
	"/api/v1/identity/passwordless/qr-login/poll",
}

func isPollPath(path string) bool {
	for _, pp := range pollPaths {
		if strings.HasPrefix(path, pp) {
			return true
		}
	}
	return false
}

// DistributedRateLimit implements Redis-backed distributed rate limiting using a
// sliding window counter. If Redis is unavailable, it fails open (allows the request).
func DistributedRateLimit(redisClient *redis.Client, cfg RateLimitConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip health/metrics/readiness endpoints
		for _, sp := range skipPaths {
			if path == sp {
				c.Next()
				return
			}
		}

		// Skip out-of-band status polling (see pollPaths): token-scoped, read-only,
		// and polled frequently by design, so they must not consume the shared
		// per-IP budget.
		if isPollPath(path) {
			c.Next()
			return
		}

		// Determine rate limit tier
		isAuth := isAuthPath(path)
		limit := cfg.Requests
		window := cfg.Window
		if isAuth && cfg.AuthRequests > 0 {
			limit = cfg.AuthRequests
			window = cfg.AuthWindow
		}

		// Build key: per-IP by default, optionally per-user
		identifier := c.ClientIP()
		scope := "ip"
		if cfg.PerUser {
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok && uid != "" {
					identifier = uid
					scope = "user"
				}
			}
		}

		// v1.8.0: partition buckets by org so one tenant's traffic can't exhaust
		// another's budget. Falls back to a shared "_" segment when no org is
		// resolved (infra/unauthenticated paths).
		orgSeg := "_"
		if org, err := orgctx.From(c.Request.Context()); err == nil && org.ID != "" {
			orgSeg = org.ID
		}

		windowEpoch := time.Now().Unix() / int64(window.Seconds())
		key := fmt.Sprintf("ratelimit:%s:%s:%s:%d", scope, orgSeg, identifier, windowEpoch)

		// If Redis is nil, the limiter can't enforce. Fail closed for auth
		// paths (unless explicitly opted out) so brute-force protection isn't
		// silently lost; fail open elsewhere to preserve availability.
		if redisClient == nil {
			if isAuth && !cfg.AuthFailOpen {
				rateLimitFailClosed(c, logger, key)
				return
			}
			rlFailOpenTotal.WithLabelValues(scope).Inc()
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 200*time.Millisecond)
		defer cancel()

		count, err := redisClient.Incr(ctx, key).Result()
		if err != nil {
			if isAuth && !cfg.AuthFailOpen {
				rateLimitFailClosed(c, logger, key)
				return
			}
			// Fail open: allow request, log warning
			rlFailOpenTotal.WithLabelValues(scope).Inc()
			logger.Warn("Rate limit Redis error, failing open",
				zap.Error(err),
				zap.String("key", key))
			c.Next()
			return
		}

		// Set expiry on first increment
		if count == 1 {
			redisClient.Expire(ctx, key, window+time.Second)
		}

		// Set rate limit headers
		remaining := int64(limit) - count
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if count > int64(limit) {
			retryAfter := int64(window.Seconds()) - (time.Now().Unix() % int64(window.Seconds()))
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			rlHitsTotal.WithLabelValues(scope).Inc()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

// rateLimitFailClosed rejects an auth-sensitive request when the rate-limit
// backend is unavailable, so brute-force protection is preserved during an
// outage. Returns 503 with a short Retry-After.
func rateLimitFailClosed(c *gin.Context, logger *zap.Logger, key string) {
	rlFailClosedTotal.Inc()
	logger.Warn("Rate limit backend unavailable on auth path, failing closed",
		zap.String("key", key),
		zap.String("path", c.Request.URL.Path))
	c.Header("Retry-After", "5")
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
		"error": "authentication temporarily unavailable, please retry",
	})
}

// isAuthPath checks if the request path matches an auth-sensitive path
func isAuthPath(path string) bool {
	for _, ap := range authPaths {
		if strings.HasPrefix(path, ap) {
			return true
		}
	}
	return false
}
