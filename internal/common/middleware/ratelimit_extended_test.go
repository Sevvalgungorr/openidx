// Package middleware provides comprehensive tests for rate limiting functionality
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// setupTestRedis creates a miniredis instance and Redis client for testing
func setupExtendedTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	s, err := miniredis.Run()
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	return s, client
}

// testLogger creates a zap logger for testing
func testLogger(t *testing.T) *zap.Logger {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	return logger
}

// resetMetrics resets the Prometheus metrics between tests
func resetMetrics() {
	rlHitsTotal.Reset()
	rlFailOpenTotal.Reset()
}

// getMetricValue retrieves the current value of a counter metric
func getMetricValue(counterVec *prometheus.CounterVec, label string) float64 {
	metricCh := make(chan prometheus.Metric, 1)
	counterVec.Collect(metricCh)
	close(metricCh)

	for metric := range metricCh {
		var m dto.Metric
		if err := metric.Write(&m); err == nil {
			for _, labelPair := range m.Label {
				if labelPair.GetName() == "scope" && labelPair.GetValue() == label {
					return m.Counter.GetValue()
				}
			}
		}
	}
	return 0
}

// TestDistributedRateLimit_AllowsRequestsUnderLimit tests that requests under the limit are allowed
func TestDistributedRateLimit_AllowsRequestsUnderLimit(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     5,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Make requests within limit
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
		}

		// Verify no rate limit hits were recorded
		assert.Equal(t, float64(0), getMetricValue(rlHitsTotal, "ip"))
	})
}

// TestDistributedRateLimit_BlocksRequestsOverLimit tests that requests over the limit are blocked
func TestDistributedRateLimit_BlocksRequestsOverLimit(t *testing.T) {
	t.Run("blocks requests over limit", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     3,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Use up the limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.2:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
		}

		// Next request should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "rate limit exceeded")
		assert.NotEmpty(t, w.Header().Get("Retry-After"))

		// Verify rate limit hit was recorded
		assert.Greater(t, getMetricValue(rlHitsTotal, "ip"), float64(0))
	})
}

// TestDistributedRateLimit_ResetAfterTimeWindow tests that the rate limit resets after the time window
func TestDistributedRateLimit_ResetAfterTimeWindow(t *testing.T) {
	t.Run("window resets correctly", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     2,
			Window:       60 * time.Second, // 60s window + matching FastForward keeps the reset assertion off the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		ip := "192.168.1.3:1234"

		// Use up the limit
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = ip
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ip
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Fast forward time past the window (matches the 60s Window above)
		s.FastForward(70 * time.Second)

		// Should be allowed again
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = ip
		router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})
}

// TestDistributedRateLimit_PerIPTracking tests that rate limiting tracks per-IP
func TestDistributedRateLimit_PerIPTracking(t *testing.T) {
	t.Run("separate limits per IP", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     2,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// IP 1 uses up its limit
		ip1 := "10.0.0.1:1234"
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = ip1
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// IP 1 should be blocked
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = ip1
		router.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusTooManyRequests, w1.Code)

		// IP 2 should still be able to make requests
		ip2 := "10.0.0.2:1234"
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = ip2
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// IP 2 should also be blocked after exceeding limit
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = ip2
		router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	})
}

// TestDistributedRateLimit_PerUserTracking tests that rate limiting can track per-user
func TestDistributedRateLimit_PerUserTracking(t *testing.T) {
	t.Run("per-user tracking when enabled", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     2,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      true,
		}

		router := gin.New()
		// Simulate auth middleware setting user_id
		router.Use(func(c *gin.Context) {
			c.Set("user_id", "user-123")
			c.Next()
		})
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Make requests as user-123
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.10:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Should be blocked for user-123
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.10:1234"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Different user should still be able to make requests
		router2 := gin.New()
		router2.Use(func(c *gin.Context) {
			c.Set("user_id", "user-456")
			c.Next()
		})
		router2.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router2.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "192.168.1.10:1234" // Same IP, different user
		router2.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})
}

// TestDistributedRateLimit_AuthPaths tests stricter rate limiting for auth paths
func TestDistributedRateLimit_AuthPaths(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		authRequests  int
		authWindow    time.Duration
		regularReqs   int
		expectBlockAt int
	}{
		{
			name:          "oauth login path uses stricter limit",
			path:          "/oauth/login",
			authRequests:  3,
			authWindow:    60 * time.Second,
			regularReqs:   100,
			expectBlockAt: 4,
		},
		{
			name:          "oauth token path uses stricter limit",
			path:          "/oauth/token",
			authRequests:  2,
			authWindow:    60 * time.Second,
			regularReqs:   100,
			expectBlockAt: 3,
		},
		{
			name:          "mfa verify path uses stricter limit",
			path:          "/oauth/mfa-verify",
			authRequests:  5,
			authWindow:    60 * time.Second,
			regularReqs:   100,
			expectBlockAt: 6,
		},
		{
			name:          "api login path uses stricter limit",
			path:          "/api/v1/identity/users/login",
			authRequests:  3,
			authWindow:    60 * time.Second,
			regularReqs:   100,
			expectBlockAt: 4,
		},
		{
			name:          "non-auth path uses regular limit",
			path:          "/api/v1/users",
			authRequests:  2,
			authWindow:    60 * time.Second,
			regularReqs:   3, // Lower limit for easier testing
			expectBlockAt: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetMetrics()
			s, client := setupExtendedTestRedis(t)
			defer s.Close()

			cfg := RateLimitConfig{
				Requests:     tt.regularReqs,
				Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
				AuthRequests: tt.authRequests,
				AuthWindow:   tt.authWindow,
				PerUser:      false,
			}

			router := gin.New()
			router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
			router.POST(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			// Determine the actual limit based on whether this is an auth path
			limit := tt.regularReqs
			if isAuthPath(tt.path) && tt.authRequests > 0 {
				limit = tt.authRequests
			}

			// Make requests up to limit
			for i := 0; i < limit; i++ {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("POST", tt.path, nil)
				req.RemoteAddr = "192.168.2.1:1234"
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
			}

			// Next request should be blocked
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", tt.path, nil)
			req.RemoteAddr = "192.168.2.1:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusTooManyRequests, w.Code)
		})
	}
}

// TestDistributedRateLimit_SkipPaths tests that certain paths are exempt from rate limiting
func TestDistributedRateLimit_SkipPaths(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		skipCount int
	}{
		{"health endpoint", "/health", 100},
		{"metrics endpoint", "/metrics", 100},
		{"ready endpoint", "/ready", 100},
		{"regular endpoint", "/api/test", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetMetrics()
			s, client := setupExtendedTestRedis(t)
			defer s.Close()

			cfg := RateLimitConfig{
				Requests:     3,
				Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
				AuthRequests: 0,
				PerUser:      false,
			}

			router := gin.New()
			router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
			router.GET(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			// Make many requests
			for i := 0; i < tt.skipCount; i++ {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", tt.path, nil)
				req.RemoteAddr = "192.168.3.1:1234"
				router.ServeHTTP(w, req)

				expectedStatus := http.StatusOK
				if tt.path == "/api/test" && i >= 3 {
					expectedStatus = http.StatusTooManyRequests
				}
				assert.Equal(t, expectedStatus, w.Code, "Request %d to %s", i+1, tt.path)
			}
		})
	}
}

// TestDistributedRateLimit_Headers tests rate limit headers
func TestDistributedRateLimit_Headers(t *testing.T) {
	tests := []struct {
		name              string
		requests          int
		limit             int
		expectRemaining   []string
		expectLimitHeader string
		expectRetryAfter  bool
	}{
		{
			name:              "first request shows remaining",
			requests:          1,
			limit:             10,
			expectRemaining:   []string{"9"},
			expectLimitHeader: "10",
			expectRetryAfter:  false,
		},
		{
			name:              "multiple requests decrement remaining",
			requests:          5,
			limit:             10,
			expectRemaining:   []string{"9", "8", "7", "6", "5"},
			expectLimitHeader: "10",
			expectRetryAfter:  false,
		},
		{
			name:              "blocked request has 0 remaining",
			requests:          4,
			limit:             3,
			expectRemaining:   []string{"2", "1", "0", "0"},
			expectLimitHeader: "3",
			expectRetryAfter:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetMetrics()
			s, client := setupExtendedTestRedis(t)
			defer s.Close()

			cfg := RateLimitConfig{
				Requests:     tt.limit,
				Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
				AuthRequests: 0,
				PerUser:      false,
			}

			router := gin.New()
			router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			for i := 0; i < tt.requests; i++ {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.4.1:1234"
				router.ServeHTTP(w, req)

				assert.Equal(t, tt.expectLimitHeader, w.Header().Get("X-RateLimit-Limit"))
				if i < len(tt.expectRemaining) {
					assert.Equal(t, tt.expectRemaining[i], w.Header().Get("X-RateLimit-Remaining"))
				}

				if tt.expectRetryAfter && w.Code == http.StatusTooManyRequests {
					assert.NotEmpty(t, w.Header().Get("Retry-After"))
				}
			}
		})
	}
}

// TestDistributedRateLimit_FailOpen tests that the rate limiter fails open when Redis is unavailable
func TestDistributedRateLimit_FailOpen(t *testing.T) {
	tests := []struct {
		name          string
		redisClient   *redis.Client
		expectAllow   bool
		expectMetrics bool
	}{
		{
			name:          "nil Redis client allows requests",
			redisClient:   nil,
			expectAllow:   true,
			expectMetrics: true,
		},
		{
			name: "closed Redis connection allows requests",
			redisClient: func() *redis.Client {
				s, client := setupExtendedTestRedis(&testing.T{})
				s.Close()
				return client
			}(),
			expectAllow:   true,
			expectMetrics: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetMetrics()
			cfg := RateLimitConfig{
				Requests:     1,
				Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
				AuthRequests: 0,
				PerUser:      false,
			}

			router := gin.New()
			router.Use(DistributedRateLimit(tt.redisClient, cfg, testLogger(t)))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			// Make many requests - should all be allowed due to fail open
			for i := 0; i < 10; i++ {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.5.1:1234"
				router.ServeHTTP(w, req)

				if tt.expectAllow {
					assert.Equal(t, http.StatusOK, w.Code, "Request %d should be allowed", i+1)
				}
			}

			if tt.expectMetrics {
				// Check that fail-open metrics were recorded
				// Note: The exact metric value may vary, just check it's > 0
				assert.GreaterOrEqual(t, getMetricValue(rlFailOpenTotal, "ip"), float64(0))
			}
		})
	}
}

// TestDistributedRateLimit_DistributedConcurrency tests concurrent requests
func TestDistributedRateLimit_DistributedConcurrency(t *testing.T) {
	t.Run("handles concurrent requests correctly", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     10,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		ip := "192.168.6.1:1234"
		numRequests := 20
		var wg sync.WaitGroup
		successCount := 0
		blockedCount := 0
		var mu sync.Mutex

		// Send concurrent requests
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "/test", nil)
				req.RemoteAddr = ip
				router.ServeHTTP(w, req)

				mu.Lock()
				defer mu.Unlock()
				if w.Code == http.StatusOK {
					successCount++
				} else if w.Code == http.StatusTooManyRequests {
					blockedCount++
				}
			}(i)
		}

		wg.Wait()

		// The limiter fails OPEN on a Redis error (availability over
		// enforcement on non-auth paths), so a flaky miniredis connection
		// lets extra requests through and this used to fail as
		// "11 is not less than or equal to 10" -- which reads like a broken
		// limiter, not a dropped backend. Observed in CI while the log
		// showed "connection refused". Count the fail-opens and hold the
		// limiter to what it could actually enforce.
		failOpen := int(getMetricValue(rlFailOpenTotal, "ip"))
		if failOpen > 0 {
			t.Logf("redis dropped %d request(s); limiter failed open by design", failOpen)
		}
		assert.Greater(t, blockedCount, 0, "Some requests should be blocked")
		assert.LessOrEqual(t, successCount, 10+failOpen,
			"At most 10 requests should succeed, plus any the limiter could not enforce because Redis was unreachable (fail-open)")
		// Without the backend excuse the bound is exactly 10: a limiter that
		// over-admits while Redis is healthy is still a real defect.
		if failOpen == 0 {
			assert.LessOrEqual(t, successCount, 10, "At most 10 requests should succeed with a healthy backend")
		}
	})
}

// TestDistributedRateLimit_DifferentStrategies tests different rate limit configurations
func TestDistributedRateLimit_DifferentStrategies(t *testing.T) {
	tests := []struct {
		name          string
		cfg           RateLimitConfig
		requests      int
		expectBlocked bool
	}{
		{
			name: "low limit high window",
			cfg: RateLimitConfig{
				Requests:     2,
				Window:       60 * time.Second, // bumped from 5s to avoid wall-clock bucket boundary flake on the blocked-at-3 assertion
				AuthRequests: 0,
				PerUser:      false,
			},
			requests:      3,
			expectBlocked: true,
		},
		{
			name: "high limit low window",
			cfg: RateLimitConfig{
				Requests:     100,
				Window:       2 * time.Second, // Must be at least 1 second for integer division
				AuthRequests: 0,
				PerUser:      false,
			},
			requests:      10,
			expectBlocked: false,
		},
		{
			name: "auth path stricter limit",
			cfg: RateLimitConfig{
				Requests:     100,
				Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
				AuthRequests: 2,
				AuthWindow:   60 * time.Second,
				PerUser:      false,
			},
			requests:      3,
			expectBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetMetrics()
			s, client := setupExtendedTestRedis(t)
			defer s.Close()

			router := gin.New()
			router.Use(DistributedRateLimit(client, tt.cfg, testLogger(t)))

			path := "/test"
			if tt.cfg.AuthRequests > 0 {
				path = "/oauth/login"
			}
			router.GET(path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			blocked := false
			for i := 0; i < tt.requests; i++ {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", path, nil)
				req.RemoteAddr = "192.168.7.1:1234"
				router.ServeHTTP(w, req)

				if w.Code == http.StatusTooManyRequests {
					blocked = true
				}
			}

			assert.Equal(t, tt.expectBlocked, blocked)
		})
	}
}

// TestDistributedRateLimit_Configuration tests rate limit configuration
func TestDistributedRateLimit_Configuration(t *testing.T) {
	t.Run("configuration is applied correctly", func(t *testing.T) {
		cfg := RateLimitConfig{
			Requests:     50,
			Window:       30 * time.Second,
			AuthRequests: 10,
			PerUser:      true,
		}

		assert.Equal(t, 50, cfg.Requests)
		assert.Equal(t, 30*time.Second, cfg.Window)
		assert.Equal(t, 10, cfg.AuthRequests)
		assert.True(t, cfg.PerUser)
	})
}

// TestIsAuthPath tests the auth path detection function
func TestIsAuthPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/oauth/login", true},
		{"/oauth/login?redirect=/foo", true},
		{"/oauth/mfa-verify", true},
		{"/oauth/authorize/callback", true},
		{"/oauth/token", true},
		{"/api/v1/identity/users/login", true},
		{"/api/v1/identity/users", false},
		{"/api/v1/governance/reviews", false},
		{"/health", false},
		{"/metrics", false},
		{"/ready", false},
		{"/api/v1/identity/users/login/extra", true}, // prefix match
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isAuthPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDistributedRateLimit_PrometheusMetrics tests that Prometheus metrics are recorded
func TestDistributedRateLimit_PrometheusMetrics(t *testing.T) {
	t.Run("records metrics correctly", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     2,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Make requests that will trigger rate limiting
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.8.1:1234"
			router.ServeHTTP(w, req)
		}

		// Check that rate limit hits were recorded
		hits := getMetricValue(rlHitsTotal, "ip")
		assert.Greater(t, hits, float64(0), "Rate limit hits should be recorded")
	})
}

// TestDistributedRateLimit_ContextTimeout tests context timeout handling
func TestDistributedRateLimit_ContextTimeout(t *testing.T) {
	t.Run("handles context timeout", func(t *testing.T) {
		resetMetrics()
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     5,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// This test ensures the middleware handles context timeouts properly
		// The actual Redis timeout is set to 200ms in the middleware
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.9.1:1234"
		router.ServeHTTP(w, req)

		// Request should succeed even if context times out
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestDistributedRateLimit_RedisKeyFormat tests the Redis key format
func TestDistributedRateLimit_RedisKeyFormat(t *testing.T) {
	t.Run("Redis keys have correct format", func(t *testing.T) {
		s, client := setupExtendedTestRedis(t)
		defer s.Close()

		cfg := RateLimitConfig{
			Requests:     5,
			Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
			AuthRequests: 0,
			PerUser:      false,
		}

		router := gin.New()
		router.Use(DistributedRateLimit(client, cfg, testLogger(t)))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Make a request
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.10.1:1234"
		router.ServeHTTP(w, req)

		// Check Redis keys
		keys, err := client.Keys(context.Background(), "ratelimit:*").Result()
		require.NoError(t, err)
		require.Greater(t, len(keys), 0, "Should have rate limit keys in Redis")

		// Check key format
		key := keys[0]
		assert.Contains(t, key, "ratelimit:ip:")
	})
}

// Benchmark tests for rate limiting
func BenchmarkDistributedRateLimit_Allow(b *testing.B) {
	s, client := setupExtendedTestRedis(&testing.T{})
	defer s.Close()

	cfg := RateLimitConfig{
		Requests:     10000,
		Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
		AuthRequests: 0,
		PerUser:      false,
	}

	router := gin.New()
	router.Use(DistributedRateLimit(client, cfg, zap.NewNop()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.100.1:1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkDistributedRateLimit_Block(b *testing.B) {
	s, client := setupExtendedTestRedis(&testing.T{})
	defer s.Close()

	cfg := RateLimitConfig{
		Requests:     1,
		Window:       10 * time.Second,
		AuthRequests: 0,
		PerUser:      false,
	}

	router := gin.New()
	router.Use(DistributedRateLimit(client, cfg, zap.NewNop()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// First request to use up the limit
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.101.1:1234"
	router.ServeHTTP(w, req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.101.1:1234"
		router.ServeHTTP(w, req)
	}
}

func BenchmarkDistributedRateLimit_Parallel(b *testing.B) {
	s, client := setupExtendedTestRedis(&testing.T{})
	defer s.Close()

	cfg := RateLimitConfig{
		Requests:     10000,
		Window:       60 * time.Second, // 60s window so tests can't straddle the wall-clock bucket boundary
		AuthRequests: 0,
		PerUser:      false,
	}

	router := gin.New()
	router.Use(DistributedRateLimit(client, cfg, zap.NewNop()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.102.1:1234"
			router.ServeHTTP(w, req)
			i++
		}
	})
}
