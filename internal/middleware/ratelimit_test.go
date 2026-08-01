// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	s, err := miniredis.Run()
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	return s, client
}

func TestSlidingWindowRateLimit_IPBased(t *testing.T) {
	s, client := setupTestRedis(t)
	defer s.Close()

	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 5
	// A window wide enough that a burst cannot straddle it. With a 1s window
	// this test was a coin flip under load: the six requests below are meant to
	// be one burst, but if the first few land in the previous second they age
	// out of the window and the sixth is legitimately allowed — a 200 where the
	// test demands 429. Expiry has its own test (TestSlidingWindowRateLimit_
	// SlidingWindow, which sleeps deliberately); this one is only about
	// counting, so it should not depend on wall-clock timing at all.
	cfg.Window = time.Minute

	router := gin.New()
	router.Use(SlidingWindowRateLimit(client, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Allows requests within limit", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)

			assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
			assert.Equal(t, "5", w.Header().Get("X-RateLimit-Limit"))
		}
	})

	t.Run("Blocks requests exceeding limit", func(t *testing.T) {
		// First, use up the limit
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.2:1234"
			router.ServeHTTP(w, req)
		}

		// 6th request should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, 429, w.Code)
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
		assert.Contains(t, w.Body.String(), "rate limit exceeded")
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		// IP1 uses up its limit
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			router.ServeHTTP(w, req)
		}

		// IP1 should be blocked
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "10.0.0.1:1234"
		router.ServeHTTP(w1, req1)
		assert.Equal(t, 429, w1.Code)

		// IP2 should still be able to make requests
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "10.0.0.2:1234"
		router.ServeHTTP(w2, req2)
		assert.Equal(t, 200, w2.Code)
	})
}

func TestSlidingWindowRateLimit_UserBased(t *testing.T) {
	s, client := setupTestRedis(t)
	defer s.Close()

	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 3
	cfg.UserRequestsPerMin = 10 // Higher limit for authenticated users
	// The limiter timestamps requests at second granularity (time.Now().Unix())
	// and counts ts > now-Window. A 1s window means only the *current* second
	// counts, so if the burst straddles a second boundary the window resets
	// mid-test and the 11th request is wrongly allowed — a flake that surfaces
	// under -race's slowdown. Use a wide window so all 11 requests fall in it
	// regardless of boundaries; this test asserts the user-vs-IP limit, not
	// window expiry (TestSlidingWindowRateLimit_SlidingWindow covers that).
	cfg.Window = time.Minute
	cfg.PerUser = true

	router := gin.New()
	// Add middleware to simulate auth middleware setting user_id BEFORE rate limiting
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Next()
	})
	router.Use(SlidingWindowRateLimit(client, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Authenticated user gets higher limit", func(t *testing.T) {
		// User can make 10 requests (user limit)
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.10:1234"
			router.ServeHTTP(w, req)

			assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
		}

		// 11th request should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.10:1234"
		router.ServeHTTP(w, req)
		assert.Equal(t, 429, w.Code)
	})
}

func TestSlidingWindowRateLimit_SlidingWindow(t *testing.T) {
	s, client := setupTestRedis(t)
	defer s.Close()

	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 3
	cfg.Window = 2 * time.Second // Use at least 1 second since time.Now().Unix() is second granularity

	router := gin.New()
	router.Use(SlidingWindowRateLimit(client, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Window slides correctly", func(t *testing.T) {
		// Make 3 requests (at limit)
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "172.16.0.1:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// 4th should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "172.16.0.1:1234"
		router.ServeHTTP(w, req)
		assert.Equal(t, 429, w.Code)

		// Wait for the window to expire (use real time since rate limiter uses time.Now())
		time.Sleep(2 * time.Second)

		// Should be allowed again
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "172.16.0.1:1234"
		router.ServeHTTP(w2, req2)
		assert.Equal(t, 200, w2.Code)
	})
}

func TestSlidingWindowRateLimit_SkipPaths(t *testing.T) {
	s, client := setupTestRedis(t)
	defer s.Close()

	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 1
	cfg.Window = time.Minute // counting only — see TestSlidingWindowRateLimit_IPBased
	cfg.SkipPaths = []string{"/health", "/metrics"}

	router := gin.New()
	router.Use(SlidingWindowRateLimit(client, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "test")
	})
	router.GET("/health", func(c *gin.Context) {
		c.String(200, "healthy")
	})
	router.GET("/metrics", func(c *gin.Context) {
		c.String(200, "metrics")
	})

	t.Run("Skips health endpoint", func(t *testing.T) {
		// Should not be rate limited
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/health", nil)
			req.RemoteAddr = "10.1.1.1:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}
	})

	t.Run("Skips metrics endpoint", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/metrics", nil)
			req.RemoteAddr = "10.1.1.2:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}
	})

	t.Run("Rate limits other endpoints", func(t *testing.T) {
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "10.1.1.3:1234"
		router.ServeHTTP(w1, req1)
		assert.Equal(t, 200, w1.Code)

		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "10.1.1.3:1234"
		router.ServeHTTP(w2, req2)
		assert.Equal(t, 429, w2.Code)
	})
}

func TestSlidingWindowRateLimit_NoRedis(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 1

	router := gin.New()
	router.Use(SlidingWindowRateLimit(nil, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Fails open when Redis is nil", func(t *testing.T) {
		// Should allow all requests when Redis is not available
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "1.2.3.4:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}
	})
}

func TestSlidingWindowRateLimit_RateLimitHeaders(t *testing.T) {
	s, client := setupTestRedis(t)
	defer s.Close()

	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 10
	cfg.Window = time.Minute // counting only — see TestSlidingWindowRateLimit_IPBased

	router := gin.New()
	router.Use(SlidingWindowRateLimit(client, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Sets rate limit headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "5.6.7.8:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, "10", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "9", w.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Window"))
	})
}

func TestSlidingWindowRateLimit_RedisTimeout(t *testing.T) {
	s, client := setupTestRedis(t)
	defer s.Close()

	cfg := DefaultRateLimitConfig()
	cfg.IPRequestsPerMin = 1
	cfg.Window = time.Second

	// Close miniredis to simulate timeout
	s.Close()

	router := gin.New()
	router.Use(SlidingWindowRateLimit(client, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Handles Redis errors gracefully", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		router.ServeHTTP(w, req)

		// Should fail open
		assert.Equal(t, 200, w.Code)
	})
}

func TestDefaultRateLimitConfig(t *testing.T) {
	cfg := DefaultRateLimitConfig()

	assert.Equal(t, 100, cfg.IPRequestsPerMin)
	assert.Equal(t, 200, cfg.UserRequestsPerMin)
	assert.Equal(t, time.Minute, cfg.Window)
	assert.True(t, cfg.PerUser)
	assert.Contains(t, cfg.SkipPaths, "/health")
}
