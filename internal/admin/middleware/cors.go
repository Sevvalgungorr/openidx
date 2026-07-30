// Package middleware provides CORS middleware for admin console frontend
package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Config holds CORS configuration
type Config struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultConfig returns default CORS configuration for development
func DefaultConfig() *Config {
	return &Config{
		AllowedOrigins: []string{
			"http://localhost:5173",
			"http://localhost:3000",
			"http://127.0.0.1:5173",
			"http://127.0.0.1:3000",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Origin",
			"Content-Type",
			"Authorization",
			"X-Request-ID",
			"Accept",
			"X-Tenant-ID",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-Total-Count",
			"Content-Range",
		},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

// ProductionConfig returns CORS configuration for production
func ProductionConfig(allowedOrigins []string) *Config {
	return &Config{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID", "X-Total-Count"},
		AllowCredentials: true,
		MaxAge:           86400,
	}
}

// CORSMiddleware returns a Gin middleware for handling CORS
func CORSMiddleware(cfg *Config) gin.HandlerFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Normalize methods to uppercase
	normalizedMethods := make([]string, len(cfg.AllowedMethods))
	for i, m := range cfg.AllowedMethods {
		normalizedMethods[i] = strings.ToUpper(m)
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow requests with no Origin header (non-browser requests like health checks, cron jobs)
		if origin == "" {
			c.Next()
			return
		}

		// Check if origin is allowed
		allowed := false
		allowedOrigin := ""
		for _, allowedOriginPattern := range cfg.AllowedOrigins {
			if allowedOriginPattern == "*" || allowedOriginPattern == origin {
				allowed = true
				allowedOrigin = allowedOriginPattern
				break
			}
			// Support wildcard subdomains (e.g., *.example.com)
			if strings.HasPrefix(allowedOriginPattern, "*.") {
				domain := strings.TrimPrefix(allowedOriginPattern, "*.")
				if strings.HasSuffix(origin, "."+domain) || origin == domain {
					allowed = true
					allowedOrigin = origin // Echo back the specific origin
					break
				}
			}
		}

		if !allowed {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Set CORS headers
		if allowedOrigin == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			c.Header("Access-Control-Allow-Origin", allowedOrigin)
			c.Header("Vary", "Origin")
		}

		c.Header("Access-Control-Allow-Methods", strings.Join(normalizedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
		c.Header("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
		c.Header("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))

		if cfg.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// CORS is a convenience function that returns CORS middleware with default config
func CORS(allowedOrigins ...string) gin.HandlerFunc {
	cfg := DefaultConfig()
	if len(allowedOrigins) > 0 {
		cfg.AllowedOrigins = allowedOrigins
	}
	return CORSMiddleware(cfg)
}
