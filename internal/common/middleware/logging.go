// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultSanitizedFields contains default sensitive field names to redact
var DefaultSanitizedFields = []string{
	"password", "token", "secret", "key", "api_key", "access_token",
	"refresh_token", "authorization", "bearer", "credentials",
	"client_secret", "private_key", "passphrase", "otp", "ssn",
}

// LoggingConfig holds configuration options for request logging
type LoggingConfig struct {
	// LogBody enables logging of request body for POST/PUT/PATCH requests
	LogBody bool

	// LogQueryParams enables logging of URL query parameters
	LogQueryParams bool

	// SanitizeFields contains field names to redact from logs
	SanitizeFields []string

	// MinDuration specifies minimum request duration to log (only log slow requests)
	// If zero, all requests are logged
	MinDuration time.Duration

	// EnableTracing enables distributed tracing integration
	EnableTracing bool

	// Logger is the zap logger instance
	Logger *zap.Logger
}

// DefaultLoggingConfig returns a LoggingConfig with sensible defaults
func DefaultLoggingConfig(logger *zap.Logger) LoggingConfig {
	return LoggingConfig{
		LogBody:        false,
		LogQueryParams: true,
		SanitizeFields: DefaultSanitizedFields,
		MinDuration:    0,
		EnableTracing:  false,
		Logger:         logger,
	}
}

// RequestLogger returns a middleware that logs HTTP requests with comprehensive information
// including request ID, user ID, duration, status, size, client IP, user-agent,
// sanitized query parameters, and sanitized request body for POST/PUT/PATCH
func RequestLogger(logger *zap.Logger) gin.HandlerFunc {
	return RequestLoggerWithConfig(DefaultLoggingConfig(logger))
}

// RequestLoggerWithConfig returns a middleware with custom logging configuration
func RequestLoggerWithConfig(config LoggingConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	// Ensure sanitized fields are lowercased for case-insensitive matching
	sanitizeFields := make(map[string]bool)
	for _, field := range config.SanitizeFields {
		sanitizeFields[strings.ToLower(field)] = true
	}

	return func(c *gin.Context) {
		start := time.Now()

		// Generate or retrieve request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Store request ID in context for retrieval in handlers
		c.Set("request_id", requestID)

		// Set response header for tracing
		c.Header("X-Request-ID", requestID)

		// Capture request body for POST/PUT/PATCH if enabled
		var requestBody string
		if config.LogBody && (c.Request.Method == http.MethodPost ||
			c.Request.Method == http.MethodPut ||
			c.Request.Method == http.MethodPatch) {

			// Read body
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			c.Request.Body.Close()

			// Restore body for subsequent handlers
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Decompress if gzip encoded
			if strings.Contains(c.Request.Header.Get("Content-Encoding"), "gzip") {
				gzReader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
				if err == nil {
					decompressed, _ := io.ReadAll(gzReader)
					gzReader.Close()
					requestBody = string(decompressed)
				} else {
					requestBody = string(bodyBytes)
				}
			} else {
				requestBody = string(bodyBytes)
			}

			// Truncate body if too large (limit to 10KB)
			const maxBodySize = 10 * 1024
			if len(requestBody) > maxBodySize {
				requestBody = requestBody[:maxBodySize] + "... (truncated)"
			}

			// Sanitize sensitive fields in request body
			requestBody = sanitizeJSON(requestBody, sanitizeFields)
		}

		// Prepare log fields before processing
		fields := []zapcore.Field{
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", getClientIP(c)),
			zap.String("user_agent", c.Request.UserAgent()),
		}

		// Add query parameters if enabled
		if config.LogQueryParams && c.Request.URL.RawQuery != "" {
			sanitizedQuery := sanitizeQueryParams(c.Request.URL.RawQuery, sanitizeFields)
			fields = append(fields, zap.String("query_params", sanitizedQuery))
		}

		// Add request body if enabled and present
		if config.LogBody && requestBody != "" {
			fields = append(fields, zap.String("request_body", requestBody))
		}

		// Add user ID from context if authenticated (set by Auth middleware)
		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, zap.String("user_id", toString(userID)))
		}

		// Add session ID if present
		if sessionID, exists := c.Get("session_id"); exists {
			fields = append(fields, zap.String("session_id", toString(sessionID)))
		}

		// Add service account ID if API key auth
		if saID, exists := c.Get("service_account_id"); exists {
			fields = append(fields, zap.String("service_account_id", toString(saID)))
		}

		// Add organization ID if present
		if orgID, exists := c.Get("org_id"); exists {
			fields = append(fields, zap.String("org_id", toString(orgID)))
		}

		// Add auth method if present
		if authMethod, exists := c.Get("auth_method"); exists {
			fields = append(fields, zap.String("auth_method", toString(authMethod)))
		}

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Check minimum duration threshold
		if config.MinDuration > 0 && duration < config.MinDuration {
			return // Skip logging for fast requests
		}

		// Add response fields
		status := c.Writer.Status()
		fields = append(fields,
			zap.Int("status", status),
			zap.Duration("duration", duration),
			zap.Int("response_size", c.Writer.Size()),
		)

		// Add error message if present
		if len(c.Errors) > 0 {
			errors := make([]string, len(c.Errors))
			for i, err := range c.Errors {
				errors[i] = err.Error()
			}
			fields = append(fields, zap.Strings("errors", errors))
		}

		// Determine log level based on status code and duration
		logLevel := determineLogLevel(status, duration, config.MinDuration)

		// Log the request
		msg := formatLogMessage(c, duration)
		config.Logger.Log(logLevel, msg, fields...)
	}
}

// getClientIP returns the real client IP for logging.
//
// SECURITY: this used to read the LEFTMOST X-Forwarded-For entry directly, which
// is entirely attacker-controllable (any client can send an arbitrary
// X-Forwarded-For), letting an attacker forge the client IP in audit/access logs
// and defeating the whole point of recording it. We now delegate to
// c.ClientIP(), which honors the engine's trusted-proxy configuration
// (ConfigureTrustedProxies) and resolves the real client IP the trusted edge saw
// rather than any client-supplied header. Do NOT reintroduce raw header parsing.
func getClientIP(c *gin.Context) string {
	return c.ClientIP()
}

// sanitizeQueryParams redacts sensitive values from query parameters
func sanitizeQueryParams(query string, sensitiveFields map[string]bool) string {
	if query == "" {
		return ""
	}

	params := strings.Split(query, "&")
	sanitized := make([]string, 0, len(params))

	for _, param := range params {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) != 2 {
			sanitized = append(sanitized, param)
			continue
		}

		key := strings.ToLower(parts[0])
		if sensitiveFields[key] {
			sanitized = append(sanitized, parts[0]+"=***REDACTED***")
		} else {
			sanitized = append(sanitized, param)
		}
	}

	return strings.Join(sanitized, "&")
}

// sanitizeJSON redacts sensitive field values in JSON strings
func sanitizeJSON(jsonStr string, sensitiveFields map[string]bool) string {
	// Simple JSON sanitization - replaces sensitive field values
	// This is a basic implementation; for production use, consider using
	// proper JSON parsing with streaming to handle large payloads

	result := jsonStr
	for field := range sensitiveFields {
		// Replace values for keys like "password":"value"
		// Handle both quoted and unquoted variations
		patterns := []string{
			`"` + field + `":"`,
			`"` + field + `": "`,
			`"` + field + `":"`,
			`"` + field + `":"`,
			`"` + field + `":"`,
		}

		for _, pattern := range patterns {
			if strings.Contains(result, pattern) {
				// Find the value and replace it
				// This is a simplified approach - for robust sanitization,
				// use json.Decoder with custom handling
				result = redactFieldValue(result, pattern)
			}
		}
	}

	return result
}

// redactFieldValue replaces sensitive field values with REDACTED
func redactFieldValue(jsonStr, keyPattern string) string {
	// Find the key pattern position
	idx := strings.Index(jsonStr, keyPattern)
	if idx == -1 {
		return jsonStr
	}

	// Start after the key pattern
	start := idx + len(keyPattern)
	end := start

	// Find the closing quote or end of value
	for end < len(jsonStr) {
		if jsonStr[end] == '"' && jsonStr[end-1] != '\\' {
			break
		}
		end++
	}

	if end >= len(jsonStr) {
		return jsonStr
	}

	// Replace the value
	return jsonStr[:start] + "***REDACTED***" + jsonStr[end:]
}

// determineLogLevel returns the appropriate log level based on status and duration
func determineLogLevel(status int, duration, minDuration time.Duration) zapcore.Level {
	// Server errors (5xx)
	if status >= 500 {
		return zapcore.ErrorLevel
	}

	// Client errors (4xx)
	if status >= 400 {
		return zapcore.WarnLevel
	}

	// Slow requests (if min duration is set, very slow requests get warning)
	if minDuration > 0 && duration > minDuration*5 {
		return zapcore.WarnLevel
	}

	return zapcore.InfoLevel
}

// formatLogMessage creates a human-readable log message
func formatLogMessage(c *gin.Context, duration time.Duration) string {
	status := c.Writer.Status()

	// Handle errors
	if len(c.Errors) > 0 {
		return "Request completed with errors"
	}

	// Server errors
	if status >= 500 {
		return "Server error"
	}

	// Client errors
	if status >= 400 {
		return "Client error"
	}

	// Redirects
	if status >= 300 {
		return "Redirect"
	}

	// Success with performance indication
	if duration > time.Second {
		return "Request completed (slow)"
	}
	if duration > 500*time.Millisecond {
		return "Request completed (moderate latency)"
	}

	return "Request completed"
}

// toString converts various types to string safely
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return string(rune(val))
	case int64:
		return string(rune(val))
	case float64:
		return string(rune(val))
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
