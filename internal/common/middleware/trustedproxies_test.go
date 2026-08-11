package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestConfigureTrustedProxies_IgnoresSpoofedLeftmostXFF is the security
// regression: with only loopback trusted, a client-supplied leftmost
// X-Forwarded-For entry must NOT be honored as the client IP. gin should resolve
// the rightmost untrusted address (the real remote_addr the edge saw).
func TestConfigureTrustedProxies_IgnoresSpoofedLeftmostXFF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("OIDX_TRUSTED_PROXIES", "") // use secure loopback default

	r := gin.New()
	ConfigureTrustedProxies(r, nil)

	var got string
	r.GET("/ip", func(c *gin.Context) {
		got = c.ClientIP()
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	// Simulate the edge (loopback) appending the real client IP after the
	// attacker's spoofed value: attacker sent 198.51.100.7, real remote is 203.0.113.9.
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")
	req.RemoteAddr = "127.0.0.1:12345" // connection comes from the trusted edge
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got == "198.51.100.7" {
		t.Fatalf("spoofed leftmost X-Forwarded-For was honored as client IP (got %q); auto-approve/geo-block bypass", got)
	}
	if got != "203.0.113.9" {
		t.Fatalf("expected real client IP 203.0.113.9, got %q", got)
	}
}

// TestConfigureTrustedProxies_UntrustedDirectClientNotSpoofable verifies that a
// direct (non-loopback) caller cannot inject a client IP at all: gin falls back
// to the real RemoteAddr and ignores the header.
func TestConfigureTrustedProxies_UntrustedDirectClientNotSpoofable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("OIDX_TRUSTED_PROXIES", "")

	r := gin.New()
	ConfigureTrustedProxies(r, nil)

	var got string
	r.GET("/ip", func(c *gin.Context) {
		got = c.ClientIP()
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.RemoteAddr = "198.51.100.7:9999" // untrusted direct client
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got != "198.51.100.7" {
		t.Fatalf("untrusted client should resolve to RemoteAddr 198.51.100.7, got %q", got)
	}
}
