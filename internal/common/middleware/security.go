package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityConfig holds configuration for security headers middleware
type SecurityConfig struct {
	// HSTSEnabled enables Strict-Transport-Security header (recommended for production)
	HSTSEnabled bool
	// CSPEnabled enables Content-Security-Policy header
	CSPEnabled bool
	// FrameOptions sets X-Frame-Options: DENY, SAMEORIGIN, or ALLOW-FROM
	FrameOptions string
	// CSPCustom allows specifying a custom CSP policy instead of the default
	CSPCustom string
	// CSPPathOverrides relaxes (or tightens) the policy for specific path
	// prefixes. The first matching prefix wins, so order is significant.
	//
	// This exists because a single application-wide policy cannot serve both
	// our own UI and an embedded third-party console with different needs.
	// Keep the entries as narrow as possible: every override is a hole in the
	// mitigation for exactly the paths it names.
	CSPPathOverrides []CSPPathOverride
}

// CSPPathOverride applies Policy to requests whose path starts with Prefix.
type CSPPathOverride struct {
	Prefix string
	Policy string
}

// GuacamoleCSP is the policy for the embedded Apache Guacamole console.
//
// Measured in headless Chrome against the live broker on 127.0.0.1:10090
// (2026-08-14), varying only this header and keeping every other byte of the
// response identical:
//
//	no CSP                                -> 0 EvalError, page renders
//	the policy we ship today              -> 4 EvalError, page body EMPTY
//	+ 'unsafe-eval'                       -> 0 EvalError, page renders
//	+ 'unsafe-eval', no 'unsafe-inline'   -> 0 EvalError, page renders
//	+ 'unsafe-eval', frame-ancestors none -> 0 EvalError, page renders
//
// Guacamole ships AngularJS 1.8.3, which compiles $parse expressions with the
// Function constructor. Angular does try to detect CSP first, but that
// detection only honours the ng-csp attribute, and Guacamole's index.html
// does not set it (measured: 0 occurrences). So Angular takes the compiling
// path, the browser refuses it, and the user gets a blank page rather than a
// degraded one.
//
// The last two measurements are why this policy grants nothing else:
//
//   - 'unsafe-inline' is omitted because the console renders without it, and
//     inline script is the directive that actually matters for XSS.
//   - frame-ancestors stays 'none' because the console is launched with
//     window.open (pam-connections.tsx:219), never embedded in an iframe, so
//     clickjacking protection costs us nothing here.
//
// The net difference from the application-wide policy is one token:
// 'unsafe-eval', on two paths. Everything else is identical or stricter.
const GuacamoleCSP = "default-src 'self'; script-src 'self' 'unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; " +
	"connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// GuacamolePathPrefixes are the paths the embedded console is served under.
// Measured live on 2026-08-14: the direct broker answers on /guacamole/ and
// the overlay broker on /guacamole-ziti/, and both received the strict policy
// that blanked AngularJS.
var GuacamolePathPrefixes = []string{"/guacamole/", "/guacamole-ziti/"}

// GuacamoleCSPOverrides returns the per-path overrides for the embedded
// console, so callers do not have to assemble the pair by hand.
func GuacamoleCSPOverrides() []CSPPathOverride {
	out := make([]CSPPathOverride, 0, len(GuacamolePathPrefixes))
	for _, p := range GuacamolePathPrefixes {
		out = append(out, CSPPathOverride{Prefix: p, Policy: GuacamoleCSP})
	}
	return out
}

// DefaultSecurityConfig returns a SecurityConfig with secure defaults
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		HSTSEnabled:  true,
		CSPEnabled:   true,
		FrameOptions: "DENY",
		CSPCustom:    "",
	}
}

// SecurityHeaders returns middleware that sets standard security response headers.
// All headers except HSTS and CSP are set by default as they're low-risk.
// HSTS and CSP can be enabled/disabled via configuration.
func SecurityHeaders(cfg SecurityConfig) gin.HandlerFunc {
	// Validate FrameOptions
	frameOpts := cfg.FrameOptions
	upper := strings.ToUpper(frameOpts)
	if upper == "DENY" || upper == "SAMEORIGIN" {
		frameOpts = upper
	} else if strings.HasPrefix(upper, "ALLOW-FROM") {
		// Preserve the URL portion after ALLOW-FROM
		frameOpts = "ALLOW-FROM" + frameOpts[len("ALLOW-FROM"):]
	} else {
		frameOpts = "DENY" // Default to most secure
	}

	return func(c *gin.Context) {
		// X-Content-Type-Options: Prevents MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// X-Frame-Options: Prevents clickjacking
		c.Header("X-Frame-Options", frameOpts)

		// X-XSS-Protection: Enables browser XSS filter (legacy but still useful)
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy: Controls referrer information sent
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions-Policy: Restricts browser features
		// Disables geolocation, microphone, and camera by default
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Strict-Transport-Security: Enforces HTTPS (only enable in production/TLS)
		if cfg.HSTSEnabled && c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Content-Security-Policy: Controls resources the browser can load
		if cfg.CSPEnabled {
			csp := cfg.CSPCustom
			if csp == "" {
				// Default CSP if no custom policy provided
				csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
			}
			// Some embedded consoles need a different policy from the rest
			// of the app; see GuacamoleCSP. Per-path on purpose: widening the
			// whole application to fix one console would trade a UI bug for a
			// real XSS mitigation.
			if len(cfg.CSPPathOverrides) > 0 {
				path := c.Request.URL.Path
				for _, o := range cfg.CSPPathOverrides {
					if o.Prefix != "" && strings.HasPrefix(path, o.Prefix) {
						csp = o.Policy
						break
					}
				}
			}
			c.Header("Content-Security-Policy", csp)
		}

		c.Next()
	}
}

// SecurityHeadersProduction is a convenience function that returns middleware
// configured for production environments (all security headers enabled)
func SecurityHeadersProduction() gin.HandlerFunc {
	return SecurityHeaders(SecurityConfig{
		HSTSEnabled:  true,
		CSPEnabled:   true,
		FrameOptions: "DENY",
		CSPCustom:    CSPCustomFromEnv(),
		// Without this the embedded Guacamole console renders a blank page
		// under our own policy. See GuacamoleCSP for the measurements.
		CSPPathOverrides: GuacamoleCSPOverrides(),
	})
}

// SecurityHeadersDevelopment returns middleware configured for development
// with HSTS disabled (since dev typically doesn't use TLS)
func SecurityHeadersDevelopment() gin.HandlerFunc {
	return SecurityHeaders(SecurityConfig{
		HSTSEnabled:      false,
		CSPEnabled:       true,
		FrameOptions:     "DENY",
		CSPCustom:        CSPCustomFromEnv(),
		CSPPathOverrides: GuacamoleCSPOverrides(),
	})
}

// CSPCustomEnvVar overrides the application-wide policy at runtime.
//
// CSPCustom used to be a dead field: it was only ever assigned in
// security_test.go, so no deployment could change the policy without a
// rebuild. That is the same shape of defect as a pipeline flag whose value is
// hardcoded in the step that reads it -- the knob exists, the documentation
// describes it, and nothing can actually turn it.
//
// Leave the variable unset to keep the secure default. It is read once at
// startup so the policy cannot change under a running process.
const CSPCustomEnvVar = "OPENIDX_CSP_POLICY"

// CSPCustomFromEnv returns the operator-supplied policy, or "" for the default.
func CSPCustomFromEnv() string {
	return strings.TrimSpace(os.Getenv(CSPCustomEnvVar))
}

// SecurityHeadersForEnv returns the appropriate security headers middleware based on environment
func SecurityHeadersForEnv(isProduction bool) gin.HandlerFunc {
	if isProduction {
		return SecurityHeadersProduction()
	}
	return SecurityHeadersDevelopment()
}

// CustomFrameOptions creates a middleware that sets a custom X-Frame-Options
// value for specific endpoints that need to be embedded (e.g., SAMEORIGIN for iframes)
func CustomFrameOptions(frameOption string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", frameOption)
		c.Next()
	}
}

// CustomCSP creates a middleware that sets a custom Content-Security-Policy
// for specific endpoints that need different policies
func CustomCSP(csp string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", csp)
		c.Next()
	}
}
