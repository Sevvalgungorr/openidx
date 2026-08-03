package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ConfigureTrustedProxies restricts which upstream hops gin will believe when it
// resolves the client IP from X-Forwarded-For.
//
// Why this matters (security): gin's DEFAULT trusts ALL proxies, so it reads the
// LEFTMOST X-Forwarded-For entry as the client IP. Since any HTTP client can send
// an arbitrary X-Forwarded-For header, c.ClientIP() is attacker-controllable by
// default. That IP feeds device-trust "known IP" auto-approval, geo/country
// blocking, risk scoring, rate limiting, and audit records — all of which become
// spoofable. An attacker could, for example, send "X-Forwarded-For: <corp IP>"
// to get an untrusted device auto-approved.
//
// In this deployment every service sits behind the edge (APISIX/nginx) and is
// reached over loopback (127.0.0.1). By trusting ONLY the loopback proxy, gin
// walks the XFF list right-to-left and stops at the first address that is NOT a
// trusted proxy — i.e. the real client IP that the edge appended via
// $proxy_add_x_forwarded_for — ignoring any client-supplied leftmost entries.
//
// The trusted set is overridable via OIDX_TRUSTED_PROXIES (comma-separated CIDRs
// or IPs) for deployments where the edge is not on loopback. Setting it to "*"
// restores gin's trust-all behavior (NOT recommended). An empty/unset value uses
// the secure loopback default.
func ConfigureTrustedProxies(router *gin.Engine, logger *zap.Logger) {
	proxies := defaultTrustedProxies()

	if env := strings.TrimSpace(os.Getenv("OIDX_TRUSTED_PROXIES")); env != "" {
		if env == "*" {
			// Explicit opt-out: trust all proxies (leftmost XFF). Loud warning.
			if logger != nil {
				logger.Warn("OIDX_TRUSTED_PROXIES=* : trusting ALL proxies; c.ClientIP() is spoofable via X-Forwarded-For")
			}
			if err := router.SetTrustedProxies(nil); err != nil && logger != nil {
				logger.Error("failed to clear trusted proxies", zap.Error(err))
			}
			// nil trusted proxies with default forwarded header still trusts all;
			// keep gin's default behavior by returning here.
			return
		}
		var parsed []string
		for _, p := range strings.Split(env, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parsed = append(parsed, p)
			}
		}
		if len(parsed) > 0 {
			proxies = parsed
		}
	}

	if err := router.SetTrustedProxies(proxies); err != nil {
		if logger != nil {
			logger.Error("failed to set trusted proxies; falling back to loopback only", zap.Error(err))
		}
		_ = router.SetTrustedProxies(defaultTrustedProxies())
		return
	}
	if logger != nil {
		logger.Info("trusted proxies configured (client IP resolved from X-Forwarded-For only for these hops)",
			zap.Strings("trusted_proxies", proxies))
	}
}

// defaultTrustedProxies returns the loopback ranges the edge proxy connects from.
func defaultTrustedProxies() []string {
	return []string{"127.0.0.1/32", "::1/128"}
}
