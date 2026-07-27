package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/middleware"
)

// darkEnrollRequest is the body of POST /api/v1/access/enroll.
type darkEnrollRequest struct {
	// EnrollmentToken is an admin/MDM-issued token (agent_enrollment_tokens).
	EnrollmentToken string `json:"enrollment_token"`
	// Passkey is a platform-authenticator assertion (device recovery). Not yet
	// verifiable in access-service; callers should use a session or token.
	Passkey map[string]interface{} `json:"passkey"`
}

// handleEnroll is the Tier-0 "dark platform" front door. It is the ONLY
// access-service route that stays public when the platform goes dark: it trades
// an entitlement proof for a one-time OpenZiti enrollment JWT so a native client
// (mobile/desktop tunnel) can join the overlay and reach everything else.
//
// Entitlement, in priority order:
//  1. a verified session (Authorization: Bearer, checked against the OAuth JWKS)
//     — self-service: an already-logged-in user enrolls a device of their own;
//  2. an admin/MDM enrollment token (agent_enrollment_tokens);
//  3. (future) a passkey assertion — not yet verifiable here.
//
// It never browses data; it only mints/returns a Ziti enrollment JWT and audits
// the issuance. See docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md §4.
func (s *Service) handleEnroll(c *gin.Context) {
	var req darkEnrollRequest
	_ = c.ShouldBindJSON(&req)

	subject, method, err := s.resolveEnrollSubject(c, &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	jwt, name, err := s.mintZitiEnrollmentJWT(c.Request.Context(), subject)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("enroll: mint ziti enrollment jwt", err), s.logger)
		return
	}

	s.logAuditEvent(c, "access.enroll", name, "ziti_identity", map[string]interface{}{
		"method":  method,
		"subject": subject,
		"outcome": "success",
	})
	s.logger.Info("dark-mode enroll issued", zap.String("subject", subject), zap.String("method", method), zap.String("identity", name))

	c.JSON(http.StatusOK, gin.H{
		"ziti_enrollment_jwt": jwt,
		"identity_name":       name,
	})
}

// errNoEntitlement is returned when a caller presents no valid session, token,
// or (future) passkey. Exposed as a sentinel so the handler/tests can assert it.
type enrollError struct{ msg string }

func (e enrollError) Error() string { return e.msg }

// resolveEnrollSubject determines whose Ziti identity to mint, from (in order) a
// verified bearer session, an enrollment token, or a passkey. Returns the
// subject id (a user_id for the session path, or an enrollment-token-derived
// identity name), the method used ("session"|"token"), and an error when no
// entitlement is present. This is the security-critical gate; keep it small.
func (s *Service) resolveEnrollSubject(c *gin.Context, req *darkEnrollRequest) (subject, method string, err error) {
	// 1. Verified session (bearer). Reuses the same JWKS verification as the
	//    proxy's getSessionFromBearer — a forged/unsigned token yields nothing.
	if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if claims, verr := middleware.VerifyBearerToken(s.oauthJWKSURL, token); verr == nil {
			if sub, _ := claims["sub"].(string); sub != "" {
				return sub, "session", nil
			}
		}
	}

	// 2. Admin/MDM enrollment token.
	if req.EnrollmentToken != "" {
		uid, terr := s.validateEnrollmentToken(c.Request.Context(), req.EnrollmentToken)
		if terr != nil {
			return "", "", enrollError{"invalid enrollment token"}
		}
		return uid, "token", nil
	}

	// 3. Passkey — deferred (see doc §12). Reject clearly rather than fake it.
	if len(req.Passkey) > 0 {
		return "", "", enrollError{"passkey enrollment not supported here yet — use a session or enrollment token"}
	}

	return "", "", enrollError{"entitlement required (session, enrollment_token, or passkey)"}
}

// validateEnrollmentToken checks an enrollment token against
// agent_enrollment_tokens (not-expired, not-revoked, single-use unless reusable)
// and returns the subject to enroll. It mirrors HandleEnroll's token check;
// single-use tokens are marked consumed. The returned subject is the token's
// created_by (the user the token was issued for) when present, else the token id
// as a device-identity name.
func (s *Service) validateEnrollmentToken(ctx context.Context, token string) (string, error) {
	incomingHash := sha256Hex(token)
	var (
		tokenID   string
		createdBy *string
		expiresAt interface{}
		usedAt    interface{}
		revoked   bool
	)
	// Use a lightweight scan; reusability handling matches HandleEnroll.
	var reusable bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, created_by, expires_at, used_at, revoked, COALESCE(reusable, false)
		FROM agent_enrollment_tokens WHERE token_hash = $1
	`, incomingHash).Scan(&tokenID, &createdBy, &expiresAt, &usedAt, &revoked, &reusable)
	if err != nil {
		return "", err
	}
	if revoked {
		return "", enrollError{"enrollment token revoked"}
	}
	if !reusable && usedAt != nil {
		return "", enrollError{"enrollment token already used"}
	}
	if !reusable {
		_, _ = s.db.Pool.Exec(ctx, `UPDATE agent_enrollment_tokens SET used_at = NOW() WHERE id = $1`, tokenID)
	}
	if createdBy != nil && *createdBy != "" {
		return *createdBy, nil
	}
	return "enroll-" + tokenID, nil
}

// mintZitiEnrollmentJWT ensures the subject has a Ziti identity and returns its
// one-time enrollment JWT + identity name. It first looks up an existing
// identity (the common case — the user-sync engine already mirrors every user),
// and only runs a sync when the subject has none yet. The JWT comes from the
// stored value or the controller. Mirrors handleGetMyZitiIdentity so it avoids
// the heavier/full sync path for already-synced users.
func (s *Service) mintZitiEnrollmentJWT(ctx context.Context, subject string) (jwt, name string, err error) {
	zm := s.ziti()
	if zm == nil {
		return "", "", enrollError{"ziti overlay not configured"}
	}

	// Look up an existing identity for this subject (user_id).
	var zitiID string
	var stored *string
	lookupErr := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore ziti_identities is keyed by the globally-unique user_id (OIDC subject); a Ziti identity is per-user, not per-org
		"SELECT ziti_id, enrollment_jwt FROM ziti_identities WHERE user_id = $1",
		subject).Scan(&zitiID, &stored)

	if lookupErr != nil {
		// No identity yet — create one via the sync engine (first-time enroll).
		res, serr := zm.SyncUserToZiti(ctx, subject)
		if serr != nil {
			return "", "", serr
		}
		zitiID = res.ZitiID
		// re-read the freshly stored JWT if present
		_ = s.db.Pool.QueryRow(ctx,
			//orgscope:ignore ziti_identities.ziti_id is a globally-unique controller identity id, not org-scoped
			"SELECT enrollment_jwt FROM ziti_identities WHERE ziti_id = $1", zitiID).Scan(&stored)
	}

	name = subject
	// A stored JWT is only good while its embedded expiry is still in the future.
	// The controller mints one-time enrollment tokens (OTT) with a short life; a
	// device that enrolls weeks later must NOT be handed the long-expired copy we
	// cached at identity-creation time. If the stored token is missing or expired,
	// re-issue a fresh OTT and persist it. (This is the mobile "JWT expired 31 days
	// ago" bug: the backend kept returning the same stale JWT every call.)
	//
	// A non-expired token can still be UNUSABLE: if it was minted while the
	// controller advertised an internal-only name (e.g. ziti-controller.localtest.me
	// -> 127.0.0.1 on a phone) its `iss`/`ctrls` send the client back to itself.
	// When ZITI_CTRL_PUBLIC_ADDRESS is configured we also re-issue on that address
	// mismatch so a mobile device always gets a reachable controller address.
	publicAddr := s.config.ZitiCtrlPublicAddress
	if stored != nil && *stored != "" && !enrollmentJWTExpired(*stored) &&
		!enrollmentJWTAddressStale(*stored, publicAddr) {
		return *stored, name, nil
	}

	// Try the controller's current OTT first; if none is pending (already consumed
	// or lapsed) re-enroll to mint a fresh one. Re-issue when the controller's copy
	// is missing, expired, OR carries a stale (internal-only) controller address.
	jwt, err = zm.GetIdentityEnrollmentJWT(ctx, zitiID)
	if err != nil || jwt == "" || enrollmentJWTExpired(jwt) || enrollmentJWTAddressStale(jwt, publicAddr) {
		fresh, rerr := zm.ReEnrollIdentity(ctx, zitiID)
		if rerr != nil {
			// If we have no usable token at all, surface the refresh error;
			// otherwise fall through with whatever non-empty (but possibly
			// stale) jwt we managed to read.
			if jwt == "" {
				return "", "", fmt.Errorf("mint fresh ziti enrollment jwt: %w", rerr)
			}
		} else {
			jwt = fresh
		}
	}
	if jwt == "" {
		return "", "", enrollError{"no enrollment JWT could be minted for identity"}
	}

	// Persist the fresh JWT so subsequent reads are consistent (best-effort).
	_, _ = s.db.Pool.Exec(ctx,
		//orgscope:ignore ziti_identities.ziti_id is a globally-unique controller identity id, not org-scoped
		"UPDATE ziti_identities SET enrollment_jwt = $1 WHERE ziti_id = $2", jwt, zitiID)

	return jwt, name, nil
}

// enrollmentJWTExpired reports whether an OTT enrollment JWT is expired (or so
// malformed we can't trust it). It parses WITHOUT verifying the signature — the
// token is issued by our own controller and we only need its `exp` to decide
// whether to reissue; a parse failure is treated as expired so we re-mint rather
// than hand out a broken token. A token expiring within a small skew is also
// treated as expired so a device isn't handed one about to lapse mid-enrollment.
func enrollmentJWTExpired(token string) bool {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil || parsed == nil {
		return true
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return true
	}
	expRaw, ok := claims["exp"]
	if !ok {
		return true
	}
	var exp int64
	switch v := expRaw.(type) {
	case float64:
		exp = int64(v)
	case int64:
		exp = v
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return true
		}
		exp = n
	default:
		return true
	}
	// 60s skew: don't hand out a token that lapses during enrollment.
	return time.Now().Add(60 * time.Second).After(time.Unix(exp, 0))
}

// enrollmentJWTAddressStale reports whether an OTT enrollment JWT points a client
// at a controller address that does NOT match wantAddr (host or host:port). The
// JWT carries the controller's advertised address in `iss` (a URL) and `ctrls`
// (tls:host:port entries); a device uses those to dial the fabric. If the token
// was minted while the controller advertised an internal-only name (e.g.
// ziti-controller.localtest.me, which a phone resolves to 127.0.0.1) it is
// unusable off-box even though it hasn't expired, so we treat it as stale and
// re-issue.
//
// wantAddr empty disables the check (returns false): single-host/dev installs
// where the advertised name is already reachable. Parsing failures are treated
// as NOT stale here so a malformed token is still caught by enrollmentJWTExpired
// rather than double-flagged.
func enrollmentJWTAddressStale(token, wantAddr string) bool {
	wantAddr = strings.TrimSpace(wantAddr)
	if wantAddr == "" {
		return false
	}
	wantHost := hostOnly(wantAddr)
	if wantHost == "" {
		return false
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil || parsed == nil {
		return false
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	// Collect every controller host the token would send a client to.
	var hosts []string
	if iss, ok := claims["iss"].(string); ok && iss != "" {
		// iss is a URL like https://host:port; strip scheme then port.
		h := iss
		if i := strings.Index(h, "://"); i >= 0 {
			h = h[i+3:]
		}
		hosts = append(hosts, hostOnly(h))
	}
	if ctrls, ok := claims["ctrls"].([]interface{}); ok {
		for _, c := range ctrls {
			if s, ok := c.(string); ok && s != "" {
				// entries look like tls:host:port
				h := s
				if i := strings.Index(h, ":"); i >= 0 && strings.HasPrefix(h, "tls:") {
					h = strings.TrimPrefix(h, "tls:")
				}
				hosts = append(hosts, hostOnly(h))
			}
		}
	}
	if len(hosts) == 0 {
		return false
	}
	// Stale if ANY advertised host differs from the wanted public host: a device
	// that dials the wrong one fails, so all must match.
	for _, h := range hosts {
		if h != "" && !strings.EqualFold(h, wantHost) {
			return true
		}
	}
	return false
}

// hostOnly strips a trailing :port from a host[:port] string, leaving the host.
// IPv6 literals are not expected for controller advertise addresses, so a simple
// last-colon split is sufficient and avoids mishandling scheme-less inputs.
func hostOnly(hostport string) string {
	h := strings.TrimSpace(hostport)
	// drop any trailing path
	if i := strings.IndexAny(h, "/"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		// only treat as port if what follows is all digits
		port := h[i+1:]
		allDigits := port != ""
		for _, r := range port {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			h = h[:i]
		}
	}
	return h
}
