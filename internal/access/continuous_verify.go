// Package access - Continuous session verification for zero-trust compliance
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ContinuousVerifier periodically re-evaluates active proxy sessions against current
// context (posture, geo, risk score, policies) and revokes sessions that no longer meet
// the route's access requirements.
type ContinuousVerifier struct {
	svc      *Service
	logger   *zap.Logger
	interval time.Duration
}

// NewContinuousVerifier creates a new continuous verifier
func NewContinuousVerifier(svc *Service, interval time.Duration, logger *zap.Logger) *ContinuousVerifier {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ContinuousVerifier{
		svc:      svc,
		logger:   logger.With(zap.String("component", "continuous-verifier")),
		interval: interval,
	}
}

// Start launches the background verification goroutine
func (cv *ContinuousVerifier) Start(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	cv.logger.Info("Continuous session verifier started", zap.Duration("interval", cv.interval))

	// Leader-gated: across replicas, re-verify each session once per interval
	// cluster-wide rather than N times.
	var rdb *redis.Client
	if cv.svc != nil && cv.svc.redis != nil {
		rdb = cv.svc.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, cv.logger, "access:continuous-verify", cv.interval, cv.verifyActiveSessions)
}

// verifyActiveSessions re-evaluates all sessions that need reverification
func (cv *ContinuousVerifier) verifyActiveSessions(ctx context.Context) {
	// Find sessions that belong to routes with reverify_interval > 0
	// and whose last_verified_at is older than the route's interval
	// Background cross-org sweep: re-verify due sessions across all orgs. s.org_id
	// is selected so each session's revoke/audit writes below stay scoped to its
	// own org (the ticker has no request context to read org from).
	rows, err := cv.svc.db.Pool.Query(ctx,
		`SELECT s.id, s.user_id, s.ip_address, s.user_agent, s.route_id,
		        s.device_fingerprint, s.risk_score, s.device_trusted,
		        r.id as route_id, r.reverify_interval, s.org_id
		 FROM proxy_sessions s
		 JOIN proxy_routes r ON s.route_id = r.id AND r.org_id = s.org_id
		 WHERE s.revoked = false
		   AND s.expires_at > NOW()
		   AND r.reverify_interval > 0
		   AND (s.last_verified_at IS NULL
		        OR s.last_verified_at < NOW() - (r.reverify_interval || ' seconds')::INTERVAL)
		 LIMIT 100`)
	if err != nil {
		cv.logger.Error("Failed to query sessions for reverification", zap.Error(err))
		return
	}
	defer rows.Close()

	type sessionToVerify struct {
		SessionID         string
		UserID            string
		IPAddress         string
		UserAgent         string
		RouteID           string
		DeviceFingerprint string
		RiskScore         int
		DeviceTrusted     bool
		ReverifyInterval  int
		OrgID             string
	}

	var sessions []sessionToVerify
	for rows.Next() {
		var s sessionToVerify
		var devFP *string
		err := rows.Scan(&s.SessionID, &s.UserID, &s.IPAddress, &s.UserAgent,
			&s.RouteID, &devFP, &s.RiskScore, &s.DeviceTrusted,
			&s.RouteID, &s.ReverifyInterval, &s.OrgID)
		if err != nil {
			cv.logger.Warn("Failed to scan session for reverification", zap.Error(err))
			continue
		}
		if devFP != nil {
			s.DeviceFingerprint = *devFP
		}
		sessions = append(sessions, s)
	}

	if len(sessions) == 0 {
		return
	}

	cv.logger.Debug("Reverifying sessions", zap.Int("count", len(sessions)))

	revoked := 0
	stepUpRequired := 0

	for _, sess := range sessions {
		route, err := cv.svc.getRouteByID(ctx, sess.RouteID)
		if err != nil {
			cv.logger.Warn("Failed to load route for reverification",
				zap.String("route_id", sess.RouteID), zap.Error(err))
			continue
		}

		// Build a minimal session for context evaluation
		// Re-derive device trust from the live known_devices signal (same reader
		// as the forward-auth path) rather than the persisted column, so a device
		// that was un-trusted since login is caught on re-verification.
		trusted := cv.svc.deviceTrusted(ctx, sess.UserID, sess.IPAddress, sess.UserAgent)

		proxySession := &ProxySession{
			ID:                sess.SessionID,
			UserID:            sess.UserID,
			IPAddress:         sess.IPAddress,
			UserAgent:         sess.UserAgent,
			DeviceFingerprint: sess.DeviceFingerprint,
			RiskScore:         sess.RiskScore,
			DeviceTrusted:     trusted,
		}

		// Load session data from Redis for roles/email
		tokenHash := ""
		cv.svc.db.Pool.QueryRow(ctx,
			//orgscope:ignore continuous-verification background sweep; session looked up by its globally-unique primary key from the org-tagged driver query above
			"SELECT session_token FROM proxy_sessions WHERE id=$1", sess.SessionID).
			Scan(&tokenHash)
		if tokenHash != "" {
			data, err := cv.svc.redis.Client.Get(ctx, "proxy_session:"+tokenHash).Bytes()
			if err == nil {
				var sessionData map[string]interface{}
				if json.Unmarshal(data, &sessionData) == nil {
					proxySession.Email, _ = sessionData["email"].(string)
					proxySession.Name, _ = sessionData["name"].(string)
					if r, ok := sessionData["roles"].([]interface{}); ok {
						for _, role := range r {
							proxySession.Roles = append(proxySession.Roles, fmt.Sprint(role))
						}
					}
				}
			}
		}

		// Build access context
		ac := &AccessContext{
			Session:       proxySession,
			Route:         route,
			ClientIP:      sess.IPAddress,
			UserAgent:     sess.UserAgent,
			DeviceTrusted: trusted,
			Timestamp:     time.Now(),
		}

		// IP geo lookup
		country, city := cv.svc.lookupIPGeo(ctx, sess.IPAddress)
		ac.GeoCountry = country
		ac.GeoCity = city

		// IP threat check
		threatType, blocked := cv.svc.checkIPThreat(ctx, sess.IPAddress)
		ac.IPThreatType = threatType
		ac.IPBlocked = blocked

		// Evaluate
		decision := cv.svc.evaluateAccessContext(ac)

		now := time.Now()

		if !decision.Allowed {
			// Revoke the session
			cv.svc.db.Pool.Exec(ctx,
				"UPDATE proxy_sessions SET revoked=true, last_verified_at=$1 WHERE id=$2 AND org_id=$3",
				now, sess.SessionID, sess.OrgID)

			// Remove from Redis
			if tokenHash != "" {
				cv.svc.redis.Client.Del(ctx, "proxy_session:"+tokenHash)
			}

			// Mid-session network termination (Wave A3): revoking the proxy
			// session stops NEW dials, but an already-open Ziti circuit would
			// survive until the app closes it. When the overlay is active, sever
			// the user's live controller sessions too so a posture/risk degrade
			// kills the circuit in-flight (posture becomes a guarantee, not a
			// gate). Best-effort; never blocks the revoke.
			cv.svc.severUserZitiCircuits(ctx, sess.UserID, decision.Reason)

			cv.logger.Warn("Session revoked by continuous verification",
				zap.String("session_id", sess.SessionID),
				zap.String("user_id", sess.UserID),
				zap.String("reason", decision.Reason))

			// Log audit event
			cv.svc.db.Pool.Exec(ctx,
				`INSERT INTO audit_events (id, event_type, actor_id, target_type, resource_id, details, created_at, org_id)
				 VALUES (gen_random_uuid(), 'session.revoked.continuous_verify', $1, 'proxy_session', $2, $3, NOW(), $4)`,
				sess.UserID, sess.SessionID,
				fmt.Sprintf(`{"reason":"%s","risk_score":%d}`, decision.Reason, decision.RiskScore), sess.OrgID)

			revoked++
			continue
		}

		if decision.StepUpRequired {
			// Set step-up flag in Redis
			cv.svc.redis.Client.Set(ctx,
				fmt.Sprintf("stepup_required:%s", sess.SessionID),
				"true", time.Duration(route.ReverifyInterval)*time.Second)
			stepUpRequired++
		}

		// Update verification timestamp and risk score
		cv.svc.db.Pool.Exec(ctx,
			`UPDATE proxy_sessions SET last_verified_at=$1, risk_score=$2 WHERE id=$3 AND org_id=$4`,
			now, decision.RiskScore, sess.SessionID, sess.OrgID)
	}

	if revoked > 0 || stepUpRequired > 0 {
		cv.logger.Info("Continuous verification cycle complete",
			zap.Int("verified", len(sessions)),
			zap.Int("revoked", revoked),
			zap.Int("step_up_required", stepUpRequired))
	}
}

// StartContinuousVerification is a convenience method on Service to start the verifier
func (s *Service) StartContinuousVerification(ctx context.Context, intervalSeconds int) {
	if intervalSeconds <= 0 {
		intervalSeconds = 30
	}
	cv := NewContinuousVerifier(s, time.Duration(intervalSeconds)*time.Second, s.logger)
	cv.Start(ctx)
}

// severUserZitiCircuits terminates the user's (and their enrolled devices')
// live Ziti controller sessions so a mid-session posture/risk degrade kills any
// already-open overlay circuit, not just future dials (Wave A3). No-op when the
// overlay is not active. Best-effort: failures are logged, never propagated.
func (s *Service) severUserZitiCircuits(ctx context.Context, userID, reason string) {
	zm := s.ziti()
	if zm == nil || userID == "" {
		return
	}
	// Collect the user's own identity + any enrolled-device identities.
	var zitiIDs []string
	var userZitiID string
	if err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore mid-session network termination; resolves the session user's own Ziti identity by user_id on the continuous-verify sweep
		`SELECT ziti_id FROM ziti_identities WHERE user_id = $1 LIMIT 1`, userID).Scan(&userZitiID); err == nil && userZitiID != "" {
		zitiIDs = append(zitiIDs, userZitiID)
	}
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore enrolled_agents scoped through the org-verified enrolled_by_user_id key (data plane)
		`SELECT ziti_identity_id FROM enrolled_agents
		  WHERE enrolled_by_user_id = $1 AND ziti_identity_id IS NOT NULL AND ziti_identity_id <> ''`, userID)
	if err == nil {
		for rows.Next() {
			var zid string
			if err := rows.Scan(&zid); err == nil && zid != "" {
				zitiIDs = append(zitiIDs, zid)
			}
		}
		rows.Close()
	}

	total := 0
	for _, zid := range zitiIDs {
		edge, api, terr := zm.TerminateIdentitySessions(ctx, zid)
		if terr != nil {
			s.logger.Warn("continuous-verify: Ziti session termination failed",
				zap.String("ziti_id", zid), zap.Error(terr))
			continue
		}
		total += edge + api
	}
	if total > 0 {
		s.logger.Warn("continuous-verify: severed live Ziti circuits",
			zap.String("user_id", userID), zap.String("reason", reason), zap.Int("sessions", total))
	}
}
