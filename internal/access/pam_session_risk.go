// Privileged-session risk scoring + auto-suspend (PAM C2).
//
// A leader-gated worker periodically scores every ACTIVE PAM/Guacamole session
// and, in "enforce" mode, terminates sessions whose risk score crosses the
// configured threshold. This extends the ZTNA continuous-verifier (which scores
// proxy_sessions) to the privileged-session plane — CyberArk PTA / StrongDM
// runtime-authZ territory — reusing the existing Guacamole TerminateSession
// mechanism.
//
// Risk signals (all derivable from data OpenIDX already holds, no agent):
//   - off-hours    : session active outside 07:00–20:00 local (server) time.
//   - long-running : privileged sessions that run unusually long.
//   - user risk    : the user's live risk_score from their proxy_session (the
//     same adaptive-risk signal the IdP computes at login).
//
// Gate (config.PAMSessionRiskGate): off | observe | enforce, mirroring the
// posture gate. "observe" scores + audits what WOULD be suspended but never
// terminates, so an operator can watch before enforcing.
package access

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// pamRiskSignals are the inputs to scorePAMSession, kept as a struct so the
// scoring is a pure, unit-testable function independent of the DB/Guacamole.
type pamRiskSignals struct {
	OffHours        bool // session active outside business hours
	DurationMinutes int  // how long the session has run
	UserRiskScore   int  // 0-100, the user's live login risk
}

// scorePAMSession maps signals to a 0-100 risk score. Deterministic and pure.
// Weights are intentionally simple and explainable (this is evidence an auditor
// reads): a high user risk dominates, off-hours and very long sessions add on.
func scorePAMSession(s pamRiskSignals) int {
	score := 0
	// The user's own risk is the strongest signal; carry ~60% of its weight.
	score += (s.UserRiskScore * 6) / 10 // up to 60
	if s.OffHours {
		score += 25
	}
	switch {
	case s.DurationMinutes >= 240: // >= 4h
		score += 20
	case s.DurationMinutes >= 120: // >= 2h
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

// isOffHours reports whether t (server local time) is outside 07:00–20:00.
func isOffHours(t time.Time) bool {
	h := t.Hour()
	return h < 7 || h >= 20
}

// PAMSessionRiskScorer is the background worker.
type PAMSessionRiskScorer struct {
	svc       *Service
	interval  time.Duration
	gate      string // off | observe | enforce
	threshold int
	logger    *zap.Logger
}

// NewPAMSessionRiskScorer builds the worker. gate/threshold come from config.
func NewPAMSessionRiskScorer(svc *Service, interval time.Duration, gate string, threshold int, logger *zap.Logger) *PAMSessionRiskScorer {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if threshold <= 0 || threshold > 100 {
		threshold = 80
	}
	if gate == "" {
		gate = "off"
	}
	return &PAMSessionRiskScorer{
		svc:       svc,
		interval:  interval,
		gate:      gate,
		threshold: threshold,
		logger:    logger.With(zap.String("component", "pam-session-risk")),
	}
}

// Start launches the leader-gated scoring loop. A no-op when the gate is "off".
func (p *PAMSessionRiskScorer) Start(ctx context.Context) {
	if p.gate == "off" {
		p.logger.Info("PAM session risk scorer disabled (gate=off)")
		return
	}
	ctx = orgctx.WithBypassRLS(ctx)
	p.logger.Info("PAM session risk scorer started",
		zap.String("gate", p.gate), zap.Int("threshold", p.threshold), zap.Duration("interval", p.interval))
	var rdb *redis.Client
	if p.svc != nil && p.svc.redis != nil {
		rdb = p.svc.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, p.logger, "access:pam-session-risk", p.interval, p.scoreActiveSessions)
}

// activePAMSession is one active privileged session pulled from the DB.
type activePAMSession struct {
	SessionID     string
	OrgID         string
	UserID        string
	GuacConnID    string
	StartedAt     time.Time
	UserRiskScore int
}

// scoreActiveSessions scores every active PAM session and suspends the risky
// ones (enforce) or just audits them (observe). Cross-org sweep under bypass RLS;
// each write is scoped to the session's own org.
func (p *PAMSessionRiskScorer) scoreActiveSessions(ctx context.Context) {
	if p.svc == nil || p.svc.db == nil {
		return
	}
	// (per-tick scoring; details logged only on action)
	// Active PAM sessions joined to the user's latest live proxy_session risk.
	//orgscope:ignore cross-org background sweep under bypass RLS; org_id is selected per row and used to scope the terminate/audit writes
	rows, err := p.svc.db.Pool.Query(ctx, `
		SELECT s.id, s.org_id, s.user_id, COALESCE(s.guac_connection_id,''), s.started_at,
		       COALESCE((
		           SELECT ps.risk_score FROM proxy_sessions ps
		            WHERE ps.user_id = s.user_id AND ps.revoked = false
		            ORDER BY ps.started_at DESC LIMIT 1
		       ), 0) AS user_risk
		  FROM pam_entry_sessions s
		 WHERE s.status = 'active' AND s.ended_at IS NULL AND s.user_id IS NOT NULL`)
	if err != nil {
		p.logger.Warn("pam risk: query active sessions failed", zap.Error(err))
		return
	}
	defer rows.Close()

	var sessions []activePAMSession
	for rows.Next() {
		var a activePAMSession
		if err := rows.Scan(&a.SessionID, &a.OrgID, &a.UserID, &a.GuacConnID, &a.StartedAt, &a.UserRiskScore); err != nil {
			p.logger.Warn("pam risk: scan failed", zap.Error(err))
			continue
		}
		sessions = append(sessions, a)
	}

	now := time.Now()
	for _, a := range sessions {
		sig := pamRiskSignals{
			OffHours:        isOffHours(a.StartedAt) || isOffHours(now),
			DurationMinutes: int(now.Sub(a.StartedAt).Minutes()),
			UserRiskScore:   a.UserRiskScore,
		}
		score := scorePAMSession(sig)
		if score < p.threshold {
			continue
		}
		reason := fmt.Sprintf("risk score %d >= threshold %d (off_hours=%v, duration_min=%d, user_risk=%d)",
			score, p.threshold, sig.OffHours, sig.DurationMinutes, sig.UserRiskScore)

		if p.gate == "observe" {
			p.logger.Warn("PAM session WOULD be auto-suspended (observe mode)",
				zap.String("session_id", a.SessionID), zap.String("user_id", a.UserID), zap.Int("score", score))
			p.audit(ctx, a, score, reason, "observe")
			continue
		}
		// enforce: terminate the live Guacamole connection, mark the row, audit.
		if a.GuacConnID != "" && p.svc.guacamoleClient != nil {
			if err := p.svc.guacamoleClient.TerminateSession(ctx, a.GuacConnID); err != nil {
				p.logger.Warn("pam risk: terminate failed", zap.String("session_id", a.SessionID), zap.Error(err))
			}
		}
		//orgscope:ignore write scoped to this session's own org_id (selected above); background ticker has no request org
		_, _ = p.svc.db.Pool.Exec(ctx,
			`UPDATE pam_entry_sessions SET status = 'suspended', ended_at = NOW()
			  WHERE id = $1 AND org_id = $2`, a.SessionID, a.OrgID)
		p.logger.Warn("PAM session auto-suspended (enforce)",
			zap.String("session_id", a.SessionID), zap.String("user_id", a.UserID), zap.Int("score", score))
		p.audit(ctx, a, score, reason, "enforce")
	}
}

// audit records the suspend decision on the hash-chained audit trail.
func (p *PAMSessionRiskScorer) audit(ctx context.Context, a activePAMSession, score int, reason, mode string) {
	//orgscope:ignore audit_events row is stamped with the session's own org_id; background ticker has no request org
	if _, err := p.svc.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_type, resource_id, details, created_at, org_id)
		VALUES (gen_random_uuid(), 'pam.session.risk_suspend', 'privileged_access', 'session.risk_suspend', 'success', $1, 'pam_entry_session', $2, $3, NOW(), $4)`,
		a.UserID, a.SessionID,
		fmt.Sprintf(`{"score":%d,"mode":"%s","reason":%q}`, score, mode, reason), a.OrgID); err != nil {
		p.logger.Warn("pam risk: audit insert failed", zap.Error(err))
	}
}
