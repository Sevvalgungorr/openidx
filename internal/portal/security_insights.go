// My Security Insights — the end-user face of the AI identity intelligence
// layer. Where the admin surface ranks the whole org, this endpoint answers
// one question for the signed-in user: "how safe is my account, and what
// should I do next?" — in plain language. The risk fusion is the same
// deterministic internal/intelligence logic the admin side uses, so the user
// and the admin always see the same number. The optional locally-hosted LLM
// only rephrases the summary; with it off, template text is returned.
//
// The friction field is the UX payoff: a "low" friction posture tells the
// user (and the adaptive-auth layer) that their good standing earns fewer
// MFA prompts on trusted devices.
package portal

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/ai"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/intelligence"
)

// SetAIClient wires the optional local AI client (nil-safe: template output
// is used whenever the client is absent or disabled).
func (s *Service) SetAIClient(c *ai.Client) { s.aiClient = c }

// SecurityInsights is the user-facing security self-assessment.
type SecurityInsights struct {
	Score          int             `json:"score"`
	Level          string          `json:"level"`
	Friction       string          `json:"friction"`
	Summary        string          `json:"summary"`
	GeneratedBy    string          `json:"generated_by"`
	MFAEnrolled    bool            `json:"mfa_enrolled"`
	Tips           []string        `json:"tips"`
	Devices        []InsightDevice `json:"devices"`
	RecentLogins   []InsightLogin  `json:"recent_logins"`
	OpenAlerts     int             `json:"open_alerts"`
	FailedLogins7d int             `json:"failed_logins_7d"`
}

type InsightDevice struct {
	Name     string     `json:"name"`
	Trusted  bool       `json:"trusted"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}

type InsightLogin struct {
	At        time.Time `json:"at"`
	IPAddress string    `json:"ip_address"`
	Location  string    `json:"location,omitempty"`
	Success   bool      `json:"success"`
	RiskScore int       `json:"risk_score"`
}

// computeSecurityInsights gathers the signed-in user's own signals and fuses
// them with the shared deterministic logic. Every query is double-scoped to
// the caller's user ID and org.
func (s *Service) computeSecurityInsights(ctx context.Context, userID, orgID string) (*SecurityInsights, error) {
	out := &SecurityInsights{}

	var avgRisk float64
	var maxRisk, failed7d int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(risk_score),0), COALESCE(MAX(risk_score),0),
		       COUNT(*) FILTER (WHERE NOT success AND created_at > NOW() - INTERVAL '7 days')
		  FROM login_history
		 WHERE user_id = $1 AND org_id = $2 AND created_at > NOW() - INTERVAL '30 days'`,
		userID, orgID).Scan(&avgRisk, &maxRisk, &failed7d)
	out.FailedLogins7d = failed7d

	var alertSevs []string
	rows, err := s.db.Pool.Query(ctx,
		`SELECT severity FROM security_alerts WHERE user_id = $1 AND org_id = $2 AND status = 'open'`, userID, orgID)
	if err == nil {
		for rows.Next() {
			var sev string
			if err := rows.Scan(&sev); err == nil {
				alertSevs = append(alertSevs, sev)
			}
		}
		rows.Close()
	}
	out.OpenAlerts = len(alertSevs)

	var mfaEnrolled bool
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mfa_totp t WHERE t.user_id = $1 AND t.org_id = $2 AND t.enabled = true)
		    OR EXISTS(SELECT 1 FROM mfa_webauthn w WHERE w.user_id = $1 AND w.org_id = $2)`,
		userID, orgID).Scan(&mfaEnrolled)
	out.MFAEnrolled = mfaEnrolled

	trusted, untrusted := 0, 0
	rows, err = s.db.Pool.Query(ctx, `
		SELECT COALESCE(NULLIF(name,''), 'Device'), trusted, last_seen_at
		  FROM known_devices WHERE user_id = $1 AND org_id = $2
		 ORDER BY last_seen_at DESC NULLS LAST LIMIT 20`, userID, orgID)
	if err == nil {
		for rows.Next() {
			var d InsightDevice
			if err := rows.Scan(&d.Name, &d.Trusted, &d.LastSeen); err == nil {
				out.Devices = append(out.Devices, d)
				if d.Trusted {
					trusted++
				} else {
					untrusted++
				}
			}
		}
		rows.Close()
	}

	rows, err = s.db.Pool.Query(ctx, `
		SELECT created_at, COALESCE(ip_address,''), COALESCE(location,''), success, COALESCE(risk_score,0)
		  FROM login_history WHERE user_id = $1 AND org_id = $2
		 ORDER BY created_at DESC LIMIT 10`, userID, orgID)
	if err == nil {
		for rows.Next() {
			var l InsightLogin
			if err := rows.Scan(&l.At, &l.IPAddress, &l.Location, &l.Success, &l.RiskScore); err == nil {
				out.RecentLogins = append(out.RecentLogins, l)
			}
		}
		rows.Close()
	}

	var lastLogin *time.Time
	var enabled bool
	_ = s.db.Pool.QueryRow(ctx,
		`SELECT last_login_at, enabled FROM users WHERE id = $1 AND org_id = $2`,
		userID, orgID).Scan(&lastLogin, &enabled)
	days := -1
	if lastLogin != nil {
		days = int(time.Since(*lastLogin).Hours() / 24)
	}

	sig := intelligence.IdentitySignals{
		AvgRiskScore:     avgRisk,
		MaxRiskScore:     maxRisk,
		FailedLogins7d:   failed7d,
		OpenAlerts:       alertSevs,
		MFAEnrolled:      mfaEnrolled,
		DaysSinceLogin:   days,
		TrustedDevices:   trusted,
		UntrustedDevices: untrusted,
		AccountEnabled:   enabled,
	}
	score, level, reasons := intelligence.FuseIdentityRisk(sig)
	out.Score = score
	out.Level = level
	out.Friction = intelligence.FrictionRecommendation(score, mfaEnrolled)
	out.Tips = buildUserTips(sig, trusted, untrusted)
	out.Summary, out.GeneratedBy = s.buildUserSummary(context.WithoutCancel(ctx), score, level, reasons, out.Friction, mfaEnrolled)
	return out, nil
}

// buildUserTips derives friendly, actionable advice from the signal set.
func buildUserTips(sig intelligence.IdentitySignals, trusted, untrusted int) []string {
	var tips []string
	if !sig.MFAEnrolled {
		tips = append(tips, "Enroll a second factor (authenticator app or security key) — it's the single biggest security upgrade, and it unlocks fewer login prompts on trusted devices.")
	}
	if untrusted > 0 && trusted == 0 {
		tips = append(tips, "None of your devices are marked trusted yet. Request device trust for the computer you use every day to reduce verification prompts.")
	}
	if sig.FailedLogins7d >= 3 {
		tips = append(tips, "There were several failed sign-in attempts on your account this week. If they weren't you, change your password now.")
	}
	if len(sig.OpenAlerts) > 0 {
		tips = append(tips, "There are open security alerts on your account — review your recent activity and report anything you don't recognize.")
	}
	if len(tips) == 0 {
		tips = append(tips, "Your account is in good standing — keep using your trusted devices and your sign-ins will stay low-friction.")
	}
	return tips
}

// buildUserSummary produces the plain-language summary, LLM-phrased when the
// local provider is available.
func (s *Service) buildUserSummary(ctx context.Context, score int, level string, reasons []string, friction string, mfaEnrolled bool) (string, string) {
	frictionText := map[string]string{
		"low":    "Because your risk is low, you'll see fewer verification prompts on trusted devices.",
		"normal": "You'll see standard verification prompts.",
		"strict": "Because of elevated risk, extra verification will be required for sensitive actions.",
	}[friction]

	summary := fmt.Sprintf("Your account security level is %s (score %d/100). %s", level, score, frictionText)
	if len(reasons) > 0 {
		summary += " What's affecting it: " + strings.Join(reasons, "; ") + "."
	}
	if s.aiClient != nil && s.aiClient.Enabled() {
		llmCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		facts := fmt.Sprintf("Security level: %s (score %d/100). Factors: %s. MFA enrolled: %t. Friction: %s.",
			level, score, strings.Join(reasons, "; "), mfaEnrolled, friction)
		prompt := "Explain this end user's account security status to them in 2-3 friendly, non-technical sentences. " +
			"Mention how it affects how often they'll be asked to verify. Use ONLY these facts:\n" + facts
		if text, err := s.aiClient.Complete(llmCtx, "You are a helpful, honest security assistant inside an identity platform. Never invent facts.", prompt); err == nil {
			return text, "local-ai:" + s.aiClient.Model()
		}
		s.logger.Debug("security insights: LLM summary fell back to template", zap.Int("score", score))
	}
	return summary, "template"
}

// handleGetSecurityInsights handles GET /portal/security-insights.
func (s *Service) handleGetSecurityInsights(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	insights, err := s.computeSecurityInsights(c.Request.Context(), userID, org.ID)
	if err != nil {
		s.logger.Error("failed to compute security insights", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute security insights"})
		return
	}
	c.JSON(http.StatusOK, insights)
}
