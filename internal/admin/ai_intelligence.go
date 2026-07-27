// AI Identity Intelligence — the IAM-side twin of the Ziti AI engine, and the
// cross-pillar fusion point. It pulls every existing signal source (login
// risk history, open security alerts, MFA enrollment, device trust, breach
// incidents, Ziti overlay anomalies) into one deterministic per-identity risk
// score via internal/intelligence, and layers an OPTIONAL locally-hosted LLM
// on top for narratives: a daily security briefing, per-user explanations and
// a grounded ask-the-copilot endpoint. Everything works with the LLM off —
// template output is always produced first and the model only rephrases it.
package admin

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/intelligence"
)

// IdentityIntelligence is one user's fused assessment.
type IdentityIntelligence struct {
	UserID         string   `json:"user_id"`
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	Score          int      `json:"score"`
	Level          string   `json:"level"`
	Reasons        []string `json:"reasons"`
	MFAEnrolled    bool     `json:"mfa_enrolled"`
	OpenAlerts     int      `json:"open_alerts"`
	FailedLogins7d int      `json:"failed_logins_7d"`
	ZitiAnomalies  int      `json:"ziti_anomalies"`
	Friction       string   `json:"friction"`
	DaysSinceLogin int      `json:"days_since_login"`
	AccountEnabled bool     `json:"account_enabled"`
}

// orgIntelligence is the assembled org-wide picture used by the overview,
// briefing and ask handlers.
type orgIntelligence struct {
	Users         []IdentityIntelligence
	Levels        map[string]int
	MFAEnrolled   int
	TotalUsers    int
	OpenAlerts    int
	AlertsBySev   map[string]int
	Logins24h     int
	Failed24h     int
	ZitiAnomalies int
}

// computeOrgIntelligence gathers all fusion signals for an org with a handful
// of bulk queries and scores every user.
func (s *Service) computeOrgIntelligence(ctx context.Context, orgID string) (*orgIntelligence, error) {
	type userRow struct {
		id, username, email string
		enabled, locked     bool
		lastLogin           *time.Time
	}
	var users []userRow
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, username, COALESCE(email,''), enabled,
		       (locked_until IS NOT NULL AND locked_until > NOW()),
		       last_login_at
		  FROM users WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u userRow
		if err := rows.Scan(&u.id, &u.username, &u.email, &u.enabled, &u.locked, &u.lastLogin); err == nil {
			users = append(users, u)
		}
	}
	rows.Close()

	type loginAgg struct {
		avg    float64
		max    int
		failed int
	}
	logins := make(map[string]loginAgg)
	rows, err = s.db.Pool.Query(ctx, `
		SELECT user_id::text, COALESCE(AVG(risk_score),0), COALESCE(MAX(risk_score),0),
		       COUNT(*) FILTER (WHERE NOT success AND created_at > NOW() - INTERVAL '7 days')
		  FROM login_history
		 WHERE org_id = $1 AND created_at > NOW() - INTERVAL '30 days'
		 GROUP BY user_id`, orgID)
	if err == nil {
		for rows.Next() {
			var id string
			var a loginAgg
			if err := rows.Scan(&id, &a.avg, &a.max, &a.failed); err == nil {
				logins[id] = a
			}
		}
		rows.Close()
	}

	alerts := make(map[string][]string)
	alertsBySev := map[string]int{}
	openAlerts := 0
	rows, err = s.db.Pool.Query(ctx, `
		SELECT COALESCE(user_id::text,''), severity FROM security_alerts
		 WHERE org_id = $1 AND status = 'open'`, orgID)
	if err == nil {
		for rows.Next() {
			var id, sev string
			if err := rows.Scan(&id, &sev); err == nil {
				openAlerts++
				alertsBySev[sev]++
				if id != "" {
					alerts[id] = append(alerts[id], sev)
				}
			}
		}
		rows.Close()
	}

	mfa := make(map[string]bool)
	rows, err = s.db.Pool.Query(ctx, `
		SELECT u.id::text FROM users u
		 WHERE u.org_id = $1 AND (
		       EXISTS(SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.enabled = true)
		    OR EXISTS(SELECT 1 FROM mfa_webauthn w WHERE w.user_id = u.id))`, orgID)
	if err == nil {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				mfa[id] = true
			}
		}
		rows.Close()
	}

	type devAgg struct{ trusted, untrusted int }
	devices := make(map[string]devAgg)
	rows, err = s.db.Pool.Query(ctx, `
		SELECT user_id::text,
		       COUNT(*) FILTER (WHERE trusted), COUNT(*) FILTER (WHERE NOT trusted)
		  FROM known_devices WHERE org_id = $1 GROUP BY user_id`, orgID)
	if err == nil {
		for rows.Next() {
			var id string
			var d devAgg
			if err := rows.Scan(&id, &d.trusted, &d.untrusted); err == nil {
				devices[id] = d
			}
		}
		rows.Close()
	}

	// Breach incidents are install-wide (no org_id); affected_user_ids carries
	// users.id values so scoping happens implicitly via the org's user set.
	breaches := make(map[string]int)
	rows, err = s.db.Pool.Query(ctx, `
		SELECT unnest(affected_user_ids) FROM breach_incidents
		 WHERE created_at > NOW() - INTERVAL '30 days' AND status NOT IN ('resolved','closed')`)
	if err == nil {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				breaches[id]++
			}
		}
		rows.Close()
	}

	// Ziti overlay anomalies: synced overlay identities are NAMED with the
	// OpenIDX user ID, so identity_name = users.id::text is the join.
	zitiAnomalies := make(map[string]int)
	zitiOpenTotal := 0
	rows, err = s.db.Pool.Query(ctx,
		`SELECT COALESCE(identity_name,''), COUNT(*) FROM ziti_ai_anomalies
		  WHERE status = 'open' GROUP BY identity_name`)
	if err == nil {
		for rows.Next() {
			var name string
			var n int
			if err := rows.Scan(&name, &n); err == nil {
				zitiOpenTotal += n
				if name != "" {
					zitiAnomalies[name] = n
				}
			}
		}
		rows.Close()
	}

	var logins24h, failed24h int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE NOT success)
		  FROM login_history WHERE org_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
		orgID).Scan(&logins24h, &failed24h)

	out := &orgIntelligence{
		Levels:        map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0},
		AlertsBySev:   alertsBySev,
		OpenAlerts:    openAlerts,
		Logins24h:     logins24h,
		Failed24h:     failed24h,
		ZitiAnomalies: zitiOpenTotal,
		TotalUsers:    len(users),
	}
	now := time.Now()
	for _, u := range users {
		la := logins[u.id]
		dev := devices[u.id]
		days := -1
		if u.lastLogin != nil {
			days = int(now.Sub(*u.lastLogin).Hours() / 24)
		}
		sig := intelligence.IdentitySignals{
			AvgRiskScore:      la.avg,
			MaxRiskScore:      la.max,
			FailedLogins7d:    la.failed,
			OpenAlerts:        alerts[u.id],
			MFAEnrolled:       mfa[u.id],
			DaysSinceLogin:    days,
			TrustedDevices:    dev.trusted,
			UntrustedDevices:  dev.untrusted,
			BreachIncidents:   breaches[u.id],
			ZitiOpenAnomalies: zitiAnomalies[u.id],
			AccountLocked:     u.locked,
			AccountEnabled:    u.enabled,
		}
		score, level, reasons := intelligence.FuseIdentityRisk(sig)
		out.Levels[level]++
		if mfa[u.id] {
			out.MFAEnrolled++
		}
		out.Users = append(out.Users, IdentityIntelligence{
			UserID: u.id, Username: u.username, Email: u.email,
			Score: score, Level: level, Reasons: reasons,
			MFAEnrolled: mfa[u.id], OpenAlerts: len(alerts[u.id]),
			FailedLogins7d: la.failed, ZitiAnomalies: zitiAnomalies[u.id],
			Friction:       intelligence.FrictionRecommendation(score, mfa[u.id]),
			DaysSinceLogin: days, AccountEnabled: u.enabled,
		})
	}
	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Score > out.Users[j].Score })
	return out, nil
}

// buildBriefingFacts renders the deterministic facts block that both the
// template briefing and the LLM prompt are built from — the LLM never sees
// anything the template didn't.
func buildBriefingFacts(intel *orgIntelligence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- Users: %d total; MFA enrolled: %d (%.0f%%)\n",
		intel.TotalUsers, intel.MFAEnrolled, percent(intel.MFAEnrolled, intel.TotalUsers))
	fmt.Fprintf(&b, "- Identity risk levels: %d critical, %d high, %d medium, %d low\n",
		intel.Levels["critical"], intel.Levels["high"], intel.Levels["medium"], intel.Levels["low"])
	fmt.Fprintf(&b, "- Open security alerts: %d (critical %d, high %d, medium %d, low %d)\n",
		intel.OpenAlerts, intel.AlertsBySev["critical"], intel.AlertsBySev["high"],
		intel.AlertsBySev["medium"], intel.AlertsBySev["low"])
	fmt.Fprintf(&b, "- Logins last 24h: %d (%d failed)\n", intel.Logins24h, intel.Failed24h)
	fmt.Fprintf(&b, "- Open zero-trust network anomalies: %d\n", intel.ZitiAnomalies)
	top := intel.Users
	if len(top) > 5 {
		top = top[:5]
	}
	for _, u := range top {
		if u.Score < 30 {
			break
		}
		fmt.Fprintf(&b, "- At-risk user %s (score %d, %s): %s\n",
			u.Username, u.Score, u.Level, strings.Join(u.Reasons, "; "))
	}
	return b.String()
}

func buildTemplateBriefing(intel *orgIntelligence) string {
	atRisk := intel.Levels["critical"] + intel.Levels["high"]
	headline := "Security posture is stable."
	if intel.Levels["critical"] > 0 {
		headline = fmt.Sprintf("%d identities are at CRITICAL risk and need attention today.", intel.Levels["critical"])
	} else if atRisk > 0 {
		headline = fmt.Sprintf("%d identities are at elevated risk.", atRisk)
	}
	return fmt.Sprintf("%s\n\n%s", headline, buildBriefingFacts(intel))
}

func percent(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) * 100 / float64(total)
}

const briefingSystemPrompt = "You are the on-premises security copilot of an identity and access management platform. " +
	"You are given verified facts about the deployment. Write a concise daily security briefing (max 150 words) for an administrator: " +
	"lead with the most urgent item, then summarize posture, and end with the top 2-3 recommended actions. " +
	"Use ONLY the provided facts — never invent numbers, users or events."

const askSystemPrompt = "You are the on-premises security copilot of an identity and access management platform. " +
	"Answer the administrator's question using ONLY the verified facts provided. " +
	"If the facts don't contain the answer, say so plainly. Be concise and concrete. Never invent numbers, users or events."

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleAIIntelligenceOverview returns the fused org-wide picture.
func (s *Service) handleAIIntelligenceOverview(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	intel, err := s.computeOrgIntelligence(ctx, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("compute identity intelligence", err))
		return
	}
	top := intel.Users
	if len(top) > 25 {
		top = top[:25]
	}
	c.JSON(http.StatusOK, gin.H{
		"total_users":         intel.TotalUsers,
		"risk_levels":         intel.Levels,
		"identities_at_risk":  intel.Levels["critical"] + intel.Levels["high"],
		"mfa_enrolled":        intel.MFAEnrolled,
		"mfa_coverage_pct":    percent(intel.MFAEnrolled, intel.TotalUsers),
		"open_alerts":         intel.OpenAlerts,
		"alerts_by_severity":  intel.AlertsBySev,
		"logins_24h":          intel.Logins24h,
		"failed_logins_24h":   intel.Failed24h,
		"ziti_open_anomalies": intel.ZitiAnomalies,
		"top_risks":           top,
		"ai":                  s.aiClient.Status(ctx),
	})
}

// handleAIIntelligenceUser returns one user's fused assessment plus a
// narrative explanation (LLM-phrased when local AI is on, template otherwise).
func (s *Service) handleAIIntelligenceUser(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.Param("id")
	intel, err := s.computeOrgIntelligence(ctx, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("compute identity intelligence", err))
		return
	}
	for _, u := range intel.Users {
		if u.UserID != userID {
			continue
		}
		narrative := fmt.Sprintf("%s is at %s risk (score %d/100).", u.Username, u.Level, u.Score)
		if len(u.Reasons) > 0 {
			narrative += " Contributing factors: " + strings.Join(u.Reasons, "; ") + "."
		}
		generatedBy := "template"
		if s.aiClient.Enabled() {
			facts := fmt.Sprintf("User %s: risk score %d (%s). Factors: %s. MFA enrolled: %t. Recommended auth friction: %s.",
				u.Username, u.Score, u.Level, strings.Join(u.Reasons, "; "), u.MFAEnrolled, u.Friction)
			if text, err := s.aiClient.Complete(ctx, askSystemPrompt,
				"Explain this user's security posture to an administrator in 2-3 sentences, with the single most useful next action:\n"+facts); err == nil {
				narrative = text
				generatedBy = "local-ai:" + s.aiClient.Model()
			} else {
				s.logger.Debug("ai intelligence: user narrative fell back to template")
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"assessment":   u,
			"narrative":    narrative,
			"generated_by": generatedBy,
		})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
}

// handleAIIntelligenceBriefing produces the daily security briefing.
func (s *Service) handleAIIntelligenceBriefing(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	intel, err := s.computeOrgIntelligence(ctx, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("compute identity intelligence", err))
		return
	}
	briefing := buildTemplateBriefing(intel)
	generatedBy := "template"
	if s.aiClient.Enabled() {
		if text, err := s.aiClient.Complete(ctx, briefingSystemPrompt, buildBriefingFacts(intel)); err == nil {
			briefing = text
			generatedBy = "local-ai:" + s.aiClient.Model()
		} else {
			s.logger.Warn("ai intelligence: briefing fell back to template")
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"briefing":     briefing,
		"facts":        buildBriefingFacts(intel),
		"generated_by": generatedBy,
		"generated_at": time.Now(),
	})
}

// handleAIIntelligenceAsk answers a free-form admin question grounded on the
// current fused facts. Requires the local AI provider.
func (s *Service) handleAIIntelligenceAsk(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	if !s.aiClient.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "local AI provider is not enabled",
			"hint":  "set AI_ENABLED=true and point AI_BASE_URL at an on-prem OpenAI-compatible endpoint (e.g. Ollama at http://localhost:11434/v1)",
		})
		return
	}
	var req struct {
		Question string `json:"question" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Question) > 2000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "question too long (max 2000 characters)"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	intel, err := s.computeOrgIntelligence(ctx, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("compute identity intelligence", err))
		return
	}
	// The question is untrusted input: it is passed as data in the user turn,
	// and the system prompt pins the model to the facts block.
	prompt := "FACTS:\n" + buildBriefingFacts(intel) + "\nQUESTION: " + req.Question
	answer, err := s.aiClient.Complete(ctx, askSystemPrompt, prompt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("local AI completion", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"answer":       answer,
		"generated_by": "local-ai:" + s.aiClient.Model(),
	})
}

// handleAIIntelligenceStatus reports the local AI provider's state.
func (s *Service) handleAIIntelligenceStatus(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	c.JSON(http.StatusOK, s.aiClient.Status(c.Request.Context()))
}
