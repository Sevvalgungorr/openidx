// Package intelligence holds the pure, dependency-free identity risk fusion
// logic shared by the admin AI-intelligence surface and the end-user portal.
// It fuses signals from every pillar — IAM login risk, security alerts, MFA
// enrollment, device trust, breach involvement, Ziti overlay anomalies — into
// one deterministic 0–100 score, and derives the authentication-friction
// recommendation that lets low-risk users see fewer MFA prompts. Keeping this
// deterministic and separate from any LLM means the numbers are reproducible
// and auditable; the LLM only ever narrates them.
package intelligence

import "fmt"

// IdentitySignals is the fused input for one user.
type IdentitySignals struct {
	AvgRiskScore      float64  // mean login_history.risk_score, last 30 days
	MaxRiskScore      int      // worst login risk seen, last 30 days
	FailedLogins7d    int      // failed logins in the last 7 days
	OpenAlerts        []string // severities of open security_alerts
	MFAEnrolled       bool     // TOTP or WebAuthn enrolled
	DaysSinceLogin    int      // -1 when never logged in / unknown
	TrustedDevices    int      // known_devices with trusted=true
	UntrustedDevices  int      // known_devices with trusted=false
	BreachIncidents   int      // breach_incidents naming this user
	ZitiOpenAnomalies int      // open ziti_ai_anomalies for the mapped overlay identity
	AccountLocked     bool
	AccountEnabled    bool
}

// FuseIdentityRisk turns the signal set into a 0–100 score, a level and
// human-readable reasons.
func FuseIdentityRisk(sig IdentitySignals) (int, string, []string) {
	score := 0
	var reasons []string

	alertPoints := 0
	for _, sev := range sig.OpenAlerts {
		switch sev {
		case "critical":
			alertPoints += 30
		case "high":
			alertPoints += 20
		case "medium":
			alertPoints += 10
		default:
			alertPoints += 4
		}
	}
	if alertPoints > 50 {
		alertPoints = 50
	}
	if alertPoints > 0 {
		reasons = append(reasons, fmt.Sprintf("%d open security alerts", len(sig.OpenAlerts)))
	}
	score += alertPoints

	loginPoints := int(sig.AvgRiskScore * 0.3)
	if loginPoints > 30 {
		loginPoints = 30
	}
	if sig.MaxRiskScore >= 70 {
		loginPoints += 10
		reasons = append(reasons, fmt.Sprintf("a recent login scored %d risk", sig.MaxRiskScore))
	} else if loginPoints >= 5 {
		reasons = append(reasons, fmt.Sprintf("elevated average login risk (%.0f)", sig.AvgRiskScore))
	}
	score += loginPoints

	failedPoints := sig.FailedLogins7d * 3
	if failedPoints > 15 {
		failedPoints = 15
	}
	if failedPoints > 0 {
		reasons = append(reasons, fmt.Sprintf("%d failed logins this week", sig.FailedLogins7d))
	}
	score += failedPoints

	if !sig.MFAEnrolled {
		score += 15
		reasons = append(reasons, "no MFA method enrolled")
	}

	if sig.AccountEnabled && sig.DaysSinceLogin >= 30 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("dormant for %d days", sig.DaysSinceLogin))
	}

	untrustedPoints := sig.UntrustedDevices * 3
	if untrustedPoints > 10 {
		untrustedPoints = 10
	}
	if untrustedPoints > 0 && sig.TrustedDevices == 0 {
		reasons = append(reasons, fmt.Sprintf("%d devices, none trusted", sig.UntrustedDevices))
	}
	score += untrustedPoints

	breachPoints := sig.BreachIncidents * 20
	if breachPoints > 40 {
		breachPoints = 40
	}
	if breachPoints > 0 {
		reasons = append(reasons, fmt.Sprintf("involved in %d breach incidents", sig.BreachIncidents))
	}
	score += breachPoints

	zitiPoints := sig.ZitiOpenAnomalies * 10
	if zitiPoints > 20 {
		zitiPoints = 20
	}
	if zitiPoints > 0 {
		reasons = append(reasons, fmt.Sprintf("%d open network anomalies on the zero-trust overlay", sig.ZitiOpenAnomalies))
	}
	score += zitiPoints

	if sig.AccountLocked {
		reasons = append(reasons, "account is currently locked")
	}

	if score > 100 {
		score = 100
	}
	return score, RiskLevel(score), reasons
}

// RiskLevel maps a fused score to a level label.
func RiskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

// FrictionRecommendation derives the authentication-friction posture for a
// user: "low" lets adaptive auth skip MFA on trusted devices (the UX win for
// well-behaved identities), "normal" keeps standard prompts, "strict" forces
// step-up on every sensitive action.
func FrictionRecommendation(score int, mfaEnrolled bool) string {
	switch {
	case score >= 60:
		return "strict"
	case score < 30 && mfaEnrolled:
		return "low"
	default:
		return "normal"
	}
}
