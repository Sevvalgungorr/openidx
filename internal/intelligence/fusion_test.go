package intelligence

import "testing"

func TestFuseIdentityRiskCleanUser(t *testing.T) {
	score, level, reasons := FuseIdentityRisk(IdentitySignals{
		MFAEnrolled:    true,
		AccountEnabled: true,
		DaysSinceLogin: 2,
		TrustedDevices: 1,
	})
	if level != "low" {
		t.Fatalf("clean user should be low risk, got %s (score %d, reasons %v)", level, score, reasons)
	}
	if score != 0 {
		t.Errorf("clean user should score 0, got %d", score)
	}
}

func TestFuseIdentityRiskNoMFA(t *testing.T) {
	score, _, reasons := FuseIdentityRisk(IdentitySignals{
		AccountEnabled: true,
		DaysSinceLogin: 1,
	})
	if score != 15 {
		t.Errorf("no-MFA user should score 15, got %d", score)
	}
	if len(reasons) != 1 || reasons[0] != "no MFA method enrolled" {
		t.Errorf("expected the no-MFA reason, got %v", reasons)
	}
}

func TestFuseIdentityRiskAlertPileup(t *testing.T) {
	score, level, _ := FuseIdentityRisk(IdentitySignals{
		OpenAlerts:     []string{"critical", "critical", "high"},
		MFAEnrolled:    true,
		AccountEnabled: true,
		DaysSinceLogin: 1,
	})
	// Alert points cap at 50 (30+30+20 = 80 → 50).
	if score != 50 {
		t.Errorf("alert points should cap at 50, got %d", score)
	}
	if level != "medium" {
		t.Errorf("expected medium at 50, got %s", level)
	}
}

func TestFuseIdentityRiskWorstCaseCapped(t *testing.T) {
	score, level, _ := FuseIdentityRisk(IdentitySignals{
		AvgRiskScore:      100,
		MaxRiskScore:      100,
		FailedLogins7d:    20,
		OpenAlerts:        []string{"critical", "critical"},
		DaysSinceLogin:    90,
		UntrustedDevices:  10,
		BreachIncidents:   5,
		ZitiOpenAnomalies: 5,
		AccountEnabled:    true,
	})
	if score != 100 {
		t.Errorf("worst case must cap at 100, got %d", score)
	}
	if level != "critical" {
		t.Errorf("expected critical, got %s", level)
	}
}

func TestFuseIdentityRiskDormancyRequiresEnabled(t *testing.T) {
	enabled, _, _ := FuseIdentityRisk(IdentitySignals{MFAEnrolled: true, AccountEnabled: true, DaysSinceLogin: 60})
	disabled, _, _ := FuseIdentityRisk(IdentitySignals{MFAEnrolled: true, AccountEnabled: false, DaysSinceLogin: 60})
	if enabled != 10 {
		t.Errorf("dormant enabled account should score 10, got %d", enabled)
	}
	if disabled != 0 {
		t.Errorf("disabled account should not accrue dormancy points, got %d", disabled)
	}
}

func TestRiskLevelBoundaries(t *testing.T) {
	cases := map[int]string{0: "low", 29: "low", 30: "medium", 59: "medium", 60: "high", 79: "high", 80: "critical", 100: "critical"}
	for score, want := range cases {
		if got := RiskLevel(score); got != want {
			t.Errorf("RiskLevel(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestFrictionRecommendation(t *testing.T) {
	if got := FrictionRecommendation(10, true); got != "low" {
		t.Errorf("low-risk MFA user should get low friction, got %s", got)
	}
	if got := FrictionRecommendation(10, false); got != "normal" {
		t.Errorf("low-risk user WITHOUT MFA must not get low friction, got %s", got)
	}
	if got := FrictionRecommendation(45, true); got != "normal" {
		t.Errorf("medium risk should be normal friction, got %s", got)
	}
	if got := FrictionRecommendation(75, true); got != "strict" {
		t.Errorf("high risk should be strict friction, got %s", got)
	}
}
