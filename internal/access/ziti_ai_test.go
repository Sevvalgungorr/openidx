package access

import (
	"testing"
	"time"
)

// baselineFor builds a mature baseline row (old + busy enough to pass the
// maturity gates) for identity id on service svc.
func baselineFor(id, svc string, sessions int64, hourHist map[int]int64, firstSeen, lastSeen time.Time) ZitiActivityBaseline {
	return ZitiActivityBaseline{
		IdentityID:    id,
		IdentityName:  "ident-" + id,
		ServiceID:     svc,
		ServiceName:   "svc-" + svc,
		SessionCount:  sessions,
		HourHistogram: hourHist,
		FirstSeen:     firstSeen,
		LastSeen:      lastSeen,
	}
}

func anomalyTypes(anomalies []ZitiAnomaly) map[string]int {
	out := make(map[string]int)
	for _, a := range anomalies {
		out[a.Type]++
	}
	return out
}

func TestDetectZitiAnomaliesNewService(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	baselines := []ZitiActivityBaseline{
		baselineFor("id1", "svcA", 50, map[int]int64{10: 50}, now.Add(-30*24*time.Hour), now.Add(-time.Hour)),
	}
	obs := []ZitiObservation{
		{IdentityID: "id1", IdentityName: "alice", ServiceID: "svcB", ServiceName: "payroll", At: now},
	}

	anomalies := detectZitiAnomalies(baselines, obs, now)
	types := anomalyTypes(anomalies)
	if types["new_service_access"] != 1 {
		t.Fatalf("expected 1 new_service_access anomaly, got %v", types)
	}
	for _, a := range anomalies {
		if a.Type == "new_service_access" {
			if a.Details["service_id"] != "svcB" {
				t.Errorf("expected service_id svcB in details, got %v", a.Details)
			}
			if a.Status != "open" {
				t.Errorf("expected status open, got %s", a.Status)
			}
		}
	}
}

func TestDetectZitiAnomaliesImmatureBaselineSkipped(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	// Too few sessions AND too young: both maturity gates fail.
	baselines := []ZitiActivityBaseline{
		baselineFor("id1", "svcA", 2, map[int]int64{10: 2}, now.Add(-time.Hour), now.Add(-time.Hour)),
	}
	obs := []ZitiObservation{
		{IdentityID: "id1", ServiceID: "svcB", At: now},
		{IdentityID: "brand-new", ServiceID: "svcC", At: now},
	}

	if anomalies := detectZitiAnomalies(baselines, obs, now); len(anomalies) != 0 {
		t.Fatalf("expected no anomalies for immature/unknown identities, got %d", len(anomalies))
	}
}

func TestDetectZitiAnomaliesOffHours(t *testing.T) {
	now := time.Date(2026, 7, 24, 3, 0, 0, 0, time.UTC) // 03:00 UTC
	// All 100 historic sessions were at 09:00-10:00; hour 3 has zero.
	baselines := []ZitiActivityBaseline{
		baselineFor("id1", "svcA", 100, map[int]int64{9: 60, 10: 40}, now.Add(-60*24*time.Hour), now.Add(-time.Hour)),
	}
	obs := []ZitiObservation{
		{IdentityID: "id1", ServiceID: "svcA", At: now},
	}

	types := anomalyTypes(detectZitiAnomalies(baselines, obs, now))
	if types["off_hours_access"] != 1 {
		t.Fatalf("expected 1 off_hours_access anomaly, got %v", types)
	}
	// Activity within the normal window must NOT trigger it.
	normalObs := []ZitiObservation{{IdentityID: "id1", ServiceID: "svcA", At: time.Date(2026, 7, 24, 9, 30, 0, 0, time.UTC)}}
	types = anomalyTypes(detectZitiAnomalies(baselines, normalObs, time.Date(2026, 7, 24, 9, 30, 0, 0, time.UTC)))
	if types["off_hours_access"] != 0 {
		t.Fatalf("expected no off_hours anomaly at a normal hour, got %v", types)
	}
}

func TestDetectZitiAnomaliesDormantReactivation(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	baselines := []ZitiActivityBaseline{
		baselineFor("id1", "svcA", 40, map[int]int64{10: 40}, now.Add(-120*24*time.Hour), now.Add(-45*24*time.Hour)),
	}
	obs := []ZitiObservation{
		{IdentityID: "id1", ServiceID: "svcA", At: now},
	}

	anomalies := detectZitiAnomalies(baselines, obs, now)
	types := anomalyTypes(anomalies)
	if types["dormant_identity_active"] != 1 {
		t.Fatalf("expected 1 dormant_identity_active anomaly, got %v", types)
	}
	for _, a := range anomalies {
		if a.Type == "dormant_identity_active" && a.Severity != "high" {
			t.Errorf("expected high severity, got %s", a.Severity)
		}
	}
}

func TestDetectZitiAnomaliesSessionSpike(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	baselines := []ZitiActivityBaseline{
		baselineFor("id1", "svcA", 100, map[int]int64{10: 100}, now.Add(-30*24*time.Hour), now.Add(-time.Hour)),
	}
	var obs []ZitiObservation
	for i := 0; i < 20; i++ {
		obs = append(obs, ZitiObservation{IdentityID: "id1", ServiceID: "svcA", At: now})
	}

	types := anomalyTypes(detectZitiAnomalies(baselines, obs, now))
	if types["session_spike"] != 1 {
		t.Fatalf("expected 1 session_spike anomaly, got %v", types)
	}

	// A few sessions must not trigger the spike heuristic.
	types = anomalyTypes(detectZitiAnomalies(baselines, obs[:3], now))
	if types["session_spike"] != 0 {
		t.Fatalf("expected no spike anomaly for 3 sessions, got %v", types)
	}
}

func TestScoreZitiIdentityRisk(t *testing.T) {
	cases := []struct {
		name      string
		sig       zitiRiskSignals
		wantLevel string
	}{
		{"clean identity", zitiRiskSignals{}, "low"},
		{"one medium anomaly", zitiRiskSignals{AnomalySeverities: []string{"medium"}}, "low"},
		{"anomalies plus posture", zitiRiskSignals{AnomalySeverities: []string{"high", "medium"}, PostureFailures: 2}, "high"},
		{"critical pileup", zitiRiskSignals{AnomalySeverities: []string{"critical", "high"}, PostureFailures: 3, NeverEnrolled: true}, "critical"},
		{"never enrolled only", zitiRiskSignals{NeverEnrolled: true}, "low"},
	}
	for _, tc := range cases {
		score, level, _ := scoreZitiIdentityRisk(tc.sig)
		if level != tc.wantLevel {
			t.Errorf("%s: expected level %s, got %s (score %d)", tc.name, tc.wantLevel, level, score)
		}
		if score < 0 || score > 100 {
			t.Errorf("%s: score %d out of range", tc.name, score)
		}
	}

	// Score must be capped at 100 no matter the pileup.
	score, level, _ := scoreZitiIdentityRisk(zitiRiskSignals{
		AnomalySeverities: []string{"critical", "critical", "critical"},
		PostureFailures:   10,
		NeverEnrolled:     true,
		DormantDays:       90,
	})
	if score != 100 || level != "critical" {
		t.Errorf("expected capped 100/critical, got %d/%s", score, level)
	}
}

func TestAnalyzeZitiPolicyHygiene(t *testing.T) {
	policies := []ZitiServicePolicyInfo{
		{ID: "p1", Name: "everyone-dials-everything", Type: "Dial", ServiceRoles: []string{"#all"}, IdentityRoles: []string{"#all"}},
		{ID: "p2", Name: "scoped", Type: "Dial", ServiceRoles: []string{"#web"}, IdentityRoles: []string{"#team-a"}},
		{ID: "p3", Name: "open-bind", Type: "Bind", ServiceRoles: []string{"#web"}, IdentityRoles: []string{"#all"}},
	}
	services := []ZitiServiceInfo{
		{ID: "s1", Name: "used-service"},
		{ID: "s2", Name: "ghost-service"},
	}
	enrollment := &struct {
		OTT *struct {
			JWT string `json:"jwt"`
		} `json:"ott,omitempty"`
	}{OTT: &struct {
		JWT string `json:"jwt"`
	}{JWT: "pending.jwt.token"}}
	identities := []ZitiIdentityInfo{
		{ID: "i1", Name: "enrolled-user"},
		{ID: "i2", Name: "never-enrolled-user", Enrollment: enrollment},
	}
	baselines := []ZitiActivityBaseline{
		{IdentityID: "i1", ServiceID: "s1", SessionCount: 30},
	}

	recs := analyzeZitiPolicyHygiene(policies, services, identities, baselines)
	byType := make(map[string][]ZitiRecommendation)
	for _, r := range recs {
		byType[r.Type] = append(byType[r.Type], r)
	}

	if len(byType["over_permissive_policy"]) != 2 {
		t.Fatalf("expected 2 over-permissive findings, got %d", len(byType["over_permissive_policy"]))
	}
	for _, r := range byType["over_permissive_policy"] {
		if r.TargetID == "p3" && r.Severity != "critical" {
			t.Errorf("bind #all policy should be critical, got %s", r.Severity)
		}
		if r.TargetID == "p1" && r.Severity != "high" {
			t.Errorf("dial #all policy should be high, got %s", r.Severity)
		}
		if r.TargetID == "p2" {
			t.Error("scoped policy must not be flagged")
		}
	}

	unused := byType["unused_service"]
	if len(unused) != 1 || unused[0].TargetID != "s2" {
		t.Fatalf("expected exactly ghost-service flagged unused, got %+v", unused)
	}

	unenrolled := byType["unenrolled_identity"]
	if len(unenrolled) != 1 || unenrolled[0].TargetID != "i2" {
		t.Fatalf("expected exactly never-enrolled-user flagged, got %+v", unenrolled)
	}
}

func TestAnalyzeZitiPolicyHygieneEmptyBaselineSkipsUnused(t *testing.T) {
	services := []ZitiServiceInfo{{ID: "s1", Name: "svc"}}
	recs := analyzeZitiPolicyHygiene(nil, services, nil, nil)
	for _, r := range recs {
		if r.Type == "unused_service" {
			t.Fatal("no unused-service findings expected while the baseline is empty")
		}
	}
}

func TestParseZitiSemverMajor(t *testing.T) {
	cases := map[string]int{
		"v2.0.1":       2,
		"v2.0.0-pre12": 2,
		"1.1.15":       1,
		"v1.6.5":       1,
		"":             0,
		"garbage":      0,
	}
	for in, want := range cases {
		if got := parseZitiSemverMajor(in); got != want {
			t.Errorf("parseZitiSemverMajor(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestDeriveZitiControllerFeatures(t *testing.T) {
	v2 := deriveZitiControllerFeatures("v2.0.1", nil)
	if !v2.HAControllers || !v2.OIDCAuth || !v2.JWTSessionAuth || !v2.GranularPermissions {
		t.Errorf("v2 controller should report all v2 features: %+v", v2)
	}
	if len(v2.Advisories) != 0 {
		t.Errorf("v2 controller should carry no upgrade advisories, got %v", v2.Advisories)
	}

	v1 := deriveZitiControllerFeatures("v1.1.15", nil)
	if v1.HAControllers || v1.JWTSessionAuth {
		t.Errorf("v1 controller should not report v2 features: %+v", v1)
	}
	if len(v1.Advisories) == 0 {
		t.Error("v1 controller should carry an upgrade advisory")
	}

	// Capability strings can grant features even below v2.
	v1caps := deriveZitiControllerFeatures("v1.6.5", []string{"OIDC_AUTH", "HA_CONTROLLER"})
	if !v1caps.OIDCAuth || !v1caps.HAControllers {
		t.Errorf("capabilities should enable features: %+v", v1caps)
	}
}
