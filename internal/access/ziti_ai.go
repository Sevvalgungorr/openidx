// Package access - AI-driven network intelligence for the Ziti overlay.
//
// The engine learns per-identity behavioral baselines from the controller's
// live session state (which services each identity dials, when, and how much),
// detects deviations from those baselines as anomalies, fuses the anomaly
// ledger with posture results and enrollment state into a per-identity risk
// score, and derives policy-hygiene recommendations (over-permissive #all
// policies, unused services, never-enrolled identities). High-risk identities
// can be quarantined: role attributes are swapped for a lone `quarantined`
// attribute (severing every attribute-based policy grant) and live sessions
// are terminated; the prior attributes are saved so unquarantine restores
// them exactly.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// sanitizeForLog strips CR/LF from user-supplied values before they are written
// to logs, preventing forged or split log entries (CWE-117 log injection).
func sanitizeForLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// Baseline maturity gates: an identity's baseline only produces anomalies once
// it has enough history to be meaningful, otherwise every new identity would
// light up the ledger on its first session.
const (
	zitiBaselineMinSessions = 10
	zitiBaselineMinAge      = 24 * time.Hour
	// Off-hours detection needs a denser histogram before an "unusual hour" is
	// statistically interesting.
	zitiOffHoursMinSessions = 20
	// An hour bucket holding under this fraction of the identity's activity is
	// considered outside its normal working pattern.
	zitiOffHoursFraction = 0.02
	// A dormant identity is one silent for this long before reappearing.
	zitiDormantAfter = 30 * 24 * time.Hour
	// Session-spike heuristic: a single identity holding at least this many
	// concurrent sessions AND at least this share of the whole snapshot.
	zitiSpikeMinSessions = 15
	zitiSpikeShare       = 0.20
)

// ZitiActivityBaseline is one learned (identity, service) usage row.
// ServiceID "" tracks overlay logins (api-sessions) rather than service dials.
type ZitiActivityBaseline struct {
	IdentityID    string        `json:"identity_id"`
	IdentityName  string        `json:"identity_name"`
	ServiceID     string        `json:"service_id"`
	ServiceName   string        `json:"service_name"`
	SessionCount  int64         `json:"session_count"`
	HourHistogram map[int]int64 `json:"hour_histogram"`
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
}

// ZitiObservation is one live data point from the controller: identity X has a
// session toward service Y (or an overlay login when ServiceID is empty).
type ZitiObservation struct {
	IdentityID   string
	IdentityName string
	ServiceID    string
	ServiceName  string
	At           time.Time
}

// ZitiAnomaly is one detected deviation from an identity's baseline.
type ZitiAnomaly struct {
	ID           string                 `json:"id"`
	IdentityID   string                 `json:"identity_id"`
	IdentityName string                 `json:"identity_name"`
	Type         string                 `json:"anomaly_type"`
	Severity     string                 `json:"severity"`
	Score        float64                `json:"score"`
	Details      map[string]interface{} `json:"details"`
	Status       string                 `json:"status"`
	DetectedAt   time.Time              `json:"detected_at"`
	ResolvedAt   *time.Time             `json:"resolved_at,omitempty"`
}

// ZitiIdentityRisk is the fused per-identity risk assessment.
type ZitiIdentityRisk struct {
	IdentityID   string `json:"identity_id"`
	IdentityName string `json:"identity_name"`
	// Subject answers "whose access is this?". The overlay names a synced
	// identity after the user's UUID, which tells an admin nothing — and the
	// only action on this screen (quarantine) cuts that person off. Resolving
	// it here means the destructive action is never offered anonymously.
	Subject         string   `json:"subject"`
	SubjectKind     string   `json:"subject_kind"`
	Email           string   `json:"email,omitempty"`
	Source          string   `json:"source,omitempty"`
	Score           int      `json:"score"`
	Level           string   `json:"level"`
	Signals         []string `json:"signals"`
	OpenAnomalies   int      `json:"open_anomalies"`
	PostureFailures int      `json:"posture_failures"`
	Quarantined     bool     `json:"quarantined"`
}

// ZitiRecommendation is one policy-hygiene finding with a suggested action.
type ZitiRecommendation struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	TargetID    string `json:"target_id,omitempty"`
	TargetName  string `json:"target_name,omitempty"`
	Action      string `json:"action"`
}

// ZitiAIAnalysisResult summarizes one analysis pass.
type ZitiAIAnalysisResult struct {
	Observations       int       `json:"observations"`
	NewAnomalies       int       `json:"new_anomalies"`
	BaselineIdentities int       `json:"baseline_identities"`
	AnalyzedAt         time.Time `json:"analyzed_at"`
}

// ---------------------------------------------------------------------------
// Pure detection / scoring logic (unit-testable, no I/O)
// ---------------------------------------------------------------------------

// zitiIdentityProfile is the per-identity rollup of its baseline rows.
type zitiIdentityProfile struct {
	services      map[string]bool // service IDs previously seen
	total         int64
	hourHistogram map[int]int64
	firstSeen     time.Time
	lastSeen      time.Time
}

func buildZitiIdentityProfiles(baselines []ZitiActivityBaseline) map[string]*zitiIdentityProfile {
	profiles := make(map[string]*zitiIdentityProfile)
	for _, b := range baselines {
		p := profiles[b.IdentityID]
		if p == nil {
			p = &zitiIdentityProfile{
				services:      make(map[string]bool),
				hourHistogram: make(map[int]int64),
				firstSeen:     b.FirstSeen,
				lastSeen:      b.LastSeen,
			}
			profiles[b.IdentityID] = p
		}
		if b.ServiceID != "" {
			p.services[b.ServiceID] = true
		}
		p.total += b.SessionCount
		for h, n := range b.HourHistogram {
			p.hourHistogram[h] += n
		}
		if b.FirstSeen.Before(p.firstSeen) {
			p.firstSeen = b.FirstSeen
		}
		if b.LastSeen.After(p.lastSeen) {
			p.lastSeen = b.LastSeen
		}
	}
	return profiles
}

func (p *zitiIdentityProfile) mature(now time.Time) bool {
	return p.total >= zitiBaselineMinSessions && now.Sub(p.firstSeen) >= zitiBaselineMinAge
}

// detectZitiAnomalies compares a live observation snapshot against learned
// baselines and returns the deviations. Identities without a mature baseline
// are skipped (still learning).
func detectZitiAnomalies(baselines []ZitiActivityBaseline, obs []ZitiObservation, now time.Time) []ZitiAnomaly {
	profiles := buildZitiIdentityProfiles(baselines)

	byIdentity := make(map[string][]ZitiObservation)
	names := make(map[string]string)
	for _, o := range obs {
		if o.IdentityID == "" {
			continue
		}
		byIdentity[o.IdentityID] = append(byIdentity[o.IdentityID], o)
		if o.IdentityName != "" {
			names[o.IdentityID] = o.IdentityName
		}
	}

	var out []ZitiAnomaly
	add := func(identityID, anomalyType, severity string, score float64, details map[string]interface{}) {
		out = append(out, ZitiAnomaly{
			IdentityID:   identityID,
			IdentityName: names[identityID],
			Type:         anomalyType,
			Severity:     severity,
			Score:        score,
			Details:      details,
			Status:       "open",
			DetectedAt:   now,
		})
	}

	// Deterministic iteration order keeps output stable for tests and dedupe.
	identityIDs := make([]string, 0, len(byIdentity))
	for id := range byIdentity {
		identityIDs = append(identityIDs, id)
	}
	sort.Strings(identityIDs)

	for _, identityID := range identityIDs {
		identityObs := byIdentity[identityID]
		p := profiles[identityID]
		if p == nil || !p.mature(now) {
			continue
		}

		// Dormant identity reactivation: silent for 30+ days, now active.
		if now.Sub(p.lastSeen) >= zitiDormantAfter {
			add(identityID, "dormant_identity_active", "high", 75, map[string]interface{}{
				"last_seen":    p.lastSeen,
				"dormant_days": int(now.Sub(p.lastSeen).Hours() / 24),
			})
		}

		// New-service access + off-hours, per observation (one anomaly per
		// distinct service / hour to avoid duplicates within a snapshot).
		seenNewServices := make(map[string]bool)
		seenOffHours := make(map[int]bool)
		for _, o := range identityObs {
			if o.ServiceID != "" && !p.services[o.ServiceID] && !seenNewServices[o.ServiceID] {
				seenNewServices[o.ServiceID] = true
				add(identityID, "new_service_access", "medium", 60, map[string]interface{}{
					"service_id":   o.ServiceID,
					"service_name": o.ServiceName,
				})
			}
			hour := o.At.UTC().Hour()
			if p.total >= zitiOffHoursMinSessions && !seenOffHours[hour] {
				if float64(p.hourHistogram[hour]) < zitiOffHoursFraction*float64(p.total) {
					seenOffHours[hour] = true
					add(identityID, "off_hours_access", "medium", 55, map[string]interface{}{
						"hour_utc":       hour,
						"historic_count": p.hourHistogram[hour],
						"total_sessions": p.total,
					})
				}
			}
		}

		// Session spike: unusually many concurrent sessions held by one
		// identity, and a dominant share of the whole snapshot.
		if len(identityObs) >= zitiSpikeMinSessions && float64(len(identityObs)) >= zitiSpikeShare*float64(len(obs)) {
			add(identityID, "session_spike", "high", 70, map[string]interface{}{
				"concurrent_sessions": len(identityObs),
				"snapshot_total":      len(obs),
			})
		}
	}
	return out
}

// zitiRiskSignals are the fused inputs to one identity's risk score.
type zitiRiskSignals struct {
	AnomalySeverities []string // severities of open anomalies
	PostureFailures   int
	NeverEnrolled     bool
	DormantDays       int
	Quarantined       bool
}

// scoreZitiIdentityRisk turns the signal set into a 0–100 score and a level.
func scoreZitiIdentityRisk(sig zitiRiskSignals) (int, string, []string) {
	score := 0
	var reasons []string

	anomalyPoints := 0
	for _, sev := range sig.AnomalySeverities {
		switch sev {
		case "critical":
			anomalyPoints += 40
		case "high":
			anomalyPoints += 25
		case "medium":
			anomalyPoints += 15
		default:
			anomalyPoints += 5
		}
	}
	if anomalyPoints > 70 {
		anomalyPoints = 70
	}
	if anomalyPoints > 0 {
		reasons = append(reasons, fmt.Sprintf("%d open anomalies", len(sig.AnomalySeverities)))
	}
	score += anomalyPoints

	posturePoints := sig.PostureFailures * 10
	if posturePoints > 30 {
		posturePoints = 30
	}
	if posturePoints > 0 {
		reasons = append(reasons, fmt.Sprintf("%d failing posture checks", sig.PostureFailures))
	}
	score += posturePoints

	if sig.NeverEnrolled {
		score += 10
		reasons = append(reasons, "enrollment never completed")
	}
	if sig.DormantDays >= 30 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("dormant for %d days", sig.DormantDays))
	}
	if sig.Quarantined {
		reasons = append(reasons, "quarantined")
	}

	if score > 100 {
		score = 100
	}
	level := "low"
	switch {
	case score >= 80:
		level = "critical"
	case score >= 60:
		level = "high"
	case score >= 30:
		level = "medium"
	}
	return score, level, reasons
}

// analyzeZitiPolicyHygiene derives recommendations from the fabric's current
// policy/service/identity state plus the learned activity baselines.
func analyzeZitiPolicyHygiene(policies []ZitiServicePolicyInfo, services []ZitiServiceInfo, identities []ZitiIdentityInfo, baselines []ZitiActivityBaseline) []ZitiRecommendation {
	var out []ZitiRecommendation

	hasAll := func(roles []string) bool {
		for _, r := range roles {
			if r == "#all" {
				return true
			}
		}
		return false
	}
	for _, p := range policies {
		if !hasAll(p.IdentityRoles) {
			continue
		}
		sev, title := "high", "Over-permissive dial policy"
		if strings.EqualFold(p.Type, "Bind") {
			sev, title = "critical", "Over-permissive bind policy"
		}
		out = append(out, ZitiRecommendation{
			Type:       "over_permissive_policy",
			Severity:   sev,
			Title:      title,
			TargetID:   p.ID,
			TargetName: p.Name,
			Description: fmt.Sprintf("Service policy %q grants %s access to #all identities. Every identity on the overlay matches it, defeating least-privilege segmentation.",
				p.Name, strings.ToLower(p.Type)),
			Action: "Replace #all with scoped identity role attributes (e.g. per-team or per-org attributes).",
		})
	}

	activeServices := make(map[string]bool)
	for _, b := range baselines {
		if b.ServiceID != "" && b.SessionCount > 0 {
			activeServices[b.ServiceID] = true
		}
	}
	// Only flag unused services once the engine has observed some activity at
	// all — with an empty baseline every service would be "unused".
	if len(activeServices) > 0 {
		for _, svc := range services {
			if !activeServices[svc.ID] {
				out = append(out, ZitiRecommendation{
					Type:        "unused_service",
					Severity:    "low",
					Title:       "Service with no observed activity",
					TargetID:    svc.ID,
					TargetName:  svc.Name,
					Description: fmt.Sprintf("Service %q has no recorded sessions in the learned activity baseline. Unused services widen the attack surface for no benefit.", svc.Name),
					Action:      "Verify the service is still needed; decommission it or its policies if not.",
				})
			}
		}
	}

	for _, ident := range identities {
		if ident.Enrollment != nil && ident.Enrollment.OTT != nil {
			out = append(out, ZitiRecommendation{
				Type:        "unenrolled_identity",
				Severity:    "medium",
				Title:       "Identity never enrolled",
				TargetID:    ident.ID,
				TargetName:  ident.Name,
				Description: fmt.Sprintf("Identity %q still has a pending one-time enrollment token. An unclaimed enrollment JWT is a live network-join credential.", ident.Name),
				Action:      "Complete the enrollment or delete the identity to invalidate the token.",
			})
		}
	}

	return out
}

// ---------------------------------------------------------------------------
// Controller feature detection (OpenZiti v2.0 readiness)
// ---------------------------------------------------------------------------

// ZitiControllerFeatures reports the controller's version and which
// v2.0-generation capabilities it offers.
type ZitiControllerFeatures struct {
	Version             string   `json:"version"`
	SemverMajor         int      `json:"semver_major"`
	HAControllers       bool     `json:"ha_controllers"`
	OIDCAuth            bool     `json:"oidc_auth"`
	JWTSessionAuth      bool     `json:"jwt_session_auth"`
	GranularPermissions bool     `json:"granular_permissions"`
	Capabilities        []string `json:"capabilities,omitempty"`
	Advisories          []string `json:"advisories,omitempty"`
}

// parseZitiSemverMajor extracts the major version from strings like
// "v2.0.1", "1.1.15" or "v2.0.0-pre12". Returns 0 when unparseable.
func parseZitiSemverMajor(version string) int {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if i := strings.IndexAny(v, ".-+"); i > 0 {
		v = v[:i]
	}
	major, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return major
}

// deriveZitiControllerFeatures maps a controller version + capability list to
// feature flags and upgrade advisories.
func deriveZitiControllerFeatures(version string, capabilities []string) *ZitiControllerFeatures {
	major := parseZitiSemverMajor(version)
	f := &ZitiControllerFeatures{
		Version:      version,
		SemverMajor:  major,
		Capabilities: capabilities,
	}
	capSet := make(map[string]bool, len(capabilities))
	for _, c := range capabilities {
		capSet[strings.ToUpper(c)] = true
	}
	// v2.0 made HA controllers GA, OIDC the default auth path and JWTs the
	// session mechanism; the granular permissions model shipped as beta.
	f.HAControllers = major >= 2 || capSet["HA_CONTROLLER"]
	f.OIDCAuth = major >= 2 || capSet["OIDC_AUTH"]
	f.JWTSessionAuth = major >= 2
	f.GranularPermissions = major >= 2
	if major > 0 && major < 2 {
		f.Advisories = append(f.Advisories,
			"OpenZiti v2.0 is available: HA controllers, JWT/OIDC-default authentication and a granular permissions model. Legacy API sessions are deprecated for removal in v3.0.",
			"Upgrade order matters: v2.x routers require v2.x controllers — upgrade controllers first, then routers.")
	}
	return f
}

// GetControllerFeatures queries the controller's version endpoint and derives
// its v2.0-generation feature set.
func (zm *ZitiManager) GetControllerFeatures(ctx context.Context) (*ZitiControllerFeatures, error) {
	info, err := zm.GetControllerVersion(ctx)
	if err != nil {
		return nil, err
	}
	version := ""
	var capabilities []string
	if data, ok := info["data"].(map[string]interface{}); ok {
		if v, ok := data["version"].(string); ok {
			version = v
		}
		if caps, ok := data["capabilities"].([]interface{}); ok {
			for _, c := range caps {
				if s, ok := c.(string); ok {
					capabilities = append(capabilities, s)
				}
			}
		}
	}
	return deriveZitiControllerFeatures(version, capabilities), nil
}

// ---------------------------------------------------------------------------
// Engine I/O: snapshots, baselines, the analysis pass
// ---------------------------------------------------------------------------

// snapshotZitiObservations reads the controller's live session state — service
// dials (sessions) and overlay logins (api-sessions) — as observations.
func (zm *ZitiManager) snapshotZitiObservations(ctx context.Context) ([]ZitiObservation, error) {
	var out []ZitiObservation

	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/sessions?limit=500&sort=createdAt%20desc", nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
		var resp struct {
			Data []struct {
				CreatedAt time.Time `json:"createdAt"`
				Service   struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"service"`
				APISession struct {
					Identity struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"identity"`
					IdentityID string `json:"identityId"`
				} `json:"apiSession"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &resp); err == nil {
			for _, d := range resp.Data {
				identityID := d.APISession.Identity.ID
				if identityID == "" {
					identityID = d.APISession.IdentityID
				}
				out = append(out, ZitiObservation{
					IdentityID:   identityID,
					IdentityName: d.APISession.Identity.Name,
					ServiceID:    d.Service.ID,
					ServiceName:  d.Service.Name,
					At:           d.CreatedAt,
				})
			}
		}
	}

	apiSessions, err := zm.listFabricAPISessions(ctx)
	if err != nil {
		zm.logger.Debug("ziti ai: list api-sessions failed", zap.Error(err))
	}
	for _, s := range apiSessions {
		out = append(out, ZitiObservation{
			IdentityID:   s.IdentityID,
			IdentityName: s.IdentityName,
			At:           s.CreatedAt,
		})
	}
	return out, nil
}

// loadZitiBaselines reads every learned activity row.
func (zm *ZitiManager) loadZitiBaselines(ctx context.Context) ([]ZitiActivityBaseline, error) {
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT identity_id, COALESCE(identity_name,''), service_id, COALESCE(service_name,''),
		        session_count, hour_histogram, first_seen, last_seen
		   FROM ziti_identity_activity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ZitiActivityBaseline
	for rows.Next() {
		var b ZitiActivityBaseline
		var histRaw []byte
		if err := rows.Scan(&b.IdentityID, &b.IdentityName, &b.ServiceID, &b.ServiceName,
			&b.SessionCount, &histRaw, &b.FirstSeen, &b.LastSeen); err != nil {
			return nil, err
		}
		b.HourHistogram = make(map[int]int64)
		var hist map[string]int64
		if err := json.Unmarshal(histRaw, &hist); err == nil {
			for k, v := range hist {
				if h, err := strconv.Atoi(k); err == nil {
					b.HourHistogram[h] = v
				}
			}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// updateZitiBaselines folds an observation snapshot into the learned rows.
// A live session can be observed by several passes, so counts weight recurring
// usage rather than measuring exact dial totals — fine for a behavioral
// baseline, which only needs relative shape.
func (zm *ZitiManager) updateZitiBaselines(ctx context.Context, obs []ZitiObservation) error {
	type key struct{ identityID, serviceID string }
	type agg struct {
		identityName, serviceName string
		count                     int64
		hours                     map[int]int64
		lastSeen                  time.Time
	}
	grouped := make(map[key]*agg)
	for _, o := range obs {
		if o.IdentityID == "" {
			continue
		}
		k := key{o.IdentityID, o.ServiceID}
		a := grouped[k]
		if a == nil {
			a = &agg{hours: make(map[int]int64)}
			grouped[k] = a
		}
		a.count++
		a.hours[o.At.UTC().Hour()]++
		if o.At.After(a.lastSeen) {
			a.lastSeen = o.At
		}
		if o.IdentityName != "" {
			a.identityName = o.IdentityName
		}
		if o.ServiceName != "" {
			a.serviceName = o.ServiceName
		}
	}

	for k, a := range grouped {
		histJSON, _ := json.Marshal(hourHistToJSON(a.hours))
		// Merge histograms in SQL: existing || increments would overwrite, so
		// fetch-merge-write per hour via jsonb concatenation of summed values.
		_, err := zm.db.Pool.Exec(ctx, `
			INSERT INTO ziti_identity_activity
			    (identity_id, identity_name, service_id, service_name, session_count, hour_histogram, first_seen, last_seen)
			VALUES ($1, NULLIF($2,''), $3, NULLIF($4,''), $5, $6::jsonb, NOW(), $7)
			ON CONFLICT (identity_id, service_id) DO UPDATE SET
			    identity_name  = COALESCE(NULLIF(EXCLUDED.identity_name,''), ziti_identity_activity.identity_name),
			    service_name   = COALESCE(NULLIF(EXCLUDED.service_name,''), ziti_identity_activity.service_name),
			    session_count  = ziti_identity_activity.session_count + EXCLUDED.session_count,
			    hour_histogram = (
			        SELECT COALESCE(jsonb_object_agg(hour, total), '{}'::jsonb) FROM (
			            SELECT COALESCE(a.key, b.key) AS hour,
			                   COALESCE(a.value::bigint, 0) + COALESCE(b.value::bigint, 0) AS total
			              FROM jsonb_each_text(ziti_identity_activity.hour_histogram) a
			              FULL OUTER JOIN jsonb_each_text(EXCLUDED.hour_histogram) b ON a.key = b.key
			        ) merged
			    ),
			    last_seen      = GREATEST(ziti_identity_activity.last_seen, EXCLUDED.last_seen)`,
			k.identityID, a.identityName, k.serviceID, a.serviceName, a.count, string(histJSON), a.lastSeen)
		if err != nil {
			return err
		}
	}
	return nil
}

func hourHistToJSON(hours map[int]int64) map[string]int64 {
	out := make(map[string]int64, len(hours))
	for h, n := range hours {
		out[strconv.Itoa(h)] = n
	}
	return out
}

// RunZitiAIAnalysis executes one full pass: snapshot the fabric, detect
// anomalies against the learned baselines, persist new anomalies (deduped
// against still-open ones of the same type per identity), then fold the
// snapshot into the baselines.
func (zm *ZitiManager) RunZitiAIAnalysis(ctx context.Context) (*ZitiAIAnalysisResult, error) {
	obs, err := zm.snapshotZitiObservations(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot fabric state: %w", err)
	}
	baselines, err := zm.loadZitiBaselines(ctx)
	if err != nil {
		return nil, fmt.Errorf("load baselines: %w", err)
	}

	now := time.Now()
	anomalies := detectZitiAnomalies(baselines, obs, now)

	// Dedupe against still-open anomalies of the same (identity, type).
	openPairs := make(map[string]bool)
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT identity_id, anomaly_type FROM ziti_ai_anomalies WHERE status = 'open'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var identityID, anomalyType string
		if err := rows.Scan(&identityID, &anomalyType); err == nil {
			openPairs[identityID+"|"+anomalyType] = true
		}
	}
	rows.Close()

	inserted := 0
	for _, a := range anomalies {
		if openPairs[a.IdentityID+"|"+a.Type] {
			continue
		}
		openPairs[a.IdentityID+"|"+a.Type] = true
		detailsJSON, _ := json.Marshal(a.Details)
		if _, err := zm.db.Pool.Exec(ctx, `
			INSERT INTO ziti_ai_anomalies (identity_id, identity_name, anomaly_type, severity, score, details, detected_at)
			VALUES ($1, NULLIF($2,''), $3, $4, $5, $6::jsonb, $7)`,
			a.IdentityID, a.IdentityName, a.Type, a.Severity, a.Score, string(detailsJSON), a.DetectedAt); err != nil {
			zm.logger.Warn("ziti ai: persist anomaly failed", zap.Error(err))
			continue
		}
		inserted++
	}

	if err := zm.updateZitiBaselines(ctx, obs); err != nil {
		zm.logger.Warn("ziti ai: baseline update failed", zap.Error(err))
	}

	profiles := buildZitiIdentityProfiles(baselines)
	_ = zm.RecordMetric(ctx, "ai_analysis_anomalies", "ziti-ai", float64(inserted), nil)

	return &ZitiAIAnalysisResult{
		Observations:       len(obs),
		NewAnomalies:       inserted,
		BaselineIdentities: len(profiles),
		AnalyzedAt:         now,
	}, nil
}

// ListZitiAnomalies returns anomalies from the ledger, optionally filtered by
// status, newest first.
func (zm *ZitiManager) ListZitiAnomalies(ctx context.Context, status string, limit int) ([]ZitiAnomaly, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, identity_id, COALESCE(identity_name,''), anomaly_type, severity, score, details, status, detected_at, resolved_at
	            FROM ziti_ai_anomalies`
	args := []interface{}{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY detected_at DESC LIMIT %d`, limit)

	rows, err := zm.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ZitiAnomaly{}
	for rows.Next() {
		var a ZitiAnomaly
		var detailsRaw []byte
		if err := rows.Scan(&a.ID, &a.IdentityID, &a.IdentityName, &a.Type, &a.Severity,
			&a.Score, &detailsRaw, &a.Status, &a.DetectedAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detailsRaw, &a.Details)
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateZitiAnomalyStatus moves an anomaly through its lifecycle
// (open → acknowledged → resolved).
func (zm *ZitiManager) UpdateZitiAnomalyStatus(ctx context.Context, id, status string) error {
	switch status {
	case "open", "acknowledged", "resolved":
	default:
		return fmt.Errorf("invalid status %q", status)
	}
	var resolvedAt interface{}
	if status == "resolved" {
		resolvedAt = time.Now()
	}
	tag, err := zm.db.Pool.Exec(ctx,
		`UPDATE ziti_ai_anomalies SET status = $2, resolved_at = $3 WHERE id = $1`,
		id, status, resolvedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("anomaly not found: %s", id)
	}
	return nil
}

// ComputeZitiIdentityRisks fuses open anomalies, posture failures, enrollment
// state, dormancy and quarantine state into a per-identity risk score.
func (zm *ZitiManager) ComputeZitiIdentityRisks(ctx context.Context) ([]ZitiIdentityRisk, error) {
	identities, err := zm.ListIdentities(ctx)
	if err != nil {
		return nil, err
	}

	anomaliesByIdentity := make(map[string][]string)
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT identity_id, severity FROM ziti_ai_anomalies WHERE status = 'open'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var identityID, severity string
		if err := rows.Scan(&identityID, &severity); err == nil {
			anomaliesByIdentity[identityID] = append(anomaliesByIdentity[identityID], severity)
		}
	}
	rows.Close()

	// Posture results key on the OpenIDX-side identity UUID; synced Ziti
	// identities are named with that UUID, so match by identity name.
	postureFailures := make(map[string]int)
	rows, err = zm.db.Pool.Query(ctx,
		//orgscope:ignore controller-wide risk rollup over the Ziti fabric (identities span orgs, like the other ziti_* reads); aggregates failure counts keyed by identity, exposed only via admin-gated fabric endpoints
		`SELECT identity_id::text, COUNT(*) FROM device_posture_results
		 WHERE passed = false AND (expires_at IS NULL OR expires_at > NOW())
		 GROUP BY identity_id`)
	if err == nil {
		for rows.Next() {
			var id string
			var n int
			if err := rows.Scan(&id, &n); err == nil {
				postureFailures[id] = n
			}
		}
		rows.Close()
	}

	quarantined := make(map[string]bool)
	rows, err = zm.db.Pool.Query(ctx, `SELECT identity_id FROM ziti_ai_quarantine`)
	if err == nil {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				quarantined[id] = true
			}
		}
		rows.Close()
	}

	baselines, err := zm.loadZitiBaselines(ctx)
	if err != nil {
		zm.logger.Debug("ziti ai: load baselines for risk failed", zap.Error(err))
	}
	profiles := buildZitiIdentityProfiles(baselines)
	// Resolve every identity to the account behind it in one query, so each
	// row can say who it is rather than showing a bare UUID.
	names := make([]string, 0, len(identities))
	for _, ident := range identities {
		names = append(names, ident.Name)
	}
	subjects := zm.resolveIdentitySubjects(ctx, names)

	now := time.Now()
	out := make([]ZitiIdentityRisk, 0, len(identities))
	for _, ident := range identities {
		sig := zitiRiskSignals{
			AnomalySeverities: anomaliesByIdentity[ident.ID],
			PostureFailures:   postureFailures[ident.Name],
			NeverEnrolled:     ident.Enrollment != nil && ident.Enrollment.OTT != nil,
			Quarantined:       quarantined[ident.ID],
		}
		if p := profiles[ident.ID]; p != nil && now.Sub(p.lastSeen) >= zitiDormantAfter {
			sig.DormantDays = int(now.Sub(p.lastSeen).Hours() / 24)
		}
		score, level, reasons := scoreZitiIdentityRisk(sig)
		subj, ok := subjects[ident.Name]
		if !ok {
			subj = IdentitySubject{DisplayName: ident.Name, Kind: "unknown"}
		}
		out = append(out, ZitiIdentityRisk{
			IdentityID:      ident.ID,
			IdentityName:    ident.Name,
			Subject:         subj.DisplayName,
			SubjectKind:     subj.Kind,
			Email:           subj.Email,
			Source:          subj.Source,
			Score:           score,
			Level:           level,
			Signals:         reasons,
			OpenAnomalies:   len(sig.AnomalySeverities),
			PostureFailures: sig.PostureFailures,
			Quarantined:     sig.Quarantined,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, nil
}

// GenerateZitiRecommendations gathers the fabric state and derives
// policy-hygiene recommendations.
func (zm *ZitiManager) GenerateZitiRecommendations(ctx context.Context) ([]ZitiRecommendation, error) {
	policies, err := zm.ListServicePolicies(ctx)
	if err != nil {
		return nil, err
	}
	services, err := zm.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	identities, err := zm.ListIdentities(ctx)
	if err != nil {
		return nil, err
	}
	baselines, err := zm.loadZitiBaselines(ctx)
	if err != nil {
		zm.logger.Debug("ziti ai: load baselines for recommendations failed", zap.Error(err))
	}
	recs := analyzeZitiPolicyHygiene(policies, services, identities, baselines)
	if recs == nil {
		recs = []ZitiRecommendation{}
	}
	return recs, nil
}

// terminateIdentitySessions deletes every edge session held by an identity.
func (zm *ZitiManager) terminateIdentitySessions(ctx context.Context, identityID string) int {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/sessions?limit=500", nil)
	if err != nil || status != http.StatusOK {
		return 0
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			APISession struct {
				Identity struct {
					ID string `json:"id"`
				} `json:"identity"`
				IdentityID string `json:"identityId"`
			} `json:"apiSession"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0
	}
	terminated := 0
	for _, s := range resp.Data {
		owner := s.APISession.Identity.ID
		if owner == "" {
			owner = s.APISession.IdentityID
		}
		if owner != identityID {
			continue
		}
		if _, sc, err := zm.mgmtRequest("DELETE", "/edge/management/v1/sessions/"+s.ID, nil); err == nil &&
			(sc == http.StatusOK || sc == http.StatusNoContent) {
			terminated++
		}
	}
	return terminated
}

// QuarantineZitiIdentity severs an identity's attribute-based access: its role
// attributes are saved and replaced with a lone `quarantined` attribute (which
// no policy should reference), and its live sessions are terminated.
func (zm *ZitiManager) QuarantineZitiIdentity(ctx context.Context, zitiID, reason, actor string) (int, error) {
	var exists bool
	if err := zm.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM ziti_ai_quarantine WHERE identity_id = $1)`, zitiID).Scan(&exists); err != nil {
		return 0, err
	}
	if exists {
		return 0, fmt.Errorf("identity %s is already quarantined", zitiID)
	}

	attrs, err := zm.GetIdentityRoleAttributes(ctx, zitiID)
	if err != nil {
		return 0, fmt.Errorf("read identity attributes: %w", err)
	}
	identityName := ""
	if identities, err := zm.ListIdentities(ctx); err == nil {
		for _, ident := range identities {
			if ident.ID == zitiID {
				identityName = ident.Name
				break
			}
		}
	}

	savedJSON, _ := json.Marshal(attrs)
	if _, err := zm.db.Pool.Exec(ctx, `
		INSERT INTO ziti_ai_quarantine (identity_id, identity_name, saved_attributes, reason, quarantined_by)
		VALUES ($1, NULLIF($2,''), $3::jsonb, NULLIF($4,''), NULLIF($5,''))`,
		zitiID, identityName, string(savedJSON), reason, actor); err != nil {
		return 0, err
	}

	if err := zm.PatchIdentityRoleAttributes(ctx, zitiID, []string{"quarantined"}); err != nil {
		// Roll back the ledger row so the state stays consistent.
		_, _ = zm.db.Pool.Exec(ctx, `DELETE FROM ziti_ai_quarantine WHERE identity_id = $1`, zitiID)
		return 0, fmt.Errorf("patch identity attributes: %w", err)
	}

	terminated := zm.terminateIdentitySessions(ctx, zitiID)
	zm.logger.Info("ziti ai: identity quarantined",
		zap.String("identity_id", sanitizeForLog(zitiID)), zap.Int("sessions_terminated", terminated))
	return terminated, nil
}

// UnquarantineZitiIdentity restores the attributes saved at quarantine time.
func (zm *ZitiManager) UnquarantineZitiIdentity(ctx context.Context, zitiID string) error {
	var savedRaw []byte
	err := zm.db.Pool.QueryRow(ctx,
		`SELECT saved_attributes FROM ziti_ai_quarantine WHERE identity_id = $1`, zitiID).Scan(&savedRaw)
	if err != nil {
		return fmt.Errorf("identity %s is not quarantined", zitiID)
	}
	var attrs []string
	if err := json.Unmarshal(savedRaw, &attrs); err != nil {
		attrs = []string{}
	}
	if attrs == nil {
		attrs = []string{}
	}
	if err := zm.PatchIdentityRoleAttributes(ctx, zitiID, attrs); err != nil {
		return fmt.Errorf("restore identity attributes: %w", err)
	}
	_, err = zm.db.Pool.Exec(ctx, `DELETE FROM ziti_ai_quarantine WHERE identity_id = $1`, zitiID)
	return err
}
