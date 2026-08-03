package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// handleAuthAnalyticsDashboard returns detailed authentication analytics for a given period.
// GET /api/v1/analytics/auth?period=24h|7d|30d|90d
func (s *Service) handleAuthAnalyticsDashboard(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Parse period
	period := c.DefaultQuery("period", "30d")
	interval := periodToInterval(period)

	result := make(map[string]interface{})

	// Total logins
	var totalLogins int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID).Scan(&totalLogins)
	result["total_logins"] = totalLogins

	// Successful logins
	var successLogins int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID).Scan(&successLogins)

	// Failed logins
	var failedLogins int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'failure'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID).Scan(&failedLogins)

	// Rates
	if totalLogins > 0 {
		result["success_rate"] = float64(successLogins) / float64(totalLogins) * 100
		result["failure_rate"] = float64(failedLogins) / float64(totalLogins) * 100
	} else {
		result["success_rate"] = 0.0
		result["failure_rate"] = 0.0
	}

	// MFA usage rate
	var mfaLogins int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'mfa_verification' AND outcome = 'success'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2`, interval, org.ID).Scan(&mfaLogins)

	if successLogins > 0 {
		result["mfa_usage_rate"] = float64(mfaLogins) / float64(successLogins) * 100
	} else {
		result["mfa_usage_rate"] = 0.0
	}

	// Method breakdown
	methodBreakdown := make(map[string]int)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(action, 'unknown'), COUNT(*)
		FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY action
		ORDER BY COUNT(*) DESC
	`, interval, org.ID)
	if err == nil {
		for rows.Next() {
			var method string
			var cnt int
			if rows.Scan(&method, &cnt) == nil {
				methodBreakdown[method] = cnt
			}
		}
		rows.Close()
	}
	result["method_breakdown"] = methodBreakdown

	// Peak hour
	var peakHour *int
	var peakCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT EXTRACT(HOUR FROM timestamp)::int AS hour, COUNT(*) AS cnt
		FROM audit_events
		WHERE event_type = 'authentication'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY hour
		ORDER BY cnt DESC
		LIMIT 1
	`, interval, org.ID).Scan(&peakHour, &peakCount)
	if peakHour != nil {
		result["peak_hour"] = *peakHour
	} else {
		result["peak_hour"] = 0
	}

	// Geo top 5 countries from login_history
	geoTop5 := []map[string]interface{}{}
	geoRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(location, 'Unknown'), COUNT(*) AS cnt
		FROM login_history
		WHERE created_at > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY location
		ORDER BY cnt DESC
		LIMIT 5
	`, interval, org.ID)
	if err == nil {
		for geoRows.Next() {
			var loc string
			var cnt int
			if geoRows.Scan(&loc, &cnt) == nil {
				geoTop5 = append(geoTop5, map[string]interface{}{
					"country": loc,
					"count":   cnt,
				})
			}
		}
		geoRows.Close()
	}
	result["geo_top_5"] = geoTop5
	result["period"] = period

	c.JSON(http.StatusOK, result)
}

// handleUsageAnalytics returns platform usage metrics: DAU, WAU, MAU, entity counts.
// GET /api/v1/analytics/usage
func (s *Service) handleUsageAnalytics(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	result := make(map[string]interface{})

	// DAU: distinct actors who authenticated today
	var dau int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > CURRENT_DATE
		  AND org_id = $1
	`, org.ID).Scan(&dau)
	result["dau"] = dau

	// WAU: distinct actors who authenticated in last 7 days
	var wau int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '7 days'
		  AND org_id = $1
	`, org.ID).Scan(&wau)
	result["wau"] = wau

	// MAU: distinct actors who authenticated in last 30 days
	var mau int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '30 days'
		  AND org_id = $1
	`, org.ID).Scan(&mau)
	result["mau"] = mau

	// New users today
	var newUsersToday int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE created_at > CURRENT_DATE
		  AND org_id = $1
	`, org.ID).Scan(&newUsersToday)
	result["new_users_today"] = newUsersToday

	// Total counts
	var totalUsers int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1`, org.ID).Scan(&totalUsers)
	result["total_users"] = totalUsers

	var totalGroups int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM groups WHERE org_id = $1`, org.ID).Scan(&totalGroups)
	result["total_groups"] = totalGroups

	var totalApplications int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM applications WHERE org_id = $1`, org.ID).Scan(&totalApplications)
	result["total_applications"] = totalApplications

	// Active sessions
	var activeSessions int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE expires_at > NOW()
		  AND org_id = $1
	`, org.ID).Scan(&activeSessions)
	result["active_sessions_count"] = activeSessions

	// Frontend (usage-analytics page) and its unit test read {usage: {...}};
	// returning the flat object left the whole page blank.
	c.JSON(http.StatusOK, gin.H{"usage": result})
}

// handleAPIUsageMetrics returns API usage statistics from the api_usage_metrics table.
// GET /api/v1/analytics/api?period=24h|7d|30d|90d
func (s *Service) handleAPIUsageMetrics(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	period := c.DefaultQuery("period", "30d")
	interval := periodToInterval(period)

	result := make(map[string]interface{})

	// Total requests in period
	var totalRequests int
	s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(request_count), 0)
		FROM api_usage_metrics
		WHERE recorded_at > NOW() - $1::interval`, interval).Scan(&totalRequests)
	result["total_requests"] = totalRequests

	// Top endpoints
	topEndpoints := []map[string]interface{}{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT endpoint, method, SUM(request_count) AS total,
		       AVG(avg_latency_ms) AS avg_lat,
		       SUM(error_count) AS errors
		FROM api_usage_metrics
		WHERE recorded_at > NOW() - $1::interval
		GROUP BY endpoint, method
		ORDER BY total DESC
		LIMIT 10
	`, interval)
	if err == nil {
		for rows.Next() {
			var endpoint, method string
			var total, errors int
			var avgLat float64
			if rows.Scan(&endpoint, &method, &total, &avgLat, &errors) == nil {
				topEndpoints = append(topEndpoints, map[string]interface{}{
					"endpoint":       endpoint,
					"method":         method,
					"total_requests": total,
					"avg_latency_ms": avgLat,
					"error_count":    errors,
				})
			}
		}
		rows.Close()
	}
	result["top_endpoints"] = topEndpoints

	// Overall error rate
	var totalErrors int
	s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(error_count), 0)
		FROM api_usage_metrics
		WHERE recorded_at > NOW() - $1::interval`, interval).Scan(&totalErrors)
	if totalRequests > 0 {
		result["error_rate"] = float64(totalErrors) / float64(totalRequests) * 100
	} else {
		result["error_rate"] = 0.0
	}

	// Average latency across all endpoints
	var avgLatency float64
	s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(avg_latency_ms), 0)
		FROM api_usage_metrics
		WHERE recorded_at > NOW() - $1::interval`, interval).Scan(&avgLatency)
	result["avg_latency_ms"] = avgLatency
	result["period"] = period

	// Frontend reads {api_usage: {...}}.
	c.JSON(http.StatusOK, gin.H{"api_usage": result})
}

// handleFeatureAdoption returns feature adoption metrics from the feature_adoption table.
// GET /api/v1/analytics/features
func (s *Service) handleFeatureAdoption(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Total enabled users for computing adoption rates
	var totalUsers int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1`, org.ID).Scan(&totalUsers)

	features := []map[string]interface{}{}
	featureNames := []string{"mfa_totp", "mfa_webauthn", "passkey_login", "magic_link", "api_keys", "social_login"}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT feature_name, total_users, trend
		FROM feature_adoption
		WHERE feature_name = ANY($1)
		ORDER BY total_users DESC
	`, featureNames)
	if err == nil {
		for rows.Next() {
			var name string
			var featureUsers int
			var trend string
			if rows.Scan(&name, &featureUsers, &trend) == nil {
				var adoptionRate float64
				if totalUsers > 0 {
					adoptionRate = float64(featureUsers) / float64(totalUsers) * 100
				}
				features = append(features, map[string]interface{}{
					"name":          name,
					"total_users":   featureUsers,
					"adoption_rate": adoptionRate,
					"trend":         trend,
				})
			}
		}
		rows.Close()
	}

	// If no rows exist in the feature_adoption table, compute from live data
	if len(features) == 0 {
		// Compute feature usage from actual tables
		// Each query is scoped to the caller's org. org_id-bearing tables carry an
		// `AND org_id = $1` predicate with org.ID passed in Args; webauthn_credentials
		// is not an org-scoped table so it runs without an org filter.
		featureSources := []struct {
			Name  string
			Query string
			Args  []interface{}
		}{
			{"mfa_totp", "SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE enabled = true AND org_id = $1", []interface{}{org.ID}},
			{"mfa_webauthn", "SELECT COUNT(DISTINCT user_id) FROM mfa_webauthn WHERE org_id = $1", []interface{}{org.ID}},
			{"passkey_login", "SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE action = 'passkey_login' AND timestamp > NOW() - INTERVAL '30 days' AND org_id = $1", []interface{}{org.ID}},
			{"magic_link", "SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE action = 'magic_link_login' AND timestamp > NOW() - INTERVAL '30 days' AND org_id = $1", []interface{}{org.ID}},
			{"api_keys", "SELECT COUNT(DISTINCT COALESCE(user_id, service_account_id)) FROM api_keys WHERE revoked_at IS NULL AND org_id = $1", []interface{}{org.ID}},
			{"social_login", "SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE action = 'social_login' AND timestamp > NOW() - INTERVAL '30 days' AND org_id = $1", []interface{}{org.ID}},
		}

		for _, fs := range featureSources {
			var count int
			s.db.Pool.QueryRow(ctx, fs.Query, fs.Args...).Scan(&count)
			var adoptionRate float64
			if totalUsers > 0 {
				adoptionRate = float64(count) / float64(totalUsers) * 100
			}
			features = append(features, map[string]interface{}{
				"name":          fs.Name,
				"total_users":   count,
				"adoption_rate": adoptionRate,
				"trend":         "stable",
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		// Frontend reads {adoption: {features: [...]}}.
		"adoption": gin.H{
			"total_users": totalUsers,
			"features":    features,
		},
	})
}

// handleRiskScoreTimeline returns daily risk score trends.
// GET /api/v1/analytics/risk-timeline?days=30
func (s *Service) handleRiskScoreTimeline(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	if s.riskService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "risk service not available"})
		return
	}

	days := 30
	if d := c.Query("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(created_at) AS day,
		       AVG(risk_score) AS avg_score,
		       MAX(risk_score) AS max_score,
		       COUNT(*) AS login_count
		FROM login_history
		WHERE created_at > NOW() - make_interval(days => $1)
		  AND org_id = $2
		GROUP BY day
		ORDER BY day
	`, days, org.ID)
	if err != nil {
		s.logger.Error("Failed to query risk timeline", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query risk timeline"})
		return
	}
	defer rows.Close()

	var timeline []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var avgScore float64
		var maxScore, loginCount int
		if err := rows.Scan(&day, &avgScore, &maxScore, &loginCount); err != nil {
			s.logger.Warn("Failed to scan risk timeline row", zap.Error(err))
			continue
		}
		timeline = append(timeline, map[string]interface{}{
			"date":        day.Format("2006-01-02"),
			"avg_score":   int(avgScore),
			"max_score":   maxScore,
			"login_count": loginCount,
		})
	}

	if timeline == nil {
		timeline = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"days":     days,
		"timeline": timeline,
	})
}

// handleUserActivityHeatmap returns a 24x7 heatmap of login activity (hour x day of week).
// GET /api/v1/analytics/activity-heatmap?period=30d
func (s *Service) handleUserActivityHeatmap(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	period := c.DefaultQuery("period", "30d")
	interval := periodToInterval(period)

	// Query: hour of day (0-23) x day of week (0=Sunday through 6=Saturday)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT EXTRACT(DOW FROM timestamp)::int AS dow,
		       EXTRACT(HOUR FROM timestamp)::int AS hour,
		       COUNT(*) AS cnt
		FROM audit_events
		WHERE event_type = 'authentication'
		  AND timestamp > NOW() - $1::interval
		  AND org_id = $2
		GROUP BY dow, hour
		ORDER BY dow, hour
	`, interval, org.ID)
	if err != nil {
		s.logger.Error("Failed to query activity heatmap", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query activity heatmap"})
		return
	}
	defer rows.Close()

	// Build a 7x24 matrix
	dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	heatmap := make([]map[string]interface{}, 0)

	for rows.Next() {
		var dow, hour, cnt int
		if rows.Scan(&dow, &hour, &cnt) == nil {
			dayName := "Unknown"
			if dow >= 0 && dow < len(dayNames) {
				dayName = dayNames[dow]
			}
			heatmap = append(heatmap, map[string]interface{}{
				"day_of_week": dow,
				"day_name":    dayName,
				"hour":        hour,
				"count":       cnt,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"period":  period,
		"heatmap": heatmap,
	})
}

// periodToInterval converts a period string like "24h", "7d", "30d", "90d"
// to a plain interval string safe for use as a parameterized query value
// with PostgreSQL's $N::interval cast.
func periodToInterval(period string) string {
	switch period {
	case "24h":
		return "24 hours"
	case "7d":
		return "7 days"
	case "90d":
		return "90 days"
	case "30d":
		return "30 days"
	default:
		return "30 days"
	}
}
