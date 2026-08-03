package risk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// GeoResult represents a geo-IP lookup result
type GeoResult struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Query       string  `json:"query"`
}

// Device represents a known device for a user
type Device struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Location    string    `json:"location"`
	Trusted     bool      `json:"trusted"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// LoginRecord represents a login history entry
type LoginRecord struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Location          string    `json:"location"`
	Latitude          float64   `json:"latitude"`
	Longitude         float64   `json:"longitude"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	RiskScore         int       `json:"risk_score"`
	Success           bool      `json:"success"`
	AuthMethods       []string  `json:"auth_methods"`
	CreatedAt         time.Time `json:"created_at"`
}

// Service provides risk assessment and device management
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	logger *zap.Logger
}

// NewService creates a new risk service
func NewService(db *database.PostgresDB, redis *database.RedisClient, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger.With(zap.String("component", "risk")),
	}
}

// ComputeDeviceFingerprint generates a SHA256 fingerprint from IP subnet and User-Agent.
// Method form retained for existing callers; delegates to the package-level function
// so other services (e.g. the access proxy) can compute an identical fingerprint
// without constructing a risk.Service.
func (s *Service) ComputeDeviceFingerprint(ipAddress, userAgent string) string {
	return ComputeDeviceFingerprint(ipAddress, userAgent)
}

// ComputeDeviceFingerprint generates a SHA256 fingerprint from the IP's /24 subnet
// and the User-Agent: sha256("<x.y.z.0/24>|<userAgent>"). Pure and deterministic.
func ComputeDeviceFingerprint(ipAddress, userAgent string) string {
	// Extract /24 subnet from IP
	subnet := ipAddress
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			subnet = fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
	}

	hash := sha256.Sum256([]byte(subnet + "|" + userAgent))
	return fmt.Sprintf("%x", hash)
}

// RegisterDevice registers or updates a known device for a user
func (s *Service) RegisterDevice(ctx context.Context, userID, fingerprint, ipAddress, userAgent, location string) (string, bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", false, err
	}

	// Try to find existing device
	var deviceID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id FROM known_devices WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3`,
		userID, fingerprint, org.ID).Scan(&deviceID)

	if err == nil {
		// Device exists — update last seen
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE known_devices SET last_seen_at = NOW(), ip_address = $3, location = $4 WHERE id = $1 AND org_id = $5`,
			deviceID, userID, ipAddress, location, org.ID); err != nil {
			return deviceID, false, fmt.Errorf("failed to update device: %w", err)
		}
		return deviceID, false, nil
	}

	// New device — insert
	name := parseDeviceName(userAgent)
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, ip_address, user_agent, location, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen_at = NOW()
		 RETURNING id`,
		userID, fingerprint, name, ipAddress, userAgent, location, org.ID).Scan(&deviceID)
	if err != nil {
		return "", false, fmt.Errorf("failed to register device: %w", err)
	}

	s.logger.Info("New device registered",
		zap.String("user_id", userID),
		zap.String("device_id", deviceID),
		zap.String("ip", ipAddress),
		zap.String("location", location),
	)

	return deviceID, true, nil
}

// IsDeviceTrusted checks if a device is trusted for a user
func (s *Service) IsDeviceTrusted(ctx context.Context, userID, fingerprint string) bool {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}
	var trusted bool
	err = s.db.Pool.QueryRow(ctx,
		`SELECT trusted FROM known_devices WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3`,
		userID, fingerprint, org.ID).Scan(&trusted)
	if err != nil {
		return false
	}
	return trusted
}

// GetDeviceTrustLevel returns the trust level for a device fingerprint
func (s *Service) GetDeviceTrustLevel(ctx context.Context, userID, fingerprint string) TrustLevel {
	org, err := orgctx.From(ctx)
	if err != nil {
		return TrustLevelUnknown
	}
	var seenCount int
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(seen_count, 0) FROM known_devices WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3`,
		userID, fingerprint, org.ID).Scan(&seenCount)
	if err != nil {
		return TrustLevelUnknown
	}

	var trusted bool
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(trusted, false) FROM known_devices WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3`,
		userID, fingerprint, org.ID).Scan(&trusted)
	if err == nil && trusted {
		return TrustLevelTrusted
	}

	// Calculate trust level based on seen count
	if seenCount >= 5 {
		return TrustLevelTrusted
	}
	if seenCount >= 1 {
		return TrustLevelKnown
	}
	return TrustLevelUnknown
}

// GetUserDevices returns all known devices for a user
func (s *Service) GetUserDevices(ctx context.Context, userID string) ([]Device, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, user_id, fingerprint, COALESCE(name,''), COALESCE(ip_address,''), COALESCE(user_agent,''),
		        COALESCE(location,''), trusted, last_seen_at, created_at
		 FROM known_devices WHERE user_id = $1 AND org_id = $2 ORDER BY last_seen_at DESC`, userID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Fingerprint, &d.Name, &d.IPAddress,
			&d.UserAgent, &d.Location, &d.Trusted, &d.LastSeenAt, &d.CreatedAt); err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// GetAllDevices returns all known devices (admin)
func (s *Service) GetAllDevices(ctx context.Context, limit, offset int) ([]Device, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}
	var total int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM known_devices WHERE org_id = $1`, org.ID).Scan(&total)

	rows, err := s.db.Pool.Query(ctx,
		`SELECT d.id, d.user_id, d.fingerprint, COALESCE(d.name,''), COALESCE(d.ip_address,''),
		        COALESCE(d.user_agent,''), COALESCE(d.location,''), d.trusted, d.last_seen_at, d.created_at
		 FROM known_devices d WHERE d.org_id = $3 ORDER BY d.last_seen_at DESC LIMIT $1 OFFSET $2`, limit, offset, org.ID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Fingerprint, &d.Name, &d.IPAddress,
			&d.UserAgent, &d.Location, &d.Trusted, &d.LastSeenAt, &d.CreatedAt); err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, total, nil
}

// TrustDevice marks a device as trusted
func (s *Service) TrustDevice(ctx context.Context, deviceID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE known_devices SET trusted = true WHERE id = $1 AND org_id = $2`, deviceID, org.ID)
	return err
}

// RevokeDevice removes trust or deletes a device
func (s *Service) RevokeDevice(ctx context.Context, deviceID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx,
		`DELETE FROM known_devices WHERE id = $1 AND org_id = $2`, deviceID, org.ID)
	return err
}

// RecordLogin records a login attempt in history
func (s *Service) RecordLogin(ctx context.Context, userID, ip, userAgent, location string, lat, lon float64, fingerprint string, success bool, authMethods []string, riskScore int) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Error("Failed to record login: no org context", zap.Error(err))
		return
	}
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO login_history (user_id, ip_address, user_agent, location, latitude, longitude, device_fingerprint, risk_score, success, auth_methods, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		userID, ip, userAgent, location, lat, lon, fingerprint, riskScore, success, authMethods, org.ID)
	if err != nil {
		s.logger.Error("Failed to record login", zap.Error(err))
	}
}

// GetLoginHistory returns recent login history
func (s *Service) GetLoginHistory(ctx context.Context, userID string, limit int) ([]LoginRecord, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `SELECT id, user_id, ip_address, COALESCE(user_agent,''), COALESCE(location,''),
	                 COALESCE(latitude,0), COALESCE(longitude,0), COALESCE(device_fingerprint,''),
	                 risk_score, success, COALESCE(auth_methods,'{}'), created_at
	          FROM login_history WHERE org_id = $1`
	args := []interface{}{org.ID}

	if userID != "" {
		query += ` AND user_id = $2`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC`

	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []LoginRecord
	for rows.Next() {
		var r LoginRecord
		if err := rows.Scan(&r.ID, &r.UserID, &r.IPAddress, &r.UserAgent, &r.Location,
			&r.Latitude, &r.Longitude, &r.DeviceFingerprint, &r.RiskScore, &r.Success,
			&r.AuthMethods, &r.CreatedAt); err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}

// CalculateRiskScore calculates a risk score for a login attempt
func (s *Service) CalculateRiskScore(ctx context.Context, userID, ip, userAgent, fingerprint, location string, lat, lon float64) (int, []string) {
	score := 0
	var factors []string

	org, err := orgctx.From(ctx)
	if err != nil {
		return 0, factors
	}

	// Factor 1: New device (+30)
	var deviceCount int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3`,
		userID, fingerprint, org.ID).Scan(&deviceCount)
	if deviceCount == 0 {
		score += 30
		factors = append(factors, "new_device")
	}

	// Factor 2: Unusual location (+25) — country differs from last 5 logins
	if location != "" {
		country := extractCountry(location)
		rows, err := s.db.Pool.Query(ctx,
			`SELECT DISTINCT location FROM login_history
			 WHERE user_id = $1 AND success = true AND org_id = $2
			 ORDER BY location LIMIT 5`, userID, org.ID)
		if err == nil {
			defer rows.Close()
			knownCountries := make(map[string]bool)
			for rows.Next() {
				var loc string
				if rows.Scan(&loc) == nil {
					knownCountries[extractCountry(loc)] = true
				}
			}
			if len(knownCountries) > 0 && !knownCountries[country] {
				score += 25
				factors = append(factors, "unusual_location")
			}
		}
	}

	// Factor 3: Failed login attempts in last hour (+10 each, max +50)
	var failedCount int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND success = false AND created_at > NOW() - INTERVAL '1 hour' AND org_id = $2`,
		userID, org.ID).Scan(&failedCount)
	if failedCount > 0 {
		addition := failedCount * 10
		if addition > 50 {
			addition = 50
		}
		score += addition
		factors = append(factors, fmt.Sprintf("failed_attempts_%d", failedCount))
	}

	// Factor 4: Impossible travel (+50)
	if lat != 0 && lon != 0 {
		if s.detectImpossibleTravel(ctx, userID, lat, lon) {
			score += 50
			factors = append(factors, "impossible_travel")
		}
	}

	// Factor 5: Off-hours login (+10) — before 6am or after 10pm UTC
	hour := time.Now().UTC().Hour()
	if hour < 6 || hour >= 22 {
		score += 10
		factors = append(factors, "off_hours")
	}

	// Factor 6: First login from this country ever (+15)
	if location != "" {
		country := extractCountry(location)
		var countryCount int
		s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM login_history WHERE user_id = $1 AND location LIKE $2 AND success = true AND org_id = $3`,
			userID, "%"+country, org.ID).Scan(&countryCount)
		if countryCount == 0 {
			score += 15
			factors = append(factors, "first_country_login")
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	s.logger.Debug("Risk score calculated",
		zap.String("user_id", userID),
		zap.Int("score", score),
		zap.Strings("factors", factors),
	)

	return score, factors
}

// detectImpossibleTravel checks if the user could have physically traveled from their last login location
func (s *Service) detectImpossibleTravel(ctx context.Context, userID string, lat, lon float64) bool {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}

	var lastLat, lastLon float64
	var lastTime time.Time

	err = s.db.Pool.QueryRow(ctx,
		`SELECT latitude, longitude, created_at FROM login_history
		 WHERE user_id = $1 AND success = true AND latitude != 0 AND longitude != 0 AND org_id = $2
		 ORDER BY created_at DESC LIMIT 1`, userID, org.ID).Scan(&lastLat, &lastLon, &lastTime)
	if err != nil {
		return false
	}

	distance := haversineDistance(lastLat, lastLon, lat, lon)
	timeDelta := time.Since(lastTime)

	// If more than 500km in less than 1 hour → impossible travel
	if distance > 500 && timeDelta < time.Hour {
		s.logger.Warn("Impossible travel detected",
			zap.String("user_id", userID),
			zap.Float64("distance_km", distance),
			zap.Duration("time_delta", timeDelta),
		)
		return true
	}

	return false
}

// GeoIPLookup performs a geo-IP lookup with Redis caching
func (s *Service) GeoIPLookup(ctx context.Context, ip string) (*GeoResult, error) {
	// Skip private/local IPs
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return &GeoResult{Country: "Local", CountryCode: "LO", City: "Local", Query: ip}, nil
	}

	// Check Redis cache
	cacheKey := "geoip:" + ip
	cached, err := s.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil {
		var result GeoResult
		if json.Unmarshal([]byte(cached), &result) == nil {
			return &result, nil
		}
	}

	// Call ip-api.com (free tier)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country,countryCode,city,lat,lon,isp,query", ip))
	if err != nil {
		return nil, fmt.Errorf("geo-IP lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("geo-IP read failed: %w", err)
	}

	var result GeoResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("geo-IP parse failed: %w", err)
	}

	// Cache for 24 hours
	data, _ := json.Marshal(result)
	s.redis.Client.Set(ctx, cacheKey, string(data), 24*time.Hour)

	return &result, nil
}

// GetRiskStats returns risk statistics for the dashboard
func (s *Service) GetRiskStats(ctx context.Context) (map[string]interface{}, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	stats := make(map[string]interface{})

	// High-risk logins today
	var highRiskToday int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history WHERE risk_score >= 50 AND created_at > CURRENT_DATE AND org_id = $1`, org.ID).Scan(&highRiskToday)
	stats["high_risk_logins_today"] = highRiskToday

	// New devices today
	var newDevicesToday int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices WHERE created_at > CURRENT_DATE AND org_id = $1`, org.ID).Scan(&newDevicesToday)
	stats["new_devices_today"] = newDevicesToday

	// Total known devices
	var totalDevices int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM known_devices WHERE org_id = $1`, org.ID).Scan(&totalDevices)
	stats["total_devices"] = totalDevices

	// Trusted devices
	var trustedDevices int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM known_devices WHERE trusted = true AND org_id = $1`, org.ID).Scan(&trustedDevices)
	stats["trusted_devices"] = trustedDevices

	// Failed logins today
	var failedToday int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history WHERE success = false AND created_at > CURRENT_DATE AND org_id = $1`, org.ID).Scan(&failedToday)
	stats["failed_logins_today"] = failedToday

	// Average risk score today
	var avgRisk *float64
	s.db.Pool.QueryRow(ctx,
		`SELECT AVG(risk_score) FROM login_history WHERE created_at > CURRENT_DATE AND success = true AND org_id = $1`, org.ID).Scan(&avgRisk)
	if avgRisk != nil {
		stats["avg_risk_score_today"] = int(*avgRisk)
	} else {
		stats["avg_risk_score_today"] = 0
	}

	return stats, nil
}

// CreateStepUpChallenge creates a step-up MFA challenge for a session
func (s *Service) CreateStepUpChallenge(ctx context.Context, userID, sessionID, reason string) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	var challengeID string
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO stepup_challenges (user_id, session_id, reason, expires_at, org_id)
		 VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes', $4)
		 RETURNING id`,
		userID, sessionID, reason, org.ID).Scan(&challengeID)
	if err != nil {
		return "", fmt.Errorf("failed to create step-up challenge: %w", err)
	}

	// Store in Redis for fast lookup
	s.redis.Client.Set(ctx, "stepup:"+challengeID, userID, 5*time.Minute)

	return challengeID, nil
}

// CompleteStepUpChallenge marks a step-up challenge as completed
func (s *Service) CompleteStepUpChallenge(ctx context.Context, challengeID, userID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Verify challenge belongs to user and is pending
	var status string
	var storedUserID string
	var expiresAt time.Time
	err = s.db.Pool.QueryRow(ctx,
		`SELECT user_id, status, expires_at FROM stepup_challenges WHERE id = $1 AND org_id = $2`,
		challengeID, org.ID).Scan(&storedUserID, &status, &expiresAt)
	if err != nil {
		return fmt.Errorf("challenge not found")
	}
	if storedUserID != userID {
		return fmt.Errorf("challenge does not belong to user")
	}
	if status != "pending" {
		return fmt.Errorf("challenge already %s", status)
	}
	if time.Now().After(expiresAt) {
		s.db.Pool.Exec(ctx, `UPDATE stepup_challenges SET status = 'expired' WHERE id = $1 AND org_id = $2`, challengeID, org.ID)
		return fmt.Errorf("challenge expired")
	}

	_, err = s.db.Pool.Exec(ctx,
		`UPDATE stepup_challenges SET status = 'completed', completed_at = NOW() WHERE id = $1 AND org_id = $2`, challengeID, org.ID)
	if err != nil {
		return err
	}

	s.redis.Client.Del(ctx, "stepup:"+challengeID)
	return nil
}

// haversineDistance is defined in behavior.go to avoid duplication

// extractCountry extracts the country portion from a "City, Country" string
func extractCountry(location string) string {
	parts := strings.Split(location, ", ")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return location
}

// parseDeviceName generates a human-readable device name from User-Agent
func parseDeviceName(userAgent string) string {
	ua := strings.ToLower(userAgent)
	var os, browser string

	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
	default:
		os = "Unknown OS"
	}

	switch {
	case strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	case strings.Contains(ua, "edg"):
		browser = "Edge"
	default:
		browser = "Browser"
	}

	return browser + " on " + os
}

// GetRecentFailedAttempts returns the count of recent failed login attempts for a user
func (s *Service) GetRecentFailedAttempts(ctx context.Context, userID string) int {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0
	}
	var count int
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND success = false AND created_at > NOW() - INTERVAL '1 hour' AND org_id = $2`,
		userID, org.ID).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// ListRiskPolicies returns all risk policies, optionally filtered by enabled status
func (s *Service) ListRiskPolicies(ctx context.Context, enabledOnly bool) ([]RiskPolicy, error) {
	query := `SELECT id, name, COALESCE(description,''), enabled, COALESCE(priority,100),
	                 COALESCE(conditions,'{}'), COALESCE(actions,'{}'), created_at, updated_at
	          FROM risk_policies`
	args := []interface{}{}
	if enabledOnly {
		query += ` WHERE enabled = $1`
		args = append(args, true)
	}
	query += ` ORDER BY priority ASC, created_at DESC`

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list risk policies: %w", err)
	}
	defer rows.Close()

	var policies []RiskPolicy
	for rows.Next() {
		p, err := scanRiskPolicy(rows)
		if err != nil {
			s.logger.Warn("Failed to scan risk policy row", zap.Error(err))
			continue
		}
		policies = append(policies, *p)
	}
	if policies == nil {
		policies = []RiskPolicy{}
	}
	return policies, nil
}

// GetRiskPolicy returns a specific risk policy by ID
func (s *Service) GetRiskPolicy(ctx context.Context, policyID string) (*RiskPolicy, error) {
	row := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, COALESCE(description,''), enabled, COALESCE(priority,100),
		        COALESCE(conditions,'{}'), COALESCE(actions,'{}'), created_at, updated_at
		 FROM risk_policies WHERE id = $1`, policyID)

	var p RiskPolicy
	var priority int
	var conditionsJSON, actionsJSON []byte
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &priority,
		&conditionsJSON, &actionsJSON, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("policy not found")
	}

	p.Priority = priority
	p.Conditions = conditionsJSON
	p.Actions = actionsJSON
	parseThresholdsFromJSON(conditionsJSON, actionsJSON, &p)
	return &p, nil
}

// CreateRiskPolicy creates a new risk policy
func (s *Service) CreateRiskPolicy(ctx context.Context, req CreateRiskPolicyRequest) (*RiskPolicy, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	conditions := buildConditionsJSON(req)
	actions := buildActionsJSON(req)
	priorityIn := 100
	if req.Priority != nil {
		priorityIn = *req.Priority
	}

	var p RiskPolicy
	var priority int
	var conditionsOut, actionsOut []byte
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO risk_policies (name, description, enabled, priority, conditions, actions)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, COALESCE(description,''), enabled, COALESCE(priority,100),
		           COALESCE(conditions,'{}'), COALESCE(actions,'{}'), created_at, updated_at`,
		req.Name, req.Description, enabled, priorityIn, conditions, actions,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &priority,
		&conditionsOut, &actionsOut, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create risk policy: %w", err)
	}

	p.Priority = priority
	p.Conditions = conditionsOut
	p.Actions = actionsOut
	parseThresholdsFromJSON(conditionsOut, actionsOut, &p)
	if req.TenantID != "" {
		p.TenantID = req.TenantID
	}

	s.logger.Info("Risk policy created",
		zap.String("id", p.ID),
		zap.String("name", p.Name),
	)
	return &p, nil
}

// UpdateRiskPolicy updates an existing risk policy
func (s *Service) UpdateRiskPolicy(ctx context.Context, policyID string, req CreateRiskPolicyRequest) (*RiskPolicy, error) {
	// First verify the policy exists
	existing, err := s.GetRiskPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}

	// Merge: use existing values where request fields are nil
	if req.LowThreshold == nil {
		req.LowThreshold = &existing.LowThreshold
	}
	if req.MediumThreshold == nil {
		req.MediumThreshold = &existing.MediumThreshold
	}
	if req.HighThreshold == nil {
		req.HighThreshold = &existing.HighThreshold
	}
	if req.CriticalThreshold == nil {
		req.CriticalThreshold = &existing.CriticalThreshold
	}
	if req.Enabled == nil {
		req.Enabled = &existing.Enabled
	}
	if req.Name == "" {
		req.Name = existing.Name
	}
	if req.Description == "" {
		req.Description = existing.Description
	}
	// Preserve existing conditions/actions/priority when the request omits them,
	// so a partial edit (e.g. just toggling enabled) does not wipe the policy's
	// stored condition/action model.
	if isJSONNull(req.Conditions) && len(existing.Conditions) > 0 {
		req.Conditions = existing.Conditions
	}
	if isJSONNull(req.Actions) && len(existing.Actions) > 0 {
		req.Actions = existing.Actions
	}
	if req.Priority == nil {
		req.Priority = &existing.Priority
	}
	priorityIn := 100
	if req.Priority != nil {
		priorityIn = *req.Priority
	}

	conditions := buildConditionsJSON(req)
	actions := buildActionsJSON(req)

	var p RiskPolicy
	var priority int
	var conditionsOut, actionsOut []byte
	err = s.db.Pool.QueryRow(ctx,
		`UPDATE risk_policies
		 SET name = $2, description = $3, enabled = $4, priority = $5, conditions = $6, actions = $7, updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, name, COALESCE(description,''), enabled, COALESCE(priority,100),
		           COALESCE(conditions,'{}'), COALESCE(actions,'{}'), created_at, updated_at`,
		policyID, req.Name, req.Description, *req.Enabled, priorityIn, conditions, actions,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &priority,
		&conditionsOut, &actionsOut, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to update risk policy: %w", err)
	}

	p.Priority = priority
	p.Conditions = conditionsOut
	p.Actions = actionsOut
	parseThresholdsFromJSON(conditionsOut, actionsOut, &p)
	if req.TenantID != "" {
		p.TenantID = req.TenantID
	}

	s.logger.Info("Risk policy updated",
		zap.String("id", p.ID),
		zap.String("name", p.Name),
	)
	return &p, nil
}

// DeleteRiskPolicy deletes a risk policy by ID
func (s *Service) DeleteRiskPolicy(ctx context.Context, policyID string) error {
	result, err := s.db.Pool.Exec(ctx,
		`DELETE FROM risk_policies WHERE id = $1`, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete risk policy: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("policy not found")
	}

	s.logger.Info("Risk policy deleted", zap.String("id", policyID))
	return nil
}

// ToggleRiskPolicy enables or disables a risk policy
func (s *Service) ToggleRiskPolicy(ctx context.Context, policyID string, enabled bool) error {
	result, err := s.db.Pool.Exec(ctx,
		`UPDATE risk_policies SET enabled = $2, updated_at = NOW() WHERE id = $1`,
		policyID, enabled)
	if err != nil {
		return fmt.Errorf("failed to toggle risk policy: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("policy not found")
	}

	s.logger.Info("Risk policy toggled",
		zap.String("id", policyID),
		zap.Bool("enabled", enabled),
	)
	return nil
}

// scanRiskPolicy scans a risk policy row from a pgx.Rows iterator
func scanRiskPolicy(rows interface {
	Scan(dest ...interface{}) error
}) (*RiskPolicy, error) {
	var p RiskPolicy
	var priority int
	var conditionsJSON, actionsJSON []byte
	err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &priority,
		&conditionsJSON, &actionsJSON, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	p.Priority = priority
	p.Conditions = conditionsJSON
	p.Actions = actionsJSON
	parseThresholdsFromJSON(conditionsJSON, actionsJSON, &p)
	return &p, nil
}

// parseThresholdsFromJSON extracts threshold and tenant values from the JSONB columns
func parseThresholdsFromJSON(conditionsJSON, actionsJSON []byte, p *RiskPolicy) {
	var conditions map[string]interface{}
	if json.Unmarshal(conditionsJSON, &conditions) == nil {
		if v, ok := conditions["low_threshold"]; ok {
			if f, ok := v.(float64); ok {
				p.LowThreshold = int(f)
			}
		}
		if v, ok := conditions["medium_threshold"]; ok {
			if f, ok := v.(float64); ok {
				p.MediumThreshold = int(f)
			}
		}
		if v, ok := conditions["high_threshold"]; ok {
			if f, ok := v.(float64); ok {
				p.HighThreshold = int(f)
			}
		}
		if v, ok := conditions["critical_threshold"]; ok {
			if f, ok := v.(float64); ok {
				p.CriticalThreshold = int(f)
			}
		}
	}

	var actions map[string]interface{}
	if json.Unmarshal(actionsJSON, &actions) == nil {
		if v, ok := actions["tenant_id"]; ok {
			if s, ok := v.(string); ok {
				p.TenantID = s
			}
		}
	}
}

// buildConditionsJSON creates the conditions JSONB value. When the request
// carries a conditions object (the admin console model) it is persisted
// verbatim; otherwise it is synthesized from the legacy threshold fields.
func buildConditionsJSON(req CreateRiskPolicyRequest) []byte {
	if len(req.Conditions) > 0 && !isJSONNull(req.Conditions) {
		return req.Conditions
	}
	conditions := map[string]interface{}{}
	if req.LowThreshold != nil {
		conditions["low_threshold"] = *req.LowThreshold
	}
	if req.MediumThreshold != nil {
		conditions["medium_threshold"] = *req.MediumThreshold
	}
	if req.HighThreshold != nil {
		conditions["high_threshold"] = *req.HighThreshold
	}
	if req.CriticalThreshold != nil {
		conditions["critical_threshold"] = *req.CriticalThreshold
	}
	data, _ := json.Marshal(conditions)
	return data
}

// buildActionsJSON creates the actions JSONB value. Prefers the request's
// actions object (admin console model); falls back to storing the tenant id.
func buildActionsJSON(req CreateRiskPolicyRequest) []byte {
	if len(req.Actions) > 0 && !isJSONNull(req.Actions) {
		return req.Actions
	}
	actions := map[string]interface{}{}
	if req.TenantID != "" {
		actions["tenant_id"] = req.TenantID
	}
	data, _ := json.Marshal(actions)
	return data
}

// isJSONNull reports whether a raw JSON value is empty or the literal null.
func isJSONNull(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// EvaluateRiskPolicies evaluates risk for a given login context (placeholder for compatibility)
func (s *Service) EvaluateRiskPolicies(ctx context.Context, loginCtx EvaluateLoginContext) (*PolicyEvaluationResult, error) {
	// Calculate risk score using existing method
	score, factors := s.CalculateRiskScore(ctx, loginCtx.UserID, loginCtx.IPAddress,
		loginCtx.UserAgent, loginCtx.DeviceFingerprint, loginCtx.Location,
		loginCtx.Latitude, loginCtx.Longitude)

	// Determine risk level
	var level RiskLevel
	switch {
	case score < 30:
		level = RiskLevelLow
	case score < 50:
		level = RiskLevelMedium
	case score < 70:
		level = RiskLevelHigh
	default:
		level = RiskLevelCritical
	}

	// Determine action
	var action AuthAction
	var allowed bool
	var requireMFA bool
	var duration *int

	switch {
	case score < 30:
		action = AuthActionAllow
		allowed = true
		d := 480
		duration = &d
	case score < 50:
		action = AuthActionRequireMFA
		allowed = true
		requireMFA = true
		d := 240
		duration = &d
	case score < 70:
		action = AuthActionRequireStrongMFA
		allowed = true
		requireMFA = true
		d := 60
		duration = &d
	default:
		action = AuthActionBlock
		allowed = false
	}

	return &PolicyEvaluationResult{
		RiskScore:       score,
		RiskLevel:       level,
		Action:          action,
		Reasons:         factors,
		RequireMFA:      requireMFA,
		Allowed:         allowed,
		SessionDuration: duration,
	}, nil
}
