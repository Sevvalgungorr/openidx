// Package identity - Push Notification MFA implementation
package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// PushMFADevice represents a registered push notification device
type PushMFADevice struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	DeviceToken string     `json:"-"`        // Never expose token in JSON
	Platform    string     `json:"platform"` // ios, android, web
	DeviceName  string     `json:"device_name"`
	DeviceModel string     `json:"device_model,omitempty"`
	OSVersion   string     `json:"os_version,omitempty"`
	AppVersion  string     `json:"app_version,omitempty"`
	Enabled     bool       `json:"enabled"`
	Trusted     bool       `json:"trusted"`
	LastIP      string     `json:"last_ip,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// PushMFAChallenge represents a push notification challenge
type PushMFAChallenge struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"user_id"`
	DeviceID      string                 `json:"device_id"`
	ChallengeCode string                 `json:"challenge_code"` // Number matching code
	Status        string                 `json:"status"`         // pending, approved, denied, expired
	SessionInfo   map[string]interface{} `json:"session_info,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	RespondedAt   *time.Time             `json:"responded_at,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	Location      string                 `json:"location,omitempty"`
}

// PushMFAEnrollment represents enrollment request
type PushMFAEnrollment struct {
	DeviceToken string `json:"device_token"`
	Platform    string `json:"platform"`
	DeviceName  string `json:"device_name"`
	DeviceModel string `json:"device_model,omitempty"`
	OSVersion   string `json:"os_version,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
}

// PushMFAChallengeRequest represents challenge creation request
type PushMFAChallengeRequest struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Location  string `json:"location,omitempty"`
	// AppName is the application requesting approval (e.g. "Admin Console",
	// "SecureTask"). Shown on the approve screen so the user knows what they're
	// approving — the anti-MFA-fatigue "additional context" pattern.
	AppName string `json:"app_name,omitempty"`
}

// PushMFAChallengeResponse represents challenge response from user
type PushMFAChallengeResponse struct {
	ChallengeID   string `json:"challenge_id"`
	ChallengeCode string `json:"challenge_code"` // User must enter the number they see
	Approved      bool   `json:"approved"`
	// Reported marks a deny as "this wasn't me" — a suspicious-activity signal.
	// Only meaningful when Approved is false.
	Reported bool `json:"reported,omitempty"`
}

// RegisterPushMFADevice registers a new push notification device
func (s *Service) RegisterPushMFADevice(ctx context.Context, userID string, enrollment *PushMFAEnrollment, ipAddress string) (*PushMFADevice, error) {
	// Validate platform
	if enrollment.Platform != "ios" && enrollment.Platform != "android" && enrollment.Platform != "web" {
		return nil, fmt.Errorf("invalid platform: must be ios, android, or web")
	}

	// Check if device already exists
	existingDevice, err := s.getPushDeviceByToken(ctx, enrollment.DeviceToken)
	if err == nil && existingDevice != nil {
		// Update existing device
		existingDevice.DeviceName = enrollment.DeviceName
		existingDevice.DeviceModel = enrollment.DeviceModel
		existingDevice.OSVersion = enrollment.OSVersion
		existingDevice.AppVersion = enrollment.AppVersion
		existingDevice.Enabled = true
		existingDevice.LastIP = ipAddress

		if err := s.updatePushDevice(ctx, existingDevice); err != nil {
			return nil, fmt.Errorf("failed to update device: %w", err)
		}

		s.logger.Info("Push MFA device updated",
			zap.String("user_id", userID),
			zap.String("device_id", existingDevice.ID),
			zap.String("platform", enrollment.Platform))

		return existingDevice, nil
	}

	// Create new device
	device := &PushMFADevice{
		ID:          uuid.New().String(),
		UserID:      userID,
		DeviceToken: enrollment.DeviceToken,
		Platform:    enrollment.Platform,
		DeviceName:  enrollment.DeviceName,
		DeviceModel: enrollment.DeviceModel,
		OSVersion:   enrollment.OSVersion,
		AppVersion:  enrollment.AppVersion,
		Enabled:     true,
		Trusted:     false, // Require trust establishment
		LastIP:      ipAddress,
		CreatedAt:   time.Now(),
	}

	if err := s.storePushDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("failed to store device: %w", err)
	}

	s.logger.Info("Push MFA device registered",
		zap.String("user_id", userID),
		zap.String("device_id", device.ID),
		zap.String("platform", enrollment.Platform))

	return device, nil
}

// CreatePushMFAChallenge creates a new push notification challenge
func (s *Service) CreatePushMFAChallenge(ctx context.Context, request *PushMFAChallengeRequest) (*PushMFAChallenge, error) {
	// Get user's active devices
	devices, err := s.GetPushMFADevices(ctx, request.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	if len(devices) == 0 {
		return nil, fmt.Errorf("no push MFA devices registered")
	}

	// Find first enabled device (in production, allow user to choose or send to all)
	var targetDevice *PushMFADevice
	for _, d := range devices {
		if d.Enabled {
			targetDevice = &d
			break
		}
	}

	if targetDevice == nil {
		return nil, fmt.Errorf("no enabled push MFA devices found")
	}

	// Generate random number matching code (2 digits)
	codeNum, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge code: %w", err)
	}
	challengeCode := fmt.Sprintf("%02d", codeNum.Int64()+10) // Ensures 2 digits (10-99)

	// Rich approval context (anti-MFA-fatigue). Resolve a human-readable
	// location from the request IP if the risk service is wired and no explicit
	// location was supplied, and stash the requesting app name in session_info.
	location := request.Location
	if location == "" && s.risk != nil && request.IPAddress != "" {
		if geo, gerr := s.risk.GeoIPLookup(ctx, request.IPAddress); gerr == nil && geo != nil {
			switch {
			case geo.City != "" && geo.Country != "":
				location = geo.City + ", " + geo.Country
			case geo.Country != "":
				location = geo.Country
			}
		}
	}
	sessionInfo := map[string]interface{}{}
	if request.AppName != "" {
		sessionInfo["app_name"] = request.AppName
	}

	// Create challenge
	challenge := &PushMFAChallenge{
		ID:            uuid.New().String(),
		UserID:        request.UserID,
		DeviceID:      targetDevice.ID,
		ChallengeCode: challengeCode,
		Status:        "pending",
		SessionInfo:   sessionInfo,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Duration(s.cfg.PushMFA.ChallengeTimeout) * time.Second),
		IPAddress:     request.IPAddress,
		UserAgent:     request.UserAgent,
		Location:      location,
	}

	// Store challenge
	if err := s.storePushChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	// Send push notification via the registered provider (FCM/APNs).
	if err := s.sendPushNotification(ctx, targetDevice, challenge); err != nil {
		s.logger.Error("Failed to send push notification",
			zap.String("challenge_id", challenge.ID),
			zap.Error(err))
		// Don't fail the challenge creation, just log the error
	}

	// Also deliver over the self-hosted ntfy topic the app already subscribes
	// to. This is the always-on, no-FCM/APNs-credentials delivery path: the
	// phone gets a real-time, tappable prompt that deep-links into the approve
	// screen. Best-effort.
	if s.publishChallengeToNtfy(ctx, challenge) {
		s.logger.Info("Push MFA challenge delivered via ntfy",
			zap.String("challenge_id", challenge.ID))
	}

	s.logger.Info("Push MFA challenge created",
		zap.String("user_id", request.UserID),
		zap.String("challenge_id", challenge.ID),
		zap.String("device_id", targetDevice.ID))

	return challenge, nil
}

// VerifyPushMFAChallenge verifies a push MFA challenge response
func (s *Service) VerifyPushMFAChallenge(ctx context.Context, response *PushMFAChallengeResponse) (bool, error) {
	// Get challenge
	challenge, err := s.getPushChallenge(ctx, response.ChallengeID)
	if err != nil {
		return false, fmt.Errorf("challenge not found: %w", err)
	}

	// Check if already responded
	if challenge.Status != "pending" {
		return false, fmt.Errorf("challenge already responded: %s", challenge.Status)
	}

	// Check expiry
	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = "expired"
		s.updatePushChallenge(ctx, challenge)
		return false, fmt.Errorf("challenge expired")
	}

	// Verify challenge code (number matching) — required only to APPROVE. A user
	// denying a prompt they don't recognize must not be forced to type a number
	// they were never shown (the GET response redacts it); requiring it would
	// make "deny suspicious" impossible and push users toward blind approval.
	if response.Approved && response.ChallengeCode != challenge.ChallengeCode {
		s.logger.Warn("Push MFA challenge code mismatch",
			zap.String("challenge_id", challenge.ID),
			zap.String("expected", challenge.ChallengeCode),
			zap.String("received", response.ChallengeCode))
		return false, fmt.Errorf("invalid challenge code")
	}

	// Update challenge status
	now := time.Now()
	challenge.RespondedAt = &now
	if response.Approved {
		challenge.Status = "approved"
	} else if response.Reported {
		challenge.Status = "reported"
	} else {
		challenge.Status = "denied"
	}

	if err := s.updatePushChallenge(ctx, challenge); err != nil {
		s.logger.Error("Failed to update challenge", zap.Error(err))
	}

	// A "reported" deny is a security signal: the user says this sign-in wasn't
	// them. Record it loudly so downstream alerting/risk can react.
	if response.Reported {
		s.logger.Warn("Push MFA challenge reported as suspicious by user",
			zap.String("challenge_id", challenge.ID),
			zap.String("user_id", challenge.UserID),
			zap.String("ip_address", scrubLogValue(challenge.IPAddress)),
			zap.String("location", challenge.Location))
	}

	// Update device last used time
	s.updatePushDeviceLastUsed(ctx, challenge.DeviceID)

	s.logger.Info("Push MFA challenge verified",
		zap.String("challenge_id", challenge.ID),
		zap.String("status", challenge.Status),
		zap.Bool("approved", response.Approved))

	return response.Approved, nil
}

// GetPushMFAChallenge retrieves a challenge by ID
func (s *Service) GetPushMFAChallenge(ctx context.Context, challengeID string) (*PushMFAChallenge, error) {
	return s.getPushChallenge(ctx, challengeID)
}

// GetPushMFADevices returns all push MFA devices for a user
func (s *Service) GetPushMFADevices(ctx context.Context, userID string) ([]PushMFADevice, error) {
	query := `
		SELECT id, user_id, device_token, platform, device_name, device_model,
		       os_version, app_version, enabled, trusted, last_ip,
		       created_at, last_used_at, expires_at
		FROM mfa_push_devices
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []PushMFADevice
	for rows.Next() {
		var device PushMFADevice
		err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.DeviceToken,
			&device.Platform,
			&device.DeviceName,
			&device.DeviceModel,
			&device.OSVersion,
			&device.AppVersion,
			&device.Enabled,
			&device.Trusted,
			&device.LastIP,
			&device.CreatedAt,
			&device.LastUsedAt,
			&device.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// DeletePushMFADevice removes a push MFA device
func (s *Service) DeletePushMFADevice(ctx context.Context, userID, deviceID string) error {
	query := `DELETE FROM mfa_push_devices WHERE user_id = $1 AND id = $2`
	result, err := s.db.Pool.Exec(ctx, query, userID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("device not found")
	}

	s.logger.Info("Push MFA device deleted",
		zap.String("user_id", userID),
		zap.String("device_id", deviceID))

	return nil
}

// Helper functions

func (s *Service) getPushDeviceByToken(ctx context.Context, token string) (*PushMFADevice, error) {
	query := `
		SELECT id, user_id, device_token, platform, device_name, device_model,
		       os_version, app_version, enabled, trusted, last_ip,
		       created_at, last_used_at, expires_at
		FROM mfa_push_devices
		WHERE device_token = $1
	`

	var device PushMFADevice
	err := s.db.Pool.QueryRow(ctx, query, token).Scan(
		&device.ID,
		&device.UserID,
		&device.DeviceToken,
		&device.Platform,
		&device.DeviceName,
		&device.DeviceModel,
		&device.OSVersion,
		&device.AppVersion,
		&device.Enabled,
		&device.Trusted,
		&device.LastIP,
		&device.CreatedAt,
		&device.LastUsedAt,
		&device.ExpiresAt,
	)

	if err != nil {
		return nil, err
	}

	return &device, nil
}

func (s *Service) storePushDevice(ctx context.Context, device *PushMFADevice) error {
	// mfa_push_devices.org_id is NOT NULL (and the table is FORCE-RLS by org).
	// It carried a default of the seed org, so omitting org_id silently filed
	// every non-seed-org device under the wrong tenant. Set it explicitly from
	// context.
	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required to store push device: %w", err)
	}

	query := `
		INSERT INTO mfa_push_devices
		(id, user_id, device_token, platform, device_name, device_model,
		 os_version, app_version, enabled, trusted, last_ip, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err = s.db.Pool.Exec(ctx, query,
		device.ID,
		device.UserID,
		device.DeviceToken,
		device.Platform,
		device.DeviceName,
		device.DeviceModel,
		device.OSVersion,
		device.AppVersion,
		device.Enabled,
		device.Trusted,
		device.LastIP,
		device.CreatedAt,
		org.ID,
	)

	return err
}

func (s *Service) updatePushDevice(ctx context.Context, device *PushMFADevice) error {
	query := `
		UPDATE mfa_push_devices
		SET device_name = $1, device_model = $2, os_version = $3,
		    app_version = $4, enabled = $5, last_ip = $6
		WHERE id = $7
	`

	_, err := s.db.Pool.Exec(ctx, query,
		device.DeviceName,
		device.DeviceModel,
		device.OSVersion,
		device.AppVersion,
		device.Enabled,
		device.LastIP,
		device.ID,
	)

	return err
}

func (s *Service) updatePushDeviceLastUsed(ctx context.Context, deviceID string) error {
	query := `UPDATE mfa_push_devices SET last_used_at = $1 WHERE id = $2`
	_, err := s.db.Pool.Exec(ctx, query, time.Now(), deviceID)
	return err
}

func (s *Service) storePushChallenge(ctx context.Context, challenge *PushMFAChallenge) error {
	sessionInfoJSON, _ := json.Marshal(challenge.SessionInfo)

	query := `
		INSERT INTO mfa_push_challenges
		(id, user_id, device_id, challenge_code, status, session_info,
		 created_at, expires_at, ip_address, user_agent, location)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := s.db.Pool.Exec(ctx, query,
		challenge.ID,
		challenge.UserID,
		challenge.DeviceID,
		challenge.ChallengeCode,
		challenge.Status,
		sessionInfoJSON,
		challenge.CreatedAt,
		challenge.ExpiresAt,
		challenge.IPAddress,
		challenge.UserAgent,
		challenge.Location,
	)

	return err
}

func (s *Service) getPushChallenge(ctx context.Context, challengeID string) (*PushMFAChallenge, error) {
	query := `
		SELECT id, user_id, device_id, challenge_code, status, session_info,
		       created_at, expires_at, responded_at, ip_address, user_agent, location
		FROM mfa_push_challenges
		WHERE id = $1
	`

	var challenge PushMFAChallenge
	var sessionInfoJSON []byte

	err := s.db.Pool.QueryRow(ctx, query, challengeID).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.DeviceID,
		&challenge.ChallengeCode,
		&challenge.Status,
		&sessionInfoJSON,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.RespondedAt,
		&challenge.IPAddress,
		&challenge.UserAgent,
		&challenge.Location,
	)

	if err != nil {
		return nil, err
	}

	if len(sessionInfoJSON) > 0 {
		json.Unmarshal(sessionInfoJSON, &challenge.SessionInfo)
	}

	return &challenge, nil
}

func (s *Service) updatePushChallenge(ctx context.Context, challenge *PushMFAChallenge) error {
	query := `
		UPDATE mfa_push_challenges
		SET status = $1, responded_at = $2
		WHERE id = $3
	`

	_, err := s.db.Pool.Exec(ctx, query,
		challenge.Status,
		challenge.RespondedAt,
		challenge.ID,
	)

	return err
}

func (s *Service) sendPushNotification(ctx context.Context, device *PushMFADevice, challenge *PushMFAChallenge) error {
	// Auto-approve in development mode (for testing without actual push service)
	if s.cfg.PushMFA.AutoApprove {
		s.logger.Info("Auto-approving push challenge (development mode)",
			zap.String("challenge_id", challenge.ID))
		return nil
	}

	// Build notification payload
	payload := map[string]interface{}{
		"challenge_id":   challenge.ID,
		"challenge_code": challenge.ChallengeCode,
		"ip_address":     challenge.IPAddress,
		"location":       challenge.Location,
		"user_agent":     challenge.UserAgent,
		"expires_at":     challenge.ExpiresAt.Unix(),
	}

	// Send based on platform
	var sendErr error
	switch device.Platform {
	case "android", "web":
		sendErr = s.sendFCMNotification(ctx, device.DeviceToken, payload)
	case "ios":
		sendErr = s.sendAPNSNotification(ctx, device.DeviceToken, payload)
	default:
		return fmt.Errorf("unsupported platform: %s", device.Platform)
	}

	// If the provider reported the token is dead (app uninstalled / token
	// rotated), prune the stale registration so we stop retrying it every login
	// and the table doesn't accumulate garbage tokens.
	if errors.Is(sendErr, errDeadPushToken) {
		if delErr := s.DeletePushMFADevice(ctx, device.UserID, device.ID); delErr != nil {
			s.logger.Warn("failed to prune dead push device",
				zap.String("device_id", device.ID), zap.Error(delErr))
		} else {
			s.logger.Info("pruned dead push device (token no longer registered)",
				zap.String("device_id", device.ID), zap.String("platform", device.Platform))
		}
	}
	return sendErr
}

// Process-wide caches for the push provider credentials/tokens. Config is fixed
// per process, so a single cached token source (FCM) and provider token (APNS)
// serve every challenge.
var (
	defaultFCMProvider  = &fcmProvider{}
	defaultAPNSProvider = &apnsProvider{}
)

func (s *Service) sendFCMNotification(ctx context.Context, token string, payload map[string]interface{}) error {
	accessToken, projectID, err := defaultFCMProvider.getToken(ctx, s.cfg.PushMFA.FCMCredentialsFile, s.cfg.PushMFA.FCMProjectID)
	if err != nil {
		s.logger.Warn("FCM HTTP v1 not configured, skipping push notification", zap.Error(err))
		return fmt.Errorf("FCM not configured: %w", err)
	}

	s.logger.Info("Sending FCM notification",
		zap.String("token_prefix", token[:min(10, len(token))]))

	// FCM HTTP v1 requires all data values to be strings.
	var msg fcmMessage
	msg.Message.Token = token
	msg.Message.Notification = map[string]string{
		"title": "Authentication Request",
		"body":  "Approve or deny the login request",
	}
	msg.Message.Data = stringifyPayload(payload)

	jsonBody, err := json.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("failed to marshal FCM payload: %w", err)
	}

	endpoint := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create FCM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("FCM request failed", zap.Error(err))
		return fmt.Errorf("FCM request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("FCM returned non-200 status",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(respBody)))
		// A 404, or an UNREGISTERED/INVALID_ARGUMENT FcmError, means the device
		// token is dead (app uninstalled / token rotated) — signal the caller to
		// prune the registration rather than retry it forever.
		if resp.StatusCode == http.StatusNotFound ||
			bytes.Contains(respBody, []byte("UNREGISTERED")) ||
			bytes.Contains(respBody, []byte("INVALID_ARGUMENT")) {
			return fmt.Errorf("FCM token unregistered (status %d): %w", resp.StatusCode, errDeadPushToken)
		}
		return fmt.Errorf("FCM returned status %d", resp.StatusCode)
	}

	s.logger.Info("FCM notification sent successfully",
		zap.String("token_prefix", token[:min(10, len(token))]))
	return nil
}

func (s *Service) sendAPNSNotification(ctx context.Context, token string, payload map[string]interface{}) error {
	bundleID := s.cfg.PushMFA.APNSBundleID
	if bundleID == "" {
		s.logger.Warn("APNS bundle ID not configured, skipping push notification")
		return fmt.Errorf("APNS bundle ID not configured")
	}

	providerToken, err := defaultAPNSProvider.getToken(s.cfg.PushMFA.APNSKeyPath, s.cfg.PushMFA.APNSKeyID, s.cfg.PushMFA.APNSTeamID)
	if err != nil {
		s.logger.Warn("APNS token auth not configured, skipping push notification", zap.Error(err))
		return fmt.Errorf("APNS not configured: %w", err)
	}

	s.logger.Info("Sending APNS notification",
		zap.String("token_prefix", token[:min(10, len(token))]))

	apnsPayload := map[string]interface{}{
		"aps": map[string]interface{}{
			"alert": map[string]string{
				"title": "Authentication Request",
				"body":  "Approve or deny the login request",
			},
			"sound":             "default",
			"content-available": 1,
			"category":          "AUTH_CHALLENGE",
		},
		"data": payload,
	}

	jsonBody, err := json.Marshal(apnsPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal APNS payload: %w", err)
	}

	// Sandbox by default; production host only when explicitly enabled.
	host := "https://api.sandbox.push.apple.com"
	if s.cfg.PushMFA.APNSProduction {
		host = "https://api.push.apple.com"
	}
	url := fmt.Sprintf("%s/3/device/%s", host, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create APNS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+providerToken)
	req.Header.Set("apns-topic", bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("APNS request failed", zap.Error(err))
		return fmt.Errorf("APNS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("APNS returned non-200 status",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(respBody)))
		// 410 Gone, or a BadDeviceToken/Unregistered reason, means the token is
		// dead — signal the caller to prune the registration.
		if resp.StatusCode == http.StatusGone ||
			bytes.Contains(respBody, []byte("BadDeviceToken")) ||
			bytes.Contains(respBody, []byte("Unregistered")) {
			return fmt.Errorf("APNS token invalid (status %d): %w", resp.StatusCode, errDeadPushToken)
		}
		return fmt.Errorf("APNS returned status %d", resp.StatusCode)
	}

	s.logger.Info("APNS notification sent successfully",
		zap.String("token_prefix", token[:min(10, len(token))]))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
