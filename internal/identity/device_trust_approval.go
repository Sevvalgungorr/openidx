// Package identity - Admin Device Trust Approval Workflow
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/notifications"
)

// DeviceTrustRequest represents a request for device trust approval
type DeviceTrustRequest struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	UserEmail         string     `json:"user_email,omitempty"`
	UserName          string     `json:"user_name,omitempty"`
	DeviceID          string     `json:"device_id"`
	DeviceFingerprint string     `json:"device_fingerprint"`
	DeviceName        string     `json:"device_name"`
	DeviceType        string     `json:"device_type"`
	IPAddress         string     `json:"ip_address"`
	UserAgent         string     `json:"user_agent,omitempty"`
	Justification     string     `json:"justification"`
	Status            string     `json:"status"` // pending, approved, rejected, expired
	ReviewedBy        *string    `json:"reviewed_by,omitempty"`
	ReviewedAt        *time.Time `json:"reviewed_at,omitempty"`
	ReviewNotes       string     `json:"review_notes,omitempty"`
	AutoExpireAt      *time.Time `json:"auto_expire_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// DeviceTrustSettings represents organization settings for device trust
type DeviceTrustSettings struct {
	ID                       string    `json:"id"`
	OrgID                    *string   `json:"org_id,omitempty"`
	RequireApproval          bool      `json:"require_approval"`
	AutoApproveKnownIPs      bool      `json:"auto_approve_known_ips"`
	AutoApproveCorporateDevs bool      `json:"auto_approve_corporate_devices"`
	RequestExpiryHours       int       `json:"request_expiry_hours"`
	NotifyAdmins             bool      `json:"notify_admins"`
	NotifyUserOnDecision     bool      `json:"notify_user_on_decision"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// CreateDeviceTrustRequest creates a new trust request
func (s *Service) CreateDeviceTrustRequest(ctx context.Context, userID, deviceID, deviceFingerprint, deviceName, deviceType, ipAddress, userAgent, justification string) (*DeviceTrustRequest, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Check if there's already a pending request for this device
	var existing string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id FROM device_trust_requests
		WHERE user_id = $1 AND device_fingerprint = $2 AND status = 'pending' AND org_id = $3`,
		userID, deviceFingerprint, org.ID,
	).Scan(&existing)
	if err == nil {
		return nil, errors.New("a trust request for this device is already pending")
	}

	// Get settings
	settings, _ := s.GetDeviceTrustSettings(ctx)

	requestID := uuid.New().String()
	var autoExpireAt *time.Time
	if settings != nil && settings.RequestExpiryHours > 0 {
		exp := time.Now().Add(time.Duration(settings.RequestExpiryHours) * time.Hour)
		autoExpireAt = &exp
	}

	// Check for auto-approval conditions
	status := "pending"
	var reviewedAt *time.Time
	var reviewNotes string

	if settings != nil {
		if settings.AutoApproveKnownIPs && s.isKnownIP(ctx, userID, ipAddress) {
			status = "approved"
			now := time.Now()
			reviewedAt = &now
			reviewNotes = "Auto-approved: Known IP address"
		} else if settings.AutoApproveCorporateDevs && s.isCorporateDevice(ctx, deviceFingerprint) {
			status = "approved"
			now := time.Now()
			reviewedAt = &now
			reviewNotes = "Auto-approved: Corporate device"
		}
	}

	// Create request
	query := `
		INSERT INTO device_trust_requests (
			id, user_id, device_id, device_fingerprint, device_name, device_type,
			ip_address, user_agent, justification, status, reviewed_at, review_notes,
			auto_expire_at, org_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
		RETURNING created_at
	`

	var createdAt time.Time
	err = s.db.Pool.QueryRow(ctx, query,
		requestID, userID, deviceID, deviceFingerprint, deviceName, deviceType,
		ipAddress, userAgent, justification, status, reviewedAt, reviewNotes,
		autoExpireAt, org.ID,
	).Scan(&createdAt)
	if err != nil {
		return nil, err
	}

	// If auto-approved, also trust the device
	if status == "approved" {
		s.trustDevice(ctx, userID, deviceFingerprint)
	}

	// Notify admins if configured
	if settings != nil && settings.NotifyAdmins && status == "pending" {
		s.notifyAdminsOfTrustRequest(ctx, userID, deviceName)
	}

	return &DeviceTrustRequest{
		ID:                requestID,
		UserID:            userID,
		DeviceID:          deviceID,
		DeviceFingerprint: deviceFingerprint,
		DeviceName:        deviceName,
		DeviceType:        deviceType,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		Justification:     justification,
		Status:            status,
		ReviewedAt:        reviewedAt,
		ReviewNotes:       reviewNotes,
		AutoExpireAt:      autoExpireAt,
		CreatedAt:         createdAt,
	}, nil
}

// ListDeviceTrustRequests returns trust requests with optional filtering
func (s *Service) ListDeviceTrustRequests(ctx context.Context, status string, userID string, limit, offset int) ([]DeviceTrustRequest, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 50
	}

	// Count total
	countQuery := `
		SELECT COUNT(*) FROM device_trust_requests
		WHERE org_id = $3 AND ($1 = '' OR status = $1)
		  AND ($2 = '' OR user_id::text = $2)
	`
	var total int
	s.db.Pool.QueryRow(ctx, countQuery, status, userID, org.ID).Scan(&total)

	// Get requests with user info
	query := `
		SELECT
			dtr.id, dtr.user_id, u.email, u.first_name || ' ' || u.last_name,
			dtr.device_id, dtr.device_fingerprint, dtr.device_name, dtr.device_type,
			dtr.ip_address, dtr.user_agent, dtr.justification, dtr.status,
			dtr.reviewed_by, dtr.reviewed_at, dtr.review_notes, dtr.auto_expire_at, dtr.created_at
		FROM device_trust_requests dtr
		JOIN users u ON dtr.user_id = u.id
		WHERE dtr.org_id = $5 AND ($1 = '' OR dtr.status = $1)
		  AND ($2 = '' OR dtr.user_id::text = $2)
		ORDER BY dtr.created_at DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := s.db.Pool.Query(ctx, query, status, userID, limit, offset, org.ID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var requests []DeviceTrustRequest
	for rows.Next() {
		var r DeviceTrustRequest
		err := rows.Scan(
			&r.ID, &r.UserID, &r.UserEmail, &r.UserName,
			&r.DeviceID, &r.DeviceFingerprint, &r.DeviceName, &r.DeviceType,
			&r.IPAddress, &r.UserAgent, &r.Justification, &r.Status,
			&r.ReviewedBy, &r.ReviewedAt, &r.ReviewNotes, &r.AutoExpireAt, &r.CreatedAt,
		)
		if err != nil {
			continue
		}
		requests = append(requests, r)
	}

	return requests, total, nil
}

// ApproveDeviceTrustRequest approves a trust request
func (s *Service) ApproveDeviceTrustRequest(ctx context.Context, requestID, adminID, notes string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Get request details (scoped to the caller's org so an admin can't act on
	// another tenant's request by id).
	var userID, fingerprint, status string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT user_id, device_fingerprint, status FROM device_trust_requests WHERE id = $1 AND org_id = $2",
		requestID, org.ID,
	).Scan(&userID, &fingerprint, &status)
	if err != nil {
		return errors.New("request not found")
	}

	if status != "pending" {
		return errors.New("request is not pending")
	}

	// Update request
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE device_trust_requests
		SET status = 'approved', reviewed_by = $1, reviewed_at = NOW(), review_notes = $2
		WHERE id = $3 AND org_id = $4`,
		adminID, notes, requestID, org.ID,
	)
	if err != nil {
		return err
	}

	// Trust the device
	s.trustDevice(ctx, userID, fingerprint)

	// Notify user
	settings, _ := s.GetDeviceTrustSettings(ctx)
	if settings != nil && settings.NotifyUserOnDecision {
		s.notifyUserOfTrustDecision(ctx, userID, "approved", notes)
	}

	return nil
}

// RejectDeviceTrustRequest rejects a trust request
func (s *Service) RejectDeviceTrustRequest(ctx context.Context, requestID, adminID, notes string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	var userID, status string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT user_id, status FROM device_trust_requests WHERE id = $1 AND org_id = $2",
		requestID, org.ID,
	).Scan(&userID, &status)
	if err != nil {
		return errors.New("request not found")
	}

	if status != "pending" {
		return errors.New("request is not pending")
	}

	_, err = s.db.Pool.Exec(ctx,
		`UPDATE device_trust_requests
		SET status = 'rejected', reviewed_by = $1, reviewed_at = NOW(), review_notes = $2
		WHERE id = $3 AND org_id = $4`,
		adminID, notes, requestID, org.ID,
	)
	if err != nil {
		return err
	}

	// Notify user
	settings, _ := s.GetDeviceTrustSettings(ctx)
	if settings != nil && settings.NotifyUserOnDecision {
		s.notifyUserOfTrustDecision(ctx, userID, "rejected", notes)
	}

	return nil
}

// BulkApproveDeviceTrustRequests approves multiple requests
func (s *Service) BulkApproveDeviceTrustRequests(ctx context.Context, requestIDs []string, adminID, notes string) (int, int, error) {
	approved := 0
	failed := 0

	for _, id := range requestIDs {
		err := s.ApproveDeviceTrustRequest(ctx, id, adminID, notes)
		if err != nil {
			failed++
		} else {
			approved++
		}
	}

	return approved, failed, nil
}

// BulkRejectDeviceTrustRequests rejects multiple requests
func (s *Service) BulkRejectDeviceTrustRequests(ctx context.Context, requestIDs []string, adminID, notes string) (int, int, error) {
	rejected := 0
	failed := 0

	for _, id := range requestIDs {
		err := s.RejectDeviceTrustRequest(ctx, id, adminID, notes)
		if err != nil {
			failed++
		} else {
			rejected++
		}
	}

	return rejected, failed, nil
}

// GetDeviceTrustSettings returns the current settings
func (s *Service) GetDeviceTrustSettings(ctx context.Context) (*DeviceTrustSettings, error) {
	query := `
		SELECT id, org_id, require_approval, auto_approve_known_ips, auto_approve_corporate_devices,
			request_expiry_hours, notify_admins, notify_user_on_decision, updated_at
		FROM device_trust_settings
		LIMIT 1
	`

	var settings DeviceTrustSettings
	err := s.db.Pool.QueryRow(ctx, query).Scan(
		&settings.ID, &settings.OrgID, &settings.RequireApproval, &settings.AutoApproveKnownIPs,
		&settings.AutoApproveCorporateDevs, &settings.RequestExpiryHours, &settings.NotifyAdmins,
		&settings.NotifyUserOnDecision, &settings.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// No settings row configured yet — return sensible defaults rather than
		// 500ing the device-trust page on a fresh install.
		return &DeviceTrustSettings{
			RequireApproval:      false,
			RequestExpiryHours:   72,
			NotifyAdmins:         true,
			NotifyUserOnDecision: true,
			UpdatedAt:            time.Now(),
		}, nil
	}
	if err != nil {
		return nil, err
	}

	return &settings, nil
}

// UpdateDeviceTrustSettings updates the settings
func (s *Service) UpdateDeviceTrustSettings(ctx context.Context, settings *DeviceTrustSettings) error {
	query := `
		UPDATE device_trust_settings
		SET require_approval = $1, auto_approve_known_ips = $2, auto_approve_corporate_devices = $3,
			request_expiry_hours = $4, notify_admins = $5, notify_user_on_decision = $6, updated_at = NOW()
		WHERE id = $7
	`

	_, err := s.db.Pool.Exec(ctx, query,
		settings.RequireApproval, settings.AutoApproveKnownIPs, settings.AutoApproveCorporateDevs,
		settings.RequestExpiryHours, settings.NotifyAdmins, settings.NotifyUserOnDecision,
		settings.ID,
	)

	return err
}

// GetPendingRequestCount returns count of pending requests
func (s *Service) GetPendingRequestCount(ctx context.Context) (int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM device_trust_requests WHERE status = 'pending' AND org_id = $1", org.ID,
	).Scan(&count)
	return count, err
}

// ExpireOldRequests expires requests past their auto_expire_at
func (s *Service) ExpireOldRequests(ctx context.Context) (int, error) {
	result, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore background maintenance sweep across orgs; bounded by auto_expire_at, not tenant-scoped
		`UPDATE device_trust_requests
		SET status = 'expired'
		WHERE status = 'pending' AND auto_expire_at IS NOT NULL AND auto_expire_at < NOW()`,
	)
	if err != nil {
		return 0, err
	}
	return int(result.RowsAffected()), nil
}

// Helper functions

func (s *Service) trustDevice(ctx context.Context, userID, fingerprint string) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return
	}
	s.db.Pool.Exec(ctx,
		"UPDATE known_devices SET trusted = true WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3",
		userID, fingerprint, org.ID,
	)
	// Nudge the Ziti mirror: identity-service has no controller access, but
	// marking the user's Ziti identity attributes stale makes the
	// access-service sync poller (30s tick; IS NULL qualifies immediately)
	// recompute #device-trusted on its next pass — instead of waiting for the
	// 5-minute staleness window or a console-driven manual sync. Same shared
	// Postgres, no cross-service call (IAM_PAM_ZITI_INTERRELATION: "one
	// store, JOINs not integrations").
	if _, err := s.db.Pool.Exec(ctx,
		"UPDATE ziti_identities SET group_attrs_synced_at = NULL WHERE user_id = $1 AND org_id = $2",
		userID, org.ID); err != nil {
		s.logger.Warn("device trust: failed to mark ziti identity attrs stale", zap.Error(err))
	}
}

func (s *Service) isKnownIP(ctx context.Context, userID, ipAddress string) bool {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}
	var count int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices
		WHERE user_id = $1 AND ip_address = $2 AND trusted = true AND org_id = $3`,
		userID, ipAddress, org.ID,
	).Scan(&count)
	return count > 0
}

func (s *Service) isCorporateDevice(ctx context.Context, fingerprint string) bool {
	// Check if device matches corporate device criteria
	// This could check domain membership, MDM enrollment, etc.
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}
	var count int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices
		WHERE fingerprint = $1 AND (device_type = 'corporate' OR name LIKE '%Corporate%') AND org_id = $2`,
		fingerprint, org.ID,
	).Scan(&count); err != nil {
		// Degrade to "not corporate", but say so: a silently swallowed scan
		// error is exactly what kept this check returning false while the
		// device_type column was missing (pre-v75).
		s.logger.Warn("corporate-device check failed", zap.Error(err))
		return false
	}
	return count > 0
}

// notifyAdminsOfTrustRequest notifies org admins (the well-known "admin" role)
// that a device is awaiting trust approval. Best-effort.
func (s *Service) notifyAdminsOfTrustRequest(ctx context.Context, userID, deviceName string) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Warn("device-trust admin notify: no org in context", zap.Error(err))
		return
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO notifications (user_id, channel, type, title, body, metadata, org_id)
		SELECT DISTINCT ur.user_id, 'in_app', 'device_trust',
			'New device trust request',
			'A device ("' || $1 || '") is awaiting trust approval.',
			jsonb_build_object('requesting_user', $2::text), r.org_id
		FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE r.name = 'admin' AND r.org_id = $3`,
		deviceName, userID, org.ID); err != nil {
		s.logger.Warn("failed to notify admins of device-trust request", zap.Error(err))
	}
}

// notifyUserOfTrustDecision notifies the requesting user that their device-trust
// request was approved or rejected. Best-effort.
func (s *Service) notifyUserOfTrustDecision(ctx context.Context, userID, decision, notes string) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Warn("device-trust decision notify: no org in context", zap.Error(err))
		return
	}
	body := "Your device trust request was " + decision + "."
	if notes != "" {
		body += " Note: " + notes
	}
	notif := notifications.NewService(s.db, s.logger)
	if err := notif.CreateMultiChannelNotification(ctx, userID, org.ID, "device_trust",
		"Device trust "+decision, body, "/devices", nil); err != nil {
		s.logger.Warn("failed to notify user of device-trust decision", zap.String("user_id", userID), zap.Error(err))
	}
}
