package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// MFAPolicy represents an MFA enforcement policy
type MFAPolicy struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Enabled          bool            `json:"enabled"`
	Priority         int             `json:"priority"`
	Conditions       json.RawMessage `json:"conditions"`
	RequiredMethods  json.RawMessage `json:"required_methods"`
	GracePeriodHours int             `json:"grace_period_hours"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// MFAEnrollmentStats represents aggregate MFA enrollment statistics
type MFAEnrollmentStats struct {
	TotalUsers int `json:"total_users"`
	// MFAEnabledCount is the number of users with at least one MFA method. The
	// frontend dashboard reads "mfa_enabled_count" for both the count and the
	// enabled-percentage; a mismatched tag makes the percentage render as NaN%.
	AnyMFA        int `json:"mfa_enabled_count"`
	TOTPCount     int `json:"totp_count"`
	SMSCount      int `json:"sms_count"`
	EmailOTPCount int `json:"email_otp_count"`
	PushCount     int `json:"push_count"`
	WebAuthnCount int `json:"webauthn_count"`
}

// UserMFAStatus represents MFA enrollment status for a single user
type UserMFAStatus struct {
	UserID               string `json:"user_id"`
	Username             string `json:"username"`
	Email                string `json:"email"`
	TOTPEnabled          bool   `json:"totp_enabled"`
	SMSEnabled           bool   `json:"sms_enabled"`
	EmailOTPEnabled      bool   `json:"email_otp_enabled"`
	PushEnabled          bool   `json:"push_enabled"`
	WebAuthnEnabled      bool   `json:"webauthn_enabled"`
	BackupCodesRemaining int    `json:"backup_codes_remaining"`
}

// --- MFA Enrollment Stats Handler ---

// mfaStatusColumns derives per-user MFA enrollment flags from the real
// enrollment tables. user_mfa_methods was a view only legacy SQL files defined
// — the migration runner never creates it, so every handler reading it failed.
// mfa_sms/mfa_email_otp have no org_id column; the others are org-belted.
const mfaStatusColumns = `
	EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.org_id = $1 AND t.enabled) AS totp_enabled,
	EXISTS (SELECT 1 FROM mfa_sms sm WHERE sm.user_id = u.id AND sm.enabled AND sm.verified) AS sms_enabled,
	EXISTS (SELECT 1 FROM mfa_email_otp e WHERE e.user_id = u.id AND e.enabled) AS email_otp_enabled,
	EXISTS (SELECT 1 FROM mfa_push_devices p WHERE p.user_id = u.id AND p.org_id = $1 AND p.enabled) AS push_enabled,
	EXISTS (SELECT 1 FROM mfa_webauthn w WHERE w.user_id = u.id AND w.org_id = $1) AS webauthn_enabled`

func (s *Service) handleMFAEnrollmentStats(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var stats MFAEnrollmentStats
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT
			COUNT(*) AS total_users,
			COUNT(*) FILTER (WHERE totp_enabled OR sms_enabled OR email_otp_enabled OR push_enabled OR webauthn_enabled) AS any_mfa,
			COUNT(*) FILTER (WHERE totp_enabled) AS totp_count,
			COUNT(*) FILTER (WHERE sms_enabled) AS sms_count,
			COUNT(*) FILTER (WHERE email_otp_enabled) AS email_otp_count,
			COUNT(*) FILTER (WHERE push_enabled) AS push_count,
			COUNT(*) FILTER (WHERE webauthn_enabled) AS webauthn_count
		 FROM (SELECT `+mfaStatusColumns+`
		       FROM users u WHERE u.org_id = $1) m`, org.ID,
	).Scan(&stats.TotalUsers, &stats.AnyMFA, &stats.TOTPCount, &stats.SMSCount,
		&stats.EmailOTPCount, &stats.PushCount, &stats.WebAuthnCount)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get MFA enrollment stats", err))
		return
	}

	c.JSON(http.StatusOK, stats)
}

// --- MFA Policies Handlers ---

func (s *Service) handleListMFAPolicies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// The dashboard paginates with page/page_size and reads {policies,total}.
	// Returning a bare {"data": [...]} made every created policy invisible in the
	// UI even though the insert succeeded.
	page := 1
	if v, perr := strconv.Atoi(c.Query("page")); perr == nil && v > 0 {
		page = v
	}
	pageSize := 20
	if v, perr := strconv.Atoi(c.Query("page_size")); perr == nil && v > 0 && v <= 200 {
		pageSize = v
	}
	offset := (page - 1) * pageSize

	var total int
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM mfa_policies WHERE org_id = $1`, org.ID).Scan(&total); err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to count MFA policies", err))
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at
		 FROM mfa_policies WHERE org_id = $1 ORDER BY priority, name
		 LIMIT $2 OFFSET $3`, org.ID, pageSize, offset)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list MFA policies", err))
		return
	}
	defer rows.Close()

	var policies []MFAPolicy
	for rows.Next() {
		var p MFAPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
			&p.Conditions, &p.RequiredMethods, &p.GracePeriodHours, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []MFAPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{
		"policies":  policies,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (s *Service) handleCreateMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name             string          `json:"name"`
		Description      string          `json:"description"`
		Enabled          bool            `json:"enabled"`
		Priority         int             `json:"priority"`
		Conditions       json.RawMessage `json:"conditions"`
		RequiredMethods  json.RawMessage `json:"required_methods"`
		GracePeriodHours int             `json:"grace_period_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Name == "" {
		respondError(c, nil, apperrors.BadRequest("name is required"))
		return
	}

	conditions := req.Conditions
	if conditions == nil {
		conditions = json.RawMessage("{}")
	}
	requiredMethods := req.RequiredMethods
	if requiredMethods == nil {
		requiredMethods = json.RawMessage("[]")
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var policy MFAPolicy
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at`,
		req.Name, req.Description, req.Enabled, req.Priority, conditions, requiredMethods, req.GracePeriodHours, org.ID,
	).Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
		&policy.Conditions, &policy.RequiredMethods, &policy.GracePeriodHours, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create MFA policy", err))
		return
	}

	c.JSON(http.StatusCreated, policy)
}

func (s *Service) handleGetMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	var p MFAPolicy
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at
		 FROM mfa_policies WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
		&p.Conditions, &p.RequiredMethods, &p.GracePeriodHours, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("MFA policy"))
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Service) handleUpdateMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	var req struct {
		Name             *string          `json:"name"`
		Description      *string          `json:"description"`
		Enabled          *bool            `json:"enabled"`
		Priority         *int             `json:"priority"`
		Conditions       *json.RawMessage `json:"conditions"`
		RequiredMethods  *json.RawMessage `json:"required_methods"`
		GracePeriodHours *int             `json:"grace_period_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.Priority != nil {
		sets = append(sets, fmt.Sprintf("priority = $%d", argIdx))
		args = append(args, *req.Priority)
		argIdx++
	}
	if req.Conditions != nil {
		sets = append(sets, fmt.Sprintf("conditions = $%d", argIdx))
		args = append(args, *req.Conditions)
		argIdx++
	}
	if req.RequiredMethods != nil {
		sets = append(sets, fmt.Sprintf("required_methods = $%d", argIdx))
		args = append(args, *req.RequiredMethods)
		argIdx++
	}
	if req.GracePeriodHours != nil {
		sets = append(sets, fmt.Sprintf("grace_period_hours = $%d", argIdx))
		args = append(args, *req.GracePeriodHours)
		argIdx++
	}

	args = append(args, id)
	orgArgIdx := argIdx + 1
	args = append(args, org.ID)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE mfa_policies SET %s WHERE id = $%d AND org_id = $%d",
		joinSetClauses(sets), argIdx, orgArgIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update MFA policy", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("MFA policy"))
		return
	}

	// Return the updated policy
	var p MFAPolicy
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at
		 FROM mfa_policies WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
		&p.Conditions, &p.RequiredMethods, &p.GracePeriodHours, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to fetch updated MFA policy", err))
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Service) handleDeleteMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM mfa_policies WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete MFA policy", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("MFA policy"))
		return
	}
	c.Status(http.StatusNoContent)
}

// --- User MFA Status Handlers ---

func (s *Service) handleListUserMFAStatus(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var total int
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE org_id = $1", org.ID).Scan(&total)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to count user MFA records", err))
		return
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT u.id::text, u.username, COALESCE(u.email, ''),`+mfaStatusColumns+`,
		        (SELECT COUNT(*) FROM mfa_backup_codes b WHERE b.user_id = u.id AND b.org_id = $1 AND NOT b.used) AS backup_codes_remaining
		 FROM users u
		 WHERE u.org_id = $1
		 ORDER BY u.username
		 LIMIT $2 OFFSET $3`, org.ID, limit, offset)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list user MFA status", err))
		return
	}
	defer rows.Close()

	var statuses []UserMFAStatus
	for rows.Next() {
		var u UserMFAStatus
		if err := rows.Scan(&u.UserID, &u.Username, &u.Email,
			&u.TOTPEnabled, &u.SMSEnabled, &u.EmailOTPEnabled,
			&u.PushEnabled, &u.WebAuthnEnabled, &u.BackupCodesRemaining); err != nil {
			continue
		}
		statuses = append(statuses, u)
	}
	if statuses == nil {
		statuses = []UserMFAStatus{}
	}
	c.JSON(http.StatusOK, gin.H{"data": statuses, "total": total})
}

func (s *Service) handleGetUserMFAStatus(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	var u UserMFAStatus
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT u.id::text, u.username, COALESCE(u.email, ''),`+mfaStatusColumns+`,
		        (SELECT COUNT(*) FROM mfa_backup_codes b WHERE b.user_id = u.id AND b.org_id = $1 AND NOT b.used) AS backup_codes_remaining
		 FROM users u
		 WHERE u.org_id = $1 AND u.id::text = $2`, org.ID, id,
	).Scan(&u.UserID, &u.Username, &u.Email,
		&u.TOTPEnabled, &u.SMSEnabled, &u.EmailOTPEnabled,
		&u.PushEnabled, &u.WebAuthnEnabled, &u.BackupCodesRemaining)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("user MFA status"))
		return
	}
	c.JSON(http.StatusOK, u)
}
