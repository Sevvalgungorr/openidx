// Package portal provides self-service portal functionality for end users
package portal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/ai"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrInvalidDecision is returned when a group-request review decision is not one
// of the accepted values. It is a client-input (validation) error, so handlers
// map it to HTTP 400 rather than a generic 500.
var ErrInvalidDecision = errors.New("invalid decision: must be 'approved' or 'denied'")

// UserApplication represents an application assigned to a user
type UserApplication struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	BaseURL     string `json:"base_url"`
	Protocol    string `json:"protocol"`
	LogoURL     string `json:"logo_url"`
	SSOEnabled  bool   `json:"sso_enabled"`
}

// GroupJoinRequest represents a user's request to join a group
type GroupJoinRequest struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	GroupID        string     `json:"group_id"`
	GroupName      string     `json:"group_name"`
	Justification  string     `json:"justification"`
	Status         string     `json:"status"`
	ReviewedBy     *string    `json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
	ReviewComments *string    `json:"review_comments,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// AccessOverview represents a summary of a user's current access across all
// three pillars: IAM (roles/groups/apps), PAM (privileged access), and the
// Ziti zero-trust network — the user-side face of the unified store.
type AccessOverview struct {
	RolesCount      int                      `json:"roles_count"`
	GroupsCount     int                      `json:"groups_count"`
	AppsCount       int                      `json:"apps_count"`
	PendingRequests int                      `json:"pending_requests"`
	Roles           []map[string]interface{} `json:"roles"`
	Groups          []map[string]interface{} `json:"groups"`
	Privileged      PrivilegedOverview       `json:"privileged"`
	Network         NetworkOverview          `json:"network"`
}

// PrivilegedOverview is the PAM slice of the user's own access: what
// privileged material they hold right now.
type PrivilegedOverview struct {
	VaultGrants       int `json:"vault_grants"`
	ActiveCheckouts   int `json:"active_checkouts"`
	ActiveJITGrants   int `json:"active_jit_grants"`
	ActiveSessions    int `json:"active_sessions"`
	PendingSessionReq int `json:"pending_session_requests"`
}

// NetworkOverview is the Ziti slice of the user's own access: their network
// identity and enrolled devices.
type NetworkOverview struct {
	ZitiLinked    bool `json:"ziti_linked"`
	ZitiEnrolled  bool `json:"ziti_enrolled"`
	Devices       int  `json:"devices"`
	TrustedDevice bool `json:"trusted_device"`
}

// Service provides portal business logic
type Service struct {
	db       *database.PostgresDB
	logger   *zap.Logger
	aiClient *ai.Client // optional local-LLM client for security insights
}

// NewService creates a new portal service
func NewService(db *database.PostgresDB, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// GetMyApplications returns the applications assigned to a user.
// If no assignments exist, it falls back to returning all enabled applications.
func (s *Service) GetMyApplications(ctx context.Context, userID string) ([]UserApplication, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT a.id, a.name, COALESCE(a.description, '') AS description,
		       COALESCE(a.base_url, '') AS base_url, COALESCE(a.protocol, '') AS protocol
		FROM user_application_assignments uaa
		JOIN applications a ON a.id = uaa.application_id
		WHERE uaa.user_id = $1 AND uaa.org_id = $2 AND a.enabled = true
		ORDER BY a.name`

	rows, err := s.db.Pool.Query(ctx, query, userID, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user applications: %w", err)
	}
	defer rows.Close()

	var apps []UserApplication
	for rows.Next() {
		var app UserApplication
		if err := rows.Scan(&app.ID, &app.Name, &app.Description, &app.BaseURL, &app.Protocol); err != nil {
			return nil, fmt.Errorf("failed to scan application: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating application rows: %w", err)
	}

	// Fallback: if no assignments exist, return all enabled applications
	if len(apps) == 0 {
		fallbackQuery := `
			SELECT id, name, COALESCE(description, '') AS description,
			       COALESCE(base_url, '') AS base_url, COALESCE(protocol, '') AS protocol
			FROM applications
			WHERE enabled = true AND org_id = $1
			ORDER BY name`

		fallbackRows, err := s.db.Pool.Query(ctx, fallbackQuery, org.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to query all applications: %w", err)
		}
		defer fallbackRows.Close()

		for fallbackRows.Next() {
			var app UserApplication
			if err := fallbackRows.Scan(&app.ID, &app.Name, &app.Description, &app.BaseURL, &app.Protocol); err != nil {
				return nil, fmt.Errorf("failed to scan fallback application: %w", err)
			}
			apps = append(apps, app)
		}
		if err := fallbackRows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating fallback application rows: %w", err)
		}
	}

	return apps, nil
}

// GetAvailableGroups returns groups that allow self-join, along with membership and pending request status for the user.
func (s *Service) GetAvailableGroups(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT g.id, g.name, COALESCE(g.description, '') AS description,
		       EXISTS(SELECT 1 FROM group_memberships gm WHERE gm.group_id = g.id AND gm.user_id = $1 AND gm.org_id = $2) AS is_member,
		       EXISTS(SELECT 1 FROM group_join_requests gjr WHERE gjr.group_id = g.id AND gjr.user_id = $1 AND gjr.org_id = $2 AND gjr.status = 'pending') AS has_pending_request
		FROM groups g
		WHERE g.allow_self_join = true AND g.org_id = $2
		ORDER BY g.name`

	rows, err := s.db.Pool.Query(ctx, query, userID, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query available groups: %w", err)
	}
	defer rows.Close()

	var groups []map[string]interface{}
	for rows.Next() {
		var id, name, description string
		var isMember, hasPendingRequest bool
		if err := rows.Scan(&id, &name, &description, &isMember, &hasPendingRequest); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, map[string]interface{}{
			"id":                  id,
			"name":                name,
			"description":         description,
			"is_member":           isMember,
			"has_pending_request": hasPendingRequest,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group rows: %w", err)
	}

	return groups, nil
}

// RequestGroupJoin handles a user's request to join a group.
// If the group does not require approval, the user is added directly.
func (s *Service) RequestGroupJoin(ctx context.Context, userID, groupID, justification string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Check that the group allows self-join and whether approval is required
	var allowSelfJoin, requireApproval bool
	err = s.db.Pool.QueryRow(ctx,
		`SELECT allow_self_join, COALESCE(require_approval, true) FROM groups WHERE id = $1 AND org_id = $2`,
		groupID, org.ID,
	).Scan(&allowSelfJoin, &requireApproval)
	if err != nil {
		return fmt.Errorf("failed to query group: %w", err)
	}
	if !allowSelfJoin {
		return fmt.Errorf("group does not allow self-join")
	}

	if !requireApproval {
		// Add the user directly to the group
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (group_id, user_id, joined_at, org_id) VALUES ($1, $2, $3, $4)
			 ON CONFLICT DO NOTHING`,
			groupID, userID, time.Now().UTC(), org.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to add user to group: %w", err)
		}
		return nil
	}

	// Insert a join request for approval
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO group_join_requests (id, user_id, group_id, justification, status, created_at, org_id)
		 VALUES ($1, $2, $3, $4, 'pending', $5, $6)`,
		uuid.New().String(), userID, groupID, justification, time.Now().UTC(), org.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to create group join request: %w", err)
	}

	return nil
}

// GetMyGroupRequests returns the current user's group join requests.
func (s *Service) GetMyGroupRequests(ctx context.Context, userID string) ([]GroupJoinRequest, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT gjr.id, gjr.user_id, gjr.group_id, g.name AS group_name,
		       COALESCE(gjr.justification, '') AS justification, gjr.status,
		       gjr.reviewed_by, gjr.reviewed_at, gjr.review_comments, gjr.created_at
		FROM group_join_requests gjr
		JOIN groups g ON g.id = gjr.group_id
		WHERE gjr.user_id = $1 AND gjr.org_id = $2
		ORDER BY gjr.created_at DESC`

	rows, err := s.db.Pool.Query(ctx, query, userID, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query group requests: %w", err)
	}
	defer rows.Close()

	var requests []GroupJoinRequest
	for rows.Next() {
		var r GroupJoinRequest
		if err := rows.Scan(&r.ID, &r.UserID, &r.GroupID, &r.GroupName,
			&r.Justification, &r.Status, &r.ReviewedBy, &r.ReviewedAt,
			&r.ReviewComments, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group request: %w", err)
		}
		requests = append(requests, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group request rows: %w", err)
	}

	return requests, nil
}

// GetAccessOverview returns an overview of the user's current access entitlements.
func (s *Service) GetAccessOverview(ctx context.Context, userID string) (*AccessOverview, error) {
	overview := &AccessOverview{}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Count roles
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND org_id = $2`, userID, org.ID,
	).Scan(&overview.RolesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count roles: %w", err)
	}

	// Count groups
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_memberships WHERE user_id = $1 AND org_id = $2`, userID, org.ID,
	).Scan(&overview.GroupsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count groups: %w", err)
	}

	// Count apps
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_application_assignments WHERE user_id = $1 AND org_id = $2`, userID, org.ID,
	).Scan(&overview.AppsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count apps: %w", err)
	}

	// Count pending requests
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_join_requests WHERE user_id = $1 AND status = 'pending' AND org_id = $2`, userID, org.ID,
	).Scan(&overview.PendingRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to count pending requests: %w", err)
	}

	// Get role names
	roleRows, err := s.db.Pool.Query(ctx,
		`SELECT r.id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 AND ur.org_id = $2 ORDER BY r.name`, userID, org.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	defer roleRows.Close()

	overview.Roles = []map[string]interface{}{}
	for roleRows.Next() {
		var id, name string
		if err := roleRows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		overview.Roles = append(overview.Roles, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := roleRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role rows: %w", err)
	}

	// Get group names
	groupRows, err := s.db.Pool.Query(ctx,
		`SELECT g.id, g.name FROM group_memberships gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = $1 AND gm.org_id = $2 ORDER BY g.name`, userID, org.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query groups: %w", err)
	}
	defer groupRows.Close()

	overview.Groups = []map[string]interface{}{}
	for groupRows.Next() {
		var id, name string
		if err := groupRows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		overview.Groups = append(overview.Groups, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := groupRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group rows: %w", err)
	}

	// PAM pillar: the user's own privileged surface. All tables live in the
	// same Postgres, so cross-pillar is a set of scoped counts, not a call to
	// another service. Vault grants count both direct user grants and grants
	// on any of the user's roles.
	err = s.db.Pool.QueryRow(ctx,
		`SELECT
		   (SELECT COUNT(DISTINCT vg.secret_id) FROM vault_access_grants vg
		     WHERE vg.org_id = $2
		       AND (vg.expires_at IS NULL OR vg.expires_at > NOW())
		       AND ((vg.principal_type = 'user' AND vg.principal_id = $1)
		         OR (vg.principal_type = 'role' AND vg.principal_id IN
		              (SELECT role_id FROM user_roles WHERE user_id = $1 AND org_id = $2)))),
		   (SELECT COUNT(*) FROM vault_checkouts
		     WHERE principal_id = $1 AND org_id = $2 AND status = 'active'),
		   (SELECT COUNT(*) FROM jit_grants
		     WHERE user_id = $1 AND org_id = $2 AND status = 'active' AND expires_at > NOW()),
		   (SELECT COUNT(*) FROM guacamole_sessions
		     WHERE user_id = $1 AND org_id = $2 AND status = 'active'),
		   (SELECT COUNT(*) FROM guacamole_session_requests
		     WHERE requester_id = $1 AND org_id = $2 AND status = 'pending'
		       AND (expires_at IS NULL OR expires_at > NOW()))`,
		userID, org.ID,
	).Scan(&overview.Privileged.VaultGrants, &overview.Privileged.ActiveCheckouts,
		&overview.Privileged.ActiveJITGrants, &overview.Privileged.ActiveSessions,
		&overview.Privileged.PendingSessionReq)
	if err != nil {
		return nil, fmt.Errorf("failed to query privileged overview: %w", err)
	}

	// Ziti pillar: network identity + devices. enrolled_agents has no org_id;
	// it is scoped through the org-verified user key.
	err = s.db.Pool.QueryRow(ctx,
		`SELECT
		   EXISTS(SELECT 1 FROM ziti_identities WHERE user_id = $1 AND org_id = $2),
		   COALESCE((SELECT enrolled FROM ziti_identities WHERE user_id = $1 AND org_id = $2 LIMIT 1), false),
		   (SELECT COUNT(*) FROM enrolled_agents WHERE enrolled_by_user_id = $1),
		   EXISTS(SELECT 1 FROM known_devices WHERE user_id = $1 AND org_id = $2 AND trusted = true)`,
		userID, org.ID,
	).Scan(&overview.Network.ZitiLinked, &overview.Network.ZitiEnrolled,
		&overview.Network.Devices, &overview.Network.TrustedDevice)
	if err != nil {
		return nil, fmt.Errorf("failed to query network overview: %w", err)
	}

	return overview, nil
}

// ReviewGroupRequest allows an admin to approve or deny a group join request.
func (s *Service) ReviewGroupRequest(ctx context.Context, requestID, reviewerID, decision, comments string) error {
	if decision != "approved" && decision != "denied" {
		return ErrInvalidDecision
	}

	now := time.Now().UTC()

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Update the request status
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE group_join_requests
		 SET status = $1, reviewed_by = $2, reviewed_at = $3, review_comments = $4
		 WHERE id = $5 AND org_id = $6 AND status = 'pending'`,
		decision, reviewerID, now, comments, requestID, org.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update group join request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("request not found or already reviewed")
	}

	// If approved, add the user to the group
	if decision == "approved" {
		var userID, groupID string
		err := s.db.Pool.QueryRow(ctx,
			`SELECT user_id, group_id FROM group_join_requests WHERE id = $1 AND org_id = $2`, requestID, org.ID,
		).Scan(&userID, &groupID)
		if err != nil {
			return fmt.Errorf("failed to fetch request details: %w", err)
		}

		_, err = s.db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (group_id, user_id, joined_at, org_id) VALUES ($1, $2, $3, $4)
			 ON CONFLICT DO NOTHING`,
			groupID, userID, now, org.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to add user to group: %w", err)
		}
	}

	return nil
}

// getUserID extracts the user ID from the Gin context.
// Returns the user ID or empty string if not authenticated.
func getUserID(c *gin.Context) string {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	return userIDStr
}

// requireUserID extracts the user ID and returns 401 if not present.
// Returns the user ID and true if valid, empty string and false if not.
func requireUserID(c *gin.Context) (string, bool) {
	uid := getUserID(c)
	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		c.Abort()
		return "", false
	}
	return uid, true
}

// handleGetMyApplications handles GET /portal/applications
func (s *Service) handleGetMyApplications(c *gin.Context) {
	userIDStr := getUserID(c)

	apps, err := s.GetMyApplications(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get user applications", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get applications"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"applications": apps})
}

// handleGetAvailableGroups handles GET /portal/groups/available
func (s *Service) handleGetAvailableGroups(c *gin.Context) {
	userIDStr := getUserID(c)

	groups, err := s.GetAvailableGroups(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get available groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get available groups"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

// handleRequestGroupJoin handles POST /portal/groups/request
func (s *Service) handleRequestGroupJoin(c *gin.Context) {
	userIDStr, ok := requireUserID(c)
	if !ok {
		return
	}

	var req struct {
		GroupID       string `json:"group_id" binding:"required"`
		Justification string `json:"justification"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	err := s.RequestGroupJoin(c.Request.Context(), userIDStr, req.GroupID, req.Justification)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to request group join", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group join request submitted"})
}

// handleGetMyGroupRequests handles GET /portal/groups/requests
func (s *Service) handleGetMyGroupRequests(c *gin.Context) {
	userIDStr := getUserID(c)

	requests, err := s.GetMyGroupRequests(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get group requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get group requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

// handleGetAccessOverview handles GET /portal/access-overview
func (s *Service) handleGetAccessOverview(c *gin.Context) {
	userIDStr := getUserID(c)

	overview, err := s.GetAccessOverview(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get access overview", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access overview"})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// handleReviewGroupRequest handles POST /portal/groups/requests/:id/review (admin only)
func (s *Service) handleReviewGroupRequest(c *gin.Context) {
	requestID := c.Param("id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request ID is required"})
		return
	}

	reviewerID, ok := requireUserID(c)
	if !ok {
		return
	}

	var req struct {
		Decision string `json:"decision" binding:"required"`
		Comments string `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	err := s.ReviewGroupRequest(c.Request.Context(), requestID, reviewerID, req.Decision, req.Comments)
	if err != nil {
		if errors.Is(err, ErrInvalidDecision) {
			apperrors.HandleError(c, apperrors.ValidationError(err.Error()))
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to review group request", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group request reviewed"})
}

// --- Device Management ---

// UserDevice represents a user's registered device
type UserDevice struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	Name           string     `json:"name"`
	DeviceType     string     `json:"device_type"` // desktop, mobile, tablet
	IPAddress      string     `json:"ip_address"`
	UserAgent      string     `json:"user_agent,omitempty"`
	Location       string     `json:"location,omitempty"`
	Trusted        bool       `json:"trusted"`
	TrustRequested bool       `json:"trust_requested"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// GetMyDevices returns all devices for a user
func (s *Service) GetMyDevices(ctx context.Context, userID string) ([]UserDevice, error) {
	query := `
		SELECT id, user_id, fingerprint, COALESCE(name, 'Unknown Device') AS name,
		       ip_address, user_agent, COALESCE(location, '') AS location,
		       trusted, last_seen_at, created_at
		FROM known_devices
		WHERE user_id = $1
		ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()

	var devices []UserDevice
	for rows.Next() {
		var d UserDevice
		if err := rows.Scan(&d.ID, &d.UserID, &d.Fingerprint, &d.Name,
			&d.IPAddress, &d.UserAgent, &d.Location, &d.Trusted,
			&d.LastSeenAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}
		d.DeviceType = detectDeviceType(d.UserAgent)
		devices = append(devices, d)
	}

	return devices, nil
}

// RegisterDevice registers a new device for a user
func (s *Service) RegisterDevice(ctx context.Context, userID, name, fingerprint, ipAddress, userAgent, location string) (*UserDevice, error) {
	// Resolve the tenant explicitly: without this the INSERT below relied on
	// the known_devices.org_id column DEFAULT (the primary org), silently
	// mis-tenanting every portal-registered device — org-scoped consumers
	// (isKnownIP / trustDevice / isCorporateDevice) could never match them.
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	device := &UserDevice{
		ID:          uuid.New().String(),
		UserID:      userID,
		Fingerprint: fingerprint,
		Name:        name,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Location:    location,
		Trusted:     false,
		CreatedAt:   time.Now().UTC(),
	}

	if device.Name == "" {
		device.Name = detectDeviceName(userAgent)
	}
	if device.Fingerprint == "" {
		device.Fingerprint = generateFingerprint(userAgent, ipAddress)
	}
	device.DeviceType = detectDeviceType(userAgent)

	// org_id = EXCLUDED.org_id on conflict also heals rows that were
	// mis-tenanted to the column default before this fix, the next time the
	// same device re-registers.
	query := `
		INSERT INTO known_devices (id, user_id, fingerprint, name, ip_address, user_agent, location, trusted, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id, fingerprint) DO UPDATE
		SET name = EXCLUDED.name, ip_address = EXCLUDED.ip_address, user_agent = EXCLUDED.user_agent,
		    location = EXCLUDED.location, last_seen_at = NOW(), org_id = EXCLUDED.org_id
		RETURNING id
	`

	err = s.db.Pool.QueryRow(ctx, query,
		device.ID, device.UserID, device.Fingerprint, device.Name,
		device.IPAddress, device.UserAgent, device.Location, device.Trusted, device.CreatedAt, org.ID,
	).Scan(&device.ID)

	if err != nil {
		return nil, fmt.Errorf("failed to register device: %w", err)
	}

	return device, nil
}

// UpdateDevice updates a device's name
func (s *Service) UpdateDevice(ctx context.Context, userID, deviceID, name string) error {
	query := `UPDATE known_devices SET name = $1 WHERE id = $2 AND user_id = $3`
	result, err := s.db.Pool.Exec(ctx, query, name, deviceID, userID)
	if err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// DeleteDevice removes a device
func (s *Service) DeleteDevice(ctx context.Context, userID, deviceID string) error {
	query := `DELETE FROM known_devices WHERE id = $1 AND user_id = $2`
	result, err := s.db.Pool.Exec(ctx, query, deviceID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// RequestDeviceTrust creates a trust request for a device
func (s *Service) RequestDeviceTrust(ctx context.Context, userID, deviceID, justification string) error {
	// For now, just mark the device - in production, this would create an approval workflow
	// Note: This is a simplified implementation. A full implementation would have:
	// - device_trust_requests table
	// - Approval workflow
	// - Admin notification
	s.logger.Info("Device trust requested",
		zap.String("user_id", userID),
		zap.String("device_id", deviceID),
		zap.String("justification", justification))
	return nil
}

// --- Device HTTP Handlers ---

func (s *Service) handleGetMyDevices(c *gin.Context) {
	userID := getUserID(c)

	devices, err := s.GetMyDevices(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get devices", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get devices"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"devices": devices})
}

func (s *Service) handleRegisterDevice(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	var req struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
		Location    string `json:"location"`
	}
	c.ShouldBindJSON(&req)

	device, err := s.RegisterDevice(c.Request.Context(), userID, req.Name, req.Fingerprint,
		c.ClientIP(), c.GetHeader("User-Agent"), req.Location)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to register device", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, device)
}

func (s *Service) handleUpdateDevice(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}
	deviceID := c.Param("id")

	var req struct {
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	if err := s.UpdateDevice(c.Request.Context(), userID, deviceID, req.Name); err != nil {
		s.logger.Error("failed to update device", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device updated"})
}

func (s *Service) handleDeleteDevice(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}
	deviceID := c.Param("id")

	if err := s.DeleteDevice(c.Request.Context(), userID, deviceID); err != nil {
		s.logger.Error("failed to delete device", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device removed"})
}

func (s *Service) handleRequestDeviceTrust(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}
	deviceID := c.Param("id")

	var req struct {
		Justification string `json:"justification"`
	}
	c.ShouldBindJSON(&req)

	if err := s.RequestDeviceTrust(c.Request.Context(), userID, deviceID, req.Justification); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to request device trust", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "trust request submitted"})
}

// --- Helper Functions ---

func detectDeviceType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		return "mobile"
	}
	if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		return "tablet"
	}
	return "desktop"
}

func detectDeviceName(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Detect OS
	var os string
	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		os = "macOS"
	case strings.Contains(ua, "iphone"):
		os = "iPhone"
	case strings.Contains(ua, "ipad"):
		os = "iPad"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	default:
		os = "Unknown"
	}

	// Detect browser
	var browser string
	switch {
	case strings.Contains(ua, "edg"):
		browser = "Edge"
	case strings.Contains(ua, "chrome"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	default:
		browser = "Browser"
	}

	return fmt.Sprintf("%s %s", os, browser)
}

func generateFingerprint(userAgent, ipAddress string) string {
	// Simple fingerprint - in production use more sophisticated methods
	data := fmt.Sprintf("%s|%s", userAgent, ipAddress)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter ID
}

// RegisterRoutes registers all portal HTTP routes on the given router group.
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	router.GET("/portal/applications", svc.handleGetMyApplications)
	router.GET("/portal/groups/available", svc.handleGetAvailableGroups)
	router.POST("/portal/groups/request", svc.handleRequestGroupJoin)
	router.GET("/portal/groups/requests", svc.handleGetMyGroupRequests)
	router.GET("/portal/access-overview", svc.handleGetAccessOverview)
	router.POST("/portal/groups/requests/:id/review", svc.handleReviewGroupRequest)

	// Device management
	router.GET("/portal/devices", svc.handleGetMyDevices)
	router.POST("/portal/devices", svc.handleRegisterDevice)
	router.PUT("/portal/devices/:id", svc.handleUpdateDevice)
	router.DELETE("/portal/devices/:id", svc.handleDeleteDevice)
	router.POST("/portal/devices/:id/trust", svc.handleRequestDeviceTrust)

	// My security insights (caller-scoped; plain-language self-assessment)
	router.GET("/portal/security-insights", svc.handleGetSecurityInsights)
}
