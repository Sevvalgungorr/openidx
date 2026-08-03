package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// AccessRequest represents a request for access to a role, group, or application
type AccessRequest struct {
	ID            string     `json:"id"`
	RequesterID   string     `json:"requester_id"`
	RequesterName string     `json:"requester_name,omitempty"`
	ResourceType  string     `json:"resource_type"`
	ResourceID    string     `json:"resource_id"`
	ResourceName  string     `json:"resource_name"`
	Justification string     `json:"justification"`
	Status        string     `json:"status"`
	Priority      string     `json:"priority"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Approvals     []Approval `json:"approvals,omitempty"`
}

// Approval represents a single approval/denial decision on an access request
type Approval struct {
	ID           string     `json:"id"`
	RequestID    string     `json:"request_id"`
	ApproverID   string     `json:"approver_id"`
	ApproverName string     `json:"approver_name,omitempty"`
	StepOrder    int        `json:"step_order"`
	Decision     string     `json:"decision"`
	Comments     string     `json:"comments"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AutoApproveConditions defines typed conditions for automatic approval (V-007 security fix)
type AutoApproveConditions struct {
	MaxRiskScore    *int     `json:"max_risk_score,omitempty"`
	AllowedRoles    []string `json:"allowed_roles,omitempty"`
	AllowedGroups   []string `json:"allowed_groups,omitempty"`
	RequireMFA      *bool    `json:"require_mfa,omitempty"`
	MaxRequestCount *int     `json:"max_request_count,omitempty"`
}

// ApprovalPolicy defines who must approve requests for specific resource types
type ApprovalPolicy struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	ResourceType          string                 `json:"resource_type"`
	ResourceID            *string                `json:"resource_id,omitempty"`
	ApprovalSteps         []ApprovalStep         `json:"approval_steps"`
	AutoApproveConditions *AutoApproveConditions `json:"auto_approve_conditions,omitempty"`
	MaxWaitHours          int                    `json:"max_wait_hours"`
	Enabled               bool                   `json:"enabled"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// parseDuration converts a human-friendly duration string to time.Duration.
// Supports: "4h", "8h", "1d", "3d", "7d", "30d", "90d"
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	unit := s[len(s)-1]
	value := s[:len(s)-1]
	var n int
	if _, err := fmt.Sscanf(value, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", s)
	}
	switch unit {
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported duration unit: %c", unit)
	}
}

// handleCreateAccessRequest creates a new access request
func (s *Service) handleCreateAccessRequest(c *gin.Context) {
	var body struct {
		ResourceType  string `json:"resource_type"`
		ResourceID    string `json:"resource_id"`
		ResourceName  string `json:"resource_name"`
		Justification string `json:"justification"`
		Priority      string `json:"priority"`
		Duration      string `json:"duration,omitempty"` // e.g. "4h", "1d", "7d", "30d" — empty means permanent
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.ResourceType == "" || body.ResourceName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource_type and resource_name are required"})
		return
	}

	if body.Priority == "" {
		body.Priority = "normal"
	}

	requesterID := c.GetString("user_id")
	if requesterID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	if body.ResourceID == "" {
		body.ResourceID = uuid.New().String()
	}

	// vault_credential requests: validate the secret exists under the caller's org
	// context (RLS scopes the SELECT to the caller's org) and require a bounded window.
	if body.ResourceType == "vault_credential" {
		var exists bool
		if err := s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT EXISTS(SELECT 1 FROM vault_secrets WHERE id=$1)`, body.ResourceID).Scan(&exists); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "validate secret"})
			return
		}
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "vault secret not found or not accessible"})
			return
		}
		// A duration/expires_at is required so the checkout window is bounded.
		if body.Duration == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "vault_credential requests require a duration"})
			return
		}
	}

	// Parse duration to calculate expires_at
	var expiresAt *time.Time
	if body.Duration != "" {
		d, err := parseDuration(body.Duration)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid duration: " + err.Error()})
			return
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	id := uuid.New().String()
	now := time.Now()

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, justification, status, priority, expires_at, created_at, updated_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		id, requesterID, body.ResourceType, body.ResourceID, body.ResourceName,
		body.Justification, "pending", body.Priority, expiresAt, now, now, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to create access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access request"})
		return
	}

	// Find matching approval policy and create approval rows
	s.createApprovalRows(c.Request.Context(), id, body.ResourceType, body.ResourceID)

	c.JSON(http.StatusCreated, AccessRequest{
		ID:            id,
		RequesterID:   requesterID,
		ResourceType:  body.ResourceType,
		ResourceID:    body.ResourceID,
		ResourceName:  body.ResourceName,
		Justification: body.Justification,
		Status:        "pending",
		Priority:      body.Priority,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
}

// createApprovalRows looks up approval policies and creates approval rows for a request
func (s *Service) createApprovalRows(ctx context.Context, requestID, resourceType, resourceID string) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Error("createApprovalRows: no org context", zap.Error(err))
		return
	}

	// Resolve the requester up front so approver steps can EXCLUDE them:
	// four-eyes means a user must never end up as an approver of their own
	// request. A role- or group-based approver step would otherwise insert an
	// approval row for the requester whenever they hold the approver role/group
	// (e.g. a manager requesting access where "managers" is the approver role),
	// letting them self-approve. Empty on lookup failure — the per-step guard
	// then simply doesn't exclude, matching prior behavior on error.
	var requesterID string
	_ = s.db.Pool.QueryRow(ctx,
		`SELECT requester_id FROM access_requests WHERE id = $1 AND org_id = $2`, requestID, org.ID,
	).Scan(&requesterID)

	// Try to find a matching policy (specific resource first, then generic)
	var stepsJSON, condJSON []byte
	err = s.db.Pool.QueryRow(ctx,
		`SELECT approval_steps, auto_approve_conditions FROM approval_policies
		 WHERE resource_type = $1 AND (resource_id = $2 OR resource_id IS NULL) AND enabled = true AND org_id = $3
		 ORDER BY resource_id NULLS LAST LIMIT 1`,
		resourceType, resourceID, org.ID,
	).Scan(&stepsJSON, &condJSON)
	if err != nil {
		// No matching policy — create a default admin approval
		adminID := "00000000-0000-0000-0000-000000000001"
		_, _ = s.db.Pool.Exec(ctx,
			`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at, org_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			uuid.New().String(), requestID, adminID, 1, "pending", time.Now(), org.ID,
		)
		return
	}

	// V-007: evaluate the policy's typed auto_approve_conditions before
	// creating approval rows. Fail-closed — only a fully-supported,
	// fully-held condition set short-circuits the manual approval chain.
	if len(condJSON) > 0 && string(condJSON) != "null" {
		var cond AutoApproveConditions
		if uerr := json.Unmarshal(condJSON, &cond); uerr != nil {
			s.logger.Warn("createApprovalRows: malformed auto_approve_conditions; ignoring",
				zap.String("request_id", requestID), zap.Error(uerr))
		} else if s.tryAutoApprove(ctx, requestID, &cond) {
			return
		}
	}

	var steps []ApprovalStep
	if err := json.Unmarshal(stepsJSON, &steps); err != nil || len(steps) == 0 {
		return
	}

	for i, step := range steps {
		// Handle different approval step types
		switch step.Type {
		case ApprovalStepTypeSpecificUser:
			if step.ApproverID != "" {
				_, _ = s.db.Pool.Exec(ctx,
					`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at, org_id)
					 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
					uuid.New().String(), requestID, step.ApproverID, step.Order, "pending", time.Now(), org.ID,
				)
			}
		case ApprovalStepTypeRole:
			if step.RoleID != "" {
				// Role membership lives in the user_roles join table — users has
				// no `roles` column, so the old `$1 = ANY(roles)` query errored on
				// every call, was swallowed, and created ZERO approver rows: a
				// role-based approval tier silently approved nothing (and a mixed
				// [user, role] policy auto-fulfilled once the user approved).
				// DISTINCT guards against a user holding the role via >1 grant.
				roleRows, err := s.db.Pool.Query(ctx,
					`SELECT DISTINCT user_id FROM user_roles WHERE role_id = $1 AND org_id = $2`, step.RoleID, org.ID,
				)
				if err != nil {
					s.logger.Error("Failed to query users by role", zap.Error(err), zap.String("role_id", step.RoleID))
				} else {
					defer roleRows.Close()
					for roleRows.Next() {
						var userID string
						if err := roleRows.Scan(&userID); err != nil {
							s.logger.Error("Failed to scan role user", zap.Error(err))
							continue
						}
						if userID == requesterID {
							continue // four-eyes: never make the requester their own approver
						}
						_, _ = s.db.Pool.Exec(ctx,
							`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at, org_id)
							 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
							uuid.New().String(), requestID, userID, step.Order, "pending", time.Now(), org.ID,
						)
					}
				}
			}
		case ApprovalStepTypeGroup:
			if step.GroupID != "" {
				groupRows, err := s.db.Pool.Query(ctx,
					`SELECT user_id FROM group_memberships WHERE group_id = $1 AND org_id = $2`, step.GroupID, org.ID,
				)
				if err != nil {
					s.logger.Error("Failed to query group members", zap.Error(err), zap.String("group_id", step.GroupID))
				} else {
					defer groupRows.Close()
					for groupRows.Next() {
						var userID string
						if err := groupRows.Scan(&userID); err != nil {
							s.logger.Error("Failed to scan group member", zap.Error(err))
							continue
						}
						if userID == requesterID {
							continue // four-eyes: never make the requester their own approver
						}
						_, _ = s.db.Pool.Exec(ctx,
							`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at, org_id)
							 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
							uuid.New().String(), requestID, userID, step.Order, "pending", time.Now(), org.ID,
						)
					}
				}
			}
		case ApprovalStepTypeManager:
			// Look up the requester's manager from the access request
			var requesterID string
			err := s.db.Pool.QueryRow(ctx,
				`SELECT requester_id FROM access_requests WHERE id = $1 AND org_id = $2`, requestID, org.ID,
			).Scan(&requesterID)
			if err != nil {
				s.logger.Error("Failed to get requester for manager approval", zap.Error(err))
			} else {
				var managerID *string
				err = s.db.Pool.QueryRow(ctx,
					`SELECT manager_id FROM users WHERE id = $1 AND org_id = $2`, requesterID, org.ID,
				).Scan(&managerID)
				if err != nil {
					s.logger.Error("Failed to get manager for requester", zap.Error(err), zap.String("requester_id", requesterID))
				} else if managerID != nil {
					_, _ = s.db.Pool.Exec(ctx,
						`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at, org_id)
						 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
						uuid.New().String(), requestID, *managerID, step.Order, "pending", time.Now(), org.ID,
					)
				}
			}
		case ApprovalStepTypeAuto:
			// Automatic approval - no human approver needed
			s.logger.Debug("Auto-approval step", zap.Int("step", i+1))
		default:
			s.logger.Warn("Unknown approval step type", zap.String("type", string(step.Type)))
		}
	}
}

// handleListAccessRequests lists access requests with optional filtering
func (s *Service) handleListAccessRequests(c *gin.Context) {
	status := c.Query("status")
	requesterID := c.Query("requester_id")

	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	// Handle "me" as requester_id
	if requesterID == "me" {
		requesterID = c.GetString("user_id")
		if requesterID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	baseQuery := `SELECT ar.id, ar.requester_id, COALESCE(NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), ''), u.username, ''),
		ar.resource_type, ar.resource_id, ar.resource_name, ar.justification,
		ar.status, ar.priority, ar.expires_at, ar.created_at, ar.updated_at
		FROM access_requests ar
		LEFT JOIN users u ON u.id = ar.requester_id AND u.org_id = ar.org_id`
	countQuery := `SELECT COUNT(*) FROM access_requests ar`

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("ar.org_id = $%d", argIdx))
	args = append(args, org.ID)
	argIdx++

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("ar.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if requesterID != "" {
		conditions = append(conditions, fmt.Sprintf("ar.requester_id = $%d", argIdx))
		args = append(args, requesterID)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				whereClause += " AND "
			}
			whereClause += cond
		}
	}

	var total int
	err = s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count access requests"})
		return
	}

	finalQuery := baseQuery + whereClause + " ORDER BY ar.created_at DESC"
	paginatedArgs := append([]interface{}{}, args...)
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		s.logger.Error("Failed to query access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query access requests"})
		return
	}
	defer rows.Close()

	requests := []AccessRequest{}
	for rows.Next() {
		var r AccessRequest
		var requesterName *string
		var expiresAt *time.Time
		if err := rows.Scan(&r.ID, &r.RequesterID, &requesterName,
			&r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Justification,
			&r.Status, &r.Priority, &expiresAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			s.logger.Error("Failed to scan access request", zap.Error(err))
			continue
		}
		if requesterName != nil {
			r.RequesterName = *requesterName
		}
		r.ExpiresAt = expiresAt
		requests = append(requests, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"requests": requests,
		"total":    total,
	})
}

// handleGetAccessRequest gets a single access request with its approvals
func (s *Service) handleGetAccessRequest(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var r AccessRequest
	var requesterName *string
	var expiresAt *time.Time

	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT ar.id, ar.requester_id, COALESCE(NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), ''), u.username, ''),
		 ar.resource_type, ar.resource_id, ar.resource_name, ar.justification,
		 ar.status, ar.priority, ar.expires_at, ar.created_at, ar.updated_at
		 FROM access_requests ar
		 LEFT JOIN users u ON u.id = ar.requester_id AND u.org_id = ar.org_id
		 WHERE ar.id = $1 AND ar.org_id = $2`, id, org.ID,
	).Scan(&r.ID, &r.RequesterID, &requesterName,
		&r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Justification,
		&r.Status, &r.Priority, &expiresAt, &r.CreatedAt, &r.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Access request not found"})
			return
		}
		s.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get access request"})
		return
	}
	if requesterName != nil {
		r.RequesterName = *requesterName
	}
	r.ExpiresAt = expiresAt

	// Fetch approvals
	approvalRows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT a.id, a.request_id, a.approver_id, COALESCE(NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), ''), u.username, ''), a.step_order, a.decision, a.comments, a.decided_at, a.created_at
		 FROM access_request_approvals a
		 LEFT JOIN users u ON u.id = a.approver_id AND u.org_id = a.org_id
		 WHERE a.request_id = $1 AND a.org_id = $2
		 ORDER BY a.step_order ASC`, id, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to query approvals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get approvals"})
		return
	}
	defer approvalRows.Close()

	var approvals []Approval
	for approvalRows.Next() {
		var a Approval
		var approverName *string
		var decidedAt *time.Time
		if err := approvalRows.Scan(&a.ID, &a.RequestID, &a.ApproverID, &approverName,
			&a.StepOrder, &a.Decision, &a.Comments, &decidedAt, &a.CreatedAt); err != nil {
			s.logger.Error("Failed to scan approval", zap.Error(err))
			continue
		}
		if approverName != nil {
			a.ApproverName = *approverName
		}
		a.DecidedAt = decidedAt
		approvals = append(approvals, a)
	}

	if approvals == nil {
		approvals = []Approval{}
	}
	r.Approvals = approvals

	c.JSON(http.StatusOK, r)
}

// handleApproveRequest approves an access request
func (s *Service) handleApproveRequest(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Comments string `json:"comments"`
	}
	_ = c.ShouldBindJSON(&body)

	approverID := c.GetString("user_id")
	if approverID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	now := time.Now()

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_request_approvals
		 SET decision = 'approved', comments = $1, decided_at = $2
		 WHERE request_id = $3 AND approver_id = $4 AND decision = 'pending' AND org_id = $5`,
		body.Comments, now, id, approverID, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to approve request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to approve request"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No pending approval found for this approver"})
		return
	}

	// Check if ALL approvals for this request are now approved
	var pendingCount int
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM access_request_approvals WHERE request_id = $1 AND decision = 'pending' AND org_id = $2`,
		id, org.ID,
	).Scan(&pendingCount)
	if err != nil {
		s.logger.Error("Failed to check pending approvals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check approval status"})
		return
	}

	if pendingCount == 0 {
		_, err = s.db.Pool.Exec(c.Request.Context(),
			`UPDATE access_requests SET status = 'approved', updated_at = $1 WHERE id = $2 AND org_id = $3`,
			time.Now(), id, org.ID,
		)
		if err != nil {
			s.logger.Error("Failed to update request status", zap.Error(err))
		}

		var request AccessRequest
		err = s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT id, requester_id, resource_type, resource_id, resource_name, status FROM access_requests WHERE id = $1 AND org_id = $2`, id, org.ID,
		).Scan(&request.ID, &request.RequesterID, &request.ResourceType, &request.ResourceID, &request.ResourceName, &request.Status)
		if err == nil {
			if fulfillErr := s.fulfillRequest(c.Request.Context(), &request); fulfillErr != nil {
				s.logger.Error("Failed to fulfill approved request", zap.Error(fulfillErr))
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Request approved successfully"})
}

// handleDenyRequest denies an access request
func (s *Service) handleDenyRequest(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Comments string `json:"comments"`
	}
	_ = c.ShouldBindJSON(&body)

	approverID := c.GetString("user_id")
	if approverID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	now := time.Now()

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_request_approvals
		 SET decision = 'denied', comments = $1, decided_at = $2
		 WHERE request_id = $3 AND approver_id = $4 AND decision = 'pending' AND org_id = $5`,
		body.Comments, now, id, approverID, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to deny request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deny request"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No pending approval found for this approver"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_requests SET status = 'denied', updated_at = $1 WHERE id = $2 AND org_id = $3`,
		time.Now(), id, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to update request status to denied", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{"message": "Request denied"})
}

// handleCancelRequest allows the requester to cancel their own access request
func (s *Service) handleCancelRequest(c *gin.Context) {
	id := c.Param("id")

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var requesterID, status string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT requester_id, status FROM access_requests WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&requesterID, &status)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Access request not found"})
			return
		}
		s.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel request"})
		return
	}

	if requesterID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only the requester can cancel this request"})
		return
	}

	if status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Cannot cancel request with status: %s", status)})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_requests SET status = 'cancelled', updated_at = $1 WHERE id = $2 AND org_id = $3`,
		time.Now(), id, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to cancel request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Request cancelled"})
}

// handleListPendingApprovals returns pending approvals for the current user
func (s *Service) handleListPendingApprovals(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT ar.id, ar.requester_id, COALESCE(NULLIF(TRIM(CONCAT(ru.first_name, ' ', ru.last_name)), ''), ru.username, ''),
		        ar.resource_type, ar.resource_id, ar.resource_name, ar.justification,
		        ar.status, ar.priority, ar.created_at, ar.updated_at
		 FROM access_request_approvals a
		 JOIN access_requests ar ON ar.id = a.request_id AND ar.org_id = a.org_id
		 LEFT JOIN users ru ON ru.id = ar.requester_id AND ru.org_id = ar.org_id
		 WHERE a.approver_id = $1 AND a.decision = 'pending' AND a.org_id = $2
		 ORDER BY ar.created_at DESC`, userID, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to query pending approvals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list pending approvals"})
		return
	}
	defer rows.Close()

	var results []AccessRequest
	for rows.Next() {
		var r AccessRequest
		var requesterName *string
		if err := rows.Scan(
			&r.ID, &r.RequesterID, &requesterName,
			&r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Justification,
			&r.Status, &r.Priority,
			&r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			s.logger.Error("Failed to scan pending approval", zap.Error(err))
			continue
		}
		if requesterName != nil {
			r.RequesterName = *requesterName
		}
		results = append(results, r)
	}

	if results == nil {
		results = []AccessRequest{}
	}

	c.JSON(http.StatusOK, gin.H{"pending_approvals": results})
}

// handleListApprovalPolicies returns all approval policies
func (s *Service) handleListApprovalPolicies(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, resource_type, resource_id, approval_steps, auto_approve_conditions, max_wait_hours, enabled, created_at, updated_at
		 FROM approval_policies
		 WHERE org_id = $1
		 ORDER BY created_at DESC`, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to query approval policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list approval policies"})
		return
	}
	defer rows.Close()

	var policies []ApprovalPolicy
	for rows.Next() {
		var p ApprovalPolicy
		var resourceID *string
		var stepsJSON, autoApproveJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.ResourceType, &resourceID,
			&stepsJSON, &autoApproveJSON, &p.MaxWaitHours, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("Failed to scan approval policy", zap.Error(err))
			continue
		}
		p.ResourceID = resourceID
		if stepsJSON != nil {
			_ = json.Unmarshal(stepsJSON, &p.ApprovalSteps)
		}
		if p.ApprovalSteps == nil {
			p.ApprovalSteps = []ApprovalStep{}
		}
		if autoApproveJSON != nil {
			_ = json.Unmarshal(autoApproveJSON, &p.AutoApproveConditions)
		}
		policies = append(policies, p)
	}

	if policies == nil {
		policies = []ApprovalPolicy{}
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// handleCreateApprovalPolicy creates a new approval policy
func (s *Service) handleCreateApprovalPolicy(c *gin.Context) {
	var body struct {
		Name                  string                 `json:"name"`
		ResourceType          string                 `json:"resource_type"`
		ResourceID            *string                `json:"resource_id,omitempty"`
		ApprovalSteps         []ApprovalStep         `json:"approval_steps"`
		AutoApproveConditions *AutoApproveConditions `json:"auto_approve_conditions,omitempty"`
		MaxWaitHours          int                    `json:"max_wait_hours"`
		Enabled               bool                   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.Name == "" || body.ResourceType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and resource_type are required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	stepsJSON, err := json.Marshal(body.ApprovalSteps)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval_steps"})
		return
	}

	var autoApproveJSON []byte
	if body.AutoApproveConditions != nil {
		autoApproveJSON, err = json.Marshal(body.AutoApproveConditions)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid auto_approve_conditions"})
			return
		}
	}

	id := uuid.New().String()
	now := time.Now()

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO approval_policies (id, name, resource_type, resource_id, approval_steps, auto_approve_conditions, max_wait_hours, enabled, created_at, updated_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, body.Name, body.ResourceType, body.ResourceID, stepsJSON, autoApproveJSON,
		body.MaxWaitHours, body.Enabled, now, now, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to create approval policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create approval policy"})
		return
	}

	c.JSON(http.StatusCreated, ApprovalPolicy{
		ID:                    id,
		Name:                  body.Name,
		ResourceType:          body.ResourceType,
		ResourceID:            body.ResourceID,
		ApprovalSteps:         body.ApprovalSteps,
		AutoApproveConditions: body.AutoApproveConditions,
		MaxWaitHours:          body.MaxWaitHours,
		Enabled:               body.Enabled,
		CreatedAt:             now,
		UpdatedAt:             now,
	})
}

// handleUpdateApprovalPolicy updates an existing approval policy
func (s *Service) handleUpdateApprovalPolicy(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Name                  string                 `json:"name"`
		ResourceType          string                 `json:"resource_type"`
		ResourceID            *string                `json:"resource_id,omitempty"`
		ApprovalSteps         []ApprovalStep         `json:"approval_steps"`
		AutoApproveConditions *AutoApproveConditions `json:"auto_approve_conditions,omitempty"`
		MaxWaitHours          int                    `json:"max_wait_hours"`
		Enabled               bool                   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	stepsJSON, err := json.Marshal(body.ApprovalSteps)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval_steps"})
		return
	}

	var autoApproveJSON []byte
	if body.AutoApproveConditions != nil {
		autoApproveJSON, err = json.Marshal(body.AutoApproveConditions)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid auto_approve_conditions"})
			return
		}
	}

	now := time.Now()
	result, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE approval_policies
		 SET name = $1, resource_type = $2, resource_id = $3, approval_steps = $4,
		     auto_approve_conditions = $5, max_wait_hours = $6, enabled = $7, updated_at = $8
		 WHERE id = $9 AND org_id = $10`,
		body.Name, body.ResourceType, body.ResourceID, stepsJSON,
		autoApproveJSON, body.MaxWaitHours, body.Enabled, now, id, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to update approval policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update approval policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Approval policy not found"})
		return
	}

	c.JSON(http.StatusOK, ApprovalPolicy{
		ID:                    id,
		Name:                  body.Name,
		ResourceType:          body.ResourceType,
		ResourceID:            body.ResourceID,
		ApprovalSteps:         body.ApprovalSteps,
		AutoApproveConditions: body.AutoApproveConditions,
		MaxWaitHours:          body.MaxWaitHours,
		Enabled:               body.Enabled,
		UpdatedAt:             now,
	})
}

// handleDeleteApprovalPolicy deletes an approval policy
func (s *Service) handleDeleteApprovalPolicy(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM approval_policies WHERE id = $1 AND org_id = $2`, id, org.ID,
	)
	if err != nil {
		s.logger.Error("Failed to delete approval policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete approval policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Approval policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Approval policy deleted"})
}

// SoDViolationError signals that fulfilling a role request would create a
// separation-of-duty conflict with the requester's existing roles.
type SoDViolationError struct{ PolicyName string }

func (e *SoDViolationError) Error() string {
	return fmt.Sprintf("separation-of-duty violation: role conflicts with existing roles under policy %q", e.PolicyName)
}

// checkSoDForRoleGrant fails closed if granting targetRoleID to userID would
// violate any enabled separation-of-duty policy, given the roles the user
// already holds. It reuses the canonical governance SoD evaluator
// (evaluateSoDPolicy) so the access-request fulfillment path enforces the same
// rule as the direct role-update path — closing the back door where a user
// could obtain a conflicting role by requesting it instead of being assigned it.
func (s *Service) checkSoDForRoleGrant(ctx context.Context, userID, targetRoleID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Role names the user would hold after the grant: current (non-expired) + target.
	roleNames := []interface{}{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.name FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.org_id = $2 AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`, userID, org.ID)
	if err != nil {
		return fmt.Errorf("load current roles for SoD check: %w", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan current role for SoD check: %w", err)
		}
		roleNames = append(roleNames, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate current roles for SoD check: %w", err)
	}

	var targetName string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT name FROM roles WHERE id = $1 AND org_id = $2`, targetRoleID, org.ID).Scan(&targetName); err != nil {
		return fmt.Errorf("load target role for SoD check: %w", err)
	}
	roleNames = append(roleNames, targetName)

	request := map[string]interface{}{"roles": roleNames}

	// Evaluate every enabled SoD policy; any violation blocks the grant.
	rows, err = s.db.Pool.Query(ctx,
		`SELECT id FROM policies WHERE enabled = true AND type = $1 AND org_id = $2`, string(PolicyTypeSoD), org.ID)
	if err != nil {
		return fmt.Errorf("load SoD policies for check: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan SoD policy id: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate SoD policies: %w", err)
	}

	for _, pid := range ids {
		policy, err := s.GetPolicy(ctx, pid)
		if err != nil {
			return fmt.Errorf("load SoD policy %s: %w", pid, err)
		}
		allowed, err := s.evaluateSoDPolicy(ctx, policy, request)
		if err != nil {
			return fmt.Errorf("evaluate SoD policy %s: %w", pid, err)
		}
		if !allowed {
			return &SoDViolationError{PolicyName: policy.Name}
		}
	}
	return nil
}

// fulfillRequest provisions the approved access by granting the requested resource
// to the requester. The supported resource types are exactly the three that
// access requests can be raised against: role, group, and application. An
// unknown resource type is a hard error rather than a silent "marked
// fulfilled but nothing granted" — the previous warning-only no-op path
// shipped approved-but-empty requests to production (the P1.1 gap the
// roadmap called out).
func (s *Service) fulfillRequest(ctx context.Context, request *AccessRequest) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	switch request.ResourceType {
	case "role":
		// SoD gate: fulfilling an access request must not hand a user a role that
		// conflicts with one they already hold. Without this, the request workflow
		// is a back door around the direct role-update SoD check (a user requests
		// the conflicting role instead of being assigned it).
		if err := s.checkSoDForRoleGrant(ctx, request.RequesterID, request.ResourceID); err != nil {
			return err
		}
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			request.RequesterID, request.ResourceID, org.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to assign role: %w", err)
		}
	case "group":
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			request.RequesterID, request.ResourceID, org.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to add to group: %w", err)
		}
	case "application":
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			request.RequesterID, request.ResourceID, org.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to assign application: %w", err)
		}
	case "vault_credential":
		if s.vaultSvc == nil {
			return fmt.Errorf("vault service not configured; cannot fulfill vault_credential request %s", request.ID)
		}
		if request.ExpiresAt == nil {
			return fmt.Errorf("vault_credential request %s has no expires_at (unbounded checkout)", request.ID)
		}
		// Time-boxed reveal grant IS the authorization to retrieve; it auto-expires
		// with the checkout window (vault hasGrant checks expires_at > NOW()).
		if _, err := s.vaultSvc.AddGrant(ctx, vault.Grant{
			SecretID:      request.ResourceID,
			PrincipalType: "user",
			PrincipalID:   request.RequesterID,
			Actions:       []string{"reveal"},
			ExpiresAt:     request.ExpiresAt,
			GrantedBy:     "", // system fulfillment
		}); err != nil {
			return fmt.Errorf("grant vault reveal for request %s: %w", request.ID, err)
		}
		// Best-effort audit; the grant itself already succeeded.
		auditDetails, _ := json.Marshal(map[string]any{
			"request_id": request.ID, "secret_id": request.ResourceID, "expires_at": request.ExpiresAt,
		})
		if _, err := s.db.Pool.Exec(ctx,
			`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
			 VALUES (gen_random_uuid(), 'access', 'provisioning', 'jit_credential.checkout_granted', 'success', $1, '0.0.0.0', $2, 'vault_credential', $3, NOW(), $4)`,
			request.RequesterID, request.ResourceID, string(auditDetails), org.ID); err != nil {
			// The column was `ip_address`, which does not exist on audit_events
			// (the real column is actor_ip), so this INSERT silently failed and the
			// checkout was never audited. Log the error now so any future breakage
			// is visible instead of lost.
			s.logger.Warn("Failed to write jit_credential.checkout_granted audit event",
				zap.String("request_id", request.ID), zap.Error(err))
		}
	case "network_service":
		// JIT network grant (Wave B1): fulfilling a network_service request adds
		// a time-bound Ziti role attribute (jit-<request-id>) to the requester's
		// identity, which a service policy binds to open the dial. Governance has
		// no Ziti access, so hand off to the access-service worker. The grant
		// itself is the fulfillment; the attribute apply is async + best-effort.
		attr := jitNetworkAttribute(request.ID)
		s.enqueueNetworkGrant(ctx, request.RequesterID, org.ID, request.ID, attr, request.ExpiresAt)
		grantDetails, _ := json.Marshal(map[string]any{
			"request_id": request.ID, "resource_id": request.ResourceID,
			"attribute": attr, "expires_at": request.ExpiresAt,
		})
		if _, err := s.db.Pool.Exec(ctx,
			`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
			 VALUES (gen_random_uuid(), 'access', 'provisioning', 'jit_network.grant_issued', 'success', $1, '0.0.0.0', $2, 'network_service', $3, NOW(), $4)`,
			request.RequesterID, request.ResourceID, string(grantDetails), org.ID); err != nil {
			s.logger.Warn("Failed to write jit_network.grant_issued audit event",
				zap.String("request_id", request.ID), zap.Error(err))
		}
	default:
		// Fail loudly. Marking a request "fulfilled" without granting
		// anything is exactly the bug the P1.1 audit found — an approved
		// application request used to land here and silently no-op.
		return fmt.Errorf("unsupported access-request resource type %q", request.ResourceType)
	}

	_, err = s.db.Pool.Exec(ctx,
		`UPDATE access_requests SET status = 'fulfilled', updated_at = $1 WHERE id = $2 AND org_id = $3`,
		time.Now(), request.ID, org.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update request status to fulfilled: %w", err)
	}

	// Audit the grant so the access trail isn't lost to whoever investigates
	// later. Keep it best-effort — the grant itself already succeeded.
	s.logger.Info("Access request fulfilled",
		zap.String("request_id", request.ID),
		zap.String("requester_id", request.RequesterID),
		zap.String("resource_type", request.ResourceType),
		zap.String("resource_id", request.ResourceID),
	)

	request.Status = "fulfilled"
	return nil
}

// handleRetrieveCredential reveals the plaintext of a checked-out vault credential
// to the requester for the duration of the approved checkout window.
func (s *Service) handleRetrieveCredential(c *gin.Context) {
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "vault not configured"})
		return
	}
	reqID := c.Param("id")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var resourceType, resourceID, status, requester string
	var expiresAt *time.Time
	err = s.db.Pool.QueryRow(ctx,
		`SELECT resource_type, resource_id, status, requester_id, expires_at
		 FROM access_requests WHERE id=$1 AND org_id=$2`, reqID, org.ID).
		Scan(&resourceType, &resourceID, &status, &requester, &expiresAt)
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load request"})
		return
	}
	if resourceType != "vault_credential" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not a vault_credential request"})
		return
	}
	if requester != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not your request"})
		return
	}
	if status != "fulfilled" {
		c.JSON(http.StatusConflict, gin.H{"error": "request not approved/fulfilled"})
		return
	}
	if expiresAt == nil || time.Now().After(*expiresAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "checkout window expired"})
		return
	}
	// Roles are not set by the governance middleware; the vault grant (added during
	// fulfillRequest) is the authorisation — Reveal checks it via hasGrant.
	pt, err := s.vaultSvc.Reveal(ctx, resourceID, userID, nil, "JIT checkout "+reqID, false)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "reveal denied"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"value": string(pt)})
	for i := range pt { // zero plaintext after write to avoid retaining it in heap
		pt[i] = 0
	}
}

// bumpRotationOnReturn wakes the M1b rotation scheduler for a secret whose policy is
// rotate_on_checkout, so the credential rotates when the checkout concludes.
func (s *Service) bumpRotationOnReturn(ctx context.Context, secretID string) {
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE credential_rotation_policies SET next_run_at = NOW()
		 WHERE secret_id = $1 AND rotate_on_checkout = true`, secretID); err != nil {
		s.logger.Warn("bump rotation on return failed", zap.String("secret_id", secretID), zap.Error(err))
	}
}

// handleReturnCredential allows the requester to return a checked-out credential
// early: revokes the vault grant immediately, marks the request expired, and
// triggers rotation if the policy is rotate_on_checkout.
func (s *Service) handleReturnCredential(c *gin.Context) {
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "vault not configured"})
		return
	}
	reqID := c.Param("id")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var resourceType, resourceID, requester, status string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT resource_type, resource_id, requester_id, status FROM access_requests WHERE id=$1 AND org_id=$2`, reqID, org.ID).
		Scan(&resourceType, &resourceID, &requester, &status)
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load request"})
		return
	}
	if resourceType != "vault_credential" || requester != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not your vault_credential request"})
		return
	}
	if status != "fulfilled" {
		c.JSON(http.StatusConflict, gin.H{"error": "credential not currently checked out"})
		return
	}
	// Immediate deauthorization + mark expired + rotate-on-return.
	if err := s.vaultSvc.RevokeGrantForPrincipal(ctx, resourceID, "user", userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke grant"})
		return
	}
	_, _ = s.db.Pool.Exec(ctx,
		`UPDATE access_requests SET status='expired', updated_at=NOW() WHERE id=$1 AND org_id=$2`, reqID, org.ID)
	s.bumpRotationOnReturn(ctx, resourceID)
	// Best-effort audit.
	retDetails, _ := json.Marshal(map[string]any{"request_id": reqID, "secret_id": resourceID})
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
		 VALUES (gen_random_uuid(), 'access', 'provisioning', 'jit_credential.checkout_returned', 'success', $1, '0.0.0.0', $2, 'vault_credential', $3, NOW(), $4)`,
		userID, resourceID, string(retDetails), org.ID); err != nil {
		s.logger.Warn("Failed to write jit_credential.checkout_returned audit event",
			zap.String("request_id", sanitizeForLog(reqID)), zap.Error(err))
	}
	c.JSON(http.StatusOK, gin.H{"status": "returned"})
}
