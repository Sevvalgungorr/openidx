package admin

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// UserConsent represents a user's consent record for privacy compliance
type UserConsent struct {
	ID          string          `json:"id"`
	UserID      string          `json:"user_id"`
	ConsentType string          `json:"consent_type"`
	Version     string          `json:"version"`
	Granted     bool            `json:"granted"`
	IPAddress   *string         `json:"ip_address"`
	UserAgent   *string         `json:"user_agent"`
	Metadata    json.RawMessage `json:"metadata"`
	GrantedAt   *time.Time      `json:"granted_at"`
	RevokedAt   *time.Time      `json:"revoked_at"`
	ExpiresAt   *time.Time      `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

// DataSubjectRequest represents a GDPR/CCPA data subject access request
type DataSubjectRequest struct {
	ID                      string          `json:"id"`
	UserID                  string          `json:"user_id"`
	RequestType             string          `json:"request_type"` // export, delete, restrict
	Status                  string          `json:"status"`       // pending, in_progress, completed, rejected
	Reason                  string          `json:"reason"`
	RequestedDataCategories json.RawMessage `json:"requested_data_categories"`
	ResultFilePath          *string         `json:"result_file_path"`
	ResultFileSize          *int64          `json:"result_file_size"`
	ProcessedBy             *string         `json:"processed_by"`
	Notes                   string          `json:"notes"`
	DueDate                 *time.Time      `json:"due_date"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	CompletedAt             *time.Time      `json:"completed_at"`
}

// PrivacyRetentionPolicy defines data retention rules for privacy compliance
type PrivacyRetentionPolicy struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	DataCategory    string          `json:"data_category"`
	RetentionDays   int             `json:"retention_days"`
	Action          string          `json:"action"` // delete, anonymize
	AnonymizeFields json.RawMessage `json:"anonymize_fields"`
	Enabled         bool            `json:"enabled"`
	LastExecutedAt  *time.Time      `json:"last_executed_at"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// PrivacyAssessment represents a privacy impact assessment (PIA/DPIA)
type PrivacyAssessment struct {
	ID                 string          `json:"id"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	DataCategories     json.RawMessage `json:"data_categories"`
	ProcessingPurposes json.RawMessage `json:"processing_purposes"`
	RiskLevel          string          `json:"risk_level"` // low, medium, high, critical
	Status             string          `json:"status"`     // draft, in_review, approved, rejected
	Findings           json.RawMessage `json:"findings"`
	Mitigations        json.RawMessage `json:"mitigations"`
	AssessorID         *string         `json:"assessor_id"`
	ReviewerID         *string         `json:"reviewer_id"`
	ReviewNotes        string          `json:"review_notes"`
	ApprovedAt         *time.Time      `json:"approved_at"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// handlePrivacyDashboard returns aggregated privacy compliance statistics
func (s *Service) handlePrivacyDashboard(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var totalConsents, activeDSARs, overdueDSARs, totalAssessments int

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_consents WHERE granted = true AND org_id = $1`, org.ID).Scan(&totalConsents)
	if err != nil {
		s.logger.Error("Failed to count consents", zap.Error(err))
		totalConsents = 0
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM data_subject_requests WHERE status IN ('pending', 'in_progress') AND org_id = $1`, org.ID).Scan(&activeDSARs)
	if err != nil {
		s.logger.Error("Failed to count active DSARs", zap.Error(err))
		activeDSARs = 0
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM data_subject_requests WHERE status = 'pending' AND due_date < NOW() AND org_id = $1`, org.ID).Scan(&overdueDSARs)
	if err != nil {
		s.logger.Error("Failed to count overdue DSARs", zap.Error(err))
		overdueDSARs = 0
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM privacy_assessments WHERE org_id = $1`, org.ID).Scan(&totalAssessments)
	if err != nil {
		s.logger.Error("Failed to count assessments", zap.Error(err))
		totalAssessments = 0
	}

	// Consent breakdown by type
	type consentBreakdown struct {
		ConsentType string `json:"consent_type"`
		Granted     int    `json:"granted"`
		Revoked     int    `json:"revoked"`
	}
	var breakdown []consentBreakdown
	rows, err := s.db.Pool.Query(ctx,
		`SELECT consent_type,
			SUM(CASE WHEN granted = true THEN 1 ELSE 0 END) AS granted,
			SUM(CASE WHEN granted = false THEN 1 ELSE 0 END) AS revoked
		 FROM user_consents WHERE org_id = $1 GROUP BY consent_type`, org.ID)
	if err != nil {
		s.logger.Error("Failed to query consent breakdown", zap.Error(err))
	} else {
		defer rows.Close()
		for rows.Next() {
			var cb consentBreakdown
			if err := rows.Scan(&cb.ConsentType, &cb.Granted, &cb.Revoked); err != nil {
				continue
			}
			breakdown = append(breakdown, cb)
		}
	}
	if breakdown == nil {
		breakdown = []consentBreakdown{}
	}

	// Recent DSARs with user info
	type recentDSAR struct {
		ID          string    `json:"id"`
		UserID      string    `json:"user_id"`
		Username    string    `json:"username"`
		RequestType string    `json:"request_type"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
	}
	var recentDSARs []recentDSAR
	dsarRows, err := s.db.Pool.Query(ctx,
		`SELECT d.id, d.user_id, COALESCE(u.username, ''), d.request_type, d.status, d.created_at
		 FROM data_subject_requests d
		 LEFT JOIN users u ON d.user_id = u.id AND u.org_id = d.org_id
		 WHERE d.org_id = $1
		 ORDER BY d.created_at DESC LIMIT 5`, org.ID)
	if err != nil {
		s.logger.Error("Failed to query recent DSARs", zap.Error(err))
	} else {
		defer dsarRows.Close()
		for dsarRows.Next() {
			var rd recentDSAR
			if err := dsarRows.Scan(&rd.ID, &rd.UserID, &rd.Username, &rd.RequestType, &rd.Status, &rd.CreatedAt); err != nil {
				continue
			}
			recentDSARs = append(recentDSARs, rd)
		}
	}
	if recentDSARs == nil {
		recentDSARs = []recentDSAR{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_consents":    totalConsents,
		"active_dsars":      activeDSARs,
		"overdue_dsars":     overdueDSARs,
		"total_assessments": totalAssessments,
		"consent_breakdown": breakdown,
		"recent_dsars":      recentDSARs,
	})
}

// handleListConsents lists user consent records with optional filtering
func (s *Service) handleListConsents(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	consentType := c.Query("consent_type")
	userID := c.Query("user_id")

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

	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	baseQuery := `SELECT uc.id, uc.user_id, COALESCE(u.username, ''), uc.consent_type, uc.version,
		uc.granted, uc.ip_address, uc.user_agent, uc.metadata,
		uc.granted_at, uc.revoked_at, uc.expires_at, uc.created_at
		FROM user_consents uc LEFT JOIN users u ON uc.user_id = u.id AND u.org_id = uc.org_id`
	countQuery := `SELECT COUNT(*) FROM user_consents uc`

	conditions := []string{"uc.org_id = $1"}
	args := []interface{}{org.ID}
	argIdx := 2

	if consentType != "" {
		conditions = append(conditions, fmt.Sprintf("uc.consent_type = $%d", argIdx))
		args = append(args, consentType)
		argIdx++
	}
	if userID != "" {
		conditions = append(conditions, fmt.Sprintf("uc.user_id = $%d", argIdx))
		args = append(args, userID)
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
	err := s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to count consents", err))
		return
	}

	paginatedArgs := append([]interface{}{}, args...)
	finalQuery := baseQuery + whereClause + " ORDER BY uc.created_at DESC"
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to query consents", err))
		return
	}
	defer rows.Close()

	type consentWithUser struct {
		UserConsent
		Username string `json:"username"`
	}
	var consents []consentWithUser
	for rows.Next() {
		var cu consentWithUser
		if err := rows.Scan(&cu.ID, &cu.UserID, &cu.Username, &cu.ConsentType, &cu.Version,
			&cu.Granted, &cu.IPAddress, &cu.UserAgent, &cu.Metadata,
			&cu.GrantedAt, &cu.RevokedAt, &cu.ExpiresAt, &cu.CreatedAt); err != nil {
			s.logger.Error("Failed to scan consent row", zap.Error(err))
			continue
		}
		consents = append(consents, cu)
	}
	if consents == nil {
		consents = []consentWithUser{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  consents,
		"total": total,
	})
}

// handleConsentStats returns consent statistics grouped by type
func (s *Service) handleConsentStats(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT consent_type,
			SUM(CASE WHEN granted = true THEN 1 ELSE 0 END) AS granted,
			SUM(CASE WHEN granted = false THEN 1 ELSE 0 END) AS revoked
		 FROM user_consents WHERE org_id = $1 GROUP BY consent_type ORDER BY consent_type`, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to query consent stats", err))
		return
	}
	defer rows.Close()

	type stat struct {
		ConsentType string `json:"consent_type"`
		Granted     int    `json:"granted"`
		Revoked     int    `json:"revoked"`
	}
	var stats []stat
	for rows.Next() {
		var s stat
		if err := rows.Scan(&s.ConsentType, &s.Granted, &s.Revoked); err != nil {
			continue
		}
		stats = append(stats, s)
	}
	if stats == nil {
		stats = []stat{}
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}

// handleListDSARs lists data subject access requests with optional status filtering
func (s *Service) handleListDSARs(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	status := c.Query("status")

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

	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	baseQuery := `SELECT d.id, d.user_id, COALESCE(u.username, ''), d.request_type, d.status,
		COALESCE(d.reason, ''), d.requested_data_categories, d.result_file_path, d.result_file_size,
		d.processed_by, COALESCE(d.notes, ''), d.due_date, d.created_at, d.updated_at, d.completed_at
		FROM data_subject_requests d LEFT JOIN users u ON d.user_id = u.id AND u.org_id = d.org_id`
	countQuery := `SELECT COUNT(*) FROM data_subject_requests d`

	conditions := []string{"d.org_id = $1"}
	args := []interface{}{org.ID}
	argIdx := 2

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("d.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}

	whereClause := " WHERE "
	for i, cond := range conditions {
		if i > 0 {
			whereClause += " AND "
		}
		whereClause += cond
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to count DSARs", err))
		return
	}

	paginatedArgs := append([]interface{}{}, args...)
	finalQuery := baseQuery + whereClause + " ORDER BY d.created_at DESC"
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to query DSARs", err))
		return
	}
	defer rows.Close()

	type dsarWithUser struct {
		DataSubjectRequest
		Username string `json:"username"`
	}
	var dsars []dsarWithUser
	for rows.Next() {
		var d dsarWithUser
		if err := rows.Scan(&d.ID, &d.UserID, &d.Username, &d.RequestType, &d.Status,
			&d.Reason, &d.RequestedDataCategories, &d.ResultFilePath, &d.ResultFileSize,
			&d.ProcessedBy, &d.Notes, &d.DueDate, &d.CreatedAt, &d.UpdatedAt, &d.CompletedAt); err != nil {
			s.logger.Error("Failed to scan DSAR row", zap.Error(err))
			continue
		}
		dsars = append(dsars, d)
	}
	if dsars == nil {
		dsars = []dsarWithUser{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  dsars,
		"total": total,
	})
}

// handleCreateDSAR creates a new data subject access request
func (s *Service) handleCreateDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		UserID                  string          `json:"user_id"`
		RequestType             string          `json:"request_type"`
		Reason                  string          `json:"reason"`
		RequestedDataCategories json.RawMessage `json:"requested_data_categories"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.UserID == "" || req.RequestType == "" {
		respondError(c, nil, apperrors.BadRequest("user_id and request_type are required"))
		return
	}

	// user_id is a uuid column. A non-UUID value (the create form is a free-text
	// "Enter user ID" field, so an operator can type a username or a partial id)
	// would otherwise reach Postgres and raise an invalid-uuid error that surfaces
	// as a confusing 500. Reject it up front with a clear 400.
	if _, uerr := uuid.Parse(req.UserID); uerr != nil {
		respondError(c, nil, apperrors.BadRequest("user_id must be a valid user ID (UUID)"))
		return
	}

	validTypes := map[string]bool{"export": true, "delete": true, "restrict": true}
	if !validTypes[req.RequestType] {
		respondError(c, nil, apperrors.BadRequest("request_type must be export, delete, or restrict"))
		return
	}

	categories := req.RequestedDataCategories
	if categories == nil {
		categories = json.RawMessage("[]")
	}

	dueDate := time.Now().Add(30 * 24 * time.Hour)

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO data_subject_requests (user_id, request_type, reason, requested_data_categories, due_date, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.UserID, req.RequestType, req.Reason, categories, dueDate, org.ID,
	).Scan(&id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create DSAR", err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending", "due_date": dueDate})
}

// handleGetDSAR retrieves a single data subject access request by ID
func (s *Service) handleGetDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	type dsarDetail struct {
		DataSubjectRequest
		Username      string `json:"username"`
		ProcessedName string `json:"processed_by_name"`
	}
	var d dsarDetail
	err := s.db.Pool.QueryRow(ctx,
		`SELECT d.id, d.user_id, COALESCE(u.username, ''), d.request_type, d.status,
			COALESCE(d.reason, ''), d.requested_data_categories, d.result_file_path, d.result_file_size,
			d.processed_by, COALESCE(p.username, ''), COALESCE(d.notes, ''), d.due_date,
			d.created_at, d.updated_at, d.completed_at
		 FROM data_subject_requests d
		 LEFT JOIN users u ON d.user_id = u.id AND u.org_id = d.org_id
		 LEFT JOIN users p ON d.processed_by = p.id AND p.org_id = d.org_id
		 WHERE d.id = $1 AND d.org_id = $2`, id, org.ID,
	).Scan(&d.ID, &d.UserID, &d.Username, &d.RequestType, &d.Status,
		&d.Reason, &d.RequestedDataCategories, &d.ResultFilePath, &d.ResultFileSize,
		&d.ProcessedBy, &d.ProcessedName, &d.Notes, &d.DueDate,
		&d.CreatedAt, &d.UpdatedAt, &d.CompletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, nil, apperrors.NotFound("DSAR"))
			return
		}
		// A scan failure here (e.g. a NULL into a non-nullable field) is a server
		// bug, not a missing record — surface it instead of masking as 404.
		respondError(c, s.logger, apperrors.Internal("Failed to load DSAR", err))
		return
	}

	c.JSON(http.StatusOK, d)
}

// handleUpdateDSAR updates a data subject access request status and notes
func (s *Service) handleUpdateDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var req struct {
		Status *string `json:"status"`
		Notes  *string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *req.Status)
		argIdx++

		if *req.Status == "completed" {
			sets = append(sets, fmt.Sprintf("completed_at = $%d", argIdx))
			args = append(args, time.Now())
			argIdx++
		}
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes = $%d", argIdx))
		args = append(args, *req.Notes)
		argIdx++
	}

	if userIDStr != "" {
		sets = append(sets, fmt.Sprintf("processed_by = $%d", argIdx))
		args = append(args, userIDStr)
		argIdx++
	}

	sets = append(sets, "updated_at = NOW()")

	if len(sets) <= 1 {
		respondError(c, nil, apperrors.BadRequest("No fields to update"))
		return
	}

	args = append(args, id)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE data_subject_requests SET %s WHERE id = $%d AND org_id = $%d", joinSetClauses(sets), argIdx, argIdx+1)
	args = append(args, org.ID)

	result, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update DSAR", err))
		return
	}
	if result.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("DSAR"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "DSAR updated"})
}

// handleExecuteDSAR executes a data subject access request (export or delete)
func (s *Service) handleExecuteDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var dsar DataSubjectRequest
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, request_type, status FROM data_subject_requests WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&dsar.ID, &dsar.UserID, &dsar.RequestType, &dsar.Status)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("DSAR"))
		return
	}

	if dsar.Status == "completed" {
		respondError(c, nil, apperrors.BadRequest("DSAR is already completed"))
		return
	}

	actorID, _ := c.Get("user_id")
	actorIDStr, _ := actorID.(string)

	result, err := s.ExecuteDSAR(ctx, &dsar, actorIDStr)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal(err.Error(), err))
		return
	}
	c.JSON(http.StatusOK, result)
}

// ExecuteDSAR routes a DSAR to its type-specific executor and persists the
// completion record. Broken out from the HTTP handler so the same logic can be
// driven by the background processor (next PR) and exercised by unit tests
// without going through gin. The actorID is the admin (or scheduler) that
// triggered execution; it lands in data_subject_requests.processed_by.
func (s *Service) ExecuteDSAR(ctx context.Context, dsar *DataSubjectRequest, actorID string) (map[string]interface{}, error) {
	switch dsar.RequestType {
	case "export":
		return s.executeDSARExport(ctx, dsar, actorID)
	case "delete":
		return s.executeDSARDelete(ctx, dsar, actorID)
	case "restrict":
		return s.executeDSARRestrict(ctx, dsar, actorID)
	default:
		return nil, fmt.Errorf("unsupported DSAR request_type %q", dsar.RequestType)
	}
}

// executeDSARExport gathers the subject's PII across every table that holds
// any and writes a gzip'd JSON bundle. The category set covers every
// user-keyed table reachable from internal/identity and the OAuth flows;
// extending the export when new PII surfaces are added is a one-line entry
// in `categories` below.
func (s *Service) executeDSARExport(ctx context.Context, dsar *DataSubjectRequest, actorID string) (map[string]interface{}, error) {
	// This executor is also driven by the background DSAR processor, which
	// runs without a request org. Fall back to the default org so the
	// completion write still scopes correctly rather than failing.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}

	userData := map[string]interface{}{}

	// Each entry is (output key, SQL that returns json_agg or row_to_json).
	// Errors per category are tolerated (some tables may not exist on
	// older deployments) — we record what we got.
	type cat struct {
		key string
		sql string
	}
	categories := []cat{
		{"profile",
			`SELECT row_to_json(u) FROM (SELECT id, username, email, first_name, last_name, created_at, updated_at FROM users WHERE id = $1) u`},
		{"consents",
			`SELECT COALESCE(json_agg(row_to_json(c)), '[]'::json) FROM (SELECT id, consent_type, version, granted, granted_at, revoked_at FROM user_consents WHERE user_id = $1) c`},
		{"sessions",
			`SELECT COALESCE(json_agg(row_to_json(s)), '[]'::json) FROM (SELECT id, client_id, ip_address, started_at, expires_at FROM sessions WHERE user_id = $1) s`},
		{"audit_events",
			`SELECT COALESCE(json_agg(row_to_json(a)), '[]'::json) FROM (SELECT id, event_type, action, resource_type, created_at FROM audit_events WHERE actor_id = $1 ORDER BY created_at DESC LIMIT 1000) a`},
		{"roles",
			`SELECT COALESCE(json_agg(row_to_json(r)), '[]'::json) FROM (SELECT ur.role_id, r.name, ur.expires_at FROM user_roles ur LEFT JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1) r`},
		{"groups",
			`SELECT COALESCE(json_agg(row_to_json(g)), '[]'::json) FROM (SELECT gm.group_id, g.name FROM group_memberships gm LEFT JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = $1) g`},
		{"application_assignments",
			`SELECT COALESCE(json_agg(row_to_json(a)), '[]'::json) FROM (SELECT application_id, assigned_at FROM user_application_assignments WHERE user_id = $1) a`},
		{"access_requests",
			`SELECT COALESCE(json_agg(row_to_json(ar)), '[]'::json) FROM (SELECT id, resource_type, resource_name, status, created_at FROM access_requests WHERE requester_id = $1) ar`},
		{"mfa_totp",
			`SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (SELECT enabled, verified_at, created_at FROM mfa_totp WHERE user_id = $1) t`},
		{"mfa_webauthn",
			`SELECT COALESCE(json_agg(row_to_json(w)), '[]'::json) FROM (SELECT id, friendly_name, created_at FROM mfa_webauthn WHERE user_id = $1) w`},
		{"mfa_push_devices",
			`SELECT COALESCE(json_agg(row_to_json(p)), '[]'::json) FROM (SELECT id, device_type, created_at FROM mfa_push_devices WHERE user_id = $1) p`},
		{"earlier_dsars",
			`SELECT COALESCE(json_agg(row_to_json(d)), '[]'::json) FROM (SELECT id, request_type, status, created_at, completed_at FROM data_subject_requests WHERE user_id = $1) d`},
	}
	for _, c := range categories {
		var raw json.RawMessage
		if err := s.db.Pool.QueryRow(ctx, c.sql, dsar.UserID).Scan(&raw); err == nil {
			userData[c.key] = raw
		} else {
			// Don't blank the export on a single missing-table failure
			// (older Postgres clusters may pre-date some optional tables).
			s.logger.Debug("DSAR export skipped category",
				zap.String("category", c.key), zap.Error(err))
		}
	}

	// Write a gzip'd JSON bundle. Keep using the local-fs path the original
	// implementation used so existing operator runbooks still apply;
	// uploading to S3 is the next-PR concern.
	exportDir := "/tmp/openidx-privacy"
	if err := os.MkdirAll(exportDir, 0750); err != nil {
		return nil, fmt.Errorf("create export directory: %w", err)
	}
	filename := fmt.Sprintf("dsar-export-%s-%s.json.gz", dsar.UserID, time.Now().Format("20060102-150405"))
	filePath := filepath.Join(exportDir, filename)
	f, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("create export file: %w", err)
	}
	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)
	enc.SetIndent("", "  ")
	encErr := enc.Encode(userData)
	gz.Close()
	f.Close()
	if encErr != nil {
		return nil, fmt.Errorf("write export data: %w", encErr)
	}
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat export file: %w", err)
	}
	fileSize := fi.Size()

	_, err = s.db.Pool.Exec(ctx,
		`UPDATE data_subject_requests SET status = 'completed', result_file_path = $1, result_file_size = $2,
			processed_by = $3, completed_at = NOW(), updated_at = NOW() WHERE id = $4 AND org_id = $5`,
		filePath, fileSize, nilIfEmpty(actorID), dsar.ID, orgID)
	if err != nil {
		return nil, fmt.Errorf("update DSAR record: %w", err)
	}
	s.logger.Info("DSAR export completed",
		zap.String("dsar_id", dsar.ID),
		zap.String("user_id", dsar.UserID),
		zap.String("actor_id", actorID),
		zap.Int64("file_size", fileSize))
	return map[string]interface{}{
		"message":    "Data export completed",
		"categories": len(userData),
		"file_path":  filePath,
		"file_size":  fileSize,
	}, nil
}

// executeDSARDelete implements the GDPR Article 17 "right to erasure": tear
// down everything that identifies the subject. The user row itself is kept
// (and anonymized) rather than deleted so foreign keys from audit tables
// don't get orphaned — audit immutability requirements would otherwise
// conflict with the erasure request. Sessions and refresh tokens are
// wiped (so the user is signed out immediately and can't log in again),
// MFA enrollments are cleared (no leftover phone numbers / device IDs),
// consents are cleared, role/group/application assignments are removed.
func (s *Service) executeDSARDelete(ctx context.Context, dsar *DataSubjectRequest, actorID string) (map[string]interface{}, error) {
	// This executor is also driven by the background DSAR processor, which
	// runs without a request org. Fall back to the default org so the
	// erasure writes still scope correctly rather than failing.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}

	// Anonymize the user row. Disable the account so a stale session can't
	// be revived and the user can't log back in.
	deletedEmail := fmt.Sprintf("deleted-%s@deleted.local", dsar.UserID)
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		SET email = $1,
		    first_name = 'Deleted',
		    last_name  = 'Deleted',
		    username   = $1,
		    phone_number = NULL,
		    avatar_url   = NULL,
		    password_hash = NULL,
		    enabled = false,
		    updated_at = NOW()
		WHERE id = $2 AND org_id = $3`, deletedEmail, dsar.UserID, orgID); err != nil {
		return nil, fmt.Errorf("anonymize user row: %w", err)
	}

	// Wipe everything that holds PII *about* the subject. Each statement is
	// idempotent and `DELETE FROM … WHERE user_id = $1 AND org_id = $2` — if
	// the table doesn't exist on this install, log and continue rather than
	// rolling back the whole erasure.
	wipes := []string{
		`DELETE FROM sessions WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM user_roles WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM group_memberships WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM user_application_assignments WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM mfa_totp WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM mfa_push_devices WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM mfa_backup_codes WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM user_consents WHERE user_id = $1 AND org_id = $2`,
		`DELETE FROM api_keys WHERE user_id = $1 AND org_id = $2`,
	}
	wiped := 0
	for _, sql := range wipes {
		if _, err := s.db.Pool.Exec(ctx, sql, dsar.UserID, orgID); err != nil {
			s.logger.Debug("DSAR delete skipped table",
				zap.String("sql", sql), zap.Error(err))
			continue
		}
		wiped++
	}

	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE data_subject_requests SET status = 'completed', processed_by = $1, completed_at = NOW(), updated_at = NOW() WHERE id = $2 AND org_id = $3`,
		nilIfEmpty(actorID), dsar.ID, orgID); err != nil {
		return nil, fmt.Errorf("update DSAR record: %w", err)
	}
	s.logger.Info("DSAR delete completed",
		zap.String("dsar_id", dsar.ID),
		zap.String("user_id", dsar.UserID),
		zap.String("actor_id", actorID),
		zap.Int("tables_wiped", wiped))
	return map[string]interface{}{
		"message":      "Subject data erased and account anonymized",
		"tables_wiped": wiped,
	}, nil
}

// executeDSARRestrict implements the GDPR Article 18 "right to restriction":
// keep the data on file (it may be needed for legal claims) but prevent
// further processing. We disable the account, revoke active sessions and
// refresh tokens, and flag the user record so background jobs can skip them.
// Crucially, we do *not* delete anything — the user can have the restriction
// lifted later, and `restrict` is supposed to be reversible.
func (s *Service) executeDSARRestrict(ctx context.Context, dsar *DataSubjectRequest, actorID string) (map[string]interface{}, error) {
	// This executor is also driven by the background DSAR processor, which
	// runs without a request org. Fall back to the default org so the
	// restriction writes still scope correctly rather than failing.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}

	if _, err := s.db.Pool.Exec(ctx, `UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2`, dsar.UserID, orgID); err != nil {
		return nil, fmt.Errorf("disable user: %w", err)
	}
	if _, err := s.db.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND org_id = $2`, dsar.UserID, orgID); err != nil {
		s.logger.Warn("DSAR restrict: failed to drop sessions", zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND org_id = $2`, dsar.UserID, orgID); err != nil {
		s.logger.Warn("DSAR restrict: failed to drop refresh tokens", zap.Error(err))
	}

	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE data_subject_requests SET status = 'completed', processed_by = $1, completed_at = NOW(), updated_at = NOW() WHERE id = $2 AND org_id = $3`,
		nilIfEmpty(actorID), dsar.ID, orgID); err != nil {
		return nil, fmt.Errorf("update DSAR record: %w", err)
	}
	s.logger.Info("DSAR restrict completed",
		zap.String("dsar_id", dsar.ID),
		zap.String("user_id", dsar.UserID),
		zap.String("actor_id", actorID))
	return map[string]interface{}{
		"message": "Subject processing restricted; account disabled, sessions revoked",
	}, nil
}

// handleListPrivacyRetention lists all privacy retention policies
func (s *Service) handleListPrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, data_category, retention_days, action, anonymize_fields,
			enabled, last_executed_at, created_at, updated_at
		 FROM privacy_retention_policies WHERE org_id = $1 ORDER BY data_category`, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list retention policies", err))
		return
	}
	defer rows.Close()

	var policies []PrivacyRetentionPolicy
	for rows.Next() {
		var p PrivacyRetentionPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.DataCategory, &p.RetentionDays, &p.Action,
			&p.AnonymizeFields, &p.Enabled, &p.LastExecutedAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []PrivacyRetentionPolicy{}
	}

	c.JSON(http.StatusOK, gin.H{"data": policies})
}

// handleCreatePrivacyRetention creates a new privacy retention policy
func (s *Service) handleCreatePrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name            string          `json:"name"`
		DataCategory    string          `json:"data_category"`
		RetentionDays   int             `json:"retention_days"`
		Action          string          `json:"action"`
		AnonymizeFields json.RawMessage `json:"anonymize_fields"`
		Enabled         bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Name == "" || req.DataCategory == "" {
		respondError(c, nil, apperrors.BadRequest("name and data_category are required"))
		return
	}

	validActions := map[string]bool{"delete": true, "anonymize": true}
	if !validActions[req.Action] {
		respondError(c, nil, apperrors.BadRequest("action must be delete or anonymize"))
		return
	}

	anonymizeFields := req.AnonymizeFields
	if anonymizeFields == nil {
		anonymizeFields = json.RawMessage("[]")
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO privacy_retention_policies (name, data_category, retention_days, action, anonymize_fields, enabled, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		req.Name, req.DataCategory, req.RetentionDays, req.Action, anonymizeFields, req.Enabled, org.ID,
	).Scan(&id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create retention policy", err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// handleUpdatePrivacyRetention updates an existing privacy retention policy
func (s *Service) handleUpdatePrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var req struct {
		Name            *string          `json:"name"`
		DataCategory    *string          `json:"data_category"`
		RetentionDays   *int             `json:"retention_days"`
		Action          *string          `json:"action"`
		AnonymizeFields *json.RawMessage `json:"anonymize_fields"`
		Enabled         *bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.DataCategory != nil {
		sets = append(sets, fmt.Sprintf("data_category = $%d", argIdx))
		args = append(args, *req.DataCategory)
		argIdx++
	}
	if req.RetentionDays != nil {
		sets = append(sets, fmt.Sprintf("retention_days = $%d", argIdx))
		args = append(args, *req.RetentionDays)
		argIdx++
	}
	if req.Action != nil {
		sets = append(sets, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, *req.Action)
		argIdx++
	}
	if req.AnonymizeFields != nil {
		sets = append(sets, fmt.Sprintf("anonymize_fields = $%d", argIdx))
		args = append(args, *req.AnonymizeFields)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}

	if len(sets) == 0 {
		respondError(c, nil, apperrors.BadRequest("No fields to update"))
		return
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE privacy_retention_policies SET %s WHERE id = $%d AND org_id = $%d", joinSetClauses(sets), argIdx, argIdx+1)
	args = append(args, org.ID)

	result, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update retention policy", err))
		return
	}
	if result.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Retention policy"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Retention policy updated"})
}

// handleDeletePrivacyRetention deletes a privacy retention policy
func (s *Service) handleDeletePrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM privacy_retention_policies WHERE id = $1 AND org_id = $2`, id, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete retention policy", err))
		return
	}
	if result.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Retention policy"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Retention policy deleted"})
}

// handleListPrivacyAssessments lists privacy impact assessments with optional filtering
func (s *Service) handleListPrivacyAssessments(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	status := c.Query("status")
	riskLevel := c.Query("risk_level")

	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	baseQuery := `SELECT id, title, COALESCE(description, ''), data_categories, processing_purposes,
		risk_level, status, findings, mitigations, assessor_id, reviewer_id,
		COALESCE(review_notes, ''), approved_at, created_at, updated_at
		FROM privacy_assessments`

	conditions := []string{"org_id = $1"}
	args := []interface{}{org.ID}
	argIdx := 2

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if riskLevel != "" {
		conditions = append(conditions, fmt.Sprintf("risk_level = $%d", argIdx))
		args = append(args, riskLevel)
	}

	whereClause := " WHERE "
	for i, cond := range conditions {
		if i > 0 {
			whereClause += " AND "
		}
		whereClause += cond
	}

	rows, err := s.db.Pool.Query(ctx, baseQuery+whereClause+" ORDER BY created_at DESC", args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list privacy assessments", err))
		return
	}
	defer rows.Close()

	var assessments []PrivacyAssessment
	for rows.Next() {
		var a PrivacyAssessment
		if err := rows.Scan(&a.ID, &a.Title, &a.Description, &a.DataCategories, &a.ProcessingPurposes,
			&a.RiskLevel, &a.Status, &a.Findings, &a.Mitigations, &a.AssessorID, &a.ReviewerID,
			&a.ReviewNotes, &a.ApprovedAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
			s.logger.Error("Failed to scan privacy assessment row", zap.Error(err))
			continue
		}
		assessments = append(assessments, a)
	}
	if assessments == nil {
		assessments = []PrivacyAssessment{}
	}

	c.JSON(http.StatusOK, gin.H{"data": assessments})
}

// handleCreatePrivacyAssessment creates a new privacy impact assessment
func (s *Service) handleCreatePrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Title              string          `json:"title"`
		Description        string          `json:"description"`
		DataCategories     json.RawMessage `json:"data_categories"`
		ProcessingPurposes json.RawMessage `json:"processing_purposes"`
		RiskLevel          string          `json:"risk_level"`
		Findings           json.RawMessage `json:"findings"`
		Mitigations        json.RawMessage `json:"mitigations"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Title == "" {
		respondError(c, nil, apperrors.BadRequest("title is required"))
		return
	}

	validRisk := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if req.RiskLevel != "" && !validRisk[req.RiskLevel] {
		respondError(c, nil, apperrors.BadRequest("risk_level must be low, medium, high, or critical"))
		return
	}
	if req.RiskLevel == "" {
		req.RiskLevel = "medium"
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	dataCategories := req.DataCategories
	if dataCategories == nil {
		dataCategories = json.RawMessage("[]")
	}
	processingPurposes := req.ProcessingPurposes
	if processingPurposes == nil {
		processingPurposes = json.RawMessage("[]")
	}
	findings := req.Findings
	if findings == nil {
		findings = json.RawMessage("[]")
	}
	mitigations := req.Mitigations
	if mitigations == nil {
		mitigations = json.RawMessage("[]")
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO privacy_assessments (title, description, data_categories, processing_purposes,
			risk_level, findings, mitigations, assessor_id, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		req.Title, req.Description, dataCategories, processingPurposes,
		req.RiskLevel, findings, mitigations, nilIfEmpty(userIDStr), org.ID,
	).Scan(&id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create privacy assessment", err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "draft"})
}

// handleGetPrivacyAssessment retrieves a single privacy assessment by ID
func (s *Service) handleGetPrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var a PrivacyAssessment
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, title, COALESCE(description, ''), data_categories, processing_purposes,
			risk_level, status, findings, mitigations, assessor_id, reviewer_id,
			COALESCE(review_notes, ''), approved_at, created_at, updated_at
		 FROM privacy_assessments WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&a.ID, &a.Title, &a.Description, &a.DataCategories, &a.ProcessingPurposes,
		&a.RiskLevel, &a.Status, &a.Findings, &a.Mitigations, &a.AssessorID, &a.ReviewerID,
		&a.ReviewNotes, &a.ApprovedAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, nil, apperrors.NotFound("Privacy assessment"))
			return
		}
		respondError(c, s.logger, apperrors.Internal("Failed to load privacy assessment", err))
		return
	}

	c.JSON(http.StatusOK, a)
}

// handleUpdatePrivacyAssessment updates an existing privacy assessment
func (s *Service) handleUpdatePrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var req struct {
		Title              *string          `json:"title"`
		Description        *string          `json:"description"`
		DataCategories     *json.RawMessage `json:"data_categories"`
		ProcessingPurposes *json.RawMessage `json:"processing_purposes"`
		RiskLevel          *string          `json:"risk_level"`
		Status             *string          `json:"status"`
		Findings           *json.RawMessage `json:"findings"`
		Mitigations        *json.RawMessage `json:"mitigations"`
		ReviewerID         *string          `json:"reviewer_id"`
		ReviewNotes        *string          `json:"review_notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Title != nil {
		sets = append(sets, fmt.Sprintf("title = $%d", argIdx))
		args = append(args, *req.Title)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.DataCategories != nil {
		sets = append(sets, fmt.Sprintf("data_categories = $%d", argIdx))
		args = append(args, *req.DataCategories)
		argIdx++
	}
	if req.ProcessingPurposes != nil {
		sets = append(sets, fmt.Sprintf("processing_purposes = $%d", argIdx))
		args = append(args, *req.ProcessingPurposes)
		argIdx++
	}
	if req.RiskLevel != nil {
		sets = append(sets, fmt.Sprintf("risk_level = $%d", argIdx))
		args = append(args, *req.RiskLevel)
		argIdx++
	}
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *req.Status)
		argIdx++

		if *req.Status == "approved" {
			sets = append(sets, fmt.Sprintf("approved_at = $%d", argIdx))
			args = append(args, time.Now())
			argIdx++
		}
	}
	if req.Findings != nil {
		sets = append(sets, fmt.Sprintf("findings = $%d", argIdx))
		args = append(args, *req.Findings)
		argIdx++
	}
	if req.Mitigations != nil {
		sets = append(sets, fmt.Sprintf("mitigations = $%d", argIdx))
		args = append(args, *req.Mitigations)
		argIdx++
	}
	if req.ReviewerID != nil {
		sets = append(sets, fmt.Sprintf("reviewer_id = $%d", argIdx))
		args = append(args, *req.ReviewerID)
		argIdx++
	}
	if req.ReviewNotes != nil {
		sets = append(sets, fmt.Sprintf("review_notes = $%d", argIdx))
		args = append(args, *req.ReviewNotes)
		argIdx++
	}

	if len(sets) == 0 {
		respondError(c, nil, apperrors.BadRequest("No fields to update"))
		return
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE privacy_assessments SET %s WHERE id = $%d AND org_id = $%d", joinSetClauses(sets), argIdx, argIdx+1)
	args = append(args, org.ID)

	result, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update privacy assessment", err))
		return
	}
	if result.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Privacy assessment"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Privacy assessment updated"})
}

// handleDeletePrivacyAssessment deletes a privacy assessment
func (s *Service) handleDeletePrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM privacy_assessments WHERE id = $1 AND org_id = $2`, id, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete privacy assessment", err))
		return
	}
	if result.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Privacy assessment"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Privacy assessment deleted"})
}
