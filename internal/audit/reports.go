// Package audit provides audit logging and compliance reporting
package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"
)

const reportDir = "/tmp/openidx-reports"

// reportFilePath joins a report file name under reportDir, constraining it to a single path
// element via filepath.Base and then verifying the cleaned result stays within reportDir, so a
// path-traversing report_type/format in the export request cannot escape reportDir
// (go/path-injection). The explicit prefix check is what makes the containment provable to
// static analysis, not just to filepath.Base.
func reportFilePath(fileName string) (string, error) {
	p := filepath.Join(reportDir, filepath.Base(fileName))
	clean := filepath.Clean(p)
	if clean != reportDir && !strings.HasPrefix(clean, reportDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("report path %q escapes report directory", fileName)
	}
	return clean, nil
}

// ReportExport represents an exported report file
type ReportExport struct {
	ID                string     `json:"id"`
	OrgID             string     `json:"org_id"`
	ScheduledReportID *string    `json:"scheduled_report_id,omitempty"`
	Name              string     `json:"name"`
	ReportType        string     `json:"report_type"`
	Framework         string     `json:"framework"`
	Format            string     `json:"format"`
	Status            string     `json:"status"`
	FilePath          string     `json:"file_path"`
	FileSize          int64      `json:"file_size"`
	RowCount          int        `json:"row_count"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	GeneratedBy       string     `json:"generated_by"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}

// ScheduledReport represents a scheduled report configuration
type ScheduledReport struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"org_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	ReportType  string                 `json:"report_type"`
	Framework   string                 `json:"framework"`
	Parameters  map[string]interface{} `json:"parameters"`
	Schedule    string                 `json:"schedule"`
	Format      string                 `json:"format"`
	Enabled     bool                   `json:"enabled"`
	Recipients  []string               `json:"recipients"`
	LastRunAt   *time.Time             `json:"last_run_at,omitempty"`
	NextRunAt   *time.Time             `json:"next_run_at,omitempty"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// GenerateReportExport creates a new report export and starts async generation
func (s *Service) GenerateReportExport(ctx context.Context, orgID, reportType, framework, format, generatedBy string) (*ReportExport, error) {
	export := &ReportExport{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		Name:        fmt.Sprintf("%s %s Report", framework, reportType),
		ReportType:  reportType,
		Framework:   framework,
		Format:      format,
		Status:      "generating",
		GeneratedBy: generatedBy,
		CreatedAt:   time.Now(),
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO report_exports (id, org_id, name, report_type, framework, format, status, generated_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, export.ID, export.OrgID, export.Name, export.ReportType, export.Framework,
		export.Format, export.Status, export.GeneratedBy, export.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert report export: %w", err)
	}

	go s.generateReportAsync(export)

	return export, nil
}

// generateReportAsync runs report generation in the background
func (s *Service) generateReportAsync(export *ReportExport) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	s.logger.Info("Starting async report generation",
		zap.String("export_id", export.ID),
		zap.String("report_type", export.ReportType))

	var data []map[string]interface{}
	var headers []string
	var err error

	// typeSlug is a compile-time-constant file-name token chosen by the validated report
	// type, never the request string itself — this is what keeps the export path free of
	// caller-controlled data (go/path-injection).
	var typeSlug string
	switch export.ReportType {
	case "user_access":
		data, err = s.getUserAccessData(ctx, export.OrgID)
		headers = []string{"user_id", "username", "email", "role_name", "group_name"}
		typeSlug = "user_access"
	case "compliance":
		data, err = s.getComplianceData(ctx, export.OrgID)
		headers = []string{"event_type", "category", "outcome", "event_count"}
		typeSlug = "compliance"
	case "entitlement":
		data, err = s.getEntitlementData(ctx, export.OrgID)
		headers = []string{"user_id", "username", "role_name", "group_name", "assigned_at"}
		typeSlug = "entitlement"
	case "activity":
		data, err = s.getActivityData(ctx, export.OrgID)
		headers = []string{"action", "event_count", "last_occurred"}
		typeSlug = "activity"
	default:
		err = fmt.Errorf("unsupported report type: %s", export.ReportType)
	}

	if err != nil {
		s.logger.Error("Failed to query report data", zap.Error(err))
		s.updateExportStatus(ctx, export.ID, "failed", "", 0, 0, err.Error())
		return
	}

	// Ensure report directory exists
	if mkErr := os.MkdirAll(reportDir, 0755); mkErr != nil {
		s.logger.Error("Failed to create report directory", zap.Error(mkErr))
		s.updateExportStatus(ctx, export.ID, "failed", "", 0, 0, mkErr.Error())
		return
	}

	// ext is likewise a constant token selected by the validated format, so the file name is
	// assembled entirely from server-controlled values (typeSlug, the server-generated export
	// ID, a timestamp, ext) — no request string reaches the filesystem path.
	var ext string
	switch export.Format {
	case "csv":
		ext = "csv"
	case "json":
		ext = "json"
	default:
		err = fmt.Errorf("unsupported format: %s", export.Format)
		s.logger.Error("Failed to write report file", zap.Error(err))
		s.updateExportStatus(ctx, export.ID, "failed", "", 0, 0, err.Error())
		return
	}

	fileName := fmt.Sprintf("%s_%s_%s.%s", typeSlug, export.ID[:8], time.Now().Format("20060102150405"), ext)
	filePath, pathErr := reportFilePath(fileName)
	if pathErr != nil {
		s.logger.Error("Rejected report export path", zap.Error(pathErr))
		s.updateExportStatus(ctx, export.ID, "failed", "", 0, 0, pathErr.Error())
		return
	}

	switch ext {
	case "csv":
		err = s.writeCSVFile(filePath, headers, data)
	case "json":
		err = s.writeJSONFile(filePath, data)
	}

	if err != nil {
		s.logger.Error("Failed to write report file", zap.Error(err))
		s.updateExportStatus(ctx, export.ID, "failed", "", 0, 0, err.Error())
		return
	}

	// Get file size
	var fileSize int64
	if info, statErr := os.Stat(filePath); statErr == nil {
		fileSize = info.Size()
	}

	s.updateExportStatus(ctx, export.ID, "completed", filePath, fileSize, len(data), "")
	s.logger.Info("Report generation completed",
		zap.String("export_id", export.ID),
		zap.String("file_path", filePath),
		zap.Int("row_count", len(data)))
}

// getUserAccessData queries users with their roles and groups
func (s *Service) getUserAccessData(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email,
		       COALESCE(r.name, '') AS role_name,
		       COALESCE(g.name, '') AS group_name
		FROM users u
		LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.org_id = u.org_id
		LEFT JOIN roles r ON ur.role_id = r.id AND r.org_id = u.org_id
		LEFT JOIN group_memberships gm ON u.id = gm.user_id AND gm.org_id = u.org_id
		LEFT JOIN groups g ON gm.group_id = g.id AND g.org_id = u.org_id
		WHERE u.org_id = $1
		ORDER BY u.username
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user access data: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var userID, username, email, roleName, groupName string
		if err := rows.Scan(&userID, &username, &email, &roleName, &groupName); err != nil {
			return nil, fmt.Errorf("failed to scan user access row: %w", err)
		}
		results = append(results, map[string]interface{}{
			"user_id":    userID,
			"username":   username,
			"email":      email,
			"role_name":  roleName,
			"group_name": groupName,
		})
	}

	return results, nil
}

// getComplianceData queries audit event summary for compliance
func (s *Service) getComplianceData(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT event_type, category, outcome, COUNT(*) AS event_count
		FROM audit_events
		WHERE org_id = $1
		GROUP BY event_type, category, outcome
		ORDER BY event_count DESC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query compliance data: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var eventType, category, outcome string
		var eventCount int
		if err := rows.Scan(&eventType, &category, &outcome, &eventCount); err != nil {
			return nil, fmt.Errorf("failed to scan compliance row: %w", err)
		}
		results = append(results, map[string]interface{}{
			"event_type":  eventType,
			"category":    category,
			"outcome":     outcome,
			"event_count": eventCount,
		})
	}

	return results, nil
}

// getEntitlementData queries role and group assignments
func (s *Service) getEntitlementData(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id AS user_id, u.username,
		       COALESCE(r.name, '') AS role_name,
		       COALESCE(g.name, '') AS group_name,
		       COALESCE(ur.assigned_at, gm.joined_at, NOW()) AS assigned_at
		FROM users u
		LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.org_id = u.org_id
		LEFT JOIN roles r ON ur.role_id = r.id AND r.org_id = u.org_id
		LEFT JOIN group_memberships gm ON u.id = gm.user_id AND gm.org_id = u.org_id
		LEFT JOIN groups g ON gm.group_id = g.id AND g.org_id = u.org_id
		WHERE u.org_id = $1 AND (ur.role_id IS NOT NULL OR gm.group_id IS NOT NULL)
		ORDER BY u.username
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query entitlement data: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var userID, username, roleName, groupName string
		var assignedAt time.Time
		if err := rows.Scan(&userID, &username, &roleName, &groupName, &assignedAt); err != nil {
			return nil, fmt.Errorf("failed to scan entitlement row: %w", err)
		}
		results = append(results, map[string]interface{}{
			"user_id":     userID,
			"username":    username,
			"role_name":   roleName,
			"group_name":  groupName,
			"assigned_at": assignedAt.Format(time.RFC3339),
		})
	}

	return results, nil
}

// getActivityData queries recent audit events grouped by action
func (s *Service) getActivityData(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT action, COUNT(*) AS event_count, MAX(timestamp) AS last_occurred
		FROM audit_events
		WHERE org_id = $1
		GROUP BY action
		ORDER BY event_count DESC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query activity data: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var action string
		var eventCount int
		var lastOccurred time.Time
		if err := rows.Scan(&action, &eventCount, &lastOccurred); err != nil {
			return nil, fmt.Errorf("failed to scan activity row: %w", err)
		}
		results = append(results, map[string]interface{}{
			"action":        action,
			"event_count":   eventCount,
			"last_occurred": lastOccurred.Format(time.RFC3339),
		})
	}

	return results, nil
}

// writeCSVFile writes data to a CSV file
func (s *Service) writeCSVFile(filePath string, headers []string, data []map[string]interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %w", err)
	}

	// Write data rows
	for _, row := range data {
		record := make([]string, len(headers))
		for i, header := range headers {
			if val, ok := row[header]; ok {
				record[i] = fmt.Sprintf("%v", val)
			}
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// writeJSONFile writes data to a JSON file
func (s *Service) writeJSONFile(filePath string, data []map[string]interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// updateExportStatus updates the status of a report export in the database
func (s *Service) updateExportStatus(ctx context.Context, exportID, status, filePath string, fileSize int64, rowCount int, errMsg string) {
	now := time.Now()
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE report_exports
		SET status = $1, file_path = $2, file_size = $3, row_count = $4,
		    error_message = $5, completed_at = $6
		WHERE id = $7
	`, status, filePath, fileSize, rowCount, errMsg, &now, exportID)
	if err != nil {
		s.logger.Error("Failed to update export status",
			zap.String("export_id", exportID),
			zap.Error(err))
	}
}

// ListReportExports returns paginated report exports for an org
func (s *Service) ListReportExports(ctx context.Context, orgID string, limit, offset int) ([]ReportExport, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM report_exports WHERE org_id = $1
	`, orgID).Scan(&total)
	if err != nil {
		return []ReportExport{}, 0, nil
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, org_id, scheduled_report_id, name, report_type, framework, format,
		       status, COALESCE(file_path, ''), file_size, row_count,
		       COALESCE(error_message, ''), generated_by, created_at, completed_at
		FROM report_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		OFFSET $2 LIMIT $3
	`, orgID, offset, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query report exports: %w", err)
	}
	defer rows.Close()

	var exports []ReportExport
	for rows.Next() {
		var e ReportExport
		if err := rows.Scan(
			&e.ID, &e.OrgID, &e.ScheduledReportID, &e.Name, &e.ReportType,
			&e.Framework, &e.Format, &e.Status, &e.FilePath, &e.FileSize,
			&e.RowCount, &e.ErrorMessage, &e.GeneratedBy, &e.CreatedAt, &e.CompletedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan report export: %w", err)
		}
		exports = append(exports, e)
	}

	return exports, total, nil
}

// GetReportExportFile returns the file path for a completed export
func (s *Service) GetReportExportFile(ctx context.Context, orgID, exportID string) (string, error) {
	var filePath, status string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(file_path, ''), status FROM report_exports
		WHERE id = $1 AND org_id = $2
	`, exportID, orgID).Scan(&filePath, &status)
	if err != nil {
		return "", fmt.Errorf("export not found: %w", err)
	}

	if status != "completed" {
		return "", fmt.Errorf("export is not completed, current status: %s", status)
	}

	return filePath, nil
}

// ListScheduledReports returns all scheduled reports for an org
func (s *Service) ListScheduledReports(ctx context.Context, orgID string) ([]ScheduledReport, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, org_id, name, COALESCE(description, ''), report_type, COALESCE(framework, ''),
		       COALESCE(parameters::text, '{}'), schedule, format, enabled,
		       COALESCE(recipients, '[]'), last_run_at, next_run_at,
		       created_by, created_at, updated_at
		FROM scheduled_reports
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return []ScheduledReport{}, nil
	}
	defer rows.Close()

	var reports []ScheduledReport
	for rows.Next() {
		var r ScheduledReport
		var paramsJSON, recipientsJSON string
		if err := rows.Scan(
			&r.ID, &r.OrgID, &r.Name, &r.Description, &r.ReportType, &r.Framework,
			&paramsJSON, &r.Schedule, &r.Format, &r.Enabled,
			&recipientsJSON, &r.LastRunAt, &r.NextRunAt,
			&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan scheduled report: %w", err)
		}
		if paramsJSON != "" {
			json.Unmarshal([]byte(paramsJSON), &r.Parameters)
		}
		if recipientsJSON != "" {
			json.Unmarshal([]byte(recipientsJSON), &r.Recipients)
		}
		reports = append(reports, r)
	}

	return reports, nil
}

// CreateScheduledReport creates a new scheduled report
func (s *Service) CreateScheduledReport(ctx context.Context, report *ScheduledReport) error {
	report.ID = uuid.New().String()
	report.CreatedAt = time.Now()
	report.UpdatedAt = time.Now()

	paramsJSON, _ := json.Marshal(report.Parameters)
	if report.Recipients == nil {
		report.Recipients = []string{}
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO scheduled_reports (id, org_id, name, description, report_type, framework,
		                                parameters, schedule, format, enabled, recipients,
		                                next_run_at, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`, report.ID, report.OrgID, report.Name, report.Description, report.ReportType,
		report.Framework, paramsJSON, report.Schedule, report.Format, report.Enabled,
		report.Recipients, report.NextRunAt, report.CreatedBy, report.CreatedAt, report.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create scheduled report: %w", err)
	}

	return nil
}

// UpdateScheduledReport updates an existing scheduled report
func (s *Service) UpdateScheduledReport(ctx context.Context, reportID string, name, schedule, format string, enabled bool) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE scheduled_reports
		SET name = $1, schedule = $2, format = $3, enabled = $4, updated_at = $5
		WHERE id = $6
	`, name, schedule, format, enabled, time.Now(), reportID)
	if err != nil {
		return fmt.Errorf("failed to update scheduled report: %w", err)
	}

	return nil
}

// DeleteScheduledReport deletes a scheduled report
func (s *Service) DeleteScheduledReport(ctx context.Context, reportID string) error {
	_, err := s.db.Pool.Exec(ctx, `
		DELETE FROM scheduled_reports WHERE id = $1
	`, reportID)
	if err != nil {
		return fmt.Errorf("failed to delete scheduled report: %w", err)
	}

	return nil
}

// HTTP Handlers for report exports and scheduled reports

func (s *Service) handleGenerateExport(c *gin.Context) {
	var req struct {
		ReportType string `json:"report_type" binding:"required"`
		Framework  string `json:"framework"`
		Format     string `json:"format"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Format == "" {
		req.Format = "csv"
	}

	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		orgIDStr = "00000000-0000-0000-0000-000000000010"
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		userIDStr = "00000000-0000-0000-0000-000000000001"
	}

	export, err := s.GenerateReportExport(c.Request.Context(), orgIDStr, req.ReportType, req.Framework, req.Format, userIDStr)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("generate export", err), s.logger)
		return
	}

	c.JSON(http.StatusAccepted, export)
}

func (s *Service) handleListExports(c *gin.Context) {
	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		orgIDStr = "00000000-0000-0000-0000-000000000010"
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	exports, total, err := s.ListReportExports(c.Request.Context(), orgIDStr, limit, offset)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list exports", err), s.logger)
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	// Frontend (reports page) and its test read {exports, total}; a bare array
	// left exportsData?.exports undefined and the list empty.
	if exports == nil {
		exports = []ReportExport{}
	}
	c.JSON(http.StatusOK, gin.H{"exports": exports, "total": total})
}

func (s *Service) handleDownloadExport(c *gin.Context) {
	exportID := c.Param("id")

	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		orgIDStr = "00000000-0000-0000-0000-000000000010"
	}

	filePath, err := s.GetReportExportFile(c.Request.Context(), orgIDStr, exportID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	fileName := filepath.Base(filePath)
	c.FileAttachment(filePath, fileName)
}

func (s *Service) handleListScheduledReports(c *gin.Context) {
	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		orgIDStr = "00000000-0000-0000-0000-000000000010"
	}

	reports, err := s.ListScheduledReports(c.Request.Context(), orgIDStr)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list scheduled reports", err), s.logger)
		return
	}

	// Frontend (reports page) and its test read {reports}; a bare array left
	// scheduledData?.reports undefined and the list empty.
	if reports == nil {
		reports = []ScheduledReport{}
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}

func (s *Service) handleCreateScheduledReport(c *gin.Context) {
	var report ScheduledReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	if orgIDStr == "" {
		orgIDStr = "00000000-0000-0000-0000-000000000010"
	}
	report.OrgID = orgIDStr

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		userIDStr = "00000000-0000-0000-0000-000000000001"
	}
	report.CreatedBy = userIDStr

	if err := s.CreateScheduledReport(c.Request.Context(), &report); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create scheduled report", err), s.logger)
		return
	}

	c.JSON(http.StatusCreated, report)
}

func (s *Service) handleUpdateScheduledReport(c *gin.Context) {
	reportID := c.Param("id")

	var req struct {
		Name     string `json:"name"`
		Schedule string `json:"schedule"`
		Format   string `json:"format"`
		Enabled  bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateScheduledReport(c.Request.Context(), reportID, req.Name, req.Schedule, req.Format, req.Enabled); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("update scheduled report", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "scheduled report updated"})
}

func (s *Service) handleDeleteScheduledReport(c *gin.Context) {
	reportID := c.Param("id")

	if err := s.DeleteScheduledReport(c.Request.Context(), reportID); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete scheduled report", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "scheduled report deleted"})
}

// RegisterReportRoutes registers report-related routes
func RegisterReportRoutes(router *gin.RouterGroup, svc *Service, extraMiddleware ...gin.HandlerFunc) {
	// These endpoints generate/download/schedule reports over the audit trail
	// (sensitive). Apply the JWT auth middleware passed by the caller.
	for _, mw := range extraMiddleware {
		router.Use(mw)
	}
	router.POST("/reports/generate", svc.handleGenerateExport)
	router.GET("/reports/exports", svc.handleListExports)
	router.GET("/reports/exports/:id/download", svc.handleDownloadExport)
	router.GET("/reports/scheduled", svc.handleListScheduledReports)
	router.POST("/reports/scheduled", svc.handleCreateScheduledReport)
	router.PUT("/reports/scheduled/:id", svc.handleUpdateScheduledReport)
	router.DELETE("/reports/scheduled/:id", svc.handleDeleteScheduledReport)
}
