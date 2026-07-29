// Package admin provides bulk import/export operations for the admin console
package admin

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// UserImportRow represents a single row in the user import CSV
type UserImportRow struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Enabled    string `json:"enabled"` // "true" or "false"
	Roles      string `json:"roles"`   // comma-separated
	Groups     string `json:"groups"`  // comma-separated
	LineNumber int    `json:"line_number"`
}

// UserImportResult represents the result of a bulk user import
type UserImportResult struct {
	SuccessCount  int                `json:"success_count"`
	ErrorCount    int                `json:"error_count"`
	TotalRows     int                `json:"total_rows"`
	Errors        []UserImportError  `json:"errors,omitempty"`
	ImportedUsers []ImportedUserInfo `json:"imported_users,omitempty"`
}

// UserImportError represents an error that occurred during import
type UserImportError struct {
	LineNumber int    `json:"line_number"`
	Username   string `json:"username"`
	Error      string `json:"error"`
}

// ImportedUserInfo contains information about a successfully imported user
type ImportedUserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// ImportUsersFromCSV imports users from a CSV file
func (s *Service) ImportUsersFromCSV(ctx context.Context, reader io.Reader) (*UserImportResult, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1 // Allow variable number of fields

	// Read header row
	headers, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Validate headers
	requiredHeaders := []string{"username", "email"}
	headerMap := make(map[string]int)
	for i, header := range headers {
		headerMap[strings.ToLower(strings.TrimSpace(header))] = i
	}

	for _, required := range requiredHeaders {
		if _, ok := headerMap[required]; !ok {
			return nil, fmt.Errorf("missing required header: %s", required)
		}
	}

	result := &UserImportResult{
		SuccessCount:  0,
		ErrorCount:    0,
		TotalRows:     0,
		Errors:        []UserImportError{},
		ImportedUsers: []ImportedUserInfo{},
	}

	lineNumber := 1 // After header

	// Read data rows
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, UserImportError{
				LineNumber: lineNumber,
				Error:      fmt.Sprintf("Failed to read row: %v", err),
			})
			lineNumber++
			continue
		}

		lineNumber++
		result.TotalRows++

		// Parse row
		row, err := s.parseUserImportRow(record, headerMap, lineNumber)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, UserImportError{
				LineNumber: lineNumber,
				Error:      err.Error(),
			})
			continue
		}

		// Validate row
		if err := s.validateUserImportRow(ctx, row); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, UserImportError{
				LineNumber: lineNumber,
				Username:   row.Username,
				Error:      err.Error(),
			})
			continue
		}

		// Import user
		userID, err := s.importUser(ctx, row)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, UserImportError{
				LineNumber: lineNumber,
				Username:   row.Username,
				Error:      err.Error(),
			})
			continue
		}

		result.SuccessCount++
		result.ImportedUsers = append(result.ImportedUsers, ImportedUserInfo{
			ID:       userID,
			Username: row.Username,
			Email:    row.Email,
		})
	}

	return result, nil
}

// parseUserImportRow parses a CSV record into a UserImportRow
func (s *Service) parseUserImportRow(record []string, headerMap map[string]int, lineNumber int) (*UserImportRow, error) {
	getField := func(name string) string {
		if idx, ok := headerMap[name]; ok && idx < len(record) {
			return strings.TrimSpace(record[idx])
		}
		return ""
	}

	row := &UserImportRow{
		Username:   getField("username"),
		Email:      getField("email"),
		FirstName:  getField("first_name"),
		LastName:   getField("last_name"),
		Enabled:    getField("enabled"),
		Roles:      getField("roles"),
		Groups:     getField("groups"),
		LineNumber: lineNumber,
	}

	// Set default enabled value
	if row.Enabled == "" {
		row.Enabled = "true"
	}

	return row, nil
}

// validateUserImportRow validates a user import row
func (s *Service) validateUserImportRow(ctx context.Context, row *UserImportRow) error {
	if row.Username == "" {
		return fmt.Errorf("username is required")
	}
	if row.Email == "" {
		return fmt.Errorf("email is required")
	}

	// Validate email format
	if !strings.Contains(row.Email, "@") {
		return fmt.Errorf("invalid email format")
	}

	// Validate enabled value
	if row.Enabled != "true" && row.Enabled != "false" {
		return fmt.Errorf("enabled must be 'true' or 'false'")
	}

	// Skip DB checks if database is not available (e.g., in tests)
	if s.db == nil || s.db.Pool == nil {
		return nil
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Check if username already exists (uniqueness is per-org)
	var exists bool
	err = s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND org_id = $2)", row.Username, org.ID).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("username already exists")
	}

	// Check if email already exists
	err = s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND org_id = $2)", row.Email, org.ID).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("email already exists")
	}

	// Validate roles if specified
	if row.Roles != "" {
		roles := strings.Split(row.Roles, ",")
		for _, role := range roles {
			role = strings.TrimSpace(role)
			if role != "" {
				// Check if role exists
				var roleExists bool
				err := s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1 AND org_id = $2)", role, org.ID).Scan(&roleExists)
				if err != nil || !roleExists {
					return fmt.Errorf("role '%s' does not exist", role)
				}
			}
		}
	}

	return nil
}

// importUser imports a single user
func (s *Service) importUser(ctx context.Context, row *UserImportRow) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}

	// Generate user ID
	userID := uuid.New().String()

	// Parse enabled value
	enabled := row.Enabled == "true"

	// Set temporary password that must be changed
	tempPassword := uuid.New().String()[:16]

	// Insert user
	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name, enabled,
		                   password_hash, password_must_change, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $8, $9)
	`, userID, row.Username, row.Email, row.FirstName, row.LastName,
		enabled, tempPassword, now, org.ID)

	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	// Assign roles if specified
	if row.Roles != "" {
		roles := strings.Split(row.Roles, ",")
		for _, roleName := range roles {
			roleName = strings.TrimSpace(roleName)
			if roleName == "" {
				continue
			}

			// Get role ID
			var roleID string
			err := s.db.Pool.QueryRow(ctx, "SELECT id FROM roles WHERE name = $1 AND org_id = $2", roleName, org.ID).Scan(&roleID)
			if err != nil {
				s.logger.Warn("Failed to find role for assignment",
					zap.String("role", roleName),
					zap.Error(err))
				continue
			}

			// Assign role
			_, err = s.db.Pool.Exec(ctx, `
				INSERT INTO user_roles (user_id, role_id, assigned_at, org_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (user_id, role_id) DO NOTHING
			`, userID, roleID, now, org.ID)
			if err != nil {
				s.logger.Warn("Failed to assign role",
					zap.String("user_id", userID),
					zap.String("role", roleName),
					zap.Error(err))
			}
		}
	}

	// Add to groups if specified
	if row.Groups != "" {
		groups := strings.Split(row.Groups, ",")
		for _, groupName := range groups {
			groupName = strings.TrimSpace(groupName)
			if groupName == "" {
				continue
			}

			// Get group ID
			var groupID string
			err := s.db.Pool.QueryRow(ctx, "SELECT id FROM groups WHERE name = $1 AND org_id = $2", groupName, org.ID).Scan(&groupID)
			if err != nil {
				s.logger.Warn("Failed to find group for membership",
					zap.String("group", groupName),
					zap.Error(err))
				continue
			}

			// Add to group
			_, err = s.db.Pool.Exec(ctx, `
				INSERT INTO group_memberships (user_id, group_id, joined_at, org_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (user_id, group_id) DO NOTHING
			`, userID, groupID, now, org.ID)
			if err != nil {
				s.logger.Warn("Failed to add user to group",
					zap.String("user_id", userID),
					zap.String("group", groupName),
					zap.Error(err))
			}
		}
	}

	return userID, nil
}

// ExportUsersToCSV exports all users to CSV format
func (s *Service) ExportUsersToCSV(ctx context.Context, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"ID", "Username", "Email", "FirstName", "LastName", "Enabled", "EmailVerified", "CreatedAt", "LastLogin", "Roles", "Groups"}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Query users with roles and groups
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.enabled,
		       u.email_verified, u.created_at, u.last_login_at,
		       COALESCE(string_agg(DISTINCT r.name, ','), '') as roles,
		       COALESCE(string_agg(DISTINCT g.name, ','), '') as groups
		FROM users u
		LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.org_id = u.org_id
		LEFT JOIN roles r ON ur.role_id = r.id AND r.org_id = u.org_id
		LEFT JOIN group_memberships gm ON u.id = gm.user_id AND gm.org_id = u.org_id
		LEFT JOIN groups g ON gm.group_id = g.id AND g.org_id = u.org_id
		WHERE u.org_id = $1
		GROUP BY u.id
		ORDER BY u.username
	`, org.ID)
	if err != nil {
		return fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	// Write rows
	for rows.Next() {
		var id, username, email, firstName, lastName, roles, groups string
		var enabled, emailVerified bool
		var createdAt time.Time
		var lastLogin *time.Time

		if err := rows.Scan(&id, &username, &email, &firstName, &lastName, &enabled,
			&emailVerified, &createdAt, &lastLogin, &roles, &groups); err != nil {
			s.logger.Warn("Failed to scan user row for export", zap.Error(err))
			continue
		}

		record := []string{
			id,
			username,
			email,
			firstName,
			lastName,
			strconv.FormatBool(enabled),
			strconv.FormatBool(emailVerified),
			createdAt.Format(time.RFC3339),
			formatTimePtr(lastLogin),
			roles,
			groups,
		}

		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// ExportUsersToCSVStreaming exports users with streaming response for large datasets
func (s *Service) ExportUsersToCSVStreaming(ctx context.Context) (<-chan []string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.enabled,
		       u.email_verified, u.created_at, u.last_login_at,
		       COALESCE(string_agg(DISTINCT r.name, ','), '') as roles,
		       COALESCE(string_agg(DISTINCT g.name, ','), '') as groups
		FROM users u
		LEFT JOIN user_roles ur ON u.id = ur.user_id AND ur.org_id = u.org_id
		LEFT JOIN roles r ON ur.role_id = r.id AND r.org_id = u.org_id
		LEFT JOIN group_memberships gm ON u.id = gm.user_id AND gm.org_id = u.org_id
		LEFT JOIN groups g ON gm.group_id = g.id AND g.org_id = u.org_id
		WHERE u.org_id = $1
		GROUP BY u.id
		ORDER BY u.username
	`, org.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}

	ch := make(chan []string, 100)

	go func() {
		defer close(ch)
		defer rows.Close()

		// Send header first
		header := []string{"ID", "Username", "Email", "FirstName", "LastName", "Enabled", "EmailVerified", "CreatedAt", "LastLogin", "Roles", "Groups"}
		ch <- header

		// Send rows
		for rows.Next() {
			var id, username, email, firstName, lastName, roles, groups string
			var enabled, emailVerified bool
			var createdAt time.Time
			var lastLogin *time.Time

			if err := rows.Scan(&id, &username, &email, &firstName, &lastName, &enabled,
				&emailVerified, &createdAt, &lastLogin, &roles, &groups); err != nil {
				continue
			}

			record := []string{
				id,
				username,
				email,
				firstName,
				lastName,
				strconv.FormatBool(enabled),
				strconv.FormatBool(emailVerified),
				createdAt.Format(time.RFC3339),
				formatTimePtr(lastLogin),
				roles,
				groups,
			}

			select {
			case ch <- record:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// handleExportUsersCSV handles GET /api/v1/admin/users/export
func (s *Service) handleExportUsersCSV(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=users_export_%s.csv", time.Now().Format("2006-01-02")))

	// Use streaming export for better performance
	ch, err := s.ExportUsersToCSVStreaming(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to start user export", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export users"})
		return
	}

	csvWriter := csv.NewWriter(c.Writer)
	defer csvWriter.Flush()

	for record := range ch {
		if err := csvWriter.Write(record); err != nil {
			s.logger.Error("Failed to write CSV row", zap.Error(err))
			return
		}
	}
}
