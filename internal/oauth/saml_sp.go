// Package oauth provides SAML Service Provider registration and management
package oauth

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// SAMLServiceProvider represents a registered Service Provider
type SAMLServiceProvider struct {
	ID                   string            `json:"id" db:"id"`
	Name                 string            `json:"name" db:"name"`
	Description          string            `json:"description" db:"description"`
	EntityID             string            `json:"entity_id" db:"entity_id"`
	ACSURL               string            `json:"acs_url" db:"acs_url"`
	SLOURL               string            `json:"slo_url,omitempty" db:"slo_url"`
	MetadataURL          string            `json:"metadata_url,omitempty" db:"metadata_url"`
	Certificate          string            `json:"certificate,omitempty" db:"certificate"`
	NameIDFormat         string            `json:"name_id_format" db:"name_id_format"`
	AttributeMappings    map[string]string `json:"attribute_mappings,omitempty" db:"attribute_mappings"`
	WantAssertionsSigned bool              `json:"want_assertions_signed" db:"want_assertions_signed"`
	EncryptionEnabled    bool              `json:"encryption_enabled" db:"encryption_enabled"`
	Enabled              bool              `json:"enabled" db:"enabled"`
	CreatedAt            time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at" db:"updated_at"`
	LastUsedAt           *time.Time        `json:"last_used_at,omitempty" db:"last_used_at"`
}

// CreateSAMLServiceProviderRequest is the request to create a new SP
type CreateSAMLServiceProviderRequest struct {
	Name                 string            `json:"name" binding:"required"`
	Description          string            `json:"description"`
	EntityID             string            `json:"entity_id" binding:"required"`
	ACSURL               string            `json:"acs_url" binding:"required"`
	SLOURL               string            `json:"slo_url"`
	MetadataURL          string            `json:"metadata_url"`
	Certificate          string            `json:"certificate"`
	NameIDFormat         string            `json:"name_id_format"`
	AttributeMappings    map[string]string `json:"attribute_mappings"`
	WantAssertionsSigned bool              `json:"want_assertions_signed"`
	EncryptionEnabled    bool              `json:"encryption_enabled"`
	// Enabled is a POINTER on purpose. As a plain bool, a request that simply
	// omits the field decodes to Go's zero value (false) and is written to the
	// column verbatim, silently overriding its DEFAULT true -- so every SP
	// created by the admin console (whose form has no enable switch) was born
	// disabled. Measured on the live database: both existing rows have
	// enabled=f, including one created through the UI. nil now means "not
	// specified", and the default is enabled.
	Enabled     *bool  `json:"enabled"`
	MetadataXML string `json:"metadata_xml"` // For uploading metadata directly
}

// UpdateSAMLServiceProviderRequest is the request to update an SP
type UpdateSAMLServiceProviderRequest struct {
	Name                 *string           `json:"name"`
	Description          *string           `json:"description"`
	EntityID             *string           `json:"entity_id"`
	ACSURL               *string           `json:"acs_url"`
	SLOURL               *string           `json:"slo_url"`
	MetadataURL          *string           `json:"metadata_url"`
	Certificate          *string           `json:"certificate"`
	NameIDFormat         *string           `json:"name_id_format"`
	AttributeMappings    map[string]string `json:"attribute_mappings"`
	WantAssertionsSigned *bool             `json:"want_assertions_signed"`
	EncryptionEnabled    *bool             `json:"encryption_enabled"`
	Enabled              *bool             `json:"enabled"`
}

// boolPtr returns a pointer to b, for request fields where "unset" and
// "false" must stay distinguishable.
func boolPtr(b bool) *bool { return &b }

// resolveSPEnabled turns the tri-state request field into the value written to
// the column: nil means the caller did not specify, and a new SP is enabled.
// This lives in one place so the rule is testable rather than restated at each
// call site (a test that re-implements the rule proves only that the test
// agrees with itself).
func resolveSPEnabled(requested *bool) bool {
	if requested == nil {
		return true
	}
	return *requested
}

// SAMLServiceProviderListResponse is the paginated list response.
//
// The list is emitted under BOTH "service_providers" and "providers". The
// admin console reads "service_providers" and always has; this handler only
// ever sent "providers", so every registration succeeded and the list stayed
// empty ("No SAML service providers found") with no error anywhere -- the
// worst shape of bug, because the UI looks healthy and the data looks lost.
// Emitting both keeps any existing consumer of "providers" working, so this
// is additive rather than a rename that breaks the other half.
type SAMLServiceProviderListResponse struct {
	ServiceProviders []SAMLServiceProvider `json:"service_providers"`
	// Deprecated: kept so an existing client of this field keeps working.
	Providers []SAMLServiceProvider `json:"providers"`
	Total     int64                 `json:"total"`
	Page      int                   `json:"page"`
	PageSize  int                   `json:"page_size"`
}

// handleListSAMLServiceProviders lists all registered SPs with pagination
// GET /api/v1/saml/service-providers
func (s *Service) handleListSAMLServiceProviders(c *gin.Context) {
	// Parse pagination parameters
	page := getIntParam(c, "page", 1)
	pageSize := getIntParam(c, "page_size", 20)
	enabledOnly := c.Query("enabled") == "true"
	search := c.Query("search")

	offset := (page - 1) * pageSize

	// Build query
	query := `SELECT id, name, description, entity_id, acs_url, slo_url, metadata_url,
	          certificate, name_id_format, attribute_mappings, want_assertions_signed,
	          encryption_enabled, enabled, created_at, updated_at, last_used_at
	          FROM saml_service_providers`
	countQuery := `SELECT COUNT(*) FROM saml_service_providers`

	args := []interface{}{}
	whereClause := ""

	if enabledOnly {
		whereClause = " WHERE enabled = true"
	}

	if search != "" {
		if whereClause == "" {
			whereClause = " WHERE"
		} else {
			whereClause += " AND"
		}
		whereClause += " (name ILIKE $1 OR description ILIKE $1 OR entity_id ILIKE $1)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern)
	}

	query += whereClause + " ORDER BY name ASC LIMIT $" + fmt.Sprint(len(args)+1) + " OFFSET $" + fmt.Sprint(len(args)+2)
	countQuery += whereClause

	args = append(args, pageSize, offset)

	// Get total count
	var total int64
	if len(args) > 2 {
		countArgs := args[:len(args)-2]
		err := s.db.Pool.QueryRow(c.Request.Context(), countQuery, countArgs...).Scan(&total)
		if err != nil {
			s.logger.Error("Failed to count SAML service providers", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service providers"})
			return
		}
	} else {
		err := s.db.Pool.QueryRow(c.Request.Context(), countQuery).Scan(&total)
		if err != nil {
			s.logger.Error("Failed to count SAML service providers", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service providers"})
			return
		}
	}

	// Query providers
	rows, err := s.db.Pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to list SAML service providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service providers"})
		return
	}
	defer rows.Close()

	providers, err := scanSAMLServiceProviders(rows)
	if err != nil {
		s.logger.Error("Failed to scan SAML service providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan service providers"})
		return
	}

	c.JSON(http.StatusOK, SAMLServiceProviderListResponse{
		ServiceProviders: providers,
		Providers:        providers,
		Total:            total,
		Page:             page,
		PageSize:         pageSize,
	})
}

// handleGetSAMLServiceProvider gets a single SP by ID
// GET /api/v1/saml/service-providers/:id
func (s *Service) handleGetSAMLServiceProvider(c *gin.Context) {
	spID := c.Param("id")

	sp, err := s.getSAMLServiceProviderByID(c.Request.Context(), spID)
	if err != nil {
		if errors.Is(err, ErrSPNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service provider not found"})
			return
		}
		s.logger.Error("Failed to get SAML service provider", zap.Error(err), zap.String("id", spID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get service provider"})
		return
	}

	c.JSON(http.StatusOK, sp)
}

// handleCreateSAMLServiceProvider creates a new SP registration
// POST /api/v1/saml/service-providers
func (s *Service) handleCreateSAMLServiceProvider(c *gin.Context) {
	var req CreateSAMLServiceProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	// If metadata XML is provided, parse it to extract configuration
	if req.MetadataXML != "" {
		if err := s.parseMetadataIntoRequest(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metadata XML", "details": err.Error()})
			return
		}
	}

	// If metadata URL is provided, fetch it
	if req.MetadataURL != "" && req.MetadataXML == "" {
		metadata, err := s.FetchSAMLMetadata(c.Request.Context(), req.MetadataURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to fetch metadata", "details": err.Error()})
			return
		}

		// Extract info from metadata
		if req.EntityID == "" {
			req.EntityID = metadata.EntityID
		}
		if len(metadata.SPSSODescriptor.AssertionConsumerServices) > 0 && req.ACSURL == "" {
			req.ACSURL = metadata.SPSSODescriptor.AssertionConsumerServices[0].Location
		}
		if len(metadata.SPSSODescriptor.KeyDescriptors) > 0 && req.Certificate == "" {
			for _, kd := range metadata.SPSSODescriptor.KeyDescriptors {
				if kd.Use == "signing" {
					req.Certificate = kd.KeyInfo.X509Data.X509Certificate
					break
				}
			}
		}
	}

	// Validate required fields
	if req.NameIDFormat == "" {
		req.NameIDFormat = NameIDFormatEmail
	}

	// Check for duplicate entity ID
	var exists bool
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM saml_service_providers WHERE entity_id = $1)",
		req.EntityID).Scan(&exists)
	if err == nil && exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Service provider with this entity ID already exists"})
		return
	}

	// Create the SP
	sp, err := s.createSAMLServiceProvider(c.Request.Context(), &req)
	if err != nil {
		s.logger.Error("Failed to create SAML service provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service provider"})
		return
	}

	s.logger.Info("Created SAML service provider",
		zap.String("id", sp.ID),
		zap.String("name", sp.Name),
		zap.String("entity_id", sp.EntityID),
	)

	c.JSON(http.StatusCreated, sp)
}

// handleUpdateSAMLServiceProvider updates an existing SP registration
// PUT /api/v1/saml/service-providers/:id
func (s *Service) handleUpdateSAMLServiceProvider(c *gin.Context) {
	spID := c.Param("id")

	var req UpdateSAMLServiceProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	sp, err := s.updateSAMLServiceProvider(c.Request.Context(), spID, &req)
	if err != nil {
		if errors.Is(err, ErrSPNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service provider not found"})
			return
		}
		s.logger.Error("Failed to update SAML service provider", zap.Error(err), zap.String("id", spID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update service provider"})
		return
	}

	s.logger.Info("Updated SAML service provider", zap.String("id", spID))

	c.JSON(http.StatusOK, sp)
}

// handleDeleteSAMLServiceProvider deletes an SP registration
// DELETE /api/v1/saml/service-providers/:id
func (s *Service) handleDeleteSAMLServiceProvider(c *gin.Context) {
	spID := c.Param("id")

	err := s.deleteSAMLServiceProvider(c.Request.Context(), spID)
	if err != nil {
		if errors.Is(err, ErrSPNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service provider not found"})
			return
		}
		s.logger.Error("Failed to delete SAML service provider", zap.Error(err), zap.String("id", spID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service provider"})
		return
	}

	s.logger.Info("Deleted SAML service provider", zap.String("id", spID))

	c.JSON(http.StatusOK, gin.H{"message": "Service provider deleted"})
}

// handleRotateSPCertificate rotates the certificate for an SP
// POST /api/v1/saml/service-providers/:id/rotate-certificate
func (s *Service) handleRotateSPCertificate(c *gin.Context) {
	spID := c.Param("id")

	var req struct {
		Certificate string `json:"certificate" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	now := time.Now()
	result, err := s.db.Pool.Exec(c.Request.Context(), `
		UPDATE saml_service_providers
		SET certificate = $1, updated_at = $2
		WHERE id = $3
	`, req.Certificate, now, spID)

	if err != nil {
		s.logger.Error("Failed to rotate SP certificate", zap.Error(err), zap.String("id", spID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate certificate"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service provider not found"})
		return
	}

	s.logger.Info("Rotated SAML SP certificate", zap.String("id", spID))

	c.JSON(http.StatusOK, gin.H{"message": "Certificate rotated successfully"})
}

// handleImportSAMLMetadata imports an SP from its metadata
// POST /api/v1/saml/service-providers/import-metadata
func (s *Service) handleImportSAMLMetadata(c *gin.Context) {
	var req struct {
		MetadataURL string `json:"metadata_url"`
		MetadataXML string `json:"metadata_xml"`
		Name        string `json:"name"` // Optional override name
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	var metadata *SPMetadata
	var err error

	// Get metadata from URL or direct XML
	if req.MetadataURL != "" {
		metadata, err = s.FetchSAMLMetadata(c.Request.Context(), req.MetadataURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to fetch metadata", "details": err.Error()})
			return
		}
	} else if req.MetadataXML != "" {
		metadata, err = s.parseSPMetadata(req.MetadataXML)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse metadata", "details": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either metadata_url or metadata_xml is required"})
		return
	}

	// Validate metadata
	if err := ValidateSAMLMetadata(metadata); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metadata", "details": err.Error()})
		return
	}

	// Extract certificate if available
	var certificate string
	if len(metadata.SPSSODescriptor.KeyDescriptors) > 0 {
		for _, kd := range metadata.SPSSODescriptor.KeyDescriptors {
			if kd.Use == "signing" {
				certificate = kd.KeyInfo.X509Data.X509Certificate
				break
			}
		}
	}

	// Create SP from metadata
	createReq := &CreateSAMLServiceProviderRequest{
		Name:                 req.Name,
		Description:          "Imported from SAML metadata",
		EntityID:             metadata.EntityID,
		ACSURL:               metadata.SPSSODescriptor.AssertionConsumerServices[0].Location,
		MetadataURL:          req.MetadataURL,
		Certificate:          certificate,
		WantAssertionsSigned: metadata.SPSSODescriptor.WantAssertionsSigned,
		Enabled:              boolPtr(true),
		MetadataXML:          req.MetadataXML,
	}

	// Use entity ID as name if not provided
	if createReq.Name == "" {
		createReq.Name = metadata.EntityID
	}

	// Extract SLO URL if available
	if len(metadata.SPSSODescriptor.SingleLogoutServices) > 0 {
		createReq.SLOURL = metadata.SPSSODescriptor.SingleLogoutServices[0].Location
	}

	sp, err := s.createSAMLServiceProvider(c.Request.Context(), createReq)
	if err != nil {
		s.logger.Error("Failed to create SP from metadata", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to import service provider"})
		return
	}

	s.logger.Info("Imported SAML service provider from metadata",
		zap.String("id", sp.ID),
		zap.String("entity_id", sp.EntityID),
	)

	c.JSON(http.StatusCreated, sp)
}

// Database operations

// getSAMLServiceProviderByID retrieves an SP by ID
func (s *Service) getSAMLServiceProviderByID(ctx context.Context, id string) (*SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	var sloURL, metadataURL, certificate *string
	var attrMappingsJSON []byte
	var lastUsedAt *time.Time

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description, ''), entity_id, acs_url, slo_url, metadata_url,
		       certificate, name_id_format, attribute_mappings, want_assertions_signed,
		       encryption_enabled, enabled, created_at, updated_at, last_used_at
		FROM saml_service_providers
		WHERE id = $1
	`, id).Scan(&sp.ID, &sp.Name, &sp.Description, &sp.EntityID, &sp.ACSURL, &sloURL,
		&metadataURL, &certificate, &sp.NameIDFormat, &attrMappingsJSON,
		&sp.WantAssertionsSigned, &sp.EncryptionEnabled, &sp.Enabled,
		&sp.CreatedAt, &sp.UpdatedAt, &lastUsedAt)

	if err != nil {
		return nil, ErrSPNotFound
	}

	if sloURL != nil {
		sp.SLOURL = *sloURL
	}
	if metadataURL != nil {
		sp.MetadataURL = *metadataURL
	}
	if certificate != nil {
		sp.Certificate = *certificate
	}
	if lastUsedAt != nil {
		sp.LastUsedAt = lastUsedAt
	}
	if len(attrMappingsJSON) > 0 {
		_ = json.Unmarshal(attrMappingsJSON, &sp.AttributeMappings)
	}

	return &sp, nil
}

// getSAMLServiceProviderByEntityID retrieves an SP by its entity ID
func (s *Service) getSAMLServiceProviderByEntityID(ctx context.Context, entityID string) (*SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	var sloURL, metadataURL, certificate *string
	var attrMappingsJSON []byte
	var lastUsedAt *time.Time

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description, ''), entity_id, acs_url, slo_url, metadata_url,
		       certificate, name_id_format, attribute_mappings, want_assertions_signed,
		       encryption_enabled, enabled, created_at, updated_at, last_used_at
		FROM saml_service_providers
		WHERE entity_id = $1
	`, entityID).Scan(&sp.ID, &sp.Name, &sp.Description, &sp.EntityID, &sp.ACSURL, &sloURL,
		&metadataURL, &certificate, &sp.NameIDFormat, &attrMappingsJSON,
		&sp.WantAssertionsSigned, &sp.EncryptionEnabled, &sp.Enabled,
		&sp.CreatedAt, &sp.UpdatedAt, &lastUsedAt)

	if err != nil {
		return nil, ErrSPNotFound
	}

	if sloURL != nil {
		sp.SLOURL = *sloURL
	}
	if metadataURL != nil {
		sp.MetadataURL = *metadataURL
	}
	if certificate != nil {
		sp.Certificate = *certificate
	}
	if lastUsedAt != nil {
		sp.LastUsedAt = lastUsedAt
	}
	if len(attrMappingsJSON) > 0 {
		_ = json.Unmarshal(attrMappingsJSON, &sp.AttributeMappings)
	}

	return &sp, nil
}

// createSAMLServiceProvider creates a new SP in the database
func (s *Service) createSAMLServiceProvider(ctx context.Context, req *CreateSAMLServiceProviderRequest) (*SAMLServiceProvider, error) {
	id := uuid.New().String()
	enabled := resolveSPEnabled(req.Enabled)

	attrMappingsJSON, _ := json.Marshal(req.AttributeMappings)
	now := time.Now()

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO saml_service_providers (
			id, name, description, entity_id, acs_url, slo_url, metadata_url,
			certificate, name_id_format, attribute_mappings, want_assertions_signed,
			encryption_enabled, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`, id, req.Name, req.Description, req.EntityID, req.ACSURL, req.SLOURL,
		req.MetadataURL, req.Certificate, req.NameIDFormat, attrMappingsJSON,
		req.WantAssertionsSigned, req.EncryptionEnabled, enabled, now, now)

	if err != nil {
		return nil, err
	}

	return &SAMLServiceProvider{
		ID:                   id,
		Name:                 req.Name,
		Description:          req.Description,
		EntityID:             req.EntityID,
		ACSURL:               req.ACSURL,
		SLOURL:               req.SLOURL,
		MetadataURL:          req.MetadataURL,
		Certificate:          req.Certificate,
		NameIDFormat:         req.NameIDFormat,
		AttributeMappings:    req.AttributeMappings,
		WantAssertionsSigned: req.WantAssertionsSigned,
		EncryptionEnabled:    req.EncryptionEnabled,
		Enabled:              enabled,
		CreatedAt:            now,
		UpdatedAt:            now,
	}, nil
}

// samlSPUpdatableColumns is the closed allow-list of columns
// updateSAMLServiceProvider is permitted to touch. The builder below
// rejects anything else even if a future bug tries to wire it in.
// updated_at is appended unconditionally and is therefore in the set too.
var samlSPUpdatableColumns = map[string]struct{}{
	"name":                   {},
	"description":            {},
	"entity_id":              {},
	"acs_url":                {},
	"slo_url":                {},
	"metadata_url":           {},
	"certificate":            {},
	"name_id_format":         {},
	"attribute_mappings":     {},
	"want_assertions_signed": {},
	"encryption_enabled":     {},
	"enabled":                {},
	"updated_at":             {},
}

// samlSPColumnRE is the runtime defense-in-depth check on column names.
// PostgreSQL identifiers are at most 63 chars and SQL-safe identifiers
// are [A-Za-z_][A-Za-z0-9_]*; we keep it lowercase to match our schema.
var samlSPColumnRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// updateSAMLServiceProvider updates an existing SP
func (s *Service) updateSAMLServiceProvider(ctx context.Context, id string, req *UpdateSAMLServiceProviderRequest) (*SAMLServiceProvider, error) {
	// Get existing SP
	sp, err := s.getSAMLServiceProviderByID(ctx, id)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	// Single source of truth for the (column → value, set?) mapping. By
	// pulling every column literal into one slice we kill the previous
	// pattern of scattered `fmt.Sprintf("column = $%d", argIdx)` calls in
	// if-blocks — any new column has to be added here, declared in
	// samlSPUpdatableColumns, AND go through the runtime allow-list check
	// in buildUpdateClause below.
	attrJSON, _ := json.Marshal(req.AttributeMappings)
	fields := []sqlUpdateField{
		{col: "name", val: derefStr(req.Name), set: req.Name != nil},
		{col: "description", val: derefStr(req.Description), set: req.Description != nil},
		{col: "entity_id", val: derefStr(req.EntityID), set: req.EntityID != nil},
		{col: "acs_url", val: derefStr(req.ACSURL), set: req.ACSURL != nil},
		{col: "slo_url", val: derefStr(req.SLOURL), set: req.SLOURL != nil},
		{col: "metadata_url", val: derefStr(req.MetadataURL), set: req.MetadataURL != nil},
		{col: "certificate", val: derefStr(req.Certificate), set: req.Certificate != nil},
		{col: "name_id_format", val: derefStr(req.NameIDFormat), set: req.NameIDFormat != nil},
		{col: "attribute_mappings", val: attrJSON, set: req.AttributeMappings != nil},
		{col: "want_assertions_signed", val: derefBool(req.WantAssertionsSigned), set: req.WantAssertionsSigned != nil},
		{col: "encryption_enabled", val: derefBool(req.EncryptionEnabled), set: req.EncryptionEnabled != nil},
		{col: "enabled", val: derefBool(req.Enabled), set: req.Enabled != nil},
	}

	setClauses, args, err := buildUpdateClause(fields, samlSPUpdatableColumns, samlSPColumnRE)
	if err != nil {
		return nil, err
	}
	if len(setClauses) == 0 {
		return sp, nil
	}

	// updated_at is always written when there's at least one user-driven
	// column to update.
	setClauses = append(setClauses, "updated_at = $"+strconv.Itoa(len(args)+1))
	args = append(args, now)
	args = append(args, id)

	// Mirror the requested changes onto the returned struct now that we
	// know we'll execute the UPDATE.
	if req.Name != nil {
		sp.Name = *req.Name
	}
	if req.Description != nil {
		sp.Description = *req.Description
	}
	if req.EntityID != nil {
		sp.EntityID = *req.EntityID
	}
	if req.ACSURL != nil {
		sp.ACSURL = *req.ACSURL
	}
	if req.SLOURL != nil {
		sp.SLOURL = *req.SLOURL
	}
	if req.MetadataURL != nil {
		sp.MetadataURL = *req.MetadataURL
	}
	if req.Certificate != nil {
		sp.Certificate = *req.Certificate
	}
	if req.NameIDFormat != nil {
		sp.NameIDFormat = *req.NameIDFormat
	}
	if req.AttributeMappings != nil {
		sp.AttributeMappings = req.AttributeMappings
	}
	if req.WantAssertionsSigned != nil {
		sp.WantAssertionsSigned = *req.WantAssertionsSigned
	}
	if req.EncryptionEnabled != nil {
		sp.EncryptionEnabled = *req.EncryptionEnabled
	}
	if req.Enabled != nil {
		sp.Enabled = *req.Enabled
	}

	// Table name + WHERE column are package-literal strings. The
	// SET clause comes from setClauses, every entry of which has been
	// allow-listed by buildUpdateClause.
	query := "UPDATE saml_service_providers SET " + strings.Join(setClauses, ", ") +
		" WHERE id = $" + strconv.Itoa(len(args))

	_, err = s.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	sp.UpdatedAt = now
	return sp, nil
}

// derefStr returns *p (or "" for nil). Used by the SQL update builder
// above to flatten *string columns into the args slice without inline
// dereferences.
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// derefBool — see derefStr.
func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

// deleteSAMLServiceProvider deletes an SP
func (s *Service) deleteSAMLServiceProvider(ctx context.Context, id string) error {
	result, err := s.db.Pool.Exec(ctx, "DELETE FROM saml_service_providers WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrSPNotFound
	}
	return nil
}

// Helper functions

// scanSAMLServiceProviders scans a rowset into SAMLServiceProvider structs
func scanSAMLServiceProviders(rows pgx.Rows) ([]SAMLServiceProvider, error) {
	// The list query selects, in order:
	//   id, name, description, entity_id, acs_url, slo_url, metadata_url,
	//   certificate, name_id_format, attribute_mappings, want_assertions_signed,
	//   encryption_enabled, enabled, created_at, updated_at, last_used_at
	// slo_url / metadata_url / certificate / last_used_at are nullable, and
	// description may be NULL — scan them via pointers/COALESCE-equivalents so a
	// NULL doesn't fail the scan (which previously left the whole list nil).
	providers := []SAMLServiceProvider{}
	for rows.Next() {
		var sp SAMLServiceProvider
		var description, sloURL, metadataURL, certificate *string
		var attrMappingsJSON []byte
		var lastUsedAt *time.Time

		if err := rows.Scan(
			&sp.ID, &sp.Name, &description, &sp.EntityID, &sp.ACSURL, &sloURL,
			&metadataURL, &certificate, &sp.NameIDFormat, &attrMappingsJSON,
			&sp.WantAssertionsSigned, &sp.EncryptionEnabled, &sp.Enabled,
			&sp.CreatedAt, &sp.UpdatedAt, &lastUsedAt,
		); err != nil {
			return nil, err
		}

		if description != nil {
			sp.Description = *description
		}
		if sloURL != nil {
			sp.SLOURL = *sloURL
		}
		if metadataURL != nil {
			sp.MetadataURL = *metadataURL
		}
		if certificate != nil {
			sp.Certificate = *certificate
		}
		if lastUsedAt != nil {
			sp.LastUsedAt = lastUsedAt
		}
		if len(attrMappingsJSON) > 0 {
			_ = json.Unmarshal(attrMappingsJSON, &sp.AttributeMappings)
		}
		providers = append(providers, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return providers, nil
}

// parseMetadataIntoRequest extracts SP configuration from metadata XML
func (s *Service) parseMetadataIntoRequest(req *CreateSAMLServiceProviderRequest) error {
	metadata, err := s.parseSPMetadata(req.MetadataXML)
	if err != nil {
		return err
	}

	// Extract entity ID
	if metadata.EntityID != "" && req.EntityID == "" {
		req.EntityID = metadata.EntityID
	}

	// Extract ACS URL
	if len(metadata.SPSSODescriptor.AssertionConsumerServices) > 0 && req.ACSURL == "" {
		req.ACSURL = metadata.SPSSODescriptor.AssertionConsumerServices[0].Location
	}

	// Extract SLO URL
	if len(metadata.SPSSODescriptor.SingleLogoutServices) > 0 && req.SLOURL == "" {
		req.SLOURL = metadata.SPSSODescriptor.SingleLogoutServices[0].Location
	}

	// Extract certificate
	if len(metadata.SPSSODescriptor.KeyDescriptors) > 0 && req.Certificate == "" {
		for _, kd := range metadata.SPSSODescriptor.KeyDescriptors {
			if kd.Use == "signing" {
				req.Certificate = kd.KeyInfo.X509Data.X509Certificate
				break
			}
		}
	}

	// Extract WantAssertionsSigned
	req.WantAssertionsSigned = metadata.SPSSODescriptor.WantAssertionsSigned

	return nil
}

// parseSPMetadata parses SP metadata XML into a struct
func (s *Service) parseSPMetadata(xmlData string) (*SPMetadata, error) {
	var metadata SPMetadata
	if err := xml.Unmarshal([]byte(xmlData), &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata XML: %w", err)
	}
	return &metadata, nil
}

// getIntParam gets an integer query parameter with a default value
func getIntParam(c *gin.Context, key string, defaultValue int) int {
	value := c.Query(key)
	if value == "" {
		return defaultValue
	}
	var result int
	if _, err := fmt.Sscanf(value, "%d", &result); err != nil {
		return defaultValue
	}
	return result
}
