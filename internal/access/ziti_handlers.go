// Package access - HTTP handlers for OpenZiti management endpoints
package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ---- Ziti Status ----

// zitiConsoleURL returns the browser-facing URL of the controller-hosted ZAC
// console. An explicit ZITI_CONSOLE_URL wins (needed when the browser reaches
// the controller on a mapped host/port); otherwise it is derived from the
// effective controller URL as <ctrl>/zac/. Empty when nothing is configured.
func (s *Service) zitiConsoleURL(ctx context.Context) string {
	if s.config != nil && s.config.ZitiConsoleURL != "" {
		return s.config.ZitiConsoleURL
	}
	ctrlURL, _, _, _, _, _, err := s.buildZitiConnParams(ctx)
	if err != nil || ctrlURL == "" {
		return ""
	}
	return strings.TrimRight(ctrlURL, "/") + "/zac/"
}

func (s *Service) handleZitiStatus(c *gin.Context) {
	consoleURL := s.zitiConsoleURL(c.Request.Context())
	if s.ziti() == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":     false,
			"message":     "OpenZiti integration is not configured",
			"sdk_ready":   false,
			"console_url": consoleURL,
		})
		return
	}

	status := gin.H{
		"enabled":     true,
		"sdk_ready":   s.ziti().IsInitialized(),
		"console_url": consoleURL,
	}

	// Check controller connectivity
	version, err := s.ziti().GetControllerVersion(c.Request.Context())
	if err != nil {
		status["controller_reachable"] = false
		status["controller_error"] = err.Error()
	} else {
		status["controller_reachable"] = true
		status["controller_version"] = version
	}

	// Management endpoint pool (HA failover state). ha=true when more than one
	// controller endpoint is configured via ZITI_CTRL_URLS.
	endpoints := s.ziti().ControllerEndpoints()
	status["controller_endpoints"] = endpoints
	status["ha"] = len(endpoints) > 1

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Count local DB records
	var serviceCount, identityCount int
	if err := s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM ziti_services WHERE org_id = $1", org.ID).Scan(&serviceCount); err != nil {
		s.logger.Warn("Failed to count ziti services", zap.Error(err))
	}
	if err := s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM ziti_identities WHERE org_id = $1", org.ID).Scan(&identityCount); err != nil {
		s.logger.Warn("Failed to count ziti identities", zap.Error(err))
	}
	status["services_count"] = serviceCount
	status["identities_count"] = identityCount

	c.JSON(http.StatusOK, status)
}

// ---- Ziti Services ----

func (s *Service) handleListZitiServices(c *gin.Context) {
	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	// List services with BrowZer route info via LEFT JOIN
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT zs.id, zs.ziti_id, zs.name, zs.description, zs.protocol, zs.host, zs.port,
		        zs.route_id, zs.enabled, zs.created_at, zs.updated_at,
		        pr_path.from_url AS browzer_path_url,
		        pr_vhost.from_url AS browzer_domain_url
		 FROM ziti_services zs
		 LEFT JOIN proxy_routes pr_path ON pr_path.ziti_service_name = zs.name
		      AND pr_path.org_id = zs.org_id
		      AND pr_path.browzer_enabled = true AND pr_path.name LIKE 'browzer-%' AND pr_path.name NOT LIKE 'browzer-vhost-%'
		 LEFT JOIN proxy_routes pr_vhost ON pr_vhost.ziti_service_name = zs.name
		      AND pr_vhost.org_id = zs.org_id
		      AND pr_vhost.browzer_enabled = true AND pr_vhost.name LIKE 'browzer-vhost-%'
		 WHERE zs.org_id = $1
		 ORDER BY zs.name`, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list ziti services"})
		return
	}
	defer rows.Close()

	type zitiServiceRow struct {
		ID            string    `json:"id"`
		ZitiID        string    `json:"ziti_id"`
		Name          string    `json:"name"`
		Description   *string   `json:"description,omitempty"`
		Protocol      string    `json:"protocol"`
		Host          string    `json:"host"`
		Port          int       `json:"port"`
		RouteID       *string   `json:"route_id,omitempty"`
		Enabled       bool      `json:"enabled"`
		CreatedAt     time.Time `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
		BrowzerPath   string    `json:"browzer_path,omitempty"`
		BrowzerDomain string    `json:"browzer_domain,omitempty"`
	}

	services := []zitiServiceRow{}
	for rows.Next() {
		var svc zitiServiceRow
		var browzerPathURL, browzerDomainURL *string
		err := rows.Scan(&svc.ID, &svc.ZitiID, &svc.Name, &svc.Description, &svc.Protocol,
			&svc.Host, &svc.Port, &svc.RouteID, &svc.Enabled, &svc.CreatedAt, &svc.UpdatedAt,
			&browzerPathURL, &browzerDomainURL)
		if err != nil {
			s.logger.Error("Failed to scan ziti service", zap.Error(err))
			continue
		}
		// Extract path from URL like "http://browzer.localtest.me/apisix"
		if browzerPathURL != nil && *browzerPathURL != "" {
			if u, err := url.Parse(*browzerPathURL); err == nil {
				svc.BrowzerPath = u.Path
			}
		}
		// Extract domain from URL like "http://apisix.localtest.me/"
		if browzerDomainURL != nil && *browzerDomainURL != "" {
			if u, err := url.Parse(*browzerDomainURL); err == nil {
				svc.BrowzerDomain = u.Hostname()
			}
		}
		services = append(services, svc)
	}

	c.JSON(http.StatusOK, gin.H{"services": services})
}

func (s *Service) handleCreateZitiService(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		Protocol    string   `json:"protocol"`
		Host        string   `json:"host" binding:"required"`
		Port        int      `json:"port" binding:"required"`
		Attributes  []string `json:"attributes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "protocol must be 'tcp' or 'udp'"})
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "port must be between 1 and 65535"})
		return
	}

	attrs := req.Attributes
	if attrs == nil {
		attrs = []string{req.Name}
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	zitiID, err := s.ziti().CreateService(c.Request.Context(), req.Name, attrs)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to create ziti service", err), s.logger)
		return
	}

	// Persist to DB
	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO ziti_services (ziti_id, name, description, protocol, host, port, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		zitiID, req.Name, req.Description, req.Protocol, req.Host, req.Port, org.ID).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to persist ziti service to DB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "service created in Ziti but failed to persist locally"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"ziti_id": zitiID,
		"name":    req.Name,
		"message": "ziti service created",
	})
}

func (s *Service) handleDeleteZitiService(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Get ziti_id from DB
	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id FROM ziti_services WHERE id=$1 AND org_id=$2", id, org.ID).Scan(&zitiID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti service not found"})
		return
	}

	// Delete from Ziti controller
	if err := s.ziti().DeleteService(c.Request.Context(), zitiID); err != nil {
		s.logger.Error("Failed to delete ziti service from controller", zap.Error(err))
		// Continue to delete from DB anyway
	}

	// Clean up any BrowZer proxy_routes linked to this service
	var serviceName string
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT name FROM ziti_services WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&serviceName); err == nil && serviceName != "" {
		s.db.Pool.Exec(c.Request.Context(),
			`DELETE FROM proxy_routes WHERE ziti_service_name = $1 AND browzer_enabled = true AND org_id = $2`, serviceName, org.ID)
	}

	// Delete from DB
	s.db.Pool.Exec(c.Request.Context(), "DELETE FROM ziti_services WHERE id=$1 AND org_id=$2", id, org.ID)

	c.JSON(http.StatusOK, gin.H{"message": "ziti service deleted"})
}

// ---- Ziti Identities ----

func (s *Service) handleListZitiIdentities(c *gin.Context) {
	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(),
		// The identity `name` is the user's UUID (it is the stable linking key to
		// the Ziti controller / BrowZer OIDC sub — see ziti_user_sync.go). Join
		// the user so the UI can show a human-readable display_name instead of the
		// raw UUID, without changing the controller-facing name.
		`SELECT zi.id, zi.ziti_id, zi.name, zi.identity_type, zi.user_id, zi.enrolled,
		        zi.attributes, zi.created_at, zi.updated_at,
		        COALESCE(NULLIF(TRIM(CONCAT_WS(' ', u.first_name, u.last_name)), ''),
		                 NULLIF(u.username, ''), NULLIF(u.email, '')) AS display_name
		 FROM ziti_identities zi
		 LEFT JOIN users u ON u.id = zi.user_id
		 WHERE zi.org_id = $1 ORDER BY display_name NULLS LAST, zi.name`, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list ziti identities"})
		return
	}
	defer rows.Close()

	type zitiIdentityRow struct {
		ID           string    `json:"id"`
		ZitiID       string    `json:"ziti_id"`
		Name         string    `json:"name"`
		DisplayName  string    `json:"display_name"`
		IdentityType string    `json:"identity_type"`
		UserID       *string   `json:"user_id,omitempty"`
		Enrolled     bool      `json:"enrolled"`
		Attributes   []string  `json:"attributes"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
	}

	identities := []zitiIdentityRow{}
	for rows.Next() {
		var ident zitiIdentityRow
		var attrs []byte
		var displayName *string
		err := rows.Scan(&ident.ID, &ident.ZitiID, &ident.Name, &ident.IdentityType,
			&ident.UserID, &ident.Enrolled, &attrs, &ident.CreatedAt, &ident.UpdatedAt, &displayName)
		if err != nil {
			s.logger.Error("Failed to scan ziti identity", zap.Error(err))
			continue
		}
		json.Unmarshal(attrs, &ident.Attributes)
		// Fall back to the name (UUID) only when there's no linked user to name.
		if displayName != nil && *displayName != "" {
			ident.DisplayName = *displayName
		} else {
			ident.DisplayName = ident.Name
		}
		identities = append(identities, ident)
	}

	c.JSON(http.StatusOK, gin.H{"identities": identities})
}

func (s *Service) handleCreateZitiIdentity(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	var req struct {
		Name         string   `json:"name" binding:"required"`
		IdentityType string   `json:"identity_type"`
		UserID       *string  `json:"user_id"`
		Attributes   []string `json:"attributes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.IdentityType == "" {
		req.IdentityType = "Device"
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	zitiID, enrollmentJWT, err := s.ziti().CreateIdentity(c.Request.Context(), req.Name, req.IdentityType, req.Attributes)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to create ziti identity", err), s.logger)
		return
	}

	attrsJSON, _ := json.Marshal(req.Attributes)

	// Persist to DB
	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, enrollment_jwt, attributes, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		zitiID, req.Name, req.IdentityType, req.UserID, enrollmentJWT, attrsJSON, org.ID).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to persist ziti identity to DB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "identity created in Ziti but failed to persist locally"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":             id,
		"ziti_id":        zitiID,
		"name":           req.Name,
		"enrollment_jwt": enrollmentJWT,
		"message":        "ziti identity created",
	})
}

func (s *Service) handleDeleteZitiIdentity(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id FROM ziti_identities WHERE id=$1 AND org_id=$2", id, org.ID).Scan(&zitiID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti identity not found"})
		return
	}

	if err := s.ziti().DeleteIdentity(c.Request.Context(), zitiID); err != nil {
		s.logger.Error("Failed to delete ziti identity from controller", zap.Error(err))
	}

	s.db.Pool.Exec(c.Request.Context(), "DELETE FROM ziti_identities WHERE id=$1 AND org_id=$2", id, org.ID)

	c.JSON(http.StatusOK, gin.H{"message": "ziti identity deleted"})
}

func (s *Service) handleGetEnrollmentJWT(c *gin.Context) {
	id := c.Param("id")

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var enrollmentJWT *string
	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id, enrollment_jwt FROM ziti_identities WHERE id=$1 AND org_id=$2", id, org.ID).Scan(&zitiID, &enrollmentJWT)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti identity not found"})
		return
	}

	if enrollmentJWT != nil && *enrollmentJWT != "" {
		c.JSON(http.StatusOK, gin.H{
			"enrollment_jwt": *enrollmentJWT,
			"ziti_id":        zitiID,
		})
		return
	}

	// Try to fetch from controller
	if s.ziti() != nil {
		jwt, err := s.ziti().GetIdentityEnrollmentJWT(c.Request.Context(), zitiID)
		if err == nil && jwt != "" {
			// Update DB
			s.db.Pool.Exec(c.Request.Context(),
				"UPDATE ziti_identities SET enrollment_jwt=$1 WHERE id=$2 AND org_id=$3", jwt, id, org.ID)
			c.JSON(http.StatusOK, gin.H{
				"enrollment_jwt": jwt,
				"ziti_id":        zitiID,
			})
			return
		}
	}

	c.JSON(http.StatusGone, gin.H{
		"error":   "enrollment JWT not available (identity may already be enrolled)",
		"ziti_id": zitiID,
	})
}

// ---- Enable/Disable Ziti on Routes ----

func (s *Service) handleEnableZitiOnRoute(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	routeID := c.Param("id")

	var req struct {
		ServiceName string `json:"service_name" binding:"required"`
		Host        string `json:"host" binding:"required"`
		Port        int    `json:"port" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify route exists
	_, err := s.getRouteByID(c.Request.Context(), routeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	if err := s.ziti().SetupZitiForRoute(c.Request.Context(), routeID, req.ServiceName, req.Host, req.Port); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to enable Ziti on route", err), s.logger)
		return
	}

	s.enqueueReconcile()

	s.logAuditEvent(c, "ziti_enabled_on_route", routeID, "proxy_route", map[string]interface{}{
		"service_name": req.ServiceName,
		"host":         req.Host,
		"port":         req.Port,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Ziti enabled on route", "service_name": req.ServiceName})
}

func (s *Service) handleDisableZitiOnRoute(c *gin.Context) {
	if s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	routeID := c.Param("id")

	// Verify route exists
	_, err := s.getRouteByID(c.Request.Context(), routeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	if err := s.ziti().TeardownZitiForRoute(c.Request.Context(), routeID); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to disable Ziti on route", err), s.logger)
		return
	}

	s.enqueueReconcile()

	s.logAuditEvent(c, "ziti_disabled_on_route", routeID, "proxy_route", nil)

	c.JSON(http.StatusOK, gin.H{"message": "Ziti disabled on route"})
}
