// Package access — Windows application delivery.
//
// Turns the RemoteApp launch path (pam_launch.go) into a real catalog. A host
// is an ordinary pam_entries row (entry_type windows_app_host); the app/pool
// layer (migration v119) sits on top:
//
//   - a windows_apps row publishes one app, bound to a single host OR a pool
//   - launching an app resolves a concrete host by placement (capacity across
//     the pool, honoring the GUACAMOLE-1951 one-session-per-user constraint),
//     then delegates to launchPamSession — reusing RBAC, approval, vault
//     injection, recording, Ziti reach and audit unchanged
//   - a placement conflict returns 409 with the sessions in the way, so the UI
//     can offer an explicit "disconnect and launch here" instead of silently
//     killing a session
package access

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// maxAppIconBytes caps the stored PNG icon. Small enough for row storage
// (unlike the WASM plan's rejected wasm_binary BYTEA) and to bound response
// size for the catalog.
const maxAppIconBytes = 32 * 1024

// windowsApp is the API view of a windows_apps row.
type windowsApp struct {
	ID              string `json:"id"`
	HostEntryID     string `json:"host_entry_id,omitempty"`
	HostName        string `json:"host_name,omitempty"`
	PoolID          string `json:"pool_id,omitempty"`
	PoolName        string `json:"pool_name,omitempty"`
	Alias           string `json:"alias"`
	DisplayName     string `json:"display_name"`
	ExecPath        string `json:"exec_path,omitempty"`
	Args            string `json:"args,omitempty"`
	WorkingDir      string `json:"working_dir,omitempty"`
	HasIcon         bool   `json:"has_icon"`
	Source          string `json:"source"`
	Verified        bool   `json:"verified"`
	Status          string `json:"status"`
	RequireApproval *bool  `json:"require_approval,omitempty"`
	RecordSession   *bool  `json:"record_session,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// windowsAppInput is the create/update request body.
type windowsAppInput struct {
	HostEntryID     string `json:"host_entry_id"`
	PoolID          string `json:"pool_id"`
	Alias           string `json:"alias"`
	DisplayName     string `json:"display_name"`
	ExecPath        string `json:"exec_path"`
	Args            string `json:"args"`
	WorkingDir      string `json:"working_dir"`
	RequireApproval *bool  `json:"require_approval"`
	RecordSession   *bool  `json:"record_session"`
}

// validate checks the input and returns a normalized alias (no "||" prefix).
func (in *windowsAppInput) validate() error {
	in.Alias = strings.TrimPrefix(strings.TrimSpace(in.Alias), "||")
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.Alias == "" {
		return errors.New("alias is required")
	}
	if in.DisplayName == "" {
		return errors.New("display_name is required")
	}
	if (in.HostEntryID == "") == (in.PoolID == "") {
		return errors.New("an app must target exactly one host or one pool")
	}
	// Same secret guard as entry save — args must never carry a password.
	if err := validateRemoteAppArgs(in.Args); err != nil {
		return err
	}
	return nil
}

// handleWindowsAppList — GET /pam/apps. Apps + pools + host posture in one shot.
func (s *Service) handleWindowsAppList(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	apps, err := s.listWindowsApps(ctx, org.ID)
	if err != nil {
		s.logger.Error("handleWindowsAppList: apps query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load apps"})
		return
	}
	pools, err := s.listWindowsAppPools(ctx, org.ID)
	if err != nil {
		s.logger.Error("handleWindowsAppList: pools query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load pools"})
		return
	}
	hostState, err := s.listWindowsAppHostState(ctx, org.ID)
	if err != nil {
		s.logger.Error("handleWindowsAppList: host state query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load host state"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"apps": apps, "pools": pools, "host_state": hostState})
}

func (s *Service) listWindowsApps(ctx context.Context, orgID string) ([]windowsApp, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, COALESCE(a.host_entry_id::text,''), COALESCE(he.name,''),
		       COALESCE(a.pool_id::text,''), COALESCE(p.name,''),
		       a.alias, a.display_name, COALESCE(a.exec_path,''), COALESCE(a.args,''),
		       COALESCE(a.working_dir,''), (a.icon_png IS NOT NULL),
		       a.source, (a.verified_at IS NOT NULL), a.status,
		       a.require_approval, a.record_session,
		       a.created_at, a.updated_at
		  FROM windows_apps a
		  LEFT JOIN pam_entries he ON he.id = a.host_entry_id
		  LEFT JOIN windows_app_pools p ON p.id = a.pool_id
		 WHERE a.org_id = $1
		 ORDER BY a.display_name ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []windowsApp{}
	for rows.Next() {
		var a windowsApp
		if err := rows.Scan(
			&a.ID, &a.HostEntryID, &a.HostName, &a.PoolID, &a.PoolName,
			&a.Alias, &a.DisplayName, &a.ExecPath, &a.Args, &a.WorkingDir, &a.HasIcon,
			&a.Source, &a.Verified, &a.Status, &a.RequireApproval, &a.RecordSession,
			&a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// handleWindowsAppCreate — POST /pam/apps (admin).
func (s *Service) handleWindowsAppCreate(c *gin.Context) {
	var in windowsAppInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := in.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if err := s.validateAppTarget(ctx, org.ID, in.HostEntryID, in.PoolID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id := uuid.New().String()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO windows_apps (id, org_id, host_entry_id, pool_id, alias, display_name,
		                          exec_path, args, working_dir, source, require_approval, record_session, created_by)
		VALUES ($1, $2, NULLIF($3,'')::uuid, NULLIF($4,'')::uuid, $5, $6,
		        NULLIF($7,''), NULLIF($8,''), NULLIF($9,''), 'manual', $10, $11, NULLIF($12,'')::uuid)`,
		id, org.ID, in.HostEntryID, in.PoolID, in.Alias, in.DisplayName,
		in.ExecPath, in.Args, in.WorkingDir, in.RequireApproval, in.RecordSession, c.GetString("user_id"))
	if err != nil {
		s.logger.Error("handleWindowsAppCreate: insert failed", zap.Error(err))
		c.JSON(http.StatusConflict, gin.H{"error": "failed to create app (duplicate alias on host?)"})
		return
	}
	s.logAuditEvent(c, "windows_app.created", id, "windows_app",
		map[string]interface{}{"alias": in.Alias, "display_name": in.DisplayName})
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// handleWindowsAppUpdate — PUT /pam/apps/:id (admin).
func (s *Service) handleWindowsAppUpdate(c *gin.Context) {
	var in windowsAppInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := in.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if err := s.validateAppTarget(ctx, org.ID, in.HostEntryID, in.PoolID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE windows_apps
		   SET host_entry_id = NULLIF($3,'')::uuid, pool_id = NULLIF($4,'')::uuid,
		       alias = $5, display_name = $6, exec_path = NULLIF($7,''),
		       args = NULLIF($8,''), working_dir = NULLIF($9,''),
		       require_approval = $10, record_session = $11, updated_at = NOW()
		 WHERE id = $1 AND org_id = $2`,
		c.Param("id"), org.ID, in.HostEntryID, in.PoolID, in.Alias, in.DisplayName,
		in.ExecPath, in.Args, in.WorkingDir, in.RequireApproval, in.RecordSession)
	if err != nil {
		s.logger.Error("handleWindowsAppUpdate: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update app"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}
	s.logAuditEvent(c, "windows_app.updated", c.Param("id"), "windows_app", nil)
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id")})
}

// handleWindowsAppDelete — DELETE /pam/apps/:id (admin).
func (s *Service) handleWindowsAppDelete(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM windows_apps WHERE id = $1 AND org_id = $2`, c.Param("id"), org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete app"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}
	s.logAuditEvent(c, "windows_app.deleted", c.Param("id"), "windows_app", nil)
	c.Status(http.StatusNoContent)
}

// handleWindowsAppIcon — GET /pam/apps/:id/icon. Returns the stored PNG.
func (s *Service) handleWindowsAppIcon(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var icon []byte
	err = s.db.Pool.QueryRow(ctx, `SELECT icon_png FROM windows_apps WHERE id = $1 AND org_id = $2`,
		c.Param("id"), org.ID).Scan(&icon)
	if err != nil || len(icon) == 0 {
		c.Status(http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "image/png", icon)
}

// validateAppTarget confirms the referenced host/pool exists in the org and
// (for a host) is a launchable session entry.
func (s *Service) validateAppTarget(ctx context.Context, orgID, hostEntryID, poolID string) error {
	if hostEntryID != "" {
		var entryType string
		err := s.db.Pool.QueryRow(ctx,
			`SELECT entry_type FROM pam_entries WHERE id = $1 AND org_id = $2`, hostEntryID, orgID).Scan(&entryType)
		if err != nil {
			return errors.New("host entry not found")
		}
		if t, ok := pamEntryTypeByName[entryType]; !ok || t.Kind != "session" || t.Protocol != "rdp" {
			return errors.New("host must be an RDP or Windows App Host entry")
		}
		return nil
	}
	var exists bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM windows_app_pools WHERE id = $1 AND org_id = $2)`, poolID, orgID).Scan(&exists); err != nil || !exists {
		return errors.New("pool not found")
	}
	return nil
}
