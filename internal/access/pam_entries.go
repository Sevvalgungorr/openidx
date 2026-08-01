// Package access — PAM connection manager (Devolutions RDM parity).
//
// The RDM-style entry tree over the M1–M5 PAM foundations: org-scoped folders
// and typed entries (remote sessions, credentials, secure information records)
// whose secret payloads are envelope-encrypted vault_secrets rows. Entries are
// permissioned per principal (view/connect/edit/reveal), can link a shared
// credential entry (RDM "linked credential"), and launch through the Guacamole
// broker with the credential injected server-side (pam_launch.go) — the user
// opens a remote session without ever seeing the password.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// ---- Entry-type catalog (RDM parity) ----

// PamEntryType describes one supported entry type. Kind partitions the
// catalog the way RDM does: "session" entries are launchable connections,
// "credential" entries hold reusable secrets other entries link to, and
// "info" entries are secure information records (notes, cards, licenses…).
type PamEntryType struct {
	Type        string `json:"type"`
	Kind        string `json:"kind"` // session | credential | info
	Label       string `json:"label"`
	Protocol    string `json:"protocol,omitempty"` // guacamole protocol for brokered session types
	SecretLabel string `json:"secret_label,omitempty"`
}

// pamEntryTypeCatalog enumerates every supported entry type. Order is the
// display order the console uses.
var pamEntryTypeCatalog = []PamEntryType{
	// Remote sessions — brokered through Guacamole with server-side credential injection.
	{Type: "rdp", Kind: "session", Label: "RDP Session", Protocol: "rdp", SecretLabel: "Password"},
	{Type: "ssh", Kind: "session", Label: "SSH Shell", Protocol: "ssh", SecretLabel: "Password or private key"},
	{Type: "vnc", Kind: "session", Label: "VNC Session", Protocol: "vnc", SecretLabel: "Password"},
	{Type: "telnet", Kind: "session", Label: "Telnet Session", Protocol: "telnet", SecretLabel: "Password"},
	// Website sessions launch by URL (no Guacamole brokering).
	{Type: "website", Kind: "session", Label: "Website", SecretLabel: "Password"},
	// Reusable credentials (RDM "Credential" entries; linkable from sessions).
	{Type: "credential", Kind: "credential", Label: "Credential (username/password)", SecretLabel: "Password"},
	{Type: "ssh_key", Kind: "credential", Label: "SSH Private Key", SecretLabel: "Private key"},
	{Type: "api_key", Kind: "credential", Label: "API Key", SecretLabel: "API key"},
	{Type: "certificate", Kind: "credential", Label: "Certificate", SecretLabel: "Certificate (PEM)"},
	// Secure information records (RDM "Information" entries).
	{Type: "secure_note", Kind: "info", Label: "Secure Note", SecretLabel: "Note body"},
	{Type: "website_login", Kind: "info", Label: "Website Login", SecretLabel: "Password"},
	{Type: "bank_account", Kind: "info", Label: "Bank Account", SecretLabel: "Account details"},
	{Type: "credit_card", Kind: "info", Label: "Credit Card", SecretLabel: "Card details"},
	{Type: "software_license", Kind: "info", Label: "Software License", SecretLabel: "License key"},
	{Type: "serial_number", Kind: "info", Label: "Serial Number", SecretLabel: "Serial"},
	{Type: "email_account", Kind: "info", Label: "Email Account", SecretLabel: "Password"},
	{Type: "alarm_code", Kind: "info", Label: "Alarm Code", SecretLabel: "Code"},
	{Type: "passport", Kind: "info", Label: "Passport", SecretLabel: "Passport details"},
	{Type: "drivers_license", Kind: "info", Label: "Driver's License", SecretLabel: "License details"},
	{Type: "wifi", Kind: "info", Label: "Wi-Fi", SecretLabel: "Wi-Fi password"},
	{Type: "phone", Kind: "info", Label: "Phone / Voicemail", SecretLabel: "PIN"},
	{Type: "document", Kind: "info", Label: "Document", SecretLabel: "Content"},
}

// pamEntryTypeByName indexes the catalog by type name.
var pamEntryTypeByName = func() map[string]PamEntryType {
	m := make(map[string]PamEntryType, len(pamEntryTypeCatalog))
	for _, t := range pamEntryTypeCatalog {
		m[t.Type] = t
	}
	return m
}()

// pamVaultSecretType maps an entry type to the vault_secrets.type its secret
// payload is stored under. The launch path keys the injection parameter off
// this ("ssh_key" → private-key, everything else → password), matching the M3
// convention in buildInjectedParams.
func pamVaultSecretType(entryType string) string {
	switch entryType {
	case "ssh_key":
		return "ssh_key"
	case "api_key":
		return "api_key"
	case "certificate":
		return "certificate"
	case "rdp", "ssh", "vnc", "telnet", "website", "credential", "website_login", "email_account", "wifi":
		return "password"
	default:
		return "pam_data"
	}
}

// pamGrantActions is the closed set of per-entry ACL actions.
var pamGrantActions = map[string]bool{"view": true, "connect": true, "edit": true, "reveal": true}

// ---- Auth helpers ----

// pamCallerIsAdmin mirrors requireAdminRole's posture for inline checks: a
// caller is admin when the request carries an admin / super_admin role.
//
// The local-development convenience bypass (treat every caller as admin so a
// single unauthenticated dev caller isn't hidden from all entries) is now an
// EXPLICIT opt-in via DevAdminBypass — it is NOT implied by APP_ENV=development.
// Piggybacking the bypass on IsDevelopment() meant a box left in dev mode
// exposed the whole PAM inventory to anonymous callers; gating it behind a
// dedicated flag keeps the endpoint controlled by default even in dev.
func (s *Service) pamCallerIsAdmin(c *gin.Context) bool {
	if s.config != nil && s.config.DevAdminBypass {
		return true
	}
	if rolesRaw, ok := c.Get("roles"); ok {
		if roles, ok := rolesRaw.([]string); ok {
			for _, r := range roles {
				if r == "admin" || r == "super_admin" {
					return true
				}
			}
		}
	}
	return false
}

// pamCallerRoles returns the authenticated caller's roles ([] when unauthenticated).
func pamCallerRoles(c *gin.Context) []string {
	if rolesRaw, ok := c.Get("roles"); ok {
		if roles, ok := rolesRaw.([]string); ok {
			return roles
		}
	}
	return nil
}

// pamEntryAllowed reports whether userID holds a non-expired grant carrying
// action on the entry (directly or via one of their roles). Admins are
// checked at the call sites and bypass this.
func (s *Service) pamEntryAllowed(ctx context.Context, orgID, entryID, userID string, roles []string, action string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	if roles == nil {
		roles = []string{}
	}
	var ok bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pam_entry_grants
			WHERE org_id = $1 AND entry_id = $2
			  AND $3 = ANY(actions)
			  AND (expires_at IS NULL OR expires_at > NOW())
			  AND (
			    (principal_type = 'user' AND principal_id = $4)
			    OR (principal_type = 'role' AND principal_id = ANY($5))
			  )
		)`, orgID, entryID, action, userID, roles).Scan(&ok)
	return ok, err
}

// ---- DTOs ----

// PamFolder is a folder-tree node (RDM "group").
type PamFolder struct {
	ID          string    `json:"id"`
	ParentID    string    `json:"parent_id,omitempty"`
	Name        string    `json:"name"`
	Icon        string    `json:"icon,omitempty"`
	Description string    `json:"description,omitempty"`
	EntryCount  int       `json:"entry_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PamEntry is the API representation of a pam_entries row. It deliberately
// carries no secret material — HasSecret/CredentialEntryID say where the
// secret lives, never what it is.
type PamEntry struct {
	ID                  string                 `json:"id"`
	FolderID            string                 `json:"folder_id,omitempty"`
	Name                string                 `json:"name"`
	EntryType           string                 `json:"entry_type"`
	Kind                string                 `json:"kind"`
	Description         string                 `json:"description,omitempty"`
	Tags                []string               `json:"tags"`
	Hostname            string                 `json:"hostname,omitempty"`
	Port                int                    `json:"port,omitempty"`
	Username            string                 `json:"username,omitempty"`
	Domain              string                 `json:"domain,omitempty"`
	URL                 string                 `json:"url,omitempty"`
	Settings            map[string]interface{} `json:"settings"`
	HasSecret           bool                   `json:"has_secret"`
	CredentialEntryID   string                 `json:"credential_entry_id,omitempty"`
	CredentialEntryName string                 `json:"credential_entry_name,omitempty"`
	AllowReveal         bool                   `json:"allow_reveal"`
	RequireApproval     bool                   `json:"require_approval"`
	DualControlRequired bool                   `json:"dual_control_required"`
	ExclusiveCheckout   bool                   `json:"exclusive_checkout"`
	BreakGlassEnabled   bool                   `json:"break_glass_enabled"`
	RecordSession       bool                   `json:"record_session"`
	ReachMode           string                 `json:"reach_mode"`
	Renderer            string                 `json:"renderer"`
	ZitiEnabled         bool                   `json:"ziti_enabled"`
	Favorite            bool                   `json:"favorite"`
	LastConnectedAt     *time.Time             `json:"last_connected_at,omitempty"`
	ConnectCount        int                    `json:"connect_count"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// pamEntryUpsertReq is the create/update request body. Secret is write-only:
// on create it seeds vault version 1; on update it appends a new version.
type pamEntryUpsertReq struct {
	FolderID          string                 `json:"folder_id"`
	Name              string                 `json:"name"`
	EntryType         string                 `json:"entry_type"`
	Description       string                 `json:"description"`
	Tags              []string               `json:"tags"`
	Hostname          string                 `json:"hostname"`
	Port              int                    `json:"port"`
	Username          string                 `json:"username"`
	Domain            string                 `json:"domain"`
	URL               string                 `json:"url"`
	Settings          map[string]interface{} `json:"settings"`
	Secret            string                 `json:"secret"`
	CredentialEntryID string                 `json:"credential_entry_id"`
	AllowReveal       bool                   `json:"allow_reveal"`
	RequireApproval   bool                   `json:"require_approval"`
	// DualControlRequired, ExclusiveCheckout, BreakGlassEnabled are the v105
	// checkout controls; all default false so existing entries are unaffected.
	DualControlRequired bool   `json:"dual_control_required"`
	ExclusiveCheckout   bool   `json:"exclusive_checkout"`
	BreakGlassEnabled   bool   `json:"break_glass_enabled"`
	RecordSession       bool   `json:"record_session"`
	Renderer            string `json:"renderer"`
}

// pamNormalizeRenderer clamps a requested renderer to a safe, valid value.
// Defaults to 'guacamole'. 'wasm-ssh' is only allowed for ssh-protocol entries
// (the in-browser terminal); 'novnc'/'support' pass through for future use.
// Anything unrecognized falls back to 'guacamole' so a bad client value can
// never brick a launch.
func pamNormalizeRenderer(renderer, entryType string) string {
	switch renderer {
	case "wasm-ssh":
		if pamEntryTypeByName[entryType].Protocol == "ssh" {
			return "wasm-ssh"
		}
		return "guacamole"
	case "novnc", "support":
		return renderer
	default:
		return "guacamole"
	}
}

// validatePamEntry checks the type against the catalog and the per-kind
// required fields. Returns the catalog record on success.
func validatePamEntry(req *pamEntryUpsertReq) (PamEntryType, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return PamEntryType{}, errors.New("name is required")
	}
	t, ok := pamEntryTypeByName[req.EntryType]
	if !ok {
		return PamEntryType{}, fmt.Errorf("unsupported entry_type %q", req.EntryType)
	}
	if t.Protocol != "" && strings.TrimSpace(req.Hostname) == "" {
		return PamEntryType{}, fmt.Errorf("hostname is required for %s entries", t.Type)
	}
	if t.Type == "website" && strings.TrimSpace(req.URL) == "" {
		return PamEntryType{}, errors.New("url is required for website entries")
	}
	if req.Port < 0 || req.Port > 65535 {
		return PamEntryType{}, errors.New("port out of range")
	}
	// RemoteApp command-line args must never carry a secret (visible in the
	// target's process list). Reject on write so the mistake surfaces in the
	// entry dialog, not as an opaque failure at launch.
	if raw, ok := req.Settings["remote-app-args"]; ok {
		if s, ok := raw.(string); ok {
			if err := validateRemoteAppArgs(s); err != nil {
				return PamEntryType{}, err
			}
		}
	}
	return t, nil
}

// pamDefaultPort fills the protocol default when the request leaves port 0.
func pamDefaultPort(entryType string, port int) int {
	if port != 0 {
		return port
	}
	switch entryType {
	case "rdp":
		return 3389
	case "ssh":
		return 22
	case "vnc":
		return 5900
	case "telnet":
		return 23
	}
	return 0
}

// ---- Folder handlers ----

// handlePamListFolders — GET /pam/folders (any authenticated user).
func (s *Service) handlePamListFolders(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT f.id, COALESCE(f.parent_id::text,''), f.name, COALESCE(f.icon,''), COALESCE(f.description,''),
		       (SELECT COUNT(*) FROM pam_entries e WHERE e.folder_id = f.id AND e.org_id = f.org_id),
		       f.created_at, f.updated_at
		  FROM pam_folders f
		 WHERE f.org_id = $1
		 ORDER BY f.name`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListFolders: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list folders"})
		return
	}
	defer rows.Close()

	folders := []PamFolder{}
	for rows.Next() {
		var f PamFolder
		if err := rows.Scan(&f.ID, &f.ParentID, &f.Name, &f.Icon, &f.Description, &f.EntryCount, &f.CreatedAt, &f.UpdatedAt); err != nil {
			s.logger.Warn("handlePamListFolders: scan failed", zap.Error(err))
			continue
		}
		folders = append(folders, f)
	}
	c.JSON(http.StatusOK, gin.H{"folders": folders})
}

// handlePamCreateFolder — POST /pam/folders (admin).
func (s *Service) handlePamCreateFolder(c *gin.Context) {
	var req struct {
		ParentID    string `json:"parent_id"`
		Name        string `json:"name" binding:"required"`
		Icon        string `json:"icon"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var id string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_folders (org_id, parent_id, name, icon, description, created_by)
		VALUES ($1, NULLIF($2,'')::uuid, $3, NULLIF($4,''), NULLIF($5,''), NULLIF($6,'')::uuid)
		RETURNING id`,
		org.ID, req.ParentID, strings.TrimSpace(req.Name), req.Icon, req.Description, c.GetString("user_id")).Scan(&id)
	if err != nil {
		s.logger.Error("handlePamCreateFolder: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create folder"})
		return
	}

	s.logAuditEvent(c, "pam.folder_created", id, "pam_folder", map[string]interface{}{"name": req.Name})
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// handlePamUpdateFolder — PUT /pam/folders/:id (admin).
func (s *Service) handlePamUpdateFolder(c *gin.Context) {
	folderID := c.Param("id")
	var req struct {
		ParentID    string `json:"parent_id"`
		Name        string `json:"name" binding:"required"`
		Icon        string `json:"icon"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ParentID == folderID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "folder cannot be its own parent"})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_folders
		   SET parent_id = NULLIF($1,'')::uuid, name = $2, icon = NULLIF($3,''),
		       description = NULLIF($4,''), updated_at = NOW()
		 WHERE id = $5 AND org_id = $6`,
		req.ParentID, strings.TrimSpace(req.Name), req.Icon, req.Description, folderID, org.ID)
	if err != nil {
		s.logger.Error("handlePamUpdateFolder: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update folder"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "folder not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": folderID})
}

// handlePamDeleteFolder — DELETE /pam/folders/:id (admin). Child folders
// cascade; entries in the folder fall back to the root (folder_id NULL).
func (s *Service) handlePamDeleteFolder(c *gin.Context) {
	folderID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	tag, err := s.db.Pool.Exec(ctx,
		`DELETE FROM pam_folders WHERE id = $1 AND org_id = $2`, folderID, org.ID)
	if err != nil {
		s.logger.Error("handlePamDeleteFolder: delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete folder"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "folder not found"})
		return
	}
	s.logAuditEvent(c, "pam.folder_deleted", folderID, "pam_folder", nil)
	c.Status(http.StatusNoContent)
}

// ---- Entry handlers ----

// pamEntrySelectColumns is the shared column list scanPamEntry expects.
const pamEntrySelectColumns = `
	e.id, COALESCE(e.folder_id::text,''), e.name, e.entry_type, COALESCE(e.description,''),
	e.tags, COALESCE(e.hostname,''), COALESCE(e.port,0), COALESCE(e.username,''),
	COALESCE(e.domain,''), COALESCE(e.url,''), e.settings,
	(e.vault_secret_id IS NOT NULL), COALESCE(e.credential_entry_id::text,''), COALESCE(ce.name,''),
	e.allow_reveal, e.require_approval, e.record_session, e.reach_mode,
	COALESCE(e.renderer,'guacamole'),
	e.dual_control_required, e.exclusive_checkout, e.break_glass_enabled,
	e.last_connected_at, e.connect_count, e.created_at, e.updated_at`

type pamEntryScanner interface {
	Scan(dest ...any) error
}

func scanPamEntry(row pamEntryScanner) (*PamEntry, error) {
	var e PamEntry
	var settingsJSON []byte
	if err := row.Scan(
		&e.ID, &e.FolderID, &e.Name, &e.EntryType, &e.Description,
		&e.Tags, &e.Hostname, &e.Port, &e.Username,
		&e.Domain, &e.URL, &settingsJSON,
		&e.HasSecret, &e.CredentialEntryID, &e.CredentialEntryName,
		&e.AllowReveal, &e.RequireApproval, &e.RecordSession, &e.ReachMode,
		&e.Renderer,
		&e.DualControlRequired, &e.ExclusiveCheckout, &e.BreakGlassEnabled,
		&e.LastConnectedAt, &e.ConnectCount, &e.CreatedAt, &e.UpdatedAt,
	); err != nil {
		return nil, err
	}
	e.ZitiEnabled = e.ReachMode == "ziti"
	if len(settingsJSON) > 0 {
		_ = json.Unmarshal(settingsJSON, &e.Settings)
	}
	if e.Settings == nil {
		e.Settings = map[string]interface{}{}
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	e.Kind = pamEntryTypeByName[e.EntryType].Kind
	return &e, nil
}

// handlePamListEntryTypes — GET /pam/entry-types (any authenticated user).
func (s *Service) handlePamListEntryTypes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"types": pamEntryTypeCatalog})
}

// handlePamListEntries — GET /pam/entries?folder_id=&type=&q=&favorites=
// (any authenticated user). Admins see every entry in the org; other callers
// see only entries they hold a grant on (any action).
func (s *Service) handlePamListEntries(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	query := `
		SELECT ` + pamEntrySelectColumns + `,
		       EXISTS(SELECT 1 FROM pam_entry_favorites fav
		               WHERE fav.entry_id = e.id AND fav.user_id::text = $2)
		  FROM pam_entries e
		  LEFT JOIN pam_entries ce ON ce.id = e.credential_entry_id
		 WHERE e.org_id = $1`
	args := []interface{}{org.ID, userID}

	if !s.pamCallerIsAdmin(c) {
		roles := pamCallerRoles(c)
		if roles == nil {
			roles = []string{}
		}
		args = append(args, roles)
		query += fmt.Sprintf(`
		   AND EXISTS (SELECT 1 FROM pam_entry_grants g
		                WHERE g.entry_id = e.id
		                  AND (g.expires_at IS NULL OR g.expires_at > NOW())
		                  AND ((g.principal_type = 'user' AND g.principal_id = $2)
		                    OR (g.principal_type = 'role' AND g.principal_id = ANY($%d))))`, len(args))
	}

	if folderID := c.Query("folder_id"); folderID != "" {
		args = append(args, folderID)
		query += fmt.Sprintf(" AND e.folder_id = $%d", len(args))
	}
	if entryType := c.Query("type"); entryType != "" {
		args = append(args, entryType)
		query += fmt.Sprintf(" AND e.entry_type = $%d", len(args))
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		args = append(args, "%"+strings.ToLower(q)+"%")
		query += fmt.Sprintf(` AND (LOWER(e.name) LIKE $%d OR LOWER(COALESCE(e.hostname,'')) LIKE $%d
		   OR LOWER(COALESCE(e.description,'')) LIKE $%d
		   OR EXISTS (SELECT 1 FROM unnest(e.tags) tag WHERE LOWER(tag) LIKE $%d))`,
			len(args), len(args), len(args), len(args))
	}
	if c.Query("favorites") == "true" {
		query += ` AND EXISTS(SELECT 1 FROM pam_entry_favorites fav2
		                       WHERE fav2.entry_id = e.id AND fav2.user_id::text = $2)`
	}
	query += " ORDER BY e.name LIMIT 1000"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("handlePamListEntries: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list entries"})
		return
	}
	defer rows.Close()

	entries := []PamEntry{}
	for rows.Next() {
		var e PamEntry
		var settingsJSON []byte
		if err := rows.Scan(
			&e.ID, &e.FolderID, &e.Name, &e.EntryType, &e.Description,
			&e.Tags, &e.Hostname, &e.Port, &e.Username,
			&e.Domain, &e.URL, &settingsJSON,
			&e.HasSecret, &e.CredentialEntryID, &e.CredentialEntryName,
			&e.AllowReveal, &e.RequireApproval, &e.RecordSession, &e.ReachMode,
			&e.Renderer,
			&e.DualControlRequired, &e.ExclusiveCheckout, &e.BreakGlassEnabled,
			&e.LastConnectedAt, &e.ConnectCount, &e.CreatedAt, &e.UpdatedAt,
			&e.Favorite,
		); err != nil {
			s.logger.Warn("handlePamListEntries: scan failed", zap.Error(err))
			continue
		}
		e.ZitiEnabled = e.ReachMode == "ziti"
		if len(settingsJSON) > 0 {
			_ = json.Unmarshal(settingsJSON, &e.Settings)
		}
		if e.Settings == nil {
			e.Settings = map[string]interface{}{}
		}
		if e.Tags == nil {
			e.Tags = []string{}
		}
		e.Kind = pamEntryTypeByName[e.EntryType].Kind
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handlePamListEntries: rows iteration failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list entries"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// handlePamGetEntry — GET /pam/entries/:id (view grant or admin). Never
// returns secret material.
func (s *Service) handlePamGetEntry(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	if !s.pamCallerIsAdmin(c) {
		ok, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, c.GetString("user_id"), pamCallerRoles(c), "view")
		if aclErr != nil || !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}

	row := s.db.Pool.QueryRow(ctx, `
		SELECT `+pamEntrySelectColumns+`
		  FROM pam_entries e
		  LEFT JOIN pam_entries ce ON ce.id = e.credential_entry_id
		 WHERE e.id = $1 AND e.org_id = $2`, entryID, org.ID)
	entry, err := scanPamEntry(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamGetEntry: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}
	c.JSON(http.StatusOK, entry)
}

// validateCredentialLink checks a credential_entry_id points at a same-org
// credential-kind entry and not at the entry itself.
func (s *Service) validateCredentialLink(ctx context.Context, orgID, entryID, credentialEntryID string) error {
	if credentialEntryID == "" {
		return nil
	}
	if credentialEntryID == entryID {
		return errors.New("entry cannot link itself as credential")
	}
	var credType string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT entry_type FROM pam_entries WHERE id = $1 AND org_id = $2`,
		credentialEntryID, orgID).Scan(&credType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("credential entry not found")
		}
		return err
	}
	if pamEntryTypeByName[credType].Kind != "credential" {
		return fmt.Errorf("linked entry %q is not a credential entry", credType)
	}
	return nil
}

// storePamSecret seals a secret payload into the vault for an entry. Returns
// the vault_secrets id.
func (s *Service) storePamSecret(ctx context.Context, entryID, entryType, name, secret, userID string) (string, error) {
	if s.vaultSvc == nil {
		return "", errors.New("credential vault is not configured")
	}
	meta, err := s.vaultSvc.Store(ctx, vault.StoreInput{
		Name:        "pam:" + entryID,
		Type:        pamVaultSecretType(entryType),
		Description: "PAM entry secret: " + name,
		Value:       []byte(secret),
		Metadata:    map[string]interface{}{"pam_entry_id": entryID},
		CreatedBy:   userID,
	})
	if err != nil {
		return "", err
	}
	return meta.ID, nil
}

// handlePamCreateEntry — POST /pam/entries (admin).
func (s *Service) handlePamCreateEntry(c *gin.Context) {
	var req pamEntryUpsertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	typeInfo, err := validatePamEntry(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	entryID := uuid.New().String()

	if err := s.validateCredentialLink(ctx, org.ID, entryID, req.CredentialEntryID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Seal the secret first so the entry never exists pointing at nothing;
	// compensate by deleting the secret if the entry INSERT fails.
	vaultSecretID := ""
	if req.Secret != "" {
		vaultSecretID, err = s.storePamSecret(ctx, entryID, req.EntryType, req.Name, req.Secret, userID)
		if err != nil {
			s.logger.Error("handlePamCreateEntry: secret store failed", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to store secret"})
			return
		}
	}

	settingsJSON, _ := json.Marshal(req.Settings)
	if req.Settings == nil {
		settingsJSON = []byte("{}")
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO pam_entries (id, org_id, folder_id, name, entry_type, description, tags,
		                         hostname, port, username, domain, url, settings,
		                         vault_secret_id, credential_entry_id,
		                         allow_reveal, require_approval, record_session, renderer, created_by,
		                         dual_control_required, exclusive_checkout, break_glass_enabled)
		VALUES ($1, $2, NULLIF($3,'')::uuid, $4, $5, NULLIF($6,''), $7,
		        NULLIF($8,''), NULLIF($9,0), NULLIF($10,''), NULLIF($11,''), NULLIF($12,''), $13,
		        NULLIF($14,'')::uuid, NULLIF($15,'')::uuid,
		        $16, $17, $18, $19, NULLIF($20,'')::uuid,
		        $21, $22, $23)`,
		entryID, org.ID, req.FolderID, req.Name, req.EntryType, req.Description, req.Tags,
		req.Hostname, pamDefaultPort(req.EntryType, req.Port), req.Username, req.Domain, req.URL, settingsJSON,
		vaultSecretID, req.CredentialEntryID,
		req.AllowReveal, req.RequireApproval, req.RecordSession, pamNormalizeRenderer(req.Renderer, req.EntryType), userID,
		req.DualControlRequired, req.ExclusiveCheckout, req.BreakGlassEnabled)
	if err != nil {
		if vaultSecretID != "" && s.vaultSvc != nil {
			if delErr := s.vaultSvc.Delete(ctx, vaultSecretID); delErr != nil {
				s.logger.Warn("handlePamCreateEntry: orphan secret cleanup failed",
					zap.String("secret_id", vaultSecretID), zap.Error(delErr))
			}
		}
		s.logger.Error("handlePamCreateEntry: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create entry"})
		return
	}

	s.logAuditEvent(c, "pam.entry_created", entryID, "pam_entry", map[string]interface{}{
		"name": req.Name, "entry_type": req.EntryType, "kind": typeInfo.Kind,
		"has_secret": vaultSecretID != "",
	})
	c.JSON(http.StatusCreated, gin.H{"id": entryID})
}

// handlePamUpdateEntry — PUT /pam/entries/:id (edit grant or admin). A
// non-empty secret appends a new vault version (or creates the secret when
// the entry had none).
func (s *Service) handlePamUpdateEntry(c *gin.Context) {
	entryID := c.Param("id")
	var req pamEntryUpsertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := validatePamEntry(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	if !s.pamCallerIsAdmin(c) {
		ok, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "edit")
		if aclErr != nil || !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}

	// The stored entry_type is immutable (it decides the vault secret type and
	// launch behaviour); reject mismatches instead of silently converting.
	var currentType, currentSecretID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT entry_type, COALESCE(vault_secret_id::text,'') FROM pam_entries WHERE id = $1 AND org_id = $2`,
		entryID, org.ID).Scan(&currentType, &currentSecretID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamUpdateEntry: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}
	if currentType != req.EntryType {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entry_type cannot be changed"})
		return
	}
	if err := s.validateCredentialLink(ctx, org.ID, entryID, req.CredentialEntryID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Secret rotation-by-hand: new version on an existing secret, or first
	// version when the entry had none.
	vaultSecretID := currentSecretID
	if req.Secret != "" {
		if currentSecretID != "" {
			if s.vaultSvc == nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault is not configured"})
				return
			}
			if _, err := s.vaultSvc.NewVersion(ctx, currentSecretID, []byte(req.Secret), userID); err != nil {
				s.logger.Error("handlePamUpdateEntry: secret version failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update secret"})
				return
			}
		} else {
			vaultSecretID, err = s.storePamSecret(ctx, entryID, req.EntryType, req.Name, req.Secret, userID)
			if err != nil {
				s.logger.Error("handlePamUpdateEntry: secret store failed", zap.Error(err))
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to store secret"})
				return
			}
		}
	}

	settingsJSON, _ := json.Marshal(req.Settings)
	if req.Settings == nil {
		settingsJSON = []byte("{}")
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_entries
		   SET folder_id = NULLIF($1,'')::uuid, name = $2, description = NULLIF($3,''), tags = $4,
		       hostname = NULLIF($5,''), port = NULLIF($6,0), username = NULLIF($7,''),
		       domain = NULLIF($8,''), url = NULLIF($9,''), settings = $10,
		       vault_secret_id = NULLIF($11,'')::uuid, credential_entry_id = NULLIF($12,'')::uuid,
		       allow_reveal = $13, require_approval = $14, record_session = $15,
		       renderer = $18,
		       dual_control_required = $19, exclusive_checkout = $20, break_glass_enabled = $21,
		       updated_at = NOW()
		 WHERE id = $16 AND org_id = $17`,
		req.FolderID, req.Name, req.Description, req.Tags,
		req.Hostname, pamDefaultPort(req.EntryType, req.Port), req.Username,
		req.Domain, req.URL, settingsJSON,
		vaultSecretID, req.CredentialEntryID,
		req.AllowReveal, req.RequireApproval, req.RecordSession,
		entryID, org.ID, pamNormalizeRenderer(req.Renderer, req.EntryType),
		req.DualControlRequired, req.ExclusiveCheckout, req.BreakGlassEnabled)
	if err != nil {
		s.logger.Error("handlePamUpdateEntry: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update entry"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
		return
	}

	s.logAuditEvent(c, "pam.entry_updated", entryID, "pam_entry", map[string]interface{}{
		"name": req.Name, "secret_rotated": req.Secret != "",
	})
	c.JSON(http.StatusOK, gin.H{"id": entryID})
}

// handlePamDeleteEntry — DELETE /pam/entries/:id (admin). Deletes the vault
// secret (cryptographic erasure) and the per-entry Guacamole connection.
func (s *Service) handlePamDeleteEntry(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var secretID, guacConnID, zitiServiceName string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(vault_secret_id::text,''), COALESCE(guacamole_connection_id,''),
		        COALESCE(ziti_service_name,'')
		   FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID).
		Scan(&secretID, &guacConnID, &zitiServiceName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamDeleteEntry: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}

	tag, err := s.db.Pool.Exec(ctx,
		`DELETE FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID)
	if err != nil {
		s.logger.Error("handlePamDeleteEntry: delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete entry"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
		return
	}

	// Best-effort teardown of the secret and the brokered connection. The
	// entry row is already gone; failures leave only inert residue (an
	// unreferenced ciphertext / an unused guacamole connection).
	if secretID != "" && s.vaultSvc != nil {
		if err := s.vaultSvc.Delete(ctx, secretID); err != nil && !errors.Is(err, vault.ErrNotFound) {
			s.logger.Warn("handlePamDeleteEntry: vault secret delete failed",
				zap.String("secret_id", secretID), zap.Error(err))
		}
	}
	if guacConnID != "" && s.guacamoleClient != nil {
		if err := s.guacamoleClient.DeleteConnection(guacConnID); err != nil {
			s.logger.Warn("handlePamDeleteEntry: guacamole connection delete failed",
				zap.String("guac_conn_id", guacConnID), zap.Error(err))
		}
	}
	// Tear down the per-entry OpenZiti overlay service (host.v1 + bind/dial/serp)
	// so a ziti-reach entry leaves no orphaned service/policies on the controller.
	if zitiServiceName != "" {
		if zm := s.ziti(); zm != nil {
			if err := zm.TeardownZitiServiceByName(ctx, zitiServiceName); err != nil {
				s.logger.Warn("handlePamDeleteEntry: ziti service teardown failed",
					zap.String("service", scrubLogValue(zitiServiceName)), zap.Error(err))
			}
		}
	}

	s.logAuditEvent(c, "pam.entry_deleted", entryID, "pam_entry", map[string]interface{}{
		"had_secret": secretID != "", "had_ziti": zitiServiceName != "",
	})
	c.Status(http.StatusNoContent)
}

// ---- Favorites ----

// handlePamFavoriteEntry — POST /pam/entries/:id/favorite.
func (s *Service) handlePamFavoriteEntry(c *gin.Context) {
	s.setPamFavorite(c, true)
}

// handlePamUnfavoriteEntry — DELETE /pam/entries/:id/favorite.
func (s *Service) handlePamUnfavoriteEntry(c *gin.Context) {
	s.setPamFavorite(c, false)
}

func (s *Service) setPamFavorite(c *gin.Context, favorite bool) {
	entryID := c.Param("id")
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	if favorite {
		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO pam_entry_favorites (org_id, entry_id, user_id)
			SELECT $1, id, $3::uuid FROM pam_entries WHERE id = $2 AND org_id = $1
			ON CONFLICT (entry_id, user_id) DO NOTHING`, org.ID, entryID, userID)
	} else {
		_, err = s.db.Pool.Exec(ctx,
			`DELETE FROM pam_entry_favorites WHERE org_id = $1 AND entry_id = $2 AND user_id::text = $3`,
			org.ID, entryID, userID)
	}
	if err != nil {
		s.logger.Error("setPamFavorite: exec failed", zap.Bool("favorite", favorite), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update favorite"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"favorite": favorite})
}

// ---- Grants ----

// handlePamListEntryGrants — GET /pam/entries/:id/grants (admin).
func (s *Service) handlePamListEntryGrants(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, principal_type, principal_id, actions, expires_at, COALESCE(granted_by::text,''), created_at
		  FROM pam_entry_grants
		 WHERE org_id = $1 AND entry_id = $2
		 ORDER BY principal_type, principal_id`, org.ID, entryID)
	if err != nil {
		s.logger.Error("handlePamListEntryGrants: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list grants"})
		return
	}
	defer rows.Close()

	type grantRow struct {
		ID            string     `json:"id"`
		PrincipalType string     `json:"principal_type"`
		PrincipalID   string     `json:"principal_id"`
		Actions       []string   `json:"actions"`
		ExpiresAt     *time.Time `json:"expires_at,omitempty"`
		GrantedBy     string     `json:"granted_by,omitempty"`
		CreatedAt     time.Time  `json:"created_at"`
	}
	grants := []grantRow{}
	for rows.Next() {
		var g grantRow
		if err := rows.Scan(&g.ID, &g.PrincipalType, &g.PrincipalID, &g.Actions, &g.ExpiresAt, &g.GrantedBy, &g.CreatedAt); err != nil {
			s.logger.Warn("handlePamListEntryGrants: scan failed", zap.Error(err))
			continue
		}
		grants = append(grants, g)
	}
	c.JSON(http.StatusOK, gin.H{"grants": grants})
}

// handlePamAddEntryGrant — POST /pam/entries/:id/grants (admin).
func (s *Service) handlePamAddEntryGrant(c *gin.Context) {
	entryID := c.Param("id")
	var req struct {
		PrincipalType string     `json:"principal_type" binding:"required"`
		PrincipalID   string     `json:"principal_id" binding:"required"`
		Actions       []string   `json:"actions" binding:"required"`
		ExpiresAt     *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.PrincipalType != "user" && req.PrincipalType != "role" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "principal_type must be user or role"})
		return
	}
	if len(req.Actions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "actions is required"})
		return
	}
	for _, a := range req.Actions {
		if !pamGrantActions[a] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported action %q", a)})
			return
		}
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var id string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, granted_by, expires_at)
		SELECT $1, id, $3, $4, $5, NULLIF($6,'')::uuid, $7 FROM pam_entries WHERE id = $2 AND org_id = $1
		ON CONFLICT (entry_id, principal_type, principal_id)
		DO UPDATE SET actions = EXCLUDED.actions, expires_at = EXCLUDED.expires_at
		RETURNING id`,
		org.ID, entryID, req.PrincipalType, req.PrincipalID, req.Actions,
		c.GetString("user_id"), req.ExpiresAt).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamAddEntryGrant: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add grant"})
		return
	}

	s.logAuditEvent(c, "pam.entry_grant_added", entryID, "pam_entry", map[string]interface{}{
		"principal": req.PrincipalType + ":" + req.PrincipalID, "actions": req.Actions,
	})
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// handlePamRemoveEntryGrant — DELETE /pam/entries/:id/grants/:grantId (admin).
func (s *Service) handlePamRemoveEntryGrant(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx,
		`DELETE FROM pam_entry_grants WHERE id = $1 AND entry_id = $2 AND org_id = $3`,
		c.Param("grantId"), c.Param("id"), org.ID)
	if err != nil {
		s.logger.Error("handlePamRemoveEntryGrant: delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove grant"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
		return
	}
	s.logAuditEvent(c, "pam.entry_grant_removed", c.Param("id"), "pam_entry",
		map[string]interface{}{"grant_id": c.Param("grantId")})
	c.Status(http.StatusNoContent)
}

// ---- Reveal ----

// handlePamRevealEntry — POST /pam/entries/:id/reveal {reason} — returns the
// entry's secret plaintext, once, to a permitted caller.
//
// This is the ONLY path that ever hands PAM secret material to a human, and
// it is double-gated: the entry must have allow_reveal=true (the flag is
// enforced for admins too — an entry provisioned for injection-only access
// stays password-less for everyone until an audited edit flips the flag),
// and non-admin callers additionally need a `reveal` grant. Every reveal is
// reason-stamped, ledgered in vault_checkouts, and audited.
func (s *Service) handlePamRevealEntry(c *gin.Context) {
	entryID := c.Param("id")
	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required"})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	var secretID, credentialEntryID string
	var allowReveal bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(vault_secret_id::text,''), COALESCE(credential_entry_id::text,''), allow_reveal
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID).
		Scan(&secretID, &credentialEntryID, &allowReveal)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamRevealEntry: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}
	if secretID == "" {
		if credentialEntryID != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "entry uses a linked credential; reveal the credential entry instead"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "entry has no stored secret"})
		return
	}
	if !allowReveal {
		c.JSON(http.StatusForbidden, gin.H{"error": "reveal is disabled for this entry (injection-only access)"})
		return
	}
	if !s.pamCallerIsAdmin(c) {
		ok, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "reveal")
		if aclErr != nil || !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault is not configured"})
		return
	}

	// v105 checkout controls: exclusivity + dual-control (two-person rule).
	// A dual-control entry returns 202 until a second admin authorizes the
	// checkout; an exclusive entry returns 409 while another principal holds it.
	if proceed, status, body := s.pamCheckoutGate(ctx, org.ID, entryID, userID, "reveal", req.Reason); !proceed {
		c.JSON(status, body)
		return
	}

	// PAM's entry-level ACL above is the authorization; pass isAdmin=true so
	// the vault does not also require a vault_access_grants row (these
	// entry-backing secrets have none). Reveal still records the checkout
	// lease and the vault.reveal audit event.
	pt, err := s.vaultSvc.Reveal(ctx, secretID, userID, pamCallerRoles(c), req.Reason, true)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "secret not found"})
			return
		}
		s.logger.Error("handlePamRevealEntry: reveal failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reveal secret"})
		return
	}

	s.logAuditEvent(c, "pam.entry_revealed", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "reason": req.Reason, "user_id": userID,
		// Secret value intentionally omitted.
	})

	// Record the live checkout so an exclusive entry blocks concurrent access
	// until this lease expires or the holder checks in. Best-effort: a ledger
	// failure must not fail a reveal the caller was already authorized for.
	s.pamRecordCheckout(ctx, org.ID, entryID, userID, "reveal", req.Reason, false)

	// Returned once; never logged. Same encoder-buffer caveat as vault reveal.
	c.JSON(http.StatusOK, gin.H{"value": string(pt)})
	for i := range pt {
		pt[i] = 0
	}
}
