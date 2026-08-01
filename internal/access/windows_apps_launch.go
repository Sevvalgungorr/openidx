package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// launchAppRow is the app data needed to launch: identity, target, params,
// per-app policy overrides, and the persisted per-app Guacamole connection id.
type launchAppRow struct {
	ID              string
	DisplayName     string
	Alias           string
	Args            string
	WorkingDir      string
	HostEntryID     string
	PoolID          string
	GuacConnID      string
	Status          string
	RequireApproval *bool
	RecordSession   *bool
}

// candidateHost is one placement candidate with its live capacity picture.
type candidateHost struct {
	HostEntryID    string
	HostName       string
	MaxSessions    int
	ActiveSessions int
	UserSessionID  string // this user's active session on the host, if any (would be killed by a new launch)
	UserAppName    string
}

// launchConflict is the 409 body when placement can't proceed without
// disconnecting something — the frontend renders the resolution dialog from it.
type launchConflict struct {
	Reason    string                  `json:"reason"` // no_capacity | user_session_conflict
	Message   string                  `json:"message"`
	Conflicts []launchConflictSession `json:"conflicts"`
}

type launchConflictSession struct {
	HostEntryID string `json:"host_entry_id"`
	HostName    string `json:"host_name"`
	SessionID   string `json:"session_id"`
	AppName     string `json:"app_name,omitempty"`
	StartedAt   string `json:"started_at"`
}

// handleWindowsAppLaunch — POST /pam/apps/:id/launch?replace=<session_id>.
//
// Resolves a concrete host by placement, then runs the exact same gates as a
// normal PAM connect (ACL + approval) against that host before delegating to
// launchPamSession with the app's RemoteApp parameters. On a placement
// conflict it returns 409 with the sessions in the way; passing ?replace ends
// the named session first, freeing its slot.
func (s *Service) handleWindowsAppLaunch(c *gin.Context) {
	appID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	isAdmin := s.pamCallerIsAdmin(c)

	app, err := s.loadLaunchApp(ctx, org.ID, appID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
			return
		}
		s.logger.Error("handleWindowsAppLaunch: load failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load app"})
		return
	}
	if app.Status == "inconsistent" {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this app's alias resolves to different programs across the pool; launch is blocked until it is consistent",
			"code":  "app_inconsistent"})
		return
	}
	if app.Status == "disabled" {
		c.JSON(http.StatusForbidden, gin.H{"error": "this app is disabled"})
		return
	}

	// If the caller chose to replace a session, end it first so its host frees
	// a slot for the placement below.
	if replace := c.Query("replace"); replace != "" {
		s.endPamSession(ctx, org.ID, replace)
	}

	candidates, err := s.appCandidateHosts(ctx, org.ID, userID, &app)
	if err != nil {
		s.logger.Error("handleWindowsAppLaunch: candidates query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve hosts"})
		return
	}
	if len(candidates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this app has no reachable host"})
		return
	}

	chosen, conflict := placeApp(candidates)
	if chosen == nil {
		s.logAuditEvent(c, "windows_app.launch_denied", appID, "windows_app",
			map[string]interface{}{"reason": conflict.Reason})
		c.JSON(http.StatusConflict, conflict)
		return
	}

	// Load the chosen host as a launch entry and run the gates against it.
	entry, typeInfo, ok := s.loadPamLaunchEntry(c, org.ID, chosen.HostEntryID)
	if !ok {
		return // loadPamLaunchEntry already wrote the error
	}
	// Per-app overrides may only TIGHTEN the host's policy.
	if app.RequireApproval != nil && *app.RequireApproval {
		entry.RequireApproval = true
	}
	if app.RecordSession != nil && *app.RecordSession {
		entry.RecordSession = true
	}

	if !isAdmin {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, chosen.HostEntryID, userID, pamCallerRoles(c), "connect")
		if aclErr != nil {
			s.logger.Error("handleWindowsAppLaunch: ACL check failed", zap.Error(aclErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}
	if entry.RequireApproval && !isAdmin {
		consumed, gateErr := s.checkAndConsumePamApproval(ctx, chosen.HostEntryID, userID)
		if gateErr != nil || !consumed {
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval", "approval_required": true})
			return
		}
	}

	// RemoteApp params. disable-gfx is forced inside buildPamGuacParams because
	// remote-app is set (GUACAMOLE-2123).
	extra := map[string]string{"remote-app": "||" + app.Alias}
	if app.WorkingDir != "" {
		extra["remote-app-dir"] = app.WorkingDir
	}
	if app.Args != "" {
		extra["remote-app-args"] = app.Args
	}

	connName := fmt.Sprintf("pam-%s-app-%s", chosen.HostEntryID, app.ID)
	res, ok := s.launchPamSession(c, org.ID, &entry, typeInfo.Protocol, extra, connName, app.GuacConnID,
		func(ctx context.Context, connID string) {
			if _, err := s.db.Pool.Exec(ctx,
				`UPDATE windows_apps SET guac_connection_id = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
				connID, app.ID, org.ID); err != nil {
				s.logger.Warn("handleWindowsAppLaunch: persist connection id failed", zap.Error(err))
			}
		})
	if !ok {
		return
	}

	s.logAuditEvent(c, "windows_app.launched", app.ID, "windows_app", map[string]interface{}{
		"app_name": app.DisplayName, "alias": app.Alias, "host_entry_id": chosen.HostEntryID,
	})
	c.JSON(http.StatusOK, gin.H{
		"launch_type":   "guacamole",
		"connect_url":   res.ConnectURL,
		"app_id":        app.ID,
		"host_entry_id": chosen.HostEntryID,
		"host_name":     chosen.HostName,
		"session_id":    res.SessionID,
		"recorded":      entry.RecordSession,
	})
}

// placeApp picks a host and, when none is usable, returns the conflict to
// surface. Rules (GUACAMOLE-1951): skip a host at capacity; skip a host where
// THIS user already has a session, because a new RDP connection there would
// terminate it. least-loaded ordering is applied by the caller's query.
func placeApp(candidates []candidateHost) (*candidateHost, *launchConflict) {
	var blocked []launchConflictSession
	sawUserConflict := false
	for i := range candidates {
		h := &candidates[i]
		if h.UserSessionID != "" {
			// Launching here would kill the user's existing session — offer it
			// as a resolvable conflict rather than silently replacing it.
			sawUserConflict = true
			blocked = append(blocked, launchConflictSession{
				HostEntryID: h.HostEntryID, HostName: h.HostName,
				SessionID: h.UserSessionID, AppName: h.UserAppName,
			})
			continue
		}
		if h.ActiveSessions >= h.MaxSessions {
			continue
		}
		return h, nil
	}
	if sawUserConflict {
		return nil, &launchConflict{
			Reason:    "user_session_conflict",
			Message:   "You already have an active session on the only host(s) with capacity. Launching a new app there would disconnect it.",
			Conflicts: blocked,
		}
	}
	return nil, &launchConflict{
		Reason:  "no_capacity",
		Message: "Every host for this app is at its session limit. Try again shortly, or free a session.",
	}
}

// appCandidateHosts resolves the app's hosts (a single host, or the pool's
// members) with per-host capacity and this user's active-session picture.
// Ordering follows the pool's placement strategy (least_loaded by active
// count; round_robin by least-recently-connected host).
func (s *Service) appCandidateHosts(ctx context.Context, orgID, userID string, app *launchAppRow) ([]candidateHost, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if app.HostEntryID != "" {
		rows, err = s.db.Pool.Query(ctx, `
			SELECT he.id, he.name, 1 AS max_sessions,
			       (SELECT count(*) FROM pam_entry_sessions es WHERE es.entry_id = he.id AND es.status = 'active'),
			       COALESCE((SELECT es2.id::text FROM pam_entry_sessions es2
			                  WHERE es2.entry_id = he.id AND es2.user_id = $2::uuid AND es2.status = 'active'
			                  ORDER BY es2.started_at DESC LIMIT 1), '')
			  FROM pam_entries he
			 WHERE he.id = $1 AND he.org_id = $3`, app.HostEntryID, userID, orgID)
	} else {
		var order string
		var placement string
		_ = s.db.Pool.QueryRow(ctx, `SELECT placement FROM windows_app_pools WHERE id = $1 AND org_id = $2`, app.PoolID, orgID).Scan(&placement)
		if placement == "round_robin" {
			order = "ORDER BY he.last_connected_at ASC NULLS FIRST"
		} else {
			order = "ORDER BY active_sessions ASC"
		}
		rows, err = s.db.Pool.Query(ctx, `
			SELECT he.id, he.name, m.max_sessions,
			       (SELECT count(*) FROM pam_entry_sessions es WHERE es.entry_id = he.id AND es.status = 'active') AS active_sessions,
			       COALESCE((SELECT es2.id::text FROM pam_entry_sessions es2
			                  WHERE es2.entry_id = he.id AND es2.user_id = $2::uuid AND es2.status = 'active'
			                  ORDER BY es2.started_at DESC LIMIT 1), '')
			  FROM windows_app_pool_members m
			  JOIN pam_entries he ON he.id = m.host_entry_id
			 WHERE m.pool_id = $1 AND m.org_id = $3 `+order, app.PoolID, userID, orgID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidateHost
	for rows.Next() {
		var h candidateHost
		if err := rows.Scan(&h.HostEntryID, &h.HostName, &h.MaxSessions, &h.ActiveSessions, &h.UserSessionID); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// endPamSession marks a session ended, freeing its host's capacity slot. The
// user explicitly asked to disconnect it (the 409 resolution flow). Best-effort.
func (s *Service) endPamSession(ctx context.Context, orgID, sessionID string) {
	if _, err := uuid.Parse(sessionID); err != nil {
		return
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE pam_entry_sessions SET status = 'ended', ended_at = NOW()
		  WHERE id = $1 AND org_id = $2 AND status = 'active'`, sessionID, orgID); err != nil {
		s.logger.Warn("endPamSession: update failed", zap.String("session_id", scrubLogValue(sessionID)), zap.Error(err))
	}
}

func (s *Service) loadLaunchApp(ctx context.Context, orgID, appID string) (launchAppRow, error) {
	var a launchAppRow
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, display_name, alias, COALESCE(args,''), COALESCE(working_dir,''),
		       COALESCE(host_entry_id::text,''), COALESCE(pool_id::text,''),
		       COALESCE(guac_connection_id,''), status, require_approval, record_session
		  FROM windows_apps WHERE id = $1 AND org_id = $2`, appID, orgID).Scan(
		&a.ID, &a.DisplayName, &a.Alias, &a.Args, &a.WorkingDir,
		&a.HostEntryID, &a.PoolID, &a.GuacConnID, &a.Status, &a.RequireApproval, &a.RecordSession)
	return a, err
}

// ---- Pools ----

type windowsAppPool struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Placement   string                 `json:"placement"`
	Members     []windowsAppPoolMember `json:"members"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
}

type windowsAppPoolMember struct {
	ID             string `json:"id"`
	HostEntryID    string `json:"host_entry_id"`
	HostName       string `json:"host_name"`
	MaxSessions    int    `json:"max_sessions"`
	ActiveSessions int    `json:"active_sessions"`
}

func (s *Service) listWindowsAppPools(ctx context.Context, orgID string) ([]windowsAppPool, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''), placement, created_at, updated_at
		  FROM windows_app_pools WHERE org_id = $1 ORDER BY name ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pools := []windowsAppPool{}
	byID := map[string]int{}
	for rows.Next() {
		var p windowsAppPool
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Placement, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Members = []windowsAppPoolMember{}
		byID[p.ID] = len(pools)
		pools = append(pools, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mrows, err := s.db.Pool.Query(ctx, `
		SELECT m.id, m.pool_id::text, m.host_entry_id::text, COALESCE(he.name,''), m.max_sessions,
		       (SELECT count(*) FROM pam_entry_sessions es WHERE es.entry_id = m.host_entry_id AND es.status = 'active')
		  FROM windows_app_pool_members m
		  LEFT JOIN pam_entries he ON he.id = m.host_entry_id
		 WHERE m.org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var poolID string
		var m windowsAppPoolMember
		if err := mrows.Scan(&m.ID, &poolID, &m.HostEntryID, &m.HostName, &m.MaxSessions, &m.ActiveSessions); err != nil {
			return nil, err
		}
		if idx, ok := byID[poolID]; ok {
			pools[idx].Members = append(pools[idx].Members, m)
		}
	}
	return pools, mrows.Err()
}

func (s *Service) handleWindowsAppPoolList(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	pools, err := s.listWindowsAppPools(ctx, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load pools"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pools": pools})
}

func (s *Service) handleWindowsAppPoolCreate(c *gin.Context) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Placement   string `json:"placement"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Placement != "round_robin" {
		body.Placement = "least_loaded"
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := uuid.New().String()
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO windows_app_pools (id, org_id, name, description, placement, created_by)
		VALUES ($1, $2, $3, NULLIF($4,''), $5, NULLIF($6,'')::uuid)`,
		id, org.ID, strings.TrimSpace(body.Name), body.Description, body.Placement, c.GetString("user_id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create pool"})
		return
	}
	s.logAuditEvent(c, "windows_app_pool.created", id, "windows_app_pool", map[string]interface{}{"name": body.Name})
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (s *Service) handleWindowsAppPoolUpdate(c *gin.Context) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Placement   string `json:"placement"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Placement != "round_robin" {
		body.Placement = "least_loaded"
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE windows_app_pools SET name = $3, description = NULLIF($4,''), placement = $5, updated_at = NOW()
		 WHERE id = $1 AND org_id = $2`, c.Param("id"), org.ID, strings.TrimSpace(body.Name), body.Description, body.Placement)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "pool not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id")})
}

func (s *Service) handleWindowsAppPoolDelete(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM windows_app_pools WHERE id = $1 AND org_id = $2`, c.Param("id"), org.ID)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "pool not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) handleWindowsAppPoolAddMember(c *gin.Context) {
	var body struct {
		HostEntryID string `json:"host_entry_id"`
		MaxSessions int    `json:"max_sessions"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.HostEntryID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host_entry_id is required"})
		return
	}
	if body.MaxSessions < 1 {
		body.MaxSessions = 1
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if err := s.validateAppTarget(ctx, org.ID, body.HostEntryID, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id := uuid.New().String()
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO windows_app_pool_members (id, org_id, pool_id, host_entry_id, max_sessions)
		VALUES ($1, $2, $3, $4, $5)`,
		id, org.ID, c.Param("id"), body.HostEntryID, body.MaxSessions); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "failed to add member (already in pool?)"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (s *Service) handleWindowsAppPoolRemoveMember(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx,
		`DELETE FROM windows_app_pool_members WHERE id = $1 AND pool_id = $2 AND org_id = $3`,
		c.Param("memberId"), c.Param("id"), org.ID)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- Host posture state ----

type windowsAppHostState struct {
	HostEntryID                 string `json:"host_entry_id"`
	OSEdition                   string `json:"os_edition,omitempty"`
	NLAEnabled                  *bool  `json:"nla_enabled,omitempty"`
	AllowUnlistedRemotePrograms *bool  `json:"allow_unlisted_remote_programs,omitempty"`
	AllowlistEnforced           *bool  `json:"allowlist_enforced,omitempty"`
	PublishedAppCount           *int   `json:"published_app_count,omitempty"`
	CheckedAt                   string `json:"checked_at,omitempty"`
}

func (s *Service) listWindowsAppHostState(ctx context.Context, orgID string) ([]windowsAppHostState, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT host_entry_id::text, COALESCE(os_edition,''), nla_enabled,
		       allow_unlisted_remote_programs, allowlist_enforced, published_app_count, checked_at
		  FROM windows_app_host_state WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []windowsAppHostState{}
	for rows.Next() {
		var h windowsAppHostState
		if err := rows.Scan(&h.HostEntryID, &h.OSEdition, &h.NLAEnabled,
			&h.AllowUnlistedRemotePrograms, &h.AllowlistEnforced, &h.PublishedAppCount, &h.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- Discovery import (paste the host prep / discovery JSON) ----

// discoveryReport is the JSON emitted by Prepare-OpenIDXAppHost.ps1 -Report and
// posted by the agent. Kept in sync with scripts/windows/Prepare-OpenIDXAppHost.ps1.
type discoveryReport struct {
	Host struct {
		OSEdition                   string `json:"os_edition"`
		NLAEnabled                  *bool  `json:"nla_enabled"`
		AllowUnlistedRemotePrograms *bool  `json:"allow_unlisted_remote_programs"`
		AllowlistEnforced           *bool  `json:"allowlist_enforced"`
	} `json:"host"`
	Apps []discoveryApp `json:"apps"`
}

type discoveryApp struct {
	Alias      string `json:"alias"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Args       string `json:"args"`
	WorkingDir string `json:"working_dir"`
	IconB64    string `json:"icon_b64"`
	Source     string `json:"source"` // tsapp | app_paths | start_menu | appx
}

// handleWindowsAppImport — POST /pam/apps/import. Imports a discovery report
// for a host: upserts apps and records host posture. Apps seen in the host's
// TSAppAllowList (source=tsapp) are marked verified (published & launchable).
func (s *Service) handleWindowsAppImport(c *gin.Context) {
	var body struct {
		HostEntryID string `json:"host_entry_id"`
		Data        string `json:"data"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.HostEntryID == "" || strings.TrimSpace(body.Data) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host_entry_id and data are required"})
		return
	}
	var report discoveryReport
	if err := json.Unmarshal([]byte(body.Data), &report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid discovery JSON: " + err.Error()})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if err := s.validateAppTarget(ctx, org.ID, body.HostEntryID, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	created, updated := s.importDiscoveredApps(ctx, org.ID, body.HostEntryID, report.Apps, c.GetString("user_id"))
	hostUpdated := s.upsertHostState(ctx, org.ID, body.HostEntryID, &report)

	s.logAuditEvent(c, "windows_app.discovery_imported", body.HostEntryID, "pam_entry",
		map[string]interface{}{"apps_created": created, "apps_updated": updated})
	c.JSON(http.StatusOK, gin.H{"apps_created": created, "apps_updated": updated, "host_updated": hostUpdated})
}

func (s *Service) importDiscoveredApps(ctx context.Context, orgID, hostEntryID string, apps []discoveryApp, userID string) (created, updated int) {
	for _, a := range apps {
		alias := strings.TrimPrefix(strings.TrimSpace(a.Alias), "||")
		name := strings.TrimSpace(a.Name)
		if alias == "" || name == "" {
			continue
		}
		// Reject secret-looking args from a report rather than store them.
		if validateRemoteAppArgs(a.Args) != nil {
			a.Args = ""
		}
		var icon []byte
		if a.IconB64 != "" {
			if raw, derr := base64.StdEncoding.DecodeString(a.IconB64); derr == nil && len(raw) <= maxAppIconBytes && isPNG(raw) {
				icon = raw
			}
		}
		verified := a.Source == "tsapp"
		// Upsert on (org, host, alias). RETURNING xmax=0 identifies a fresh
		// insert vs an update of an existing row, so we report accurate counts.
		// verified_at is set only for published (tsapp) entries; a later publish
		// flips an unverified row.
		var wasInsert bool
		err := s.db.Pool.QueryRow(ctx, `
			INSERT INTO windows_apps (id, org_id, host_entry_id, alias, display_name, exec_path, args, working_dir,
			                          icon_png, source, verified_at, created_by)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), NULLIF($7,''),
			        $8, 'discovered', CASE WHEN $9 THEN NOW() ELSE NULL END, NULLIF($10,'')::uuid)
			ON CONFLICT (org_id, host_entry_id, alias) WHERE host_entry_id IS NOT NULL
			DO UPDATE SET display_name = EXCLUDED.display_name,
			              exec_path = COALESCE(EXCLUDED.exec_path, windows_apps.exec_path),
			              working_dir = COALESCE(EXCLUDED.working_dir, windows_apps.working_dir),
			              icon_png = COALESCE(EXCLUDED.icon_png, windows_apps.icon_png),
			              verified_at = CASE WHEN $9 THEN NOW() ELSE windows_apps.verified_at END,
			              updated_at = NOW()
			RETURNING (xmax = 0)`,
			orgID, hostEntryID, alias, name, a.Path, a.Args, a.WorkingDir, icon, verified, userID).Scan(&wasInsert)
		if err != nil {
			s.logger.Warn("importDiscoveredApps: upsert failed", zap.String("alias", scrubLogValue(alias)), zap.Error(err))
			continue
		}
		if wasInsert {
			created++
		} else {
			updated++
		}
	}
	return created, updated
}

func (s *Service) upsertHostState(ctx context.Context, orgID, hostEntryID string, report *discoveryReport) bool {
	appCount := 0
	for _, a := range report.Apps {
		if a.Source == "tsapp" {
			appCount++
		}
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO windows_app_host_state (org_id, host_entry_id, os_edition, nla_enabled,
		                                    allow_unlisted_remote_programs, allowlist_enforced, published_app_count, checked_at)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6, $7, NOW())
		ON CONFLICT (org_id, host_entry_id) DO UPDATE SET
		    os_edition = EXCLUDED.os_edition, nla_enabled = EXCLUDED.nla_enabled,
		    allow_unlisted_remote_programs = EXCLUDED.allow_unlisted_remote_programs,
		    allowlist_enforced = EXCLUDED.allowlist_enforced,
		    published_app_count = EXCLUDED.published_app_count, checked_at = NOW()`,
		orgID, hostEntryID, report.Host.OSEdition, report.Host.NLAEnabled,
		report.Host.AllowUnlistedRemotePrograms, report.Host.AllowlistEnforced, appCount); err != nil {
		s.logger.Warn("upsertHostState: failed", zap.Error(err))
		return false
	}
	return true
}

// isPNG reports whether b starts with the PNG magic number.
func isPNG(b []byte) bool {
	return len(b) >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' &&
		b[4] == '\r' && b[5] == '\n' && b[6] == 0x1a && b[7] == '\n'
}
