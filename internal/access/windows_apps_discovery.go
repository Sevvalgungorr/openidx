// Package access — Windows application delivery: agent-based discovery (P3).
//
// The paste-import path (handleWindowsAppImport) lets an admin copy the JSON
// that Prepare-OpenIDXAppHost.ps1 -Report prints into the console. This file
// adds the automated path: the OpenIDX agent installed on the host runs the
// same -Report and POSTs the identical discoveryReport JSON to a public
// agent endpoint, so the catalog stays in sync without manual pasting.
//
// Because the agent authenticates with its own X-Agent-ID + X-Auth-Token
// credentials (not a tenant JWT), the endpoint cannot read the tenant from an
// org context. Instead an admin binds the agent to the windows_app_host
// pam_entry it prepares (migration v120: enrolled_agents.windows_app_host_entry_id);
// the endpoint resolves the host + its org_id from that link and reuses
// importDiscoveredApps + upsertHostState exactly as the paste path does.
package access

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// verifyAgentToken checks an agent's X-Auth-Token against the stored
// enrolled_agents.auth_token_hash, mirroring RemoteSupportHandler.verifyAgentAuth
// so the Windows-app discovery endpoint authenticates agents the same way as
// /agent/report and the remote-support WebSocket. Dev mode (no DB) accepts any
// non-empty token, matching the other agent surfaces.
func (s *Service) verifyAgentToken(ctx context.Context, agentID, token string) bool {
	if agentID == "" || token == "" {
		return false
	}
	if s.db == nil || s.db.Pool == nil {
		return token != "" // dev mode: any non-empty token
	}
	// Agent callback carries no tenant context; enrolled_agents is a global
	// fleet table keyed on the globally-unique agent_id, so bypass RLS.
	ctx = orgctx.WithBypassRLS(ctx)
	var stored string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT auth_token_hash FROM enrolled_agents WHERE agent_id = $1`,
		agentID).Scan(&stored); err != nil {
		return false
	}
	return sha256Hex(token) == stored
}

// handleAgentWindowsAppReport — POST /agent/windows-apps/report (public agent
// surface). An agent bound to a windows_app_host posts the discoveryReport JSON
// that Prepare-OpenIDXAppHost.ps1 -Report emits; the handler resolves the host
// + its tenant from the binding and upserts the apps and host posture, reusing
// the same importDiscoveredApps / upsertHostState the admin paste path uses.
//
// Auth is X-Agent-ID + X-Auth-Token (same as /agent/report), NOT a tenant JWT,
// so this route is registered outside the JWT middleware. A report from an
// agent that isn't bound to a host is refused (412) rather than silently
// dropped, so an operator can tell discovery is mis-wired.
func (s *Service) handleAgentWindowsAppReport(c *gin.Context) {
	agentID := strings.TrimSpace(c.GetHeader("X-Agent-ID"))
	token := c.GetHeader("X-Auth-Token")
	ctx := c.Request.Context()

	if !s.verifyAgentToken(ctx, agentID, token) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid agent credentials"})
		return
	}

	// Resolve the bound host + its tenant. Bypass RLS: the lookup keys on the
	// globally-unique agent_id and the pam_entries FK, and the agent request
	// carries no org context. org_id comes from the host entry, not the agent.
	rctx := orgctx.WithBypassRLS(ctx)
	var hostEntryID, orgID string
	err := s.db.Pool.QueryRow(rctx, `
		SELECT ea.windows_app_host_entry_id::text, pe.org_id::text
		  FROM enrolled_agents ea
		  JOIN pam_entries pe ON pe.id = ea.windows_app_host_entry_id
		 WHERE ea.agent_id = $1 AND ea.windows_app_host_entry_id IS NOT NULL`,
		agentID).Scan(&hostEntryID, &orgID)
	if err != nil {
		c.JSON(http.StatusPreconditionFailed, gin.H{
			"error": "this agent is not linked to a Windows app host; link it in Windows Apps → host settings"})
		return
	}

	var report discoveryReport
	if err := json.NewDecoder(c.Request.Body).Decode(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid discovery JSON: " + err.Error()})
		return
	}

	// Scope the writes to the resolved tenant explicitly (org_id is passed to
	// every statement) while bypassing RLS, matching the posture-bridge pattern
	// used by the other agent callbacks.
	created, updated := s.importDiscoveredApps(rctx, orgID, hostEntryID, report.Apps, "")
	s.upsertHostState(rctx, orgID, hostEntryID, &report)

	s.logger.Info("windows app discovery report accepted",
		zap.String("agent_id", scrubLogValue(agentID)),
		zap.String("host_entry_id", hostEntryID),
		zap.Int("apps_created", created),
		zap.Int("apps_updated", updated))

	c.JSON(http.StatusOK, gin.H{"apps_created": created, "apps_updated": updated})
}

// ---- Admin: bind an enrolled agent to a Windows app host ----

// handleWindowsAppHostLinkAgent — POST /pam/app-hosts/:entryId/agent
// {agent_id}. Binds an enrolled agent to a windows_app_host entry so its
// discovery reports route to that host. Verifies the entry is a
// windows_app_host in the caller's tenant before writing the link. Any prior
// binding of the same agent to another host is replaced (an agent prepares one
// host). Clearing a stale binding on a different agent for this host keeps the
// invariant "at most one agent per host" so the discovery source is unambiguous.
func (s *Service) handleWindowsAppHostLinkAgent(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	entryID := c.Param("entryId")
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.AgentID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}
	agentID := strings.TrimSpace(body.AgentID)

	// Confirm the entry is a windows_app_host in this tenant.
	if err := s.validateAppTarget(ctx, org.ID, entryID, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The agent exists in the global fleet (bypass RLS for that check only).
	rctx := orgctx.WithBypassRLS(ctx)
	var exists bool
	if err := s.db.Pool.QueryRow(rctx,
		`SELECT EXISTS(SELECT 1 FROM enrolled_agents WHERE agent_id = $1)`, agentID).Scan(&exists); err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "enrolled agent not found"})
		return
	}

	// Enforce one agent per host: clear any other agent currently bound to this
	// host, then bind the requested agent.
	if _, err := s.db.Pool.Exec(rctx,
		`UPDATE enrolled_agents SET windows_app_host_entry_id = NULL
		  WHERE windows_app_host_entry_id = $1 AND agent_id <> $2`, entryID, agentID); err != nil {
		s.logger.Warn("link agent: clearing prior binding failed", zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(rctx,
		`UPDATE enrolled_agents SET windows_app_host_entry_id = $1 WHERE agent_id = $2`,
		entryID, agentID); err != nil {
		s.logger.Error("link agent: bind failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to link agent"})
		return
	}

	s.logAuditEvent(c, "windows_app.host_agent_linked", entryID, "pam_entry",
		map[string]interface{}{"agent_id": agentID})
	c.JSON(http.StatusOK, gin.H{"host_entry_id": entryID, "agent_id": agentID})
}

// handleWindowsAppHostUnlinkAgent — DELETE /pam/app-hosts/:entryId/agent.
// Removes the agent binding for a host (verified to be a windows_app_host in
// the caller's tenant). Idempotent: unlinking an already-unlinked host succeeds.
func (s *Service) handleWindowsAppHostUnlinkAgent(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	entryID := c.Param("entryId")
	if err := s.validateAppTarget(ctx, org.ID, entryID, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rctx := orgctx.WithBypassRLS(ctx)
	if _, err := s.db.Pool.Exec(rctx,
		`UPDATE enrolled_agents SET windows_app_host_entry_id = NULL WHERE windows_app_host_entry_id = $1`,
		entryID); err != nil {
		s.logger.Error("unlink agent: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unlink agent"})
		return
	}
	s.logAuditEvent(c, "windows_app.host_agent_unlinked", entryID, "pam_entry", nil)
	c.Status(http.StatusNoContent)
}

// ---- Host → agent binding surfacing (for the console) ----

// windowsAppHostAgent reports which enrolled agent is bound to a host entry, so
// the Windows Apps page can show discovery status ("agent linked, last seen …")
// alongside the pasted-import fallback.
type windowsAppHostAgent struct {
	HostEntryID string `json:"host_entry_id"`
	AgentID     string `json:"agent_id"`
	AgentStatus string `json:"agent_status,omitempty"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
}

// listWindowsAppHostAgents returns the agent bindings for every windows_app_host
// entry in the tenant. It joins the global enrolled_agents fleet to this org's
// windows_app_host entries, so it needs the entry set from an org-scoped read;
// the join predicate restricts to entries owned by orgID.
func (s *Service) listWindowsAppHostAgents(ctx context.Context, orgID string) ([]windowsAppHostAgent, error) {
	// Bypass RLS to read the global enrolled_agents table, but constrain the
	// join to windows_app_host entries owned by this tenant so only in-tenant
	// bindings are returned.
	rctx := orgctx.WithBypassRLS(ctx)
	rows, err := s.db.Pool.Query(rctx, `
		SELECT ea.windows_app_host_entry_id::text, ea.agent_id,
		       COALESCE(ea.status,''), COALESCE(ea.last_seen_at::text,'')
		  FROM enrolled_agents ea
		  JOIN pam_entries pe ON pe.id = ea.windows_app_host_entry_id
		 WHERE ea.windows_app_host_entry_id IS NOT NULL
		   AND pe.org_id = $1 AND pe.entry_type = 'windows_app_host'`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []windowsAppHostAgent{}
	for rows.Next() {
		var a windowsAppHostAgent
		if err := rows.Scan(&a.HostEntryID, &a.AgentID, &a.AgentStatus, &a.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
