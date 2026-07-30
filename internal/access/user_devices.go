// Package access — per-user cross-pillar device correlation (IAM ⇄ Ziti ⇄ PAM).
//
// OpenIDX carries two per-user device registries that historically never met:
//
//	IAM   known_devices    — browser/endpoint fingerprints + a `trusted` flag,
//	                         written by the portal and the login risk engine.
//	Ziti  enrolled_agents  — endpoint agents, each with a Ziti "Device"
//	                         identity and posture/compliance reporting.
//
// Migration v80 added enrolled_agents.known_device_id, and the user-bound
// (OAuth) enrollment path now links the two. This file serves the correlated
// view: for one user, every device with its IAM trust state and its Ziti
// compliance/posture side by side, plus a device-scoped kill that severs the
// device's network access across pillars. PAM ties in at the user level (a
// privileged session records its user, not its device), so the device view
// links back to the user's access map rather than claiming per-device PAM.
//
// Registered admin-only in RegisterRoutes; every query carries an explicit
// org predicate (or is scoped through the org-verified user key).
package access

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// DevicePostureSummary is one posture check's latest result for an agent.
type DevicePostureSummary struct {
	CheckType  string     `json:"check_type"`
	Status     string     `json:"status"`
	Severity   string     `json:"severity"`
	ReportedAt *time.Time `json:"reported_at,omitempty"`
}

// DeviceIAM is the IAM device-trust side of a correlated device.
type DeviceIAM struct {
	KnownDeviceID string     `json:"known_device_id"`
	Fingerprint   string     `json:"fingerprint"`
	Name          string     `json:"name"`
	DeviceType    string     `json:"device_type"`
	IPAddress     string     `json:"ip_address,omitempty"`
	Trusted       bool       `json:"trusted"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
}

// DeviceZiti is the Ziti endpoint-agent side of a correlated device.
type DeviceZiti struct {
	AgentID          string                 `json:"agent_id"`
	ZitiIdentityID   string                 `json:"ziti_identity_id,omitempty"`
	Status           string                 `json:"status"`
	Platform         string                 `json:"platform,omitempty"`
	ManagementMode   string                 `json:"management_mode,omitempty"`
	ComplianceStatus string                 `json:"compliance_status"`
	ComplianceScore  float64                `json:"compliance_score"`
	Posture          []DevicePostureSummary `json:"posture"`
	LastSeenAt       *time.Time             `json:"last_seen_at,omitempty"`
}

// UserDeviceEntry is one physical device correlated across pillars. Source is
// "linked" (present in both registries), "iam" (browser/known device only), or
// "ziti" (agent with no linked known_devices row — token-enrolled or legacy).
type UserDeviceEntry struct {
	Source string      `json:"source"`
	IAM    *DeviceIAM  `json:"iam,omitempty"`
	Ziti   *DeviceZiti `json:"ziti,omitempty"`
}

// UserDevicesResponse is the correlated device list for one user.
type UserDevicesResponse struct {
	UserID      string            `json:"user_id"`
	Username    string            `json:"username"`
	Devices     []UserDeviceEntry `json:"devices"`
	GeneratedAt time.Time         `json:"generated_at"`
}

// handleUserDevices returns the user's devices correlated across IAM and Ziti.
// GET /api/v1/access/users/:id/devices (admin)
func (s *Service) handleUserDevices(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.Param("id")

	username, _, err := s.verifyOrgUser(ctx, org.ID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	devices, err := s.collectUserDevices(ctx, org.ID, userID)
	if err != nil {
		s.logger.Error("handleUserDevices: aggregation failed",
			zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to correlate devices"})
		return
	}

	c.JSON(http.StatusOK, UserDevicesResponse{
		UserID:      userID,
		Username:    username,
		Devices:     devices,
		GeneratedAt: time.Now().UTC(),
	})
}

// handleMyDevices returns the authenticated caller's own correlated devices
// (self-service; same correlation as the admin view, scoped to the caller).
// GET /api/v1/access/my-devices
func (s *Service) handleMyDevices(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userIDRaw, ok := c.Get("user_id")
	userID, _ := userIDRaw.(string)
	if !ok || userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	devices, err := s.collectUserDevices(ctx, org.ID, userID)
	if err != nil {
		s.logger.Error("handleMyDevices: aggregation failed",
			zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to correlate devices"})
		return
	}
	c.JSON(http.StatusOK, UserDevicesResponse{
		UserID:      userID,
		Devices:     devices,
		GeneratedAt: time.Now().UTC(),
	})
}

// collectUserDevices correlates the two registries: every known_devices row
// (with its linked agent, if any) plus every agent not linked to a known
// device. Agent-side rows are enriched with their latest posture summary.
func (s *Service) collectUserDevices(ctx context.Context, orgID, userID string) ([]UserDeviceEntry, error) {
	entries := []UserDeviceEntry{}

	// IAM known devices, LEFT JOINed to their linked agent (v80 link).
	rows, err := s.db.Pool.Query(ctx,
		`SELECT kd.id, kd.fingerprint, COALESCE(kd.name,''), COALESCE(kd.device_type,''),
		        COALESCE(kd.ip_address,''), kd.trusted, kd.last_seen_at,
		        ea.agent_id, COALESCE(ea.ziti_identity_id,''), COALESCE(ea.status,''),
		        COALESCE(ea.platform,''), COALESCE(ea.management_mode,''),
		        COALESCE(ea.compliance_status,'unknown'), COALESCE(ea.compliance_score,0),
		        ea.last_seen_at
		   FROM known_devices kd
		   LEFT JOIN enrolled_agents ea ON ea.known_device_id = kd.id
		  WHERE kd.user_id = $1 AND kd.org_id = $2
		  ORDER BY kd.last_seen_at DESC NULLS LAST, kd.created_at DESC`, userID, orgID)
	if err != nil {
		return nil, err
	}
	var agentIDs []string
	agentEntry := map[string]*DeviceZiti{}
	for rows.Next() {
		var iam DeviceIAM
		var agentID, zitiID, agentStatus, platform, mgmtMode, compStatus *string
		var compScore *float64
		var agentLastSeen *time.Time
		if err := rows.Scan(
			&iam.KnownDeviceID, &iam.Fingerprint, &iam.Name, &iam.DeviceType,
			&iam.IPAddress, &iam.Trusted, &iam.LastSeenAt,
			&agentID, &zitiID, &agentStatus, &platform, &mgmtMode,
			&compStatus, &compScore, &agentLastSeen,
		); err != nil {
			rows.Close()
			return nil, err
		}
		iamCopy := iam
		entry := UserDeviceEntry{Source: "iam", IAM: &iamCopy}
		if agentID != nil && *agentID != "" {
			entry.Source = "linked"
			z := &DeviceZiti{
				AgentID:          *agentID,
				ZitiIdentityID:   derefStr(zitiID),
				Status:           derefStr(agentStatus),
				Platform:         derefStr(platform),
				ManagementMode:   derefStr(mgmtMode),
				ComplianceStatus: derefStr(compStatus),
				ComplianceScore:  derefFloat(compScore),
				Posture:          []DevicePostureSummary{},
				LastSeenAt:       agentLastSeen,
			}
			entry.Ziti = z
			agentIDs = append(agentIDs, *agentID)
			agentEntry[*agentID] = z
		}
		entries = append(entries, entry)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Ziti agents with no linked known device (token-enrolled / legacy).
	// enrolled_agents has no org_id; scoped through the org-verified user key.
	//orgscope:ignore enrolled_agents is scoped through the org-verified enrolled_by_user_id key
	aRows, err := s.db.Pool.Query(ctx,
		`SELECT agent_id, COALESCE(ziti_identity_id,''), COALESCE(status,''),
		        COALESCE(platform,''), COALESCE(management_mode,''),
		        COALESCE(compliance_status,'unknown'), COALESCE(compliance_score,0), last_seen_at
		   FROM enrolled_agents
		  WHERE enrolled_by_user_id = $1 AND known_device_id IS NULL
		  ORDER BY enrolled_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	for aRows.Next() {
		z := &DeviceZiti{Posture: []DevicePostureSummary{}}
		if err := aRows.Scan(&z.AgentID, &z.ZitiIdentityID, &z.Status, &z.Platform,
			&z.ManagementMode, &z.ComplianceStatus, &z.ComplianceScore, &z.LastSeenAt); err != nil {
			aRows.Close()
			return nil, err
		}
		entries = append(entries, UserDeviceEntry{Source: "ziti", Ziti: z})
		agentIDs = append(agentIDs, z.AgentID)
		agentEntry[z.AgentID] = z
	}
	aRows.Close()
	if err := aRows.Err(); err != nil {
		return nil, err
	}

	// Attach each agent's latest posture result per check_type.
	if len(agentIDs) > 0 {
		if err := s.attachDevicePosture(ctx, agentIDs, agentEntry); err != nil {
			return nil, err
		}
	}

	return entries, nil
}

// attachDevicePosture fills the latest posture result per (agent, check_type)
// onto the matching DeviceZiti entries.
func (s *Service) attachDevicePosture(ctx context.Context, agentIDs []string, byAgent map[string]*DeviceZiti) error {
	//orgscope:ignore agent_posture_results keyed by globally-unique agent_id, restricted to the org-verified agent set above
	rows, err := s.db.Pool.Query(ctx,
		`SELECT DISTINCT ON (agent_id, check_type)
		        agent_id, check_type, status, COALESCE(severity,''), reported_at
		   FROM agent_posture_results
		  WHERE agent_id = ANY($1)
		  ORDER BY agent_id, check_type, reported_at DESC`, agentIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var agentID string
		var p DevicePostureSummary
		if err := rows.Scan(&agentID, &p.CheckType, &p.Status, &p.Severity, &p.ReportedAt); err != nil {
			return err
		}
		if z := byAgent[agentID]; z != nil {
			z.Posture = append(z.Posture, p)
		}
	}
	return rows.Err()
}

// DeviceRevokeResult reports what a device-scoped revoke severed.
type DeviceRevokeResult struct {
	AgentID              string    `json:"agent_id"`
	AgentRevoked         bool      `json:"agent_revoked"`
	ZitiIdentityDeleted  bool      `json:"ziti_identity_deleted"`
	ZitiEdgeSessions     int       `json:"ziti_edge_sessions_terminated"`
	ZitiAPISessions      int       `json:"ziti_api_sessions_terminated"`
	KnownDeviceUntrusted bool      `json:"known_device_untrusted"`
	ZitiControllerOnline bool      `json:"ziti_controller_online"`
	Warnings             []string  `json:"warnings,omitempty"`
	ExecutedAt           time.Time `json:"executed_at"`
}

// handleRevokeUserDevice severs one device's access across pillars: it
// terminates the agent's live Ziti sessions, deletes its Ziti Device identity,
// marks the enrolled_agent revoked, and untrusts the linked IAM known device.
// POST /api/v1/access/users/:id/devices/:agentId/revoke (admin)
func (s *Service) handleRevokeUserDevice(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.Param("id")
	agentID := c.Param("agentId")

	if _, _, err := s.verifyOrgUser(ctx, org.ID, userID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// The agent must belong to this user (defense in depth: enrolled_agents has
	// no org_id, so the enrolled_by_user_id match plus the org-verified user is
	// the tenant gate).
	var zitiIdentityID, knownDeviceID string
	//orgscope:ignore enrolled_agents scoped through the org-verified enrolled_by_user_id match
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(ziti_identity_id,''), COALESCE(known_device_id::text,'')
		   FROM enrolled_agents WHERE agent_id = $1 AND enrolled_by_user_id = $2`,
		agentID, userID).Scan(&zitiIdentityID, &knownDeviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found for this user"})
		return
	}

	var reqBody struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&reqBody)

	res := s.executeDeviceRevoke(ctx, org.ID, agentID, zitiIdentityID, knownDeviceID)

	// Recompute the user's #device-trusted overlay attribute right away: if
	// this was their last trusted device, dial policies keyed on device trust
	// must stop matching now, not on the next 5-minute staleness pass.
	if zm := s.ziti(); zm != nil {
		if err := zm.SyncDeviceTrustForUser(ctx, userID); err != nil {
			s.logger.Warn("device revoke: device-trust attribute resync failed",
				zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		}
	}

	actorID, _ := c.Get("user_id")
	actorIDStr, _ := actorID.(string)
	if s.auditService != nil {
		if err := s.auditService.RecordEvent(ctx, "openidx", "device.revoked", "", userID, c.ClientIP(),
			map[string]interface{}{
				"actor_id":                      actorIDStr,
				"agent_id":                      agentID,
				"reason":                        reqBody.Reason,
				"ziti_identity_deleted":         res.ZitiIdentityDeleted,
				"ziti_edge_sessions_terminated": res.ZitiEdgeSessions,
				"ziti_api_sessions_terminated":  res.ZitiAPISessions,
				"known_device_untrusted":        res.KnownDeviceUntrusted,
			}); err != nil {
			s.logger.Warn("device revoke: unified audit write failed", zap.Error(err))
		}
	}
	s.logAuditEvent(c, "device_revoked", agentID, "enrolled_agent", map[string]interface{}{
		"user_id": userID, "reason": reqBody.Reason,
	})

	c.JSON(http.StatusOK, res)
}

// executeDeviceRevoke performs the cross-pillar device severance. Best-effort:
// each pillar failing is a warning, never aborts the rest.
func (s *Service) executeDeviceRevoke(ctx context.Context, orgID, agentID, zitiIdentityID, knownDeviceID string) *DeviceRevokeResult {
	res := &DeviceRevokeResult{AgentID: agentID, ExecutedAt: time.Now().UTC()}
	safeAgentID := scrubLogValue(agentID)
	warn := func(step string, err error) {
		s.logger.Warn("device revoke: step failed",
			zap.String("step", step), zap.String("agent_id", safeAgentID), zap.Error(err))
		res.Warnings = append(res.Warnings, step+": "+err.Error())
	}

	// Ziti: sever live circuits + delete the Device identity on the controller.
	zm := s.ziti()
	res.ZitiControllerOnline = zm != nil
	if zm != nil && zitiIdentityID != "" {
		if edge, api, err := zm.TerminateIdentitySessions(ctx, zitiIdentityID); err != nil {
			warn("terminate_ziti_sessions", err)
		} else {
			res.ZitiEdgeSessions, res.ZitiAPISessions = edge, api
		}
		if err := zm.DeleteIdentity(ctx, zitiIdentityID); err != nil {
			warn("delete_ziti_identity", err)
		} else {
			res.ZitiIdentityDeleted = true
		}
	} else if zitiIdentityID != "" {
		res.Warnings = append(res.Warnings,
			"ziti: controller not connected — network sessions not severed (revoked agent's identity delete deferred)")
	}

	// Ziti mirror + IAM: mark the agent revoked and untrust the known device.
	//orgscope:ignore enrolled_agents keyed by globally-unique agent_id resolved from the org-verified user above
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE enrolled_agents SET status = 'revoked', ziti_identity_id = NULL WHERE agent_id = $1`,
		agentID); err != nil {
		warn("revoke_agent", err)
	} else {
		res.AgentRevoked = true
	}
	if knownDeviceID != "" {
		if tag, err := s.db.Pool.Exec(ctx,
			`UPDATE known_devices SET trusted = false WHERE id = $1 AND org_id = $2`,
			knownDeviceID, orgID); err != nil {
			warn("untrust_known_device", err)
		} else if tag.RowsAffected() > 0 {
			res.KnownDeviceUntrusted = true
		}
	}

	s.logger.Info("device revoked across pillars",
		zap.String("agent_id", safeAgentID),
		zap.Bool("ziti_identity_deleted", res.ZitiIdentityDeleted),
		zap.Int("ziti_edge_sessions", res.ZitiEdgeSessions),
		zap.Bool("known_device_untrusted", res.KnownDeviceUntrusted))
	return res
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefFloat(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}
