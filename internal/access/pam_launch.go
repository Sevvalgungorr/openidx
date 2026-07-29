// Package access — PAM entry launch: passwordless brokered sessions.
//
// The "connect without a password" path of the RDM-parity PAM module
// (pam_entries.go). A launchable entry (rdp/ssh/vnc/telnet) resolves its
// credential server-side — its own vault secret or the linked credential
// entry's — and the plaintext is injected straight into the per-entry
// Guacamole connection. The browser only ever receives a connect URL: the
// user lands inside the remote session without seeing, typing, or being able
// to copy the target credential. Every launch is ACL-checked, optionally
// approval-gated, ledgered in pam_entry_sessions, optionally recorded, and
// audited.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// pamReservedGuacParams are connection parameters an entry's settings JSON may
// NOT override: injected credentials, identity fields, endpoint address, and
// recording configuration all come from the entry columns / server config.
var pamReservedGuacParams = map[string]bool{
	"password": true, "private-key": true, "passphrase": true,
	"username": true, "domain": true,
	"hostname": true, "port": true,
	"recording-path": true, "recording-name": true, "recording-include-keys": true,
}

// buildPamGuacParams assembles the Guacamole parameters for a PAM entry
// launch. Layering (later wins): protocol extras from entry settings →
// identity (username/domain) → injected credential (password, or private-key
// for ssh_key secrets) → guacd recording parameters. Reserved keys in
// settings are dropped so stored settings can never leak, replace, or
// redirect the injected credential or the recording.
func buildPamGuacParams(secretType, username, domain string, cred []byte, settings map[string]interface{}, record bool, recordingPath, recordingName string) map[string]string {
	params := map[string]string{}
	for k, v := range settings {
		if pamReservedGuacParams[k] {
			continue
		}
		if sv, ok := v.(string); ok && sv != "" {
			params[k] = sv
		}
	}
	if username != "" {
		params["username"] = username
	}
	if domain != "" {
		params["domain"] = domain
	}
	if len(cred) > 0 {
		if secretType == "ssh_key" {
			params["private-key"] = string(cred)
		} else {
			params["password"] = string(cred)
		}
	}
	if record {
		params["recording-path"] = recordingPath
		params["recording-name"] = recordingName
		params["recording-include-keys"] = "true"
	}
	return params
}

// pamLaunchTarget is the credential resolution result for a launch: which
// vault secret to inject and under which account identity.
type pamLaunchTarget struct {
	SecretID string
	Username string
	Domain   string
}

// resolvePamLaunchTarget picks the credential source for an entry: the linked
// credential entry when set (its username/domain override empty entry
// fields), otherwise the entry's own secret and identity columns.
func (s *Service) resolvePamLaunchTarget(ctx context.Context, orgID string, entry *pamLaunchEntry) (pamLaunchTarget, error) {
	target := pamLaunchTarget{
		SecretID: entry.VaultSecretID,
		Username: entry.Username,
		Domain:   entry.Domain,
	}
	if entry.CredentialEntryID == "" {
		return target, nil
	}
	var credSecretID, credUsername, credDomain string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(vault_secret_id::text,''), COALESCE(username,''), COALESCE(domain,'')
		  FROM pam_entries WHERE id = $1 AND org_id = $2`,
		entry.CredentialEntryID, orgID).Scan(&credSecretID, &credUsername, &credDomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target, errors.New("linked credential entry not found")
		}
		return target, err
	}
	target.SecretID = credSecretID
	if credUsername != "" {
		target.Username = credUsername
	}
	if credDomain != "" {
		target.Domain = credDomain
	}
	return target, nil
}

// pamLaunchEntry carries the pam_entries columns the launch path needs.
type pamLaunchEntry struct {
	ID                string
	Name              string
	EntryType         string
	Hostname          string
	Port              int
	Username          string
	Domain            string
	URL               string
	Settings          map[string]interface{}
	VaultSecretID     string
	CredentialEntryID string
	GuacConnectionID  string
	RequireApproval   bool
	RecordSession     bool
	ReachMode         string
	ZitiInterceptPort int
}

// dialTarget returns the host:port guacd should open the protocol connection
// to. In ziti reach mode this is the broker's Ziti intercept address (the
// ziti-tunnel carries it over the overlay to the edge-router-hosted target); in
// direct mode it is the entry's real target. Falls back to the real target if a
// ziti entry somehow has no intercept port assigned.
//
// The intercept host is a NON-loopback Ziti IP (pamZitiInterceptHost) rather
// than 127.0.0.1: ziti-edge-tunnel runs in TUN mode and cannot intercept
// loopback traffic (the kernel short-circuits 127.0.0.0/8 before it reaches the
// tun device), so guacd dialing 127.0.0.1 got connection-refused. Dialing a
// tun-routed address lets the tunnel capture it and dial the service. The
// per-entry intercept config must advertise this same address.
func (e *pamLaunchEntry) dialTarget() (host string, port int) {
	if e.ReachMode == "ziti" && e.ZitiInterceptPort > 0 {
		return pamZitiInterceptHost, e.ZitiInterceptPort
	}
	return e.Hostname, e.Port
}

// handlePamConnect — POST /pam/entries/:id/connect (connect grant or admin).
//
// Passwordless launch: resolves the entry's credential inside the service,
// pushes it into the per-entry Guacamole connection, and returns only the
// connect URL. Website entries return their URL (no brokering). 403s when a
// required approval is missing — the UI then offers "request access".
func (s *Service) handlePamConnect(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	isAdmin := s.pamCallerIsAdmin(c)

	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, entry_type, COALESCE(hostname,''), COALESCE(port,0),
		       COALESCE(username,''), COALESCE(domain,''), COALESCE(url,''), settings,
		       COALESCE(vault_secret_id::text,''), COALESCE(credential_entry_id::text,''),
		       COALESCE(guacamole_connection_id,''), require_approval, record_session,
		       reach_mode, COALESCE(ziti_intercept_port,0)
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID)

	var entry pamLaunchEntry
	var settingsJSON []byte
	if err := row.Scan(
		&entry.ID, &entry.Name, &entry.EntryType, &entry.Hostname, &entry.Port,
		&entry.Username, &entry.Domain, &entry.URL, &settingsJSON,
		&entry.VaultSecretID, &entry.CredentialEntryID,
		&entry.GuacConnectionID, &entry.RequireApproval, &entry.RecordSession,
		&entry.ReachMode, &entry.ZitiInterceptPort,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamConnect: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}
	entry.Settings = decodePamSettings(settingsJSON)

	typeInfo, ok := pamEntryTypeByName[entry.EntryType]
	if !ok || typeInfo.Kind != "session" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entry is not a launchable session"})
		return
	}

	if !isAdmin {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "connect")
		if aclErr != nil {
			s.logger.Error("handlePamConnect: ACL check failed", zap.Error(aclErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}

	// Approval gate — single-use, atomically consumed. Admins (the approvers)
	// bypass their own gate.
	if entry.RequireApproval && !isAdmin {
		consumed, gateErr := s.checkAndConsumePamApproval(ctx, entryID, userID)
		if gateErr != nil {
			s.logger.Error("handlePamConnect: approval check failed", zap.Error(gateErr))
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval"})
			return
		}
		if !consumed {
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval", "approval_required": true})
			return
		}
	}

	// Website entries: no brokering — hand back the URL. The password (if
	// any) stays in the vault, retrievable only via the audited reveal path.
	if typeInfo.Protocol == "" {
		s.recordPamLaunch(c, org.ID, &entry, "", "", false, "")
		c.JSON(http.StatusOK, gin.H{"launch_type": "url", "url": entry.URL, "entry_id": entryID})
		return
	}

	// Route to the broker matching the connection's per-entry choice: the
	// dedicated OpenZiti broker for reach_mode='ziti' (its guacd rides the
	// overlay), the direct broker otherwise. Fail closed when that broker isn't
	// configured — never launch a ziti connection through the direct broker
	// (it can't see the overlay loopback ports) or vice-versa.
	broker := s.brokerFor(entry.ReachMode)
	if broker == nil {
		if entry.ReachMode == "ziti" {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "the OpenZiti PAM broker is not configured", "code": "ziti_broker_unconfigured"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "no session broker is configured", "code": "broker_unconfigured"})
		return
	}
	// A ziti-reach entry also needs a live overlay to carry the target hop;
	// without it the loopback intercept dials nothing. Fail closed with a code.
	if entry.ReachMode == "ziti" && s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "OpenZiti overlay is unavailable for this Ziti-reach connection",
			"code":  "ziti_unavailable"})
		return
	}

	// Resolve the credential source (own secret or linked credential entry).
	target, err := s.resolvePamLaunchTarget(ctx, org.ID, &entry)
	if err != nil {
		s.logger.Warn("handlePamConnect: credential resolution failed",
			zap.String("entry_id", scrubLogValue(entryID)), zap.Error(err))
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	// Decrypt server-side. The plaintext never enters any response or log.
	var cred []byte
	var secretType string
	if target.SecretID != "" && s.vaultSvc != nil {
		bctx := orgctx.WithBypassRLS(ctx)
		cred, err = s.vaultSvc.Use(bctx, target.SecretID)
		if err != nil {
			s.logger.Warn("handlePamConnect: vault credential unavailable",
				zap.String("secret_id", target.SecretID), zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "credential unavailable"})
			return
		}
		//orgscope:ignore vault_secrets SELECT under bypass-RLS context to determine injection field
		_ = s.db.Pool.QueryRow(bctx,
			`SELECT type FROM vault_secrets WHERE id=$1`, target.SecretID).Scan(&secretType)
	}

	recName := fmt.Sprintf("pam-%s-%d", entryID, time.Now().UnixMilli())
	recPath := ""
	recFile := ""
	if entry.RecordSession {
		recPath = s.config.GuacamoleRecordingPath
		recFile = filepath.Join(recPath, recName)
	}

	params := buildPamGuacParams(secretType, target.Username, target.Domain, cred,
		entry.Settings, entry.RecordSession, recPath, recName)
	injected := len(cred) > 0
	// Zero the plaintext immediately after buildPamGuacParams copies it into
	// the params map (string copies are GC-managed; same caveat as M3).
	for i := range cred {
		cred[i] = 0
	}

	connID, err := s.ensurePamGuacConnection(ctx, org.ID, &entry, typeInfo.Protocol, params, broker)
	if err != nil {
		s.logger.Error("handlePamConnect: guacamole connection failed",
			zap.String("entry_id", scrubLogValue(entryID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare session"})
		return
	}

	if injected {
		s.logAuditEvent(c, "pam.credential_injected", entryID, "pam_entry",
			map[string]interface{}{
				"entry_id":  entryID,
				"secret_id": target.SecretID,
				"user_id":   userID,
				// Credential value intentionally omitted.
			})
	}

	// Build the browser URL before recording the launch so the per-user Guacamole
	// identity (if enabled) can be persisted on the session row for later revoke.
	connectURL, guacUser := s.connectURLForBroker(ctx, broker, org.ID, userID, connID, realClientIP(c))

	sessionID := s.recordPamLaunch(c, org.ID, &entry, typeInfo.Protocol, connID, injected, guacUser)
	if entry.RecordSession && sessionID != "" && recFile != "" {
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore pam_entry_sessions UPDATE keyed by its own primary key immediately after the org-scoped INSERT
			`UPDATE pam_entry_sessions SET recording_path = $2 WHERE id = $1`, sessionID, recFile); err != nil {
			s.logger.Warn("handlePamConnect: recording path update failed", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"launch_type":         "guacamole",
		"connect_url":         connectURL,
		"entry_id":            entryID,
		"session_id":          sessionID,
		"credential_injected": injected,
		"recorded":            entry.RecordSession,
		"reach_mode":          entry.ReachMode,
	})
}

// decodePamSettings unmarshals a settings JSONB blob, tolerating NULL/garbage.
func decodePamSettings(raw []byte) map[string]interface{} {
	settings := map[string]interface{}{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &settings)
	}
	return settings
}

// ensurePamGuacConnection creates or refreshes the per-entry Guacamole
// connection with the (credential-bearing) params. The connection is stable
// per entry (mirrors the M3 per-route model); a vanished connection — e.g.
// deleted inside Guacamole — is transparently recreated.
func (s *Service) ensurePamGuacConnection(ctx context.Context, orgID string, entry *pamLaunchEntry, protocol string, params map[string]string, broker *GuacamoleClient) (string, error) {
	name := "pam-" + entry.ID
	// In ziti reach mode guacd dials the broker's loopback intercept, which the
	// ziti-tunnel carries over the overlay to the target; in direct mode it dials
	// the real target. The injected credential/params are identical either way.
	dialHost, dialPort := entry.dialTarget()
	connID := entry.GuacConnectionID
	if connID != "" {
		if err := broker.UpdateConnection(connID, name, protocol, dialHost, dialPort, params); err == nil {
			return connID, nil
		}
		s.logger.Warn("ensurePamGuacConnection: update failed; recreating",
			zap.String("entry_id", entry.ID), zap.String("guac_conn_id", connID))
	}
	newID, err := broker.CreateConnection(name, protocol, dialHost, dialPort, params)
	if err != nil {
		// The connection name is deterministic (pam-<entryID>). If a prior launch
		// created it but we never persisted the id (failed/cross-context persist, or
		// a stale guacamole_connection_id that no longer resolves), Guacamole rejects
		// the duplicate name. Recover by finding the existing connection by name and
		// updating it in place — makes ensure idempotent regardless of persisted state.
		existingID := s.findGuacConnectionIDByName(ctx, broker, name)
		if existingID == "" {
			return "", err
		}
		if uerr := broker.UpdateConnection(existingID, name, protocol, dialHost, dialPort, params); uerr != nil {
			s.logger.Warn("ensurePamGuacConnection: update of existing connection failed",
				zap.String("entry_id", entry.ID), zap.Error(uerr))
		}
		newID = existingID
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE pam_entries SET guacamole_connection_id = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
		newID, entry.ID, orgID); err != nil {
		s.logger.Warn("ensurePamGuacConnection: persist connection id failed", zap.Error(err))
	}
	return newID, nil
}

// findGuacConnectionIDByName returns the Guacamole identifier of the connection
// with the given name, or "" if not found or on error. Used to recover the
// deterministic pam-<entryID> connection when its id wasn't persisted.
func (s *Service) findGuacConnectionIDByName(ctx context.Context, broker *GuacamoleClient, name string) string {
	conns, err := broker.ListConnections(ctx)
	if err != nil {
		s.logger.Warn("findGuacConnectionIDByName: list connections failed", zap.Error(err))
		return ""
	}
	for _, c := range conns {
		if c.Name == name {
			return c.ID
		}
	}
	return ""
}

// recordPamLaunch writes the pam_entry_sessions ledger row, bumps the entry's
// launch counters, and emits the pam.entry_connected audit event. Best-effort:
// a ledger failure must not block the session. Returns the session row id.
func (s *Service) recordPamLaunch(c *gin.Context, orgID string, entry *pamLaunchEntry, protocol, guacConnID string, injected bool, guacUsername string) string {
	ctx := c.Request.Context()
	userID := c.GetString("user_id")

	var sessionID string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, credential_injected, guac_username)
		VALUES ($1, $2, NULLIF($3,'')::uuid, NULLIF($4,''), NULLIF($5,''), $6, NULLIF($7,''))
		RETURNING id`,
		orgID, entry.ID, userID, protocol, guacConnID, injected, guacUsername).Scan(&sessionID); err != nil {
		s.logger.Warn("recordPamLaunch: session ledger insert failed",
			zap.String("entry_id", entry.ID), zap.Error(err))
	}

	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_entries SET last_connected_at = NOW(), connect_count = connect_count + 1
		 WHERE id = $1 AND org_id = $2`, entry.ID, orgID); err != nil {
		s.logger.Warn("recordPamLaunch: counter update failed", zap.Error(err))
	}

	s.logAuditEvent(c, "pam.entry_connected", entry.ID, "pam_entry", map[string]interface{}{
		"entry_id":            entry.ID,
		"entry_name":          entry.Name,
		"entry_type":          entry.EntryType,
		"protocol":            protocol,
		"user_id":             userID,
		"credential_injected": injected,
		"recorded":            entry.RecordSession,
	})
	return sessionID
}

// ---- Approval lifecycle (pre-connect gate) ----

// checkAndConsumePamApproval atomically consumes the most recent approved,
// unexpired pam_entry_access_requests row for (entry, user). Same single-use
// pattern as the M3 guacamole gate. RLS scopes the statement via the request
// context's app.org_id.
func (s *Service) checkAndConsumePamApproval(ctx context.Context, entryID, userID string) (bool, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore RLS on pam_entry_access_requests is enforced via the request context's app.org_id setting
		`UPDATE pam_entry_access_requests SET status = 'consumed'
		  WHERE id = (
		        SELECT id FROM pam_entry_access_requests
		         WHERE entry_id      = $1
		           AND requester_id  = $2
		           AND status        = 'approved'
		           AND (expires_at IS NULL OR expires_at > NOW())
		         ORDER BY created_at DESC
		         LIMIT 1
		  )
		  RETURNING id`,
		entryID, userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// handlePamRequestAccess — POST /pam/entries/:id/request {reason}.
// The requester must hold the connect grant (or be admin — pointless but
// harmless); the approval is an additional, single-use gate on top.
func (s *Service) handlePamRequestAccess(c *gin.Context) {
	entryID := c.Param("id")
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body) // reason is optional

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	if !s.pamCallerIsAdmin(c) {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "connect")
		if aclErr != nil || !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}

	expiresAt := time.Now().Add(time.Hour)
	var requestID string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, reason, status, expires_at)
		SELECT $1, id, $3::uuid, NULLIF($4,''), 'pending', $5 FROM pam_entries WHERE id = $2 AND org_id = $1
		RETURNING id`,
		org.ID, entryID, userID, body.Reason, expiresAt).Scan(&requestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamRequestAccess: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access request"})
		return
	}

	s.logAuditEvent(c, "pam.access_requested", requestID, "pam_entry_access_request",
		map[string]interface{}{
			"entry_id": entryID, "requester_id": userID,
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	c.JSON(http.StatusCreated, gin.H{"request_id": requestID})
}

// handlePamApproveRequest — POST /pam/entry-requests/:id/approve (admin).
func (s *Service) handlePamApproveRequest(c *gin.Context) {
	s.decidePamRequest(c, "approved", "pam.access_approved")
}

// handlePamDenyRequest — POST /pam/entry-requests/:id/deny (admin).
func (s *Service) handlePamDenyRequest(c *gin.Context) {
	s.decidePamRequest(c, "denied", "pam.access_denied")
}

func (s *Service) decidePamRequest(c *gin.Context, newStatus, auditAction string) {
	requestID := c.Param("id")
	approverID := c.GetString("user_id")

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE pam_entry_access_requests
		    SET status = $1, approver_id = NULLIF($2,'')::uuid, decided_at = NOW()
		  WHERE id = $3 AND org_id = $4 AND status = 'pending'`,
		newStatus, approverID, requestID, org.ID)
	if err != nil {
		s.logger.Error("decidePamRequest: update failed",
			zap.String("request_id", scrubLogValue(requestID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update request"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found or not pending"})
		return
	}

	s.logAuditEvent(c, auditAction, requestID, "pam_entry_access_request",
		map[string]interface{}{"request_id": requestID, "approver_id": approverID, "new_status": newStatus})
	c.JSON(http.StatusOK, gin.H{"request_id": requestID, "status": newStatus})
}

// PamAccessRequest is the API row for the approval queues.
type PamAccessRequest struct {
	ID          string     `json:"id"`
	EntryID     string     `json:"entry_id"`
	EntryName   string     `json:"entry_name"`
	EntryType   string     `json:"entry_type"`
	RequesterID string     `json:"requester_id"`
	Reason      string     `json:"reason,omitempty"`
	Status      string     `json:"status"`
	ApproverID  *string    `json:"approver_id,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func scanPamAccessRequests(rows pgx.Rows, logger *zap.Logger) []PamAccessRequest {
	requests := []PamAccessRequest{}
	for rows.Next() {
		var r PamAccessRequest
		var reason *string
		if err := rows.Scan(&r.ID, &r.EntryID, &r.EntryName, &r.EntryType, &r.RequesterID,
			&reason, &r.Status, &r.ApproverID, &r.DecidedAt, &r.ExpiresAt, &r.CreatedAt); err != nil {
			logger.Warn("scanPamAccessRequests: scan failed", zap.Error(err))
			continue
		}
		if reason != nil {
			r.Reason = *reason
		}
		requests = append(requests, r)
	}
	return requests
}

// handlePamListRequests — GET /pam/entry-requests (admin): pending queue.
func (s *Service) handlePamListRequests(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.entry_id, e.name, e.entry_type, r.requester_id::text,
		       r.reason, r.status, r.approver_id::text, r.decided_at, r.expires_at, r.created_at
		  FROM pam_entry_access_requests r
		  JOIN pam_entries e ON e.id = r.entry_id
		 WHERE r.org_id = $1 AND r.status = 'pending'
		 ORDER BY r.created_at DESC`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list requests"})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"requests": scanPamAccessRequests(rows, s.logger)})
}

// handlePamListMyRequests — GET /pam/my-entry-requests: the caller's own
// requests, newest first, all statuses.
func (s *Service) handlePamListMyRequests(c *gin.Context) {
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

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.entry_id, e.name, e.entry_type, r.requester_id::text,
		       r.reason, r.status, r.approver_id::text, r.decided_at, r.expires_at, r.created_at
		  FROM pam_entry_access_requests r
		  JOIN pam_entries e ON e.id = r.entry_id
		 WHERE r.org_id = $1 AND r.requester_id::text = $2
		 ORDER BY r.created_at DESC
		 LIMIT 100`, org.ID, userID)
	if err != nil {
		s.logger.Error("handlePamListMyRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list requests"})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"requests": scanPamAccessRequests(rows, s.logger)})
}

// ---- Session ledger ----

// PamEntrySession is the API row for the launch ledger.
type PamEntrySession struct {
	ID                 string     `json:"id"`
	EntryID            string     `json:"entry_id"`
	EntryName          string     `json:"entry_name"`
	UserID             *string    `json:"user_id,omitempty"`
	Protocol           *string    `json:"protocol,omitempty"`
	CredentialInjected bool       `json:"credential_injected"`
	RecordingAvailable bool       `json:"recording_available"`
	StartedAt          time.Time  `json:"started_at"`
	EndedAt            *time.Time `json:"ended_at,omitempty"`
	Status             string     `json:"status"`
}

// handlePamListSessions — GET /pam/sessions (admin): recent launches.
func (s *Service) handlePamListSessions(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT s.id, s.entry_id, e.name, s.user_id::text, s.protocol,
		       s.credential_injected, (COALESCE(s.recording_path,'') <> ''),
		       s.started_at, s.ended_at, s.status
		  FROM pam_entry_sessions s
		  JOIN pam_entries e ON e.id = s.entry_id
		 WHERE s.org_id = $1
		 ORDER BY s.started_at DESC
		 LIMIT 200`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListSessions: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()

	sessions := []PamEntrySession{}
	for rows.Next() {
		var r PamEntrySession
		if err := rows.Scan(&r.ID, &r.EntryID, &r.EntryName, &r.UserID, &r.Protocol,
			&r.CredentialInjected, &r.RecordingAvailable, &r.StartedAt, &r.EndedAt, &r.Status); err != nil {
			s.logger.Warn("handlePamListSessions: scan failed", zap.Error(err))
			continue
		}
		sessions = append(sessions, r)
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// handlePamEndSession — POST /pam/sessions/:id/end. The launcher (or an
// admin) marks a ledger row ended; purely bookkeeping — Guacamole session
// termination is the existing admin force-terminate surface.
func (s *Service) handlePamEndSession(c *gin.Context) {
	sessionID := c.Param("id")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	query := `UPDATE pam_entry_sessions SET status = 'ended', ended_at = NOW()
	           WHERE id = $1 AND org_id = $2 AND status = 'active'`
	args := []interface{}{sessionID, org.ID}
	if !s.pamCallerIsAdmin(c) {
		query += ` AND user_id::text = $3`
		args = append(args, userID)
	}

	tag, err := s.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		s.logger.Error("handlePamEndSession: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end session"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "active session not found"})
		return
	}

	// Best-effort JIT revoke of the per-user connection READ grant on the broker
	// that served this session (per-user identities path only).
	var connID, guacUser, reach string
	if qerr := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(pes.guac_connection_id,''), COALESCE(pes.guac_username,''),
		       COALESCE(e.reach_mode,'')
		  FROM pam_entry_sessions pes JOIN pam_entries e ON e.id = pes.entry_id
		 WHERE pes.id = $1 AND pes.org_id = $2`, sessionID, org.ID).Scan(&connID, &guacUser, &reach); qerr == nil {
		if connID != "" && guacUser != "" {
			if broker := s.brokerFor(reach); broker != nil && broker.perUserIdentities {
				if rerr := broker.revokeConnectionRead(ctx, guacUser, connID); rerr != nil {
					s.logger.Warn("handlePamEndSession: revoke connection READ failed",
						zap.String("guac_user", guacUser), zap.String("conn_id", connID), zap.Error(rerr))
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"id": sessionID, "status": "ended"})
}
