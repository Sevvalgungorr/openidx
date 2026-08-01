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
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// remoteAppSecretArgRE matches credential-looking tokens in a RemoteApp
// command line. RDP passes remote-app-args verbatim and they are visible in the
// target's process list (Task Manager, `Get-CimInstance Win32_Process`), so a
// password placed there leaks to anyone who can see processes on the host. We
// reject the common forms and steer admins to integrated auth (e.g. SSMS `-E`,
// which authenticates as the vault-injected Windows identity — no secret in the
// args at all). Case-insensitive; matches `-P xxx`, `/password:xxx`,
// `--pass=xxx`, `pwd=xxx`, `pass=xxx`.
var remoteAppSecretArgRE = regexp.MustCompile(`(?i)(^|\s)(-{1,2}p(ass(word)?)?|/pass(word)?)([\s:=]|$)|(?i)(^|\s|;|&)(password|passwd|pwd)\s*=`)

// errRemoteAppSecretArg is returned when RemoteApp args appear to carry a
// secret. Callers surface it to the admin (on save) or the user (on launch).
var errRemoteAppSecretArg = errors.New(
	"remote-app-args must not contain a password — RDP command lines are visible in the target's process list. " +
		"Use integrated authentication instead (e.g. SSMS \"-E\"), which signs in as the injected Windows identity")

// validateRemoteAppArgs rejects credential-looking RemoteApp command-line
// arguments. Empty args are always fine.
func validateRemoteAppArgs(args string) error {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	if remoteAppSecretArgRE.MatchString(args) {
		return errRemoteAppSecretArg
	}
	return nil
}

// pamReservedGuacParams are connection parameters an entry's settings JSON may
// NOT override: injected credentials, identity fields, endpoint address,
// recording configuration, and the GFX toggle all come from the entry columns
// / server config. `disable-gfx` is reserved because RemoteApp launches must
// force it on (see forcePamRemoteAppParams) — a stored setting must never be
// able to re-enable GFX and reintroduce the GUACAMOLE-2123 blank-window bug.
var pamReservedGuacParams = map[string]bool{
	"password": true, "private-key": true, "passphrase": true,
	"username": true, "domain": true,
	"hostname": true, "port": true,
	"recording-path": true, "recording-name": true, "recording-include-keys": true,
	"disable-gfx": true,
}

// forcePamRemoteAppParams applies the server-mandated overrides for RemoteApp
// (single published Windows application) launches. Guacamole 1.6.0 enables the
// RDP Graphics Pipeline (GFX) by default, but RemoteApp windows fail to repaint
// with GFX on (GUACAMOLE-2123). Whenever a launch is a RemoteApp — signalled by
// a non-empty `remote-app` parameter — we force `disable-gfx=true` server-side.
// `disable-gfx` is in pamReservedGuacParams so stored settings can never turn
// it back on. No-op for full-desktop RDP, which keeps GFX for responsiveness.
func forcePamRemoteAppParams(params map[string]string) {
	if params["remote-app"] != "" {
		params["disable-gfx"] = "true"
	}
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
	// RemoteApp launches must run with GFX disabled (GUACAMOLE-2123); applied
	// after the settings/credential layering so nothing can override it.
	forcePamRemoteAppParams(params)
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

	// Everything from broker selection onward is the shared launch core, reused
	// by the Windows-app launch path.
	res, ok := s.launchPamSession(c, org.ID, &entry, typeInfo.Protocol, nil, "pam-"+entry.ID, entry.GuacConnectionID,
		func(ctx context.Context, connID string) {
			if _, err := s.db.Pool.Exec(ctx,
				`UPDATE pam_entries SET guacamole_connection_id = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
				connID, entry.ID, org.ID); err != nil {
				s.logger.Warn("handlePamConnect: persist connection id failed", zap.Error(err))
			}
		})
	if !ok {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"launch_type":         "guacamole",
		"connect_url":         res.ConnectURL,
		"entry_id":            entryID,
		"session_id":          res.SessionID,
		"credential_injected": res.Injected,
		"recorded":            entry.RecordSession,
		"reach_mode":          entry.ReachMode,
	})
}

// pamSessionResult is the outcome of a successful brokered launch.
type pamSessionResult struct {
	ConnectURL string
	ConnID     string
	SessionID  string
	Injected   bool
	GuacUser   string
}

// launchPamSession runs the post-gate brokered-launch core shared by
// entry-connect (handlePamConnect) and Windows-app launch (handleWindowsAppLaunch):
// broker selection → credential resolution → vault decrypt → params (entry
// settings + extraSettings, with RemoteApp GFX forcing) → Guacamole connection
// (named connName, id persisted via persistConnID) → connect URL → session
// ledger. The caller has already loaded the host `entry` and passed ACL +
// approval (+ placement for apps).
//
// extraSettings are server-controlled parameters merged over the entry's stored
// settings (the RemoteApp keys for an app launch); connName is the deterministic
// Guacamole connection name; existingConnID is the id a prior launch persisted.
//
// Returns (result, true) on success. On any failure it has already written the
// error response to c and returns (nil, false) — the caller just returns.
func (s *Service) launchPamSession(
	c *gin.Context, orgID string, entry *pamLaunchEntry, protocol string,
	extraSettings map[string]string, connName, existingConnID string,
	persistConnID func(ctx context.Context, connID string),
) (*pamSessionResult, bool) {
	ctx := c.Request.Context()
	userID := c.GetString("user_id")

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
			return nil, false
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "no session broker is configured", "code": "broker_unconfigured"})
		return nil, false
	}
	// A ziti-reach entry also needs a live overlay to carry the target hop;
	// without it the loopback intercept dials nothing. Fail closed with a code.
	if entry.ReachMode == "ziti" && s.ziti() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "OpenZiti overlay is unavailable for this Ziti-reach connection",
			"code":  "ziti_unavailable"})
		return nil, false
	}

	// Resolve the credential source (own secret or linked credential entry).
	target, err := s.resolvePamLaunchTarget(ctx, orgID, entry)
	if err != nil {
		s.logger.Warn("launchPamSession: credential resolution failed",
			zap.String("entry_id", scrubLogValue(entry.ID)), zap.Error(err))
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return nil, false
	}

	// Decrypt server-side. The plaintext never enters any response or log.
	var cred []byte
	var secretType string
	if target.SecretID != "" && s.vaultSvc != nil {
		bctx := orgctx.WithBypassRLS(ctx)
		cred, err = s.vaultSvc.Use(bctx, target.SecretID)
		if err != nil {
			s.logger.Warn("launchPamSession: vault credential unavailable",
				zap.String("secret_id", target.SecretID), zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "credential unavailable"})
			return nil, false
		}
		//orgscope:ignore vault_secrets SELECT under bypass-RLS context to determine injection field
		_ = s.db.Pool.QueryRow(bctx,
			`SELECT type FROM vault_secrets WHERE id=$1`, target.SecretID).Scan(&secretType)
	}

	recName := fmt.Sprintf("pam-%s-%d", entry.ID, time.Now().UnixMilli())
	recPath := ""
	recFile := ""
	if entry.RecordSession {
		recPath = s.config.GuacamoleRecordingPath
		recFile = filepath.Join(recPath, recName)
	}

	// Merge server-controlled extraSettings over the entry's stored settings so
	// reserved-key filtering AND RemoteApp GFX forcing (buildPamGuacParams)
	// apply uniformly to app-derived params.
	settings := entry.Settings
	if len(extraSettings) > 0 {
		settings = make(map[string]interface{}, len(entry.Settings)+len(extraSettings))
		for k, v := range entry.Settings {
			settings[k] = v
		}
		for k, v := range extraSettings {
			settings[k] = v
		}
	}

	params := buildPamGuacParams(secretType, target.Username, target.Domain, cred,
		settings, entry.RecordSession, recPath, recName)
	injected := len(cred) > 0
	// Zero the plaintext immediately after buildPamGuacParams copies it into
	// the params map (string copies are GC-managed; same caveat as M3).
	for i := range cred {
		cred[i] = 0
	}

	dialHost, dialPort := entry.dialTarget()
	connID, err := s.ensureGuacConnection(ctx, connName, existingConnID, protocol, dialHost, dialPort, params, broker, persistConnID)
	if err != nil {
		s.logger.Error("launchPamSession: guacamole connection failed",
			zap.String("entry_id", scrubLogValue(entry.ID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare session"})
		return nil, false
	}

	if injected {
		s.logAuditEvent(c, "pam.credential_injected", entry.ID, "pam_entry",
			map[string]interface{}{
				"entry_id":  entry.ID,
				"secret_id": target.SecretID,
				"user_id":   userID,
				// Credential value intentionally omitted.
			})
	}

	// Build the browser URL before recording the launch so the per-user Guacamole
	// identity (if enabled) can be persisted on the session row for later revoke.
	connectURL, guacUser := s.connectURLForBroker(ctx, broker, orgID, userID, connID, realClientIP(c))

	sessionID := s.recordPamLaunch(c, orgID, entry, protocol, connID, injected, guacUser)
	if entry.RecordSession && sessionID != "" && recFile != "" {
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore pam_entry_sessions UPDATE keyed by its own primary key immediately after the org-scoped INSERT
			`UPDATE pam_entry_sessions SET recording_path = $2 WHERE id = $1`, sessionID, recFile); err != nil {
			s.logger.Warn("launchPamSession: recording path update failed", zap.Error(err))
		}
	}

	return &pamSessionResult{
		ConnectURL: connectURL, ConnID: connID, SessionID: sessionID,
		Injected: injected, GuacUser: guacUser,
	}, true
}

// decodePamSettings unmarshals a settings JSONB blob, tolerating NULL/garbage.
func decodePamSettings(raw []byte) map[string]interface{} {
	settings := map[string]interface{}{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &settings)
	}
	return settings
}

// ensureGuacConnection creates or refreshes a Guacamole connection by
// deterministic name with the given (credential-bearing) params, decoupled
// from any particular catalog table. The name is stable per logical target
// (pam-<entryID> for a session entry, pam-<hostID>-app-<appID> for a published
// app) so two apps on one host each get their own connection instead of
// fighting over one. existingConnID is the id persisted by a prior launch (may
// be stale); persist stores the resulting id. A vanished/duplicate connection
// is transparently recovered by name.
func (s *Service) ensureGuacConnection(
	ctx context.Context, name, existingConnID, protocol, dialHost string, dialPort int,
	params map[string]string, broker *GuacamoleClient, persist func(ctx context.Context, connID string),
) (string, error) {
	if existingConnID != "" {
		if err := broker.UpdateConnection(existingConnID, name, protocol, dialHost, dialPort, params); err == nil {
			return existingConnID, nil
		}
		s.logger.Warn("ensureGuacConnection: update failed; recreating",
			zap.String("name", name), zap.String("guac_conn_id", existingConnID))
	}
	newID, err := broker.CreateConnection(name, protocol, dialHost, dialPort, params)
	if err != nil {
		// The connection name is deterministic. If a prior launch created it but
		// we never persisted the id (failed/cross-context persist, or a stale id
		// that no longer resolves), Guacamole rejects the duplicate name. Recover
		// by finding the existing connection by name and updating it in place —
		// makes ensure idempotent regardless of persisted state.
		existingID := s.findGuacConnectionIDByName(ctx, broker, name)
		if existingID == "" {
			return "", err
		}
		if uerr := broker.UpdateConnection(existingID, name, protocol, dialHost, dialPort, params); uerr != nil {
			s.logger.Warn("ensureGuacConnection: update of existing connection failed",
				zap.String("name", name), zap.Error(uerr))
		}
		newID = existingID
	}
	if persist != nil {
		persist(ctx, newID)
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
