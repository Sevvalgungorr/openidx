package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// SyncResult represents the result of syncing a single user to Ziti.
type SyncResult struct {
	UserID     string   `json:"user_id"`
	ZitiID     string   `json:"ziti_id"`
	Created    bool     `json:"created"`
	Attributes []string `json:"attributes"`
	Error      string   `json:"error,omitempty"`
}

// BatchSyncResult represents the result of a batch sync operation.
type BatchSyncResult struct {
	UsersSynced  int `json:"users_synced"`
	UsersFailed  int `json:"users_failed"`
	GroupsSynced int `json:"groups_synced"`
}

// SyncStatus represents the current state of user-to-Ziti sync.
type SyncStatus struct {
	Status          string     `json:"status"`
	LastFullSyncAt  *time.Time `json:"last_full_sync_at,omitempty"`
	LastAutoSyncAt  *time.Time `json:"last_auto_sync_at,omitempty"`
	UsersSynced     int        `json:"users_synced"`
	UsersFailed     int        `json:"users_failed"`
	GroupsSynced    int        `json:"groups_synced"`
	UnsyncedUsers   int        `json:"unsynced_users"`
	TotalUsers      int        `json:"total_users"`
	TotalIdentities int        `json:"total_identities"`
}

// getUserGroupNames returns the names of all groups a user belongs to.
func (zm *ZitiManager) getUserGroupNames(ctx context.Context, userID string) ([]string, error) {
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore Ziti user-sync engine; keyed by globally-unique user_id (a user belongs to exactly one org), so the membership set is org-bounded
		`SELECT g.name, g.org_id FROM groups g
		 JOIN group_memberships gm ON gm.group_id = g.id
		 WHERE gm.user_id = $1
		 ORDER BY g.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("query group memberships: %w", err)
	}
	defer rows.Close()

	perOrg := zm.cfg != nil && zm.cfg.ZitiPerOrgAttributes
	var names []string
	for rows.Next() {
		var name string
		var orgID *string
		if err := rows.Scan(&name, &orgID); err != nil {
			continue
		}
		if perOrg {
			name = orgScopedAttr(orgID, name)
		}
		names = append(names, name)
	}
	return names, nil
}

// orgScopedAttr namespaces a Ziti role attribute by its owning org so that two
// tenants' identically named groups (e.g. "engineers") map to distinct overlay
// attributes and cannot dial each other's services. The result is sanitized to
// the Ziti-legal attribute charset (alphanumerics, '-', '.', '_'). A nil/empty
// org falls back to the bare name so global groups keep their existing policies.
func orgScopedAttr(orgID *string, name string) string {
	if orgID == nil || *orgID == "" {
		return sanitizeAttr(name)
	}
	return "org-" + sanitizeAttr(*orgID) + "-" + sanitizeAttr(name)
}

// sanitizeAttr coerces an arbitrary string into the Ziti role-attribute charset.
// Any character outside [A-Za-z0-9._-] becomes '-'; runs are not collapsed so the
// mapping is deterministic and reversible enough for auditing.
func sanitizeAttr(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			b = append(b, c)
		default:
			b = append(b, '-')
		}
	}
	return string(b)
}

// SyncUserToZiti creates a Ziti identity for a user if one doesn't exist,
// and syncs their group memberships as role attributes.
func (zm *ZitiManager) SyncUserToZiti(ctx context.Context, userID string) (*SyncResult, error) {
	// Check if user already has a Ziti identity
	var existingID string
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore Ziti user-sync engine; one identity per globally-unique user_id, so the lookup is org-bounded
		`SELECT id FROM ziti_identities WHERE user_id = $1`, userID).Scan(&existingID)
	if err == nil {
		// Already has identity — just sync group attributes
		if syncErr := zm.SyncGroupAttributesForUser(ctx, userID); syncErr != nil {
			return &SyncResult{UserID: userID, Created: false, Error: syncErr.Error()}, syncErr
		}
		return &SyncResult{UserID: userID, Created: false}, nil
	}

	// Fetch user info to verify user exists; capture the user's org so the Ziti
	// identity row is tagged with it (org is derived from the user, since this
	// runs from the background poller without a request context).
	var username, userOrgID string
	err = zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore Ziti user-sync engine; keyed by globally-unique user_id, org_id is selected and propagated to the identity row below
		`SELECT username, org_id FROM users WHERE id = $1 AND enabled = true`, userID).Scan(&username, &userOrgID)
	if err != nil {
		return nil, fmt.Errorf("user %s not found or disabled: %w", userID, err)
	}

	// Get group names + device trust for initial role attributes
	attrs, err := zm.buildUserAttributes(ctx, userID)
	if err != nil {
		zm.logger.Warn("Failed to build attributes for user", zap.String("user_id", userID), zap.Error(err))
		attrs = []string{}
	}

	// Create Ziti identity (name = userID for unique linking). If the controller
	// already has an identity with this name — e.g. seeded out-of-band, or a DB
	// reset left the controller ahead of the ziti_identities table — adopt it
	// rather than failing on the duplicate-name unique constraint. This keeps the
	// sync convergent when the controller and DB drift apart.
	zitiID, enrollmentJWT, err := zm.CreateIdentity(ctx, userID, "User", attrs)
	if err != nil {
		existing := zm.findResourceByName("identities", userID)
		if existing == "" {
			return nil, fmt.Errorf("create ziti identity for user %s: %w", userID, err)
		}
		zm.logger.Info("Adopting pre-existing Ziti identity for user",
			zap.String("user_id", userID), zap.String("ziti_id", existing))
		zitiID = existing
		if perr := zm.PatchIdentityRoleAttributes(ctx, zitiID, attrs); perr != nil {
			zm.logger.Warn("Failed to patch attributes on adopted identity",
				zap.String("user_id", userID), zap.Error(perr))
		}
	}

	// Persist to DB
	attrsJSON, _ := json.Marshal(attrs)
	_, err = zm.db.Pool.Exec(ctx,
		`INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, enrollment_jwt, attributes, group_attrs_synced_at, org_id)
		 VALUES ($1, $2, 'User', $3, $4, $5, NOW(), $6)`,
		zitiID, userID, userID, enrollmentJWT, attrsJSON, userOrgID)
	if err != nil {
		return nil, fmt.Errorf("persist ziti identity for user %s: %w", userID, err)
	}

	// When BrowZer is enabled, wire the fresh identity for external-JWT (OIDC)
	// auth so the user can reach BrowZer-enabled services immediately, rather
	// than waiting for the next group-attribute reconcile.
	zm.applyBrowZerAuth(ctx, zitiID, userID)

	zm.logger.Info("Auto-synced user to Ziti identity",
		zap.String("user_id", userID),
		zap.String("username", username),
		zap.String("ziti_id", zitiID),
		zap.Strings("attributes", attrs))

	return &SyncResult{
		UserID:     userID,
		ZitiID:     zitiID,
		Created:    true,
		Attributes: attrs,
	}, nil
}

// SyncAllUsersToZiti creates Ziti identities for all users that don't have one,
// and refreshes group attributes for all linked identities.
func (zm *ZitiManager) SyncAllUsersToZiti(ctx context.Context) (*BatchSyncResult, error) {
	// Mark sync as running
	zm.db.Pool.Exec(ctx,
		`UPDATE ziti_user_sync SET status='running', updated_at=NOW()
		 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`)

	// Find all enabled users without Ziti identities
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore Ziti user-sync background sweep across all orgs (install-wide users -> Ziti mirror)
		`SELECT u.id FROM users u
		 LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		 WHERE zi.id IS NULL AND u.enabled = true`)
	if err != nil {
		zm.db.Pool.Exec(ctx,
			`UPDATE ziti_user_sync SET status='failed', updated_at=NOW()
			 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`)
		return nil, fmt.Errorf("query unsynced users: %w", err)
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			userIDs = append(userIDs, id)
		}
	}

	var synced, failed int
	for _, userID := range userIDs {
		if _, err := zm.SyncUserToZiti(ctx, userID); err != nil {
			failed++
			zm.logger.Warn("Failed to sync user to Ziti", zap.String("user_id", userID), zap.Error(err))
		} else {
			synced++
		}
	}

	// Also refresh group attributes for all existing linked identities
	groupResult, _ := zm.SyncAllGroupAttributes(ctx)
	groupsSynced := 0
	if groupResult != nil {
		groupsSynced = groupResult.GroupsSynced
	}

	// Update sync status
	zm.db.Pool.Exec(ctx,
		`UPDATE ziti_user_sync SET status='completed', last_full_sync_at=NOW(),
		 users_synced=$1, users_failed=$2, groups_synced=$3, updated_at=NOW()
		 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`,
		synced, failed, groupsSynced)

	zm.logger.Info("Batch user sync completed",
		zap.Int("synced", synced), zap.Int("failed", failed), zap.Int("groups_synced", groupsSynced))

	return &BatchSyncResult{
		UsersSynced:  synced,
		UsersFailed:  failed,
		GroupsSynced: groupsSynced,
	}, nil
}

// hasUserTrustedDevice checks if a user has at least one trusted device.
func (zm *ZitiManager) hasUserTrustedDevice(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore Ziti user-sync engine; keyed by globally-unique user_id, so the device set is org-bounded
		`SELECT EXISTS(SELECT 1 FROM known_devices WHERE user_id = $1 AND trusted = true)`,
		userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check trusted devices for user %s: %w", userID, err)
	}
	return exists, nil
}

// buildUserAttributes combines group names with device trust attribute.
func (zm *ZitiManager) buildUserAttributes(ctx context.Context, userID string) ([]string, error) {
	groups, err := zm.getUserGroupNames(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get groups for user %s: %w", userID, err)
	}

	// #device-trusted iff the user has any trusted device.
	hasTrusted, err := zm.hasUserTrustedDevice(ctx, userID)
	if err != nil {
		zm.logger.Warn("Failed to check device trust", zap.String("user_id", userID), zap.Error(err))
		hasTrusted = false
	}

	// #browzer-users when BrowZer is enabled.
	_, browzer := zm.browzerAuthPolicy(ctx)

	attrs := assembleAttributes(groups, hasTrusted, browzer)

	// Per-org overlay scoping (Wave A2): when the flag is on, tag the identity
	// with a bare org marker (org-<id>) so the reconciler's per-org Dial policy
	// (openidx-orgdial-*) grants this identity only its OWN org's services. Off
	// by default → no extra attribute, install-wide behavior unchanged.
	if zm.cfg != nil && zm.cfg.ZitiPerOrgAttributes {
		if orgID := zm.userOrgID(ctx, userID); orgID != "" {
			attrs = append(attrs, orgMarkerAttr(orgID))
		}
	}
	return attrs, nil
}

// userOrgID returns the user's org_id (or "" on miss). Small helper so
// buildUserAttributes can stamp the per-org marker without widening
// getUserGroupNames' contract.
func (zm *ZitiManager) userOrgID(ctx context.Context, userID string) string {
	var orgID *string
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore Ziti user-sync engine; keyed by globally-unique user_id, selects that user's own org_id
		`SELECT org_id FROM users WHERE id = $1`, userID).Scan(&orgID)
	if err != nil || orgID == nil {
		return ""
	}
	return *orgID
}

// assembleAttributes is the pure attribute-assembly for a synced Ziti identity,
// factored out of buildUserAttributes so the policy can be unit-tested without a
// database. The canonical set is:
//   - the user's group names,
//   - #enrolled-users on EVERY identity (Tier 1 dial gate: any enrolled user),
//   - #device-trusted iff the user has a trusted device (Tier 2 dial gate),
//   - #browzer-users iff BrowZer is enabled.
//
// This is the whole roleAttributes set; the periodic group-attribute reconcile
// replaces roleAttributes wholesale, so anything omitted here is stripped off.
func assembleAttributes(groups []string, deviceTrusted, browzer bool) []string {
	attrs := make([]string, 0, len(groups)+3)
	attrs = append(attrs, groups...)
	// Every enrolled identity carries #enrolled-users so the Tier-1 dial policy
	// (#enrolled-users -> Tier-1 services) applies to any logged-in user.
	attrs = append(attrs, "enrolled-users")
	if deviceTrusted {
		attrs = append(attrs, "device-trusted")
	}
	if browzer {
		attrs = append(attrs, "browzer-users")
	}
	return attrs
}

// browzerAuthPolicy returns the BrowZer auth-policy id when BrowZer is enabled,
// otherwise ("", false). Cheap single-row lookup; returns false (no error) when
// the ziti_browzer_config table is absent or BrowZer is off, so callers can use
// it as a fast feature gate without incurring any Ziti API calls.
func (zm *ZitiManager) browzerAuthPolicy(ctx context.Context) (string, bool) {
	var authPolicyID string
	var enabled bool
	err := zm.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(auth_policy_id,''), COALESCE(enabled,false) FROM ziti_browzer_config LIMIT 1`).
		Scan(&authPolicyID, &enabled)
	if err != nil || !enabled || authPolicyID == "" {
		return "", false
	}
	return authPolicyID, true
}

// applyBrowZerAuth wires a synced identity for BrowZer external-JWT auth: it sets
// externalId = userID (which must equal the OIDC `sub` claim OpenIDX issues) and
// assigns the BrowZer auth policy, so the controller will accept the user's OIDC
// token when the clientless SDK creates an API session. No-op (after one cheap
// DB read) when BrowZer is disabled; idempotent, so it both provisions new
// identities and retrofits ones synced before BrowZer was turned on.
func (zm *ZitiManager) applyBrowZerAuth(ctx context.Context, zitiID, userID string) {
	authPolicyID, ok := zm.browzerAuthPolicy(ctx)
	if !ok {
		return
	}
	body, _ := json.Marshal(map[string]interface{}{
		"externalId":   userID,
		"authPolicyId": authPolicyID,
	})
	_, statusCode, err := zm.mgmtRequest("PATCH",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), body)
	if err != nil || statusCode != http.StatusOK {
		zm.logger.Warn("Failed to apply BrowZer auth to identity",
			zap.String("user_id", userID), zap.String("ziti_id", zitiID),
			zap.Int("status", statusCode), zap.Error(err))
		return
	}
	zm.logger.Debug("Applied BrowZer auth to identity",
		zap.String("user_id", userID), zap.String("ziti_id", zitiID))
}

// SyncGroupAttributesForUser fetches the user's current group memberships
// and device trust status, then patches their Ziti identity's role attributes.
func (zm *ZitiManager) SyncGroupAttributesForUser(ctx context.Context, userID string) error {
	// Get the user's Ziti identity
	var zitiIdentityID, zitiID string
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore Ziti user-sync engine; one identity per globally-unique user_id, so the lookup is org-bounded
		`SELECT id, ziti_id FROM ziti_identities WHERE user_id = $1`, userID).Scan(&zitiIdentityID, &zitiID)
	if err != nil {
		return fmt.Errorf("no ziti identity for user %s: %w", userID, err)
	}

	// Build attributes: groups + device trust
	attrs, err := zm.buildUserAttributes(ctx, userID)
	if err != nil {
		return err
	}

	// Patch Ziti controller
	if err := zm.PatchIdentityRoleAttributes(ctx, zitiID, attrs); err != nil {
		return fmt.Errorf("patch ziti identity attributes: %w", err)
	}

	// Update local DB
	attrsJSON, _ := json.Marshal(attrs)
	zm.db.Pool.Exec(ctx,
		//orgscope:ignore Ziti user-sync engine; updates the identity by its primary key resolved from the org-bounded user_id lookup above
		`UPDATE ziti_identities SET attributes=$1, group_attrs_synced_at=NOW(), updated_at=NOW()
		 WHERE id=$2`, attrsJSON, zitiIdentityID)

	// Reconcile BrowZer external-JWT auth on every attribute sync. This is the
	// choke point that runs for all linked identities (including ones synced
	// before BrowZer was enabled), so it retrofits externalId + auth policy on
	// existing identities, not just freshly created ones.
	zm.applyBrowZerAuth(ctx, zitiID, userID)

	return nil
}

// SyncDeviceTrustForUser re-syncs a user's Ziti identity attributes
// after a device trust change (trust granted or revoked).
func (zm *ZitiManager) SyncDeviceTrustForUser(ctx context.Context, userID string) error {
	err := zm.SyncGroupAttributesForUser(ctx, userID)
	if err != nil {
		zm.logger.Warn("Failed to sync device trust attribute",
			zap.String("user_id", userID), zap.Error(err))
		return err
	}

	zm.logger.Info("Synced device trust attribute for user", zap.String("user_id", userID))
	return nil
}

// SyncAllGroupAttributes updates role attributes for all identities linked to users.
func (zm *ZitiManager) SyncAllGroupAttributes(ctx context.Context) (*BatchSyncResult, error) {
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore Ziti user-sync background sweep across all orgs; refreshes attributes for every linked identity
		`SELECT user_id FROM ziti_identities WHERE user_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("query linked identities: %w", err)
	}
	defer rows.Close()

	var synced, failed int
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			continue
		}
		if err := zm.SyncGroupAttributesForUser(ctx, userID); err != nil {
			failed++
			zm.logger.Warn("Failed to sync group attributes", zap.String("user_id", userID), zap.Error(err))
		} else {
			synced++
		}
	}

	return &BatchSyncResult{GroupsSynced: synced, UsersFailed: failed}, nil
}

// GetSyncStatus returns the current sync state with live counts.
func (zm *ZitiManager) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	var status SyncStatus
	var lastFull, lastAuto *time.Time

	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore install-wide Ziti sync status; counts the whole users->Ziti mirror across all orgs
		`SELECT zus.status, zus.last_full_sync_at, zus.last_auto_sync_at,
		        zus.users_synced, zus.users_failed, zus.groups_synced,
		        (SELECT COUNT(*) FROM users u LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		         WHERE zi.id IS NULL AND u.enabled = true),
		        (SELECT COUNT(*) FROM users WHERE enabled = true),
		        (SELECT COUNT(*) FROM ziti_identities)
		 FROM ziti_user_sync zus LIMIT 1`).Scan(
		&status.Status, &lastFull, &lastAuto,
		&status.UsersSynced, &status.UsersFailed, &status.GroupsSynced,
		&status.UnsyncedUsers, &status.TotalUsers, &status.TotalIdentities)
	if err != nil {
		// Table may not exist yet or be empty — return defaults
		return &SyncStatus{Status: "idle"}, nil
	}

	status.LastFullSyncAt = lastFull
	status.LastAutoSyncAt = lastAuto
	return &status, nil
}

// StartUserSyncPoller starts a background goroutine that periodically checks
// for users without Ziti identities and creates them.
func (zm *ZitiManager) StartUserSyncPoller(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		zm.logger.Info("Ziti user sync poller started", zap.Duration("interval", 30*time.Second))

		// Initial delay to let services stabilize
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}

		for {
			select {
			case <-ctx.Done():
				zm.logger.Info("Ziti user sync poller stopped")
				return
			case <-ticker.C:
				zm.runAutoSync(ctx)
			}
		}
	}()
}

// runAutoSync is called each tick to sync new users and refresh stale group attributes.
func (zm *ZitiManager) runAutoSync(ctx context.Context) {
	// Find up to 10 users without Ziti identities
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore Ziti user-sync background poller sweep across all orgs (install-wide users -> Ziti mirror)
		`SELECT u.id FROM users u
		 LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		 WHERE zi.id IS NULL AND u.enabled = true
		 LIMIT 10`)
	if err != nil {
		zm.logger.Warn("Auto-sync query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	var synced int
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			continue
		}
		if _, err := zm.SyncUserToZiti(ctx, userID); err != nil {
			zm.logger.Warn("Auto-sync failed for user", zap.String("user_id", userID), zap.Error(err))
		} else {
			synced++
		}
	}

	if synced > 0 {
		zm.logger.Info("Auto-synced users to Ziti", zap.Int("count", synced))
		zm.db.Pool.Exec(ctx,
			`UPDATE ziti_user_sync SET last_auto_sync_at=NOW(), updated_at=NOW()
			 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`)
	}

	// Re-sync stale group attributes (older than 5 minutes)
	staleRows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore Ziti user-sync background poller sweep across all orgs; refreshes stale identity attributes
		`SELECT zi.user_id FROM ziti_identities zi
		 WHERE zi.user_id IS NOT NULL
		 AND (zi.group_attrs_synced_at IS NULL OR zi.group_attrs_synced_at < NOW() - INTERVAL '5 minutes')
		 LIMIT 10`)
	if err != nil {
		return
	}
	defer staleRows.Close()

	for staleRows.Next() {
		var userID string
		if err := staleRows.Scan(&userID); err != nil {
			continue
		}
		zm.SyncGroupAttributesForUser(ctx, userID)
	}

	zm.runDeprovisionSweep(ctx)
}

// runDeprovisionSweep is the revocation half of the users→Ziti mirror: it
// deletes Ziti identities whose IAM user has been disabled or deleted, so a
// revoked user's enrolled tunneler stops dialing within one poll interval.
// Without this, disabling a user in OpenIDX left their Ziti identity (and
// network access) alive indefinitely. Only user-linked identities are swept —
// infrastructure identities (access-proxy, admin, routers) have no user_id.
func (zm *ZitiManager) runDeprovisionSweep(ctx context.Context) {
	// zi.user_id is a uuid column, so the previous `AND zi.user_id != ''` forced a
	// cast of the empty-string literal to uuid and failed the whole query with 22P02
	// every sweep — leaving the revocation sweep inert. IS NOT NULL alone is correct
	// (and sufficient) for a uuid column.
	rows, err := zm.db.Pool.Query(ctx,
		//orgscope:ignore Ziti user-sync background poller sweep across all orgs (install-wide users -> Ziti mirror)
		`SELECT zi.id, zi.ziti_id, zi.user_id
		 FROM ziti_identities zi
		 LEFT JOIN users u ON u.id = zi.user_id
		 WHERE zi.user_id IS NOT NULL
		   AND (u.id IS NULL OR u.enabled = false)
		 LIMIT 10`)
	if err != nil {
		zm.logger.Warn("Deprovision sweep query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	type doomed struct{ rowID, zitiID, userID string }
	var targets []doomed
	for rows.Next() {
		var d doomed
		if err := rows.Scan(&d.rowID, &d.zitiID, &d.userID); err != nil {
			continue
		}
		targets = append(targets, d)
	}

	for _, d := range targets {
		if err := zm.DeleteIdentity(ctx, d.zitiID); err != nil {
			// Already gone on the controller (e.g. deleted out-of-band) is fine —
			// proceed to drop the DB row; anything else is retried next tick.
			if !strings.Contains(err.Error(), "status 404") {
				zm.logger.Warn("Deprovision: controller delete failed (will retry)",
					zap.String("user_id", d.userID), zap.String("ziti_id", d.zitiID), zap.Error(err))
				continue
			}
		}
		if _, err := zm.db.Pool.Exec(ctx,
			//orgscope:ignore keyed by primary key from the annotated install-wide sweep above (users -> Ziti mirror)
			`DELETE FROM ziti_identities WHERE id = $1`, d.rowID); err != nil {
			zm.logger.Warn("Deprovision: DB row delete failed",
				zap.String("user_id", d.userID), zap.Error(err))
			continue
		}
		zm.logger.Info("Deprovisioned Ziti identity for disabled/deleted user",
			zap.String("user_id", d.userID), zap.String("ziti_id", d.zitiID))
	}
}
