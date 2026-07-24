// Privileged-account discovery — migration v107.
//
// Before a PAM/IGA program can protect anything it must answer "which accounts
// are privileged, and which of those are actually managed?" This sweep surfaces
// the privileged population from the identity store and tracks each account to
// onboarding or acceptance:
//
//   - standing (non-expiring) privileged role grants — the ones JIT should replace;
//   - membership in privileged groups (admin/root/privileged/sudo/domain admins);
//   - service/shared-account naming patterns (svc-, service, root, sa_, daemon…);
//   - dormant privileged accounts (no login in 90+ days) — the classic audit finding.
//
// The scan is idempotent: it upserts on (org, user), refreshes last_seen_at, and
// auto-resolves a previously-flagged account that is no longer privileged.
// 'onboarded' (brought under management) and 'ignored' (accepted) are sticky.
package governance

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// privDormantDays is the no-login window past which a privileged account is
// flagged dormant.
const privDormantDays = 90

// privRoleNames is the set of role names always treated as privileged (matched
// case-insensitively). Any role whose name merely CONTAINS "admin" is also
// caught by the scan query, so this list is for the non-"admin" privileged roles.
var privRoleNames = []string{
	"admin", "super_admin", "superadmin", "administrator",
	"manager", "auditor", "security_admin", "root", "owner",
}

// discoveredAccount is the in-flight aggregation for one user across all
// privilege sources before it is upserted.
type discoveredAccount struct {
	userID      string
	username    string
	email       string
	lastLogin   *time.Time
	sources     map[string]bool
	standing    bool
	serviceAcct bool
}

func (d *discoveredAccount) addSource(src string) {
	if d.sources == nil {
		d.sources = map[string]bool{}
	}
	d.sources[src] = true
}

// PrivDiscoveryResult summarizes one discovery scan.
type PrivDiscoveryResult struct {
	AccountsFound int       `json:"accounts_found"`
	NewAccounts   int       `json:"new_accounts"`
	StandingPriv  int       `json:"standing_privilege"`
	Dormant       int       `json:"dormant"`
	AutoResolved  int       `json:"auto_resolved"`
	ScannedAt     time.Time `json:"scanned_at"`
}

// RunPrivilegedDiscovery sweeps the identity store and reconciles the
// privileged_accounts_discovered register. Reusable by the on-demand endpoint
// and (future) a scheduled worker.
func (s *Service) RunPrivilegedDiscovery(ctx context.Context, orgID string) (*PrivDiscoveryResult, error) {
	scanStart := time.Now()
	res := &PrivDiscoveryResult{ScannedAt: scanStart}
	found := map[string]*discoveredAccount{}
	get := func(userID, username, email string, lastLogin *time.Time) *discoveredAccount {
		d := found[userID]
		if d == nil {
			d = &discoveredAccount{userID: userID, username: username, email: email, lastLogin: lastLogin}
			found[userID] = d
		}
		return d
	}

	// 1) Privileged role holders. standing = the grant does not expire.
	roleRows, err := s.db.Pool.Query(ctx, `
		SELECT ur.user_id::text, u.username, COALESCE(u.email,''), u.last_login_at, r.name, (ur.expires_at IS NULL)
		  FROM user_roles ur
		  JOIN roles r ON r.id = ur.role_id
		  JOIN users u ON u.id = ur.user_id
		 WHERE u.enabled = true AND u.org_id = $1 AND ur.org_id = $1 AND r.org_id = $1
		   AND (LOWER(r.name) = ANY($2) OR LOWER(r.name) LIKE '%admin%')`, orgID, privRoleNames)
	if err != nil {
		return nil, err
	}
	for roleRows.Next() {
		var userID, username, email, roleName string
		var lastLogin *time.Time
		var standing bool
		if err := roleRows.Scan(&userID, &username, &email, &lastLogin, &roleName, &standing); err != nil {
			roleRows.Close()
			return nil, err
		}
		d := get(userID, username, email, lastLogin)
		d.addSource("role:" + roleName)
		if standing {
			d.standing = true
		}
	}
	roleRows.Close()

	// 2) Privileged group members. Group membership has no expiry → standing.
	groupRows, err := s.db.Pool.Query(ctx, `
		SELECT gm.user_id::text, u.username, COALESCE(u.email,''), u.last_login_at, g.name
		  FROM group_memberships gm
		  JOIN groups g ON g.id = gm.group_id
		  JOIN users u ON u.id = gm.user_id
		 WHERE u.enabled = true AND u.org_id = $1 AND gm.org_id = $1 AND g.org_id = $1
		   AND (LOWER(g.name) LIKE '%admin%' OR LOWER(g.name) LIKE '%privileg%'
		        OR LOWER(g.name) LIKE '%sudo%' OR LOWER(g.name) LIKE '%root%')`, orgID)
	if err != nil {
		return nil, err
	}
	for groupRows.Next() {
		var userID, username, email, groupName string
		var lastLogin *time.Time
		if err := groupRows.Scan(&userID, &username, &email, &lastLogin, &groupName); err != nil {
			groupRows.Close()
			return nil, err
		}
		d := get(userID, username, email, lastLogin)
		d.addSource("group:" + groupName)
		d.standing = true
	}
	groupRows.Close()

	// 3) Service/shared-account naming patterns. A service account is
	// interesting even if it holds no admin role — it is often a shared secret.
	svcRows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, username, COALESCE(email,''), last_login_at
		  FROM users
		 WHERE org_id = $1 AND enabled = true
		   AND (LOWER(username) ~ '^(svc|service|sa|sys|system|root|admin|daemon)[-_.]'
		        OR LOWER(username) IN ('root','admin','administrator')
		        OR LOWER(username) LIKE '%service-account%'
		        OR LOWER(username) LIKE 'svc%')`, orgID)
	if err != nil {
		return nil, err
	}
	for svcRows.Next() {
		var userID, username, email string
		var lastLogin *time.Time
		if err := svcRows.Scan(&userID, &username, &email, &lastLogin); err != nil {
			svcRows.Close()
			return nil, err
		}
		d := get(userID, username, email, lastLogin)
		d.addSource("pattern:service-account")
		d.serviceAcct = true
	}
	svcRows.Close()

	res.AccountsFound = len(found)
	dormantCutoff := scanStart.AddDate(0, 0, -privDormantDays)
	for _, d := range found {
		dormant := d.lastLogin == nil || d.lastLogin.Before(dormantCutoff)
		if dormant {
			res.Dormant++
		}
		if d.standing {
			res.StandingPriv++
		}
		isNew, err := s.upsertDiscoveredAccount(ctx, orgID, d, dormant)
		if err != nil {
			s.logger.Warn("RunPrivilegedDiscovery: upsert failed",
				zap.String("user_id", d.userID), zap.Error(err))
			continue
		}
		if isNew {
			res.NewAccounts++
		}
	}

	// Auto-resolve accounts we flagged before that are no longer privileged
	// (not refreshed this scan). 'onboarded'/'ignored' are sticky.
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE privileged_accounts_discovered
		   SET status = 'resolved',
		       notes = COALESCE(notes,'') || ' [auto-resolved: no longer privileged]'
		 WHERE org_id = $1 AND status IN ('new','acknowledged') AND last_seen_at < $2`,
		orgID, scanStart)
	if err != nil {
		return nil, err
	}
	res.AutoResolved = int(tag.RowsAffected())
	return res, nil
}

// upsertDiscoveredAccount records (or refreshes) one discovered account. Returns
// true when the row was newly created. A 'resolved' row that is privileged again
// is reopened to 'new'.
func (s *Service) upsertDiscoveredAccount(ctx context.Context, orgID string, d *discoveredAccount, dormant bool) (bool, error) {
	sources := make([]string, 0, len(d.sources))
	for src := range d.sources {
		sources = append(sources, src)
	}
	sort.Strings(sources)

	var inserted bool
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO privileged_accounts_discovered
		    (org_id, user_id, username, email, privilege_sources, standing_privilege, is_service_account, dormant, last_login_at, status)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,'new')
		ON CONFLICT (org_id, user_id) DO UPDATE
		   SET last_seen_at = NOW(),
		       username = EXCLUDED.username,
		       email = EXCLUDED.email,
		       privilege_sources = EXCLUDED.privilege_sources,
		       standing_privilege = EXCLUDED.standing_privilege,
		       is_service_account = EXCLUDED.is_service_account,
		       dormant = EXCLUDED.dormant,
		       last_login_at = EXCLUDED.last_login_at,
		       status = CASE WHEN privileged_accounts_discovered.status = 'resolved'
		                     THEN 'new' ELSE privileged_accounts_discovered.status END
		RETURNING (xmax = 0) AS inserted`,
		orgID, d.userID, d.username, d.email, sources, d.standing, d.serviceAcct, dormant, d.lastLogin).Scan(&inserted)
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// ---- HTTP handlers ----

// handleRunPrivilegedDiscovery — POST /governance/privileged-accounts/scan.
func (s *Service) handleRunPrivilegedDiscovery(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	res, err := s.RunPrivilegedDiscovery(ctx, org.ID)
	if err != nil {
		s.logger.Error("handleRunPrivilegedDiscovery: scan failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "privileged-account discovery failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// PrivilegedAccount is the API view of a privileged_accounts_discovered row.
type PrivilegedAccount struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Username          string     `json:"username"`
	Email             string     `json:"email,omitempty"`
	PrivilegeSources  []string   `json:"privilege_sources"`
	StandingPrivilege bool       `json:"standing_privilege"`
	IsServiceAccount  bool       `json:"is_service_account"`
	Dormant           bool       `json:"dormant"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	Status            string     `json:"status"`
	Notes             string     `json:"notes,omitempty"`
	FirstSeenAt       time.Time  `json:"first_seen_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
}

// handleListPrivilegedAccounts — GET /governance/privileged-accounts?status=new.
func (s *Service) handleListPrivilegedAccounts(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	q := `
		SELECT id, user_id::text, COALESCE(username,''), COALESCE(email,''), privilege_sources,
		       standing_privilege, is_service_account, dormant, last_login_at, status,
		       COALESCE(notes,''), first_seen_at, last_seen_at
		  FROM privileged_accounts_discovered
		 WHERE org_id = $1`
	args := []interface{}{org.ID}
	if status := c.Query("status"); status != "" {
		q += ` AND status = $2`
		args = append(args, status)
	}
	q += ` ORDER BY standing_privilege DESC, dormant DESC, last_seen_at DESC LIMIT 500`

	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("handleListPrivilegedAccounts: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list privileged accounts"})
		return
	}
	defer rows.Close()
	out := []PrivilegedAccount{}
	for rows.Next() {
		var p PrivilegedAccount
		if err := rows.Scan(&p.ID, &p.UserID, &p.Username, &p.Email, &p.PrivilegeSources,
			&p.StandingPrivilege, &p.IsServiceAccount, &p.Dormant, &p.LastLoginAt, &p.Status,
			&p.Notes, &p.FirstSeenAt, &p.LastSeenAt); err != nil {
			s.logger.Warn("handleListPrivilegedAccounts: scan failed", zap.Error(err))
			continue
		}
		out = append(out, p)
	}
	c.JSON(http.StatusOK, gin.H{"accounts": out})
}

// privAccountStatuses is the closed set of statuses a caller may set.
var privAccountStatuses = map[string]bool{
	"new": true, "acknowledged": true, "onboarded": true, "ignored": true, "resolved": true,
}

// handleUpdatePrivilegedAccountStatus — POST /governance/privileged-accounts/:id/status.
func (s *Service) handleUpdatePrivilegedAccountStatus(c *gin.Context) {
	var req struct {
		Status string `json:"status" binding:"required"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !privAccountStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of new, acknowledged, onboarded, ignored, resolved"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE privileged_accounts_discovered
		   SET status = $1, notes = NULLIF($2,'')
		 WHERE id = $3 AND org_id = $4`,
		req.Status, req.Notes, c.Param("id"), org.ID)
	if err != nil {
		s.logger.Error("handleUpdatePrivilegedAccountStatus: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update account"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": req.Status})
}

// handlePrivilegedStatistics — GET /governance/privileged-accounts/statistics.
func (s *Service) handlePrivilegedStatistics(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var total, standing, service, dormant, unmanaged int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE standing_privilege),
		       COUNT(*) FILTER (WHERE is_service_account),
		       COUNT(*) FILTER (WHERE dormant),
		       COUNT(*) FILTER (WHERE status IN ('new','acknowledged'))
		  FROM privileged_accounts_discovered
		 WHERE org_id = $1`, org.ID).Scan(&total, &standing, &service, &dormant, &unmanaged)
	if err != nil {
		s.logger.Error("handlePrivilegedStatistics: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load statistics"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total":              total,
		"standing_privilege": standing,
		"service_accounts":   service,
		"dormant":            dormant,
		"unmanaged":          unmanaged,
	})
}
