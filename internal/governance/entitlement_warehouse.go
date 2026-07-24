// Entitlement warehouse + orphan detection — migration v108.
//
// Entitlements lived in four disconnected tables. This gives an auditor a single
// "who has access to what" surface and surfaces orphaned entitlements — grants
// whose owning account is disabled or gone (the top SOX/ISO access-review
// finding, and exactly what attackers reuse).
//
// RunEntitlementRebuild repopulates entitlement_warehouse for one org by full
// delete + insert, unioning every source into one row-per-(user, entitlement),
// stamping each with time_bound and orphaned (owner disabled → 'disabled_owner';
// owner missing → 'missing_owner'). It is a snapshot, so it is safe to re-run
// any time.
package governance

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// EntitlementRebuildResult summarizes one warehouse rebuild.
type EntitlementRebuildResult struct {
	Entitlements int       `json:"entitlements"`
	Orphaned     int       `json:"orphaned"`
	UsersCovered int       `json:"users_covered"`
	RebuiltAt    time.Time `json:"rebuilt_at"`
}

// entitlementSourceInserts are the per-source INSERT ... SELECT statements that
// populate the warehouse. $1 = org_id, $2 = snapshot timestamp. Each LEFT JOINs
// users to compute orphaned/orphan_reason so a grant to a disabled or missing
// owner is recorded, not silently dropped.
var entitlementSourceInserts = []string{
	// Direct role assignments (time-bound when expires_at is set).
	`INSERT INTO entitlement_warehouse
	    (org_id, user_id, username, entitlement_type, entitlement_id, entitlement_name, source, actions, time_bound, expires_at, orphaned, orphan_reason, snapshot_at)
	 SELECT $1, ur.user_id, u.username, 'role', ur.role_id::text, r.name, 'user_roles', '{}'::text[],
	        (ur.expires_at IS NOT NULL), ur.expires_at,
	        (u.id IS NULL OR NOT u.enabled),
	        CASE WHEN u.id IS NULL THEN 'missing_owner' WHEN NOT u.enabled THEN 'disabled_owner' ELSE NULL END, $2
	   FROM user_roles ur
	   JOIN roles r ON r.id = ur.role_id AND r.org_id = $1
	   LEFT JOIN users u ON u.id = ur.user_id AND u.org_id = $1
	  WHERE ur.org_id = $1`,

	// Group memberships (never time-bound at the membership level).
	`INSERT INTO entitlement_warehouse
	    (org_id, user_id, username, entitlement_type, entitlement_id, entitlement_name, source, actions, time_bound, expires_at, orphaned, orphan_reason, snapshot_at)
	 SELECT $1, gm.user_id, u.username, 'group', gm.group_id::text, g.name, 'group_memberships', '{}'::text[],
	        false, NULL,
	        (u.id IS NULL OR NOT u.enabled),
	        CASE WHEN u.id IS NULL THEN 'missing_owner' WHEN NOT u.enabled THEN 'disabled_owner' ELSE NULL END, $2
	   FROM group_memberships gm
	   JOIN groups g ON g.id = gm.group_id AND g.org_id = $1
	   LEFT JOIN users u ON u.id = gm.user_id AND u.org_id = $1
	  WHERE gm.org_id = $1`,

	// Direct per-user PAM entry grants. principal_id is a VARCHAR; the regex
	// guard keeps a non-UUID value from failing the ::uuid cast.
	`INSERT INTO entitlement_warehouse
	    (org_id, user_id, username, entitlement_type, entitlement_id, entitlement_name, source, actions, time_bound, expires_at, orphaned, orphan_reason, snapshot_at)
	 SELECT $1, peg.principal_id::uuid, u.username, 'pam_entry', peg.entry_id::text, pe.name, 'pam_entry_grants', peg.actions,
	        (peg.expires_at IS NOT NULL), peg.expires_at,
	        (u.id IS NULL OR NOT u.enabled),
	        CASE WHEN u.id IS NULL THEN 'missing_owner' WHEN NOT u.enabled THEN 'disabled_owner' ELSE NULL END, $2
	   FROM pam_entry_grants peg
	   JOIN pam_entries pe ON pe.id = peg.entry_id AND pe.org_id = $1
	   LEFT JOIN users u ON u.id = peg.principal_id::uuid AND u.org_id = $1
	  WHERE peg.org_id = $1 AND peg.principal_type = 'user'
	    AND peg.principal_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'`,

	// Direct per-user vault secret grants (principal_id is already UUID-typed).
	`INSERT INTO entitlement_warehouse
	    (org_id, user_id, username, entitlement_type, entitlement_id, entitlement_name, source, actions, time_bound, expires_at, orphaned, orphan_reason, snapshot_at)
	 SELECT $1, vag.principal_id, u.username, 'vault_secret', vag.secret_id::text, vs.name, 'vault_access_grants', vag.actions,
	        (vag.expires_at IS NOT NULL), vag.expires_at,
	        (u.id IS NULL OR NOT u.enabled),
	        CASE WHEN u.id IS NULL THEN 'missing_owner' WHEN NOT u.enabled THEN 'disabled_owner' ELSE NULL END, $2
	   FROM vault_access_grants vag
	   JOIN vault_secrets vs ON vs.id = vag.secret_id AND vs.org_id = $1
	   LEFT JOIN users u ON u.id = vag.principal_id AND u.org_id = $1
	  WHERE vag.org_id = $1 AND vag.principal_type = 'user'`,
}

// RunEntitlementRebuild rebuilds the warehouse snapshot for one org inside a
// single transaction (delete-then-insert), so a reader never sees a half-built
// snapshot. Reusable by the on-demand endpoint and (future) a scheduled worker.
func (s *Service) RunEntitlementRebuild(ctx context.Context, orgID string) (*EntitlementRebuildResult, error) {
	snapshotAt := time.Now()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `DELETE FROM entitlement_warehouse WHERE org_id = $1`, orgID); err != nil {
		return nil, err
	}
	for _, stmt := range entitlementSourceInserts {
		if _, err := tx.Exec(ctx, stmt, orgID, snapshotAt); err != nil {
			return nil, err
		}
	}

	res := &EntitlementRebuildResult{RebuiltAt: snapshotAt}
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE orphaned), COUNT(DISTINCT user_id)
		  FROM entitlement_warehouse WHERE org_id = $1`, orgID).
		Scan(&res.Entitlements, &res.Orphaned, &res.UsersCovered); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// ---- HTTP handlers ----

// handleRebuildEntitlements — POST /governance/entitlements/rebuild.
func (s *Service) handleRebuildEntitlements(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	res, err := s.RunEntitlementRebuild(ctx, org.ID)
	if err != nil {
		s.logger.Error("handleRebuildEntitlements: rebuild failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "entitlement rebuild failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Entitlement is the API view of an entitlement_warehouse row.
type Entitlement struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Username     string     `json:"username,omitempty"`
	Type         string     `json:"entitlement_type"`
	Ent          string     `json:"entitlement_id"`
	Name         string     `json:"entitlement_name,omitempty"`
	Source       string     `json:"source"`
	Actions      []string   `json:"actions"`
	TimeBound    bool       `json:"time_bound"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Orphaned     bool       `json:"orphaned"`
	OrphanReason string     `json:"orphan_reason,omitempty"`
	SnapshotAt   time.Time  `json:"snapshot_at"`
}

// entitlementQuery runs a filtered warehouse query and writes the JSON response
// under the given key. Shared by the list and orphans endpoints.
func (s *Service) entitlementQuery(c *gin.Context, orgID, extraWhere string, extraArgs []interface{}, key string) {
	ctx := c.Request.Context()
	q := `
		SELECT id, user_id::text, COALESCE(username,''), entitlement_type, entitlement_id,
		       COALESCE(entitlement_name,''), source, actions, time_bound, expires_at,
		       orphaned, COALESCE(orphan_reason,''), snapshot_at
		  FROM entitlement_warehouse
		 WHERE org_id = $1` + extraWhere + ` ORDER BY orphaned DESC, user_id, entitlement_type LIMIT 2000`
	args := append([]interface{}{orgID}, extraArgs...)

	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("entitlementQuery: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query entitlements"})
		return
	}
	defer rows.Close()
	out := []Entitlement{}
	for rows.Next() {
		var e Entitlement
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Type, &e.Ent, &e.Name, &e.Source,
			&e.Actions, &e.TimeBound, &e.ExpiresAt, &e.Orphaned, &e.OrphanReason, &e.SnapshotAt); err != nil {
			s.logger.Warn("entitlementQuery: scan failed", zap.Error(err))
			continue
		}
		out = append(out, e)
	}
	c.JSON(http.StatusOK, gin.H{key: out})
}

// handleListEntitlements — GET /governance/entitlements?user_id=&type=&orphaned=true.
func (s *Service) handleListEntitlements(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	where := ""
	var args []interface{}
	n := 1
	if uid := c.Query("user_id"); uid != "" {
		n++
		where += " AND user_id = $" + strconv.Itoa(n)
		args = append(args, uid)
	}
	if typ := c.Query("type"); typ != "" {
		n++
		where += " AND entitlement_type = $" + strconv.Itoa(n)
		args = append(args, typ)
	}
	if c.Query("orphaned") == "true" {
		where += " AND orphaned = true"
	}
	s.entitlementQuery(c, org.ID, where, args, "entitlements")
}

// handleListOrphanedEntitlements — GET /governance/entitlements/orphans.
func (s *Service) handleListOrphanedEntitlements(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	s.entitlementQuery(c, org.ID, " AND orphaned = true", nil, "orphans")
}

// handleEntitlementStatistics — GET /governance/entitlements/statistics.
func (s *Service) handleEntitlementStatistics(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var total, orphaned, users int
	var lastSnapshot *time.Time
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE orphaned), COUNT(DISTINCT user_id), MAX(snapshot_at)
		  FROM entitlement_warehouse WHERE org_id = $1`, org.ID).
		Scan(&total, &orphaned, &users, &lastSnapshot); err != nil {
		s.logger.Error("handleEntitlementStatistics: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load statistics"})
		return
	}

	byType := map[string]int{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT entitlement_type, COUNT(*) FROM entitlement_warehouse WHERE org_id = $1 GROUP BY entitlement_type`, org.ID)
	if err == nil {
		for rows.Next() {
			var t string
			var n int
			if err := rows.Scan(&t, &n); err == nil {
				byType[t] = n
			}
		}
		rows.Close()
	}

	c.JSON(http.StatusOK, gin.H{
		"total_entitlements": total,
		"orphaned":           orphaned,
		"users_covered":      users,
		"by_type":            byType,
		"last_snapshot_at":   lastSnapshot,
	})
}
