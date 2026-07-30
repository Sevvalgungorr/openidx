// Privilege graph (PAM Wave C1) — the unified-architecture moat.
//
// Because OpenIDX owns the IdP, IGA, and PAM tables in one Postgres, it can
// compute transitive effective privilege natively, without the connector
// plumbing incumbents assemble by M&A. Two questions this answers:
//
//   - "Who can reach secret/target X, and by which path?"  (blast radius)
//   - "What can user U reach, and how?"                     (effective access)
//
// A grant (vault_access_grants / pam_entry_grants) targets a principal that is
// a user, a role, or a group. This resolver expands each grant to the concrete
// set of users it reaches by walking:
//   - direct user grants,
//   - role grants → user_roles, including composite_roles (role→role) transitively,
//   - group grants → group_memberships.
//
// Expired grants are excluded. All queries run under the request's org via FORCE
// RLS on the pooled connection, so results are tenant-scoped.
package access

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// privReacher is one user who can reach a resource, plus the path that grants it.
type privReacher struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Via      string   `json:"via"`     // "direct" | "role" | "group"
	Path     string   `json:"path"`    // human-readable grant path
	Actions  []string `json:"actions"` // granted actions (reveal, checkout, connect, ...)
}

// privResource is one resource a user can reach.
type privResource struct {
	Kind    string   `json:"kind"` // "secret" | "pam_entry"
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Via     string   `json:"via"`
	Path    string   `json:"path"`
	Actions []string `json:"actions"`
}

// reachSQL is the reusable recursive-CTE core: expand every grant on the given
// resource to concrete users. $1 = resource id. The caller supplies the grant
// table name (vault_access_grants or pam_entry_grants) and its resource column.
//
// expanded_roles walks composite_roles (parent→child) so a grant to a parent
// role reaches users holding any descendant role.
func reachSQL(grantTable, resourceCol string) string {
	return `
WITH RECURSIVE live_grants AS (
    -- principal_id is uuid in vault_access_grants but varchar in pam_entry_grants;
    -- normalize to text so the CTE is table-agnostic, cast to uuid at uuid joins.
    SELECT principal_type, principal_id::text AS principal_id, actions, granted_by
    FROM ` + grantTable + `
    WHERE ` + resourceCol + ` = $1
      AND (expires_at IS NULL OR expires_at > NOW())
),
-- roles reachable from each granted role, transitively via composite_roles
expanded_roles AS (
    SELECT g.principal_id AS root_role, g.principal_id::uuid AS role_id, g.actions
    FROM live_grants g WHERE g.principal_type = 'role'
    UNION
    SELECT er.root_role, cr.child_role_id, er.actions
    FROM expanded_roles er
    JOIN composite_roles cr ON cr.parent_role_id = er.role_id
),
reachers AS (
    -- direct user grants
    SELECT lg.principal_id::uuid AS user_id, 'direct'::text AS via,
           'direct grant'::text AS path, lg.actions
    FROM live_grants lg WHERE lg.principal_type = 'user'
    UNION ALL
    -- role grants (transitive) → users holding the role
    SELECT ur.user_id, 'role'::text AS via,
           'role: ' || COALESCE(r.name, er.role_id::text) AS path, er.actions
    FROM expanded_roles er
    JOIN user_roles ur ON ur.role_id = er.role_id
    LEFT JOIN roles r ON r.id = er.role_id
    UNION ALL
    -- group grants → members
    SELECT gm.user_id, 'group'::text AS via,
           'group: ' || COALESCE(gr.name, lg.principal_id) AS path, lg.actions
    FROM live_grants lg
    JOIN group_memberships gm ON gm.group_id = lg.principal_id::uuid
    LEFT JOIN groups gr ON gr.id = lg.principal_id::uuid
    WHERE lg.principal_type = 'group'
)
SELECT DISTINCT ON (rc.user_id, rc.via, rc.path)
       rc.user_id, COALESCE(u.username, '') AS username, rc.via, rc.path, rc.actions
FROM reachers rc
LEFT JOIN users u ON u.id = rc.user_id
ORDER BY rc.user_id, rc.via, rc.path`
}

// handleSecretPrivilegeGraph — GET /pam/privilege-graph/secret/:id
// "Who can reach this vault secret, and by which path?"
func (s *Service) handleSecretPrivilegeGraph(c *gin.Context) {
	s.resourcePrivilegeGraph(c, "vault_access_grants", "secret_id", "secret")
}

// handleEntryPrivilegeGraph — GET /pam/privilege-graph/entry/:id
// "Who can reach this PAM entry, and by which path?"
func (s *Service) handleEntryPrivilegeGraph(c *gin.Context) {
	s.resourcePrivilegeGraph(c, "pam_entry_grants", "entry_id", "pam_entry")
}

func (s *Service) resourcePrivilegeGraph(c *gin.Context, grantTable, resourceCol, kind string) {
	if _, err := orgctx.From(c.Request.Context()); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	resourceID := c.Param("id")
	//orgscope:ignore all referenced tables are org-scoped by FORCE RLS on the pooled connection; the resource id is org-verified by the same RLS
	rows, err := s.db.Pool.Query(c.Request.Context(), reachSQL(grantTable, resourceCol), resourceID)
	if err != nil {
		s.logger.Error("privilege-graph query failed", zap.String("kind", kind), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute privilege graph"})
		return
	}
	defer rows.Close()

	reachers := []privReacher{}
	seen := map[string]bool{}
	for rows.Next() {
		var r privReacher
		if err := rows.Scan(&r.UserID, &r.Username, &r.Via, &r.Path, &r.Actions); err != nil {
			continue
		}
		reachers = append(reachers, r)
		seen[r.UserID] = true
	}
	c.JSON(http.StatusOK, gin.H{
		"kind":          kind,
		"resource_id":   resourceID,
		"reacher_count": len(seen),
		"reachers":      reachers,
	})
}

// handleUserPrivilegeGraph — GET /pam/privilege-graph/user/:id
// "What secrets + PAM entries can this user reach, and how?"
func (s *Service) handleUserPrivilegeGraph(c *gin.Context) {
	if _, err := orgctx.From(c.Request.Context()); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.Param("id")
	ctx := c.Request.Context()

	secrets, err := s.userReachableResources(ctx, userID, "vault_access_grants", "secret_id", "vault_secrets", "secret")
	if err != nil {
		s.logger.Error("user privilege-graph (secrets) failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute privilege graph"})
		return
	}
	entries, err := s.userReachableResources(ctx, userID, "pam_entry_grants", "entry_id", "pam_entries", "pam_entry")
	if err != nil {
		s.logger.Error("user privilege-graph (entries) failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute privilege graph"})
		return
	}
	resources := append(secrets, entries...)
	c.JSON(http.StatusOK, gin.H{
		"user_id":        userID,
		"resource_count": len(resources),
		"resources":      resources,
	})
}

// userReachableResources lists the resources of one kind a user can reach via
// direct/role(transitive)/group grants. Mirrors reachSQL but pivots on the user.
func (s *Service) userReachableResources(ctx context.Context, userID, grantTable, resourceCol, resourceTable, kind string) ([]privResource, error) {
	q := `
WITH RECURSIVE user_roles_all AS (
    -- roles held directly, expanded through composite_roles (parent→child means
    -- holding the parent grants the child's privileges)
    SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = $1
    UNION
    SELECT cr.child_role_id
    FROM user_roles_all ura
    JOIN composite_roles cr ON cr.parent_role_id = ura.role_id
),
user_groups AS (
    SELECT gm.group_id FROM group_memberships gm WHERE gm.user_id = $1
),
live_grants AS (
    -- normalize principal_id to text (uuid in vault, varchar in pam); cast to
    -- uuid at uuid joins below.
    SELECT ` + resourceCol + ` AS resource_id, principal_type, principal_id::text AS principal_id, actions
    FROM ` + grantTable + `
    WHERE (expires_at IS NULL OR expires_at > NOW())
),
hits AS (
    SELECT lg.resource_id, 'direct'::text AS via, 'direct grant'::text AS path, lg.actions
    FROM live_grants lg WHERE lg.principal_type = 'user' AND lg.principal_id = $1::text
    UNION ALL
    SELECT lg.resource_id, 'role'::text AS via, 'role: ' || COALESCE(r.name, lg.principal_id) AS path, lg.actions
    FROM live_grants lg
    JOIN user_roles_all ura ON ura.role_id = lg.principal_id::uuid
    LEFT JOIN roles r ON r.id = lg.principal_id::uuid
    WHERE lg.principal_type = 'role'
    UNION ALL
    SELECT lg.resource_id, 'group'::text AS via, 'group: ' || COALESCE(gr.name, lg.principal_id) AS path, lg.actions
    FROM live_grants lg
    JOIN user_groups ug ON ug.group_id = lg.principal_id::uuid
    LEFT JOIN groups gr ON gr.id = lg.principal_id::uuid
    WHERE lg.principal_type = 'group'
)
SELECT DISTINCT ON (h.resource_id, h.via, h.path)
       h.resource_id, COALESCE(res.name, '') AS name, h.via, h.path, h.actions
FROM hits h
LEFT JOIN ` + resourceTable + ` res ON res.id = h.resource_id
ORDER BY h.resource_id, h.via, h.path`

	//orgscope:ignore all tables org-scoped by FORCE RLS on the pooled connection; resolves one user's reachable resources within the tenant
	rows, err := s.db.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []privResource{}
	for rows.Next() {
		r := privResource{Kind: kind}
		if err := rows.Scan(&r.ID, &r.Name, &r.Via, &r.Path, &r.Actions); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
