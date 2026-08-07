package access

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Route-level group authorization.
//
// proxy_routes carries both allowed_roles and allowed_groups, and the admin UI
// lets an operator set either. Only allowed_roles was ever evaluated, so a route
// restricted purely by group was in fact open to every authenticated user in the
// organization — a fail-open surprise for whoever configured it. This file makes
// the stored restriction real.
//
// Semantics match the role check that sits beside it: an empty list means "no
// restriction", a non-empty list means the caller must match at least one entry.
// When both lists are set the caller must satisfy each configured dimension.

// groupCacheTTL keeps the membership lookup off the hot path for repeat
// requests in the same browsing session without holding stale grants for long.
const groupCacheTTL = 30 * time.Second

type groupCacheEntry struct {
	groups []string
	at     time.Time
}

// userGroupNames returns the group names a user belongs to, cached briefly.
// A lookup failure returns no groups, which fails CLOSED for a group-restricted
// route (the caller matches nothing) — the safe direction for an authz check.
func (s *Service) userGroupNames(ctx context.Context, userID string) []string {
	if userID == "" {
		return nil
	}
	if v, ok := s.groupCache.Load(userID); ok {
		if e, ok := v.(groupCacheEntry); ok && time.Since(e.at) < groupCacheTTL {
			return e.groups
		}
	}

	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore route authorization; keyed by globally-unique user_id (a user belongs to exactly one org), so the membership set is org-bounded
		`SELECT g.name FROM groups g
		   JOIN group_memberships gm ON gm.group_id = g.id
		  WHERE gm.user_id = $1`, userID)
	if err != nil {
		s.logger.Error("route authorization: group lookup failed (treating as no groups)",
			zap.String("user_id", userID), zap.Error(err))
		return nil
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			continue
		}
		names = append(names, n)
	}
	s.groupCache.Store(userID, groupCacheEntry{groups: names, at: time.Now()})
	return names
}

// routeGroupsAllow reports whether the caller satisfies a route's allowed_groups.
// An empty restriction allows everyone, mirroring the role check.
func routeGroupsAllow(allowedGroups, userGroups []string) bool {
	if len(allowedGroups) == 0 {
		return true
	}
	for _, want := range allowedGroups {
		for _, have := range userGroups {
			if want == have {
				return true
			}
		}
	}
	return false
}
