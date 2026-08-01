package identity

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// SCIM list queries.
//
// These exist because the SCIM handlers used to parse a filter, convert it to
// SQL, log the result at debug level, and then throw it away — while
// ServiceProviderConfig advertised filter.supported = true. Every
// `GET /scim/v2/Users?filter=userName eq "x"` returned the tenant's entire user
// list. Okta and Entra ID filter by userName or externalId before each create
// to decide create-vs-update, so an unfiltered response makes them believe the
// user already exists (or duplicate them, depending on the connector) — the
// integration is broken in a way that looks like it is working.
//
// The filter is applied here, alongside the tenant predicate, so a SCIM filter
// can never widen the result set beyond the caller's org.

// scimUserColumns is the users column list matching scanUser's field order.
const scimUserColumns = `
	id, username, email,
	COALESCE(first_name, '') AS first_name,
	COALESCE(last_name, '')  AS last_name,
	enabled, email_verified,
	created_at, updated_at, last_login_at, password_changed_at,
	password_must_change, failed_login_count, last_failed_login_at, locked_until`

// listUsersForSCIM lists users in the caller's tenant, optionally narrowed by a
// SCIM-derived predicate, and returns the page plus the total match count.
//
// The org predicate is always $1 and is applied independently of the filter, so
// a caller cannot use a crafted filter to read another tenant's users; the
// FORCE-RLS belt is the second line of defense behind it.
func (s *Service) listUsersForSCIM(ctx context.Context, offset, limit int, filter *SQLFilter) ([]User, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	where := "org_id = $1"
	args := []interface{}{org.ID}
	if filter != nil && filter.WhereClause != "" {
		where += " AND (" + filter.WhereClause + ")"
		args = append(args, filter.Args...)
	}

	var total int
	if err := s.db.Reader().QueryRow(ctx,
		//orgscope:ignore where always carries the org_id = $1 predicate built above
		"SELECT COUNT(*) FROM users WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scim users: %w", err)
	}

	// Pagination placeholders continue after the filter's.
	pageArgs := append(append([]interface{}{}, args...), offset, limit)
	query := fmt.Sprintf(
		//orgscope:ignore where always carries the org_id = $1 predicate built above
		"SELECT %s FROM users WHERE %s ORDER BY created_at DESC OFFSET $%d LIMIT $%d",
		scimUserColumns, where, len(args)+1, len(args)+2)

	rows, err := s.db.Reader().Query(ctx, query, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scim users: %w", err)
	}
	defer rows.Close()

	users := make([]User, 0, limit)
	for rows.Next() {
		dbUser, err := scanUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan scim user: %w", err)
		}
		users = append(users, dbUser.ToUser())
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate scim users: %w", err)
	}

	s.logger.Debug("SCIM user list",
		zap.Int("matched", total), zap.Bool("filtered", filter != nil && filter.WhereClause != ""))
	return users, total, nil
}

// listGroupsForSCIM is listUsersForSCIM for groups.
func (s *Service) listGroupsForSCIM(ctx context.Context, offset, limit int, filter *SQLFilter) ([]Group, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	// The filter's column references are bare (name, external_id). With a
	// single aliased table they still resolve unambiguously, so the clause can
	// be reused verbatim in both the aliased and unaliased query below.
	scoped := ""
	args := []interface{}{org.ID}
	if filter != nil && filter.WhereClause != "" {
		scoped = " AND (" + filter.WhereClause + ")"
		args = append(args, filter.Args...)
	}

	var total int
	if err := s.db.Reader().QueryRow(ctx,
		//orgscope:ignore the org_id = $1 predicate is unconditional; `scoped` only narrows further
		"SELECT COUNT(*) FROM groups WHERE org_id = $1"+scoped, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scim groups: %w", err)
	}

	pageArgs := append(append([]interface{}{}, args...), offset, limit)
	query := fmt.Sprintf(
		//orgscope:ignore the outer WHERE carries g.org_id = $1, and the member_count subquery is scoped by gm.org_id
		`SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval,
		        g.max_members, g.created_at, g.updated_at,
		        COALESCE((SELECT COUNT(*) FROM group_memberships gm
		                  WHERE gm.group_id = g.id AND gm.org_id = $1), 0) AS member_count
		 FROM groups g WHERE g.org_id = $1%s ORDER BY g.name OFFSET $%d LIMIT $%d`,
		scoped, len(args)+1, len(args)+2)

	rows, err := s.db.Reader().Query(ctx, query, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scim groups: %w", err)
	}
	defer rows.Close()

	groups := make([]Group, 0, limit)
	for rows.Next() {
		dbGroup, err := scanGroup(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan scim group: %w", err)
		}
		groups = append(groups, dbGroup.ToGroup())
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate scim groups: %w", err)
	}

	s.logger.Debug("SCIM group list",
		zap.Int("matched", total), zap.Bool("filtered", filter != nil && filter.WhereClause != ""))
	return groups, total, nil
}
