package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// SCIM group membership.
//
// Group membership lives in `group_memberships`, but until now no SCIM group
// handler read or wrote it. `GetGroup` selects from `groups` alone, so
// `group.Members` was always empty; `UpdateGroup` writes name/description/flags
// and nothing else. The consequences ran through every group operation:
//
//   - GET /Groups/:id reported every group as empty, so Entra ID and Okta
//     concluded the roster had been wiped externally and queued the whole
//     membership again on each sync cycle.
//   - PATCH with `add members` mutated the in-memory struct, answered 200, and
//     echoed the new member back in the response body — while the database was
//     untouched. The client had written confirmation of a membership that did
//     not exist.
//   - POST /Groups with members created an empty group and reported success.
//
// Provisioning a user into a group is the single most-used SCIM operation, and
// it was the one that did nothing. The filtered-path parser is what lets a
// client *express* "remove this member"; this file is what makes it happen.
//
// Changes go through AddGroupMember / RemoveGroupMember rather than raw SQL, so
// the max-member limit, the existence checks and the audit trail apply exactly
// as they do for the console.

// errSCIMInvalidValue marks a membership change the directory cannot satisfy —
// a member id that is not a user in this tenant. RFC 7644 §3.12 "invalidValue".
var errSCIMInvalidValue = errors.New("invalidValue")

// memberDisplay renders a member's display name the way the console does.
func memberDisplay(m GroupMember) string {
	name := strings.TrimSpace(m.FirstName + " " + m.LastName)
	if name == "" {
		return m.Username
	}
	return name
}

// loadGroupMembers populates group.Members from the membership table.
func (s *Service) loadGroupMembers(ctx context.Context, group *Group) error {
	members, err := s.GetGroupMembers(ctx, group.ID)
	if err != nil {
		return err
	}
	group.Members = make([]Member, 0, len(members))
	for _, m := range members {
		display := memberDisplay(m)
		group.Members = append(group.Members, Member{
			Value:   m.UserID,
			Type:    "User",
			Display: &display,
		})
	}
	return nil
}

// loadMembersForGroups is the batched form used by the list endpoint, so a page
// of N groups costs one query rather than N.
func (s *Service) loadMembersForGroups(ctx context.Context, groups []Group) error {
	if len(groups) == 0 {
		return nil
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	ids := make([]string, len(groups))
	byID := make(map[string]*Group, len(groups))
	for i := range groups {
		ids[i] = groups[i].ID
		groups[i].Members = nil
		byID[groups[i].ID] = &groups[i]
	}

	rows, err := s.db.Reader().Query(ctx, `
		SELECT gm.group_id, u.id, u.username, u.first_name, u.last_name
		FROM group_memberships gm
		JOIN users u ON u.id = gm.user_id
		WHERE gm.group_id = ANY($1) AND gm.org_id = $2
		ORDER BY gm.group_id, gm.joined_at
	`, ids, org.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var groupID string
		var m GroupMember
		if err := rows.Scan(&groupID, &m.UserID, &m.Username, &m.FirstName, &m.LastName); err != nil {
			return err
		}
		g, ok := byID[groupID]
		if !ok {
			continue
		}
		display := memberDisplay(m)
		g.Members = append(g.Members, Member{Value: m.UserID, Type: "User", Display: &display})
	}
	return rows.Err()
}

// diffMembers reports which member ids the client added and which it dropped.
// Order is irrelevant to SCIM, and a member repeated in the request is not a
// second membership, so both sides collapse to sets.
func diffMembers(before, after []Member) (added, removed []string) {
	beforeSet := make(map[string]struct{}, len(before))
	for _, m := range before {
		if m.Value != "" {
			beforeSet[m.Value] = struct{}{}
		}
	}
	afterSet := make(map[string]struct{}, len(after))
	for _, m := range after {
		if m.Value == "" {
			continue
		}
		if _, dup := afterSet[m.Value]; dup {
			continue
		}
		afterSet[m.Value] = struct{}{}
		if _, held := beforeSet[m.Value]; !held {
			added = append(added, m.Value)
		}
	}
	for _, m := range before {
		if m.Value == "" {
			continue
		}
		if _, want := afterSet[m.Value]; !want {
			removed = append(removed, m.Value)
		}
	}
	return added, removed
}

// syncGroupMembers writes the roster the client asked for.
//
// Removals run first: a group at its member limit must still be able to swap
// one member for another in a single PATCH, which is what Okta sends when a
// user moves between teams.
func (s *Service) syncGroupMembers(ctx context.Context, groupID string, before, after []Member) error {
	added, removed := diffMembers(before, after)

	for _, userID := range removed {
		// The id is echoed into error text that is both logged and returned, so
		// it is scrubbed here rather than at each sink (CodeQL go/log-injection).
		safeID := scrubLogValue(userID)
		err := s.RemoveGroupMember(ctx, groupID, userID)
		switch {
		case err == nil:
		case errors.Is(err, ErrNotGroupMember):
			// Already absent is the desired end state, not a failure: SCIM
			// clients retry, and a retry must not turn into an error.
		default:
			return fmt.Errorf("remove member %s: %w", safeID, err)
		}
	}

	for _, userID := range added {
		safeID := scrubLogValue(userID)
		err := s.AddGroupMember(ctx, groupID, userID)
		switch {
		case err == nil:
		case errors.Is(err, ErrAlreadyGroupMember):
			// Idempotent, as above.
		case errors.Is(err, ErrUserNotFound):
			return fmt.Errorf("member %s is not a user in this organization: %w", safeID, errSCIMInvalidValue)
		case errors.Is(err, ErrGroupMemberLimit):
			return fmt.Errorf("group %s is at its member limit: %w", scrubLogValue(groupID), errSCIMInvalidValue)
		default:
			return fmt.Errorf("add member %s: %w", safeID, err)
		}
	}

	return nil
}

// scimMemberErrorStatus maps a membership sync failure to its HTTP status and
// scimType. A rejected member is the client's error (400 invalidValue); a
// failed write is ours (500).
func scimMemberErrorStatus(err error) (int, string) {
	if errors.Is(err, errSCIMInvalidValue) {
		return 400, "invalidValue"
	}
	return 500, ""
}
