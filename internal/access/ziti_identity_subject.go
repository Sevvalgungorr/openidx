package access

import (
	"context"
	"regexp"
	"strings"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Making fabric identities readable.
//
// The overlay names a synced identity after the OpenIDX user's UUID, which is
// exactly right for machines and useless for people. An admin looking at the
// identity-risk screen saw 84 rows of "d1abde43-c950-47e1-b806-958822efb877"
// and had no way to tell whose access they were about to quarantine — the one
// action on that screen is destructive, and it was being offered without
// saying who it affects.
//
// This resolves those UUIDs back to the person: username, email, and where the
// account came from. Nothing here changes risk scoring; it only answers "who
// is this?".

// uuidLike matches the canonical 8-4-4-4-12 form. Identities that are not
// UUID-shaped (agent-*, ci-*, operator-created names) are already meaningful
// and are left exactly as they are.
var uuidLike = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IdentitySubject is who a fabric identity belongs to, in the terms an admin
// thinks in.
type IdentitySubject struct {
	// DisplayName is what to show in a list: the username when known,
	// otherwise the original identity name.
	DisplayName string `json:"display_name"`
	// Email helps disambiguate two people with similar usernames.
	Email string `json:"email,omitempty"`
	// Kind explains what sort of thing this is: "user", "agent", or
	// "unresolved" when a UUID-named identity has no account this caller can
	// see (see resolveIdentitySubjects for why that is not the same as
	// "deleted").
	Kind string `json:"kind"`
	// Source is where the account came from (ldap, local, ...). An admin
	// treats a directory-synced account differently from a local one.
	Source string `json:"source,omitempty"`
}

// resolveIdentitySubjects maps fabric identity names to the accounts behind
// them, in one query rather than one per identity.
//
// A name that is not UUID-shaped is returned as-is: those are agents and
// operator-created identities whose names already say what they are.
func (zm *ZitiManager) resolveIdentitySubjects(ctx context.Context, names []string) map[string]IdentitySubject {
	out := make(map[string]IdentitySubject, len(names))

	var uuids []string
	for _, n := range names {
		switch {
		case uuidLike.MatchString(n):
			uuids = append(uuids, n)
		case strings.HasPrefix(n, "agent-"):
			out[n] = IdentitySubject{DisplayName: n, Kind: "agent"}
		default:
			out[n] = IdentitySubject{DisplayName: n, Kind: "service"}
		}
	}
	if len(uuids) == 0 {
		return out
	}

	// Deliberately org-scoped, unlike the aggregate counts in this rollup.
	// Those expose numbers; this exposes usernames and email addresses, and the
	// identity-risk endpoint is not adminOnly. Resolving across tenants would
	// let any caller enumerate the names of users in other organisations, so a
	// row the caller may not see stays unresolved rather than being named.
	//
	// The org filter is written into the SQL rather than left to RLS alone:
	// the predicate is then visible at the call site instead of depending on a
	// GUC set somewhere else, and it keeps working if this ever runs under a
	// bypass context.
	org, err := orgctx.From(ctx)
	if err != nil {
		for _, u := range uuids {
			out[u] = IdentitySubject{DisplayName: u, Kind: "unresolved"}
		}
		return out
	}

	rows, err := zm.db.Pool.Query(ctx,
		`SELECT id::text, COALESCE(username, ''), COALESCE(email, ''), COALESCE(source, '')
		 FROM users WHERE id::text = ANY($1) AND org_id = $2`, uuids, org.ID)
	if err != nil {
		// A failed lookup must not blank out the screen: fall back to the raw
		// name so the row is still actionable, just less informative.
		zm.logger.Warn("identity subject lookup failed; showing raw identity names")
		for _, u := range uuids {
			out[u] = IdentitySubject{DisplayName: u, Kind: "unresolved"}
		}
		return out
	}
	defer rows.Close()

	for rows.Next() {
		var id, username, email, source string
		if err := rows.Scan(&id, &username, &email, &source); err != nil {
			continue
		}
		display := username
		if display == "" {
			display = email
		}
		if display == "" {
			display = id
		}
		out[id] = IdentitySubject{
			DisplayName: display,
			Email:       email,
			Kind:        "user",
			Source:      source,
		}
	}

	// A UUID-named identity with no row here means one of two things: the user
	// was deleted and their overlay identity outlived them, or the account
	// belongs to a tenant this caller cannot see. Both are worth surfacing and
	// they are genuinely indistinguishable from here, so the label says what is
	// actually known — "unresolved" — rather than asserting "orphaned" and
	// inviting someone to delete a live identity from another tenant.
	for _, u := range uuids {
		if _, ok := out[u]; !ok {
			out[u] = IdentitySubject{DisplayName: u, Kind: "unresolved"}
		}
	}
	return out
}
