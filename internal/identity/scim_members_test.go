package identity

import (
	"errors"
	"fmt"
	"sort"
	"testing"
)

// Group membership is the operation SCIM exists to perform, and it was the one
// that did nothing: the handlers mutated an in-memory Members slice that
// UpdateGroup never wrote and GetGroup never filled. These tests cover the
// diff/sync logic that now stands between the patched struct and
// group_memberships.

func members(ids ...string) []Member {
	out := make([]Member, 0, len(ids))
	for _, id := range ids {
		out = append(out, Member{Value: id, Type: "User"})
	}
	return out
}

func TestDiffMembers(t *testing.T) {
	tests := []struct {
		name          string
		before, after []Member
		added         []string
		removed       []string
	}{
		{
			name:   "no change",
			before: members("a", "b"),
			after:  members("a", "b"),
		},
		{
			name:   "one added",
			before: members("a"),
			after:  members("a", "b"),
			added:  []string{"b"},
		},
		{
			name:    "one removed",
			before:  members("a", "b"),
			after:   members("a"),
			removed: []string{"b"},
		},
		{
			name:    "swap in a single patch",
			before:  members("a"),
			after:   members("b"),
			added:   []string{"b"},
			removed: []string{"a"},
		},
		{
			name:   "populating an empty group",
			before: nil,
			after:  members("a", "b"),
			added:  []string{"a", "b"},
		},
		{
			name:    "emptying a group",
			before:  members("a", "b"),
			after:   nil,
			removed: []string{"a", "b"},
		},
		{
			name: "order is not a change",
			// SCIM multi-valued attributes are unordered. Treating a reordered
			// roster as a full remove-and-re-add would churn every membership
			// row (and its audit trail) on every sync.
			before: members("a", "b", "c"),
			after:  members("c", "a", "b"),
		},
		{
			name:   "a repeated member is one membership",
			before: members("a"),
			after:  members("a", "b", "b"),
			added:  []string{"b"},
		},
		{
			name:   "entries without a value are ignored",
			before: members("a"),
			after:  append(members("a"), Member{Type: "User"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := diffMembers(tt.before, tt.after)
			sort.Strings(added)
			sort.Strings(removed)
			if fmt.Sprint(added) != fmt.Sprint(tt.added) {
				t.Errorf("added = %v, want %v", added, tt.added)
			}
			if fmt.Sprint(removed) != fmt.Sprint(tt.removed) {
				t.Errorf("removed = %v, want %v", removed, tt.removed)
			}
		})
	}
}

func TestMemberDisplay(t *testing.T) {
	tests := []struct {
		name string
		in   GroupMember
		want string
	}{
		{"full name", GroupMember{Username: "jdoe", FirstName: "Jane", LastName: "Doe"}, "Jane Doe"},
		{"given name only", GroupMember{Username: "jdoe", FirstName: "Jane"}, "Jane"},
		{"family name only", GroupMember{Username: "jdoe", LastName: "Doe"}, "Doe"},
		// Falling back to the username matters: a member rendered with an empty
		// display is what a client shows its operator in the group roster.
		{"no name falls back to username", GroupMember{Username: "jdoe"}, "jdoe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := memberDisplay(tt.in); got != tt.want {
				t.Errorf("memberDisplay() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSCIMMemberErrorStatus(t *testing.T) {
	// A member id that is not a user is the client's mistake and must come back
	// as 400 invalidValue — a 500 tells Okta to retry the same bad request
	// forever.
	status, scimType := scimMemberErrorStatus(fmt.Errorf("member x: %w", errSCIMInvalidValue))
	if status != 400 || scimType != "invalidValue" {
		t.Errorf("got %d/%q, want 400/invalidValue", status, scimType)
	}

	status, scimType = scimMemberErrorStatus(errors.New("connection reset"))
	if status != 500 || scimType != "" {
		t.Errorf("got %d/%q, want 500/\"\"", status, scimType)
	}
}

func TestGroupPatchProducesTheRosterSyncWeIntend(t *testing.T) {
	// The two halves of the fix meeting: the filtered path selects the member,
	// and the diff turns that into exactly one removal. Neither half is useful
	// without the other — parsing `members[value eq "u2"]` correctly still
	// changes nothing if the result is never diffed against the stored roster,
	// which is precisely what used to happen.
	group := &Group{ID: "g1", DisplayName: "Engineering", Members: members("u1", "u2", "u3")}
	before := append([]Member(nil), group.Members...)

	if err := ApplySCIMPatchToGroup(group, patchOp("remove", `members[value eq "u2"]`, nil)); err != nil {
		t.Fatalf("patch: %v", err)
	}

	added, removed := diffMembers(before, group.Members)
	if len(added) != 0 {
		t.Errorf("added = %v, want none", added)
	}
	if len(removed) != 1 || removed[0] != "u2" {
		t.Errorf("removed = %v, want [u2]", removed)
	}
}

func TestGroupPatchAddProducesTheRosterSyncWeIntend(t *testing.T) {
	group := &Group{ID: "g1", DisplayName: "Engineering", Members: members("u1")}
	before := append([]Member(nil), group.Members...)

	req := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{{
			Op:   "add",
			Path: stringPtr("members"),
			Value: []interface{}{
				map[string]interface{}{"value": "u2", "type": "User", "display": "User Two"},
			},
		}},
	}
	if err := ApplySCIMPatchToGroup(group, req); err != nil {
		t.Fatalf("patch: %v", err)
	}

	added, removed := diffMembers(before, group.Members)
	if len(removed) != 0 {
		t.Errorf("removed = %v, want none", removed)
	}
	if len(added) != 1 || added[0] != "u2" {
		t.Errorf("added = %v, want [u2]", added)
	}
}
