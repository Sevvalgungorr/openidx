package identity

import (
	"errors"
	"strings"
	"testing"
)

// SCIM PATCH filtered path expressions — RFC 7644 §3.5.2.
//
// Every test here fails against the pre-change code, and the failures are not
// "wrong value" but "success reported, nothing done". `add` and `replace` had
// no bracket handling at all, so `emails[type eq "work"].value` fell through to
// a default branch matching neither displayName nor userName and returned nil:
// HTTP 200, user unmodified. `remove` had bracket branches that discarded the
// filter and compared against op.Value, so `emails[type eq "work"]` — which
// carries no value — removed nothing and also returned nil.
//
// That is the failure mode Okta and Entra ID cannot detect: both read the 200
// as confirmation and stop retrying, so the directory silently diverges.

func TestParseSCIMPatchPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		attr    string
		sub     string
		filter  *scimPatchFilter
		wantErr bool
	}{
		{
			name: "plain attribute",
			path: "displayName",
			attr: "displayName",
		},
		{
			name: "nested plain attribute stays whole",
			path: "name.givenName",
			attr: "name.givenName",
		},
		{
			name:   "filter with sub-attribute",
			path:   `emails[type eq "work"].value`,
			attr:   "emails",
			sub:    "value",
			filter: &scimPatchFilter{Attribute: "type", Operator: "eq", Value: "work"},
		},
		{
			name:   "filter without sub-attribute selects the element",
			path:   `members[value eq "abc-123"]`,
			attr:   "members",
			filter: &scimPatchFilter{Attribute: "value", Operator: "eq", Value: "abc-123"},
		},
		{
			name:   "presence filter",
			path:   "emails[type pr]",
			attr:   "emails",
			filter: &scimPatchFilter{Attribute: "type", Operator: "pr"},
		},
		{
			name:   "quoted value containing spaces survives",
			path:   `members[display eq "Jane Q Doe"].value`,
			attr:   "members",
			sub:    "value",
			filter: &scimPatchFilter{Attribute: "display", Operator: "eq", Value: "Jane Q Doe"},
		},
		{
			name:   "operator is case-insensitive",
			path:   `emails[type EQ "work"]`,
			attr:   "emails",
			filter: &scimPatchFilter{Attribute: "type", Operator: "eq", Value: "work"},
		},
		{
			name:    "unterminated bracket",
			path:    `emails[type eq "work"`,
			wantErr: true,
		},
		{
			name:    "no attribute before the bracket",
			path:    `[type eq "work"]`,
			wantErr: true,
		},
		{
			name:    "unsupported operator",
			path:    `emails[type gt "work"]`,
			wantErr: true,
		},
		{
			name: "bare value in brackets is not a filter",
			// The syntax two of this package's own tests used to assert. It is
			// not valid SCIM and no real client emits it; rejecting it is the
			// point, because the old code accepted it and then ignored it.
			path:    "members[user1]",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSCIMPatchPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSCIMPatchPath(%q) succeeded, want error", tt.path)
				}
				if scimPatchErrorType(err) != "invalidPath" {
					t.Errorf("scimType = %q, want invalidPath", scimPatchErrorType(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSCIMPatchPath(%q) = %v", tt.path, err)
			}
			if got.Attribute != tt.attr {
				t.Errorf("Attribute = %q, want %q", got.Attribute, tt.attr)
			}
			if got.SubAttribute != tt.sub {
				t.Errorf("SubAttribute = %q, want %q", got.SubAttribute, tt.sub)
			}
			if (got.Filter == nil) != (tt.filter == nil) {
				t.Fatalf("Filter = %v, want %v", got.Filter, tt.filter)
			}
			if tt.filter != nil && *got.Filter != *tt.filter {
				t.Errorf("Filter = %+v, want %+v", *got.Filter, *tt.filter)
			}
		})
	}
}

func TestSCIMPatchFilterMatches(t *testing.T) {
	attrs := map[string]string{"value": "Jane@Example.com", "type": "work"}

	tests := []struct {
		filter scimPatchFilter
		want   bool
	}{
		// eq is case-insensitive: SCIM attribute values are caseExact=false by
		// default, and Entra normalizes addresses to lower case on the wire.
		{scimPatchFilter{"value", "eq", "jane@example.com"}, true},
		{scimPatchFilter{"value", "eq", "other@example.com"}, false},
		{scimPatchFilter{"type", "ne", "home"}, true},
		{scimPatchFilter{"type", "ne", "work"}, false},
		{scimPatchFilter{"value", "co", "example"}, true},
		{scimPatchFilter{"value", "co", "contoso"}, false},
		{scimPatchFilter{"value", "sw", "jane"}, true},
		{scimPatchFilter{"value", "sw", "example"}, false},
		{scimPatchFilter{"value", "ew", ".com"}, true},
		{scimPatchFilter{"value", "ew", "jane"}, false},
		{scimPatchFilter{"type", "pr", ""}, true},
		{scimPatchFilter{"display", "pr", ""}, false},
		// An absent attribute matches nothing — including `ne`, which must not
		// become "true because there is no value to compare".
		{scimPatchFilter{"display", "ne", "anything"}, false},
		{scimPatchFilter{"display", "eq", "anything"}, false},
	}

	for _, tt := range tests {
		f := tt.filter
		t.Run(f.Attribute+" "+f.Operator+" "+f.Value, func(t *testing.T) {
			if got := f.matches(attrs); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("a nil filter matches everything", func(t *testing.T) {
		var f *scimPatchFilter
		if !f.matches(attrs) {
			t.Error("nil filter should match")
		}
	})
}

func workUser() *User {
	work, home := "work", "home"
	mobile := "mobile"
	return &User{
		ID:       "user1",
		UserName: "jane",
		Emails: []Email{
			{Value: "jane@home.example", Type: &home},
			{Value: "jane@corp.example", Type: &work},
		},
		PhoneNumbers: []PhoneNumber{
			{Value: "+1-555-0100", Type: &mobile},
			{Value: "+1-555-0199", Type: &work},
		},
		Groups: []string{"group1", "group2"},
		Roles:  []string{"viewer", "editor"},
	}
}

func patchOp(op, path string, value interface{}) *SCIMPatchRequest {
	return &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops:     []SCIMPatchOp{{Op: op, Path: &path, Value: value}},
	}
}

func TestApplySCIMPatchToUser_FilteredReplaceUpdatesOnlyTheMatch(t *testing.T) {
	user := workUser()

	if err := ApplySCIMPatchToUser(user, patchOp("replace", `emails[type eq "work"].value`, "jane.doe@corp.example")); err != nil {
		t.Fatalf("patch: %v", err)
	}

	if len(user.Emails) != 2 {
		t.Fatalf("Emails length = %d, want 2 (a filtered replace must not rewrite the array)", len(user.Emails))
	}
	if user.Emails[0].Value != "jane@home.example" {
		t.Errorf("home email changed to %q", user.Emails[0].Value)
	}
	if user.Emails[1].Value != "jane.doe@corp.example" {
		// The pre-change failure: 200 OK, work address still jane@corp.example.
		t.Errorf("work email = %q, want jane.doe@corp.example", user.Emails[1].Value)
	}
}

func TestApplySCIMPatchToUser_FilteredReplaceSubAttributes(t *testing.T) {
	user := workUser()

	if err := ApplySCIMPatchToUser(user, patchOp("replace", `emails[value eq "jane@corp.example"].primary`, true)); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if user.Emails[1].Primary == nil || !*user.Emails[1].Primary {
		t.Error("primary not set on the matched email")
	}
	if user.Emails[0].Primary != nil {
		t.Error("primary set on an unmatched email")
	}

	if err := ApplySCIMPatchToUser(user, patchOp("replace", `emails[value eq "jane@corp.example"].type`, "other")); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if user.Emails[1].Type == nil || *user.Emails[1].Type != "other" {
		t.Errorf("type = %v, want other", user.Emails[1].Type)
	}
}

func TestApplySCIMPatchToUser_FilteredAddSetsTheMatchedElement(t *testing.T) {
	// Okta sends `add` with a filtered path when it believes the sub-attribute
	// is currently unset; per RFC 7644 §3.5.2.1 it behaves as replace here.
	user := workUser()

	if err := ApplySCIMPatchToUser(user, patchOp("add", `emails[type eq "work"].display`, "Work")); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if user.Emails[1].Display == nil || *user.Emails[1].Display != "Work" {
		t.Errorf("display = %v, want Work", user.Emails[1].Display)
	}
}

func TestApplySCIMPatchToUser_FilterMatchingNothingIsNoTarget(t *testing.T) {
	// The whole point of the change: refusing to answer 200 for work not done.
	// RFC 7644 §3.5.2 calls this noTarget, and clients branch on that scimType.
	cases := []struct {
		name string
		op   string
		path string
		val  interface{}
	}{
		{"replace email", "replace", `emails[type eq "other"].value`, "nobody@example.com"},
		{"add email", "add", `emails[type eq "other"].value`, "nobody@example.com"},
		{"remove email", "remove", `emails[type eq "other"]`, nil},
		{"remove email by value", "remove", `emails[value eq "nobody@example.com"]`, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := workUser()
			before := *workUser()

			err := ApplySCIMPatchToUser(user, patchOp(tc.op, tc.path, tc.val))
			if err == nil {
				t.Fatalf("patch reported success for a filter matching nothing")
			}
			if got := scimPatchErrorType(err); got != "noTarget" {
				t.Errorf("scimType = %q, want noTarget (err: %v)", got, err)
			}
			// A failed patch must not have partially mutated the resource.
			if len(user.Emails) != len(before.Emails) ||
				len(user.PhoneNumbers) != len(before.PhoneNumbers) ||
				len(user.Groups) != len(before.Groups) ||
				len(user.Roles) != len(before.Roles) {
				t.Error("resource was mutated by a patch that failed")
			}
		})
	}
}

func TestApplySCIMPatchToUser_FilteredRemove(t *testing.T) {
	t.Run("email by type", func(t *testing.T) {
		user := workUser()
		if err := ApplySCIMPatchToUser(user, patchOp("remove", `emails[type eq "work"]`, nil)); err != nil {
			t.Fatalf("patch: %v", err)
		}
		if len(user.Emails) != 1 {
			t.Fatalf("Emails length = %d, want 1", len(user.Emails))
		}
		if user.Emails[0].Value != "jane@home.example" {
			t.Errorf("kept the wrong email: %q", user.Emails[0].Value)
		}
	})

	t.Run("op.Value is ignored — the path is the target", func(t *testing.T) {
		// The old code removed whatever op.Value named, regardless of the
		// filter. If that behavior came back, the work email would survive and
		// the home one would vanish.
		user := workUser()
		req := patchOp("remove", `emails[type eq "work"]`, "jane@home.example")
		if err := ApplySCIMPatchToUser(user, req); err != nil {
			t.Fatalf("patch: %v", err)
		}
		if len(user.Emails) != 1 || user.Emails[0].Value != "jane@home.example" {
			t.Errorf("Emails = %+v; op.Value was honored instead of the filter", user.Emails)
		}
	})
}

func TestApplySCIMPatchToUser_UnsupportedPathsAreRejected(t *testing.T) {
	cases := []struct {
		name     string
		op       string
		path     string
		val      interface{}
		scimType string
	}{
		// phoneNumbers, roles and groups are not persisted by this directory
		// (or are readOnly), so a filtered path against them is refused rather
		// than applied to a struct UpdateUser is about to throw away.
		{"filtered path on phoneNumbers", "replace", `phoneNumbers[type eq "mobile"].value`, "+1-555-0111", "invalidPath"},
		{"filtered path on roles", "replace", `roles[value eq "viewer"].display`, "V", "invalidPath"},
		{"filtered path on groups", "remove", `groups[value eq "group1"]`, nil, "invalidPath"},
		{"unknown sub-attribute", "replace", `emails[type eq "work"].bogus`, "x", "invalidPath"},
		{"malformed filter", "replace", `emails[type "work"].value`, "x", "invalidPath"},
		{"remove on an unknown attribute", "remove", "nickName", nil, "invalidPath"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := workUser()
			err := ApplySCIMPatchToUser(user, patchOp(tc.op, tc.path, tc.val))
			if err == nil {
				t.Fatal("patch reported success for an unsupported path")
			}
			if got := scimPatchErrorType(err); got != tc.scimType {
				t.Errorf("scimType = %q, want %q (err: %v)", got, tc.scimType, err)
			}
		})
	}
}

func TestApplySCIMPatchToUser_TypeMismatchIsAnError(t *testing.T) {
	user := workUser()
	err := ApplySCIMPatchToUser(user, patchOp("replace", `emails[type eq "work"].primary`, "yes"))
	if err == nil {
		t.Fatal("a string for a boolean sub-attribute was accepted")
	}
	if !strings.Contains(err.Error(), "boolean") {
		t.Errorf("error = %v, want it to name the expected type", err)
	}
}

func TestApplySCIMPatchToUser_PlainPathsStillWork(t *testing.T) {
	// The filtered-path interception runs before the plain-path switch; this
	// guards against it swallowing ordinary paths.
	user := workUser()
	req := &SCIMPatchRequest{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Ops: []SCIMPatchOp{
			{Op: "replace", Path: stringPtr("displayName"), Value: "Jane Doe"},
			{Op: "replace", Path: stringPtr("name.givenName"), Value: "Jane"},
			{Op: "add", Path: stringPtr("groups"), Value: []interface{}{"group3"}},
			{Op: "remove", Path: stringPtr("roles")},
		},
	}
	if err := ApplySCIMPatchToUser(user, req); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if user.DisplayName == nil || *user.DisplayName != "Jane Doe" {
		t.Errorf("DisplayName = %v", user.DisplayName)
	}
	if user.Name == nil || user.Name.GivenName == nil || *user.Name.GivenName != "Jane" {
		t.Errorf("Name.GivenName = %v", user.Name)
	}
	if len(user.Groups) != 3 {
		t.Errorf("Groups = %v, want 3 entries", user.Groups)
	}
	if user.Roles != nil {
		t.Errorf("Roles = %v, want nil after an unfiltered remove", user.Roles)
	}
}

func adminGroup() *Group {
	display := "User Two"
	return &Group{
		ID:          "group1",
		DisplayName: "Administrators",
		Members: []Member{
			{Value: "user1", Type: "User"},
			{Value: "user2", Type: "User", Display: &display},
		},
	}
}

func TestApplySCIMPatchToGroup_FilteredMemberRemove(t *testing.T) {
	// This is Entra ID's deprovisioning shape: the member to detach appears
	// only in the path. The old code read op.Value, found nothing, removed
	// nothing, and returned 200 — so the user stayed in the group forever.
	group := adminGroup()

	if err := ApplySCIMPatchToGroup(group, patchOp("remove", `members[value eq "user1"]`, nil)); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if len(group.Members) != 1 {
		t.Fatalf("Members length = %d, want 1", len(group.Members))
	}
	if group.Members[0].Value != "user2" {
		t.Errorf("removed the wrong member; left %q", group.Members[0].Value)
	}
}

func TestApplySCIMPatchToGroup_FilteredMemberRemoveNoMatch(t *testing.T) {
	group := adminGroup()

	err := ApplySCIMPatchToGroup(group, patchOp("remove", `members[value eq "user404"]`, nil))
	if err == nil {
		t.Fatal("removing a non-member reported success")
	}
	if got := scimPatchErrorType(err); got != "noTarget" {
		t.Errorf("scimType = %q, want noTarget (err: %v)", got, err)
	}
	if len(group.Members) != 2 {
		t.Errorf("Members length = %d, want the roster untouched", len(group.Members))
	}
}

func TestApplySCIMPatchToGroup_FilteredMemberReplace(t *testing.T) {
	group := adminGroup()

	if err := ApplySCIMPatchToGroup(group, patchOp("replace", `members[value eq "user1"].display`, "User One")); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if group.Members[0].Display == nil || *group.Members[0].Display != "User One" {
		t.Errorf("Members[0].Display = %v, want User One", group.Members[0].Display)
	}
	if group.Members[1].Display == nil || *group.Members[1].Display != "User Two" {
		t.Errorf("Members[1].Display = %v, want it untouched", group.Members[1].Display)
	}
	if len(group.Members) != 2 {
		t.Errorf("Members length = %d, want 2", len(group.Members))
	}
}

func TestApplySCIMPatchToGroup_UnsupportedFilteredPaths(t *testing.T) {
	cases := []struct {
		name string
		op   string
		path string
		val  interface{}
	}{
		{"filtered add", "add", `members[value eq "user1"]`, []interface{}{}},
		{"filtered replace of an unknown attribute", "replace", `displayName[value eq "x"]`, "y"},
		{"remove on an unknown plain path", "remove", "externalId", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			group := adminGroup()
			if err := ApplySCIMPatchToGroup(group, patchOp(tc.op, tc.path, tc.val)); err == nil {
				t.Fatal("patch reported success for an unsupported path")
			}
			if len(group.Members) != 2 {
				t.Error("roster was mutated by a patch that failed")
			}
		})
	}
}

func TestSCIMPatchErrorTypeDefaultsToInvalidSyntax(t *testing.T) {
	if got := scimPatchErrorType(errors.New("boom")); got != "invalidSyntax" {
		t.Errorf("scimType = %q, want invalidSyntax", got)
	}
	// Wrapping must survive: the handler receives errors that have been
	// re-annotated with the path they came from.
	wrapped := invalidPathf("bad")
	if got := scimPatchErrorType(wrapped); got != "invalidPath" {
		t.Errorf("scimType = %q, want invalidPath", got)
	}
}

func TestSCIMPatchEmailRoundTripsThroughStorage(t *testing.T) {
	// The end-to-end shape that matters: what a client reads back from us must
	// be patchable by the filter that same client sends.
	//
	// `users` stores one address, so ToUser types it "work" — which is exactly
	// the filter Entra ID's default attribute mapping uses. Before that, the
	// address came back untyped, `emails[type eq "work"].value` matched nothing,
	// and the update was silently dropped on the floor.
	db := UserDB{ID: "u1", Username: "jane", Email: "jane@corp.example"}

	user := db.ToUser()
	if len(user.Emails) != 1 {
		t.Fatalf("Emails = %+v, want exactly the stored address", user.Emails)
	}
	if user.Emails[0].Type == nil || *user.Emails[0].Type != "work" {
		t.Fatalf("stored address is emitted as %v; Entra's mapping filters on type eq \"work\"", user.Emails[0].Type)
	}

	if err := ApplySCIMPatchToUser(&user, patchOp("replace", `emails[type eq "work"].value`, "jane.doe@corp.example")); err != nil {
		t.Fatalf("patch: %v", err)
	}

	// FromUser is what UpdateUser persists. If the patch landed on an element
	// that never round-trips, this is where it disappears.
	if got := FromUser(user).Email; got != "jane.doe@corp.example" {
		t.Errorf("persisted email = %q, want jane.doe@corp.example", got)
	}
}
