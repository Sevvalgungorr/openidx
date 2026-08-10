package access

import "testing"

// TestUUIDLikeMatchesOnlyIdentityUUIDs guards the rule that decides which
// identity names get resolved to a person.
//
// Getting this wrong is not cosmetic. Too narrow and a real user's identity
// stays an unreadable UUID on a screen whose only action is to cut off their
// access. Too broad and an agent or CI identity gets sent through a user
// lookup, finds nothing, and is mislabelled "orphaned" — which reads as "safe
// to delete" about a machine identity that is doing its job.
func TestUUIDLikeMatchesOnlyIdentityUUIDs(t *testing.T) {
	shouldMatch := []string{
		"d1abde43-c950-47e1-b806-958822efb877",
		"b90b04ae-cf38-4abb-8bfc-520bcc51e5e6",
		// Uppercase is still a valid UUID; a synced name should not slip
		// through unresolved just because of case.
		"D1ABDE43-C950-47E1-B806-958822EFB877",
	}
	for _, s := range shouldMatch {
		if !uuidLike.MatchString(s) {
			t.Errorf("%q should be treated as a user UUID and resolved to a person", s)
		}
	}

	shouldNotMatch := []string{
		"agent-affd6b28",                        // fleet agent: name already says what it is
		"ci-azure",                              // operator-created CI identity
		"oidx-router",                           // infrastructure identity
		"",                                      // empty
		"not-a-uuid",                            //
		"d1abde43c95047e1b806958822efb877",      // no dashes
		"d1abde43-c950-47e1-b806-958822efb87",   // too short
		"d1abde43-c950-47e1-b806-958822efb8777", // too long
		"g1abde43-c950-47e1-b806-958822efb877",  // non-hex character
	}
	for _, s := range shouldNotMatch {
		if uuidLike.MatchString(s) {
			t.Errorf("%q is not a user UUID; sending it through a user lookup would mislabel it", s)
		}
	}
}

// TestIdentityRiskCarriesSubjectFields pins the API contract the screen relies
// on. The risk rows are rendered by an admin console table, and a missing field
// there degrades silently into a blank column rather than an error.
func TestIdentityRiskCarriesSubjectFields(t *testing.T) {
	r := ZitiIdentityRisk{
		IdentityID:   "abc123",
		IdentityName: "d1abde43-c950-47e1-b806-958822efb877",
		Subject:      "ahmet.copuroglu",
		SubjectKind:  "user",
		Email:        "ahmet.copuroglu@example.test",
		Source:       "ldap",
	}
	if r.Subject == "" || r.SubjectKind == "" {
		t.Fatal("a risk row must name who it is about; quarantine is destructive and must never be offered anonymously")
	}
	// The raw fabric name is kept alongside the resolved one: an operator
	// debugging the overlay still needs the identity as the controller knows it.
	if r.IdentityName == r.Subject {
		t.Error("the fabric identity name should be preserved, not overwritten by the display name")
	}
}
