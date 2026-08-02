package directory

import (
	"testing"

	"go.uber.org/zap"
)

func TestParseReferral(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ref      string
		wantErr  bool
		wantHost string
		wantBase string
	}{
		{
			name:     "AD subordinate naming context",
			ref:      "ldap://dc2.corp.example.com/DC=sub,DC=corp,DC=example,DC=com",
			wantHost: "dc2.corp.example.com",
			wantBase: "DC=sub,DC=corp,DC=example,DC=com",
		},
		{
			name:     "ldaps with explicit port",
			ref:      "ldaps://dc3.corp.example.com:636/OU=Staff,DC=corp,DC=example,DC=com",
			wantHost: "dc3.corp.example.com:636",
			wantBase: "OU=Staff,DC=corp,DC=example,DC=com",
		},
		{
			name: "percent-encoded base DN is decoded",
			ref:  "ldap://dc.example.com/OU=Sales%20Team,DC=example,DC=com",
			// A DN with a space arrives escaped; passing it through still escaped
			// would search a base DN that does not exist and quietly return nothing.
			wantHost: "dc.example.com",
			wantBase: "OU=Sales Team,DC=example,DC=com",
		},
		{
			name:     "RFC 4516 extras are ignored, not honoured",
			ref:      "ldap://dc.example.com/DC=example,DC=com?cn,mail?sub?(objectClass=*)",
			wantHost: "dc.example.com",
			wantBase: "DC=example,DC=com",
		},
		{name: "non-ldap scheme", ref: "http://evil.example.com/DC=x", wantErr: true},
		{name: "no scheme", ref: "dc.example.com/DC=x", wantErr: true},
		{name: "no host", ref: "ldap:///DC=example,DC=com", wantErr: true},
		{name: "no base DN", ref: "ldap://dc.example.com", wantErr: true},
		{name: "empty base DN path", ref: "ldap://dc.example.com/", wantErr: true},
		{name: "empty string", ref: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, base, err := parseReferral(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseReferral(%q) accepted an unusable referral (host=%s base=%q)", tc.ref, u.Host, base)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseReferral(%q): %v", tc.ref, err)
			}
			if u.Host != tc.wantHost {
				t.Errorf("host = %q, want %q", u.Host, tc.wantHost)
			}
			if base != tc.wantBase {
				t.Errorf("base DN = %q, want %q", base, tc.wantBase)
			}
		})
	}
}

func testConnector(t *testing.T, cfg LDAPConfig) *LDAPConnector {
	t.Helper()
	return NewLDAPConnector(cfg, zap.NewNop())
}

// TestReferralsAreNotFollowedWhenDisabled — chasing a referral opens a
// connection to a host the directory names rather than one this configuration
// names, so it must not happen unless the operator asked for it.
func TestReferralsAreNotFollowedWhenDisabled(t *testing.T) {
	c := testConnector(t, LDAPConfig{FollowReferrals: false})
	visited := map[string]bool{}

	// 127.0.0.1:1 refuses instantly; if this were dialled the test would still
	// pass on entries but would mark the referral visited.
	got := c.chaseReferrals([]string{"ldap://127.0.0.1:1/DC=example,DC=com"},
		"(objectClass=*)", []string{"dn"}, 100, visited, 0)

	if len(got) != 0 {
		t.Fatalf("got %d entries with follow_referrals off", len(got))
	}
	if len(visited) != 0 {
		t.Fatalf("a referral was processed while follow_referrals was off: %v", visited)
	}
}

// TestReferralHopLimitStopsChasing — a referred server can itself return
// referrals, so a forest that points back at itself must terminate.
func TestReferralHopLimitStopsChasing(t *testing.T) {
	c := testConnector(t, LDAPConfig{FollowReferrals: true, ReferralHopLimit: 2})
	visited := map[string]bool{}

	got := c.chaseReferrals([]string{"ldap://127.0.0.1:1/DC=example,DC=com"},
		"(objectClass=*)", []string{"dn"}, 100, visited, 2)

	if len(got) != 0 {
		t.Fatalf("got %d entries past the hop limit", len(got))
	}
	if len(visited) != 0 {
		t.Fatalf("a referral was dialled at or past the hop limit: %v", visited)
	}
}

// TestAlreadyVisitedReferralIsSkipped is the loop guard: two servers referring
// to each other produce the same URL again, and without this the search would
// bounce between them until the hop limit on every single sync.
func TestAlreadyVisitedReferralIsSkipped(t *testing.T) {
	c := testConnector(t, LDAPConfig{FollowReferrals: true})
	const ref = "ldap://127.0.0.1:1/DC=example,DC=com"
	visited := map[string]bool{ref: true}

	got := c.chaseReferrals([]string{ref}, "(objectClass=*)", []string{"dn"}, 100, visited, 0)
	if len(got) != 0 {
		t.Fatalf("got %d entries from an already-visited referral", len(got))
	}
	if len(visited) != 1 {
		t.Fatalf("visited set changed: %v", visited)
	}
}

// TestUnusableReferralsAreSkippedWithoutDialling — a referral naming a non-LDAP
// scheme or no base DN must be discarded before any connection is attempted.
func TestUnusableReferralsAreSkippedWithoutDialling(t *testing.T) {
	c := testConnector(t, LDAPConfig{FollowReferrals: true})
	visited := map[string]bool{}

	got := c.chaseReferrals([]string{
		"http://evil.example.com/DC=example,DC=com",
		"ldap://dc.example.com",
		"",
	}, "(objectClass=*)", []string{"dn"}, 100, visited, 0)

	if len(got) != 0 {
		t.Fatalf("got %d entries from unusable referrals", len(got))
	}
}

// TestUnreachableReferralDegradesRatherThanFails — a referred domain controller
// being down must not discard the entries the primary server already returned.
// chaseReferrals reports entries only; the caller keeps its own.
func TestUnreachableReferralDegradesRatherThanFails(t *testing.T) {
	c := testConnector(t, LDAPConfig{FollowReferrals: true})
	visited := map[string]bool{}

	got := c.chaseReferrals([]string{"ldap://127.0.0.1:1/DC=example,DC=com"},
		"(objectClass=*)", []string{"dn"}, 100, visited, 0)

	if got != nil && len(got) != 0 {
		t.Fatalf("unreachable referral produced %d entries", len(got))
	}
	if !visited["ldap://127.0.0.1:1/DC=example,DC=com"] {
		t.Fatalf("a dialled referral was not recorded as visited, so a cycle would retry it forever")
	}
}
