package access

import (
	"os"
	"strings"
	"testing"
)

// TestRouteGroupsAllow pins the authorization semantics for a route's
// allowed_groups. This restriction was configurable in the admin UI and stored
// on the route, but never evaluated at the proxy — so a route restricted purely
// by group was in fact reachable by every authenticated user in the
// organization. An operator setting it would reasonably believe access was
// limited, which is the dangerous kind of failure: silent and fail-open.
//
// Semantics deliberately mirror the role check beside it: empty means "no
// restriction", non-empty means the caller must match at least one entry.
func TestRouteGroupsAllow(t *testing.T) {
	cases := []struct {
		name          string
		allowedGroups []string
		userGroups    []string
		want          bool
	}{
		{"no restriction allows anyone", nil, nil, true},
		{"empty restriction allows anyone", []string{}, []string{"eng"}, true},
		{"member of the allowed group", []string{"eng"}, []string{"eng"}, true},
		{"member of one of several", []string{"ops", "eng"}, []string{"sales", "eng"}, true},

		// The cases that were previously broken: a restriction existed but was
		// never applied, so these all silently passed.
		{"not a member is denied", []string{"eng"}, []string{"sales"}, false},
		{"user in no groups is denied", []string{"eng"}, nil, false},
		{"no overlap is denied", []string{"ops", "eng"}, []string{"sales", "hr"}, false},

		// Group names are matched exactly; a prefix must not grant access.
		{"prefix must not match", []string{"eng"}, []string{"engineering"}, false},
		{"case sensitive", []string{"Eng"}, []string{"eng"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := routeGroupsAllow(c.allowedGroups, c.userGroups); got != c.want {
				t.Fatalf("routeGroupsAllow(allowed=%v, user=%v) = %v, want %v",
					c.allowedGroups, c.userGroups, got, c.want)
			}
		})
	}
}

// TestRouteGroupAuthzIsWiredIntoEnforcement guards against the check existing
// but never being called — the exact shape of the original bug. Both request
// paths that gate a proxied route must consult allowed_groups.
func TestRouteGroupAuthzIsWiredIntoEnforcement(t *testing.T) {
	// The forward-auth decision path and the proxy handler each enforce roles;
	// both must now enforce groups too.
	for _, file := range []string{"context_evaluator.go", "service.go"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if !strings.Contains(string(b), "routeGroupsAllow(route.AllowedGroups") {
			t.Errorf("%s enforces allowed_roles but not allowed_groups — a route "+
				"restricted by group would be open to every authenticated user", file)
		}
	}
}
