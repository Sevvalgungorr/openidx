package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readAccessSources returns the package's non-test Go sources, so a test can
// assert on how the controller is called rather than on runtime behaviour that
// would need a live fabric.
func readAccessSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		out[f] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no package sources found")
	}
	return out
}

// containsOutsideTests reports whether needle appears in any non-test source.
func containsOutsideTests(src map[string]string, needle string) bool {
	for _, body := range src {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

// TestPolicyCoversService pins how a policy is matched to a service. Getting
// this wrong is what makes a diagnosis lie: a service whose Dial policy is not
// recognised looks like "nobody may reach it" when access is in fact granted.
func TestPolicyCoversService(t *testing.T) {
	cases := []struct {
		name         string
		serviceRoles []string
		service      string
		want         bool
	}{
		{"role attribute", []string{"#secops"}, "secops", true},
		{"explicit name", []string{"@secops"}, "secops", true},
		{"wildcard", []string{"#all"}, "secops", true},
		{"different service", []string{"#other"}, "secops", false},
		{"empty", nil, "secops", false},
		{"substring must not match", []string{"#secops-staging"}, "secops", false},
		{"one of several", []string{"#a", "#secops", "#b"}, "secops", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := policyCoversService(c.serviceRoles, c.service); got != c.want {
				t.Fatalf("policyCoversService(%v, %q) = %v, want %v",
					c.serviceRoles, c.service, got, c.want)
			}
		})
	}
}

func TestDedupePreservesOrder(t *testing.T) {
	got := dedupe([]string{"#b", "#a", "#b", "", "#c", "#a"})
	want := []string{"#b", "#a", "#c"}
	if len(got) != len(want) {
		t.Fatalf("dedupe = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupe = %v, want %v", got, want)
		}
	}
}

// TestZitiListCallsArePaginated is the regression guard for a real truncation
// bug found on production: the OpenZiti management API defaults to returning 10
// items, and several list calls omitted a limit. The admin console therefore
// showed 10 of 35 service policies and 10 of 16 services — a silently partial
// view of the fabric, which also made the resource diagnosis report working
// access as "nobody may reach it".
//
// Every collection list must request an explicit limit.
func TestZitiListCallsArePaginated(t *testing.T) {
	// Collections whose full contents the console depends on.
	mustPaginate := []string{
		"services",
		"identities",
		"service-policies",
		"edge-router-policies",
		"edge-routers",
		"cas",
	}

	src := readAccessSources(t)
	for _, coll := range mustPaginate {
		// Only GET (list) calls need a limit; POST to the same path creates an
		// entity and correctly has no query string.
		bare := `mgmtRequest("GET", "/edge/management/v1/` + coll + `"`
		bareExported := `MgmtRequest("GET", "/edge/management/v1/` + coll + `"`
		if containsOutsideTests(src, bare) || containsOutsideTests(src, bareExported) {
			t.Errorf("GET list call for %q has no limit — the controller will silently "+
				"return only the first 10 rows; append ?limit=…", coll)
		}
	}
}
