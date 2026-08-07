package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// jargonWords are the overlay concepts an end user must never be shown. The
// whole point of My Network is that a user reasons about "a machine and a port",
// not about the fabric that carries them there.
var jargonWords = []string{
	"ziti", "openziti", "intercept", "terminator", "edge router",
	"role attribute", "enrollment", "enroll", "jwt", "tunneler",
	"dial policy", "bind policy", "service policy", "host.v1",
}

// seedMyResources creates one browser-reachable route and two brokered entries
// (one open, one approval-gated) plus a second org's route that must never leak.
func seedMyResources(t *testing.T, s *Service, orgA, orgB, userA, liveURL string) {
	t.Helper()
	ctx := orgctx.WithBypassRLS(context.Background())
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := s.db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}

	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,'Org B (mynet)','org-b-mynet')
	      ON CONFLICT (id) DO NOTHING`, orgB)

	// Browser-reachable (BrowZer-fronted) web route in org A.
	exec(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, browzer_enabled)
	      VALUES ($1,'Wiki',$2,'http://10.0.0.5:8080',true,true)`, orgA, liveURL)
	// Same shape in org B — must never appear for an org A caller.
	exec(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, browzer_enabled)
	      VALUES ($1,'OtherOrgWiki','https://other.example.org','http://10.9.9.9:80',true,true)`, orgB)
	// Not browser-fronted → not a browser row.
	exec(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, browzer_enabled)
	      VALUES ($1,'NoBrowzer','https://nb.example.org','http://10.0.0.6:80',true,false)`, orgA)

	// Brokered entries: one open, one approval-gated. Granted to userA.
	exec(`INSERT INTO pam_entries (id, org_id, name, entry_type, hostname, port, require_approval)
	      VALUES ('11111111-0000-0000-0000-0000000000a1',$1,'db-01','ssh','10.0.0.21',22,false)`, orgA)
	exec(`INSERT INTO pam_entries (id, org_id, name, entry_type, hostname, port, require_approval)
	      VALUES ('11111111-0000-0000-0000-0000000000a2',$1,'win-01','rdp','10.0.0.22',3389,true)`, orgA)
	// An entry the user has NO grant for — must not appear for a non-admin.
	exec(`INSERT INTO pam_entries (id, org_id, name, entry_type, hostname, port, require_approval)
	      VALUES ('11111111-0000-0000-0000-0000000000a3',$1,'secret-01','ssh','10.0.0.23',22,false)`, orgA)

	for _, id := range []string{
		"11111111-0000-0000-0000-0000000000a1",
		"11111111-0000-0000-0000-0000000000a2",
	} {
		exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		      VALUES ($1,$2,'user',$3,ARRAY['connect']::text[])`, orgA, id, userA)
	}
}

func fetchMyResources(t *testing.T, s *Service, orgID, userID string, roles []string) (map[string]interface{}, string) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/access/my/resources", nil)
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
	c.Request = req
	c.Set("user_id", userID)
	if roles != nil {
		c.Set("roles", roles)
	}
	s.handleMyResources(c)

	if w.Code != 200 {
		t.Fatalf("my-resources: status %d, body %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("my-resources: bad json: %v", err)
	}
	return body, w.Body.String()
}

// TestMyResourcesContract locks the user-facing contract that the whole
// "make OpenZiti easy" effort rests on:
//   - scoping: no other org's resources, and no entry the caller has no grant for;
//   - completeness: every row states where→where, over which port, and how;
//   - one action: exactly one primary action per row, and never a dead end;
//   - plain language: zero overlay vocabulary anywhere in the payload.
func TestMyResourcesContract(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	gin.SetMode(gin.TestMode)
	s := &Service{db: db, logger: zap.NewNop()}

	const (
		orgA  = "00000000-0000-0000-0000-000000000010" // seeded default org
		orgB  = "00000000-0000-0000-0000-0000000000b7"
		userA = "22222222-0000-0000-0000-0000000000a1"
	)
	// A real listener so the readiness probe sees a live target, mirroring how a
	// published web resource behaves in production.
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer live.Close()

	seedMyResources(t, s, orgA, orgB, userA, live.URL)

	body, raw := fetchMyResources(t, s, orgA, userA, []string{"user"})
	rows, _ := body["resources"].([]interface{})
	if len(rows) == 0 {
		t.Fatalf("expected resources, got none: %s", raw)
	}

	// --- plain language: no overlay vocabulary in the payload at all ---
	lower := strings.ToLower(raw)
	for _, w := range jargonWords {
		if strings.Contains(lower, w) {
			t.Errorf("payload leaks overlay vocabulary %q — users must not see fabric concepts: %s", w, raw)
		}
	}

	names := map[string]map[string]interface{}{}
	for _, r := range rows {
		m, _ := r.(map[string]interface{})
		if m == nil {
			t.Fatalf("row is not an object: %+v", r)
		}
		name, _ := m["name"].(string)
		names[name] = m

		// --- completeness: the where→where sentence must be answerable ---
		for _, f := range []string{"id", "name", "kind", "from", "to", "how", "status"} {
			if v, ok := m[f]; !ok || v == "" {
				t.Errorf("row %q missing %q (cannot state where→where): %+v", name, f, m)
			}
		}
		// --- exactly one actionable primary control, never a dead end ---
		act, _ := m["action"].(map[string]interface{})
		if act == nil {
			t.Errorf("row %q has no action — dead end", name)
			continue
		}
		if lbl, _ := act["label"].(string); lbl == "" {
			t.Errorf("row %q action has no label", name)
		}
		kind, _ := act["kind"].(string)
		switch kind {
		case "open_url":
			if u, _ := act["url"].(string); u == "" {
				t.Errorf("row %q open_url action without url", name)
			}
		case "broker_connect", "request":
			if tg, _ := act["target"].(string); tg == "" {
				t.Errorf("row %q %s action without target", name, kind)
			}
		default:
			t.Errorf("row %q has unknown action kind %q", name, kind)
		}
	}

	// --- scoping: other org's route must not appear ---
	if _, leaked := names["OtherOrgWiki"]; leaked {
		t.Errorf("cross-org leak: another organization's resource is listed")
	}
	// --- scoping: entry without a grant must not appear for a non-admin ---
	if _, leaked := names["secret-01"]; leaked {
		t.Errorf("entitlement leak: entry without a grant is listed")
	}
	// --- only browser-fronted routes become browser rows ---
	if _, present := names["NoBrowzer"]; present {
		t.Errorf("route without browser fronting must not be offered as a browser resource")
	}

	// --- the web row is ready and needs nothing installed ---
	wiki := names["Wiki"]
	if wiki == nil {
		t.Fatalf("browser-reachable route missing from results")
	}
	if got := wiki["status"]; got != statusReady {
		t.Errorf("browser route status = %v, want %q (it needs no client)", got, statusReady)
	}
	if got := wiki["how"]; got != reachBrowser {
		t.Errorf("browser route how = %v, want %q", got, reachBrowser)
	}

	// --- approval-gated entry stays actionable (request), never a dead end ---
	win := names["win-01"]
	if win == nil {
		t.Fatalf("granted approval-gated entry missing from results")
	}
	if got := win["status"]; got != statusRequestAccess {
		t.Errorf("approval-gated entry status = %v, want %q", got, statusRequestAccess)
	}
	// --- open granted entry is directly connectable ---
	if db01 := names["db-01"]; db01 == nil {
		t.Fatalf("granted open entry missing from results")
	} else if got := db01["status"]; got != statusReady {
		t.Errorf("granted open entry status = %v, want %q", got, statusReady)
	}
}

// TestMyResourcesNoFalseGreen guards the honesty rule discovered on production:
// a route can be fully configured (enabled + browser-fronted) yet unusable
// because its public hostname was never published in DNS. Showing it as "ready"
// hands the user a button that fails in the browser. It must be reported as
// needing setup, and must still offer the user something to do.
func TestMyResourcesNoFalseGreen(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	gin.SetMode(gin.TestMode)
	s := &Service{db: db, logger: zap.NewNop()}

	const (
		orgA  = "00000000-0000-0000-0000-000000000010"
		userA = "22222222-0000-0000-0000-0000000000d1"
	)
	seedCtx := orgctx.WithBypassRLS(context.Background())
	// A hostname that cannot resolve anywhere (reserved .invalid TLD, RFC 2606).
	if _, err := s.db.Pool.Exec(seedCtx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, browzer_enabled)
		 VALUES ($1,'Unpublished','https://nope.invalid','http://10.0.0.9:80',true,true)`, orgA); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	body, raw := fetchMyResources(t, s, orgA, userA, []string{"user"})
	rows, _ := body["resources"].([]interface{})

	var got map[string]interface{}
	for _, r := range rows {
		m, _ := r.(map[string]interface{})
		if m["name"] == "Unpublished" {
			got = m
		}
	}
	if got == nil {
		t.Fatalf("unresolvable route missing from results: %s", raw)
	}
	if got["status"] == statusReady {
		t.Errorf("a route whose hostname does not resolve must not be advertised as ready: %+v", got)
	}
	// Still actionable — the user is told what to do, not left at a dead end.
	act, _ := got["action"].(map[string]interface{})
	if act == nil {
		t.Fatalf("unusable route has no action — dead end: %+v", got)
	}
	if lbl, _ := act["label"].(string); lbl == "" {
		t.Errorf("unusable route action has no label: %+v", act)
	}
}

// TestMyResourcesBrowserPathNeedsNoEnrollment proves the central usability
// claim: a user with NO enrolled device still gets browser-reachable resources.
// This is what removes the "install a tunneler first" wall for the common case.
func TestMyResourcesBrowserPathNeedsNoEnrollment(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	gin.SetMode(gin.TestMode)
	s := &Service{db: db, logger: zap.NewNop()}

	const (
		orgA  = "00000000-0000-0000-0000-000000000010"
		userA = "22222222-0000-0000-0000-0000000000c1"
	)
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer live.Close()

	seedCtx := orgctx.WithBypassRLS(context.Background())
	if _, err := s.db.Pool.Exec(seedCtx,
		`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled, browzer_enabled)
		 VALUES ($1,'Portal',$2,'http://10.0.0.7:80',true,true)`, orgA, live.URL); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	// Deliberately no ziti_identities row for this user: not enrolled at all.
	body, raw := fetchMyResources(t, s, orgA, userA, []string{"user"})
	rows, _ := body["resources"].([]interface{})

	found := false
	for _, r := range rows {
		m, _ := r.(map[string]interface{})
		if m["name"] == "Portal" && m["status"] == statusReady && m["how"] == reachBrowser {
			found = true
		}
	}
	if !found {
		t.Fatalf("a user with no enrolled device must still get browser-reachable resources: %s", raw)
	}
}

// TestUrlAnswersTreatsAuthChallengesAsLive pins the liveness rule that decides
// whether a user is shown a working button. A login prompt or a redirect proves
// the whole path is up and the app is simply asking the user to sign in — those
// must count as reachable. Only "nothing answered at all" is a failure.
//
// This exists because a real resource on production (kibana-dev) answers 302 to
// its login page, and es-dev answers 401; treating those as broken would hide
// working resources, while treating a dead host as ready hands the user a button
// that fails in the browser.
func TestUrlAnswersTreatsAuthChallengesAsLive(t *testing.T) {
	s := &Service{logger: zap.NewNop()}

	cases := []struct {
		name string
		code int
	}{
		{"ok", 200},
		{"login redirect", 302},
		{"needs auth", 401},
		{"forbidden", 403},
		{"not found still proves the path is live", 404},
		{"server error still proves the path is live", 500},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.code)
			}))
			defer srv.Close()
			reachCache.Delete(srv.URL)

			if !s.urlAnswers(srv.URL) {
				t.Fatalf("HTTP %d must count as reachable — the path answered", c.code)
			}
		})
	}

	// Nothing listening: the server is closed before the probe runs.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	reachCache.Delete(deadURL)
	if s.urlAnswers(deadURL) {
		t.Fatal("a dead target must not be reported as reachable")
	}

	// An empty URL is never reachable.
	if s.urlAnswers("") {
		t.Fatal("empty URL must not be reported as reachable")
	}
}
