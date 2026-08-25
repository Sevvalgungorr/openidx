package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/sso"
)

// tokenTestServer returns an httptest server that answers /oauth/token with a
// minimal token response, capturing the received code_verifier and code.
func tokenTestServer(t *testing.T, gotVerifier, gotCode *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		*gotVerifier = r.Form.Get("code_verifier")
		*gotCode = r.Form.Get("code")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600,"token_type":"Bearer"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLoginFinishColdStart simulates the Android cold-start: the app process was
// killed while the browser was foreground, so e.pendingMobileLogin is nil but a
// login_pending.json was persisted by the prior LoginStart. LoginFinish must
// reload it from disk, exchange the code, save the session, and delete the file.
func TestLoginFinishColdStart(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		configDir:    dir,
		logger:       zap.NewNop(),
		loginTimeout: 5 * time.Second,
		bridges:      map[string]*bridge{},
	}

	var gotVerifier, gotCode string
	ts := tokenTestServer(t, &gotVerifier, &gotCode)

	// Persist a pending login as if a prior LoginStart wrote it, then throw away
	// the in-memory flow (e.pendingMobileLogin stays nil = cold start).
	m, _, err := sso.StartMobileLogin(ts.URL)
	if err != nil {
		t.Fatalf("StartMobileLogin: %v", err)
	}
	if err := m.Save(e.pendingLoginPath()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cb := "openidx://oauth-callback?" + url.Values{
		"code":  {"auth-code-123"},
		"state": {m.State()},
	}.Encode()

	out, err := e.LoginFinish(cb)
	if err != nil {
		t.Fatalf("LoginFinish (cold start): %v", err)
	}
	if out == "" {
		t.Fatal("expected a user payload")
	}
	if gotCode != "auth-code-123" {
		t.Errorf("exchanged code = %q, want auth-code-123", gotCode)
	}
	if gotVerifier == "" {
		t.Error("expected the persisted PKCE verifier to be sent")
	}

	// Session saved.
	tok, err := authstore.Load(dir)
	if err != nil || tok == nil || tok.AccessToken != "at" {
		t.Fatalf("session not saved: tok=%+v err=%v", tok, err)
	}

	// Pending file removed so the code can't be replayed.
	if _, err := os.Stat(e.pendingLoginPath()); !os.IsNotExist(err) {
		t.Errorf("login_pending.json should be deleted, stat err=%v", err)
	}
}

// TestLoginFinishNoPending confirms that with neither an in-memory flow nor a
// persisted file, LoginFinish reports no login in progress.
func TestLoginFinishNoPending(t *testing.T) {
	e := &Engine{
		configDir:    t.TempDir(),
		logger:       zap.NewNop(),
		loginTimeout: time.Second,
		bridges:      map[string]*bridge{},
	}
	_, err := e.LoginFinish("openidx://oauth-callback?code=x&state=y")
	if err == nil {
		t.Fatal("expected error when no login is in progress")
	}
}

// TestLoginStartPersistsPending verifies LoginStart writes the recoverable file
// in addition to holding the in-memory flow.
func TestLoginStartPersistsPending(t *testing.T) {
	e := &Engine{
		configDir:    t.TempDir(),
		serverURL:    "https://openidx.test",
		logger:       zap.NewNop(),
		loginTimeout: time.Second,
		bridges:      map[string]*bridge{},
	}
	if _, err := e.LoginStart(); err != nil {
		t.Fatalf("LoginStart: %v", err)
	}
	if e.pendingMobileLogin == nil {
		t.Error("expected in-memory pendingMobileLogin to be set")
	}
	if _, err := os.Stat(e.pendingLoginPath()); err != nil {
		t.Errorf("expected login_pending.json to exist: %v", err)
	}
}
