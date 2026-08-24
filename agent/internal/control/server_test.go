package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/sso"
)

// fakeBackend implements the backend seam so the HTTP layer can be exercised
// without a live OpenIDX server.
type fakeBackend struct {
	loginTokens *sso.Tokens
	loginErr    error
	entries     []desktoppam.Entry
	listErr     error
	connectURL  string
	connectErr  error
	requestErr  error

	requestedEntry  string
	requestedReason string
}

func (f *fakeBackend) Login(ctx context.Context, serverURL string) (*sso.Tokens, error) {
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	return f.loginTokens, nil
}
func (f *fakeBackend) Enroll(logger *zap.Logger, serverURL, token, configDir string) (string, string, string, error) {
	return "agent-1", "device-1", "", nil
}
func (f *fakeBackend) PamList(ctx context.Context, serverURL, token string) ([]desktoppam.Entry, error) {
	return f.entries, f.listErr
}
func (f *fakeBackend) PamConnect(ctx context.Context, serverURL, token, entryID string) (string, error) {
	return f.connectURL, f.connectErr
}
func (f *fakeBackend) PamRequest(ctx context.Context, serverURL, token, entryID, reason string) error {
	f.requestedEntry = entryID
	f.requestedReason = reason
	return f.requestErr
}

// fakeDialer implements zitiDialer.
type fakeDialer struct{ closed bool }

func (d *fakeDialer) Bridge(service string) (string, func(), error) {
	return "127.0.0.1:65000", func() {}, nil
}
func (d *fakeDialer) Close() { d.closed = true }

// newTestEngine builds an Engine wired to a fake backend over a temp config dir.
func newTestEngine(t *testing.T, be backend) *Engine {
	t.Helper()
	dir := t.TempDir()
	e := &Engine{
		configDir:    dir,
		serverURL:    "https://openidx.test",
		logger:       zap.NewNop(),
		be:           be,
		newDialer:    func(string) (zitiDialer, error) { return &fakeDialer{}, nil },
		loginTimeout: time.Second,
		bridges:      map[string]*bridge{},
	}
	return e
}

// startTestServer starts a control Server on its platform listener and returns
// an http.Client that reaches it plus a shutdown func. On UDS the client dials
// the socket; on Windows it dials the loopback and sets the bearer.
func startTestServer(t *testing.T, e *Engine) (*http.Client, string, func()) {
	t.Helper()
	srv, err := NewServer(e, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(done) }()

	// Wait for the listener to be reachable.
	base, client := dialControl(t, srv)
	cleanup := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	// Wrap client so the bearer token (if any) is attached.
	token := srv.Token()
	tc := &http.Client{Transport: bearerTransport{rt: client.Transport, token: token}}
	return tc, base, cleanup
}

type bearerTransport struct {
	rt    http.RoundTripper
	token string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.rt.RoundTrip(r)
}

func get(t *testing.T, c *http.Client, base, path string) (int, []byte) {
	t.Helper()
	resp, err := c.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func post(t *testing.T, c *http.Client, base, path, body string) (int, []byte) {
	t.Helper()
	resp, err := c.Post(base+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, rb
}

func TestStatusRoute(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := get(t, c, base, "/status")
	if code != http.StatusOK {
		t.Fatalf("status code = %d, body=%s", code, body)
	}
	var st statusPayload
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("unmarshal status: %v (%s)", err, body)
	}
	// Fresh temp dir: not enrolled, not logged in.
	if st.Enrolled {
		t.Errorf("expected not enrolled")
	}
	if st.LoggedIn {
		t.Errorf("expected not logged in")
	}
}

func TestStatusReflectsLoggedInUser(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	// Persist a token with a decodable JWT (sub/email/exp).
	tok := &sso.Tokens{AccessToken: makeJWT("user-42", "u@example.com", time.Now().Add(time.Hour).Unix()), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := saveToken(e.configDir, tok); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := get(t, c, base, "/status")
	if code != http.StatusOK {
		t.Fatalf("code=%d body=%s", code, body)
	}
	var st statusPayload
	_ = json.Unmarshal(body, &st)
	if !st.LoggedIn || st.UserSub != "user-42" || st.UserEmail != "u@example.com" {
		t.Fatalf("status did not reflect user: %+v", st)
	}
}

func TestLogoutRoute(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := post(t, c, base, "/logout", "")
	if code != http.StatusOK {
		t.Fatalf("logout code=%d body=%s", code, body)
	}
}

func TestEnrollBadJSON(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, _ := post(t, c, base, "/enroll", "{not json")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", code)
	}
}

func TestEnrollMissingCode(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, _ := post(t, c, base, "/enroll", `{"code":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing code, got %d", code)
	}
}

func TestPamListRequiresAuth(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	// No cached token → 401.
	code, body := get(t, c, base, "/pam/entries")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d body=%s", code, body)
	}
}

func TestPamListWithSession(t *testing.T) {
	be := &fakeBackend{entries: []desktoppam.Entry{{ID: "e1", Name: "prod-db"}}}
	e := newTestEngine(t, be)
	if err := saveToken(e.configDir, &sso.Tokens{AccessToken: "opaque-token"}); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := get(t, c, base, "/pam/entries")
	if code != http.StatusOK {
		t.Fatalf("code=%d body=%s", code, body)
	}
	var entries []desktoppam.Entry
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, body)
	}
	if len(entries) != 1 || entries[0].ID != "e1" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestPamConnectMissingEntryID(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	if err := saveToken(e.configDir, &sso.Tokens{AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, _ := post(t, c, base, "/pam/connect", `{"entry_id":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestPamConnectWithSession(t *testing.T) {
	be := &fakeBackend{connectURL: "https://guac.test/session/abc"}
	e := newTestEngine(t, be)
	if err := saveToken(e.configDir, &sso.Tokens{AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := post(t, c, base, "/pam/connect", `{"entry_id":"e1"}`)
	if code != http.StatusOK {
		t.Fatalf("code=%d body=%s", code, body)
	}
	var out map[string]string
	_ = json.Unmarshal(body, &out)
	if out["connect_url"] != "https://guac.test/session/abc" {
		t.Fatalf("unexpected connect_url: %s", out["connect_url"])
	}
}

func TestPamRequestPassesReason(t *testing.T) {
	be := &fakeBackend{}
	e := newTestEngine(t, be)
	if err := saveToken(e.configDir, &sso.Tokens{AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, _ := post(t, c, base, "/pam/request", `{"entry_id":"e1","reason":"oncall"}`)
	if code != http.StatusOK {
		t.Fatalf("code=%d", code)
	}
	if be.requestedEntry != "e1" || be.requestedReason != "oncall" {
		t.Fatalf("backend got entry=%q reason=%q", be.requestedEntry, be.requestedReason)
	}
}

func TestZitiDialMissingService(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, _ := post(t, c, base, "/ziti/dial", `{"service":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestZitiDialAndClose(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	// Provide a fake identity file so the identity-present guard passes.
	idPath := filepath.Join(e.configDir, "ziti-identity.json")
	if err := os.WriteFile(idPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := post(t, c, base, "/ziti/dial", `{"service":"openidx-rdp"}`)
	if code != http.StatusOK {
		t.Fatalf("dial code=%d body=%s", code, body)
	}
	var out map[string]string
	_ = json.Unmarshal(body, &out)
	if out["local_addr"] != "127.0.0.1:65000" {
		t.Fatalf("unexpected local_addr: %s", out["local_addr"])
	}
	// Idempotent reuse.
	code, _ = post(t, c, base, "/ziti/dial", `{"service":"openidx-rdp"}`)
	if code != http.StatusOK {
		t.Fatalf("second dial code=%d", code)
	}
	// Close.
	code, _ = post(t, c, base, "/ziti/close", `{"service":"openidx-rdp"}`)
	if code != http.StatusOK {
		t.Fatalf("close code=%d", code)
	}
	// Closing again → 500 (no active bridge).
	code, _ = post(t, c, base, "/ziti/close", `{"service":"openidx-rdp"}`)
	if code == http.StatusOK {
		t.Fatalf("expected error closing an already-closed bridge")
	}
}

// ---- test helpers ----

// saveToken writes a cached OAuth token to the engine config dir using the same
// on-disk format authstore expects.
func saveToken(dir string, t *sso.Tokens) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "user-tokens.json"), data, 0600)
}

// makeJWT builds an unsigned (alg=none-style) JWT with the given claims; only
// the payload segment is decoded by the engine (display-only).
func makeJWT(sub, email string, exp int64) string {
	header := base64URL(`{"alg":"none","typ":"JWT"}`)
	payload := base64URL(fmt.Sprintf(`{"sub":%q,"email":%q,"exp":%d}`, sub, email, exp))
	return header + "." + payload + ".signature"
}

func base64URL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
