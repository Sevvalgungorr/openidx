// Package sso implements the desktop OAuth Authorization-Code + PKCE flow over
// an RFC 8252 loopback redirect. The user authenticates (incl. MFA) in their
// default browser; the client captures the code on 127.0.0.1 and exchanges it
// for tokens. Mirrors the mobile app's oauth flow.
package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// DesktopClientID is the public/PKCE client seeded by migration v85.
	DesktopClientID = "openidx-desktop"
	// LoopbackAddr / RedirectURI must match a registered redirect on the client.
	LoopbackAddr = "127.0.0.1:47600"
	RedirectURI  = "http://127.0.0.1:47600/callback"

	// MobileClientID is the public/PKCE native client seeded by migration v84.
	// Unlike the desktop client it registers a custom-scheme redirect, so the
	// browser can 302 straight back into the app — no loopback server needed.
	MobileClientID = "openidx-mobile"
	// MobileRedirectURI is the custom-scheme deep link the server redirects to
	// after authentication; Android/iOS route it back to the app.
	MobileRedirectURI = "openidx://oauth-callback"
)

// DefaultScopes requested at login.
var DefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// Tokens is the result of a login or refresh.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"` // unix seconds
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// callbackResult carries the loopback handler's outcome to Wait.
type callbackResult struct {
	code string
	err  error
}

// PendingLogin is an in-flight loopback OAuth flow: the callback listener is
// already bound and serving, and AuthURL is ready for the caller to open in a
// browser. Desktop opens it automatically (see Login); mobile hands it to the
// Dart layer's url_launcher. Wait blocks for the redirect and exchanges the
// code for tokens.
type PendingLogin struct {
	authURL   string
	ln        net.Listener
	srv       *http.Server
	resCh     chan callbackResult
	verifier  string
	state     string
	serverURL string
}

// AuthURL is the OAuth authorize URL the browser must open to complete sign-in.
func (p *PendingLogin) AuthURL() string { return p.authURL }

// StartLogin binds the loopback listener, starts the callback handler, and
// builds the authorize URL — but does NOT open a browser or block. The caller
// opens AuthURL() (or hands it to a mobile browser) and then calls Wait.
func StartLogin(serverURL string) (*PendingLogin, error) {
	serverURL = strings.TrimRight(serverURL, "/")

	pk, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomState()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", LoopbackAddr)
	if err != nil {
		return nil, fmt.Errorf("binding loopback %s: %w", LoopbackAddr, err)
	}

	resCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "sign-in failed: "+e, http.StatusBadRequest)
			resCh <- callbackResult{err: fmt.Errorf("authorization error: %s", e)}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- callbackResult{err: fmt.Errorf("state mismatch")}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			resCh <- callbackResult{err: fmt.Errorf("no authorization code")}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">` +
			`<h2>Signed in to OpenIDX</h2><p>You can close this tab and return to the app.</p></body></html>`))
		resCh <- callbackResult{code: code}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	// Use /oauth/authorize (v1): for public/PKCE clients it renders the login
	// form inline and completes via POST /login, then redirects to our loopback
	// with the code. (v2 redirects to /oauth/login keyed on a separate session
	// store the server-rendered login page can't read.)
	authURL := serverURL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {DesktopClientID},
		"redirect_uri":          {RedirectURI},
		"scope":                 {strings.Join(DefaultScopes, " ")},
		"state":                 {state},
		"code_challenge":        {pk.challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	return &PendingLogin{
		authURL:   authURL,
		ln:        ln,
		srv:       srv,
		resCh:     resCh,
		verifier:  pk.verifier,
		state:     state,
		serverURL: serverURL,
	}, nil
}

// Wait blocks until the browser redirect is captured, the context is cancelled,
// or the timeout elapses, then tears down the listener and exchanges the code
// for tokens. It always closes the listener before returning.
func (p *PendingLogin) Wait(ctx context.Context) (*Tokens, error) {
	defer p.srv.Close()

	timeout := time.NewTimer(5 * time.Minute)
	defer timeout.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeout.C:
		return nil, fmt.Errorf("sign-in timed out")
	case res := <-p.resCh:
		if res.err != nil {
			return nil, res.err
		}
		return exchange(ctx, p.serverURL, url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {DesktopClientID},
			"code":          {res.code},
			"redirect_uri":  {RedirectURI},
			"code_verifier": {p.verifier},
		})
	}
}

// Login runs the interactive PKCE-loopback flow against serverURL (e.g.
// https://openidx.tdv.org) and returns tokens. Blocks until the browser
// redirect is captured, the context is cancelled, or the timeout elapses.
// It is StartLogin + open-browser + Wait; desktop behavior is unchanged.
func Login(ctx context.Context, serverURL string) (*Tokens, error) {
	p, err := StartLogin(serverURL)
	if err != nil {
		return nil, err
	}
	if err := openBrowser(p.AuthURL()); err != nil {
		// Non-fatal: print the URL so the user can open it manually.
		fmt.Printf("Open this URL to sign in:\n  %s\n", p.AuthURL())
	}
	return p.Wait(ctx)
}

// MobileLogin is an in-flight custom-scheme (deep-link) PKCE flow. Unlike
// PendingLogin there is no loopback server: StartMobileLogin only generates the
// PKCE material + authorize URL, the app opens that URL in the system browser,
// the server redirects to openidx://oauth-callback?code=…&state=…, the OS routes
// that back to the app, and the app hands the callback URL to Exchange.
type MobileLogin struct {
	verifier  string
	state     string
	serverURL string
}

// State returns the CSRF state value bound to this flow (for callers that want
// to validate it out-of-band; Exchange also enforces it).
func (m *MobileLogin) State() string { return m.state }

// StartMobileLogin generates PKCE + state and builds the openidx-mobile
// authorize URL for the custom-scheme redirect flow. It does NOT bind any
// listener or open a browser. Returns (flow, authURL, error).
func StartMobileLogin(serverURL string) (*MobileLogin, string, error) {
	serverURL = strings.TrimRight(serverURL, "/")

	pk, err := newPKCE()
	if err != nil {
		return nil, "", err
	}
	state, err := randomState()
	if err != nil {
		return nil, "", err
	}

	authURL := serverURL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {MobileClientID},
		"redirect_uri":          {MobileRedirectURI},
		"scope":                 {strings.Join(DefaultScopes, " ")},
		"code_challenge":        {pk.challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}.Encode()

	return &MobileLogin{
		verifier:  pk.verifier,
		state:     state,
		serverURL: serverURL,
	}, authURL, nil
}

// mobileLoginJSON is the on-disk form of a MobileLogin. MobileLogin's fields are
// unexported, so persistence marshals through this internal struct rather than
// exporting the flow's PKCE material on the public type.
type mobileLoginJSON struct {
	Verifier  string `json:"verifier"`
	State     string `json:"state"`
	ServerURL string `json:"server_url"`
}

// Save persists the flow's PKCE verifier, state, and server URL to path (0600)
// so an in-flight mobile login survives a process restart. On Android the OS
// frequently kills the app while the system browser is foreground and then
// cold-starts it to deliver the openidx://oauth-callback redirect; the relaunched
// process has lost the in-memory flow, so it reloads it from here (see
// LoadMobileLogin) to complete the code exchange.
func (m *MobileLogin) Save(path string) error {
	data, err := json.Marshal(mobileLoginJSON{
		Verifier:  m.verifier,
		State:     m.state,
		ServerURL: m.serverURL,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadMobileLogin reloads a persisted MobileLogin (see Save). It is the cold-start
// counterpart used when the app process was killed during the browser step and
// relaunched to deliver the deep-link callback.
func LoadMobileLogin(path string) (*MobileLogin, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is app-owned <configDir>/login_pending.json
	if err != nil {
		return nil, err
	}
	var mj mobileLoginJSON
	if err := json.Unmarshal(data, &mj); err != nil {
		return nil, fmt.Errorf("parsing persisted login: %w", err)
	}
	return &MobileLogin{
		verifier:  mj.Verifier,
		state:     mj.State,
		serverURL: mj.ServerURL,
	}, nil
}

// Exchange validates the returned state against the one bound at StartMobileLogin
// and swaps the authorization code for tokens using the PKCE verifier.
func (m *MobileLogin) Exchange(ctx context.Context, code, state string) (*Tokens, error) {
	if state != m.state {
		return nil, fmt.Errorf("state mismatch")
	}
	if code == "" {
		return nil, fmt.Errorf("no authorization code")
	}
	return exchange(ctx, m.serverURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {MobileClientID},
		"redirect_uri":  {MobileRedirectURI},
		"code_verifier": {m.verifier},
	})
}

// Refresh exchanges a refresh token for a fresh access token.
func Refresh(ctx context.Context, serverURL, refreshToken string) (*Tokens, error) {
	return exchange(ctx, strings.TrimRight(serverURL, "/"), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {DesktopClientID},
		"refresh_token": {refreshToken},
	})
}

func exchange(ctx context.Context, serverURL string, form url.Values) (*Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		serverURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	exp := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	if tr.ExpiresIn == 0 {
		exp = time.Now().Add(time.Hour).Unix()
	}
	return &Tokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresAt:    exp,
	}, nil
}
