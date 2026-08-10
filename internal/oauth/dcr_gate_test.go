package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Dynamic Client Registration is an anonymous write endpoint by specification
// (RFC 7591). Left open, anyone on the internet can register an OAuth client
// with a redirect_uri they control and receive a client_secret — which is a
// ready-made phishing and token-theft position against the identity provider
// itself. An external security review of this deployment reported exactly that
// as a HIGH finding.
//
// The gate is closed, and these tests exist so it cannot drift back open
// silently. They pin the DECISION (who may register), not the response body.

func dcrTestCtx(bearer string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	if bearer != "" {
		c.Request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c, w
}

// The default posture matters more than any single check: an operator who
// configures nothing must not end up with an open registration endpoint.
func TestDCRRefusesAnonymousRegistrationByDefault(t *testing.T) {
	s := &Service{} // nothing configured: no token, no explicit opt-in

	c, _ := dcrTestCtx("")
	if s.dcrAuthorized(c) {
		t.Fatal("an unconfigured deployment must NOT accept anonymous client registration; " +
			"that hands anyone a client_secret plus an attacker-controlled redirect_uri")
	}
}

// Opening registration has to be a deliberate act, not something reachable by
// forgetting to set a token.
func TestDCROpenRegistrationRequiresExplicitOptIn(t *testing.T) {
	s := &Service{dcrAllowOpenRegistration: true}

	c, _ := dcrTestCtx("")
	if !s.dcrAuthorized(c) {
		t.Fatal("an operator who explicitly opts into open registration should get it")
	}
}

func TestDCRAcceptsOnlyTheConfiguredInitialAccessToken(t *testing.T) {
	const secret = "initial-access-token-value"
	s := &Service{dcrInitialAccessToken: secret}

	for _, tc := range []struct {
		name   string
		bearer string
		want   bool
	}{
		{"correct token", secret, true},
		{"no token at all", "", false},
		{"wrong token", "not-the-token", false},
		// A prefix must not pass: it would let an attacker discover the token
		// one character at a time.
		{"prefix of the token", secret[:10], false},
		{"token with extra suffix", secret + "x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := dcrTestCtx(tc.bearer)
			if got := s.dcrAuthorized(c); got != tc.want {
				t.Errorf("dcrAuthorized(%q) = %v, want %v", tc.bearer, got, tc.want)
			}
		})
	}
}

// When a token is configured, the open-registration switch must not be a way
// around it. Otherwise a stray config flag silently disables the gate an
// operator believes is protecting them.
func TestDCRConfiguredTokenIsNotBypassedByOpenRegistration(t *testing.T) {
	s := &Service{
		dcrInitialAccessToken:    "the-token",
		dcrAllowOpenRegistration: true,
	}

	c, _ := dcrTestCtx("")
	if s.dcrAuthorized(c) {
		t.Fatal("a configured initial access token must still be required; " +
			"open registration must not override an explicit gate")
	}
}
