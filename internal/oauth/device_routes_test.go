package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestDeviceVerificationURIUsesThePublicAppOrigin.
//
// The URI is printed on a television or a terminal. The OAuth issuer is this
// API's origin and serves no /device page, so building the URI from it sends
// the user to a JSON 404 — and unlike a mistyped link in an email, a user
// reading an address off a screen has no way to correct it.
func TestDeviceVerificationURIUsesThePublicAppOrigin(t *testing.T) {
	org := orgctx.Org{ID: "11111111-0000-0000-0000-00000000000a"}

	s := &Service{
		logger: zap.NewNop(),
		config: &config.Config{
			PublicBaseURL: "https://portal.example.com",
			OAuthIssuer:   "https://api.example.com",
		},
	}
	if got := s.deviceVerificationURI(org); got != "https://portal.example.com/device" {
		t.Fatalf("verification URI = %q, want the public app origin", got)
	}

	// A trailing slash on the configured origin must not produce "//device".
	s.config.PublicBaseURL = "https://portal.example.com/"
	if got := s.deviceVerificationURI(org); got != "https://portal.example.com/device" {
		t.Fatalf("verification URI = %q, want no doubled slash", got)
	}

	// With no public origin configured, fall back rather than emit a bare path.
	s.config.PublicBaseURL = ""
	got := s.deviceVerificationURI(org)
	if !strings.HasSuffix(got, "/device") || strings.HasPrefix(got, "/device") {
		t.Fatalf("fallback verification URI = %q, want an absolute URL", got)
	}
}

// TestDeviceVerificationRoutesSitBehindFlowAuth.
//
// handleDeviceVerificationDecision reads the subject from the gin context,
// which only the auth middleware populates. Registered without it the handler
// sees an empty user id and 401s on every approval — the same failure the
// step-up endpoints were fixed for. This asserts the middleware is actually in
// front of both verification routes, which route registration alone does not
// make obvious.
func TestDeviceVerificationRoutesSitBehindFlowAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var seen []string
	flowAuth := func(c *gin.Context) {
		seen = append(seen, c.Request.Method+" "+c.FullPath())
		// Abort here so the test never reaches a handler that needs a database:
		// reaching this line at all is the property under test.
		c.AbortWithStatus(http.StatusTeapot)
	}

	router := gin.New()
	svc := &Service{logger: zap.NewNop(), config: &config.Config{}}
	RegisterRoutes(router, svc, func(c *gin.Context) { c.Next() }, flowAuth)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/oauth/device/lookup?user_code=ACDEFGHJ"},
		{http.MethodPost, "/oauth/device/decision"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			before := len(seen)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if len(seen) == before {
				t.Fatalf("%s %s did not pass through flowAuth — the handler would see no subject and reject every approval",
					tc.method, tc.path)
			}
			if w.Code != http.StatusTeapot {
				t.Fatalf("expected the middleware to short-circuit with %d, got %d",
					http.StatusTeapot, w.Code)
			}
		})
	}
}

// TestDeviceAuthorizationEndpointIsNotBehindFlowAuth — the device asks for its
// code pair before any user is involved, so requiring an end-user session there
// would make the grant impossible to start.
func TestDeviceAuthorizationEndpointIsNotBehindFlowAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reached := false
	flowAuth := func(c *gin.Context) {
		reached = true
		c.AbortWithStatus(http.StatusTeapot)
	}

	router := gin.New()
	svc := &Service{logger: zap.NewNop(), config: &config.Config{}}
	RegisterRoutes(router, svc, func(c *gin.Context) { c.Next() }, flowAuth)

	req := httptest.NewRequest(http.MethodOptions, "/oauth/device_authorization", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if reached {
		t.Fatalf("the device authorization endpoint was placed behind end-user auth; a headless device has no session to present")
	}
}
