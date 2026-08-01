package oauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Discovery advertises client_secret_basic, but no handler ever parsed an
// Authorization: Basic header — credentials were read from the form body only,
// so any client using the advertised method got invalid_client. These tests
// pin the header path, including the urlencoding step that RFC 6749 §2.3.1
// requires and that is easy to skip.

func basicRequest(t *testing.T, header string, form url.Values) *gin.Context {
	t.Helper()

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	body := ""
	if form != nil {
		body = form.Encode()
	}
	c.Request = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if header != "" {
		c.Request.Header.Set("Authorization", header)
	}
	return c
}

func basicHeader(id, secret string) string {
	// RFC 6749 §2.3.1: form-urlencode each component, then base64 the pair.
	raw := url.QueryEscape(id) + ":" + url.QueryEscape(secret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

func TestClientCredentials(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		form       url.Values
		wantID     string
		wantSecret string
		wantOK     bool
	}{
		{
			name:       "basic header is honored (the advertised method)",
			header:     basicHeader("web-app", "s3cr3t"),
			wantID:     "web-app",
			wantSecret: "s3cr3t",
			wantOK:     true,
		},
		{
			name:       "form body still works",
			form:       url.Values{"client_id": {"web-app"}, "client_secret": {"s3cr3t"}},
			wantID:     "web-app",
			wantSecret: "s3cr3t",
			wantOK:     true,
		},
		{
			name: "a secret with reserved characters survives the round trip",
			// A '+' decoded as a space, or a '%' left escaped, turns into a
			// mismatch that presents as a wrong password.
			header:     basicHeader("web-app", "a+b/c=d %e"),
			wantID:     "web-app",
			wantSecret: "a+b/c=d %e",
			wantOK:     true,
		},
		{
			name:       "client id may contain reserved characters too",
			header:     basicHeader("urn:client:one two", "x"),
			wantID:     "urn:client:one two",
			wantSecret: "x",
			wantOK:     true,
		},
		{
			name:       "basic with an empty secret is allowed (public client)",
			header:     basicHeader("public-app", ""),
			wantID:     "public-app",
			wantSecret: "",
			wantOK:     true,
		},
		{
			name:   "repeating the same client_id in the form is tolerated",
			header: basicHeader("web-app", "s3cr3t"),
			form:   url.Values{"client_id": {"web-app"}},
			wantID: "web-app", wantSecret: "s3cr3t", wantOK: true,
		},
		{
			name:   "two authentication methods at once is rejected",
			header: basicHeader("web-app", "s3cr3t"),
			form:   url.Values{"client_id": {"web-app"}, "client_secret": {"other"}},
			wantOK: false,
		},
		{
			name:   "a conflicting client_id is rejected",
			header: basicHeader("web-app", "s3cr3t"),
			form:   url.Values{"client_id": {"different-app"}},
			wantOK: false,
		},
		{
			name:   "a malformed basic header falls through to the form",
			header: "Basic !!!not-base64!!!",
			form:   url.Values{"client_id": {"form-app"}, "client_secret": {"pw"}},
			wantID: "form-app", wantSecret: "pw", wantOK: true,
		},
		{
			name:   "a bearer header is not client authentication",
			header: "Bearer abc123",
			form:   url.Values{"client_id": {"form-app"}, "client_secret": {"pw"}},
			wantID: "form-app", wantSecret: "pw", wantOK: true,
		},
		{
			name:   "no credentials at all",
			wantID: "", wantSecret: "", wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, secret, ok := clientCredentials(basicRequest(t, tt.header, tt.form))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if id != tt.wantID {
				t.Errorf("id = %q, want %q", id, tt.wantID)
			}
			if secret != tt.wantSecret {
				t.Errorf("secret = %q, want %q", secret, tt.wantSecret)
			}
		})
	}
}

func TestBasicClientAuth_SchemeIsCaseInsensitive(t *testing.T) {
	// RFC 7235 §2.1: the auth-scheme token is case-insensitive.
	raw := base64.StdEncoding.EncodeToString([]byte("app:pw"))
	for _, scheme := range []string{"Basic ", "basic ", "BASIC "} {
		id, secret, ok := basicClientAuth(basicRequest(t, scheme+raw, nil))
		if !ok || id != "app" || secret != "pw" {
			t.Errorf("scheme %q: got (%q, %q, %v)", scheme, id, secret, ok)
		}
	}
}
