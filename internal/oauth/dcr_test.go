package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBuildClientFromMetadataDefaults(t *testing.T) {
	svc := &Service{}
	md := &clientMetadata{
		ClientName:   "My Agent",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}
	client, err := svc.buildClientFromMetadata(md)
	if err != nil {
		t.Fatalf("buildClientFromMetadata: %v", err)
	}
	if !strings.HasPrefix(client.ClientID, "oidc_") {
		t.Errorf("expected generated client_id, got %q", client.ClientID)
	}
	if client.ClientSecret == "" {
		t.Error("confidential client should get a secret")
	}
	if client.Type != "confidential" {
		t.Errorf("expected confidential by default, got %q", client.Type)
	}
	if len(client.GrantTypes) != 1 || client.GrantTypes[0] != "authorization_code" {
		t.Errorf("expected default authorization_code grant, got %v", client.GrantTypes)
	}
}

func TestBuildClientPublicNoSecret(t *testing.T) {
	svc := &Service{}
	md := &clientMetadata{
		ClientName:              "SPA",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://spa.example.com/cb"},
	}
	client, err := svc.buildClientFromMetadata(md)
	if err != nil {
		t.Fatalf("buildClientFromMetadata: %v", err)
	}
	if client.Type != "public" {
		t.Errorf("expected public client for auth_method=none, got %q", client.Type)
	}
	if client.ClientSecret != "" {
		t.Error("public client must not get a secret")
	}
	if !client.PKCERequired {
		t.Error("public client should require PKCE")
	}
}

func TestBuildClientTokenExchangeGrantNoRedirect(t *testing.T) {
	svc := &Service{}
	// A machine/agent client using only token-exchange + client_credentials
	// needs no redirect_uris.
	md := &clientMetadata{
		ClientName: "agent",
		GrantTypes: []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
	}
	client, err := svc.buildClientFromMetadata(md)
	if err != nil {
		t.Fatalf("buildClientFromMetadata: %v", err)
	}
	if !contains(client.GrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange") {
		t.Error("expected token-exchange grant retained")
	}
}

func TestBuildClientRejectsBadGrant(t *testing.T) {
	svc := &Service{}
	_, err := svc.buildClientFromMetadata(&clientMetadata{GrantTypes: []string{"password"}})
	if err == nil {
		t.Fatal("expected rejection of unsupported grant_type")
	}
}

func TestBuildClientRequiresRedirectForAuthCode(t *testing.T) {
	svc := &Service{}
	_, err := svc.buildClientFromMetadata(&clientMetadata{
		GrantTypes: []string{"authorization_code"},
	})
	if err == nil {
		t.Fatal("expected error when authorization_code has no redirect_uris")
	}
}

func TestBuildClientRejectsInsecureRedirect(t *testing.T) {
	svc := &Service{}
	_, err := svc.buildClientFromMetadata(&clientMetadata{
		ClientName:   "x",
		GrantTypes:   []string{"authorization_code"},
		RedirectURIs: []string{"http://evil.example.com/cb"},
	})
	if err == nil {
		t.Fatal("expected rejection of non-localhost http redirect")
	}
}

func TestBuildClientAllowsLoopbackAndNativeScheme(t *testing.T) {
	svc := &Service{}
	for _, uri := range []string{"http://localhost:9000/cb", "http://127.0.0.1/cb", "com.example.app:/cb"} {
		_, err := svc.buildClientFromMetadata(&clientMetadata{
			ClientName:   "x",
			GrantTypes:   []string{"authorization_code"},
			RedirectURIs: []string{uri},
		})
		if err != nil {
			t.Errorf("expected %q accepted, got %v", uri, err)
		}
	}
}

func TestDCRAuthorizedGate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// No gate and no opt-in -> closed (default-secure).
	closed := &Service{}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	if closed.dcrAuthorized(c) {
		t.Error("expected CLOSED registration by default when no initial access token and no opt-in")
	}

	// No gate but explicit open-registration opt-in -> open.
	open := &Service{dcrAllowOpenRegistration: true}
	co, _ := gin.CreateTestContext(httptest.NewRecorder())
	co.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	if !open.dcrAuthorized(co) {
		t.Error("expected open registration when dcrAllowOpenRegistration is true")
	}

	// Gate configured -> requires matching bearer.
	gated := &Service{dcrInitialAccessToken: "s3cr3t"}
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	if gated.dcrAuthorized(c2) {
		t.Error("expected rejection without bearer")
	}
	c3, _ := gin.CreateTestContext(httptest.NewRecorder())
	c3.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	c3.Request.Header.Set("Authorization", "Bearer s3cr3t")
	if !gated.dcrAuthorized(c3) {
		t.Error("expected acceptance with matching bearer")
	}
	c4, _ := gin.CreateTestContext(httptest.NewRecorder())
	c4.Request = httptest.NewRequest(http.MethodPost, "/oauth/register", nil)
	c4.Request.Header.Set("Authorization", "Bearer wrong")
	if gated.dcrAuthorized(c4) {
		t.Error("expected rejection with wrong bearer")
	}
}

func TestRegistrationTokenHashStable(t *testing.T) {
	tok, hash := newRegistrationToken()
	if !strings.HasPrefix(tok, "rat_") {
		t.Errorf("expected rat_ prefix, got %q", tok)
	}
	if hashRegistrationToken(tok) != hash {
		t.Error("hash of token should match stored hash")
	}
	if hashRegistrationToken("different") == hash {
		t.Error("different token must not hash to the same value")
	}
}
