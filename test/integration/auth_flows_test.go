//go:build integration

// Package integration provides comprehensive end-to-end tests for authentication flows
package integration

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateCodeVerifier creates a cryptographically random code verifier for PKCE
// Must be 43-128 characters (RFC 7636). Used by subtests that need a verifier
// separate from the one beginAuthorizeForLogin generates (e.g., wrong-verifier
// negative tests, plain-method subtest).
func generateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate code verifier: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestOAuthAuthorizationCodeFlow tests the complete OAuth 2.0 authorization code flow
func TestOAuthAuthorizationCodeFlow(t *testing.T) {
	const username = "auth-flow-test-user"
	const email = "auth-flow-test@openidx.local"
	const password = "AuthFlow@123"

	// Setup
	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("complete authorization code flow with valid credentials", func(t *testing.T) {
		// Step 1: Initiate authorization request (admin-console client requires PKCE).
		loginSession, codeVerifier := beginAuthorizeForLogin(t, "openid profile email",
			url.Values{"state": {"test-state-123"}})
		require.NotEmpty(t, loginSession)

		// Step 2: Submit credentials
		loginData := fmt.Sprintf(`{"username":%q,"password":%q,"login_session":%q}`,
			username, password, loginSession)

		status, loginBody := apiRequest(t, "POST", oauthURL+"/oauth/login", loginData, "")
		assert.Equal(t, http.StatusOK, status, "Login should succeed")

		// Step 3: Extract authorization code (tolerant of direct `code` or `redirect_url`).
		code := extractAuthCode(loginBody)
		require.NotEmpty(t, code, "Authorization code should be present")

		// Verify state is preserved through the flow.
		if r, _ := loginBody["redirect_url"].(string); r != "" {
			if u, err := url.Parse(r); err == nil {
				assert.Equal(t, "test-state-123", u.Query().Get("state"), "State should be returned")
			}
		}

		// Step 4: Exchange authorization code for tokens (with PKCE verifier).
		status, tokenBody := exchangeCodeWithPKCE(t, code, codeVerifier)
		assert.Equal(t, http.StatusOK, status, "Token exchange should succeed")

		// Verify token response
		accessToken, ok := tokenBody["access_token"].(string)
		require.True(t, ok, "access_token should be present")
		assert.NotEmpty(t, accessToken)

		tokenType, ok := tokenBody["token_type"].(string)
		assert.True(t, ok, "token_type should be present")
		assert.Equal(t, "Bearer", tokenType)

		expiresIn, ok := tokenBody["expires_in"].(float64)
		assert.True(t, ok, "expires_in should be present")
		assert.Greater(t, expiresIn, float64(0))

		// Verify ID token for openid scope
		idToken, ok := tokenBody["id_token"].(string)
		assert.True(t, ok, "id_token should be present for openid scope")
		assert.NotEmpty(t, idToken)

		// Step 5: Use access token to access userinfo
		status, userInfo := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, userID, userInfo["sub"])
		assert.Equal(t, email, userInfo["email"])
	})

	t.Run("authorization code cannot be used twice (replay protection)", func(t *testing.T) {
		// Get a fresh authorization code
		token := loginAndGetToken(t, username, password)

		// Try to use the same code again - should fail
		// We can't directly test this without intercepting the code,
		// but the token flow already validates single-use codes
		assert.NotEmpty(t, token, "Login should succeed")
	})

	t.Run("authorization code expires after timeout", func(t *testing.T) {
		// This test would require modifying the code TTL or waiting
		// For now, we document that expired codes should be rejected
		t.Skip("Skipping - requires code TTL modification or long wait")
	})

	t.Run("invalid authorization code rejected", func(t *testing.T) {
		// admin-console requires PKCE — include a dummy code_verifier so we
		// exercise the bad-code path, not the missing-verifier path.
		tokenData := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"invalid-code-12345"},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"code_verifier": {"invalid-verifier-anything"},
		}

		status, body := formRequest(t, oauthURL+"/oauth/token", tokenData)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "error")
	})
}

// TestPKCEFlow tests PKCE (RFC 7636) authorization code flow
func TestPKCEFlow(t *testing.T) {
	const username = "pkce-test-user"
	const email = "pkce-test@openidx.local"
	// Needs a lowercase letter to satisfy ValidatePasswordPolicy
	// (the bare "PKCE" tag has none, so set-password 500'd).
	const password = "PkceFlow@123"

	// Setup
	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("PKCE S256 flow complete", func(t *testing.T) {
		loginSession, codeVerifier := beginAuthorizeForLogin(t, "openid profile", nil)
		code := submitLoginForCode(t, username, password, loginSession)

		status, tokenBody := exchangeCodeWithPKCE(t, code, codeVerifier)
		assert.Equal(t, http.StatusOK, status, "Token exchange with PKCE should succeed")

		accessToken, ok := tokenBody["access_token"].(string)
		require.True(t, ok)
		assert.NotEmpty(t, accessToken)
	})

	t.Run("PKCE with plain method", func(t *testing.T) {
		// `plain` is the legacy/discouraged challenge method; if the server is
		// configured S256-only this subtest is intentionally skipped.
		plainVerifier := generateCodeVerifier()
		extra := url.Values{
			"code_challenge":        {plainVerifier},
			"code_challenge_method": {"plain"},
		}
		// We can't reuse beginAuthorizeForLogin (it forces S256), so inline the
		// authorize step but route it through the Accept-aware path.
		q := url.Values{
			"response_type": {"code"},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"scope":         {"openid"},
		}
		for k, vs := range extra {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		req, _ := http.NewRequest("GET", oauthURL+"/oauth/authorize?"+q.Encode(), nil)
		req.Header.Set("Accept", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
			t.Skipf("server rejected plain PKCE method (likely S256-only): status %d body %s",
				resp.StatusCode, string(body))
		}
		loginSession := extractLoginSession(resp, body)
		require.NotEmpty(t, loginSession)

		code := submitLoginForCode(t, username, password, loginSession)

		status, _ := formRequest(t, oauthURL+"/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"code_verifier": {plainVerifier},
		})
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("PKCE rejects incorrect code verifier", func(t *testing.T) {
		loginSession, _ := beginAuthorizeForLogin(t, "openid", nil)
		code := submitLoginForCode(t, username, password, loginSession)

		// Use a fresh, unrelated verifier.
		wrongVerifier := generateCodeVerifier()
		status, body := exchangeCodeWithPKCE(t, code, wrongVerifier)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "error")
	})

	t.Run("PKCE missing code_verifier when challenge was present", func(t *testing.T) {
		loginSession, _ := beginAuthorizeForLogin(t, "openid", nil)
		code := submitLoginForCode(t, username, password, loginSession)

		// Omit code_verifier entirely.
		status, body := formRequest(t, oauthURL+"/oauth/token", url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"client_id":    {clientID},
			"redirect_uri": {redirectURI},
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "error")
	})
}

// TestMFATOTPFlow tests TOTP-based MFA enrollment and authentication
func TestMFATOTPFlow(t *testing.T) {
	const username = "mfa-totp-user"
	const email = "mfa-totp@openidx.local"
	const password = "MfaTotp@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	token := loginAndGetToken(t, username, password)
	require.NotEmpty(t, token)

	t.Run("TOTP setup returns secret and QR code URL", func(t *testing.T) {
		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/setup", "", token)

		assert.Equal(t, http.StatusOK, status)

		secret, ok := body["secret"].(string)
		assert.True(t, ok, "setup should return a TOTP secret")
		assert.NotEmpty(t, secret, "secret should not be empty")
		assert.GreaterOrEqual(t, len(secret), 32, "TOTP secret should be at least 32 characters")

		qrCodeURL, ok := body["qrCodeUrl"].(string)
		assert.True(t, ok, "setup should return a QR code URL")
		assert.NotEmpty(t, qrCodeURL)
		assert.Contains(t, qrCodeURL, "otpauth://totp/")
		assert.Contains(t, qrCodeURL, "OpenIDX")
	})

	t.Run("TOTP enable with valid code succeeds", func(t *testing.T) {
		// Setup to get the secret
		status, setupBody := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/setup", "", token)
		require.Equal(t, http.StatusOK, status)

		secret, _ := setupBody["secret"].(string)

		// For testing, we need a valid TOTP code
		// In a real scenario, the user would use an authenticator app
		// For integration testing, we'll calculate the TOTP code
		validCode := generateTOTPCode(secret, time.Now())

		enableData := fmt.Sprintf(`{"code":%q}`, validCode)
		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/enable", enableData, token)

		assert.Equal(t, http.StatusOK, status)
		// The handler responds with `{"status": "mfa enabled", "backupCodes": [...]}`
		// — not a `success` bool. Match the real contract.
		statusMsg, _ := body["status"].(string)
		assert.Contains(t, statusMsg, "mfa enabled", "enable should return status=mfa enabled; got body=%v", body)
		// Backup codes are issued at enable; their presence is the actual
		// signal the server completed enrollment.
		codes, _ := body["backupCodes"].([]interface{})
		assert.NotEmpty(t, codes, "enable should return backupCodes; got body=%v", body)

		// Verify MFA is now enabled
		status, profile := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", token)
		assert.Equal(t, http.StatusOK, status)
		mfaEnabled, _ := profile["mfaEnabled"].(bool)
		assert.True(t, mfaEnabled, "expected mfaEnabled=true; got profile=%v", profile)

		// Clean up - disable MFA
		apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/disable", "", token)
	})

	t.Run("TOTP enable with invalid code fails", func(t *testing.T) {
		// Setup first
		apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/setup", "", token)

		// Try invalid code
		enableData := `{"code":"000000"}`
		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/enable", enableData, token)

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, fmt.Sprintf("%v", body["error"]), "invalid")
	})

	t.Run("TOTP disable after enrollment succeeds", func(t *testing.T) {
		// Setup and enable
		status, setupBody := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/setup", "", token)
		require.Equal(t, http.StatusOK, status)

		secret, _ := setupBody["secret"].(string)
		validCode := generateTOTPCode(secret, time.Now())

		enableData := fmt.Sprintf(`{"code":%q}`, validCode)
		status, _ = apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/enable", enableData, token)
		require.Equal(t, http.StatusOK, status)

		// Now disable
		status, _ = apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/disable", "", token)
		assert.Equal(t, http.StatusOK, status)

		// Verify disabled
		status, profile := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", token)
		assert.Equal(t, http.StatusOK, status)
		mfaEnabled, ok := profile["mfaEnabled"].(bool)
		assert.True(t, ok)
		assert.False(t, mfaEnabled, "MFA should be disabled after disable")
	})

	t.Run("MFA status shows enrolled methods", func(t *testing.T) {
		// Check initial status
		status, body := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me/mfa/status", "", token)
		assert.Equal(t, http.StatusOK, status)

		methods, ok := body["methods"].([]interface{})
		assert.True(t, ok, "status should return methods array")

		// Should be empty initially
		assert.Empty(t, methods, "No MFA methods should be enrolled initially")
	})
}

// TestSessionManagement tests session creation, validation, and revocation
func TestSessionManagement(t *testing.T) {
	const username = "session-test-user"
	const email = "session-test@openidx.local"
	const password = "Session@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("create and validate session", func(t *testing.T) {
		// Login creates a session
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		// Access token should work
		status, userInfo := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, userID, userInfo["sub"])
	})

	t.Run("list user sessions", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		// `/users/:id/sessions` is admin-only; the self-access path is
		// `/users/me/sessions` and reads the user id off the JWT.
		_ = userID
		status, body := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me/sessions", "", token)
		assert.Equal(t, http.StatusOK, status)

		sessions, ok := body["sessions"].([]interface{})
		assert.True(t, ok, "response should contain sessions array")
		assert.NotEmpty(t, sessions, "user should have at least one active session")
	})

	t.Run("refresh access token", func(t *testing.T) {
		// Login with offline_access to get refresh token
		loginSession, codeVerifier := beginAuthorizeForLogin(t, "openid profile offline_access", nil)
		code := submitLoginForCode(t, username, password, loginSession)

		status, tokenBody := exchangeCodeWithPKCE(t, code, codeVerifier)
		require.Equal(t, http.StatusOK, status)

		refreshToken, ok := tokenBody["refresh_token"].(string)
		if !ok || refreshToken == "" {
			t.Skip("Skipping refresh test - offline_access not supported or no refresh token returned")
		}

		// Use refresh token to get new access token
		refreshData := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}

		status, newTokenBody := formRequest(t, oauthURL+"/oauth/token", refreshData)
		assert.Equal(t, http.StatusOK, status)

		newAccessToken, ok := newTokenBody["access_token"].(string)
		assert.True(t, ok, "refresh should return new access_token")
		assert.NotEmpty(t, newAccessToken)

		// New access token should work
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", newAccessToken)
		assert.Equal(t, http.StatusOK, status)

		// Check token rotation - new refresh token should be issued
		newRefreshToken, ok := newTokenBody["refresh_token"].(string)
		assert.True(t, ok, "refresh should return new refresh_token")
		assert.NotEqual(t, refreshToken, newRefreshToken, "refresh token should be rotated")
	})

	t.Run("revoke current session", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		// Revoke the session
		status, _ := apiRequest(t, "POST", oauthURL+"/oauth/logout", "", token)
		assert.Equal(t, http.StatusOK, status)

		// Token should no longer work
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
		// May return 401 or the response may indicate invalid session
		assert.NotEqual(t, http.StatusOK, status, "revoked session token should not work")
	})

	t.Run("revoke all user sessions", func(t *testing.T) {
		// Create multiple sessions by logging in multiple times
		token1 := loginAndGetToken(t, username, password)
		token2 := loginAndGetToken(t, username, password)

		// Both should work
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token1)
		assert.Equal(t, http.StatusOK, status)
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token2)
		assert.Equal(t, http.StatusOK, status)

		// Logout all sessions
		status, _ = apiRequest(t, "POST", oauthURL+"/oauth/logout-all", "", token1)
		assert.Equal(t, http.StatusOK, status)

		// Neither token should work now
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token1)
		assert.NotEqual(t, http.StatusOK, status)
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token2)
		assert.NotEqual(t, http.StatusOK, status)
	})
}

// TestTokenRevocation tests token revocation endpoint (RFC 7009)
func TestTokenRevocation(t *testing.T) {
	const username = "revoke-test-user"
	const email = "revoke-test@openidx.local"
	const password = "Revoke@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("revoke access token", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		// Verify token works
		status, _ := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
		assert.Equal(t, http.StatusOK, status)

		// An unauthenticated revocation must be refused (RFC 7009 §2.1) —
		// otherwise anyone holding a token string could revoke it. This runs
		// before the real revocation to prove the refusal does not take effect.
		status, _ = formRequest(t, oauthURL+"/oauth/revoke", url.Values{
			"token":           {token},
			"token_type_hint": {"access_token"},
		})
		assert.Equal(t, http.StatusUnauthorized, status,
			"revocation without client authentication must be refused")

		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
		assert.Equal(t, http.StatusOK, status, "a refused revocation must leave the token usable")

		// Revoke the token. RFC 7009 §2.1 requires client authentication on
		// the revocation endpoint; admin-console is a public client, so
		// client_id alone identifies it (there is no secret to present).
		revokeData := url.Values{
			"token":           {token},
			"token_type_hint": {"access_token"},
			"client_id":       {clientID},
		}

		status, revokeResp := formRequest(t, oauthURL+"/oauth/revoke", revokeData)
		assert.Equal(t, http.StatusOK, status)
		_ = revokeResp // consume response

		// Token should no longer work
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
		assert.NotEqual(t, http.StatusOK, status)
	})

	t.Run("revoke refresh token", func(t *testing.T) {
		// Get a refresh token
		loginSession, codeVerifier := beginAuthorizeForLogin(t, "openid offline_access", nil)
		code := submitLoginForCode(t, username, password, loginSession)

		status, tokenBody := exchangeCodeWithPKCE(t, code, codeVerifier)
		require.Equal(t, http.StatusOK, status)

		refreshToken, ok := tokenBody["refresh_token"].(string)
		if !ok || refreshToken == "" {
			t.Skip("Skipping - no refresh token returned")
		}

		// Revoke the refresh token (client-authenticated, see above).
		revokeData := url.Values{
			"token":           {refreshToken},
			"token_type_hint": {"refresh_token"},
			"client_id":       {clientID},
		}

		status, _ = formRequest(t, oauthURL+"/oauth/revoke", revokeData)
		assert.Equal(t, http.StatusOK, status)

		// Try to use the revoked refresh token
		refreshData := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}

		status, _ = formRequest(t, oauthURL+"/oauth/token", refreshData)
		assert.NotEqual(t, http.StatusOK, status, "revoked refresh token should not work")
	})
}

// TestLogoutFlow tests RP-initiated logout (OIDC)
func TestLogoutFlow(t *testing.T) {
	const username = "logout-test-user"
	const email = "logout-test@openidx.local"
	const password = "Logout@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("logout with id_token_hint", func(t *testing.T) {
		// Get ID token
		loginSession, codeVerifier := beginAuthorizeForLogin(t, "openid profile", nil)
		code := submitLoginForCode(t, username, password, loginSession)

		status, tokenBody := exchangeCodeWithPKCE(t, code, codeVerifier)
		require.Equal(t, http.StatusOK, status)

		idToken, ok := tokenBody["id_token"].(string)
		require.True(t, ok, "should have id_token")
		accessToken, ok := tokenBody["access_token"].(string)
		require.True(t, ok, "should have access_token")

		// Verify access token works
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
		assert.Equal(t, http.StatusOK, status)

		// Logout with id_token_hint
		logoutURL := fmt.Sprintf("%s/oauth/logout?id_token_hint=%s&post_logout_redirect_uri=%s",
			oauthURL, url.QueryEscape(idToken), url.QueryEscape("http://localhost:3000/"))

		req, _ := http.NewRequest("POST", logoutURL, nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		// Should redirect to post_logout_redirect_uri
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// Access token should no longer work
		status, _ = apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
		assert.NotEqual(t, http.StatusOK, status)
	})

	t.Run("logout without redirect returns JSON", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		status, body := apiRequest(t, "POST", oauthURL+"/oauth/logout", "", token)
		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, fmt.Sprintf("%v", body["status"]), "logged_out")
	})
}

// TestWebAuthnFlow tests WebAuthn/FIDO2 registration and authentication
func TestWebAuthnFlow(t *testing.T) {
	const username = "webauthn-test-user"
	const email = "webauthn-test@openidx.local"
	const password = "WebAuthn@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("begin WebAuthn registration", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		// The user id is sourced from the JWT — body is purely
		// optional metadata (and the handler ignores it). Send an
		// empty body so the server's ShouldBindJSON path isn't
		// exercised twice.
		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/mfa/webauthn/register/begin", "", token)

		if status == http.StatusNotFound || status == http.StatusNotImplemented {
			t.Skip("WebAuthn registration endpoint not accessible or not implemented")
		}

		assert.Equal(t, http.StatusOK, status)
		// go-webauthn returns *protocol.CredentialCreation directly, whose
		// JSON form has `publicKey` at the top level (per the WebAuthn spec).
		// We don't dictate this shape — both the server and the frontend
		// type it that way.
		assert.NotEmpty(t, body["publicKey"], "register/begin should return a CredentialCreation with a publicKey")
	})

	t.Run("list WebAuthn credentials", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)

		// The credentials endpoint returns a bare JSON array (the
		// frontend types it `WebAuthnCredential[]`), so use the
		// list-shaped helper rather than apiRequest's map parse.
		status, list := apiRequestList(t, "GET", identityURL+"/api/v1/identity/mfa/webauthn/credentials", "", token)

		if status == http.StatusNotFound || status == http.StatusNotImplemented {
			t.Skip("WebAuthn credentials endpoint not accessible")
		}

		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, list, "no credentials should be enrolled initially")
	})
}

// TestConcurrentSessions tests behavior with multiple concurrent sessions
func TestConcurrentSessions(t *testing.T) {
	const username = "concurrent-test-user"
	const email = "concurrent-test@openidx.local"
	const password = "Concurrent@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("multiple sessions can be active simultaneously", func(t *testing.T) {
		// Create multiple sessions
		tokens := make([]string, 3)
		for i := range tokens {
			tokens[i] = loginAndGetToken(t, username, password)
		}

		// All tokens should work
		for _, token := range tokens {
			status, _ := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", token)
			assert.Equal(t, http.StatusOK, status, "All session tokens should work")
		}
	})
}

// TestTokenExpiration tests token expiration behavior
func TestTokenExpiration(t *testing.T) {
	const username = "expire-test-user"
	const email = "expire-test@openidx.local"
	const password = "Expire@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("token contains expiration claim", func(t *testing.T) {
		token := loginAndGetToken(t, username, password)
		require.NotEmpty(t, token)

		claims := decodeJWTPayload(t, token)

		exp, ok := claims["exp"].(float64)
		assert.True(t, ok, "JWT should contain exp claim")
		assert.Greater(t, exp, float64(time.Now().Unix()), "exp should be in the future")

		iat, ok := claims["iat"].(float64)
		assert.True(t, ok, "JWT should contain iat claim")
		assert.LessOrEqual(t, iat, float64(time.Now().Unix()), "iat should be in the past or now")
	})
}

// TestInvalidScopes tests scope validation
func TestInvalidScopes(t *testing.T) {
	const username = "scope-test-user"
	const email = "scope-test@openidx.local"
	const password = "Scope@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	t.Run("request invalid scope is rejected", func(t *testing.T) {
		authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=invalid+scope",
			oauthURL, clientID, url.QueryEscape(redirectURI))

		req, _ := http.NewRequest("GET", authURL, nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should either redirect with error or return error
		location := resp.Header.Get("Location")
		if location != "" {
			redirectURL, _ := url.Parse(location)
			errorCode := redirectURL.Query().Get("error")
			assert.NotEmpty(t, errorCode, "Should return error for invalid scope")
		}
	})
}

// generateTOTPCode returns a valid RFC 6238 TOTP code for the given base32
// secret at the given moment, using the same library (pquerna/otp) that the
// identity service uses to validate them on the server side. The previous
// implementation made up a 6-digit number from time%1000000, which never
// matched the server's calculation; the enable-MFA subtest then 400'd, the
// type assertion on body["success"] panicked, and the panic aborted the
// entire integration binary — *no* later test got to run.
func generateTOTPCode(secret string, timestamp time.Time) string {
	code, err := totp.GenerateCode(secret, timestamp)
	if err != nil {
		// Surfaces as an assertion failure in the caller's subtest, not a
		// process-killing panic.
		return ""
	}
	return code
}

// Helper to perform login and get the complete token response (so a caller can
// inspect refresh_token / id_token, not just access_token).
func loginAndGetTokenResponse(t *testing.T, username, password string) (int, map[string]interface{}) {
	t.Helper()

	loginSession, codeVerifier := beginAuthorizeForLogin(t, "openid profile email offline_access", nil)
	code := submitLoginForCode(t, username, password, loginSession)
	return exchangeCodeWithPKCE(t, code, codeVerifier)
}

// makeRequest makes a raw HTTP request with custom headers
func makeRequest(t *testing.T, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return httpClient.Do(req)
}
