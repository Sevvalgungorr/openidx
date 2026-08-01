package oauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScopeAllowedForClient pins the client_credentials scope fix.
//
// handleClientCredentialsGrant used to mint the caller-supplied `scope` into
// the access token verbatim, with no comparison against the client's
// registered scopes — so any confidential client could grant itself any scope
// it asked for (RFC 6749 §3.3 requires the authorization server to check).
func TestScopeAllowedForClient(t *testing.T) {
	client := &OAuthClient{Scopes: []string{"openid", "profile", "read:reports"}}

	tests := []struct {
		name  string
		scope string
		want  bool
	}{
		{"empty request is allowed", "", true},
		{"single registered scope", "openid", true},
		{"several registered scopes", "openid profile", true},
		{"all registered scopes", "openid profile read:reports", true},
		{"unregistered scope is refused", "admin:*", false},
		{"escalation hidden among valid scopes is refused", "openid admin:*", false},
		{"near-miss scope is refused", "read:report", false},
		{"extra spaces are tolerated", "openid  profile", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, scopeAllowedForClient(client, tc.scope))
		})
	}

	t.Run("client with no registered scopes cannot be widened", func(t *testing.T) {
		require.False(t, scopeAllowedForClient(&OAuthClient{}, "openid"))
	})

	t.Run("nil client is refused", func(t *testing.T) {
		require.False(t, scopeAllowedForClient(nil, "openid"))
	})
}

// TestAudienceClientID covers both encodings of the ID token `aud` claim, which
// is how the logout handler learns which client's registered redirect URIs may
// be used for post_logout_redirect_uri.
func TestAudienceClientID(t *testing.T) {
	require.Equal(t, "client-a", audienceClientID(map[string]interface{}{"aud": "client-a"}))
	require.Equal(t, "client-b", audienceClientID(map[string]interface{}{
		"aud": []interface{}{"client-b", "client-c"},
	}))
	require.Empty(t, audienceClientID(map[string]interface{}{}))
	require.Empty(t, audienceClientID(map[string]interface{}{"aud": 42}))
	require.Empty(t, audienceClientID(map[string]interface{}{"aud": []interface{}{}}))
}
