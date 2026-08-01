// Package oauth provides unit tests for OIDC Discovery functionality
package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test Discovery Document

func TestBuildDiscoveryDocument(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	// Test required fields per OpenID Connect Discovery 1.0
	t.Run("Required fields present", func(t *testing.T) {
		assert.Equal(t, issuer, doc.Issuer, "issuer must match")
		assert.NotEmpty(t, doc.AuthorizationEndpoint, "authorization_endpoint is required")
		assert.NotEmpty(t, doc.TokenEndpoint, "token_endpoint is required")
		assert.NotEmpty(t, doc.JWKSURI, "jwks_uri is required")
		assert.NotEmpty(t, doc.ResponseTypesSupported, "response_types_supported is required")
		assert.NotEmpty(t, doc.SubjectTypesSupported, "subject_types_supported is required")
		assert.NotEmpty(t, doc.IDTokenSigningAlgValuesSupported, "id_token_signing_alg_values_supported is required")
	})

	t.Run("Endpoint URLs use correct issuer", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(doc.AuthorizationEndpoint, issuer))
		assert.True(t, strings.HasPrefix(doc.TokenEndpoint, issuer))
		assert.True(t, strings.HasPrefix(doc.JWKSURI, issuer))
		assert.True(t, strings.HasPrefix(doc.UserInfoEndpoint, issuer))
	})

	t.Run("Response types include code flow", func(t *testing.T) {
		assert.Contains(t, doc.ResponseTypesSupported, "code", "code response type must be supported")
	})

	t.Run("Subject types include public", func(t *testing.T) {
		assert.Contains(t, doc.SubjectTypesSupported, "public", "public subject type must be supported")
	})

	t.Run("Signing algorithms include RS256", func(t *testing.T) {
		assert.Contains(t, doc.IDTokenSigningAlgValuesSupported, "RS256", "RS256 must be supported")
	})

	t.Run("Scopes include openid", func(t *testing.T) {
		assert.Contains(t, doc.ScopesSupported, "openid", "openid scope must be supported")
	})

	t.Run("Grant types include authorization_code", func(t *testing.T) {
		assert.Contains(t, doc.GrantTypesSupported, "authorization_code", "authorization_code grant must be supported")
	})

	t.Run("Token endpoint auth methods include client_secret_basic", func(t *testing.T) {
		assert.Contains(t, doc.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	})
}

func TestValidateDiscoveryDocument(t *testing.T) {
	tests := []struct {
		name        string
		doc         *DiscoveryDocument
		expectErr   bool
		errContains string
	}{
		{
			name: "Valid discovery document",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr: false,
		},
		{
			name: "Missing issuer",
			doc: &DiscoveryDocument{
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr:   true,
			errContains: "issuer",
		},
		{
			name: "Missing authorization_endpoint",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr:   true,
			errContains: "authorization_endpoint",
		},
		{
			name: "Missing token_endpoint",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr:   true,
			errContains: "token_endpoint",
		},
		{
			name: "Missing jwks_uri",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr:   true,
			errContains: "jwks_uri",
		},
		{
			name: "Empty response_types_supported",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr:   true,
			errContains: "response_types_supported",
		},
		{
			name: "Empty subject_types_supported",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			expectErr:   true,
			errContains: "subject_types_supported",
		},
		{
			name: "Empty id_token_signing_alg_values_supported",
			doc: &DiscoveryDocument{
				Issuer:                           "https://test.openidx.org",
				AuthorizationEndpoint:            "https://test.openidx.org/oauth/authorize",
				TokenEndpoint:                    "https://test.openidx.org/oauth/token",
				JWKSURI:                          "https://test.openidx.org/.well-known/jwks.json",
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{},
			},
			expectErr:   true,
			errContains: "id_token_signing_alg_values_supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDiscoveryDocument(tt.doc)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDiscoveryHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		expectedStatus int
		validateResp   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "GET request returns discovery document",
			method:         "GET",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

				var doc DiscoveryDocument
				err := json.Unmarshal(w.Body.Bytes(), &doc)
				require.NoError(t, err)

				// Verify required fields
				assert.NotEmpty(t, doc.Issuer)
				assert.NotEmpty(t, doc.AuthorizationEndpoint)
				assert.NotEmpty(t, doc.TokenEndpoint)
				assert.NotEmpty(t, doc.JWKSURI)
			},
		},
		{
			name:           "OPTIONS request returns 204 No Content",
			method:         "OPTIONS",
			expectedStatus: http.StatusNoContent,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))
			},
		},
		{
			name:           "HEAD request should be handled",
			method:         "HEAD",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDiscoveryHandler("https://test.openidx.org", zap.NewNop())

			router := gin.New()
			router.GET("/.well-known/openid-configuration", handler.HandleDiscovery)
			router.OPTIONS("/.well-known/openid-configuration", handler.HandleDiscovery)
			router.HEAD("/.well-known/openid-configuration", handler.HandleDiscovery)

			req := httptest.NewRequest(tt.method, "/.well-known/openid-configuration", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.validateResp != nil {
				tt.validateResp(t, w)
			}
		})
	}
}

func TestDiscoveryDocumentJSONSerialization(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	// Serialize to JSON
	data, err := json.Marshal(doc)
	require.NoError(t, err)

	// Deserialize back
	var decoded DiscoveryDocument
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify key fields are preserved
	assert.Equal(t, doc.Issuer, decoded.Issuer)
	assert.Equal(t, doc.AuthorizationEndpoint, decoded.AuthorizationEndpoint)
	assert.Equal(t, doc.TokenEndpoint, decoded.TokenEndpoint)
	assert.Equal(t, doc.JWKSURI, decoded.JWKSURI)
	assert.Equal(t, len(doc.ResponseTypesSupported), len(decoded.ResponseTypesSupported))
	assert.Equal(t, len(doc.ScopesSupported), len(decoded.ScopesSupported))
	assert.Equal(t, len(doc.ClaimsSupported), len(decoded.ClaimsSupported))
}

func TestDiscoveryDocumentComprehensiveClaims(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("Standard OIDC claims are supported", func(t *testing.T) {
		// Required OIDC claims
		requiredClaims := []string{"sub", "iss", "aud", "exp", "iat"}
		for _, claim := range requiredClaims {
			assert.Contains(t, doc.ClaimsSupported, claim, "required claim %s must be supported", claim)
		}

		// Standard profile claims
		profileClaims := []string{"name", "given_name", "family_name", "preferred_username"}
		for _, claim := range profileClaims {
			assert.Contains(t, doc.ClaimsSupported, claim, "profile claim %s should be supported", claim)
		}

		// Email claims
		assert.Contains(t, doc.ClaimsSupported, "email")
		assert.Contains(t, doc.ClaimsSupported, "email_verified")

		// Phone claims
		assert.Contains(t, doc.ClaimsSupported, "phone_number")

		// Address claim
		assert.Contains(t, doc.ClaimsSupported, "address")
	})

	t.Run("Custom OpenIDX claims are supported", func(t *testing.T) {
		assert.Contains(t, doc.ClaimsSupported, "roles", "roles claim should be supported")
		assert.Contains(t, doc.ClaimsSupported, "groups", "groups claim should be supported")
		assert.Contains(t, doc.ClaimsSupported, "sid", "session ID claim should be supported")
		assert.Contains(t, doc.ClaimsSupported, "at_hash", "access token hash should be supported")
		assert.Contains(t, doc.ClaimsSupported, "c_hash", "code hash should be supported")
	})
}

func TestDiscoveryDocumentCodeChallengeMethods(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("only S256 PKCE is advertised", func(t *testing.T) {
		assert.Contains(t, doc.CodeChallengeMethodsSupported, "S256", "S256 method must be supported")
		assert.NotContains(t, doc.CodeChallengeMethodsSupported, "plain",
			"plain PKCE must NOT be advertised (offers no code-interception protection)")
	})
}

func TestDiscoveryDocumentSessionManagement(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("End session endpoint is present", func(t *testing.T) {
		assert.NotEmpty(t, doc.EndSessionEndpoint, "end_session_endpoint should be present")
		assert.True(t, strings.Contains(doc.EndSessionEndpoint, "/logout"))
	})

	t.Run("Back-channel logout is supported", func(t *testing.T) {
		assert.True(t, doc.BackchannelLogoutSupported, "back-channel logout should be supported")
		assert.True(t, doc.BackchannelLogoutSessionSupported, "back-channel logout session should be supported")
	})
}

func TestDiscoveryDocumentTokenIntrospectionRevocation(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("Introspection endpoint is present", func(t *testing.T) {
		assert.NotEmpty(t, doc.IntrospectionEndpoint)
		assert.True(t, strings.Contains(doc.IntrospectionEndpoint, "/introspect"))
	})

	t.Run("Revocation endpoint is present", func(t *testing.T) {
		assert.NotEmpty(t, doc.RevocationEndpoint)
		assert.True(t, strings.Contains(doc.RevocationEndpoint, "/revoke"))
	})
}

func TestDiscoveryDocumentScopes(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("OIDC scopes are supported", func(t *testing.T) {
		requiredScopes := []string{"openid", "profile", "email"}
		for _, scope := range requiredScopes {
			assert.Contains(t, doc.ScopesSupported, scope, "scope %s must be supported", scope)
		}
	})

	t.Run("Offline access scope is supported", func(t *testing.T) {
		assert.Contains(t, doc.ScopesSupported, "offline_access")
	})
}

func TestDiscoveryDocumentGrantTypes(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("Required grant types are supported", func(t *testing.T) {
		requiredGrants := []string{"authorization_code", "refresh_token"}
		for _, grant := range requiredGrants {
			assert.Contains(t, doc.GrantTypesSupported, grant, "grant type %s must be supported", grant)
		}
	})

	t.Run("Client credentials is supported", func(t *testing.T) {
		assert.Contains(t, doc.GrantTypesSupported, "client_credentials")
	})
}

func TestDiscoveryDocumentResponseTypes(t *testing.T) {
	issuer := "https://test.openidx.org"
	doc := buildDiscoveryDocument(issuer)

	t.Run("Authorization code flow is supported", func(t *testing.T) {
		assert.Contains(t, doc.ResponseTypesSupported, "code")
	})

	t.Run("Unimplemented flows are not advertised", func(t *testing.T) {
		// This used to assert the opposite. Nothing implements implicit or
		// hybrid — the authorize path always issues a code — so advertising
		// them sent conforming clients down a flow that silently returned
		// something else. Discovery must describe what the server actually
		// does; if hybrid is implemented later, add it back here and in
		// buildDiscoveryDocument together.
		for _, unimplemented := range []string{"id_token", "token id_token", "code id_token", "code token", "code id_token token"} {
			assert.NotContains(t, doc.ResponseTypesSupported, unimplemented,
				"advertised %q but no handler implements it", unimplemented)
		}
	})
}
