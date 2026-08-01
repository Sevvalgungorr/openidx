package identity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// These tests pin the MFA-bypass-code privilege-escalation fix.
//
// isIdentitySelfService treated ANY path under /mfa/ as self-service, which
// exempted it from requireAdminUnlessSelfService. The bypass-code routes live
// at /mfa/bypass-codes and are administrative — GenerateBypassCodeRequest
// carries an arbitrary target user_id — and handleGenerateBypassCode had no
// role check of its own. Together that let any authenticated user mint an
// MFA-bypass code for any account in the org, including an admin's.

func TestBypassCodeRoutesAreNotSelfService(t *testing.T) {
	const base = "/api/v1/identity"

	administrative := []string{
		base + "/mfa/bypass-codes",
		base + "/mfa/bypass-codes/some-code-id",
		base + "/mfa/bypass-codes/audit",
	}
	for _, path := range administrative {
		t.Run("admin required: "+path, func(t *testing.T) {
			require.False(t, isIdentitySelfService(path),
				"generating/listing/revoking bypass codes acts on other users and must go through the admin gate")
		})
	}

	// Redemption stays self-service: the caller verifies a code against their
	// own account, so requiring admin here would break the break-glass flow.
	t.Run("redemption stays self-service", func(t *testing.T) {
		require.True(t, isIdentitySelfService(base+"/mfa/bypass-codes/verify"))
	})

	// Ordinary MFA enrollment must keep working for regular users.
	for _, path := range []string{base + "/mfa/totp/enroll", base + "/mfa/webauthn/register"} {
		t.Run("still self-service: "+path, func(t *testing.T) {
			require.True(t, isIdentitySelfService(path))
		})
	}
}

func TestIdentityCallerIsAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	withRoles := func(roles []string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("roles", roles)
		return c
	}

	require.False(t, identityCallerIsAdmin(withRoles([]string{"user"})))
	require.False(t, identityCallerIsAdmin(withRoles(nil)))
	require.True(t, identityCallerIsAdmin(withRoles([]string{"admin"})))
	// Both spellings are accepted: the shared middleware matches "super_admin"
	// while the inline checks in handlers_advanced_mfa.go use "superadmin".
	require.True(t, identityCallerIsAdmin(withRoles([]string{"superadmin"})))
	require.True(t, identityCallerIsAdmin(withRoles([]string{"super_admin"})))
	require.True(t, identityCallerIsAdmin(withRoles([]string{"user", "admin"})))
}

// TestGenerateBypassCodeRejectsNonAdmin proves the in-handler check runs before
// anything else. The Service has a nil db on purpose: if the authorization
// check regressed, the handler would fall through to GenerateMFABypassCode and
// panic on the database instead of returning 403.
func TestGenerateBypassCodeRejectsNonAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/identity/mfa/bypass-codes",
		strings.NewReader(`{"user_id":"victim-admin","reason":"pwned"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", "attacker")
	c.Set("roles", []string{"user"})

	(&Service{}).handleGenerateBypassCode(c)

	require.Equal(t, http.StatusForbidden, w.Code,
		"a non-admin must not be able to mint an MFA bypass code for another user")
}
