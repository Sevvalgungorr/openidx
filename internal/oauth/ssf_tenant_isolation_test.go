package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// These tests pin the SSF tenant-isolation fix.
//
// Before it, /ssf/streams was mounted with no auth middleware and ssfOrgID
// returned "" whenever no tenant could be resolved. That empty string was fed
// into predicates of the form `(org_id::text=$N OR $N='')`, where it
// short-circuited the tenant filter to TRUE — so an unauthenticated caller
// could list, read, create and delete EVERY tenant's SSF/CAEP streams (a
// stream carries a delivery_endpoint that receives that tenant's security
// events). Both halves are covered here: the request-side helper must fail
// closed, and the service-side operations must refuse an empty org outright.

func TestSSFRequireOrgFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop()}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// No orgctx on the request context — exactly the shape an unauthenticated
	// caller produced.
	c.Request = httptest.NewRequest(http.MethodGet, "/ssf/streams", nil)

	orgID, ok := s.ssfRequireOrg(c)
	require.False(t, ok, "unresolved tenant must not be treated as authorized")
	require.Empty(t, orgID)
	require.Equal(t, http.StatusForbidden, w.Code,
		"an unscoped SSF stream-management request must be refused, not silently widened to every tenant")
}

// TestSSFStreamOpsRejectEmptyOrg asserts the service layer refuses an empty
// org before it ever reaches SQL. The Service here has a nil db on purpose: if
// any of these guards regressed, the call would fall through to the database
// and panic rather than return, so a passing test proves the guard runs first.
func TestSSFStreamOpsRejectEmptyOrg(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	ctx := context.Background()

	t.Run("get", func(t *testing.T) {
		_, err := s.GetSSFStream(ctx, "", "stream-1")
		require.ErrorIs(t, err, errSSFNoOrg)
	})

	t.Run("list", func(t *testing.T) {
		_, err := s.ListSSFStreams(ctx, "")
		require.ErrorIs(t, err, errSSFNoOrg)
	})

	t.Run("delete", func(t *testing.T) {
		err := s.DeleteSSFStream(ctx, "", "stream-1")
		require.ErrorIs(t, err, errSSFNoOrg)
	})

	t.Run("create", func(t *testing.T) {
		_, err := s.CreateSSFStream(ctx, "", &SSFStreamInput{
			Audience:         "https://rp.example.com",
			DeliveryEndpoint: "https://attacker.example.com/collect",
		})
		require.ErrorIs(t, err, errSSFNoOrg,
			"creating a stream without a tenant would let an unscoped caller register an exfiltration endpoint")
	})
}
