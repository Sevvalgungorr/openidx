package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The SCIM filter used to be parsed, converted to SQL, logged at debug level,
// and then discarded — while ServiceProviderConfig advertised
// filter.supported = true. Every GET /scim/v2/Users?filter=... returned the
// tenant's entire user list.
//
// That is not a cosmetic gap. Okta and Entra ID issue
// `filter=userName eq "..."` before each provisioning write to decide
// create-vs-update; an unfiltered 200 tells them the user already exists, so
// the connector takes the wrong branch on every single user. These tests assert
// the filter narrows the result set for real, against a real database — the
// pure-SQL-string tests could not have caught this, because the string was
// correct and simply never used.

const scimFilterSchema = `
CREATE TABLE users (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username             VARCHAR(255) NOT NULL,
    email                VARCHAR(255) NOT NULL,
    first_name           VARCHAR(255),
    last_name            VARCHAR(255),
    enabled              BOOLEAN     NOT NULL DEFAULT true,
    email_verified       BOOLEAN     NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at        TIMESTAMPTZ,
    password_changed_at  TIMESTAMPTZ,
    password_must_change BOOLEAN     NOT NULL DEFAULT false,
    failed_login_count   INT         NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,
    locked_until         TIMESTAMPTZ,
    external_id          VARCHAR(255),
    job_title            VARCHAR(255),
    department           VARCHAR(255),
    org_id               UUID        NOT NULL
);
CREATE TABLE groups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    parent_id        UUID,
    allow_self_join  BOOLEAN NOT NULL DEFAULT false,
    require_approval BOOLEAN NOT NULL DEFAULT false,
    max_members      INT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    external_id      VARCHAR(255),
    org_id           UUID NOT NULL
);
CREATE TABLE group_memberships (
    user_id   UUID NOT NULL,
    group_id  UUID NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id    UUID NOT NULL
);`

const (
	scimOrgA = "33333333-0000-0000-0000-00000000000a"
	scimOrgB = "44444444-0000-0000-0000-00000000000b"
)

func newSCIMFilterService(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, scimFilterSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return NewService(db, nil, &config.Config{}, zap.NewNop()), db, ctx
}

// scimListUsers drives the routed handler and returns the decoded ListResponse.
func scimListUsers(t *testing.T, s *Service, ctx context.Context, org, query string) (int, map[string]interface{}) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/scim/v2/Users"+query, nil)
	c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
	s.HandleSCIMListUsers(c)

	var body map[string]interface{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &body)
	}
	return w.Code, body
}

func resourceCount(t *testing.T, body map[string]interface{}) (int, int) {
	t.Helper()
	total, _ := body["totalResults"].(float64)
	res, _ := body["Resources"].([]interface{})
	return int(total), len(res)
}

func TestSCIMListUsers_FilterIsApplied(t *testing.T) {
	s, db, ctx := newSCIMFilterService(t)

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (username, email, first_name, last_name, enabled, external_id, org_id) VALUES
		  ('alice', 'alice@example.com', 'Alice', 'Anderson', true,  'ext-alice', $1),
		  ('bob',   'bob@example.com',   'Bob',   'Brown',    true,  'ext-bob',   $1),
		  ('carol', 'carol@example.com', 'Carol', 'Clark',    false, NULL,        $1),
		  ('alice', 'alice@other.test',  'Alice', 'Other',    true,  'ext-alice', $2)`,
		scimOrgA, scimOrgB); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t.Run("no filter returns the whole tenant", func(t *testing.T) {
		code, body := scimListUsers(t, s, ctx, scimOrgA, "")
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if total, n := resourceCount(t, body); total != 3 || n != 3 {
			t.Fatalf("got total=%d n=%d, want 3/3", total, n)
		}
	})

	t.Run("userName eq returns exactly one", func(t *testing.T) {
		// The assertion the old code could never satisfy: it returned all 3.
		code, body := scimListUsers(t, s, ctx, scimOrgA, `?filter=userName+eq+%22alice%22`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %v", code, body)
		}
		total, n := resourceCount(t, body)
		if total != 1 || n != 1 {
			t.Fatalf("got total=%d n=%d, want 1/1 — filter not applied", total, n)
		}
	})

	t.Run("externalId eq returns exactly one", func(t *testing.T) {
		code, body := scimListUsers(t, s, ctx, scimOrgA, `?filter=externalId+eq+%22ext-bob%22`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %v", code, body)
		}
		if total, n := resourceCount(t, body); total != 1 || n != 1 {
			t.Fatalf("got total=%d n=%d, want 1/1", total, n)
		}
	})

	t.Run("emails eq matches the scalar email column", func(t *testing.T) {
		code, body := scimListUsers(t, s, ctx, scimOrgA, `?filter=emails+eq+%22carol@example.com%22`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %v", code, body)
		}
		if total, _ := resourceCount(t, body); total != 1 {
			t.Fatalf("got total=%d, want 1", total)
		}
	})

	t.Run("active eq false maps to enabled", func(t *testing.T) {
		code, body := scimListUsers(t, s, ctx, scimOrgA, `?filter=active+eq+false`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %v", code, body)
		}
		if total, _ := resourceCount(t, body); total != 1 {
			t.Fatalf("got total=%d, want 1 (carol)", total)
		}
	})

	t.Run("a filter cannot reach another tenant", func(t *testing.T) {
		// alice exists in both orgs; org A must still see only its own.
		code, body := scimListUsers(t, s, ctx, scimOrgA, `?filter=userName+eq+%22alice%22`)
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		res, _ := body["Resources"].([]interface{})
		if len(res) != 1 {
			t.Fatalf("got %d resources, want 1", len(res))
		}
		first, _ := res[0].(map[string]interface{})
		emails, _ := first["emails"].([]interface{})
		if len(emails) > 0 {
			e, _ := emails[0].(map[string]interface{})
			if v, _ := e["value"].(string); v != "alice@example.com" {
				t.Fatalf("cross-tenant leak: got %q", v)
			}
		}
	})

	t.Run("no match returns an empty list, not everything", func(t *testing.T) {
		code, body := scimListUsers(t, s, ctx, scimOrgA, `?filter=userName+eq+%22nobody%22`)
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if total, n := resourceCount(t, body); total != 0 || n != 0 {
			t.Fatalf("got total=%d n=%d, want 0/0", total, n)
		}
	})

	t.Run("an unsupported attribute is rejected, not ignored", func(t *testing.T) {
		// `groups` used to be mapped to a nonexistent column. Returning 400 is
		// the honest answer (RFC 7644 invalidFilter); silently returning every
		// user is not.
		code, _ := scimListUsers(t, s, ctx, scimOrgA, `?filter=groups+eq+%22admins%22`)
		if code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", code)
		}
	})

	t.Run("a malformed filter is rejected", func(t *testing.T) {
		code, _ := scimListUsers(t, s, ctx, scimOrgA, `?filter=userName+~~+%22x%22`)
		if code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", code)
		}
	})
}

func TestSCIMListGroups_FilterIsApplied(t *testing.T) {
	s, db, ctx := newSCIMFilterService(t)

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO groups (name, description, external_id, org_id) VALUES
		  ('engineering', 'Eng',   'g-eng',   $1),
		  ('finance',     'Fin',   'g-fin',   $1),
		  ('engineering', 'Other', 'g-other', $2)`,
		scimOrgA, scimOrgB); err != nil {
		t.Fatalf("seed: %v", err)
	}

	list := func(t *testing.T, org, query string) (int, map[string]interface{}) {
		t.Helper()
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/scim/v2/Groups"+query, nil)
		c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
		s.HandleSCIMListGroups(c)
		var body map[string]interface{}
		if w.Body.Len() > 0 {
			_ = json.Unmarshal(w.Body.Bytes(), &body)
		}
		return w.Code, body
	}

	t.Run("displayName eq returns exactly one, scoped to the tenant", func(t *testing.T) {
		code, body := list(t, scimOrgA, `?filter=displayName+eq+%22engineering%22`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %v", code, body)
		}
		if total, n := resourceCount(t, body); total != 1 || n != 1 {
			t.Fatalf("got total=%d n=%d, want 1/1", total, n)
		}
	})

	t.Run("no filter returns the tenant's groups", func(t *testing.T) {
		code, body := list(t, scimOrgA, "")
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if total, _ := resourceCount(t, body); total != 2 {
			t.Fatalf("got total=%d, want 2", total)
		}
	})

	t.Run("filtering on members is rejected", func(t *testing.T) {
		// Membership is a join table; it cannot be a column predicate.
		code, _ := list(t, scimOrgA, `?filter=members+eq+%22someone%22`)
		if code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", code)
		}
	})
}
