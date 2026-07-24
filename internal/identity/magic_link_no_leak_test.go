package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The routed /passwordless/magic-link handler must NOT return the one-time token
// in its JSON body (it used to, "for testing"), and must respond with the generic
// non-enumerating message. This is the token-leak landmine fix.
func TestHandleCreateMagicLink_DoesNotLeakToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	// Minimal schema the CreateMagicLink path touches.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			email VARCHAR(255) NOT NULL,
			enabled BOOLEAN DEFAULT true,
			org_id UUID NOT NULL
		);
		CREATE TABLE magic_links (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			email VARCHAR(255) NOT NULL,
			token_hash TEXT NOT NULL,
			purpose VARCHAR(50) NOT NULL,
			redirect_url TEXT,
			ip_address VARCHAR(45),
			user_agent TEXT,
			status VARCHAR(20) NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ
		);`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const org = "00000000-0000-0000-0000-0000000000aa"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (email, enabled, org_id) VALUES ('user@example.com', true, $1)`, org); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// emailService left nil → SendMagicLinkEmail logs and returns nil (no SMTP).
	s := NewService(db, nil, &config.Config{OAuthIssuer: "https://openidx.tdv.org"}, zap.NewNop())

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/passwordless/magic-link",
		strings.NewReader(`{"email":"user@example.com","purpose":"login"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	// The handler needs org context (CreateMagicLink is org-scoped).
	c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))

	s.handleCreateMagicLink(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()

	// The response must NOT carry a token or a /magic-link?token= link.
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("bad json: %v (%s)", err, body)
	}
	if _, ok := resp["link"]; ok {
		t.Errorf("response leaks a 'link' field: %s", body)
	}
	if _, ok := resp["token"]; ok {
		t.Errorf("response leaks a 'token' field: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "token=") {
		t.Errorf("response body contains a token= param: %s", body)
	}
	// And it must be the generic, non-enumerating message.
	if msg, _ := resp["message"].(string); !strings.Contains(strings.ToLower(msg), "magic link has been sent") {
		t.Errorf("unexpected message %q", msg)
	}

	// A token row WAS created (the link exists, it just isn't echoed).
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM magic_links WHERE email='user@example.com' AND status='pending'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected exactly 1 pending magic link, got %d", n)
	}
}
