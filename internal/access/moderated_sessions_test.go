package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestModeratedSessionStateMachine proves the PAM C3 four-eyes gate end to end
// against a migrated DB: a require_moderator connection blocks the requester
// until a moderator joins, a moderator cannot be the requester (four-eyes),
// join is atomic (single claim), and end terminates the session. It drives the
// real HTTP handlers over gin test contexts carrying org + user identity.
func TestModeratedSessionStateMachine(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010"
	const requester = "00000000-0000-0000-0000-0000000000a1"
	const moderator = "00000000-0000-0000-0000-0000000000b2"

	// Seed a route + a require_moderator connection.
	var routeID, connID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url)
		VALUES ($1::uuid, 'modtest', 'https://modtest.example.com', 'ssh://h:22')
		RETURNING id::text`, org).Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_connections
		    (route_id, guacamole_connection_id, protocol, hostname, port,
		     require_approval, record_session, require_moderator)
		VALUES ($1::uuid, 'gc-1', 'ssh', 'h', 22, false, false, true)
		RETURNING id::text`, routeID).Scan(&connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	// 1. Before any moderator, the gate reports inactive.
	if ok, err := s.checkModerationActive(ctx, connID, requester); err != nil || ok {
		t.Fatalf("checkModerationActive before request = (%v,%v), want (false,nil)", ok, err)
	}

	// 2. Requester opens a moderation request.
	modID := requestModeration(t, s, org, requester, routeID)

	// 3. Still pending → gate inactive.
	if ok, _ := s.checkModerationActive(ctx, connID, requester); ok {
		t.Fatal("gate active while still pending, want inactive")
	}

	// 4. Requester cannot self-moderate (four-eyes).
	if code := joinModeration(t, s, org, requester, modID); code != http.StatusConflict {
		t.Fatalf("self-join status = %d, want 409 (four-eyes)", code)
	}

	// 5. A real moderator joins → active.
	if code := joinModeration(t, s, org, moderator, modID); code != http.StatusOK {
		t.Fatalf("moderator join status = %d, want 200", code)
	}

	// 6. Gate now active → connect would proceed.
	if ok, err := s.checkModerationActive(ctx, connID, requester); err != nil || !ok {
		t.Fatalf("checkModerationActive after join = (%v,%v), want (true,nil)", ok, err)
	}

	// 7. A second join is a no-op conflict (already claimed).
	if code := joinModeration(t, s, org, moderator, modID); code != http.StatusConflict {
		t.Fatalf("double-join status = %d, want 409", code)
	}

	// 8. End the moderation → gate inactive again.
	if code := endModeration(t, s, org, moderator, modID); code != http.StatusOK {
		t.Fatalf("end status = %d, want 200", code)
	}
	if ok, _ := s.checkModerationActive(ctx, connID, requester); ok {
		t.Fatal("gate active after end, want inactive")
	}
}

func requestModeration(t *testing.T, s *Service, org, userID, routeID string) string {
	t.Helper()
	w := driveModeration(t, s, org, userID, http.MethodPost, "/pam/moderation/request",
		`{"route_id":"`+routeID+`","reason":"test"}`, func(c *gin.Context) { s.handleRequestModeration(c) })
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("request moderation status = %d, body = %s", w.Code, w.Body.String())
	}
	var body struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.ID == "" {
		t.Fatal("no moderation id returned")
	}
	return body.ID
}

func joinModeration(t *testing.T, s *Service, org, userID, modID string) int {
	t.Helper()
	w := driveModeration(t, s, org, userID, http.MethodPost, "/pam/moderation/"+modID+"/join", "",
		func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: modID}}; s.handleJoinModeration(c) })
	return w.Code
}

func endModeration(t *testing.T, s *Service, org, userID, modID string) int {
	t.Helper()
	w := driveModeration(t, s, org, userID, http.MethodPost, "/pam/moderation/"+modID+"/end", "",
		func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: modID}}; s.handleEndModeration(c) })
	return w.Code
}

// driveModeration runs a handler over a gin test context carrying org + user_id.
func driveModeration(t *testing.T, s *Service, org, userID, method, path, body string, fn func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: org}))
	c.Request = req
	c.Set("user_id", userID)
	fn(c)
	return w
}
