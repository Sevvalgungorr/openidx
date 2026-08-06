package admin

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestPlaygroundSessionCreateAndExecute is the regression guard for QA 11.2:
// POST /developer/playground/sessions failed two ways in sequence:
//   - an empty request body (the UI's "Create Session" posts none) made
//     ShouldBindJSON return io.EOF → a confusing 400 {"error":"EOF"};
//   - once that was tolerated, the handler bound the space-separated scopes
//     string into the text[] `scopes` column → 500 "malformed array literal".
//
// This drives the handlers against a real Postgres and asserts a body-less
// create succeeds, stores scopes as an array, and the execute/authorize step
// reads the session back (array→string) and builds the authorize URL.
func TestPlaygroundSessionCreateAndExecute(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	s := &Service{db: db, logger: zap.NewNop()}

	// --- create with NO body (the failing case) ---
	cw := httptest.NewRecorder()
	cc, _ := gin.CreateTestContext(cw)
	cc.Request = httptest.NewRequest("POST", "/api/v1/developer/playground/sessions", nil)
	s.handleCreatePlaygroundSession(cc)

	if cw.Code != 201 {
		t.Fatalf("create session (empty body): status = %d, body = %s", cw.Code, cw.Body.String())
	}
	var created PlaygroundSession
	if err := json.Unmarshal(cw.Body.Bytes(), &created); err != nil {
		t.Fatalf("create session: bad json: %v", err)
	}
	if created.ID == "" || created.CodeChallenge == "" || created.State == "" {
		t.Fatalf("create session: missing PKCE fields: %+v", created)
	}
	if created.Scopes != "openid profile email" {
		t.Fatalf("create session: scopes = %q, want default 'openid profile email'", created.Scopes)
	}

	// scopes must be persisted as a text[] array, not a bare string.
	var stored []string
	if err := db.Pool.QueryRow(context.Background(),
		"SELECT scopes FROM oauth_playground_sessions WHERE id = $1", created.ID).Scan(&stored); err != nil {
		t.Fatalf("read stored scopes as array: %v (the text[] bind bug)", err)
	}
	if len(stored) != 3 || stored[0] != "openid" {
		t.Fatalf("stored scopes = %+v, want [openid profile email]", stored)
	}

	// --- execute the authorize step: reads the session back (array→string) ---
	body, _ := json.Marshal(map[string]string{"session_id": created.ID, "step": "authorize"})
	ew := httptest.NewRecorder()
	ec, _ := gin.CreateTestContext(ew)
	ec.Request = httptest.NewRequest("POST", "/api/v1/developer/playground/execute", strings.NewReader(string(body)))
	ec.Request.Header.Set("Content-Type", "application/json")
	s.handleExecutePlayground(ec)

	if ew.Code != 200 {
		t.Fatalf("execute authorize: status = %d, body = %s", ew.Code, ew.Body.String())
	}
	var exec PlaygroundExecResult
	if err := json.Unmarshal(ew.Body.Bytes(), &exec); err != nil {
		t.Fatalf("execute authorize: bad json: %v", err)
	}
	if !exec.Success {
		t.Fatalf("execute authorize: success=false, body=%s", ew.Body.String())
	}
	// The built authorize URL must carry the scopes that were read back from the
	// array column.
	if !strings.Contains(exec.URL, "scope=openid") {
		t.Fatalf("authorize URL missing scopes (array read-back broken): %s", exec.URL)
	}
}
