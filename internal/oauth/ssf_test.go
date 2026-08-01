package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ssfSetupTestDB spins a throwaway Postgres for the SSF receiver DB tests.
func ssfSetupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Skipf("start container: %v", err)
		return nil, func() {}
	}
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	conn := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"
	db, err := database.NewPostgres(conn)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
		return nil, func() {}
	}
	return db, func() { db.Close(); container.Terminate(ctx) }
}

func TestBuildSETStructure(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	svc := ctx.Service

	setJWT, jti, err := svc.BuildSET("https://receiver.example.com", EventSessionRevoked, "alice@corp.com", "u-1",
		map[string]interface{}{"reason": "kill_switch"})
	if err != nil {
		t.Fatalf("BuildSET: %v", err)
	}
	if jti == "" {
		t.Fatal("expected jti")
	}
	// Verify signature with our own key + inspect the SET shape.
	parsed, err := jwt.Parse(setJWT, svc.verificationKeyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("SET should verify: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["aud"] != "https://receiver.example.com" {
		t.Errorf("aud wrong: %v", claims["aud"])
	}
	events, ok := claims["events"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected events map, got %v", claims["events"])
	}
	ev, ok := events[EventSessionRevoked].(map[string]interface{})
	if !ok {
		t.Fatalf("expected session-revoked event, got %v", events)
	}
	subj, ok := ev["subject"].(map[string]interface{})
	if !ok || subj["email"] != "alice@corp.com" {
		t.Errorf("subject wrong: %v", ev["subject"])
	}
	if ev["reason"] != "kill_switch" {
		t.Errorf("expected event claim carried, got %v", ev["reason"])
	}
	// typ header set.
	if parsed.Header["typ"] != "secevent+jwt" {
		t.Errorf("expected secevent+jwt typ, got %v", parsed.Header["typ"])
	}
}

func TestStreamWantsEvent(t *testing.T) {
	if !streamWantsEvent(nil, EventSessionRevoked) {
		t.Error("empty events should mean all")
	}
	if !streamWantsEvent([]byte(`[]`), EventSessionRevoked) {
		t.Error("empty array should mean all")
	}
	if !streamWantsEvent([]byte(`["`+EventSessionRevoked+`"]`), EventSessionRevoked) {
		t.Error("listed event should match")
	}
	if streamWantsEvent([]byte(`["`+EventCredentialChange+`"]`), EventSessionRevoked) {
		t.Error("unlisted event should not match")
	}
}

func TestExtractCAEPEvent(t *testing.T) {
	claims := jwt.MapClaims{
		"events": map[string]interface{}{
			EventSessionRevoked: map[string]interface{}{
				"subject": map[string]interface{}{"format": "email", "email": "bob@corp.com"},
				"reason":  "admin",
			},
		},
	}
	et, subj, ec := extractCAEPEvent(claims)
	if et != EventSessionRevoked {
		t.Errorf("event type wrong: %s", et)
	}
	if subj != "bob@corp.com" {
		t.Errorf("subject wrong: %s", subj)
	}
	if ec["reason"] != "admin" {
		t.Errorf("event claims not extracted: %v", ec)
	}
}

func TestValidateInboundSETRejectsUntrusted(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()
	// A SET from an unknown issuer signed by a foreign key must be rejected
	// (no receiver config = only our own issuer trusted).
	other := NewTestOIDCContext(t)
	defer other.Cleanup()
	foreign, _, _ := other.Service.BuildSET("aud", EventSessionRevoked, "x@y.com", "u1", nil)
	// other.Service.issuer == our issuer (both use default test issuer), but the
	// key differs, so signature verification fails.
	if _, err := ctx.Service.validateInboundSET(context.Background(), foreign); err == nil {
		t.Fatal("expected untrusted/foreign-signed SET to be rejected")
	}
}

// TestSSFReceiveAppliesSessionRevoked is the headline test: an inbound
// session-revoked SET for a local user revokes that user's sessions (which the
// access-proxy honors to cut the user off the Ziti overlay).
func TestSSFReceiveAppliesSessionRevoked(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()
	dbctx := context.Background()
	db.Pool.Exec(dbctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(dbctx, `
        CREATE TABLE users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email VARCHAR(255), enabled BOOLEAN DEFAULT true, org_id UUID);
        CREATE TABLE sessions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID, revoked BOOLEAN DEFAULT false, revoked_at TIMESTAMPTZ);
        CREATE TABLE refresh_tokens (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID);
        CREATE TABLE ssf_received_events (jti VARCHAR(255) PRIMARY KEY, org_id UUID, issuer TEXT, event_type TEXT, subject TEXT, outcome VARCHAR(16) NOT NULL DEFAULT 'applied', detail TEXT, received_at TIMESTAMPTZ DEFAULT NOW());`)

	orgID := "00000000-0000-0000-0000-0000000000aa"
	var userID string
	db.Pool.QueryRow(dbctx, `INSERT INTO users (email, org_id) VALUES ('victim@corp.com',$1) RETURNING id`, orgID).Scan(&userID)
	db.Pool.Exec(dbctx, `INSERT INTO sessions (user_id, org_id) VALUES ($1,$2),($1,$2)`, userID, orgID)

	// Build the receiver service on the real DB (own key = trusted issuer).
	tctx := NewTestOIDCContext(t)
	defer tctx.Cleanup()
	svc := tctx.Service
	svc.db = db

	// A session-revoked SET OpenIDX itself signed (self-issued = trusted).
	setJWT, _, err := svc.BuildSET(svc.issuer, EventSessionRevoked, "victim@corp.com", userID, nil)
	if err != nil {
		t.Fatalf("BuildSET: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/ssf/events", strings.NewReader(setJWT))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	// Attach org context so revokeAllUserSessions resolves the tenant.
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))

	svc.handleSSFReceive(c)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// Both sessions revoked.
	var revoked int
	db.Pool.QueryRow(dbctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND revoked=true`, userID).Scan(&revoked)
	if revoked != 2 {
		t.Errorf("expected 2 sessions revoked, got %d", revoked)
	}
	// Recorded for dedup with outcome applied.
	var outcome string
	if err := db.Pool.QueryRow(dbctx, `SELECT outcome FROM ssf_received_events WHERE subject='victim@corp.com'`).Scan(&outcome); err != nil {
		t.Fatalf("expected a received-event row: %v", err)
	}
	if outcome != "applied" {
		t.Errorf("expected outcome applied, got %s", outcome)
	}
}

// TestSSFStreamCRUDAndEnqueue exercises the transmitter store + fan-out.
func TestSSFStreamCRUDAndEnqueue(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()
	dbctx := context.Background()
	db.Pool.Exec(dbctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(dbctx, `
        CREATE TABLE ssf_streams (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, description VARCHAR(255), audience TEXT NOT NULL, delivery_endpoint TEXT NOT NULL, delivery_auth_enc TEXT, events_requested JSONB DEFAULT '[]', status VARCHAR(16) DEFAULT 'enabled', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
        CREATE TABLE ssf_stream_delivery (id BIGSERIAL PRIMARY KEY, org_id UUID, stream_id UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE, event_type TEXT NOT NULL, subject TEXT, set_jwt TEXT NOT NULL, state VARCHAR(16) DEFAULT 'pending', attempts INTEGER DEFAULT 0, last_error TEXT, next_attempt_at TIMESTAMPTZ DEFAULT NOW(), created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());`)

	tctx := NewTestOIDCContext(t)
	defer tctx.Cleanup()
	svc := tctx.Service
	svc.db = db

	// Stream operations are tenant-scoped: an empty org is refused rather than
	// silently matching every tenant's rows.
	const orgID = "00000000-0000-0000-0000-0000000000aa"
	const otherOrgID = "00000000-0000-0000-0000-0000000000cc"

	stream, err := svc.CreateSSFStream(dbctx, orgID, &SSFStreamInput{
		Audience: "https://rp.example.com", DeliveryEndpoint: "https://rp.example.com/ssf",
		DeliveryAuth: "shh", EventsRequested: []string{EventSessionRevoked},
	})
	if err != nil {
		t.Fatalf("CreateSSFStream: %v", err)
	}
	if stream.DeliveryEndpoint == "" {
		t.Error("expected delivery endpoint")
	}

	// An unscoped create must be refused outright.
	if _, err := svc.CreateSSFStream(dbctx, "", &SSFStreamInput{
		Audience: "https://evil.example.com", DeliveryEndpoint: "https://evil.example.com/collect",
	}); !errors.Is(err, errSSFNoOrg) {
		t.Fatalf("CreateSSFStream with no tenant: want errSSFNoOrg, got %v", err)
	}

	// Matching event -> one SET enqueued.
	n := svc.EmitCAEPEvent(dbctx, orgID, EventSessionRevoked, "alice@corp.com", "u1", nil)
	if n != 1 {
		t.Fatalf("expected 1 SET enqueued to matching stream, got %d", n)
	}
	// Non-matching event -> nothing (stream didn't request it).
	n = svc.EmitCAEPEvent(dbctx, orgID, EventTokenClaimsChange, "alice@corp.com", "u1", nil)
	if n != 0 {
		t.Errorf("expected 0 enqueued for unrequested event, got %d", n)
	}
	// Another tenant's event must never reach this org's stream.
	n = svc.EmitCAEPEvent(dbctx, otherOrgID, EventSessionRevoked, "bob@other.com", "u2", nil)
	if n != 0 {
		t.Errorf("expected 0 enqueued for a different tenant, got %d", n)
	}
	// An unscoped emit must not broadcast to every tenant.
	n = svc.EmitCAEPEvent(dbctx, "", EventSessionRevoked, "alice@corp.com", "u1", nil)
	if n != 0 {
		t.Errorf("expected 0 enqueued without a tenant, got %d", n)
	}

	// A delete scoped to another tenant must not touch this org's stream.
	if err := svc.DeleteSSFStream(dbctx, otherOrgID, stream.ID); err == nil {
		t.Error("expected cross-tenant DeleteSSFStream to fail")
	}

	var pending int
	db.Pool.QueryRow(dbctx, `SELECT COUNT(*) FROM ssf_stream_delivery WHERE state='pending'`).Scan(&pending)
	if pending != 1 {
		t.Errorf("expected 1 pending delivery, got %d", pending)
	}

	if err := svc.DeleteSSFStream(dbctx, orgID, stream.ID); err != nil {
		t.Fatalf("DeleteSSFStream: %v", err)
	}
	db.Pool.QueryRow(dbctx, `SELECT COUNT(*) FROM ssf_stream_delivery`).Scan(&pending)
	if pending != 0 {
		t.Errorf("expected delivery rows cascaded on stream delete, got %d", pending)
	}
}

func TestSSFReceiveDedup(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()
	dbctx := context.Background()
	db.Pool.Exec(dbctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(dbctx, `
        CREATE TABLE users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email VARCHAR(255), enabled BOOLEAN DEFAULT true, org_id UUID);
        CREATE TABLE sessions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID, revoked BOOLEAN DEFAULT false, revoked_at TIMESTAMPTZ);
        CREATE TABLE refresh_tokens (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID);
        CREATE TABLE ssf_received_events (jti VARCHAR(255) PRIMARY KEY, org_id UUID, issuer TEXT, event_type TEXT, subject TEXT, outcome VARCHAR(16) NOT NULL DEFAULT 'applied', detail TEXT, received_at TIMESTAMPTZ DEFAULT NOW());`)
	orgID := "00000000-0000-0000-0000-0000000000bb"
	var userID string
	db.Pool.QueryRow(dbctx, `INSERT INTO users (email, org_id) VALUES ('dup@corp.com',$1) RETURNING id`, orgID).Scan(&userID)

	tctx := NewTestOIDCContext(t)
	defer tctx.Cleanup()
	svc := tctx.Service
	svc.db = db
	setJWT, _, _ := svc.BuildSET(svc.issuer, EventSessionRevoked, "dup@corp.com", userID, nil)

	send := func() int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/ssf/events", strings.NewReader(setJWT))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
		svc.handleSSFReceive(c)
		return w.Code
	}
	if code := send(); code != http.StatusAccepted {
		t.Fatalf("first send: %d", code)
	}
	if code := send(); code != http.StatusAccepted {
		t.Fatalf("dup send should also 202, got %d", code)
	}
	var n int
	db.Pool.QueryRow(dbctx, `SELECT COUNT(*) FROM ssf_received_events WHERE subject='dup@corp.com'`).Scan(&n)
	if n != 1 {
		t.Errorf("expected exactly 1 dedup row for a re-delivered SET, got %d", n)
	}
}
