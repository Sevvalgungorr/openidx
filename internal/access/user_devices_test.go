package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// deviceSchema is the minimal shape of the tables the device correlation and
// revoke touch — known_devices (IAM), enrolled_agents (Ziti, with the v80
// known_device_id link), and agent_posture_results.
var deviceSchema = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY, org_id UUID NOT NULL, username VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true)`,
	`CREATE TABLE IF NOT EXISTS known_devices (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID,
		fingerprint VARCHAR(128), name VARCHAR(255), device_type VARCHAR(50),
		ip_address VARCHAR(45), user_agent TEXT, trusted BOOLEAN DEFAULT false,
		last_seen_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE(user_id, fingerprint))`,
	`CREATE TABLE IF NOT EXISTS enrolled_agents (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), agent_id VARCHAR(64) UNIQUE,
		ziti_identity_id VARCHAR(255), status VARCHAR(20) DEFAULT 'active',
		platform VARCHAR(32), management_mode VARCHAR(32),
		compliance_status VARCHAR(20) DEFAULT 'unknown', compliance_score FLOAT DEFAULT 0,
		last_seen_at TIMESTAMPTZ, enrolled_at TIMESTAMPTZ DEFAULT NOW(),
		enrolled_by_user_id UUID, known_device_id UUID)`,
	`CREATE TABLE IF NOT EXISTS agent_posture_results (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), agent_id VARCHAR(64),
		check_type VARCHAR(64), status VARCHAR(10), severity VARCHAR(10),
		reported_at TIMESTAMPTZ DEFAULT NOW())`,
}

const (
	devOrg  = "00000000-0000-0000-0000-0000000000d0"
	devUser = "11111111-0000-0000-0000-0000000000d0"
)

func TestUserDeviceCorrelation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	for _, stmt := range deviceSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const (
		linkedKD = "22222222-0000-0000-0000-0000000000d1"
		iamKD    = "22222222-0000-0000-0000-0000000000d2"
	)
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		// A device seen by BOTH pillars: known_device linked to an agent.
		`INSERT INTO known_devices (id, user_id, org_id, fingerprint, name, device_type, trusted) VALUES ('` + linkedKD + `','` + devUser + `','` + devOrg + `','agent:device-1','Dana Laptop','agent',true)`,
		`INSERT INTO enrolled_agents (agent_id, ziti_identity_id, status, platform, management_mode, compliance_status, compliance_score, enrolled_by_user_id, known_device_id) VALUES ('agent-linked','zid-linked','active','linux','device_owner','non_compliant',55,'` + devUser + `','` + linkedKD + `')`,
		// A browser device seen by IAM only (no agent).
		`INSERT INTO known_devices (id, user_id, org_id, fingerprint, name, device_type, trusted) VALUES ('` + iamKD + `','` + devUser + `','` + devOrg + `','browserhash','Dana Browser','desktop',false)`,
		// An agent with no linked known_device (token-enrolled / legacy).
		`INSERT INTO enrolled_agents (agent_id, ziti_identity_id, status, platform, compliance_status, compliance_score, enrolled_by_user_id, known_device_id) VALUES ('agent-ziti','zid-ziti','active','android','compliant',95,'` + devUser + `',NULL)`,
		// Posture for the linked agent: one failing check.
		`INSERT INTO agent_posture_results (agent_id, check_type, status, severity) VALUES ('agent-linked','disk_encryption','fail','high')`,
		`INSERT INTO agent_posture_results (agent_id, check_type, status, severity) VALUES ('agent-linked','os_version','pass','low')`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}

	s := &Service{db: db, logger: zap.NewNop()}
	devices, err := s.collectUserDevices(ctx, devOrg, devUser)
	if err != nil {
		t.Fatalf("collectUserDevices: %v", err)
	}
	if len(devices) != 3 {
		t.Fatalf("want 3 device entries, got %d: %+v", len(devices), devices)
	}

	var linked, iamOnly, zitiOnly *UserDeviceEntry
	for i := range devices {
		switch devices[i].Source {
		case "linked":
			linked = &devices[i]
		case "iam":
			iamOnly = &devices[i]
		case "ziti":
			zitiOnly = &devices[i]
		}
	}
	if linked == nil || iamOnly == nil || zitiOnly == nil {
		t.Fatalf("missing a source category: %+v", devices)
	}

	// Linked device: has both IAM (trusted) and Ziti (non-compliant + posture).
	if linked.IAM == nil || !linked.IAM.Trusted || linked.IAM.Name != "Dana Laptop" {
		t.Errorf("linked IAM side wrong: %+v", linked.IAM)
	}
	if linked.Ziti == nil || linked.Ziti.AgentID != "agent-linked" || linked.Ziti.ComplianceStatus != "non_compliant" {
		t.Errorf("linked Ziti side wrong: %+v", linked.Ziti)
	}
	if len(linked.Ziti.Posture) != 2 {
		t.Errorf("want 2 posture rows on linked agent, got %+v", linked.Ziti.Posture)
	}

	// IAM-only device: no Ziti side.
	if iamOnly.IAM == nil || iamOnly.Ziti != nil {
		t.Errorf("iam-only device wrong: %+v", iamOnly)
	}
	// Ziti-only device: no IAM side, compliant.
	if zitiOnly.Ziti == nil || zitiOnly.IAM != nil || zitiOnly.Ziti.ComplianceStatus != "compliant" {
		t.Errorf("ziti-only device wrong: %+v", zitiOnly)
	}
}

// TestAgentEnroll_LinksKnownDevice pins the registry-convergence seam: a
// user-bound (OAuth) enrollment must mirror the agent's device into
// known_devices and link the two via enrolled_agents.known_device_id, so IAM
// device trust and Ziti device compliance describe the same physical machine.
func TestAgentEnroll_LinksKnownDevice(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	for _, stmt := range deviceSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'dana','dana@x.io')`, devUser, devOrg); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// The agent row exists (issueAgentCredentials wrote it); linking is the step
	// under test.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO enrolled_agents (agent_id, ziti_identity_id, status, enrolled_by_user_id) VALUES ('agent-oauth','zid-o','active',$1)`, devUser); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	gin.SetMode(gin.TestMode)
	h := NewAgentAPIHandler(zap.NewNop(), db, nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/agent/enroll/oauth", nil).WithContext(ctx)

	h.linkAgentToKnownDevice(c.Request.Context(), "", "agent-oauth", "device-1", devUser, devOrg, enrollRequest{Hostname: "dana-laptop", Platform: "linux"}, false)

	// A known_devices row was created with the namespaced fingerprint and the
	// agent row now points at it.
	var kdID, fingerprint, deviceType string
	if err := db.Pool.QueryRow(ctx,
		`SELECT id, fingerprint, device_type FROM known_devices WHERE user_id=$1 AND fingerprint='agent:device-1'`, devUser).
		Scan(&kdID, &fingerprint, &deviceType); err != nil {
		t.Fatalf("known_devices row not created: %v", err)
	}
	if deviceType != "agent" {
		t.Errorf("device_type = %q, want agent", deviceType)
	}
	var linkedID *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT known_device_id::text FROM enrolled_agents WHERE agent_id='agent-oauth'`).Scan(&linkedID); err != nil {
		t.Fatalf("read agent link: %v", err)
	}
	if linkedID == nil || *linkedID != kdID {
		t.Errorf("agent not linked to known device: link=%v want=%s", linkedID, kdID)
	}

	// Re-enrolling the same device_id is idempotent (ON CONFLICT heals, no dup).
	h.linkAgentToKnownDevice(c.Request.Context(), "", "agent-oauth", "device-1", devUser, devOrg, enrollRequest{Hostname: "dana-laptop", Platform: "linux"}, false)
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices WHERE user_id=$1 AND fingerprint='agent:device-1'`, devUser).Scan(&n); err != nil || n != 1 {
		t.Errorf("re-link created a duplicate known_devices row: count=%d (err %v)", n, err)
	}
}

func TestDeviceRevoke_CrossPillar(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	for _, stmt := range deviceSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const kd = "22222222-0000-0000-0000-0000000000d3"
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		`INSERT INTO known_devices (id, user_id, org_id, fingerprint, name, trusted) VALUES ('` + kd + `','` + devUser + `','` + devOrg + `','agent:device-9','Dana Laptop',true)`,
		`INSERT INTO enrolled_agents (agent_id, ziti_identity_id, status, enrolled_by_user_id, known_device_id) VALUES ('agent-x','zid-x','active','` + devUser + `','` + kd + `')`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// No ZitiManager wired: controller-offline path. The DB-side severance
	// (agent revoked + device untrusted) must still happen; the identity delete
	// is deferred with a warning (never falsely reported as done).
	s := &Service{db: db, logger: zap.NewNop()}
	res := s.executeDeviceRevoke(ctx, devOrg, "agent-x", "zid-x", kd)

	if !res.AgentRevoked {
		t.Error("agent not marked revoked")
	}
	if !res.KnownDeviceUntrusted {
		t.Error("linked known device not untrusted")
	}
	if res.ZitiIdentityDeleted {
		t.Error("ziti identity must NOT be reported deleted when the controller is offline")
	}
	if res.ZitiControllerOnline {
		t.Error("controller must be reported offline (no manager wired)")
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning about the deferred identity delete")
	}

	var status string
	var trusted bool
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM enrolled_agents WHERE agent_id='agent-x'`).Scan(&status); err != nil || status != "revoked" {
		t.Errorf("agent status = %q (err %v), want revoked", status, err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT trusted FROM known_devices WHERE id=$1`, kd).Scan(&trusted); err != nil || trusted {
		t.Errorf("known device still trusted = %v (err %v)", trusted, err)
	}
	// ziti_identity_id must be cleared so a later reconcile doesn't retry a
	// stale identity.
	var zid *string
	if err := db.Pool.QueryRow(ctx, `SELECT ziti_identity_id FROM enrolled_agents WHERE agent_id='agent-x'`).Scan(&zid); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if zid != nil && *zid != "" {
		t.Errorf("ziti_identity_id not cleared: %q", *zid)
	}
}
