package directory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// hrisSetupTestDB spins a throwaway Postgres with the minimal users schema the
// JML reconcile needs. Skips (not fails) when Docker is unavailable.
func hrisSetupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	conn := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"
	db, err := database.NewPostgres(conn)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
		return nil, func() {}
	}
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, hrisUsersSchema); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("schema: %v", err)
	}
	return db, func() { db.Close(); container.Terminate(ctx) }
}

const hrisUsersSchema = `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255),
    first_name VARCHAR(255), last_name VARCHAR(255), password_hash VARCHAR(255),
    enabled BOOLEAN DEFAULT true, email_verified BOOLEAN DEFAULT false,
    source VARCHAR(50), directory_id UUID, external_id VARCHAR(255),
    external_hr_id VARCHAR(128), employee_number VARCHAR(64),
    job_title VARCHAR(255), department VARCHAR(255), employment_status VARCHAR(32),
    hire_date DATE, termination_date DATE, manager_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);`

// bambooServer starts an httptest BambooHR returning the given directory JSON.
func bambooServer(dirJSON string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/employees/directory") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(dirJSON))
	}))
}

func hrisEngine(db *database.PostgresDB) *SyncEngine {
	return NewSyncEngine(db, zap.NewNop())
}

// runHRISSync drives doSyncHRIS against a mock BambooHR server.
func runHRISSync(t *testing.T, e *SyncEngine, srv *httptest.Server, dirID, orgID string, full bool) *SyncResult {
	t.Helper()
	cfg := HRISConfig{Provider: "bamboohr", APIKey: "k", BaseURL: srv.URL, DeprovisionAction: "disable"}
	res := &SyncResult{}
	if err := e.doSyncHRIS(context.Background(), dirID, orgID, cfg, full, res); err != nil {
		t.Fatalf("doSyncHRIS: %v", err)
	}
	return res
}

func countUsers(t *testing.T, db *database.PostgresDB, where string, args ...interface{}) int {
	t.Helper()
	var n int
	db.Pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE "+where, args...).Scan(&n)
	return n
}

func TestHRISJoinerMoverLeaver(t *testing.T) {
	db, cleanup := hrisSetupTestDB(t)
	defer cleanup()
	dirID := "00000000-0000-0000-0000-0000000000d1"
	orgID := "00000000-0000-0000-0000-0000000000a1"

	// --- Full sync #1: three active joiners, one already-terminated (skipped). ---
	dir1 := `{"employees":[
      {"id":"1","employeeNumber":"E1","firstName":"Ann","lastName":"A","workEmail":"ann@corp.com","jobTitle":"Eng","department":"R&D","supervisorEId":"2","status":"Active","hireDate":"2024-01-01"},
      {"id":"2","employeeNumber":"E2","firstName":"Bob","lastName":"B","workEmail":"bob@corp.com","jobTitle":"Lead","department":"R&D","status":"Active","hireDate":"2023-01-01"},
      {"id":"4","employeeNumber":"E4","firstName":"Dot","lastName":"D","workEmail":"dot@corp.com","jobTitle":"Eng","department":"R&D","status":"Active","hireDate":"2024-02-01"},
      {"id":"3","employeeNumber":"E3","firstName":"Cy","lastName":"C","workEmail":"cy@corp.com","status":"Terminated","terminationDate":"2024-06-01"}
    ]}`
	srv1 := bambooServer(dir1)
	e := hrisEngine(db)
	res := runHRISSync(t, e, srv1, dirID, orgID, true)
	srv1.Close()

	if res.UsersAdded != 3 {
		t.Fatalf("expected 3 joiners created, got %d (errors: %v)", res.UsersAdded, res.Errors)
	}
	if n := countUsers(t, db, "directory_id=$1 AND source='hris'", dirID); n != 3 {
		t.Fatalf("expected 3 HR users in DB, got %d", n)
	}
	// Manager resolution: Ann's manager is Bob.
	var mgrUsername string
	db.Pool.QueryRow(context.Background(), `
        SELECT m.username FROM users u JOIN users m ON u.manager_id=m.id
         WHERE u.external_hr_id='1' AND u.org_id=$1`, orgID).Scan(&mgrUsername)
	if mgrUsername != "bob@corp.com" {
		t.Errorf("expected Ann's manager to be bob@corp.com, got %q", mgrUsername)
	}
	// Terminated joiner was not created.
	if n := countUsers(t, db, "external_hr_id='3'"); n != 0 {
		t.Errorf("terminated joiner should not be created, found %d", n)
	}

	// --- Full sync #2: Ann is a mover (new dept/title); Bob becomes a leaver
	//     (absent from the directory). Dot stays so the leaver rate is 1/3. ---
	dir2 := `{"employees":[
      {"id":"1","employeeNumber":"E1","firstName":"Ann","lastName":"A","workEmail":"ann@corp.com","jobTitle":"Staff Eng","department":"Platform","status":"Active","hireDate":"2024-01-01"},
      {"id":"4","employeeNumber":"E4","firstName":"Dot","lastName":"D","workEmail":"dot@corp.com","jobTitle":"Eng","department":"R&D","status":"Active","hireDate":"2024-02-01"}
    ]}`
	srv2 := bambooServer(dir2)
	res2 := runHRISSync(t, e, srv2, dirID, orgID, true)
	srv2.Close()

	if res2.UsersUpdated < 1 {
		t.Errorf("expected Ann updated (mover), got %d updates", res2.UsersUpdated)
	}
	// Ann's new title/department landed.
	var title, dept string
	db.Pool.QueryRow(context.Background(),
		`SELECT job_title, department FROM users WHERE external_hr_id='1' AND org_id=$1`, orgID).Scan(&title, &dept)
	if title != "Staff Eng" || dept != "Platform" {
		t.Errorf("mover attrs not applied: title=%q dept=%q", title, dept)
	}
	// Bob (absent) was deprovisioned: disabled + terminated status.
	var enabled bool
	var status string
	db.Pool.QueryRow(context.Background(),
		`SELECT enabled, employment_status FROM users WHERE external_hr_id='2' AND org_id=$1`, orgID).Scan(&enabled, &status)
	if enabled {
		t.Error("expected Bob disabled (leaver)")
	}
	if status != "terminated" {
		t.Errorf("expected Bob status terminated, got %q", status)
	}
	if res2.UsersDisabled != 1 {
		t.Errorf("expected 1 leaver, got %d", res2.UsersDisabled)
	}
}

func TestHRISPresentButTerminatedIsLeaver(t *testing.T) {
	db, cleanup := hrisSetupTestDB(t)
	defer cleanup()
	dirID := "00000000-0000-0000-0000-0000000000d2"
	orgID := "00000000-0000-0000-0000-0000000000a2"

	// Sync #1: one active user.
	srv1 := bambooServer(`{"employees":[{"id":"9","firstName":"Dee","lastName":"D","workEmail":"dee@corp.com","status":"Active"}]}`)
	e := hrisEngine(db)
	runHRISSync(t, e, srv1, dirID, orgID, true)
	srv1.Close()

	// Sync #2: same user now Terminated but STILL present in the directory.
	srv2 := bambooServer(`{"employees":[{"id":"9","firstName":"Dee","lastName":"D","workEmail":"dee@corp.com","status":"Terminated","terminationDate":"2025-03-01"}]}`)
	res := runHRISSync(t, e, srv2, dirID, orgID, true)
	srv2.Close()

	if res.UsersDisabled != 1 {
		t.Fatalf("expected present-but-terminated to be a leaver, got %d", res.UsersDisabled)
	}
	var enabled bool
	db.Pool.QueryRow(context.Background(),
		`SELECT enabled FROM users WHERE external_hr_id='9' AND org_id=$1`, orgID).Scan(&enabled)
	if enabled {
		t.Error("expected terminated user disabled")
	}
}

func TestHRISLeaverSafetyValve(t *testing.T) {
	db, cleanup := hrisSetupTestDB(t)
	defer cleanup()
	dirID := "00000000-0000-0000-0000-0000000000d3"
	orgID := "00000000-0000-0000-0000-0000000000a3"

	// Seed 5 active users.
	big := `{"employees":[
      {"id":"1","firstName":"A","workEmail":"a@c.com","status":"Active"},
      {"id":"2","firstName":"B","workEmail":"b@c.com","status":"Active"},
      {"id":"3","firstName":"C","workEmail":"c@c.com","status":"Active"},
      {"id":"4","firstName":"D","workEmail":"d@c.com","status":"Active"},
      {"id":"5","firstName":"E","workEmail":"e@c.com","status":"Active"}]}`
	srv1 := bambooServer(big)
	e := hrisEngine(db)
	runHRISSync(t, e, srv1, dirID, orgID, true)
	srv1.Close()

	// Next fetch returns only 1 (looks like a broken fetch: 4/5 = 80% absent).
	srv2 := bambooServer(`{"employees":[{"id":"1","firstName":"A","workEmail":"a@c.com","status":"Active"}]}`)
	res := runHRISSync(t, e, srv2, dirID, orgID, true)
	srv2.Close()

	if res.UsersDisabled != 0 {
		t.Errorf("safety valve should block mass deprovision, but disabled %d", res.UsersDisabled)
	}
	if len(res.Errors) == 0 {
		t.Error("expected a safety-threshold error")
	}
	// All 5 still enabled.
	if n := countUsers(t, db, "directory_id=$1 AND enabled=true", dirID); n != 5 {
		t.Errorf("expected all 5 users still enabled, got %d", n)
	}
}
