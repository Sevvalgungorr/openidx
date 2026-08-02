package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Two failures, both of the same kind: a control that exists but is not
// connected to anything.
//
//  1. The atomic failed-login counter had no production caller. AuthenticateUser
//     kept its own private copy that read the count, added one in Go, and wrote
//     it back — the exact lost-update race the exported version was written to
//     remove. The fix shipped; the login path never used it.
//
//  2. Privilege grants, MFA changes, federation trust and login outcomes wrote
//     nothing to audit_events. Five call sites covered user create/delete,
//     password change and role create/update; a role *assignment* — how
//     privilege actually enters the system — left no record at all.
//
// An audit trail is not a nice-to-have on an IAM product: it is the artifact an
// incident is reconstructed from, and it can only record what was emitted at
// the time.

const auditSchema = `
CREATE TABLE users (
    id                   UUID PRIMARY KEY,
    username             VARCHAR(255) NOT NULL,
    email                VARCHAR(255) NOT NULL DEFAULT '',
    password_hash        VARCHAR(255) NOT NULL DEFAULT '',
    first_name           VARCHAR(255) NOT NULL DEFAULT '',
    last_name            VARCHAR(255) NOT NULL DEFAULT '',
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    password_changed_at  TIMESTAMPTZ,
    password_must_change BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count   INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,
    last_login_at        TIMESTAMPTZ,
    locked_until         TIMESTAMPTZ,
    source               VARCHAR(50),
    directory_id         UUID,
    org_id               UUID NOT NULL
);
CREATE TABLE roles (
    id           UUID PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    is_composite BOOLEAN DEFAULT false,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW(),
    org_id       UUID NOT NULL
);
CREATE TABLE user_roles (
    user_id     UUID NOT NULL,
    role_id     UUID NOT NULL,
    assigned_by VARCHAR(255),
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    org_id      UUID NOT NULL
);
CREATE TABLE composite_roles (
    parent_role_id UUID NOT NULL,
    child_role_id  UUID NOT NULL,
    org_id         UUID NOT NULL
);
CREATE TABLE groups (
    id               UUID PRIMARY KEY,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    parent_id        UUID,
    allow_self_join  BOOLEAN NOT NULL DEFAULT FALSE,
    require_approval BOOLEAN NOT NULL DEFAULT FALSE,
    max_members      INTEGER,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id           UUID NOT NULL
);
CREATE TABLE group_memberships (
    group_id  UUID NOT NULL,
    user_id   UUID NOT NULL,
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    org_id    UUID NOT NULL
);
CREATE TABLE mfa_totp (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL,
    secret          VARCHAR(255) NOT NULL,
    enabled         BOOLEAN DEFAULT false,
    enrolled_at     TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at  TIMESTAMPTZ,
    locked_until    TIMESTAMPTZ,
    org_id          UUID NOT NULL
);
CREATE TABLE mfa_backup_codes (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    used       BOOLEAN DEFAULT false,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    org_id     UUID NOT NULL
);
CREATE TABLE system_settings (
    key   VARCHAR(255) PRIMARY KEY,
    value JSONB
);
CREATE TABLE audit_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ DEFAULT NOW(),
    event_type  VARCHAR(100) NOT NULL,
    category    VARCHAR(50)  NOT NULL,
    action      VARCHAR(255) NOT NULL,
    outcome     VARCHAR(50)  NOT NULL,
    actor_id    VARCHAR(255),
    actor_type  VARCHAR(50),
    actor_ip    VARCHAR(45),
    target_id   VARCHAR(255),
    target_type VARCHAR(100),
    resource_id VARCHAR(255),
    details     JSONB,
    session_id  VARCHAR(255),
    request_id  VARCHAR(255),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    org_id      UUID NOT NULL
);`

const (
	auditOrg   = "44444444-5555-6666-7777-888888888888"
	auditUser  = "55555555-5555-6666-7777-888888888888"
	auditAdmin = "66666666-5555-6666-7777-888888888888"
	auditRole  = "77777777-5555-6666-7777-888888888888"
	auditGroup = "88888888-5555-6666-7777-888888888888"

	auditPassword = "Correct-Horse-1!"
	auditIP       = "203.0.113.47"
)

func newAuditService(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: auditOrg})
	if _, err := db.Pool.Exec(ctx, auditSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(auditPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, org_id) VALUES
		    ($1, 'alice', 'alice@example.test', $3, $4),
		    ($2, 'admin', 'admin@example.test', '',  $4)`,
		auditUser, auditAdmin, string(hash), auditOrg); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (id, name, org_id) VALUES ($1, 'auditors', $2)`, auditRole, auditOrg); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO groups (id, name, org_id) VALUES ($1, 'engineering', $2)`, auditGroup, auditOrg); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	// The user repository is wired because AuthenticateUser's success path
	// reads the full user back through it.
	s := &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop()}
	s.users = NewPostgresUserRepository(db)
	s.groups = NewPostgresGroupRepository(db)
	return s, db, ctx
}

type auditRow struct {
	action   string
	outcome  string
	actorID  string
	actorIP  string
	targetID string
	details  string
}

// awaitAuditEvent polls for an event, because logAuditEvent writes on a
// detached goroutine by design — audit must not add latency to, or fail, the
// operation it records.
func awaitAuditEvent(t *testing.T, db *database.PostgresDB, ctx context.Context, action string) auditRow {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var r auditRow
		err := db.Pool.QueryRow(ctx, `
			SELECT action, outcome, COALESCE(actor_id, ''), COALESCE(actor_ip, ''),
			       COALESCE(target_id, ''), COALESCE(details::text, '')
			FROM audit_events
			WHERE action = $1 AND org_id = $2
			ORDER BY timestamp DESC LIMIT 1`, action, auditOrg).Scan(
			&r.action, &r.outcome, &r.actorID, &r.actorIP, &r.targetID, &r.details)
		if err == nil {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit_events row with action=%q after 10s — the operation left no trail", action)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func countAuditEvents(t *testing.T, db *database.PostgresDB, ctx context.Context, action string) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = $1 AND org_id = $2`, action, auditOrg).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", action, err)
	}
	return n
}

func TestAuthenticateUserCountsEveryConcurrentFailure(t *testing.T) {
	// The regression guard for the disconnected fix.
	//
	// AuthenticateUser used to SELECT failed_login_count, hand it to a private
	// recorder, and have that recorder write count+1 back. Parallel guesses all
	// read the same value and all wrote the same value, so they counted as far
	// fewer than they were and the account stayed open well past its threshold —
	// under exactly the parallel traffic an attacker generates.
	//
	// This asserts against AuthenticateUser, not against RecordFailedLogin. The
	// existing test only covered the latter, which is why it stayed green while
	// the login path used the racy copy.
	//
	// The invariant is "no increment is lost", which is NOT "every call
	// increments". Once the threshold is crossed the account locks, and later
	// arrivals are refused at the lockout gate before the password is examined —
	// by design, they must not count. So the assertion is against the number of
	// attempts that actually got past that gate, which is whatever the scheduler
	// happened to allow. Asserting a flat 12 would be asserting that the lockout
	// does nothing.
	s, db, ctx := newAuditService(t)

	const attempts = 12
	var (
		mu        sync.Mutex
		evaluated int
	)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, err := s.AuthenticateUser(ctx, "alice", "wrong-password")
			if err == nil {
				t.Error("a wrong password authenticated")
				return
			}
			if errors.Is(err, ErrAccountLocked) {
				return // refused before evaluation; must not be counted
			}
			mu.Lock()
			evaluated++
			mu.Unlock()
		}()
	}
	wg.Wait()

	var count int
	var lockedUntil *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_login_count, locked_until FROM users WHERE id = $1 AND org_id = $2`,
		auditUser, auditOrg).Scan(&count, &lockedUntil); err != nil {
		t.Fatalf("read: %v", err)
	}

	// Every guess that was actually evaluated must be recorded. A
	// read-modify-write counter collapses simultaneous ones and lands short —
	// and, because it also never reaches the threshold, it leaves every attempt
	// evaluated, so the gap it opens here is large and obvious.
	if count != evaluated {
		t.Errorf("failed_login_count = %d but %d guesses were evaluated; %d increments were lost",
			count, evaluated, evaluated-count)
	}
	// And enough must have been evaluated to exercise the threshold, or this
	// test would pass against an implementation that never locks at all.
	if count < 5 {
		t.Errorf("only %d of %d guesses were evaluated, too few to reach the lockout threshold", count, attempts)
	}
	if lockedUntil == nil {
		t.Error("account not locked after exceeding the failure threshold")
	}
}

func TestAuthenticateUserLockoutIsKeyedByIDSoEmailLoginsCount(t *testing.T) {
	// AuthenticateUser resolves the account with `username = $1 OR email = $1`.
	// A counter keyed on username would update zero rows for a user who signs
	// in with their email address — the account would never lock, and the miss
	// would be invisible because nothing errors.
	s, db, ctx := newAuditService(t)

	for i := 0; i < 3; i++ {
		if _, err := s.AuthenticateUser(ctx, "alice@example.test", "wrong-password"); err == nil {
			t.Fatal("a wrong password authenticated")
		}
	}

	var count int
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_login_count FROM users WHERE id = $1 AND org_id = $2`,
		auditUser, auditOrg).Scan(&count); err != nil {
		t.Fatalf("read: %v", err)
	}
	if count != 3 {
		t.Errorf("failed_login_count = %d after 3 failures via email, want 3", count)
	}
}

func TestAuthenticateUserLocksThenRefusesTheCorrectPassword(t *testing.T) {
	// A lockout that still admits the right password only delays an attacker
	// until they guess it.
	s, _, ctx := newAuditService(t)

	for i := 0; i < 5; i++ {
		if _, err := s.AuthenticateUser(ctx, "alice", "wrong-password"); err == nil {
			t.Fatalf("attempt %d: a wrong password authenticated", i)
		}
	}

	_, err := s.AuthenticateUser(ctx, "alice", auditPassword)
	if err == nil {
		t.Fatal("the correct password was accepted on a locked account")
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("err = %v, want ErrAccountLocked so the caller can say 'wait' rather than 'wrong password'", err)
	}
}

func TestLoginOutcomesAreAudited(t *testing.T) {
	s, db, ctx := newAuditService(t)
	ipCtx := ContextWithActor(ctx, "", auditIP)

	t.Run("failure", func(t *testing.T) {
		if _, err := s.AuthenticateUser(ipCtx, "alice", "wrong-password"); err == nil {
			t.Fatal("a wrong password authenticated")
		}
		got := awaitAuditEvent(t, db, ctx, "user.login_failed")
		if got.outcome != "failure" {
			t.Errorf("outcome = %q, want failure", got.outcome)
		}
		if got.targetID != auditUser {
			t.Errorf("target_id = %q, want %q", got.targetID, auditUser)
		}
		// The IP is the field an investigator actually pivots on. It was written
		// as the empty string on every audit row before this change.
		if got.actorIP != auditIP {
			t.Errorf("actor_ip = %q, want %q", got.actorIP, auditIP)
		}
	})

	t.Run("success", func(t *testing.T) {
		if _, err := s.AuthenticateUser(ipCtx, "alice", auditPassword); err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		got := awaitAuditEvent(t, db, ctx, "user.login_succeeded")
		if got.outcome != "success" || got.targetID != auditUser {
			t.Errorf("got outcome=%q target=%q, want success/%s", got.outcome, got.targetID, auditUser)
		}
		if got.actorIP != auditIP {
			t.Errorf("actor_ip = %q, want %q", got.actorIP, auditIP)
		}
	})

	t.Run("a locked account is audited but not counted again", func(t *testing.T) {
		// Lock the account outright.
		if _, err := db.Pool.Exec(ctx,
			`UPDATE users SET locked_until = NOW() + INTERVAL '10 minutes', failed_login_count = 5
			 WHERE id = $1 AND org_id = $2`, auditUser, auditOrg); err != nil {
			t.Fatalf("lock: %v", err)
		}

		if _, err := s.AuthenticateUser(ipCtx, "alice", auditPassword); !errors.Is(err, ErrAccountLocked) {
			t.Fatalf("err = %v, want ErrAccountLocked", err)
		}
		got := awaitAuditEvent(t, db, ctx, "user.login_denied")
		if got.outcome != "failure" {
			t.Errorf("outcome = %q, want failure", got.outcome)
		}

		// Attempts against an already-locked account must not push the counter
		// higher: otherwise anyone who knows a username can hold that account
		// locked indefinitely by attempting a login every few minutes.
		var count int
		if err := db.Pool.QueryRow(ctx,
			`SELECT failed_login_count FROM users WHERE id = $1 AND org_id = $2`,
			auditUser, auditOrg).Scan(&count); err != nil {
			t.Fatalf("read: %v", err)
		}
		if count != 5 {
			t.Errorf("failed_login_count = %d after an attempt on a locked account, want it unchanged at 5", count)
		}
	})
}

func TestSensitiveIAMActionsAreAudited(t *testing.T) {
	s, db, ctx := newAuditService(t)
	// The acting admin and their address, as a request handler would supply
	// them via auditCtx.
	actx := ContextWithActor(ctx, auditAdmin, auditIP)

	tests := []struct {
		name   string
		action string
		target string
		do     func(t *testing.T)
	}{
		{
			name:   "role assigned",
			action: "role.assigned",
			target: auditUser,
			do: func(t *testing.T) {
				if err := s.AssignUserRole(actx, auditUser, auditRole, auditAdmin, nil); err != nil {
					t.Fatalf("assign: %v", err)
				}
			},
		},
		{
			name:   "role removed",
			action: "role.removed",
			target: auditUser,
			do: func(t *testing.T) {
				if err := s.RemoveUserRole(actx, auditUser, auditRole); err != nil {
					t.Fatalf("remove: %v", err)
				}
			},
		},
		{
			name:   "group member added",
			action: "group.member_added",
			target: auditUser,
			do: func(t *testing.T) {
				if _, err := db.Pool.Exec(ctx,
					`INSERT INTO group_memberships (group_id, user_id, org_id) VALUES ($1, $2, $3)`,
					auditGroup, auditAdmin, auditOrg); err != nil {
					t.Fatalf("seed membership: %v", err)
				}
				if err := s.AddGroupMember(actx, auditGroup, auditUser); err != nil {
					t.Fatalf("add member: %v", err)
				}
			},
		},
		{
			name:   "group member removed",
			action: "group.member_removed",
			target: auditUser,
			do: func(t *testing.T) {
				if err := s.RemoveGroupMember(actx, auditGroup, auditUser); err != nil {
					t.Fatalf("remove member: %v", err)
				}
			},
		},
		{
			name:   "TOTP disabled",
			action: "mfa.totp_disabled",
			target: auditUser,
			do: func(t *testing.T) {
				if err := s.DisableTOTP(actx, auditUser); err != nil {
					t.Fatalf("disable totp: %v", err)
				}
			},
		},
		{
			name:   "backup codes generated",
			action: "mfa.backup_codes_generated",
			target: auditUser,
			do: func(t *testing.T) {
				if _, err := s.GenerateBackupCodes(actx, auditUser, 5); err != nil {
					t.Fatalf("generate backup codes: %v", err)
				}
			},
		},
		{
			name:   "role deleted",
			action: "role.deleted",
			target: auditRole,
			do: func(t *testing.T) {
				if err := s.DeleteRole(actx, auditRole); err != nil {
					t.Fatalf("delete role: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.do(t)
			got := awaitAuditEvent(t, db, ctx, tt.action)
			if got.actorID != auditAdmin {
				t.Errorf("actor_id = %q, want the acting admin %q — an event that cannot name who did it is not an audit trail",
					got.actorID, auditAdmin)
			}
			if got.actorIP != auditIP {
				t.Errorf("actor_ip = %q, want %q", got.actorIP, auditIP)
			}
			if got.targetID != tt.target {
				t.Errorf("target_id = %q, want %q", got.targetID, tt.target)
			}
			if got.outcome != "success" {
				t.Errorf("outcome = %q, want success", got.outcome)
			}
		})
	}
}

func TestRoleSetReplacementAuditsWhatWasLost(t *testing.T) {
	// UpdateUserRoles replaces the whole set, so it revokes as well as grants.
	// An event carrying only the new set cannot answer "what did this user lose?",
	// which is the question asked after an incident.
	s, db, ctx := newAuditService(t)
	actx := ContextWithActor(ctx, auditAdmin, auditIP)

	const second = "99999999-5555-6666-7777-888888888888"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (id, name, org_id) VALUES ($1, 'approvers', $2)`, second, auditOrg); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := s.AssignUserRole(actx, auditUser, auditRole, auditAdmin, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}

	if err := s.UpdateUserRoles(actx, auditUser, []string{second}, auditAdmin); err != nil {
		t.Fatalf("update roles: %v", err)
	}

	got := awaitAuditEvent(t, db, ctx, "role.set_replaced")
	if !strings.Contains(got.details, auditRole) {
		t.Errorf("details %s does not name the revoked role %s", got.details, auditRole)
	}
	if !strings.Contains(got.details, second) {
		t.Errorf("details %s does not name the granted role %s", got.details, second)
	}
}

func TestMFABypassIsMirroredIntoTheUnifiedTrail(t *testing.T) {
	// mfa_bypass_audit is a private table. The unified audit view, the
	// compliance reports and the SIEM forwarder all read audit_events — so
	// issuing a code that skips the second factor was invisible to every one of
	// them.
	s, db, ctx := newAuditService(t)

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE mfa_bypass_audit (
		    id            UUID PRIMARY KEY,
		    bypass_code_id UUID,
		    user_id       UUID,
		    action        VARCHAR(50) NOT NULL,
		    performed_by  VARCHAR(255),
		    ip_address    VARCHAR(45),
		    user_agent    TEXT,
		    details       JSONB,
		    created_at    TIMESTAMPTZ DEFAULT NOW()
		)`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	admin := auditAdmin
	s.logBypassAudit(ctx, "", auditUser, "generated", &admin, auditIP, "test-agent",
		map[string]interface{}{"reason": "lost phone"})

	got := awaitAuditEvent(t, db, ctx, "mfa.bypass_generated")
	if got.actorID != auditAdmin {
		t.Errorf("actor_id = %q, want %q", got.actorID, auditAdmin)
	}
	if got.targetID != auditUser {
		t.Errorf("target_id = %q, want %q", got.targetID, auditUser)
	}
	if got.actorIP != auditIP {
		t.Errorf("actor_ip = %q, want %q", got.actorIP, auditIP)
	}
	if !strings.Contains(got.details, "lost phone") {
		t.Errorf("details %s dropped the stated reason", got.details)
	}

	// The private table keeps its row too — this mirrors, it does not move.
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_bypass_audit WHERE user_id = $1`, auditUser).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("mfa_bypass_audit rows = %d, want 1", n)
	}
}

func TestFailedOperationsDoNotEmitSuccessEvents(t *testing.T) {
	// An audit trail that records attempts as if they were changes is worse
	// than none: it manufactures history. Every emission sits after its error
	// check for this reason.
	s, db, ctx := newAuditService(t)
	actx := ContextWithActor(ctx, auditAdmin, auditIP)

	if err := s.AssignUserRole(actx, auditUser, auditRole, auditAdmin, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	awaitAuditEvent(t, db, ctx, "role.assigned")
	before := countAuditEvents(t, db, ctx, "role.assigned")

	// A duplicate assignment is refused.
	if err := s.AssignUserRole(actx, auditUser, auditRole, auditAdmin, nil); err == nil {
		t.Fatal("a duplicate role assignment succeeded")
	}
	// Removing a role the user does not hold is refused.
	if err := s.RemoveUserRole(actx, auditAdmin, auditRole); err == nil {
		t.Fatal("removing a role the user does not hold succeeded")
	}

	// Give a stray emission time to land. Waiting longer can only make this
	// stricter — if nothing was emitted, no amount of waiting invents a row —
	// so it is sized for a loaded CI runner rather than for a local one.
	time.Sleep(time.Second)
	if after := countAuditEvents(t, db, ctx, "role.assigned"); after != before {
		t.Errorf("role.assigned events = %d after a rejected assignment, want %d", after, before)
	}
	if n := countAuditEvents(t, db, ctx, "role.removed"); n != 0 {
		t.Errorf("role.removed events = %d after a rejected removal, want 0", n)
	}
}
