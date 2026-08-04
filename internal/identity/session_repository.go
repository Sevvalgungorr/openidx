// Package identity — session data-access layer.
//
// SessionRepository is the third aggregate extracted with the Repository pattern
// (after User and Group). Sessions carry an important read/write nuance that the
// seam lets us handle per-query:
//
//   - ListByUser / CountActive tolerate replica lag (a dashboard showing one
//     extra just-expired session for a few hundred ms is fine) → db.Reader().
//   - IsValid is SECURITY-CRITICAL read-after-write: a just-revoked or just-
//     created session MUST be observed immediately, so it reads the PRIMARY. A
//     lagging replica could report a revoked session as still valid — a real
//     auth bug. This is the deliberate exception, documented on the method.
//   - Create / UpdateActivity / Terminate are writes → db.Pool (primary).
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrSessionNotFound is the sentinel for a session miss / revoked / expired
// within the tenant.
var ErrSessionNotFound = errors.New("session not found")

// SessionRepository is the data-access port for sessions.
type SessionRepository interface {
	// ListByUser returns a user's active (unexpired) sessions in the tenant,
	// newest-activity first. Read (replica) — lag-tolerant.
	ListByUser(ctx context.Context, userID string) ([]Session, error)

	// CountActive returns the number of non-revoked, non-expired sessions for a
	// user in the tenant. Read (replica) — lag-tolerant.
	CountActive(ctx context.Context, userID string) (int, error)

	// IsValid reports whether a session is neither revoked nor expired. Reads the
	// PRIMARY: a just-revoked/created session must be seen immediately (security-
	// critical read-after-write). Returns ErrSessionNotFound when absent.
	IsValid(ctx context.Context, sessionID string) (bool, error)

	// Create inserts a new session (primary). Writes the generated id back onto
	// the returned Session.
	Create(ctx context.Context, s *Session) error

	// UpdateActivity bumps last_seen_at for a live session (primary). Returns
	// ErrSessionNotFound when the session is absent, revoked, or expired.
	UpdateActivity(ctx context.Context, sessionID string) error

	// Terminate removes a session row (primary). Idempotent.
	Terminate(ctx context.Context, sessionID string) error
}

// PostgresSessionRepository is the pgx implementation of SessionRepository.
type PostgresSessionRepository struct {
	db *database.PostgresDB
}

// NewPostgresSessionRepository constructs the pgx-backed session repository.
func NewPostgresSessionRepository(db *database.PostgresDB) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

const sessionSelectColumns = `id, user_id, client_id, ip_address, user_agent, started_at, last_seen_at, expires_at, COALESCE(revoked, false)`

func scanSessionRow(rows pgx.Rows) (Session, error) {
	var s Session
	err := rows.Scan(&s.ID, &s.UserID, &s.ClientID, &s.IPAddress, &s.UserAgent,
		&s.StartedAt, &s.LastSeenAt, &s.ExpiresAt, &s.Revoked)
	return s, err
}

// ListByUser implements SessionRepository. Read — replica.
func (r *PostgresSessionRepository) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Reader().Query(ctx, `
		SELECT `+sessionSelectColumns+`
		FROM sessions
		WHERE user_id = $1 AND org_id = $2 AND expires_at > NOW()
		  AND (revoked IS NULL OR revoked = false)
		ORDER BY last_seen_at DESC
	`, userID, org.ID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// CountActive implements SessionRepository. Read — replica.
func (r *PostgresSessionRepository) CountActive(ctx context.Context, userID string) (int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	err = r.db.Reader().QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false) AND expires_at > NOW()
	`, userID, org.ID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active sessions: %w", err)
	}
	return count, nil
}

// IsValid implements SessionRepository. Reads the PRIMARY on purpose — see the
// interface doc. A lagging replica could report a revoked session as valid.
func (r *PostgresSessionRepository) IsValid(ctx context.Context, sessionID string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	var revoked bool
	var expiresAt time.Time
	err = r.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(revoked, false), expires_at FROM sessions WHERE id = $1 AND org_id = $2
	`, sessionID, org.ID).Scan(&revoked, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrSessionNotFound
		}
		return false, fmt.Errorf("check session validity: %w", err)
	}
	return !revoked && time.Now().Before(expiresAt), nil
}

// Create implements SessionRepository. WRITE — primary.
func (r *PostgresSessionRepository) Create(ctx context.Context, s *Session) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	_, err = r.db.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, client_id, ip_address, user_agent, started_at, last_seen_at, expires_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, s.ID, s.UserID, s.ClientID, s.IPAddress, s.UserAgent, s.StartedAt, s.LastSeenAt, s.ExpiresAt, org.ID)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// UpdateActivity implements SessionRepository. WRITE — primary.
func (r *PostgresSessionRepository) UpdateActivity(ctx context.Context, sessionID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	result, err := r.db.Pool.Exec(ctx, `
		UPDATE sessions SET last_seen_at = $2
		WHERE id = $1 AND org_id = $3 AND (revoked IS NULL OR revoked = false) AND expires_at > NOW()
	`, sessionID, time.Now(), org.ID)
	if err != nil {
		return fmt.Errorf("update session activity: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// Terminate implements SessionRepository. WRITE — primary. Idempotent.
func (r *PostgresSessionRepository) Terminate(ctx context.Context, sessionID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	if _, err := r.db.Pool.Exec(ctx,
		`DELETE FROM sessions WHERE id = $1 AND org_id = $2`, sessionID, org.ID); err != nil {
		return fmt.Errorf("terminate session: %w", err)
	}
	return nil
}

// Ensure the concrete type satisfies the interface at compile time.
var _ SessionRepository = (*PostgresSessionRepository)(nil)
