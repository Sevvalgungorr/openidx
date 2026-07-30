package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Auditor is the subset of the unified audit service the vault uses. Satisfied
// by *access.UnifiedAuditService.RecordEvent.
type Auditor interface {
	RecordEvent(ctx context.Context, source, eventType, routeID, userID, actorIP string, details map[string]interface{}) error
}

// Service is the credential vault store.
type Service struct {
	db             *database.PostgresDB
	ring           *keyring
	audit          Auditor
	logger         *zap.Logger
	revealLeaseTTL time.Duration
}

func NewService(db *database.PostgresDB, ring *keyring, audit Auditor, revealLeaseTTL time.Duration, logger *zap.Logger) (*Service, error) {
	if ring == nil || !ring.Enabled() {
		return nil, errors.New("vault: keyring not enabled; refusing to start (fail-closed)")
	}
	if revealLeaseTTL <= 0 {
		revealLeaseTTL = 5 * time.Minute
	}
	return &Service{
		db:             db,
		ring:           ring,
		audit:          audit,
		logger:         logger.With(zap.String("component", "vault")),
		revealLeaseTTL: revealLeaseTTL,
	}, nil
}

// ---- DTOs (deliberately carry no value/ciphertext) ----

type SecretMeta struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Description    string    `json:"description,omitempty"`
	CurrentVersion int       `json:"current_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type VersionMeta struct {
	Version   int       `json:"version"`
	KeyID     int       `json:"key_id"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type SecretDetail struct {
	SecretMeta
	Versions []VersionMeta `json:"versions"`
}

type StoreInput struct {
	Name          string
	Type          string
	Description   string
	Value         []byte
	Metadata      map[string]interface{}
	OwnerID       string
	CreatedBy     string
	RequireStepUp bool
}

func (s *Service) orgID(ctx context.Context) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	return org.ID, nil
}

// Store creates a new secret at version 1. The plaintext is sealed and zeroed;
// it is never persisted, logged, or returned.
func (s *Service) Store(ctx context.Context, in StoreInput) (*SecretMeta, error) {
	defer zero(in.Value) // wipe plaintext on every return path, including Seal errors
	orgID, err := s.orgID(ctx)
	if err != nil {
		return nil, err
	}
	if in.Type == "" {
		in.Type = "generic"
	}
	secretID := uuid.New().String()
	keyID, blob, err := s.ring.Seal(secretID, 1, in.Value)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	zero(in.Value)

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var meta SecretMeta
	err = tx.QueryRow(ctx, `
		INSERT INTO vault_secrets (id, org_id, name, type, description, owner_id, metadata, current_version, created_by, require_step_up)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid,$7,1,NULLIF($8,'')::uuid,$9)
		RETURNING id, name, type, COALESCE(description,''), current_version, created_at, updated_at
	`, secretID, orgID, in.Name, in.Type, in.Description, in.OwnerID, jsonOrEmpty(in.Metadata), in.CreatedBy, in.RequireStepUp).
		Scan(&meta.ID, &meta.Name, &meta.Type, &meta.Description, &meta.CurrentVersion, &meta.CreatedAt, &meta.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		VALUES ($1,$2,1,$3,$4,NULLIF($5,'')::uuid)
	`, orgID, secretID, int(keyID), blob, in.CreatedBy); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.recordAudit(ctx, "vault.secret_created", in.CreatedBy, map[string]interface{}{"secret_id": secretID, "name": in.Name})
	return &meta, nil
}

// NewVersion appends an encrypted version and bumps current_version.
func (s *Service) NewVersion(ctx context.Context, secretID string, value []byte, by string) (int, error) {
	defer zero(value) // wipe plaintext on every return path, including Seal errors
	orgID, err := s.orgID(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var next int
	if err := tx.QueryRow(ctx,
		`UPDATE vault_secrets SET current_version = current_version + 1, updated_at = NOW()
		 WHERE id = $1 RETURNING current_version`, secretID).Scan(&next); err != nil {
		return 0, err
	}
	keyID, blob, err := s.ring.Seal(secretID, next, value)
	if err != nil {
		return 0, err
	}
	zero(value)
	if _, err := tx.Exec(ctx,
		`INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		 VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid)`, orgID, secretID, next, int(keyID), blob, by); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	s.recordAudit(ctx, "vault.secret_version", by, map[string]interface{}{"secret_id": secretID, "version": next})
	return next, nil
}

func (s *Service) List(ctx context.Context) ([]SecretMeta, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, type, COALESCE(description,''), current_version, created_at, updated_at
		FROM vault_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.ID, &m.Name, &m.Type, &m.Description, &m.CurrentVersion, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, secretID string) (*SecretDetail, error) {
	var d SecretDetail
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, type, COALESCE(description,''), current_version, created_at, updated_at
		FROM vault_secrets WHERE id = $1`, secretID).
		Scan(&d.ID, &d.Name, &d.Type, &d.Description, &d.CurrentVersion, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT version, key_id, COALESCE(created_by::text,''), created_at
		 FROM vault_secret_versions WHERE secret_id = $1 ORDER BY version DESC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v VersionMeta
		if err := rows.Scan(&v.Version, &v.KeyID, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		d.Versions = append(d.Versions, v)
	}
	return &d, rows.Err()
}

// Delete removes the secret and (via cascade) all its versions — the only copy
// of the ciphertext — so the secret is cryptographically unrecoverable.
func (s *Service) Delete(ctx context.Context, secretID string) error {
	ct, err := s.db.Pool.Exec(ctx, `DELETE FROM vault_secrets WHERE id = $1`, secretID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.recordAudit(ctx, "vault.secret_deleted", "", map[string]interface{}{"secret_id": secretID})
	return nil
}

// ErrNotFound is returned when a requested secret does not exist.
var ErrNotFound = errors.New("vault: secret not found")

func (s *Service) recordAudit(ctx context.Context, eventType, userID string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	if err := s.audit.RecordEvent(ctx, "vault", eventType, "", userID, "", details); err != nil {
		s.logger.Warn("vault audit failed", zap.String("event", eventType), zap.Error(err))
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func jsonOrEmpty(m map[string]interface{}) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---- Access grants ----

// Grant represents a principal's permission to perform one or more actions
// (use, reveal) on a secret.
type Grant struct {
	SecretID      string     `json:"secret_id"`
	PrincipalType string     `json:"principal_type"` // user|role|service_account
	PrincipalID   string     `json:"principal_id"`
	Actions       []string   `json:"actions"` // subset of {use, reveal}
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	GrantedBy     string     `json:"-"`
}

// AddGrant upserts a grant for (secret_id, principal_type, principal_id). On
// conflict the actions and expires_at are updated. Returns the grant id.
func (s *Service) AddGrant(ctx context.Context, g Grant) (string, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return "", err
	}
	id := uuid.New().String()
	var persistedID string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions, granted_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid,$8)
		ON CONFLICT (secret_id, principal_type, principal_id)
		DO UPDATE SET actions = EXCLUDED.actions, expires_at = EXCLUDED.expires_at
		RETURNING id`,
		id, orgID, g.SecretID, g.PrincipalType, g.PrincipalID, g.Actions, g.GrantedBy, g.ExpiresAt).Scan(&persistedID)
	if err != nil {
		return "", err
	}
	id = persistedID
	s.recordAudit(ctx, "vault.grant_added", g.GrantedBy, map[string]interface{}{
		"secret_id": g.SecretID, "principal": g.PrincipalType + ":" + g.PrincipalID, "actions": g.Actions})
	return id, nil
}

// RemoveGrant deletes the grant by id. Returns ErrNotFound if no row was
// deleted.
func (s *Service) RemoveGrant(ctx context.Context, grantID string) error {
	ct, err := s.db.Pool.Exec(ctx, `DELETE FROM vault_access_grants WHERE id = $1`, grantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.recordAudit(ctx, "vault.grant_removed", "", map[string]interface{}{"grant_id": grantID})
	return nil
}

// GrantRow is a JSON-safe DTO for listing grants. Unlike Grant it exposes ID
// and GrantedBy (the caller is an admin listing grants they issued).
type GrantRow struct {
	ID            string     `json:"id"`
	SecretID      string     `json:"secret_id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalID   string     `json:"principal_id"`
	Actions       []string   `json:"actions"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	GrantedBy     string     `json:"granted_by,omitempty"`
}

// ListGrants returns all access grants for secretID, ordered by principal_type
// then principal_id.
func (s *Service) ListGrants(ctx context.Context, secretID string) ([]GrantRow, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, secret_id, principal_type, principal_id, actions, expires_at,
		       COALESCE(granted_by::text,'')
		FROM vault_access_grants
		WHERE secret_id = $1
		ORDER BY principal_type, principal_id`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrantRow
	for rows.Next() {
		var g GrantRow
		if err := rows.Scan(&g.ID, &g.SecretID, &g.PrincipalType, &g.PrincipalID,
			&g.Actions, &g.ExpiresAt, &g.GrantedBy); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrantForPrincipal deletes any grant for (secretID, principalType, principalID).
// Used by the JIT-checkout early-return path for immediate deauthorization; the timeout
// path relies on the grant's expires_at. Org-scoped by RLS via ctx.
func (s *Service) RevokeGrantForPrincipal(ctx context.Context, secretID, principalType, principalID string) error {
	_, err := s.db.Pool.Exec(ctx,
		`DELETE FROM vault_access_grants WHERE secret_id=$1 AND principal_type=$2 AND principal_id=$3`,
		secretID, principalType, principalID)
	return err
}

// hasGrant reports whether principalID holds a non-expired grant carrying
// action on secretID. userRoles lets a user match role-type grants.
func (s *Service) hasGrant(ctx context.Context, secretID, principalID string, userRoles []string, action string) (bool, error) {
	var ok bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM vault_access_grants
			WHERE secret_id = $1
			  AND $2 = ANY(actions)
			  AND (expires_at IS NULL OR expires_at > NOW())
			  AND (
			    (principal_type IN ('user','service_account') AND principal_id::text = $3)
			    OR (principal_type = 'role' AND principal_id::text = ANY($4))
			  )
		)`, secretID, action, principalID, userRoles).Scan(&ok)
	return ok, err
}

// ---- Use + Reveal + checkout ledger ----

// decryptCurrent loads and decrypts the current version. Internal only.
func (s *Service) decryptCurrent(ctx context.Context, secretID string) (int, []byte, error) {
	var version, keyID int
	var blob []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT v.version, v.key_id, v.ciphertext
		FROM vault_secret_versions v
		JOIN vault_secrets s ON s.id = v.secret_id AND s.current_version = v.version
		WHERE v.secret_id = $1`, secretID).Scan(&version, &keyID, &blob)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNotFound
		}
		return 0, nil, err
	}
	pt, err := s.ring.Open(byte(keyID), secretID, version, blob)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt: %w", err)
	}
	return version, pt, nil
}

// Use returns the current plaintext to an INTERNAL Go caller (rotation engine,
// session broker). Never exposed over HTTP. System callers (WithBypassRLS) skip
// the grant check but are still recorded. Callers must zero the returned slice.
//
// IMPORTANT: Use MUST only be called by internal system callers (rotation engine,
// session-broker) that hold a bypass-RLS context (orgctx.WithBypassRLS). Calling
// this from a request-scoped context without bypass-RLS will return an error
// immediately — the check is intentionally fail-closed to prevent accidental
// exposure of plaintext over the HTTP path.
func (s *Service) Use(ctx context.Context, secretID string) ([]byte, error) {
	if !orgctx.IsBypassRLS(ctx) {
		return nil, errors.New("vault: Use requires a system (bypass-RLS) context")
	}
	version, pt, err := s.decryptCurrent(ctx, secretID)
	if err != nil {
		return nil, err
	}
	s.recordCheckout(ctx, secretID, version, "", "use", "", nil)
	s.recordAudit(ctx, "vault.use", "", map[string]interface{}{"secret_id": secretID, "system": true})
	return pt, nil
}

// Reveal returns the current plaintext to a human, requiring a `reveal` grant
// and a non-empty reason. Heavily audited; opens a short lease.
func (s *Service) Reveal(ctx context.Context, secretID, principalID string, userRoles []string, reason string, isAdmin bool) ([]byte, error) {
	if reason == "" {
		return nil, errors.New("vault: reveal requires a reason")
	}
	if !isAdmin {
		ok, err := s.hasGrant(ctx, secretID, principalID, userRoles, "reveal")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrForbidden
		}
	}
	// Step-up MFA gate (A4): a secret flagged require_step_up may only be
	// revealed when the caller completed a step-up challenge within the recent
	// window. Admins are NOT exempt — the whole point is a fresh second factor
	// on the sensitive action, not a role. Enforced fail-closed: a query error
	// denies the reveal.
	stepUp, err := s.secretRequiresStepUp(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if stepUp {
		ok, err := s.hasRecentStepUp(ctx, principalID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrStepUpRequired
		}
	}
	version, pt, err := s.decryptCurrent(ctx, secretID)
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(s.revealLeaseTTL)
	s.recordCheckout(ctx, secretID, version, principalID, "reveal", reason, &exp)
	s.recordAudit(ctx, "vault.reveal", principalID, map[string]interface{}{
		"secret_id": secretID, "version": version, "reason": reason})
	return pt, nil
}

// stepUpRecentWindow bounds how fresh a completed step-up must be to authorize a
// reveal. Short by design: a step-up authorizes the action about to happen, not
// a standing elevation.
const stepUpRecentWindow = 5 * time.Minute

// secretRequiresStepUp reports whether the secret is flagged require_step_up.
func (s *Service) secretRequiresStepUp(ctx context.Context, secretID string) (bool, error) {
	var req bool
	//orgscope:ignore vault_secrets is org-scoped by FORCE RLS on the pooled connection (same pattern as decryptCurrent's WHERE id=$1)
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(require_step_up, FALSE) FROM vault_secrets WHERE id = $1`, secretID).Scan(&req)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("vault: check require_step_up: %w", err)
	}
	return req, nil
}

// hasRecentStepUp reports whether the principal completed a step-up challenge
// within stepUpRecentWindow. Reads the same stepup_challenges ledger the OAuth
// step-up verify path writes (status='completed', completed_at set).
func (s *Service) hasRecentStepUp(ctx context.Context, principalID string) (bool, error) {
	var n int
	//orgscope:ignore stepup_challenges is user-scoped (user_id); a completed step-up is the same regardless of org, and stepup rows carry org_id under RLS
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM stepup_challenges
		 WHERE user_id = $1 AND status = 'completed'
		   AND completed_at IS NOT NULL
		   AND completed_at > NOW() - $2::interval`,
		principalID, fmt.Sprintf("%d seconds", int(stepUpRecentWindow.Seconds()))).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("vault: check recent step-up: %w", err)
	}
	return n > 0, nil
}

// ErrForbidden is returned when a principal lacks the required grant.
var ErrForbidden = errors.New("vault: principal lacks the required grant")

// ErrStepUpRequired is returned when a require_step_up secret is revealed
// without a recent completed step-up challenge. Handlers map it to 403 +
// X-Step-Up-Required so the client can trigger the step-up flow and retry.
var ErrStepUpRequired = errors.New("vault: step-up authentication required")

func (s *Service) recordCheckout(ctx context.Context, secretID string, version int, principalID, mode, reason string, expires *time.Time) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		// System Use runs under bypass with no org; derive from the secret row.
		_ = s.db.Pool.QueryRow(ctx, `SELECT org_id FROM vault_secrets WHERE id = $1`, secretID).Scan(&orgID) //orgscope:ignore system Use has no request org; org_id derived from the secret row
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO vault_checkouts (org_id, secret_id, secret_version, principal_id, mode, reason, expires_at)
		VALUES ($1,$2,$3,NULLIF($4,'')::uuid,$5,NULLIF($6,''),$7)`,
		orgID, secretID, version, principalID, mode, reason, expires); err != nil {
		s.logger.Warn("vault checkout record failed", zap.Error(err))
	}
}

// Checkout is a single ledger entry for a Use or Reveal operation.
type Checkout struct {
	ID        string     `json:"id"`
	Version   int        `json:"secret_version"`
	Principal string     `json:"principal_id,omitempty"`
	Mode      string     `json:"mode"`
	Reason    string     `json:"reason,omitempty"`
	LeasedAt  time.Time  `json:"leased_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Status    string     `json:"status"`
}

// Checkouts returns the last 200 checkout ledger entries for a secret, newest
// first.
func (s *Service) Checkouts(ctx context.Context, secretID string) ([]Checkout, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, secret_version, COALESCE(principal_id::text,''), mode, COALESCE(reason,''), leased_at, expires_at, status
		FROM vault_checkouts WHERE secret_id = $1 ORDER BY leased_at DESC LIMIT 200`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkout
	for rows.Next() {
		var c Checkout
		if err := rows.Scan(&c.ID, &c.Version, &c.Principal, &c.Mode, &c.Reason, &c.LeasedAt, &c.ExpiresAt, &c.Status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddCandidateVersion stores a new encrypted version WITHOUT bumping current_version.
// The candidate is invisible to Use/Reveal (which join on current_version) until
// PromoteVersion runs. Version number = MAX(version)+1 so repeated failed rotations
// don't collide. Used by the rotation engine to make a generated value durable before
// touching the target. value is zeroed by the caller.
func (s *Service) AddCandidateVersion(ctx context.Context, secretID string, value []byte, by string) (int, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return 0, err
	}
	var next int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version),0)+1 FROM vault_secret_versions WHERE secret_id = $1`, secretID).Scan(&next); err != nil {
		return 0, err
	}
	keyID, blob, err := s.ring.Seal(secretID, next, value)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		 VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid)`, orgID, secretID, next, int(keyID), blob, by); err != nil {
		return 0, err
	}
	return next, nil
}

// PromoteVersion sets a secret's current_version — the atomic "this value is now live on
// the target" commit that makes it visible to Use/Reveal.
func (s *Service) PromoteVersion(ctx context.Context, secretID string, version int) error {
	ct, err := s.db.Pool.Exec(ctx,
		`UPDATE vault_secrets SET current_version = $2, updated_at = NOW() WHERE id = $1`, secretID, version)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SecretOrg returns a secret's org_id. Background/bypass callers (the rotation engine)
// use it to inject the org into their context for scoped vault writes.
func (s *Service) SecretOrg(ctx context.Context, secretID string) (string, error) {
	var org string
	err := s.db.Pool.QueryRow(ctx, `SELECT org_id FROM vault_secrets WHERE id = $1`, secretID).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return org, err
}
