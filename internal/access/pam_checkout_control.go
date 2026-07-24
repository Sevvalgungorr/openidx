// PAM checkout controls (migration v105): break-glass, dual-control (two-person
// rule), and exclusive checkout.
//
// These wrap the reveal path (pam_entries.go handlePamRevealEntry) with the
// privileged-access controls DORA RTS Art 21 and ISO 27001 A.8.2 expect:
//
//   - exclusive_checkout  — one holder at a time. pamCheckoutGate refuses a
//     reveal (409) while another principal has a live lease in pam_active_checkouts.
//   - dual_control_required — a second admin must authorize the specific checkout.
//     The first reveal opens a pending pam_checkout_authorizations row (202); a
//     different admin approves it; the requester's retry consumes it and proceeds.
//   - break_glass_enabled — an audited emergency path that bypasses both the
//     dual-control wait and the exclusivity hold, raising a high-severity event.
package access

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// pamCheckoutLeaseTTL is how long a recorded reveal lease holds an exclusive
// entry before it is considered stale (a caller who never checks in should not
// wedge the entry forever). Kept a touch longer than the vault reveal lease.
const pamCheckoutLeaseTTL = 15 * time.Minute

// pamCheckoutFlags are the per-entry control toggles read by the gate.
type pamCheckoutFlags struct {
	DualControl bool
	Exclusive   bool
	BreakGlass  bool
}

// pamLoadCheckoutFlags reads the v105 control flags for an entry.
func (s *Service) pamLoadCheckoutFlags(ctx context.Context, orgID, entryID string) (pamCheckoutFlags, error) {
	var f pamCheckoutFlags
	err := s.db.Pool.QueryRow(ctx, `
		SELECT dual_control_required, exclusive_checkout, break_glass_enabled
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, orgID).
		Scan(&f.DualControl, &f.Exclusive, &f.BreakGlass)
	return f, err
}

// pamActiveHolder returns the principal currently holding a live (unexpired,
// non-released) checkout on the entry, or "" if none. Expired leases are swept
// to 'expired' so a stale hold never wedges an exclusive entry.
func (s *Service) pamActiveHolder(ctx context.Context, orgID, entryID, excludePrincipal string) (string, error) {
	// Retire leases whose TTL has passed before we look for a live holder.
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_active_checkouts SET status = 'expired', released_at = NOW()
		 WHERE org_id = $1 AND entry_id = $2 AND status = 'active'
		   AND expires_at IS NOT NULL AND expires_at <= NOW()`, orgID, entryID); err != nil {
		return "", err
	}
	var holder string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(principal_id::text,'')
		  FROM pam_active_checkouts
		 WHERE org_id = $1 AND entry_id = $2 AND status = 'active'
		   AND principal_id <> NULLIF($3,'')::uuid
		 ORDER BY leased_at ASC LIMIT 1`, orgID, entryID, excludePrincipal).Scan(&holder)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return holder, err
}

// pamRecordCheckout inserts a live checkout lease. Best-effort: a ledger write
// must not fail an operation the caller was already authorized for.
func (s *Service) pamRecordCheckout(ctx context.Context, orgID, entryID, principalID, action, reason string, breakGlass bool) {
	exp := time.Now().Add(pamCheckoutLeaseTTL)
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO pam_active_checkouts (org_id, entry_id, principal_id, action, reason, break_glass, expires_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7)`,
		orgID, entryID, principalID, action, reason, breakGlass, exp); err != nil {
		s.logger.Warn("pam checkout record failed", zap.Error(err))
	}
}

// pamCheckoutGate enforces exclusivity and dual-control for a reveal/checkout.
// It returns (proceed, httpStatus, body):
//   - proceed=true  → the caller may reveal; status/body are unset.
//   - proceed=false → respond with status/body (409 exclusivity, 202 awaiting
//     second-person, or 500 on a ledger error).
func (s *Service) pamCheckoutGate(ctx context.Context, orgID, entryID, userID, action, reason string) (bool, int, gin.H) {
	flags, err := s.pamLoadCheckoutFlags(ctx, orgID, entryID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, http.StatusNotFound, gin.H{"error": "entry not found"}
		}
		s.logger.Error("pamCheckoutGate: flag load failed", zap.Error(err))
		return false, http.StatusInternalServerError, gin.H{"error": "failed to evaluate checkout controls"}
	}
	if !flags.DualControl && !flags.Exclusive {
		return true, 0, nil // no controls on this entry
	}

	if flags.Exclusive {
		holder, err := s.pamActiveHolder(ctx, orgID, entryID, userID)
		if err != nil {
			s.logger.Error("pamCheckoutGate: exclusivity check failed", zap.Error(err))
			return false, http.StatusInternalServerError, gin.H{"error": "failed to evaluate exclusivity"}
		}
		if holder != "" {
			return false, http.StatusConflict, gin.H{
				"error":       "entry is exclusively checked out by another user",
				"held_by":     holder,
				"break_glass": flags.BreakGlass,
			}
		}
	}

	if flags.DualControl {
		// Consume an approved authorization if one is waiting for this caller.
		var authID string
		err := s.db.Pool.QueryRow(ctx, `
			UPDATE pam_checkout_authorizations
			   SET status = 'consumed', decided_at = NOW()
			 WHERE id = (
			   SELECT id FROM pam_checkout_authorizations
			    WHERE org_id = $1 AND entry_id = $2 AND requester_id = $3 AND action = $4
			      AND status = 'approved' AND expires_at > NOW()
			    ORDER BY created_at DESC LIMIT 1
			 )
			RETURNING id`, orgID, entryID, userID, action).Scan(&authID)
		if err == nil {
			return true, 0, nil // second-person authorization consumed; proceed
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error("pamCheckoutGate: authorization consume failed", zap.Error(err))
			return false, http.StatusInternalServerError, gin.H{"error": "failed to evaluate dual control"}
		}

		// No approved authorization — surface (or open) a pending request.
		var pendingID string
		err = s.db.Pool.QueryRow(ctx, `
			SELECT id FROM pam_checkout_authorizations
			 WHERE org_id = $1 AND entry_id = $2 AND requester_id = $3 AND action = $4
			   AND status = 'pending' AND expires_at > NOW()
			 ORDER BY created_at DESC LIMIT 1`, orgID, entryID, userID, action).Scan(&pendingID)
		if errors.Is(err, pgx.ErrNoRows) {
			if err = s.db.Pool.QueryRow(ctx, `
				INSERT INTO pam_checkout_authorizations (org_id, entry_id, requester_id, action, reason)
				VALUES ($1,$2,$3,$4,NULLIF($5,''))
				RETURNING id`, orgID, entryID, userID, action, reason).Scan(&pendingID); err != nil {
				s.logger.Error("pamCheckoutGate: authorization open failed", zap.Error(err))
				return false, http.StatusInternalServerError, gin.H{"error": "failed to open dual-control request"}
			}
		} else if err != nil {
			s.logger.Error("pamCheckoutGate: pending lookup failed", zap.Error(err))
			return false, http.StatusInternalServerError, gin.H{"error": "failed to evaluate dual control"}
		}
		return false, http.StatusAccepted, gin.H{
			"status":           "awaiting_authorization",
			"message":          "this entry requires a second approver; a request has been opened",
			"authorization_id": pendingID,
		}
	}

	return true, 0, nil
}

// ---- Dual-control second-person endpoints ----

// PamCheckoutAuthorization is the API view of a pending/decided dual-control row.
type PamCheckoutAuthorization struct {
	ID          string     `json:"id"`
	EntryID     string     `json:"entry_id"`
	EntryName   string     `json:"entry_name,omitempty"`
	RequesterID string     `json:"requester_id"`
	Action      string     `json:"action"`
	Reason      string     `json:"reason,omitempty"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// handlePamListCheckoutAuthorizations — GET /pam/checkout-authorizations (admin).
// Lists pending second-person authorizations awaiting an approver.
func (s *Service) handlePamListCheckoutAuthorizations(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.entry_id::text, COALESCE(e.name,''), a.requester_id::text, a.action,
		       COALESCE(a.reason,''), a.status, a.created_at, a.expires_at, a.decided_at
		  FROM pam_checkout_authorizations a
		  LEFT JOIN pam_entries e ON e.id = a.entry_id
		 WHERE a.org_id = $1 AND a.status = 'pending' AND a.expires_at > NOW()
		 ORDER BY a.created_at DESC LIMIT 200`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListCheckoutAuthorizations: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list authorizations"})
		return
	}
	defer rows.Close()
	out := []PamCheckoutAuthorization{}
	for rows.Next() {
		var a PamCheckoutAuthorization
		if err := rows.Scan(&a.ID, &a.EntryID, &a.EntryName, &a.RequesterID, &a.Action,
			&a.Reason, &a.Status, &a.CreatedAt, &a.ExpiresAt, &a.DecidedAt); err != nil {
			s.logger.Warn("handlePamListCheckoutAuthorizations: scan failed", zap.Error(err))
			continue
		}
		out = append(out, a)
	}
	c.JSON(http.StatusOK, gin.H{"authorizations": out})
}

// handlePamDecideCheckoutAuthorization — POST /pam/checkout-authorizations/:id/:decision
// (admin). decision is "approve" or "deny". Enforces the two-person rule: the
// authorizer must not be the requester.
func (s *Service) handlePamDecideCheckoutAuthorization(c *gin.Context) {
	decision := c.Param("decision")
	if decision != "approve" && decision != "deny" {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown decision"})
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	authID := c.Param("id")
	authorizerID := c.GetString("user_id")

	// Load the pending row and enforce authorizer != requester.
	var requesterID, entryID string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT requester_id::text, entry_id::text
		  FROM pam_checkout_authorizations
		 WHERE id = $1 AND org_id = $2 AND status = 'pending' AND expires_at > NOW()`,
		authID, org.ID).Scan(&requesterID, &entryID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "authorization not found or already decided"})
			return
		}
		s.logger.Error("handlePamDecideCheckoutAuthorization: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load authorization"})
		return
	}
	if requesterID == authorizerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "the requester cannot authorize their own checkout (two-person rule)"})
		return
	}

	newStatus := "approved"
	if decision == "deny" {
		newStatus = "denied"
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_checkout_authorizations
		   SET status = $1, authorizer_id = $2, authorizer_reason = NULLIF($3,''), decided_at = NOW()
		 WHERE id = $4 AND org_id = $5 AND status = 'pending'`,
		newStatus, authorizerID, req.Reason, authID, org.ID)
	if err != nil {
		s.logger.Error("handlePamDecideCheckoutAuthorization: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record decision"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "authorization already decided"})
		return
	}
	s.logAuditEvent(c, "pam.checkout_authorization_"+newStatus, entryID, "pam_entry", map[string]interface{}{
		"authorization_id": authID, "requester_id": requesterID, "authorizer_id": authorizerID,
	})
	c.JSON(http.StatusOK, gin.H{"id": authID, "status": newStatus})
}

// ---- Break-glass emergency access ----

// handlePamBreakGlass — POST /pam/entries/:id/break-glass {reason}.
//
// The emergency path: when break_glass_enabled is set, a caller who could
// normally reveal the secret (admin or holds a `reveal` grant) may bypass the
// dual-control wait and the exclusivity hold. It is deliberately loud — a
// high-severity `pam.break_glass` audit event is raised on every use.
func (s *Service) handlePamBreakGlass(c *gin.Context) {
	entryID := c.Param("id")
	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Reason) < 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a break-glass justification of at least 10 characters is required"})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	var secretID string
	var allowReveal, breakGlassEnabled bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(vault_secret_id::text,''), allow_reveal, break_glass_enabled
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, org.ID).
		Scan(&secretID, &allowReveal, &breakGlassEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("handlePamBreakGlass: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		return
	}
	if !breakGlassEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "break-glass is not enabled for this entry"})
		return
	}
	if !allowReveal || secretID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entry has no revealable secret"})
		return
	}
	// Same authorization surface as a normal reveal — break-glass bypasses the
	// dual-control WAIT and the exclusivity HOLD, not the reveal permission.
	if !s.pamCallerIsAdmin(c) {
		ok, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "reveal")
		if aclErr != nil || !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}
	if s.vaultSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault is not configured"})
		return
	}

	pt, err := s.vaultSvc.Reveal(ctx, secretID, userID, pamCallerRoles(c), "BREAK-GLASS: "+req.Reason, true)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "secret not found"})
			return
		}
		s.logger.Error("handlePamBreakGlass: reveal failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reveal secret"})
		return
	}

	// High-severity, unmissable audit trail — this is the whole point of the
	// control. Also record a break-glass checkout in the live ledger.
	s.logAuditEvent(c, "pam.break_glass", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "reason": req.Reason, "user_id": userID, "severity": "high",
	})
	s.pamRecordCheckout(ctx, org.ID, entryID, userID, "break_glass", req.Reason, true)

	c.JSON(http.StatusOK, gin.H{"value": string(pt), "break_glass": true})
	for i := range pt {
		pt[i] = 0
	}
}

// ---- Active-checkout ledger + check-in ----

// PamActiveCheckout is the API view of a live checkout lease.
type PamActiveCheckout struct {
	ID          string     `json:"id"`
	EntryID     string     `json:"entry_id"`
	EntryName   string     `json:"entry_name,omitempty"`
	PrincipalID string     `json:"principal_id"`
	Action      string     `json:"action"`
	Reason      string     `json:"reason,omitempty"`
	BreakGlass  bool       `json:"break_glass"`
	LeasedAt    time.Time  `json:"leased_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// handlePamListActiveCheckouts — GET /pam/checkouts/active (admin). The live
// "who holds what right now" ledger.
func (s *Service) handlePamListActiveCheckouts(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	// Retire expired leases so the live list is accurate.
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE pam_active_checkouts SET status = 'expired', released_at = NOW()
		 WHERE org_id = $1 AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= NOW()`, org.ID)

	rows, err := s.db.Pool.Query(ctx, `
		SELECT ac.id, ac.entry_id::text, COALESCE(e.name,''), ac.principal_id::text, ac.action,
		       COALESCE(ac.reason,''), ac.break_glass, ac.leased_at, ac.expires_at
		  FROM pam_active_checkouts ac
		  LEFT JOIN pam_entries e ON e.id = ac.entry_id
		 WHERE ac.org_id = $1 AND ac.status = 'active'
		 ORDER BY ac.leased_at DESC LIMIT 200`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListActiveCheckouts: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list checkouts"})
		return
	}
	defer rows.Close()
	out := []PamActiveCheckout{}
	for rows.Next() {
		var a PamActiveCheckout
		if err := rows.Scan(&a.ID, &a.EntryID, &a.EntryName, &a.PrincipalID, &a.Action,
			&a.Reason, &a.BreakGlass, &a.LeasedAt, &a.ExpiresAt); err != nil {
			s.logger.Warn("handlePamListActiveCheckouts: scan failed", zap.Error(err))
			continue
		}
		out = append(out, a)
	}
	c.JSON(http.StatusOK, gin.H{"checkouts": out})
}

// handlePamCheckin — POST /pam/entries/:id/checkin. Releases the caller's live
// checkout lease (an admin may release any principal's lease on the entry),
// freeing an exclusive entry for the next user immediately.
func (s *Service) handlePamCheckin(c *gin.Context) {
	entryID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")

	// An admin may release any principal's lease on the entry; a non-admin may
	// release only their own. NULLIF('' ) keeps the admin branch principal-agnostic.
	principalFilter := userID
	if s.pamCallerIsAdmin(c) {
		principalFilter = ""
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_active_checkouts SET status = 'released', released_at = NOW()
		 WHERE org_id = $1 AND entry_id = $2 AND status = 'active'
		   AND ($3 = '' OR principal_id = NULLIF($3,'')::uuid)`,
		org.ID, entryID, principalFilter)
	if err != nil {
		s.logger.Error("handlePamCheckin: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check in"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active checkout to release"})
		return
	}
	s.logAuditEvent(c, "pam.checkout_released", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "released_by": userID, "count": tag.RowsAffected(),
	})
	c.JSON(http.StatusOK, gin.H{"released": tag.RowsAffected()})
}
