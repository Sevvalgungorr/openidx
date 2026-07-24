// Detective segregation-of-duties (SoD) — migration v106.
//
// evaluateSoDPolicy is a PREVENTIVE control: it blocks a new access request that
// would hand a user a conflicting role. This file adds the DETECTIVE half an
// SOX/ISAE/DORA audit expects — a sweep that scans the EXISTING state (who holds
// what right now) against every separation_of_duty policy and records each user
// who already holds a toxic combination, tracking it to closure.
//
// The sweep is idempotent: it upserts into sod_violations keyed on
// (org, policy, user), refreshes last_detected_at on re-detection, reopens a
// 'resolved' violation whose conflict returned, and auto-resolves an
// open/acknowledged violation whose conflict is gone. 'waived' is sticky.
package governance

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// sodConflictSet is one policy rule's set of mutually-exclusive assignment names
// (role or group names), lowercased for case-insensitive matching — the same
// normalization evaluateSoDPolicy uses on the preventive side.
type sodConflictSet struct {
	policyID   string
	policyName string
	names      []string // display names (original case), for the recorded detail
	lower      []string // lowercased, for matching
}

// loadSoDConflictSets reads the org's enabled separation_of_duty policies and
// flattens their conflicting_roles rules into conflict sets.
func (s *Service) loadSoDConflictSets(ctx context.Context, orgID string) ([]sodConflictSet, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT p.id, p.name, pr.conditions
		  FROM policies p
		  JOIN policy_rules pr ON pr.policy_id = p.id
		 WHERE p.org_id = $1 AND pr.org_id = $1
		   AND p.type = 'separation_of_duty' AND p.enabled = true`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sets []sodConflictSet
	for rows.Next() {
		var policyID, policyName string
		var condition map[string]interface{}
		if err := rows.Scan(&policyID, &policyName, &condition); err != nil {
			s.logger.Warn("loadSoDConflictSets: scan failed", zap.Error(err))
			continue
		}
		raw, ok := condition["conflicting_roles"].([]interface{})
		if !ok || len(raw) < 2 {
			continue
		}
		set := sodConflictSet{policyID: policyID, policyName: policyName}
		for _, v := range raw {
			name, ok := v.(string)
			if !ok || strings.TrimSpace(name) == "" {
				continue
			}
			set.names = append(set.names, name)
			set.lower = append(set.lower, strings.ToLower(strings.TrimSpace(name)))
		}
		if len(set.lower) >= 2 {
			sets = append(sets, set)
		}
	}
	return sets, rows.Err()
}

// loadUserAssignments builds, per user, the lowercased set of every role name
// and group name the user currently holds. SoD conflicts may be expressed in
// terms of either, so both feed the same set.
func (s *Service) loadUserAssignments(ctx context.Context, orgID string) (map[string]map[string]bool, error) {
	assignments := map[string]map[string]bool{}
	add := func(userID, name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if assignments[userID] == nil {
			assignments[userID] = map[string]bool{}
		}
		assignments[userID][name] = true
	}

	roleRows, err := s.db.Pool.Query(ctx, `
		SELECT ur.user_id::text, r.name
		  FROM user_roles ur
		  JOIN roles r ON r.id = ur.role_id
		  JOIN users u ON u.id = ur.user_id
		 WHERE u.enabled = true AND u.org_id = $1 AND ur.org_id = $1 AND r.org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	for roleRows.Next() {
		var userID, name string
		if err := roleRows.Scan(&userID, &name); err != nil {
			roleRows.Close()
			return nil, err
		}
		add(userID, name)
	}
	roleRows.Close()

	groupRows, err := s.db.Pool.Query(ctx, `
		SELECT gm.user_id::text, g.name
		  FROM group_memberships gm
		  JOIN groups g ON g.id = gm.group_id
		  JOIN users u ON u.id = gm.user_id
		 WHERE u.enabled = true AND u.org_id = $1 AND gm.org_id = $1 AND g.org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer groupRows.Close()
	for groupRows.Next() {
		var userID, name string
		if err := groupRows.Scan(&userID, &name); err != nil {
			return nil, err
		}
		add(userID, name)
	}
	return assignments, groupRows.Err()
}

// SoDSweepResult summarizes one detective sweep.
type SoDSweepResult struct {
	PoliciesEvaluated int       `json:"policies_evaluated"`
	UsersScanned      int       `json:"users_scanned"`
	ViolationsFound   int       `json:"violations_found"`
	NewViolations     int       `json:"new_violations"`
	AutoResolved      int       `json:"auto_resolved"`
	SweptAt           time.Time `json:"swept_at"`
}

// RunSoDSweep scans the org's current assignments against every enabled SoD
// policy and reconciles the sod_violations register. Reusable by an on-demand
// endpoint and (future) a scheduled worker.
func (s *Service) RunSoDSweep(ctx context.Context, orgID string) (*SoDSweepResult, error) {
	sweepStart := time.Now()
	res := &SoDSweepResult{SweptAt: sweepStart}

	sets, err := s.loadSoDConflictSets(ctx, orgID)
	if err != nil {
		return nil, err
	}
	res.PoliciesEvaluated = len(sets)
	if len(sets) == 0 {
		return res, nil
	}

	assignments, err := s.loadUserAssignments(ctx, orgID)
	if err != nil {
		return nil, err
	}
	res.UsersScanned = len(assignments)

	for userID, held := range assignments {
		for _, set := range sets {
			if !sodAllPresent(set.lower, held) {
				continue
			}
			res.ViolationsFound++
			isNew, err := s.upsertSoDViolation(ctx, orgID, set, userID)
			if err != nil {
				s.logger.Warn("RunSoDSweep: upsert failed",
					zap.String("policy_id", set.policyID), zap.String("user_id", userID), zap.Error(err))
				continue
			}
			if isNew {
				res.NewViolations++
			}
		}
	}

	// Auto-resolve open/acknowledged violations whose conflict is gone: they were
	// not refreshed this sweep, so last_detected_at predates sweepStart. 'waived'
	// is never touched.
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE sod_violations
		   SET status = 'resolved', resolved_at = NOW(), resolved_by = NULL,
		       notes = COALESCE(notes,'') || ' [auto-resolved: conflict no longer present]'
		 WHERE org_id = $1 AND status IN ('open','acknowledged') AND last_detected_at < $2`,
		orgID, sweepStart)
	if err != nil {
		return nil, err
	}
	res.AutoResolved = int(tag.RowsAffected())
	return res, nil
}

// sodAllPresent reports whether every name in the conflict set is held.
func sodAllPresent(conflict []string, held map[string]bool) bool {
	for _, name := range conflict {
		if !held[name] {
			return false
		}
	}
	return true
}

// upsertSoDViolation records (or refreshes) one violation. Returns true when the
// row was newly created. A returning 'resolved' row is reopened; 'waived' and
// 'acknowledged' keep their status but get last_detected_at refreshed.
func (s *Service) upsertSoDViolation(ctx context.Context, orgID string, set sodConflictSet, userID string) (bool, error) {
	names := append([]string(nil), set.names...)
	sort.Strings(names)
	detail := "holds conflicting: " + strings.Join(names, " + ")

	// xmax = 0 on the returned row identifies a fresh INSERT (no prior tuple
	// version); a non-zero xmax means the ON CONFLICT UPDATE path fired.
	var inserted bool
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO sod_violations (org_id, policy_id, policy_name, user_id, conflicting_roles, detail, status)
		VALUES ($1,$2,$3,$4,$5,$6,'open')
		ON CONFLICT (org_id, policy_id, user_id) DO UPDATE
		   SET last_detected_at = NOW(),
		       conflicting_roles = EXCLUDED.conflicting_roles,
		       detail = EXCLUDED.detail,
		       policy_name = EXCLUDED.policy_name,
		       status = CASE WHEN sod_violations.status = 'resolved' THEN 'open' ELSE sod_violations.status END,
		       resolved_at = CASE WHEN sod_violations.status = 'resolved' THEN NULL ELSE sod_violations.resolved_at END
		RETURNING (xmax = 0) AS inserted`,
		orgID, set.policyID, set.policyName, userID, names, detail).Scan(&inserted)
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// ---- HTTP handlers ----

// handleRunSoDSweep — POST /governance/sod/sweep. Runs the detective sweep now.
func (s *Service) handleRunSoDSweep(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	res, err := s.RunSoDSweep(ctx, org.ID)
	if err != nil {
		s.logger.Error("handleRunSoDSweep: sweep failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sod sweep failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// SoDViolation is the API view of a sod_violations row.
type SoDViolation struct {
	ID               string    `json:"id"`
	PolicyID         string    `json:"policy_id"`
	PolicyName       string    `json:"policy_name"`
	UserID           string    `json:"user_id"`
	UserEmail        string    `json:"user_email,omitempty"`
	ConflictingRoles []string  `json:"conflicting_roles"`
	Status           string    `json:"status"`
	Detail           string    `json:"detail,omitempty"`
	FirstDetectedAt  time.Time `json:"first_detected_at"`
	LastDetectedAt   time.Time `json:"last_detected_at"`
	Notes            string    `json:"notes,omitempty"`
}

// handleListSoDViolations — GET /governance/sod/violations?status=open.
func (s *Service) handleListSoDViolations(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	status := c.Query("status")
	q := `
		SELECT v.id, v.policy_id::text, COALESCE(v.policy_name,''), v.user_id::text, COALESCE(u.email,''),
		       v.conflicting_roles, v.status, COALESCE(v.detail,''), v.first_detected_at, v.last_detected_at,
		       COALESCE(v.notes,'')
		  FROM sod_violations v
		  LEFT JOIN users u ON u.id = v.user_id
		 WHERE v.org_id = $1`
	args := []interface{}{org.ID}
	if status != "" {
		q += ` AND v.status = $2`
		args = append(args, status)
	}
	q += ` ORDER BY v.last_detected_at DESC LIMIT 500`

	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("handleListSoDViolations: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list violations"})
		return
	}
	defer rows.Close()
	out := []SoDViolation{}
	for rows.Next() {
		var v SoDViolation
		if err := rows.Scan(&v.ID, &v.PolicyID, &v.PolicyName, &v.UserID, &v.UserEmail,
			&v.ConflictingRoles, &v.Status, &v.Detail, &v.FirstDetectedAt, &v.LastDetectedAt, &v.Notes); err != nil {
			s.logger.Warn("handleListSoDViolations: scan failed", zap.Error(err))
			continue
		}
		out = append(out, v)
	}
	c.JSON(http.StatusOK, gin.H{"violations": out})
}

// sodViolationStatuses is the closed set of statuses a caller may set.
var sodViolationStatuses = map[string]bool{"open": true, "acknowledged": true, "resolved": true, "waived": true}

// handleUpdateSoDViolationStatus — POST /governance/sod/violations/:id/status.
func (s *Service) handleUpdateSoDViolationStatus(c *gin.Context) {
	var req struct {
		Status string `json:"status" binding:"required"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !sodViolationStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of open, acknowledged, resolved, waived"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	actor := c.GetString("user_id")
	resolved := req.Status == "resolved" || req.Status == "waived"
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE sod_violations
		   SET status = $1,
		       notes = NULLIF($2,''),
		       resolved_at = CASE WHEN $3 THEN NOW() ELSE NULL END,
		       resolved_by = CASE WHEN $3 THEN NULLIF($4,'')::uuid ELSE NULL END
		 WHERE id = $5 AND org_id = $6`,
		req.Status, req.Notes, resolved, actor, c.Param("id"), org.ID)
	if err != nil {
		s.logger.Error("handleUpdateSoDViolationStatus: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update violation"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "violation not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": req.Status})
}

// handleSoDStatistics — GET /governance/sod/statistics. The violation-dashboard
// summary: counts by status and the top offending policies.
func (s *Service) handleSoDStatistics(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	byStatus := map[string]int{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT status, COUNT(*) FROM sod_violations WHERE org_id = $1 GROUP BY status`, org.ID)
	if err != nil {
		s.logger.Error("handleSoDStatistics: status query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load statistics"})
		return
	}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			continue
		}
		byStatus[st] = n
	}
	rows.Close()

	type policyCount struct {
		PolicyID   string `json:"policy_id"`
		PolicyName string `json:"policy_name"`
		OpenCount  int    `json:"open_count"`
	}
	top := []policyCount{}
	prows, err := s.db.Pool.Query(ctx, `
		SELECT policy_id::text, COALESCE(policy_name,''), COUNT(*)
		  FROM sod_violations
		 WHERE org_id = $1 AND status IN ('open','acknowledged')
		 GROUP BY policy_id, policy_name
		 ORDER BY COUNT(*) DESC LIMIT 10`, org.ID)
	if err == nil {
		for prows.Next() {
			var pc policyCount
			if err := prows.Scan(&pc.PolicyID, &pc.PolicyName, &pc.OpenCount); err == nil {
				top = append(top, pc)
			}
		}
		prows.Close()
	}

	c.JSON(http.StatusOK, gin.H{
		"by_status":    byStatus,
		"open":         byStatus["open"],
		"acknowledged": byStatus["acknowledged"],
		"top_policies": top,
		"unresolved":   byStatus["open"] + byStatus["acknowledged"],
	})
}
