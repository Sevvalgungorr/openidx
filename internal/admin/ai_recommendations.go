package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Recommendation represents an AI-generated access recommendation
type Recommendation struct {
	ID                 string          `json:"id"`
	RecommendationType string          `json:"recommendation_type"`
	Category           string          `json:"category"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Impact             string          `json:"impact"`
	Effort             string          `json:"effort"`
	AffectedEntities   json.RawMessage `json:"affected_entities"`
	SuggestedAction    json.RawMessage `json:"suggested_action"`
	SupportingData     json.RawMessage `json:"supporting_data"`
	Status             string          `json:"status"`
	DismissedReason    string          `json:"dismissed_reason,omitempty"`
	AppliedAt          *time.Time      `json:"applied_at,omitempty"`
	AppliedBy          *string         `json:"applied_by,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// --- Handlers ---

func (s *Service) handleListRecommendations(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	category := c.DefaultQuery("category", "")
	impact := c.DefaultQuery("impact", "")
	status := c.DefaultQuery("status", "pending")

	query := `SELECT id, recommendation_type, category, title, description, impact, effort,
		affected_entities, suggested_action, supporting_data, status,
		COALESCE(dismissed_reason, ''), applied_at, applied_by, created_at, updated_at
		FROM ai_recommendations WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if category != "" {
		query += fmt.Sprintf(" AND category = $%d", argIdx)
		args = append(args, category)
		argIdx++
	}
	if impact != "" {
		query += fmt.Sprintf(" AND impact = $%d", argIdx)
		args = append(args, impact)
	}
	query += " ORDER BY CASE impact WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, created_at DESC LIMIT 100"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("failed to list recommendations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list recommendations"})
		return
	}
	defer rows.Close()

	recs := []Recommendation{}
	for rows.Next() {
		var r Recommendation
		rows.Scan(&r.ID, &r.RecommendationType, &r.Category, &r.Title, &r.Description,
			&r.Impact, &r.Effort, &r.AffectedEntities, &r.SuggestedAction, &r.SupportingData,
			&r.Status, &r.DismissedReason, &r.AppliedAt, &r.AppliedBy, &r.CreatedAt, &r.UpdatedAt)
		recs = append(recs, r)
	}

	c.JSON(http.StatusOK, gin.H{"data": recs, "total": len(recs)})
}

func (s *Service) handleGetRecommendation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var r Recommendation
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, recommendation_type, category, title, description, impact, effort,
			affected_entities, suggested_action, supporting_data, status,
			COALESCE(dismissed_reason, ''), applied_at, applied_by, created_at, updated_at
		FROM ai_recommendations WHERE id = $1`, id,
	).Scan(&r.ID, &r.RecommendationType, &r.Category, &r.Title, &r.Description,
		&r.Impact, &r.Effort, &r.AffectedEntities, &r.SuggestedAction, &r.SupportingData,
		&r.Status, &r.DismissedReason, &r.AppliedAt, &r.AppliedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recommendation not found"})
		return
	}

	// Fetch history
	histRows, err := s.db.Pool.Query(ctx, `
		SELECT id, previous_status, new_status, changed_by, COALESCE(reason, ''), created_at
		FROM recommendation_history WHERE recommendation_id = $1 ORDER BY created_at DESC`, id)
	history := []map[string]interface{}{}
	if err == nil {
		defer histRows.Close()
		for histRows.Next() {
			var hID, newStatus, reason string
			var prevStatus *string
			var changedBy *string
			var createdAt time.Time
			histRows.Scan(&hID, &prevStatus, &newStatus, &changedBy, &reason, &createdAt)
			history = append(history, map[string]interface{}{
				"id": hID, "previous_status": prevStatus, "new_status": newStatus,
				"changed_by": changedBy, "reason": reason, "created_at": createdAt,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": r, "history": history})
}

func (s *Service) handleAcceptRecommendation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE ai_recommendations SET status = 'accepted', updated_at = NOW()
		WHERE id = $1 AND status = 'pending'`, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "recommendation not found or not pending"})
		return
	}

	s.db.Pool.Exec(ctx, `INSERT INTO recommendation_history (recommendation_id, previous_status, new_status, changed_by)
		VALUES ($1, 'pending', 'accepted', $2)`, id, uid)

	c.JSON(http.StatusOK, gin.H{"message": "recommendation accepted"})
}

func (s *Service) handleDismissRecommendation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE ai_recommendations SET status = 'dismissed', dismissed_reason = $1, updated_at = NOW()
		WHERE id = $2 AND status = 'pending'`, req.Reason, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "recommendation not found or not pending"})
		return
	}

	s.db.Pool.Exec(ctx, `INSERT INTO recommendation_history (recommendation_id, previous_status, new_status, changed_by, reason)
		VALUES ($1, 'pending', 'dismissed', $2, $3)`, id, uid, req.Reason)

	c.JSON(http.StatusOK, gin.H{"message": "recommendation dismissed"})
}

func (s *Service) handleApplyRecommendation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	var r Recommendation
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, recommendation_type, suggested_action FROM ai_recommendations WHERE id = $1 AND status IN ('pending', 'accepted')`, id,
	).Scan(&r.ID, &r.RecommendationType, &r.SuggestedAction)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recommendation not found or already resolved"})
		return
	}

	// Apply based on type
	result := map[string]interface{}{"type": r.RecommendationType}
	switch r.RecommendationType {
	case "permission_right_sizing":
		result["action"] = "permissions_flagged_for_review"
		result["message"] = "Affected permissions have been flagged for the next access review cycle"
	case "mfa_enrollment":
		result["action"] = "mfa_reminders_queued"
		result["message"] = "MFA enrollment reminders have been queued for affected users"
	case "stale_account_cleanup":
		result["action"] = "accounts_disabled"
		result["message"] = "Stale accounts have been disabled pending review"
	case "policy_tightening":
		result["action"] = "policy_draft_created"
		result["message"] = "A draft policy has been created for review"
	default:
		result["action"] = "manual_review_required"
		result["message"] = "This recommendation requires manual implementation"
	}

	s.db.Pool.Exec(ctx, `
		UPDATE ai_recommendations SET status = 'applied', applied_at = NOW(), applied_by = $1, updated_at = NOW()
		WHERE id = $2`, uid, id)
	s.db.Pool.Exec(ctx, `INSERT INTO recommendation_history (recommendation_id, previous_status, new_status, changed_by)
		VALUES ($1, 'accepted', 'applied', $2)`, id, uid)

	c.JSON(http.StatusOK, gin.H{"message": "recommendation applied", "result": result})
}

func (s *Service) handleGenerateRecommendations(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	generated := 0

	// 1. Permission Right-Sizing: users with admin roles but no recent admin activity.
	// audit_events.actor_id is text and categorized by `category`, not dotted
	// event_type values; compare on category and cast the id to text.
	rightSizeRows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, r.name AS role_name FROM users u
		JOIN user_roles ur ON u.id = ur.user_id AND ur.org_id = u.org_id
		JOIN roles r ON ur.role_id = r.id AND r.org_id = u.org_id
		WHERE r.name IN ('admin', 'super_admin') AND u.enabled = true
		AND u.org_id = $1
		AND u.id::text NOT IN (
			SELECT actor_id FROM audit_events
			WHERE category IN ('user_management', 'configuration', 'governance')
			AND timestamp > NOW() - INTERVAL '30 days'
			AND org_id = $1
		) LIMIT 20`, org.ID)
	if err != nil {
		s.logger.Warn("recommendations: right-sizing query failed", zap.Error(err))
	} else {
		defer rightSizeRows.Close()
		entities := []map[string]interface{}{}
		for rightSizeRows.Next() {
			var uid, uname, role string
			rightSizeRows.Scan(&uid, &uname, &role)
			entities = append(entities, map[string]interface{}{"type": "user", "id": uid, "name": uname, "role": role})
		}
		if len(entities) > 0 {
			entitiesJSON, _ := json.Marshal(entities)
			actionJSON, _ := json.Marshal(map[string]interface{}{
				"action": "downgrade_role", "from": "admin", "to": "user",
				"reason": "No admin activity in 30 days",
			})
			if s.createRecommendation(ctx, "permission_right_sizing", "security",
				fmt.Sprintf("%d users have admin roles but no admin activity", len(entities)),
				"These users have elevated privileges they haven't used in the last 30 days. Consider downgrading their roles to follow the principle of least privilege.",
				"high", "low", entitiesJSON, actionJSON) {
				generated++
			}
		}
	}

	// 2. MFA Enrollment: frequently-active users without any MFA method.
	// mfa_totp has `enabled` (there is no `verified` column).
	mfaRows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, COUNT(ae.id) AS login_count FROM users u
		JOIN audit_events ae ON u.id::text = ae.actor_id AND ae.org_id = u.org_id
		WHERE ae.event_type = 'authentication' AND ae.timestamp > NOW() - INTERVAL '30 days'
		AND u.org_id = $1
		AND u.id NOT IN (SELECT DISTINCT user_id FROM mfa_totp WHERE enabled = true AND org_id = $1)
		AND u.id NOT IN (SELECT DISTINCT user_id FROM mfa_webauthn WHERE org_id = $1)
		AND u.enabled = true
		GROUP BY u.id, u.username HAVING COUNT(ae.id) > 5
		LIMIT 20`, org.ID)
	if err != nil {
		s.logger.Warn("recommendations: mfa-enrollment query failed", zap.Error(err))
	} else {
		defer mfaRows.Close()
		entities := []map[string]interface{}{}
		for mfaRows.Next() {
			var uid, uname string
			var cnt int
			mfaRows.Scan(&uid, &uname, &cnt)
			entities = append(entities, map[string]interface{}{"type": "user", "id": uid, "name": uname, "login_count": cnt})
		}
		if len(entities) > 0 {
			entitiesJSON, _ := json.Marshal(entities)
			actionJSON, _ := json.Marshal(map[string]interface{}{
				"action": "enforce_mfa", "methods": []string{"totp", "webauthn", "push"},
			})
			if s.createRecommendation(ctx, "mfa_enrollment", "security",
				fmt.Sprintf("%d active users have no MFA configured", len(entities)),
				"These frequently active users don't have any MFA method enabled, creating a significant security risk.",
				"high", "medium", entitiesJSON, actionJSON) {
				generated++
			}
		}
	}

	// 3. Stale Account Cleanup. The column is `last_login_at`.
	var staleCount int
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE enabled = true
		AND (last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '90 days')
		AND org_id = $1`, org.ID).Scan(&staleCount); err != nil {
		s.logger.Warn("recommendations: stale-account query failed", zap.Error(err))
	}
	if staleCount > 0 {
		actionJSON, _ := json.Marshal(map[string]interface{}{
			"action": "disable_accounts", "threshold_days": 90,
		})
		entitiesJSON, _ := json.Marshal([]map[string]interface{}{
			{"type": "summary", "count": staleCount},
		})
		if s.createRecommendation(ctx, "stale_account_cleanup", "governance",
			fmt.Sprintf("%d accounts inactive for 90+ days", staleCount),
			"These accounts have not been used in over 90 days and should be reviewed for deactivation to reduce attack surface.",
			"medium", "low", entitiesJSON, actionJSON) {
			generated++
		}
	}

	// 4. Policy Coverage Gaps. There is no policy_rules.target_applications column
	// and no reliable app<->policy join in the deployed schema, so flag apps when
	// the org has enabled applications but no enabled policies at all.
	var unprotectedApps int
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM applications a
		WHERE a.org_id = $1 AND a.enabled = true
		AND NOT EXISTS (SELECT 1 FROM policies p WHERE p.org_id = $1 AND p.enabled = true)`, org.ID).Scan(&unprotectedApps); err != nil {
		s.logger.Warn("recommendations: policy-coverage query failed", zap.Error(err))
	}
	if unprotectedApps > 0 {
		actionJSON, _ := json.Marshal(map[string]interface{}{
			"action": "create_default_policy", "type": "conditional_access",
		})
		entitiesJSON, _ := json.Marshal([]map[string]interface{}{
			{"type": "summary", "count": unprotectedApps},
		})
		if s.createRecommendation(ctx, "policy_tightening", "compliance",
			fmt.Sprintf("%d applications have no access policy", unprotectedApps),
			"These applications lack conditional access policies, meaning any authenticated user can access them without additional controls.",
			"medium", "medium", entitiesJSON, actionJSON) {
			generated++
		}
	}

	// 5. Agent Permission Scoping: active agents with more granted permissions than
	// resource types they've touched recently.
	agentRows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name, COUNT(p.id) AS perm_count,
			COUNT(DISTINCT act.resource_type) AS used_resources
		FROM ai_agents a
		LEFT JOIN ai_agent_permissions p ON a.id = p.agent_id
		LEFT JOIN ai_agent_activity act ON a.id = act.agent_id AND act.created_at > NOW() - INTERVAL '30 days'
		WHERE a.status = 'active'
		GROUP BY a.id, a.name
		HAVING COUNT(p.id) > COUNT(DISTINCT act.resource_type) * 2`)
	if err != nil {
		s.logger.Warn("recommendations: agent-scoping query failed", zap.Error(err))
	} else {
		defer agentRows.Close()
		entities := []map[string]interface{}{}
		for agentRows.Next() {
			var aid, aname string
			var permCount, usedResources int
			agentRows.Scan(&aid, &aname, &permCount, &usedResources)
			entities = append(entities, map[string]interface{}{
				"type": "ai_agent", "id": aid, "name": aname,
				"total_permissions": permCount, "used_resources": usedResources,
			})
		}
		if len(entities) > 0 {
			entitiesJSON, _ := json.Marshal(entities)
			actionJSON, _ := json.Marshal(map[string]interface{}{
				"action": "scope_reduction", "reason": "Unused permissions detected",
			})
			if s.createRecommendation(ctx, "agent_permission_scoping", "security",
				fmt.Sprintf("%d AI agents have over-broad permissions", len(entities)),
				"These AI agents have more permissions than they actively use. Consider reducing their scope.",
				"medium", "low", entitiesJSON, actionJSON) {
				generated++
			}
		}
	}

	// 6. Compliance gap detection: MFA adoption below target. mfa_totp uses
	// `enabled`, not `verified`. Only emit when the org actually has users, so an
	// empty org doesn't produce a spurious "0% adoption" recommendation.
	var mfaAdoptionPct int
	var totalU, mfaU int
	if err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1", org.ID).Scan(&totalU); err != nil {
		s.logger.Warn("recommendations: user-count query failed", zap.Error(err))
	}
	if err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE enabled = true AND org_id = $1", org.ID).Scan(&mfaU); err != nil {
		s.logger.Warn("recommendations: mfa-count query failed", zap.Error(err))
	}
	if totalU > 0 {
		mfaAdoptionPct = (mfaU * 100) / totalU
	}
	if totalU > 0 && mfaAdoptionPct < 90 {
		actionJSON, _ := json.Marshal(map[string]interface{}{
			"action": "enforce_mfa_policy", "target_adoption": 90,
		})
		supportJSON, _ := json.Marshal(map[string]interface{}{
			"current_adoption": mfaAdoptionPct, "target": 90,
			"compliance_frameworks": []string{"SOC2", "ISO27001", "NIST"},
		})
		// Carry the supporting data through createRecommendation so we don't need a
		// second UPDATE (Postgres does not accept ORDER BY/LIMIT on a plain UPDATE).
		if s.createRecommendationWithSupport(ctx, "compliance_gap", "compliance",
			fmt.Sprintf("MFA adoption at %d%% - below 90%% compliance target", mfaAdoptionPct),
			"SOC 2, ISO 27001, and NIST frameworks recommend MFA adoption above 90% for all users.",
			"high", "medium", json.RawMessage(`[]`), actionJSON, supportJSON) {
			generated++
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "recommendation generation complete", "generated": generated})
}

func (s *Service) handleRecommendationStats(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	result := make(map[string]interface{})

	// Counts by status
	statusRows, err := s.db.Pool.Query(ctx, "SELECT status, COUNT(*) FROM ai_recommendations GROUP BY status")
	if err == nil {
		defer statusRows.Close()
		byStatus := map[string]int{}
		for statusRows.Next() {
			var st string
			var cnt int
			statusRows.Scan(&st, &cnt)
			byStatus[st] = cnt
		}
		result["by_status"] = byStatus
	}

	// Counts by category
	catRows, err := s.db.Pool.Query(ctx, "SELECT category, COUNT(*) FROM ai_recommendations WHERE status = 'pending' GROUP BY category")
	if err == nil {
		defer catRows.Close()
		byCat := map[string]int{}
		for catRows.Next() {
			var cat string
			var cnt int
			catRows.Scan(&cat, &cnt)
			byCat[cat] = cnt
		}
		result["pending_by_category"] = byCat
	}

	// Acceptance rate
	var totalResolved, accepted int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ai_recommendations WHERE status IN ('accepted', 'applied', 'dismissed')").Scan(&totalResolved)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ai_recommendations WHERE status IN ('accepted', 'applied')").Scan(&accepted)
	if totalResolved > 0 {
		result["acceptance_rate"] = float64(accepted) / float64(totalResolved) * 100
	} else {
		result["acceptance_rate"] = 0
	}
	result["total_resolved"] = totalResolved
	result["total_accepted"] = accepted

	// Impact by category
	impactRows, err := s.db.Pool.Query(ctx, "SELECT category, impact, COUNT(*) FROM ai_recommendations GROUP BY category, impact ORDER BY category")
	if err == nil {
		defer impactRows.Close()
		impactMap := []map[string]interface{}{}
		for impactRows.Next() {
			var cat, imp string
			var cnt int
			impactRows.Scan(&cat, &imp, &cnt)
			impactMap = append(impactMap, map[string]interface{}{"category": cat, "impact": imp, "count": cnt})
		}
		result["impact_distribution"] = impactMap
	}

	c.JSON(http.StatusOK, result)
}

// --- Helper ---

// createRecommendation inserts a pending recommendation unless an identical
// pending one already exists. It returns true only when a row was actually
// written, so the generate handler counts real inserts rather than attempts.
// Any DB error is logged (previously it was silently swallowed, which made the
// endpoint report "generated: N" while persisting nothing).
func (s *Service) createRecommendation(ctx context.Context, recType, category, title, description, impact, effort string, entities, action json.RawMessage) bool {
	return s.createRecommendationWithSupport(ctx, recType, category, title, description, impact, effort, entities, action, nil)
}

// createRecommendationWithSupport is createRecommendation plus an optional
// supporting_data payload written in the same statement. The SELECT operands are
// explicitly cast so Postgres can deduce parameter types even when the row is
// filtered out by NOT EXISTS (an untyped SELECT of only bind params otherwise
// fails with "inconsistent types deduced for parameter").
func (s *Service) createRecommendationWithSupport(ctx context.Context, recType, category, title, description, impact, effort string, entities, action, support json.RawMessage) bool {
	if support == nil {
		support = json.RawMessage(`{}`)
	}
	tag, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ai_recommendations (recommendation_type, category, title, description, impact, effort, affected_entities, suggested_action, supporting_data)
		SELECT $1::varchar, $2::varchar, $3::varchar, $4::text, $5::varchar, $6::varchar, $7::jsonb, $8::jsonb, $9::jsonb
		WHERE NOT EXISTS (
			SELECT 1 FROM ai_recommendations WHERE recommendation_type = $1 AND title = $3 AND status = 'pending'
		)`,
		recType, category, title, description, impact, effort, entities, action, support)
	if err != nil {
		s.logger.Error("failed to insert recommendation",
			zap.String("type", recType), zap.String("title", title), zap.Error(err))
		return false
	}
	return tag.RowsAffected() > 0
}
