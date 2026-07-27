package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// PostureCheck represents a device posture check configuration
type PostureCheck struct {
	ID              string                 `json:"id"`
	ZitiID          string                 `json:"ziti_id,omitempty"`
	Name            string                 `json:"name"`
	CheckType       string                 `json:"check_type"`
	Parameters      map[string]interface{} `json:"parameters"`
	Enabled         bool                   `json:"enabled"`
	Severity        string                 `json:"severity"`
	RemediationHint string                 `json:"remediation_hint,omitempty"`
	// Platforms scopes the check to specific device platforms (e.g. ["android"],
	// ["ios"], ["android","ios"]). Empty/nil means all platforms — the agent
	// config endpoint treats a NULL platforms column as "runs everywhere".
	Platforms []string  `json:"platforms,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PostureCheckResult represents the outcome of a posture check evaluation for an identity
type PostureCheckResult struct {
	ID         string                 `json:"id"`
	IdentityID string                 `json:"identity_id"`
	CheckID    string                 `json:"check_id"`
	Passed     bool                   `json:"passed"`
	Details    map[string]interface{} `json:"details"`
	CheckedAt  time.Time              `json:"checked_at"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
}

// PolicySyncState tracks synchronization between governance policies and Ziti service policies
type PolicySyncState struct {
	ID                 string                 `json:"id"`
	GovernancePolicyID string                 `json:"governance_policy_id"`
	ZitiPolicyID       string                 `json:"ziti_policy_id,omitempty"`
	SyncType           string                 `json:"sync_type"`
	Status             string                 `json:"status"`
	LastSyncedAt       *time.Time             `json:"last_synced_at,omitempty"`
	LastError          string                 `json:"last_error,omitempty"`
	Config             map[string]interface{} `json:"config"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// mapCheckTypeToZiti converts an internal check type to the Ziti posture check type identifier
func mapCheckTypeToZiti(checkType string) string {
	switch checkType {
	case "OS":
		return "OS"
	case "Domain":
		return "DOMAIN"
	case "MFA":
		return "MFA"
	case "Process":
		return "PROCESS"
	case "MAC":
		return "MAC"
	default:
		return checkType
	}
}

// buildZitiPostureCheckBody builds the Ziti management API request body for a posture check
func buildZitiPostureCheckBody(check *PostureCheck) map[string]interface{} {
	body := map[string]interface{}{
		"name":   check.Name,
		"typeId": mapCheckTypeToZiti(check.CheckType),
		"tags":   map[string]interface{}{"openidx_id": check.ID},
	}

	switch check.CheckType {
	case "OS":
		if operatingSystems, ok := check.Parameters["operating_systems"]; ok {
			body["operatingSystems"] = operatingSystems
		}
	case "Domain":
		if domains, ok := check.Parameters["domains"]; ok {
			body["domains"] = domains
		}
	case "MFA":
		if timeoutSeconds, ok := check.Parameters["timeout_seconds"]; ok {
			body["timeoutSeconds"] = timeoutSeconds
		}
		if promptOnWake, ok := check.Parameters["prompt_on_wake"]; ok {
			body["promptOnWake"] = promptOnWake
		}
		if promptOnUnlock, ok := check.Parameters["prompt_on_unlock"]; ok {
			body["promptOnUnlock"] = promptOnUnlock
		}
		if ignoreLegacyEndpoints, ok := check.Parameters["ignore_legacy_endpoints"]; ok {
			body["ignoreLegacyEndpoints"] = ignoreLegacyEndpoints
		}
	case "Process":
		if process, ok := check.Parameters["process"]; ok {
			body["process"] = process
		}
	case "MAC":
		if macAddresses, ok := check.Parameters["mac_addresses"]; ok {
			body["macAddresses"] = macAddresses
		}
	}

	return body
}

// CreatePostureCheck inserts a posture check into the database and creates it in the Ziti controller
func (zm *ZitiManager) CreatePostureCheck(ctx context.Context, check *PostureCheck) error {
	if check.ID == "" {
		check.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	check.CreatedAt = now
	check.UpdatedAt = now

	paramsJSON, err := json.Marshal(check.Parameters)
	if err != nil {
		return fmt.Errorf("failed to marshal posture check parameters: %w", err)
	}

	// Create in Ziti controller
	zitiBody, err := json.Marshal(buildZitiPostureCheckBody(check))
	if err != nil {
		return fmt.Errorf("failed to marshal ziti posture check body: %w", err)
	}

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/posture-checks", zitiBody)
	if err != nil {
		return fmt.Errorf("failed to create posture check in ziti controller: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d creating posture check in ziti: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse ziti posture check response: %w", err)
	}
	check.ZitiID = resp.Data.ID

	// Insert into database
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	// platforms is stored as a JSONB array; nil => NULL => "all platforms".
	var platformsJSON []byte
	if len(check.Platforms) > 0 {
		platformsJSON, _ = json.Marshal(check.Platforms)
	}
	_, err = zm.db.Pool.Exec(ctx,
		`INSERT INTO posture_checks (id, ziti_id, name, check_type, parameters, enabled, severity, remediation_hint, platforms, created_at, updated_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		check.ID, check.ZitiID, check.Name, check.CheckType, paramsJSON,
		check.Enabled, check.Severity, check.RemediationHint, platformsJSON, check.CreatedAt, check.UpdatedAt, orgID)
	if err != nil {
		// Attempt to clean up the Ziti resource on DB failure
		zm.mgmtRequest("DELETE", fmt.Sprintf("/edge/management/v1/posture-checks/%s", check.ZitiID), nil)
		return fmt.Errorf("failed to insert posture check into database: %w", err)
	}

	zm.logger.Info("Created posture check",
		zap.String("id", check.ID),
		zap.String("ziti_id", check.ZitiID),
		zap.String("type", check.CheckType))
	return nil
}

// ListPostureChecks returns all posture checks from the database
func (zm *ZitiManager) ListPostureChecks(ctx context.Context) ([]PostureCheck, error) {
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT id, ziti_id, name, check_type, parameters, enabled, severity, remediation_hint, platforms, created_at, updated_at
		 FROM posture_checks WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query posture checks: %w", err)
	}
	defer rows.Close()

	var checks []PostureCheck
	for rows.Next() {
		var c PostureCheck
		var paramsJSON []byte
		var platformsJSON []byte
		err := rows.Scan(&c.ID, &c.ZitiID, &c.Name, &c.CheckType, &paramsJSON,
			&c.Enabled, &c.Severity, &c.RemediationHint, &platformsJSON, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan posture check row: %w", err)
		}
		if paramsJSON != nil {
			if err := json.Unmarshal(paramsJSON, &c.Parameters); err != nil {
				zm.logger.Warn("Failed to unmarshal posture check parameters", zap.String("check_id", c.ID), zap.Error(err))
			}
		}
		if c.Parameters == nil {
			c.Parameters = make(map[string]interface{})
		}
		if platformsJSON != nil {
			if err := json.Unmarshal(platformsJSON, &c.Platforms); err != nil {
				zm.logger.Warn("Failed to unmarshal posture check platforms", zap.String("check_id", c.ID), zap.Error(err))
			}
		}
		checks = append(checks, c)
	}

	if checks == nil {
		checks = []PostureCheck{}
	}
	return checks, nil
}

// DeletePostureCheck removes a posture check from the database and the Ziti controller
func (zm *ZitiManager) DeletePostureCheck(ctx context.Context, id string) error {
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	// Look up the Ziti ID before deleting
	var zitiID string
	err := zm.db.Pool.QueryRow(ctx,
		"SELECT ziti_id FROM posture_checks WHERE id=$1 AND org_id=$2", id, orgID).Scan(&zitiID)
	if err != nil {
		return fmt.Errorf("failed to find posture check %s: %w", id, err)
	}

	// Delete from Ziti controller
	if zitiID != "" {
		_, statusCode, err := zm.mgmtRequest("DELETE",
			fmt.Sprintf("/edge/management/v1/posture-checks/%s", zitiID), nil)
		if err != nil {
			zm.logger.Warn("Failed to delete posture check from ziti controller",
				zap.String("ziti_id", zitiID), zap.Error(err))
		} else if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
			zm.logger.Warn("Unexpected status deleting posture check from ziti",
				zap.String("ziti_id", zitiID), zap.Int("status", statusCode))
		}
	}

	// Delete from database
	_, err = zm.db.Pool.Exec(ctx, "DELETE FROM posture_checks WHERE id=$1 AND org_id=$2", id, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete posture check from database: %w", err)
	}

	zm.logger.Info("Deleted posture check", zap.String("id", id), zap.String("ziti_id", zitiID))
	return nil
}

// UpdatePostureCheck updates a posture check in both the database and the Ziti controller
func (zm *ZitiManager) UpdatePostureCheck(ctx context.Context, id string, check *PostureCheck) error {
	check.UpdatedAt = time.Now().UTC()

	paramsJSON, err := json.Marshal(check.Parameters)
	if err != nil {
		return fmt.Errorf("failed to marshal posture check parameters: %w", err)
	}

	// Get current Ziti ID
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	var zitiID string
	err = zm.db.Pool.QueryRow(ctx,
		"SELECT ziti_id FROM posture_checks WHERE id=$1 AND org_id=$2", id, orgID).Scan(&zitiID)
	if err != nil {
		return fmt.Errorf("failed to find posture check %s: %w", id, err)
	}

	// Update in Ziti controller
	if zitiID != "" {
		check.ID = id
		zitiBody, err := json.Marshal(buildZitiPostureCheckBody(check))
		if err != nil {
			return fmt.Errorf("failed to marshal ziti posture check body: %w", err)
		}

		_, statusCode, err := zm.mgmtRequest("PUT",
			fmt.Sprintf("/edge/management/v1/posture-checks/%s", zitiID), zitiBody)
		if err != nil {
			return fmt.Errorf("failed to update posture check in ziti controller: %w", err)
		}
		if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
			zm.logger.Warn("Unexpected status updating posture check in ziti",
				zap.String("ziti_id", zitiID), zap.Int("status", statusCode))
		}
	}

	// Update in database
	var platformsJSON []byte
	if len(check.Platforms) > 0 {
		platformsJSON, _ = json.Marshal(check.Platforms)
	}
	_, err = zm.db.Pool.Exec(ctx,
		`UPDATE posture_checks
		 SET name=$1, check_type=$2, parameters=$3, enabled=$4, severity=$5, remediation_hint=$6, platforms=$7, updated_at=$8
		 WHERE id=$9 AND org_id=$10`,
		check.Name, check.CheckType, paramsJSON, check.Enabled, check.Severity,
		check.RemediationHint, platformsJSON, check.UpdatedAt, id, orgID)
	if err != nil {
		return fmt.Errorf("failed to update posture check in database: %w", err)
	}

	zm.logger.Info("Updated posture check", zap.String("id", id), zap.String("ziti_id", zitiID))
	return nil
}

// RecordPostureResult inserts a device posture check result into the database
func (zm *ZitiManager) RecordPostureResult(ctx context.Context, result *PostureCheckResult) error {
	if result.ID == "" {
		result.ID = uuid.New().String()
	}
	if result.CheckedAt.IsZero() {
		result.CheckedAt = time.Now().UTC()
	}

	detailsJSON, err := json.Marshal(result.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal posture result details: %w", err)
	}

	// Device posture results may be submitted by an agent without a normal
	// request org; capture best-effort with a default-org fallback so the
	// row is never dropped.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	_, err = zm.db.Pool.Exec(ctx,
		`INSERT INTO device_posture_results (id, identity_id, check_id, passed, details, checked_at, expires_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		result.ID, result.IdentityID, result.CheckID, result.Passed,
		detailsJSON, result.CheckedAt, result.ExpiresAt, orgID)
	if err != nil {
		return fmt.Errorf("failed to insert posture result: %w", err)
	}

	zm.logger.Debug("Recorded posture result",
		zap.String("identity_id", result.IdentityID),
		zap.String("check_id", result.CheckID),
		zap.Bool("passed", result.Passed))
	return nil
}

// GetIdentityPostureStatus returns the latest posture check result per check for a given identity
func (zm *ZitiManager) GetIdentityPostureStatus(ctx context.Context, identityID string) ([]PostureCheckResult, error) {
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT DISTINCT ON (check_id) id, identity_id, check_id, passed, details, checked_at, expires_at
		 FROM device_posture_results
		 WHERE identity_id=$1 AND org_id=$2
		 ORDER BY check_id, checked_at DESC`, identityID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query posture status for identity %s: %w", identityID, err)
	}
	defer rows.Close()

	var results []PostureCheckResult
	for rows.Next() {
		var r PostureCheckResult
		var detailsJSON []byte
		err := rows.Scan(&r.ID, &r.IdentityID, &r.CheckID, &r.Passed,
			&detailsJSON, &r.CheckedAt, &r.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan posture result row: %w", err)
		}
		if detailsJSON != nil {
			if err := json.Unmarshal(detailsJSON, &r.Details); err != nil {
				zm.logger.Warn("Failed to unmarshal posture result details", zap.String("result_id", r.ID), zap.Error(err))
			}
		}
		if r.Details == nil {
			r.Details = make(map[string]interface{})
		}
		results = append(results, r)
	}

	if results == nil {
		results = []PostureCheckResult{}
	}
	return results, nil
}

// EvaluateIdentityPosture runs all enabled posture checks for an identity and returns overall pass/fail
func (zm *ZitiManager) EvaluateIdentityPosture(ctx context.Context, identityID string) (bool, []PostureCheckResult, error) {
	// Get all enabled posture checks
	checks, err := zm.ListPostureChecks(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("failed to list posture checks: %w", err)
	}

	// Get the latest results for this identity
	latestResults, err := zm.GetIdentityPostureStatus(ctx, identityID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get identity posture status: %w", err)
	}

	// Build a map of check_id -> latest result
	resultMap := make(map[string]*PostureCheckResult)
	for i := range latestResults {
		resultMap[latestResults[i].CheckID] = &latestResults[i]
	}

	overallPass := true
	var evaluationResults []PostureCheckResult

	now := time.Now().UTC()
	for _, check := range checks {
		if !check.Enabled {
			continue
		}

		result, exists := resultMap[check.ID]

		if !exists {
			// No result recorded for this check - counts as failure
			failResult := PostureCheckResult{
				ID:         uuid.New().String(),
				IdentityID: identityID,
				CheckID:    check.ID,
				Passed:     false,
				Details:    map[string]interface{}{"reason": "no posture data available"},
				CheckedAt:  now,
			}
			evaluationResults = append(evaluationResults, failResult)
			overallPass = false
			continue
		}

		// Check if the result has expired
		if result.ExpiresAt != nil && result.ExpiresAt.Before(now) {
			expiredResult := PostureCheckResult{
				ID:         result.ID,
				IdentityID: identityID,
				CheckID:    check.ID,
				Passed:     false,
				Details:    map[string]interface{}{"reason": "posture check result expired"},
				CheckedAt:  result.CheckedAt,
				ExpiresAt:  result.ExpiresAt,
			}
			evaluationResults = append(evaluationResults, expiredResult)
			overallPass = false
			continue
		}

		evaluationResults = append(evaluationResults, *result)
		if !result.Passed {
			overallPass = false
		}
	}

	if evaluationResults == nil {
		evaluationResults = []PostureCheckResult{}
	}

	zm.logger.Info("Evaluated identity posture",
		zap.String("identity_id", identityID),
		zap.Bool("overall_pass", overallPass),
		zap.Int("checks_evaluated", len(evaluationResults)))

	return overallPass, evaluationResults, nil
}

// SyncGovernancePolicy creates or updates a Ziti service policy from a governance policy
func (zm *ZitiManager) SyncGovernancePolicy(ctx context.Context, governancePolicyID string, config map[string]interface{}) error {
	// Extract role mappings from config
	serviceRoles := []string{"#all"}
	identityRoles := []string{"#all"}
	policyType := "Dial"
	policyName := fmt.Sprintf("openidx-gov-%s", governancePolicyID)

	if sr, ok := config["service_roles"].([]interface{}); ok {
		serviceRoles = make([]string, len(sr))
		for i, v := range sr {
			serviceRoles[i] = fmt.Sprintf("%v", v)
		}
	}
	if ir, ok := config["identity_roles"].([]interface{}); ok {
		identityRoles = make([]string, len(ir))
		for i, v := range ir {
			identityRoles[i] = fmt.Sprintf("%v", v)
		}
	}
	if pt, ok := config["policy_type"].(string); ok {
		policyType = pt
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal sync config: %w", err)
	}

	// Check if a sync state already exists for this governance policy
	var syncState PolicySyncState
	var existingConfigJSON []byte
	err = zm.db.Pool.QueryRow(ctx,
		`SELECT id, ziti_policy_id, sync_type, status, config
		 FROM policy_sync_state WHERE governance_policy_id=$1`, governancePolicyID).
		Scan(&syncState.ID, &syncState.ZitiPolicyID, &syncState.SyncType, &syncState.Status, &existingConfigJSON)

	now := time.Now().UTC()

	if err != nil {
		// No existing sync state - create new Ziti policy and sync state
		syncState.ID = uuid.New().String()

		zitiBody, _ := json.Marshal(map[string]interface{}{
			"name":          policyName,
			"type":          policyType,
			"serviceRoles":  serviceRoles,
			"identityRoles": identityRoles,
		})

		respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/service-policies", zitiBody)
		if err != nil {
			// Record the failed sync state
			zm.db.Pool.Exec(ctx,
				`INSERT INTO policy_sync_state (id, governance_policy_id, sync_type, status, last_error, config, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				syncState.ID, governancePolicyID, policyType, "error", err.Error(), configJSON, now, now)
			return fmt.Errorf("failed to create ziti service policy: %w", err)
		}
		if statusCode != http.StatusCreated && statusCode != http.StatusOK {
			errMsg := fmt.Sprintf("unexpected status %d: %s", statusCode, string(respData))
			zm.db.Pool.Exec(ctx,
				`INSERT INTO policy_sync_state (id, governance_policy_id, sync_type, status, last_error, config, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				syncState.ID, governancePolicyID, policyType, "error", errMsg, configJSON, now, now)
			return fmt.Errorf("unexpected status %d: %s", statusCode, string(respData))
		}

		var resp struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respData, &resp); err != nil {
			return fmt.Errorf("failed to parse ziti service policy response: %w", err)
		}

		_, err = zm.db.Pool.Exec(ctx,
			`INSERT INTO policy_sync_state (id, governance_policy_id, ziti_policy_id, sync_type, status, last_synced_at, config, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			syncState.ID, governancePolicyID, resp.Data.ID, policyType, "synced", now, configJSON, now, now)
		if err != nil {
			return fmt.Errorf("failed to insert policy sync state: %w", err)
		}

		zm.logger.Info("Synced governance policy to ziti",
			zap.String("governance_policy_id", governancePolicyID),
			zap.String("ziti_policy_id", resp.Data.ID),
			zap.String("sync_state_id", syncState.ID))
	} else {
		// Existing sync state - update the Ziti policy
		zitiBody, _ := json.Marshal(map[string]interface{}{
			"name":          policyName,
			"type":          policyType,
			"serviceRoles":  serviceRoles,
			"identityRoles": identityRoles,
		})

		if syncState.ZitiPolicyID != "" {
			_, statusCode, err := zm.mgmtRequest("PUT",
				fmt.Sprintf("/edge/management/v1/service-policies/%s", syncState.ZitiPolicyID), zitiBody)
			if err != nil {
				zm.db.Pool.Exec(ctx,
					`UPDATE policy_sync_state SET status=$1, last_error=$2, config=$3, updated_at=$4 WHERE id=$5`,
					"error", err.Error(), configJSON, now, syncState.ID)
				return fmt.Errorf("failed to update ziti service policy: %w", err)
			}
			if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
				zm.db.Pool.Exec(ctx,
					`UPDATE policy_sync_state SET status=$1, last_error=$2, config=$3, updated_at=$4 WHERE id=$5`,
					"error", fmt.Sprintf("unexpected status %d updating ziti policy", statusCode), configJSON, now, syncState.ID)
				return fmt.Errorf("unexpected status %d updating ziti policy", statusCode)
			}
		} else {
			// Ziti policy was lost - recreate it
			respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/service-policies", zitiBody)
			if err != nil {
				zm.db.Pool.Exec(ctx,
					`UPDATE policy_sync_state SET status=$1, last_error=$2, config=$3, updated_at=$4 WHERE id=$5`,
					"error", err.Error(), configJSON, now, syncState.ID)
				return fmt.Errorf("failed to recreate ziti service policy: %w", err)
			}
			if statusCode != http.StatusCreated && statusCode != http.StatusOK {
				errMsg := fmt.Sprintf("unexpected status %d recreating ziti policy: %s", statusCode, string(respData))
				zm.db.Pool.Exec(ctx,
					`UPDATE policy_sync_state SET status=$1, last_error=$2, config=$3, updated_at=$4 WHERE id=$5`,
					"error", errMsg, configJSON, now, syncState.ID)
				return fmt.Errorf("unexpected status %d recreating ziti policy: %s", statusCode, string(respData))
			}

			var resp struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			json.Unmarshal(respData, &resp)
			syncState.ZitiPolicyID = resp.Data.ID
		}

		// Update sync state
		_, err = zm.db.Pool.Exec(ctx,
			`UPDATE policy_sync_state
			 SET ziti_policy_id=$1, sync_type=$2, status=$3, last_synced_at=$4, last_error=$5, config=$6, updated_at=$7
			 WHERE id=$8`,
			syncState.ZitiPolicyID, policyType, "synced", now, "", configJSON, now, syncState.ID)
		if err != nil {
			return fmt.Errorf("failed to update policy sync state: %w", err)
		}

		zm.logger.Info("Updated governance policy sync",
			zap.String("governance_policy_id", governancePolicyID),
			zap.String("ziti_policy_id", syncState.ZitiPolicyID),
			zap.String("sync_state_id", syncState.ID))
	}

	return nil
}

// ListPolicySyncStates returns all policy sync states from the database
func (zm *ZitiManager) ListPolicySyncStates(ctx context.Context) ([]PolicySyncState, error) {
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT id, governance_policy_id, ziti_policy_id, sync_type, status, last_synced_at, last_error, config, created_at, updated_at
		 FROM policy_sync_state ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query policy sync states: %w", err)
	}
	defer rows.Close()

	var states []PolicySyncState
	for rows.Next() {
		var s PolicySyncState
		var configJSON []byte
		err := rows.Scan(&s.ID, &s.GovernancePolicyID, &s.ZitiPolicyID, &s.SyncType,
			&s.Status, &s.LastSyncedAt, &s.LastError, &configJSON, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy sync state row: %w", err)
		}
		if configJSON != nil {
			if err := json.Unmarshal(configJSON, &s.Config); err != nil {
				zm.logger.Warn("Failed to unmarshal policy sync config", zap.String("sync_id", s.ID), zap.Error(err))
			}
		}
		if s.Config == nil {
			s.Config = make(map[string]interface{})
		}
		states = append(states, s)
	}

	if states == nil {
		states = []PolicySyncState{}
	}
	return states, nil
}

// TriggerPolicySync re-syncs a specific policy by its sync state ID
func (zm *ZitiManager) TriggerPolicySync(ctx context.Context, syncID string) error {
	var governancePolicyID string
	var configJSON []byte
	err := zm.db.Pool.QueryRow(ctx,
		"SELECT governance_policy_id, config FROM policy_sync_state WHERE id=$1", syncID).
		Scan(&governancePolicyID, &configJSON)
	if err != nil {
		return fmt.Errorf("failed to find policy sync state %s: %w", syncID, err)
	}

	var config map[string]interface{}
	if configJSON != nil {
		if err := json.Unmarshal(configJSON, &config); err != nil {
			zm.logger.Warn("Failed to unmarshal trigger sync config", zap.String("sync_id", syncID), zap.Error(err))
		}
	}
	if config == nil {
		config = make(map[string]interface{})
	}

	zm.logger.Info("Triggering policy re-sync",
		zap.String("sync_id", syncID),
		zap.String("governance_policy_id", governancePolicyID))

	return zm.SyncGovernancePolicy(ctx, governancePolicyID, config)
}

// DeletePolicySyncState removes a sync state and optionally deletes the associated Ziti policy
func (zm *ZitiManager) DeletePolicySyncState(ctx context.Context, id string) error {
	// Look up the Ziti policy ID before deleting
	var zitiPolicyID string
	err := zm.db.Pool.QueryRow(ctx,
		"SELECT ziti_policy_id FROM policy_sync_state WHERE id=$1", id).Scan(&zitiPolicyID)
	if err != nil {
		return fmt.Errorf("failed to find policy sync state %s: %w", id, err)
	}

	// Delete the Ziti service policy if it exists
	if zitiPolicyID != "" {
		_, statusCode, err := zm.mgmtRequest("DELETE",
			fmt.Sprintf("/edge/management/v1/service-policies/%s", zitiPolicyID), nil)
		if err != nil {
			zm.logger.Warn("Failed to delete ziti service policy",
				zap.String("ziti_policy_id", zitiPolicyID), zap.Error(err))
		} else if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
			zm.logger.Warn("Unexpected status deleting ziti service policy",
				zap.String("ziti_policy_id", zitiPolicyID), zap.Int("status", statusCode))
		}
	}

	// Delete from database
	_, err = zm.db.Pool.Exec(ctx, "DELETE FROM policy_sync_state WHERE id=$1", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy sync state from database: %w", err)
	}

	zm.logger.Info("Deleted policy sync state",
		zap.String("id", id),
		zap.String("ziti_policy_id", zitiPolicyID))
	return nil
}

// StartPostureResultExpiryChecker runs a background goroutine that periodically
// deletes expired posture check results from the database.
func (zm *ZitiManager) StartPostureResultExpiryChecker(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		zm.logger.Info("Posture result expiry checker started")

		for {
			select {
			case <-ctx.Done():
				zm.logger.Info("Posture result expiry checker stopped")
				return
			case <-ticker.C:
				zm.cleanExpiredPostureResults(ctx)
			}
		}
	}()
}

// cleanExpiredPostureResults deletes posture check results that have passed their expiry time.
func (zm *ZitiManager) cleanExpiredPostureResults(ctx context.Context) {
	result, err := zm.db.Pool.Exec(ctx,
		//orgscope:ignore background expiry sweep across all orgs; deletes posture results purely by expires_at, no tenant context on the ticker
		"DELETE FROM device_posture_results WHERE expires_at IS NOT NULL AND expires_at < NOW()")
	if err != nil {
		zm.logger.Error("Failed to clean expired posture results", zap.Error(err))
		return
	}
	if result.RowsAffected() > 0 {
		zm.logger.Info("Cleaned expired posture results",
			zap.Int64("deleted", result.RowsAffected()))
	}
}

// GovernancePolicy represents a fetched governance policy with its rules.
type GovernancePolicy struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Type        string                   `json:"type"`
	Enabled     bool                     `json:"enabled"`
	Priority    int                      `json:"priority"`
	Rules       []map[string]interface{} `json:"rules"`
}

// FetchGovernancePolicy reads a governance policy and its rules from the shared PostgreSQL database.
func (zm *ZitiManager) FetchGovernancePolicy(ctx context.Context, policyID string) (*GovernancePolicy, error) {
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}
	var p GovernancePolicy
	var rulesJSON []byte
	err := zm.db.Pool.QueryRow(ctx,
		`SELECT id, name, COALESCE(description,''), type, enabled, priority, COALESCE(rules, '[]')
		 FROM policies WHERE id=$1 AND org_id=$2`, policyID, orgID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Type, &p.Enabled, &p.Priority, &rulesJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch governance policy %s: %w", policyID, err)
	}

	// Parse inline rules
	if err := json.Unmarshal(rulesJSON, &p.Rules); err != nil {
		zm.logger.Warn("Failed to unmarshal inline policy rules", zap.String("policy_id", policyID), zap.Error(err))
		p.Rules = []map[string]interface{}{}
	}

	// Also fetch linked policy_rules rows
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT rule_type, conditions, actions FROM policy_rules WHERE policy_id=$1 AND org_id=$2`, policyID, orgID)
	if err != nil {
		zm.logger.Warn("Failed to fetch policy_rules", zap.String("policy_id", policyID), zap.Error(err))
	} else {
		defer rows.Close()
		for rows.Next() {
			var ruleType string
			var conditionsJSON, actionsJSON []byte
			if err := rows.Scan(&ruleType, &conditionsJSON, &actionsJSON); err != nil {
				continue
			}
			rule := map[string]interface{}{"rule_type": ruleType}
			var conditions, actions map[string]interface{}
			if json.Unmarshal(conditionsJSON, &conditions) == nil {
				rule["conditions"] = conditions
			}
			if json.Unmarshal(actionsJSON, &actions) == nil {
				rule["actions"] = actions
			}
			p.Rules = append(p.Rules, rule)
		}
	}

	return &p, nil
}

// TransformGovernancePolicyToZiti converts a governance policy to a Ziti-compatible
// config map based on the policy type. Different policy types produce different
// identity_roles, service_roles, and metadata attributes.
func TransformGovernancePolicyToZiti(policy *GovernancePolicy) map[string]interface{} {
	config := map[string]interface{}{
		"policy_type":     "Dial",
		"policy_name":     policy.Name,
		"governance_type": policy.Type,
	}

	switch policy.Type {
	case "separation_of_duty":
		// Extract conflicting roles and map to identity role exclusions
		identityRoles := []string{}
		for _, rule := range policy.Rules {
			if conds, ok := rule["conditions"].(map[string]interface{}); ok {
				if roles, ok := conds["conflicting_roles"].([]interface{}); ok {
					for _, r := range roles {
						identityRoles = append(identityRoles, fmt.Sprintf("#sod_exclude_%v", r))
					}
				}
			}
		}
		if len(identityRoles) == 0 {
			identityRoles = []string{"#all"}
		}
		config["identity_roles"] = identityRoles
		config["service_roles"] = []string{"#all"}

	case "timebound":
		// Time-window policies: store windows as metadata, grant access to all during valid window
		windows := []interface{}{}
		for _, rule := range policy.Rules {
			if conds, ok := rule["conditions"].(map[string]interface{}); ok {
				if tw, ok := conds["time_window"]; ok {
					windows = append(windows, tw)
				}
				if start, ok := conds["valid_from"]; ok {
					windows = append(windows, map[string]interface{}{
						"valid_from":  start,
						"valid_until": conds["valid_until"],
					})
				}
			}
		}
		config["identity_roles"] = []string{"#all"}
		config["service_roles"] = []string{"#all"}
		config["time_windows"] = windows

	case "risk_based":
		// Map risk thresholds to identity attributes
		identityRoles := []string{}
		for _, rule := range policy.Rules {
			if conds, ok := rule["conditions"].(map[string]interface{}); ok {
				if threshold, ok := conds["risk_threshold"]; ok {
					identityRoles = append(identityRoles, fmt.Sprintf("#risk_below_%v", threshold))
				}
				if maxScore, ok := conds["max_risk_score"]; ok {
					identityRoles = append(identityRoles, fmt.Sprintf("#risk_below_%v", maxScore))
				}
			}
		}
		if len(identityRoles) == 0 {
			identityRoles = []string{"#low_risk"}
		}
		config["identity_roles"] = identityRoles
		config["service_roles"] = []string{"#all"}

	case "location":
		// Map allowed/denied countries to geo attributes
		identityRoles := []string{}
		for _, rule := range policy.Rules {
			if conds, ok := rule["conditions"].(map[string]interface{}); ok {
				if countries, ok := conds["allowed_countries"].([]interface{}); ok {
					for _, c := range countries {
						identityRoles = append(identityRoles, fmt.Sprintf("#geo_%v", c))
					}
				}
			}
		}
		if len(identityRoles) == 0 {
			identityRoles = []string{"#geo_allowed"}
		}
		config["identity_roles"] = identityRoles
		config["service_roles"] = []string{"#all"}

	case "conditional_access":
		// Map conditional access requirements to attribute tags
		identityRoles := []string{}
		for _, rule := range policy.Rules {
			if conds, ok := rule["conditions"].(map[string]interface{}); ok {
				if mfa, ok := conds["require_mfa"].(bool); ok && mfa {
					identityRoles = append(identityRoles, "#mfa_verified")
				}
				if dt, ok := conds["device_trust"].(bool); ok && dt {
					identityRoles = append(identityRoles, "#device_trusted")
				}
				if compliant, ok := conds["require_compliant_device"].(bool); ok && compliant {
					identityRoles = append(identityRoles, "#device_compliant")
				}
			}
		}
		if len(identityRoles) == 0 {
			identityRoles = []string{"#all"}
		}
		config["identity_roles"] = identityRoles
		config["service_roles"] = []string{"#all"}

	default:
		// Unknown policy type — generic pass-through
		config["identity_roles"] = []string{"#all"}
		config["service_roles"] = []string{"#all"}
	}

	return config
}

// GetPostureCheckSummary returns aggregate statistics about posture checks and their results
func (zm *ZitiManager) GetPostureCheckSummary(ctx context.Context) (map[string]interface{}, error) {
	summary := map[string]interface{}{}

	orgID := "00000000-0000-0000-0000-000000000010"
	if org, oerr := orgctx.From(ctx); oerr == nil {
		orgID = org.ID
	}

	// Counts by severity
	severityCounts := map[string]int{}
	rows, err := zm.db.Pool.Query(ctx,
		"SELECT severity, COUNT(*) FROM posture_checks WHERE org_id=$1 GROUP BY severity", orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query posture check severity counts: %w", err)
	}
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan severity count: %w", err)
		}
		severityCounts[severity] = count
	}
	rows.Close()
	summary["severity_counts"] = severityCounts

	// Total checks
	var totalChecks int
	err = zm.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM posture_checks WHERE org_id=$1", orgID).Scan(&totalChecks)
	if err != nil {
		return nil, fmt.Errorf("failed to count posture checks: %w", err)
	}
	summary["total_checks"] = totalChecks

	// Enabled checks
	var enabledChecks int
	err = zm.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM posture_checks WHERE enabled=true AND org_id=$1", orgID).Scan(&enabledChecks)
	if err != nil {
		return nil, fmt.Errorf("failed to count enabled posture checks: %w", err)
	}
	summary["enabled_checks"] = enabledChecks

	// Pass/fail rates from recent results (last 24 hours)
	var totalResults, passedResults int
	err = zm.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN passed THEN 1 ELSE 0 END), 0)
		 FROM device_posture_results
		 WHERE checked_at > NOW() - INTERVAL '24 hours' AND org_id=$1`, orgID).
		Scan(&totalResults, &passedResults)
	if err != nil {
		return nil, fmt.Errorf("failed to query pass/fail rates: %w", err)
	}

	summary["recent_total_results"] = totalResults
	summary["recent_passed_results"] = passedResults
	summary["recent_failed_results"] = totalResults - passedResults
	if totalResults > 0 {
		summary["recent_pass_rate"] = float64(passedResults) / float64(totalResults)
	} else {
		summary["recent_pass_rate"] = float64(0)
	}

	// Sync state summary
	var totalSynced, errorSynced int
	err = zm.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='error' THEN 1 ELSE 0 END), 0)
		 FROM policy_sync_state`).
		Scan(&totalSynced, &errorSynced)
	if err != nil {
		return nil, fmt.Errorf("failed to query policy sync states: %w", err)
	}
	summary["total_policy_syncs"] = totalSynced
	summary["error_policy_syncs"] = errorSynced

	return summary, nil
}
