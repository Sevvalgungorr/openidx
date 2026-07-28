// Package access - BrowZer integration for browser-native Ziti participation
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

// BrowZerConfig holds the state of BrowZer configuration on the Ziti controller
type BrowZerConfig struct {
	Enabled             bool   `json:"enabled"`
	ExternalJWTSignerID string `json:"external_jwt_signer_id"`
	AuthPolicyID        string `json:"auth_policy_id"`
	DialPolicyID        string `json:"dial_policy_id"`
	ERPolicyID          string `json:"edge_router_policy_id"`
	OIDCIssuer          string `json:"oidc_issuer"`
	OIDCClientID        string `json:"oidc_client_id"`
	BootstrapperURL     string `json:"bootstrapper_url"`
}

// BootstrapBrowZer idempotently creates all Ziti resources needed for BrowZer:
//  1. External JWT Signer (trusting OpenIDX OAuth JWKS)
//  2. Auth Policy (external JWT primary auth)
//  3. Dial policy for BrowZer identities → browzer-enabled services
//  4. Edge router policy for BrowZer identities
func (zm *ZitiManager) BootstrapBrowZer(ctx context.Context, oauthIssuer, oauthJWKSURL, browzerClientID string) error {
	zm.logger.Info("Bootstrapping BrowZer resources...",
		zap.String("issuer", oauthIssuer),
		zap.String("jwks", oauthJWKSURL),
		zap.String("client_id", browzerClientID))

	// 1. External JWT Signer
	signerID, err := zm.EnsureExternalJWTSigner(ctx,
		"openidx-oauth-browzer",
		oauthIssuer,
		oauthJWKSURL,
		browzerClientID,
		"sub")
	if err != nil {
		return fmt.Errorf("failed to ensure external JWT signer: %w", err)
	}
	zm.logger.Info("External JWT Signer ready", zap.String("id", signerID))

	// 2. Auth Policy
	authPolicyID, err := zm.EnsureBrowZerAuthPolicy(ctx, "openidx-browzer-auth", signerID)
	if err != nil {
		return fmt.Errorf("failed to ensure BrowZer auth policy: %w", err)
	}
	zm.logger.Info("BrowZer auth policy ready", zap.String("id", authPolicyID))

	// 3. Dial policy: #browzer-users can dial #browzer-enabled services
	dialPolicyID, err := zm.EnsureBrowZerDialPolicy(ctx,
		"openidx-browzer-dial",
		[]string{"#browzer-enabled"},
		[]string{"#browzer-users"})
	if err != nil {
		return fmt.Errorf("failed to ensure BrowZer dial policy: %w", err)
	}
	zm.logger.Info("BrowZer dial policy ready", zap.String("id", dialPolicyID))

	// 4. Edge router policy: #browzer-users can use all routers
	zm.EnsureBrowZerEdgeRouterPolicy(ctx)

	// 5. Auto-provision BrowZer identity for admin user
	// The externalId must match the JWT "sub" claim, which is the user's UUID
	adminUUID := zm.getAdminUserID(ctx)
	if adminUUID != "" {
		if _, err := zm.EnsureBrowZerIdentity(ctx, adminUUID, authPolicyID); err != nil {
			zm.logger.Warn("Failed to create admin BrowZer identity (non-fatal)", zap.Error(err))
		}
	}

	// 6. Persist config to DB. ziti_browzer_config is an install-wide SINGLETON,
	// but the previous upsert generated a fresh gen_random_uuid() id every
	// bootstrap, so the `ON CONFLICT (id)` never fired and each startup appended
	// a new row (the table grew to dozens). Update the canonical (kept) row in
	// place, insert one only if the table is empty, then prune any duplicates
	// left by the old bug — leaving exactly one row. "Canonical" matches the
	// health doctor's dedup rule (enabled DESC, updated_at DESC).
	const canonical = `(SELECT id FROM ziti_browzer_config ORDER BY enabled DESC, updated_at DESC NULLS LAST, id LIMIT 1)`
	res, err := zm.db.Pool.Exec(ctx,
		`UPDATE ziti_browzer_config SET external_jwt_signer_id=$1, auth_policy_id=$2, dial_policy_id=$3,
		   oidc_issuer=$4, oidc_client_id=$5, enabled=true, updated_at=NOW()
		 WHERE id = `+canonical,
		signerID, authPolicyID, dialPolicyID, oauthIssuer, browzerClientID)
	if err == nil && res.RowsAffected() == 0 {
		_, err = zm.db.Pool.Exec(ctx,
			`INSERT INTO ziti_browzer_config (id, external_jwt_signer_id, auth_policy_id, dial_policy_id, oidc_issuer, oidc_client_id, enabled)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, true)`,
			signerID, authPolicyID, dialPolicyID, oauthIssuer, browzerClientID)
	}
	if err != nil {
		zm.logger.Warn("Failed to persist BrowZer config to DB (non-fatal)", zap.Error(err))
	}
	// Collapse any rows the earlier insert-new-uuid bug accumulated.
	zm.db.Pool.Exec(ctx, `DELETE FROM ziti_browzer_config WHERE id <> `+canonical)

	zm.logger.Info("BrowZer bootstrap complete")
	return nil
}

// EnsureExternalJWTSigner creates or finds an external JWT signer on the Ziti controller
func (zm *ZitiManager) EnsureExternalJWTSigner(ctx context.Context, name, issuer, jwksURL, audience, claimsProperty string) (string, error) {
	// Check if it already exists
	if id := zm.findResourceByName("external-jwt-signers", name); id != "" {
		return id, nil
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":            name,
		"issuer":          issuer,
		"audience":        audience,
		"jwksEndpoint":    jwksURL,
		"claimsProperty":  claimsProperty,
		"useExternalId":   true,
		"enabled":         true,
		"externalAuthUrl": issuer + "/oauth/authorize",
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/external-jwt-signers", body)
	if err != nil {
		return "", fmt.Errorf("create external JWT signer failed: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating JWT signer: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse JWT signer response: %w", err)
	}

	return resp.Data.ID, nil
}

// EnsureBrowZerAuthPolicy creates an auth policy that permits external JWT authentication
func (zm *ZitiManager) EnsureBrowZerAuthPolicy(ctx context.Context, name, extJWTSignerID string) (string, error) {
	if id := zm.findResourceByName("auth-policies", name); id != "" {
		return id, nil
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name": name,
		"primary": map[string]interface{}{
			// cert MUST stay allowed: the same identity is also used by the
			// NATIVE Ziti SDK (mobile/desktop), which authenticates with its
			// enrollment certificate. Disabling cert here silently breaks native
			// overlay connections with "invalid certificate authentication, not
			// allowed by auth policy" while BrowZer (extJwt) keeps working — a
			// confusing partial failure. Allowing both lets one identity serve
			// clientless BrowZer (OIDC) AND the native tunnel.
			"cert": map[string]interface{}{
				"allowed":           true,
				"allowExpiredCerts": false,
			},
			"updb": map[string]interface{}{
				"allowed":                false,
				"minPasswordLength":      5,
				"maxAttempts":            5,
				"lockoutDurationMinutes": 0,
				"requireMixedCase":       false,
				"requireSpecialChar":     false,
				"requireNumberChar":      false,
			},
			"extJwt": map[string]interface{}{
				"allowed":        true,
				"allowedSigners": []string{extJWTSignerID},
			},
		},
		"secondary": map[string]interface{}{
			"requireTotp":         false,
			"requireExtJwtSigner": nil,
		},
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/auth-policies", body)
	if err != nil {
		return "", fmt.Errorf("create auth policy failed: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating auth policy: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse auth policy response: %w", err)
	}

	return resp.Data.ID, nil
}

// EnsureBrowZerDialPolicy creates a Dial service policy for BrowZer identities
func (zm *ZitiManager) EnsureBrowZerDialPolicy(ctx context.Context, name string, serviceRoles, identityRoles []string) (string, error) {
	if id := zm.findResourceByName("service-policies", name); id != "" {
		return id, nil
	}

	return zm.CreateServicePolicy(ctx, name, "Dial", serviceRoles, identityRoles)
}

// EnsureBrowZerEdgeRouterPolicy creates an edge router policy so BrowZer identities can use routers
func (zm *ZitiManager) EnsureBrowZerEdgeRouterPolicy(ctx context.Context) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":            "openidx-browzer-erp",
		"semantic":        "AnyOf",
		"edgeRouterRoles": []string{"#all"},
		"identityRoles":   []string{"#browzer-users"},
	})
	_, status, err := zm.mgmtRequest("POST", "/edge/management/v1/edge-router-policies", body)
	if err != nil || (status != http.StatusCreated && status != http.StatusOK) {
		zm.logger.Debug("BrowZer edge router policy creation (may already exist)", zap.Int("status", status))
	}
}

// GetBrowZerConfig retrieves the current BrowZer configuration
func (zm *ZitiManager) GetBrowZerConfig(ctx context.Context) (*BrowZerConfig, error) {
	var cfg BrowZerConfig
	err := zm.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(external_jwt_signer_id,''), COALESCE(auth_policy_id,''),
		        COALESCE(dial_policy_id,''), COALESCE(oidc_issuer,''),
		        COALESCE(oidc_client_id,''), COALESCE(enabled, false)
		 FROM ziti_browzer_config LIMIT 1`).Scan(
		&cfg.ExternalJWTSignerID, &cfg.AuthPolicyID,
		&cfg.DialPolicyID, &cfg.OIDCIssuer,
		&cfg.OIDCClientID, &cfg.Enabled)
	if err != nil {
		return nil, err
	}
	// Build bootstrapper URL from domain config
	browzerDomain := DefaultBrowZerDomain
	var configJSON []byte
	if dbErr := zm.db.Pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'browzer_domain_config'`).Scan(&configJSON); dbErr == nil {
		var domainCfg struct {
			Domain string `json:"domain"`
		}
		if json.Unmarshal(configJSON, &domainCfg) == nil && domainCfg.Domain != "" {
			browzerDomain = domainCfg.Domain
		}
	}
	cfg.BootstrapperURL = "https://" + browzerDomain
	return &cfg, nil
}

// PatchServiceRoleAttributes updates the role attributes of a Ziti service
func (zm *ZitiManager) PatchServiceRoleAttributes(ctx context.Context, zitiServiceID string, attrs []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"roleAttributes": attrs,
	})

	_, statusCode, err := zm.mgmtRequest("PATCH",
		fmt.Sprintf("/edge/management/v1/services/%s", zitiServiceID), body)
	if err != nil {
		return fmt.Errorf("failed to patch service role attributes: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d patching service", statusCode)
	}
	return nil
}

// GetServiceRoleAttributes retrieves current role attributes for a service
func (zm *ZitiManager) GetServiceRoleAttributes(ctx context.Context, zitiServiceID string) ([]string, error) {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/services/%s", zitiServiceID), nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d getting service", statusCode)
	}

	var resp struct {
		Data struct {
			RoleAttributes []string `json:"roleAttributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return resp.Data.RoleAttributes, nil
}

// getAdminUserID retrieves the admin user's UUID from the database
func (zm *ZitiManager) getAdminUserID(ctx context.Context) string {
	var userID string
	err := zm.db.Pool.QueryRow(ctx,
		//orgscope:ignore startup BrowZer bootstrap; resolves the install-wide default admin by well-known username/email before any tenant context exists
		"SELECT id FROM users WHERE username = 'admin' OR email = 'admin@openidx.local' LIMIT 1").Scan(&userID)
	if err != nil {
		zm.logger.Debug("Could not find admin user for BrowZer identity", zap.Error(err))
		return ""
	}
	return userID
}

// EnsureBrowZerIdentity creates or finds a Ziti identity for BrowZer authentication.
// The externalID must match the JWT sub claim. The identity gets the #browzer-users role
// and the specified auth policy so the controller accepts external JWT auth.
func (zm *ZitiManager) EnsureBrowZerIdentity(ctx context.Context, externalID, authPolicyID string) (string, error) {
	// Check if identity already exists by external ID
	if id := zm.findIdentityByExternalID(externalID); id != "" {
		zm.logger.Debug("BrowZer identity already exists", zap.String("externalId", externalID), zap.String("id", id))
		return id, nil
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":           externalID,
		"type":           "Default",
		"externalId":     externalID,
		"authPolicyId":   authPolicyID,
		"roleAttributes": []string{"browzer-users"},
		"isAdmin":        false,
		"enrollment":     map[string]interface{}{"ott": true},
	})

	respData, statusCode, err := zm.mgmtRequest("POST", "/edge/management/v1/identities", body)
	if err != nil {
		return "", fmt.Errorf("create BrowZer identity failed: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating identity: %s", statusCode, string(respData))
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse identity response: %w", err)
	}

	zm.logger.Info("BrowZer identity created", zap.String("externalId", externalID), zap.String("id", resp.Data.ID))
	return resp.Data.ID, nil
}

// findIdentityByExternalID looks up a Ziti identity by its externalId field
func (zm *ZitiManager) findIdentityByExternalID(externalID string) string {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/identities?filter=externalId=\"%s\"", externalID), nil)
	if err != nil || statusCode != http.StatusOK {
		return ""
	}

	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(respData, &resp) == nil && len(resp.Data) > 0 {
		return resp.Data[0].ID
	}
	return ""
}

// DisableBrowZer removes BrowZer resources from the controller
func (zm *ZitiManager) DisableBrowZer(ctx context.Context) error {
	cfg, err := zm.GetBrowZerConfig(ctx)
	if err != nil {
		return fmt.Errorf("no BrowZer config found: %w", err)
	}

	// Delete dial policy
	if cfg.DialPolicyID != "" {
		zm.DeleteServicePolicy(ctx, cfg.DialPolicyID)
	}

	// Delete auth policy
	if cfg.AuthPolicyID != "" {
		zm.mgmtRequest("DELETE",
			fmt.Sprintf("/edge/management/v1/auth-policies/%s", cfg.AuthPolicyID), nil)
	}

	// Delete external JWT signer
	if cfg.ExternalJWTSignerID != "" {
		zm.mgmtRequest("DELETE",
			fmt.Sprintf("/edge/management/v1/external-jwt-signers/%s", cfg.ExternalJWTSignerID), nil)
	}

	// Update DB
	zm.db.Pool.Exec(ctx, "UPDATE ziti_browzer_config SET enabled=false, updated_at=NOW()")

	zm.logger.Info("BrowZer disabled")
	return nil
}

// findResourceByName queries the Ziti management API for a named resource and returns its ID
func (zm *ZitiManager) findResourceByName(resourceType, name string) string {
	respData, statusCode, err := zm.mgmtRequest("GET",
		fmt.Sprintf("/edge/management/v1/%s?filter=name=\"%s\"", resourceType, name), nil)
	if err != nil || statusCode != http.StatusOK {
		return ""
	}

	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(respData, &resp) == nil && len(resp.Data) > 0 {
		return resp.Data[0].ID
	}
	return ""
}
