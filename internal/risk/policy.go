// Package risk provides risk-based authentication policies
package risk

import (
	"encoding/json"
	"time"
)

// RiskLevel is defined in scorer.go to avoid duplication

// AuthAction represents the authentication action to take
type AuthAction string

const (
	AuthActionAllow            AuthAction = "allow"
	AuthActionRequireMFA       AuthAction = "require_mfa"
	AuthActionRequireStrongMFA AuthAction = "require_strong_mfa"
	AuthActionRequireApproval  AuthAction = "require_approval"
	AuthActionBlock            AuthAction = "block"
	AuthActionBlockAndAlert    AuthAction = "block_and_alert"
)

// RiskPolicy represents a configurable risk policy (used by identity service)
type RiskPolicy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TenantID    string `json:"tenant_id"`
	// Priority, Conditions and Actions mirror the risk_policies columns and the
	// admin console's policy model. They are surfaced so the UI can list, edit
	// and toggle policies it created; the threshold fields below remain for
	// backward compatibility.
	Priority          int             `json:"priority"`
	Conditions        json.RawMessage `json:"conditions,omitempty"`
	Actions           json.RawMessage `json:"actions,omitempty"`
	LowThreshold      int             `json:"low_threshold"`
	MediumThreshold   int             `json:"medium_threshold"`
	HighThreshold     int             `json:"high_threshold"`
	CriticalThreshold int             `json:"critical_threshold"`
	Enabled           bool            `json:"enabled"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// CreateRiskPolicyRequest represents a request to create or update a risk policy
type CreateRiskPolicyRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	// TenantID is optional. The policy is org-scoped by the request context; the
	// admin console does not send a tenant_id, so requiring it produced a 400 on
	// every create. Kept for API compatibility / cross-tenant tooling.
	TenantID string `json:"tenant_id"`
	// Priority, Conditions and Actions are the model the admin console actually
	// sends. When present they are persisted verbatim into the JSONB columns.
	Priority          *int            `json:"priority"`
	Conditions        json.RawMessage `json:"conditions"`
	Actions           json.RawMessage `json:"actions"`
	LowThreshold      *int            `json:"low_threshold"`
	MediumThreshold   *int            `json:"medium_threshold"`
	HighThreshold     *int            `json:"high_threshold"`
	CriticalThreshold *int            `json:"critical_threshold"`
	Enabled           *bool           `json:"enabled"`
}

// EvaluateLoginContext represents the context for evaluating login risk
type EvaluateLoginContext struct {
	UserID            string   `json:"user_id"`
	IPAddress         string   `json:"ip_address"`
	UserAgent         string   `json:"user_agent"`
	DeviceFingerprint string   `json:"device_fingerprint"`
	Location          string   `json:"location"`
	Latitude          float64  `json:"latitude"`
	Longitude         float64  `json:"longitude"`
	Country           string   `json:"country"`
	IsNewDevice       bool     `json:"is_new_device"`
	IsDeviceTrusted   bool     `json:"is_device_trusted"`
	FailedAttempts    int      `json:"failed_attempts"`
	UserGroups        []string `json:"user_groups"`
}

// PolicyEvaluationResult represents the result of evaluating risk policies
type PolicyEvaluationResult struct {
	RiskScore       int        `json:"risk_score"`
	RiskLevel       RiskLevel  `json:"risk_level"`
	Action          AuthAction `json:"action"`
	Reasons         []string   `json:"reasons"`
	RequireMFA      bool       `json:"require_mfa"`
	Allowed         bool       `json:"allowed"`
	SessionDuration *int       `json:"session_duration_minutes,omitempty"`
}
