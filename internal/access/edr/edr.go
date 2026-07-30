// Package edr provides connectors that pull device-compliance/posture signals
// from external EDR/MDM systems (CrowdStrike Falcon, Microsoft Intune, Jamf,
// and the open-source Wazuh) so OpenIDX can feed them into its Ziti-bound
// posture pipeline. A non-compliant or
// high-risk device becomes a failing posture result, which the proxy /
// continuous-verify enforcement uses to revoke the session and sever the
// overlay circuit.
//
// Connectors are persistence-agnostic: they speak the provider API and return a
// normalized []Device. Mapping to local identities and writing posture results
// is the ingestion worker's job (internal/access).
package edr

import (
	"context"
	"strings"
)

// Provider identifiers.
const (
	ProviderCrowdStrike = "crowdstrike"
	ProviderIntune      = "intune"
	ProviderJamf        = "jamf"
	// ProviderWazuh is the open-source EDR/XDR (self-hosted Wazuh manager).
	// Endpoints run the Wazuh agent; OpenIDX pulls agent health from the
	// manager's REST API — a fully open-source posture source, no commercial
	// license required.
	ProviderWazuh = "wazuh"
)

// Risk levels, normalized across providers.
const (
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
	RiskUnknown  = "unknown"
)

// Device is a normalized device posture record from any EDR/MDM.
type Device struct {
	// ExternalID is the provider's device id (aid / managedDeviceId / jamf id).
	ExternalID string
	// Serial, Hostname, Email are the candidate match keys to a local identity.
	Serial   string
	Hostname string
	Email    string
	// Compliant is the provider's compliance verdict. A device that is not
	// compliant fails the mapped posture check.
	Compliant bool
	// Risk is the normalized risk level; High/Critical also fail the check.
	Risk string
	// LastSeen is the provider's last check-in time (RFC 3339) if available.
	LastSeen string
	// Raw carries a few provider fields for the posture-result details blob.
	Raw map[string]interface{}
}

// Passing reports whether this device should PASS the posture check: compliant
// and not high/critical risk.
func (d Device) Passing() bool {
	if !d.Compliant {
		return false
	}
	switch strings.ToLower(d.Risk) {
	case RiskHigh, RiskCritical:
		return false
	}
	return true
}

// Config configures a connector. Only the fields relevant to a provider are used.
type Config struct {
	Provider     string
	BaseURL      string
	ClientID     string
	ClientSecret string
	TenantID     string
	APIUser      string
	APIToken     string
}

// Connector pulls devices from an EDR/MDM.
type Connector interface {
	// Provider returns the connector's provider id.
	Provider() string
	// TestConnection verifies credentials + reachability without side effects.
	TestConnection(ctx context.Context) error
	// ListDevices returns all managed devices with their compliance/risk.
	ListDevices(ctx context.Context) ([]Device, error)
}

// New builds the connector for cfg.Provider.
func New(cfg Config) (Connector, error) {
	switch cfg.Provider {
	case ProviderCrowdStrike:
		return newCrowdStrike(cfg), nil
	case ProviderIntune:
		return newIntune(cfg), nil
	case ProviderJamf:
		return newJamf(cfg), nil
	case ProviderWazuh:
		return newWazuh(cfg), nil
	default:
		return nil, &unsupportedProviderError{cfg.Provider}
	}
}

type unsupportedProviderError struct{ provider string }

func (e *unsupportedProviderError) Error() string {
	return "edr: unsupported provider: " + e.provider
}
