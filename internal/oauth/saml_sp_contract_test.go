package oauth

import (
	"encoding/json"
	"testing"
)

// The admin console reads the SP list from "service_providers". This handler
// only ever sent "providers", so registration worked, the row landed in the
// database, and the screen still said "No SAML service providers found" --
// with no error on either side. Nothing in Go's type system connects a JSON
// tag to the client that consumes it, so the tag is pinned here.
func TestSAMLServiceProviderListResponseUsesServiceProvidersKey(t *testing.T) {
	body, err := json.Marshal(SAMLServiceProviderListResponse{
		ServiceProviders: []SAMLServiceProvider{{ID: "sp-1", Name: "QA"}},
		Providers:        []SAMLServiceProvider{{ID: "sp-1", Name: "QA"}},
		Total:            1,
		Page:             1,
		PageSize:         20,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The key the admin console actually reads.
	if _, ok := decoded["service_providers"]; !ok {
		t.Fatalf("response has no \"service_providers\" key; the console renders an empty list. got: %s", body)
	}
	// Kept for any existing consumer of the old key: this fix is additive, so
	// it must not become a rename that breaks the other half.
	if _, ok := decoded["providers"]; !ok {
		t.Fatalf("response dropped the legacy \"providers\" key. got: %s", body)
	}

	var typed struct {
		ServiceProviders []SAMLServiceProvider `json:"service_providers"`
	}
	if err := json.Unmarshal(body, &typed); err != nil {
		t.Fatalf("unmarshal typed: %v", err)
	}
	if len(typed.ServiceProviders) != 1 || typed.ServiceProviders[0].ID != "sp-1" {
		t.Fatalf("service_providers did not carry the rows: %+v", typed.ServiceProviders)
	}
}

// An empty result must serialise as [], not null: the console does
// `data?.service_providers || []`, but any consumer that iterates without a
// guard would break on null. scanSAMLServiceProviders already returns an empty
// slice; this keeps that from regressing to a nil return.
func TestSAMLServiceProviderListResponseEmptyIsArrayNotNull(t *testing.T) {
	body, err := json.Marshal(SAMLServiceProviderListResponse{
		ServiceProviders: []SAMLServiceProvider{},
		Providers:        []SAMLServiceProvider{},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(decoded["service_providers"]); got != "[]" {
		t.Fatalf("empty list serialised as %s, want []", got)
	}
}

// Enabled is a pointer so that "field omitted" stays distinguishable from
// "false". As a plain bool it decoded to false and was written verbatim,
// overriding the column DEFAULT true -- so every SP created by the console
// (whose form has no enable switch) was born disabled, and the list showed it
// greyed out even though the user never asked for that.
func TestCreateSAMLServiceProviderEnabledDefaultsToTrueWhenOmitted(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"omitted", `{"name":"a","entity_id":"e","acs_url":"u"}`, true},
		{"explicit false", `{"name":"a","entity_id":"e","acs_url":"u","enabled":false}`, false},
		{"explicit true", `{"name":"a","entity_id":"e","acs_url":"u","enabled":true}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req CreateSAMLServiceProviderRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// Same resolution the create path applies.
			enabled := resolveSPEnabled(req.Enabled)
			_ = enabled
			if false {
				enabled = *req.Enabled
			}
			if enabled != tc.want {
				t.Fatalf("enabled = %v, want %v (body %s)", enabled, tc.want, tc.body)
			}
		})
	}
}
