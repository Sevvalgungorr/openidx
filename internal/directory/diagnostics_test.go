package directory

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// entry builds a minimal *ldap.Entry with the given attributes for testing the
// pure suggestion helpers.
func entry(attrs map[string]string) *ldap.Entry {
	e := &ldap.Entry{Attributes: []*ldap.EntryAttribute{}}
	for k, v := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: k, Values: []string{v}})
	}
	return e
}

func TestPopulatedPctAndBest(t *testing.T) {
	sample := []*ldap.Entry{
		entry(map[string]string{"sAMAccountName": "a", "userPrincipalName": "a@x", "mail": ""}),
		entry(map[string]string{"sAMAccountName": "b", "userPrincipalName": "b@x", "mail": ""}),
	}
	if p := populatedPct(sample, "mail"); p != 0 {
		t.Fatalf("mail should be 0%% populated, got %v", p)
	}
	if p := populatedPct(sample, "userPrincipalName"); p != 1 {
		t.Fatalf("upn should be 100%% populated, got %v", p)
	}
	// The classic AD trap: mail empty → best populated email candidate is UPN.
	if got := bestPopulated(sample, []string{"userPrincipalName", "mail"}); got != "userPrincipalName" {
		t.Fatalf("bestPopulated = %q, want userPrincipalName", got)
	}
}

// TestSuggestAttributeMapping_ADEmailTrap reproduces the real bug: email mapped
// to 'mail' which is empty on every AD user, UPN populated — must suggest UPN.
func TestSuggestAttributeMapping_ADEmailTrap(t *testing.T) {
	sample := []*ldap.Entry{
		entry(map[string]string{"sAMAccountName": "umut.celebi", "userPrincipalName": "umut.celebi@test.local", "mail": ""}),
		entry(map[string]string{"sAMAccountName": "ahmet.c", "userPrincipalName": "ahmet.c@test.local", "mail": ""}),
	}
	cfg := LDAPConfig{AttributeMapping: AttributeMapping{Username: "sAMAccountName", Email: "mail"}}

	var findings []Finding
	suggestAttributeMapping(sample, true, cfg, func(f Finding) { findings = append(findings, f) })

	var emailFix string
	for _, f := range findings {
		if v, ok := f.Suggested["attribute_mapping.email"]; ok {
			emailFix, _ = v.(string)
		}
	}
	if emailFix != "userPrincipalName" {
		t.Fatalf("expected email suggestion userPrincipalName, got %q (findings=%d)", emailFix, len(findings))
	}
}

// TestSuggestAttributeMapping_WrongUsername suggests the populated username attr.
func TestSuggestAttributeMapping_WrongUsername(t *testing.T) {
	sample := []*ldap.Entry{
		entry(map[string]string{"sAMAccountName": "a", "userPrincipalName": "a@x", "mail": "a@x", "uid": ""}),
	}
	// Username mapped to uid (empty on AD).
	cfg := LDAPConfig{AttributeMapping: AttributeMapping{Username: "uid", Email: "mail"}}
	var findings []Finding
	suggestAttributeMapping(sample, true, cfg, func(f Finding) { findings = append(findings, f) })
	var userFix string
	for _, f := range findings {
		if v, ok := f.Suggested["attribute_mapping.username"]; ok {
			userFix, _ = v.(string)
		}
	}
	if userFix != "sAMAccountName" {
		t.Fatalf("expected username suggestion sAMAccountName, got %q", userFix)
	}
}

func TestDefaultFilters(t *testing.T) {
	if defaultUserFilter(true) != adUserFilter {
		t.Error("AD user filter wrong")
	}
	if defaultUserFilter(false) != "(objectClass=inetOrgPerson)" {
		t.Error("OpenLDAP user filter wrong")
	}
	if defaultGroupFilter(true) != adGroupFilter {
		t.Error("AD group filter wrong")
	}
}

func TestFinalizeOrdersAndSummarizes(t *testing.T) {
	res := &DiagnoseResult{
		SuggestedConfig: map[string]any{"port": 636},
		Findings: []Finding{
			{Severity: SeverityOK, Title: "ok"},
			{Severity: SeverityError, Title: "boom"},
			{Severity: SeverityWarn, Title: "warn"},
		},
	}
	finalize(res)
	if res.OK {
		t.Error("should not be OK with an error finding")
	}
	if res.Findings[0].Severity != SeverityError {
		t.Errorf("errors should sort first, got %s", res.Findings[0].Severity)
	}
	// All-OK case.
	res2 := &DiagnoseResult{Findings: []Finding{{Severity: SeverityOK}}}
	finalize(res2)
	if !res2.OK || res2.Summary == "" {
		t.Error("all-ok should be OK with a summary")
	}
}
