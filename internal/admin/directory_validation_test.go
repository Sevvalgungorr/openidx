package admin

import "testing"

func ldapConfig(overrides map[string]interface{}) map[string]interface{} {
	cfg := map[string]interface{}{
		"host":          "ad.corp.local",
		"port":          636,
		"bind_dn":       "svc@corp.local",
		"bind_password": "secret",
		"base_dn":       "DC=corp,DC=local",
		"user_filter":   "(&(objectClass=user)(objectCategory=person))",
		"attribute_mapping": map[string]interface{}{
			"username": "sAMAccountName",
			"email":    "userPrincipalName",
		},
	}
	for k, v := range overrides {
		if v == nil {
			delete(cfg, k)
		} else {
			cfg[k] = v
		}
	}
	return cfg
}

func TestValidateDirectoryIntegration(t *testing.T) {
	cases := []struct {
		name      string
		dir       DirectoryIntegration
		wantField string // a field key expected in the error map ("" = valid)
	}{
		{"valid AD", DirectoryIntegration{Name: "AD", Type: "active_directory", Config: ldapConfig(nil)}, ""},
		{"blank name", DirectoryIntegration{Name: "  ", Type: "ldap", Config: ldapConfig(nil)}, "name"},
		{"missing type", DirectoryIntegration{Name: "x", Type: ""}, "type"},
		{"missing host", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{"host": ""})}, "config.host"},
		{"missing bind_dn", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{"bind_dn": ""})}, "config.bind_dn"},
		{"missing base", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{"base_dn": ""})}, "config.base_dn"},
		{"missing user_filter", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{"user_filter": ""})}, "config.user_filter"},
		{"empty username mapping", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{
			"attribute_mapping": map[string]interface{}{"username": "", "email": "mail"}})}, "config.attribute_mapping.username"},
		{"empty email mapping", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{
			"attribute_mapping": map[string]interface{}{"username": "uid", "email": ""}})}, "config.attribute_mapping.email"},
		{"nil config", DirectoryIntegration{Name: "x", Type: "ldap"}, "config.host"},
		{"azure missing tenant", DirectoryIntegration{Name: "a", Type: "azure_ad", Config: map[string]interface{}{"client_id": "c", "client_secret": "s"}}, "config.tenant_id"},
		{"user_base_dn satisfies base requirement", DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{
			"base_dn": "", "user_base_dn": "OU=Users,DC=corp,DC=local"})}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := validateDirectoryIntegration(c.dir)
			if c.wantField == "" {
				if len(errs) != 0 {
					t.Fatalf("expected valid, got errors: %v", errs)
				}
				return
			}
			if _, ok := errs[c.wantField]; !ok {
				t.Fatalf("expected error on %q, got: %v", c.wantField, errs)
			}
		})
	}
}

// TestValidateTrimsWhitespace ensures whitespace-only values are treated empty.
func TestValidateTrimsWhitespace(t *testing.T) {
	dir := DirectoryIntegration{Name: "x", Type: "ldap", Config: ldapConfig(map[string]interface{}{"host": "   "})}
	if _, ok := validateDirectoryIntegration(dir)["config.host"]; !ok {
		t.Fatal("whitespace-only host should be rejected")
	}
}
