package directory

import (
	"strings"
	"testing"
)

// TestBuildUserSearchFilter guards the AD/UPN login-DN resolution: an AD user
// logging in with their UPN (contains '@') must match on userPrincipalName, not
// only sAMAccountName — otherwise directory login silently fails.
func TestBuildUserSearchFilter(t *testing.T) {
	adFilter := "(&(objectClass=user)(objectCategory=person))"

	// AD + UPN → OR includes userPrincipalName.
	f := buildUserSearchFilter(adFilter, "sAMAccountName", "jdoe@corp.local", true)
	if !strings.Contains(f, "userPrincipalName=jdoe@corp.local") ||
		!strings.Contains(f, "sAMAccountName=jdoe@corp.local") {
		t.Fatalf("AD UPN filter missing OR clause: %s", f)
	}

	// AD + sAMAccountName (no @) → still OR on AD (either identifier form works).
	f2 := buildUserSearchFilter(adFilter, "sAMAccountName", "jdoe", true)
	if !strings.Contains(f2, "userPrincipalName=jdoe") {
		t.Fatalf("AD plain filter should still allow UPN: %s", f2)
	}

	// Non-AD + no @ → single clause, no userPrincipalName (OpenLDAP unchanged).
	f3 := buildUserSearchFilter("(objectClass=inetOrgPerson)", "uid", "jdoe", false)
	if strings.Contains(f3, "userPrincipalName") {
		t.Fatalf("OpenLDAP filter should not add userPrincipalName: %s", f3)
	}
	if !strings.Contains(f3, "uid=jdoe") {
		t.Fatalf("OpenLDAP filter missing uid clause: %s", f3)
	}

	// Non-AD but identifier looks like a UPN → still add the UPN clause (a
	// convenience for AD-behind-generic-ldap setups).
	f4 := buildUserSearchFilter("(objectClass=person)", "uid", "jdoe@corp.local", false)
	if !strings.Contains(f4, "userPrincipalName=jdoe@corp.local") {
		t.Fatalf("UPN-looking identifier should add UPN clause: %s", f4)
	}

	// Empty user filter → inetOrgPerson fallback.
	f5 := buildUserSearchFilter("", "uid", "jdoe", false)
	if !strings.Contains(f5, "objectClass=inetOrgPerson") {
		t.Fatalf("empty filter should fall back to inetOrgPerson: %s", f5)
	}

	// usernameAttr already userPrincipalName → no redundant OR.
	f6 := buildUserSearchFilter(adFilter, "userPrincipalName", "jdoe@corp.local", true)
	if strings.Contains(f6, "(|(") {
		t.Fatalf("should not build OR when attr already is userPrincipalName: %s", f6)
	}
}
