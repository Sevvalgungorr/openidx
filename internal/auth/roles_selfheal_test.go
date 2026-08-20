package auth

import "testing"

// selfheal:manage is the control permission for the self-heal panel's mutating
// endpoints (mode change, kill-switch, sweep). Only admin/super_admin get it;
// operator/auditor/user can view (RequireAdmin) but never control.
func TestSelfHealManagePermission(t *testing.T) {
	cases := []struct {
		role Role
		want bool
	}{
		{RoleSuperAdmin, true},
		{RoleAdmin, true},
		{RoleOperator, false},
		{RoleAuditor, false},
		{RoleUser, false},
	}
	for _, c := range cases {
		if got := HasPermission(c.role, "selfheal", "manage"); got != c.want {
			t.Errorf("HasPermission(%s, selfheal:manage) = %v, want %v", c.role, got, c.want)
		}
	}

	// It must be enumerated so any "all permissions" surface (RBAC seed/UI) knows it.
	found := false
	for _, p := range AllPermissions {
		if p == PermSelfHealManage {
			found = true
		}
	}
	if !found {
		t.Error("PermSelfHealManage missing from AllPermissions")
	}
}
