// Package auth provides unit tests for RBAC roles
package auth

import (
	"testing"
)

// Test AllRoles constant contains all valid roles
func TestAllRoles(t *testing.T) {
	expectedRoles := []Role{RoleSuperAdmin, RoleAdmin, RoleOperator, RoleAuditor, RoleComplianceReader, RoleUser}

	if len(AllRoles) != len(expectedRoles) {
		t.Errorf("AllRoles has %d elements, expected %d", len(AllRoles), len(expectedRoles))
	}

	for i, role := range AllRoles {
		if role != expectedRoles[i] {
			t.Errorf("AllRoles[%d] = %v, expected %v", i, role, expectedRoles[i])
		}
	}
}

// Test RoleLevel contains all roles defined in AllRoles
func TestRoleLevelCompleteness(t *testing.T) {
	for _, role := range AllRoles {
		if _, exists := RoleLevel[role]; !exists {
			t.Errorf("Role %v is not defined in RoleLevel", role)
		}
	}
}

// Test RoleHierarchy contains all roles defined in AllRoles
func TestRoleHierarchyCompleteness(t *testing.T) {
	for _, role := range AllRoles {
		if _, exists := RoleHierarchy[role]; !exists {
			t.Errorf("Role %v is not defined in RoleHierarchy", role)
		}
	}
}

// Test RolePermissions contains all roles defined in AllRoles
func TestRolePermissionsCompleteness(t *testing.T) {
	for _, role := range AllRoles {
		if _, exists := RolePermissions[role]; !exists {
			t.Errorf("Role %v is not defined in RolePermissions", role)
		}
	}
}

// Test SuperAdminPermissionsAreSuperset
func TestSuperAdminPermissionsAreSuperset(t *testing.T) {
	superAdminPerms := make(map[Permission]bool)
	for _, p := range RolePermissions[RoleSuperAdmin] {
		superAdminPerms[p] = true
	}

	// Super admin should have at least all direct permissions of admin
	for _, p := range RolePermissions[RoleAdmin] {
		if !superAdminPerms[p] {
			t.Errorf("Super admin is missing permission %v that admin has", p)
		}
	}
}

// Test AllPermissions constant matches permission definitions
func TestAllPermissionsConstant(t *testing.T) {
	expectedPermissions := []string{
		PermUsersRead,
		PermUsersWrite,
		PermUsersDelete,
		PermGroupsManage,
		PermConfigManage,
		PermAuditRead,
		PermAuditExport,
		PermPoliciesManage,
		PermTenantsManage,
		PermSelfHealManage,
	}

	if len(AllPermissions) != len(expectedPermissions) {
		t.Errorf("AllPermissions has %d elements, expected %d", len(AllPermissions), len(expectedPermissions))
	}

	for i, perm := range AllPermissions {
		if perm != expectedPermissions[i] {
			t.Errorf("AllPermissions[%d] = %v, expected %v", i, perm, expectedPermissions[i])
		}
	}
}

// Test permission constants format
func TestPermissionConstantsFormat(t *testing.T) {
	permissions := []string{
		PermUsersRead,
		PermUsersWrite,
		PermUsersDelete,
		PermGroupsManage,
		PermConfigManage,
		PermAuditRead,
		PermAuditExport,
		PermPoliciesManage,
		PermTenantsManage,
	}

	for _, perm := range permissions {
		parsed, err := ParsePermission(perm)
		if err != nil {
			t.Errorf("Permission constant %q is not parseable: %v", perm, err)
		}
		if parsed.Resource == "" || parsed.Action == "" {
			t.Errorf("Permission constant %q parsed to invalid Permission: %+v", perm, parsed)
		}
	}
}

// Test GetPermissions returns unique permissions
func TestGetPermissionsReturnsUnique(t *testing.T) {
	for _, role := range AllRoles {
		perms := GetPermissions(role)
		permMap := make(map[Permission]bool)

		for _, p := range perms {
			if permMap[p] {
				t.Errorf("Duplicate permission %v found for role %v", p, role)
			}
			permMap[p] = true
		}
	}
}

// Test GetPermissions includes direct permissions
func TestGetPermissionsIncludesDirect(t *testing.T) {
	for _, role := range AllRoles {
		directPerms := RolePermissions[role]
		allPerms := GetPermissions(role)

		directPermMap := make(map[Permission]bool)
		for _, p := range directPerms {
			directPermMap[p] = true
		}

		for _, p := range directPerms {
			found := false
			for _, ap := range allPerms {
				if ap == p {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("GetPermissions(%v) is missing direct permission %v", role, p)
			}
		}
	}
}

// Test RoleHierarchyIsAcyclic ensures no circular inheritance
func TestRoleHierarchyIsAcyclic(t *testing.T) {
	visited := make(map[Role]bool)
	var checkCycle func(Role) bool

	checkCycle = func(role Role) bool {
		if visited[role] {
			return true // Cycle detected
		}
		visited[role] = true

		for _, child := range RoleHierarchy[role] {
			if checkCycle(child) {
				return true
			}
		}

		visited[role] = false // Backtrack
		return false
	}

	for _, role := range AllRoles {
		for k := range visited {
			visited[k] = false
		}
		if checkCycle(role) {
			t.Errorf("Cycle detected in role hierarchy starting from %v", role)
		}
	}
}

// Test RoleLevelIsSequential ensures levels are properly ordered
func TestRoleLevelIsSequential(t *testing.T) {
	expectedLevels := map[Role]int{
		RoleSuperAdmin: 4,
		RoleAdmin:      3,
		RoleOperator:   2,
		RoleAuditor:    1,
		RoleUser:       0,
	}

	for role, expectedLevel := range expectedLevels {
		actualLevel, exists := RoleLevel[role]
		if !exists {
			t.Errorf("Role %v not found in RoleLevel", role)
			continue
		}
		if actualLevel != expectedLevel {
			t.Errorf("Role %v has level %d, expected %d", role, actualLevel, expectedLevel)
		}
	}
}

// Test IsHigherOrEqualRoleBoundaryCases
func TestIsHigherOrEqualRoleBoundaryCases(t *testing.T) {
	// Every role should be >= itself
	for _, role := range AllRoles {
		if !IsHigherOrEqualRole(role, role) {
			t.Errorf("%v should be >= itself", role)
		}
	}

	// Super admin should be >= all roles
	for _, role := range AllRoles {
		if !IsHigherOrEqualRole(RoleSuperAdmin, role) {
			t.Errorf("Super admin should be >= %v", role)
		}
	}

	// User should not be >= any role except itself
	for _, role := range AllRoles {
		if role == RoleUser {
			continue
		}
		if IsHigherOrEqualRole(RoleUser, role) {
			t.Errorf("User should not be >= %v", role)
		}
	}
}

// Test Permission String method
func TestPermissionString(t *testing.T) {
	tests := []struct {
		perm     Permission
		expected string
	}{
		{Permission{Resource: "users", Action: "read"}, "users:read"},
		{Permission{Resource: "tenants", Action: "manage"}, "tenants:manage"},
		{Permission{Resource: "", Action: ""}, ":"},
		{Permission{Resource: "resource", Action: ""}, "resource:"},
		{Permission{Resource: "", Action: "action"}, ":action"},
	}

	for _, tt := range tests {
		if result := tt.perm.String(); result != tt.expected {
			t.Errorf("Permission{%q, %q}.String() = %q, expected %q",
				tt.perm.Resource, tt.perm.Action, result, tt.expected)
		}
	}
}

// Test ParsePermissionRoundTrip
func TestParsePermissionRoundTrip(t *testing.T) {
	original := Permission{Resource: "users", Action: "delete"}
	str := original.String()
	parsed, err := ParsePermission(str)

	if err != nil {
		t.Fatalf("ParsePermission failed: %v", err)
	}

	if parsed != original {
		t.Errorf("Round trip failed: original %v -> %q -> %v", original, str, parsed)
	}
}

// Test HasPermissionWithInvalidRole
func TestHasPermissionWithInvalidRole(t *testing.T) {
	// Create an invalid role
	invalidRole := Role("invalid_role")

	// Should not crash and should return false
	result := HasPermission(invalidRole, "users", "read")
	if result {
		t.Error("Invalid role should not have any permissions")
	}
}

// Test GetPermissionsWithInvalidRole
func TestGetPermissionsWithInvalidRole(t *testing.T) {
	// Create an invalid role
	invalidRole := Role("invalid_role")

	// Should return empty slice (not crash)
	perms := GetPermissions(invalidRole)
	if len(perms) != 0 {
		t.Errorf("Invalid role should have no permissions, got %d", len(perms))
	}
}

// Test PermissionEquality
func TestPermissionEquality(t *testing.T) {
	p1 := Permission{Resource: "users", Action: "read"}
	p2 := Permission{Resource: "users", Action: "read"}
	p3 := Permission{Resource: "users", Action: "write"}
	p4 := Permission{Resource: "audit", Action: "read"}

	if p1 != p2 {
		t.Error("Identical permissions should be equal")
	}

	if p1 == p3 {
		t.Error("Permissions with different actions should not be equal")
	}

	if p1 == p4 {
		t.Error("Permissions with different resources should not be equal")
	}
}

// TestRoleMethodsNilSafety
func TestRoleMethodsNilSafety(t *testing.T) {
	var zeroRole Role

	// These should not panic on zero value
	_ = zeroRole.Level()
	_ = string(zeroRole) // Role is a type alias for string, not a struct with String() method
	_ = zeroRole.Inherits(RoleAdmin)
	_ = zeroRole.HasPermission("users", "read")
	_ = zeroRole.IsHigherOrEqual(RoleUser)
	_ = zeroRole.GetPermissions()
}

// TestRoleStringMethod
func TestRoleStringMethod(t *testing.T) {
	tests := []struct {
		role     Role
		expected string
	}{
		{RoleSuperAdmin, "super_admin"},
		{RoleAdmin, "admin"},
		{RoleOperator, "operator"},
		{RoleAuditor, "auditor"},
		{RoleUser, "user"},
	}

	for _, tt := range tests {
		if result := string(tt.role); result != tt.expected {
			t.Errorf("Role %v as string = %q, expected %q", tt.role, result, tt.expected)
		}
	}
}

// Benchmark GetPermissions for different roles
func BenchmarkGetPermissionsSuperAdmin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetPermissions(RoleSuperAdmin)
	}
}

func BenchmarkGetPermissionsAdmin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetPermissions(RoleAdmin)
	}
}

func BenchmarkGetPermissionsUser(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetPermissions(RoleUser)
	}
}

// Benchmark HasPermission for different permission checks
func BenchmarkHasPermissionHit(b *testing.B) {
	// Benchmark case where permission exists (first in list)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasPermission(RoleAdmin, "users", "read")
	}
}

func BenchmarkHasPermissionMiss(b *testing.B) {
	// Benchmark case where permission doesn't exist
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasPermission(RoleUser, "tenants", "manage")
	}
}

// Benchmark ParsePermission
func BenchmarkParsePermission(b *testing.B) {
	permStr := "users:read"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePermission(permStr)
	}
}

// compliance_reader is an audit-only role: it can read/export audit but must NOT
// gain user/group/config/policy access (it intentionally inherits nothing).
func TestComplianceReaderIsAuditOnly(t *testing.T) {
	perms := GetPermissions(RoleComplianceReader)
	has := func(resource, action string) bool {
		for _, p := range perms {
			if p.Resource == resource && p.Action == action {
				return true
			}
		}
		return false
	}
	if !has("audit", "read") || !has("audit", "export") {
		t.Fatalf("compliance_reader must have audit read+export; got %v", perms)
	}
	if has("users", "read") || has("users", "write") || has("config", "manage") ||
		has("policies", "manage") || has("groups", "manage") || has("tenants", "manage") {
		t.Fatalf("compliance_reader must be audit-only; leaked non-audit perms: %v", perms)
	}
	if len(perms) != 2 {
		t.Fatalf("compliance_reader should have exactly 2 perms (audit read+export); got %d: %v", len(perms), perms)
	}
}
