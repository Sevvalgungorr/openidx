// Package auth provides RBAC role definitions and permission management for OpenIDX
package auth

import (
	"fmt"
	"strings"
)

// Role represents a user role in the system with hierarchical inheritance
type Role string

const (
	// RoleSuperAdmin is the highest privilege role with all permissions
	RoleSuperAdmin Role = "super_admin"
	// RoleAdmin has administrative privileges within a tenant
	RoleAdmin Role = "admin"
	// RoleOperator can manage operational tasks but not critical settings
	RoleOperator Role = "operator"
	// RoleAuditor has read-only access for compliance and auditing
	RoleAuditor Role = "auditor"
	// RoleComplianceReader is a narrow, org-scoped read-only role: it can read and
	// export the org's audit trail and nothing else (no user/group/config access).
	// Intended for external auditors / compliance reviewers granted to a single org.
	RoleComplianceReader Role = "compliance_reader"
	// RoleUser is the base role for regular users
	RoleUser Role = "user"
)

// AllRoles defines all valid roles in the system
var AllRoles = []Role{RoleSuperAdmin, RoleAdmin, RoleOperator, RoleAuditor, RoleComplianceReader, RoleUser}

// Permission represents a granular permission on a resource
type Permission struct {
	Resource string
	Action   string
}

// String returns the permission in the format "resource:action"
func (p Permission) String() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}

// ParsePermission parses a permission string in the format "resource:action"
func ParsePermission(perm string) (Permission, error) {
	parts := strings.SplitN(perm, ":", 2)
	if len(parts) != 2 {
		return Permission{}, fmt.Errorf("invalid permission format: %s", perm)
	}
	return Permission{Resource: parts[0], Action: parts[1]}, nil
}

// Permission constants - all available permissions in the system
const (
	// User permissions
	PermUsersRead   = "users:read"
	PermUsersWrite  = "users:write"
	PermUsersDelete = "users:delete"

	// Group permissions
	PermGroupsManage = "groups:manage"

	// Configuration permissions
	PermConfigManage = "config:manage"

	// Audit permissions
	PermAuditRead   = "audit:read"
	PermAuditExport = "audit:export"

	// Policy permissions
	PermPoliciesManage = "policies:manage"

	// Tenant permissions
	PermTenantsManage = "tenants:manage"

	// Self-heal permissions — controlling the self-heal loop (mode, kill-switch,
	// on-demand sweep) from the admin console. Viewing is RequireAdmin; only this
	// permission authorizes the mutating actions.
	PermSelfHealManage = "selfheal:manage"
)

// AllPermissions lists all available permissions in the system
var AllPermissions = []string{
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

// RoleLevel defines the hierarchy level of each role (higher = more privileges)
// super_admin (4) > admin (3) > operator (2) > auditor (1) > user (0)
var RoleLevel = map[Role]int{
	RoleSuperAdmin:       4,
	RoleAdmin:            3,
	RoleOperator:         2,
	RoleAuditor:          1,
	RoleComplianceReader: 1, // read-only tier, narrower than auditor (audit only)
	RoleUser:             0,
}

// RoleHierarchy defines which roles a role inherits permissions from.
// Each role inherits all permissions from roles below it in the hierarchy.
var RoleHierarchy = map[Role][]Role{
	RoleSuperAdmin: {RoleAdmin, RoleOperator, RoleAuditor, RoleUser},
	RoleAdmin:      {RoleOperator, RoleAuditor, RoleUser},
	RoleOperator:   {RoleAuditor, RoleUser},
	RoleAuditor:    {RoleUser},
	// compliance_reader is deliberately standalone — it must NOT inherit RoleUser's
	// users:read; its only capability is reading the org's audit trail.
	RoleComplianceReader: {},
	RoleUser:             {}, // Base role, no inheritance
}

// RolePermissions defines the direct permissions for each role (not including inherited)
var RolePermissions = map[Role][]Permission{
	RoleSuperAdmin: {
		{"users", "read"},
		{"users", "write"},
		{"users", "delete"},
		{"groups", "manage"},
		{"config", "manage"},
		{"audit", "read"},
		{"audit", "export"},
		{"policies", "manage"},
		{"tenants", "manage"},
		{"selfheal", "manage"},
	},
	RoleAdmin: {
		{"users", "read"},
		{"users", "write"},
		{"users", "delete"},
		{"groups", "manage"},
		{"config", "manage"},
		{"audit", "read"},
		{"audit", "export"},
		{"policies", "manage"},
		{"selfheal", "manage"},
		// Note: admin does NOT have tenants:manage
	},
	RoleOperator: {
		{"users", "read"},
		{"users", "write"},
		{"groups", "manage"},
		{"audit", "read"},
		{"policies", "manage"},
	},
	RoleAuditor: {
		{"audit", "read"},
		{"audit", "export"},
		{"users", "read"},
	},
	RoleComplianceReader: {
		{"audit", "read"},
		{"audit", "export"},
	},
	RoleUser: {
		{"users", "read"},
	},
}

// GetPermissions returns all permissions for a role, including inherited permissions
func GetPermissions(role Role) []Permission {
	perms := make(map[Permission]struct{})

	// Add direct permissions
	for _, p := range RolePermissions[role] {
		perms[p] = struct{}{}
	}

	// Add inherited permissions
	for _, inheritedRole := range RoleHierarchy[role] {
		for _, p := range RolePermissions[inheritedRole] {
			perms[p] = struct{}{}
		}
	}

	// Convert map to slice
	result := make([]Permission, 0, len(perms))
	for p := range perms {
		result = append(result, p)
	}

	return result
}

// HasPermission checks if a role has a specific permission, including inherited permissions
func HasPermission(role Role, resource, action string) bool {
	perm := Permission{Resource: resource, Action: action}

	// Check direct permissions
	for _, p := range RolePermissions[role] {
		if p.Resource == perm.Resource && p.Action == perm.Action {
			return true
		}
	}

	// Check inherited permissions
	for _, inheritedRole := range RoleHierarchy[role] {
		if HasPermission(inheritedRole, resource, action) {
			return true
		}
	}

	return false
}

// HasAnyPermission checks if a role has any of the specified permissions
func HasAnyPermission(role Role, permissions ...Permission) bool {
	for _, perm := range permissions {
		if HasPermission(role, perm.Resource, perm.Action) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if a role has all of the specified permissions
func HasAllPermissions(role Role, permissions ...Permission) bool {
	for _, perm := range permissions {
		if !HasPermission(role, perm.Resource, perm.Action) {
			return false
		}
	}
	return true
}

// IsHigherOrEqualRole checks if roleA is at the same or higher level than roleB
func IsHigherOrEqualRole(roleA, roleB Role) bool {
	levelA, okA := RoleLevel[roleA]
	levelB, okB := RoleLevel[roleB]
	if !okA || !okB {
		return false
	}
	return levelA >= levelB
}

// IsValidRole checks if a role string is a valid role
func IsValidRole(role string) bool {
	r := Role(role)
	for _, validRole := range AllRoles {
		if validRole == r {
			return true
		}
	}
	return false
}

// ParseRole parses a role string into a Role type
func ParseRole(role string) (Role, error) {
	r := Role(role)
	if !IsValidRole(role) {
		return "", fmt.Errorf("invalid role: %s", role)
	}
	return r, nil
}

// Inherits checks if a role inherits permissions from another role
func (r Role) Inherits(child Role) bool {
	for _, inherited := range RoleHierarchy[r] {
		if inherited == child {
			return true
		}
		if inherited.Inherits(child) {
			return true
		}
	}
	return false
}

// HasPermission checks if the role has a specific permission
func (r Role) HasPermission(resource, action string) bool {
	return HasPermission(r, resource, action)
}

// GetPermissions returns all permissions for this role
func (r Role) GetPermissions() []Permission {
	return GetPermissions(r)
}

// Level returns the hierarchy level of this role
func (r Role) Level() int {
	if level, ok := RoleLevel[r]; ok {
		return level
	}
	return 0
}

// IsHigherOrEqual checks if this role is at the same or higher level than another
func (r Role) IsHigherOrEqual(other Role) bool {
	return IsHigherOrEqualRole(r, other)
}
