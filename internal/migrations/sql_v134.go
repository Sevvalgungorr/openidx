package migrations

// Migration v134 — seed the `selfheal:manage` permission and grant it to every
// existing admin / super_admin role.
//
// The self-heal control panel gates its mutating endpoints (mode change,
// kill-switch, on-demand sweep) with RequirePermission("selfheal","manage"),
// which the PermissionResolver resolves from role_permissions in the DB — NOT
// from the in-code RBAC maps. Without this seed an admin would be silently 403'd
// on every control action. Reads stay on RequireAdmin (no permission needed).
//
// The grant is issued to admin/super_admin roles across ALL orgs (roles are
// per-tenant), so multi-tenant boxes get it everywhere. New orgs created after
// this migration inherit it through the normal role-seeding path.
var selfHealPermUp = `-- Migration 134: selfheal:manage permission + admin grants.
INSERT INTO permissions (id, name, description, resource, action) VALUES
('a0000000-0000-0000-0000-0000000000f1', 'Manage Self-Heal', 'Control the self-heal loop (mode, kill-switch, sweep)', 'selfheal', 'manage')
ON CONFLICT (resource, action) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id, org_id)
SELECT r.id, p.id, r.org_id
FROM roles r
CROSS JOIN permissions p
WHERE p.resource = 'selfheal' AND p.action = 'manage'
  AND r.name IN ('admin', 'super_admin')
ON CONFLICT (role_id, permission_id) DO NOTHING;
`

var selfHealPermDown = `-- Rollback migration 134.
DELETE FROM role_permissions WHERE permission_id = 'a0000000-0000-0000-0000-0000000000f1';
DELETE FROM permissions WHERE id = 'a0000000-0000-0000-0000-0000000000f1';
`
