package main

// scopedTables enumerates the tables the v2.0 multi-tenancy design
// requires org_id scoping for. This list mirrors migration v36 in
// internal/migrations/sql.go (orgIDConstraintsUp). If a table is added
// to v36 or a future scoping migration, add it here so the lint tool
// flags missing filters against it.
//
// Tables deliberately excluded because they are install-wide rather
// than tenant-data:
//
//	organizations         — the tenant table itself
//	permissions           — global permission-string catalog
//	system_settings       — install-wide config
//	ip_threat_list        — shared threat-intel feed
//	posture_check_types   — global enum of posture check kinds
//	policy_sync_state     — global ziti sync watermark
//	organization_members  — its column is organization_id, not org_id;
//	                        sibling join, not a scoped child
var scopedTables = map[string]bool{
	// v25 set (the original multi-tenancy migration)
	"users":                 true,
	"groups":                true,
	"roles":                 true,
	"applications":          true,
	"oauth_clients":         true,
	"audit_events":          true,
	"sessions":              true,
	"policies":              true,
	"access_reviews":        true,
	"service_accounts":      true,
	"webhook_subscriptions": true,
	"access_requests":       true,
	"security_alerts":       true,

	// v28 inline
	"notifications": true,

	// v34 set
	"api_keys":                     true,
	"email_verification_tokens":    true,
	"known_devices":                true,
	"login_history":                true,
	"notification_preferences":     true,
	"password_history":             true,
	"password_reset_tokens":        true,
	"qr_login_sessions":            true,
	"stepup_challenges":            true,
	"user_consents":                true,
	"user_invitations":             true,
	"user_sessions":                true,
	"group_memberships":            true,
	"user_application_assignments": true,
	"mfa_backup_codes":             true,
	"risk_factors":                 true,
	"session_risks":                true,
	"recording_retention_policies": true,
	// SSF/CAEP stream config (v99). Registered so a query that drops its org
	// predicate is caught by the lint, not just by the RLS policy added in
	// v121 — this table holds each tenant's security-event delivery targets.
	//
	// Deliberately NOT registered (and left out of the v121 belt):
	//   ssf_stream_delivery — outbox drained by a background cross-org worker
	//   ssf_received_events — install-wide replay-dedup log of INBOUND SETs,
	//                         written by the public receiver endpoint, which
	//                         has no tenant context and stores no org_id
	// Both are addressed by primary key / globally-unique jti rather than by
	// tenant; forcing RLS on them would break delivery and receipt outright.
	"ssf_streams":                true,
	"mfa_policies":               true,
	"mfa_push_challenges":        true,
	"mfa_push_devices":           true,
	"mfa_totp":                   true,
	"mfa_webauthn":               true,
	"user_mfa_policies":          true,
	"oauth_access_tokens":        true,
	"oauth_authorization_codes":  true,
	"oauth_refresh_tokens":       true,
	"composite_roles":            true,
	"role_permissions":           true,
	"user_roles":                 true,
	"application_sso_settings":   true,
	"group_join_requests":        true,
	"access_request_approvals":   true,
	"approval_policies":          true,
	"compliance_reports":         true,
	"review_items":               true,
	"directory_integrations":     true,
	"directory_sync_logs":        true,
	"directory_sync_state":       true,
	"identity_providers":         true,
	"data_subject_requests":      true,
	"privacy_assessments":        true,
	"privacy_retention_policies": true,
	"provisioning_rules":         true,
	"scim_groups":                true,
	"scim_users":                 true,
	"credential_rotations":       true,
	"device_posture_results":     true,
	"posture_checks":             true,
	"policy_rules":               true,
	"webhook_deliveries":         true,
	"proxy_routes":               true,
	"proxy_sessions":             true,
	"ziti_certificates":          true,
	"ziti_identities":            true,
	"ziti_service_policies":      true,
	"ziti_services":              true,

	// v81 — PAM connection manager (RDM parity)
	"pam_folders":               true,
	"pam_entries":               true,
	"pam_entry_grants":          true,
	"pam_entry_favorites":       true,
	"pam_entry_access_requests": true,
	"pam_entry_sessions":        true,
}
