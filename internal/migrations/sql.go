//go:build !dev

package migrations

// SQL content for migrations - embedded as strings
// This file is auto-generated from the migrations directory

const (
	// Migration 001: Initial Schema
	initialSchemaUp = `-- Migration 001: Initial Schema
-- Description: Core tables for users, groups, and roles

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    -- Password policy fields
    password_changed_at TIMESTAMP WITH TIME ZONE,
    password_must_change BOOLEAN DEFAULT false,
    -- Account lockout fields
    failed_login_count INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE
);

-- Groups table
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES groups(id),
    allow_self_join BOOLEAN DEFAULT false,
    require_approval BOOLEAN DEFAULT false,
    max_members INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Group memberships
CREATE TABLE IF NOT EXISTS group_memberships (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_composite BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Composite roles (role hierarchy)
CREATE TABLE IF NOT EXISTS composite_roles (
    parent_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id)
);

-- User roles (many-to-many relationship)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);`

	initialSchemaDown = `-- Rollback 001: Initial Schema
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS composite_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS group_memberships CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS users CASCADE;`

	// Migration 002: OAuth 2.0 / OIDC
	oauthOIDCUp = `-- Migration 002: OAuth 2.0 / OIDC Tables
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    redirect_uris JSONB,
    grant_types JSONB,
    response_types JSONB,
    scopes JSONB,
    logo_uri VARCHAR(500),
    policy_uri VARCHAR(500),
    tos_uri VARCHAR(500),
    pkce_required BOOLEAN DEFAULT false,
    allow_refresh_token BOOLEAN DEFAULT true,
    access_token_lifetime INTEGER DEFAULT 3600,
    refresh_token_lifetime INTEGER DEFAULT 86400,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    scope TEXT,
    state VARCHAR(255),
    nonce VARCHAR(255),
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(20),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    token VARCHAR(1000) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token VARCHAR(500) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	oauthOIDCDown = `-- Rollback 002: OAuth 2.0 / OIDC Tables
DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS oauth_access_tokens CASCADE;
DROP TABLE IF EXISTS oauth_authorization_codes CASCADE;
DROP TABLE IF EXISTS oauth_clients CASCADE;`

	// Migration 003: SCIM
	scimUp = `-- Migration 003: SCIM 2.0 Provisioning Tables
CREATE TABLE IF NOT EXISTS scim_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255),
    username VARCHAR(255) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255),
    display_name VARCHAR(255) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	scimDown = `-- Rollback 003: SCIM 2.0 Provisioning Tables
DROP TABLE IF EXISTS scim_groups CASCADE;
DROP TABLE IF EXISTS scim_users CASCADE;`

	// Migration 004: Governance
	governanceUp = `-- Migration 004: Governance Tables (Access Reviews & Policies)
CREATE TABLE IF NOT EXISTS access_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    reviewer_id UUID,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS review_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES access_reviews(id) ON DELETE CASCADE,
    user_id UUID,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    decision VARCHAR(50) DEFAULT 'pending',
    decided_by UUID,
    decided_at TIMESTAMP WITH TIME ZONE,
    comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    rules JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    rule_type VARCHAR(50) NOT NULL,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	governanceDown = `-- Rollback 004: Governance Tables
DROP TABLE IF EXISTS policy_rules CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS review_items CASCADE;
DROP TABLE IF EXISTS access_reviews CASCADE;`

	// Migration 005: MFA
	mfaUp = `-- Migration 005: Multi-Factor Authentication Tables
CREATE TABLE IF NOT EXISTS mfa_totp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    secret VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    enrolled_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    conditions JSONB,
    required_methods JSONB,
    grace_period_hours INTEGER DEFAULT 24,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_mfa_policies (
    user_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id)
);

CREATE TABLE IF NOT EXISTS mfa_webauthn (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    sign_count BIGINT DEFAULT 0,
    aaguid VARCHAR(36),
    transports TEXT[],
    name VARCHAR(255),
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    attestation_format VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, credential_id)
);

CREATE TABLE IF NOT EXISTS mfa_push_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    device_token TEXT UNIQUE NOT NULL,
    platform VARCHAR(20) NOT NULL,
    device_name VARCHAR(255),
    device_model VARCHAR(100),
    os_version VARCHAR(50),
    app_version VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    trusted BOOLEAN DEFAULT false,
    last_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS mfa_push_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    device_id UUID NOT NULL,
    challenge_code VARCHAR(10) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    session_info JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    responded_at TIMESTAMP WITH TIME ZONE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255)
);`

	mfaDown = `-- Rollback 005: Multi-Factor Authentication Tables
DROP TABLE IF EXISTS mfa_push_challenges CASCADE;
DROP TABLE IF EXISTS mfa_push_devices CASCADE;
DROP TABLE IF EXISTS mfa_webauthn CASCADE;
DROP TABLE IF EXISTS user_mfa_policies CASCADE;
DROP TABLE IF EXISTS mfa_policies CASCADE;
DROP TABLE IF EXISTS mfa_backup_codes CASCADE;
DROP TABLE IF EXISTS mfa_totp CASCADE;`

	// Migration 006: Sessions
	sessionsUp = `-- Migration 006: Session Management Tables
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	sessionsDown = `-- Rollback 006: Session Management Tables
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;`

	// Migration 007: Applications
	applicationsUp = `-- Migration 007: Application Management Tables
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    protocol VARCHAR(50) DEFAULT 'openid-connect',
    base_url VARCHAR(500),
    redirect_uris TEXT[],
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS application_sso_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    enabled BOOLEAN DEFAULT true,
    use_refresh_tokens BOOLEAN DEFAULT true,
    access_token_lifetime INTEGER DEFAULT 3600,
    refresh_token_lifetime INTEGER DEFAULT 86400,
    require_consent BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(application_id)
);`

	applicationsDown = `-- Rollback 007: Application Management Tables
DROP TABLE IF EXISTS application_sso_settings CASCADE;
DROP TABLE IF EXISTS applications CASCADE;`

	// Migration 008: Audit and Compliance
	auditComplianceUp = `-- Migration 008: Audit and Compliance Tables
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    action VARCHAR(255) NOT NULL,
    outcome VARCHAR(50) NOT NULL,
    actor_id VARCHAR(255),
    actor_type VARCHAR(50),
    actor_ip VARCHAR(45),
    target_id VARCHAR(255),
    target_type VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    framework VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    generated_by UUID,
    summary JSONB DEFAULT '{}',
    findings JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);`

	auditComplianceDown = `-- Rollback 008: Audit and Compliance Tables
DROP TABLE IF EXISTS compliance_reports CASCADE;
DROP TABLE IF EXISTS audit_events CASCADE;`

	// Migration 009: Indexes
	indexesUp = `-- Migration 009: Performance Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_user_id ON oauth_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client_id ON oauth_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users(external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(external_id);
CREATE INDEX IF NOT EXISTS idx_access_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_review_items_review_id ON review_items(review_id);
CREATE INDEX IF NOT EXISTS idx_review_items_user_id ON review_items(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(type);
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON mfa_webauthn(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON mfa_webauthn(credential_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_user_id ON mfa_push_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_push_devices_token ON mfa_push_devices(device_token);
CREATE INDEX IF NOT EXISTS idx_push_challenges_user_id ON mfa_push_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_push_challenges_status ON mfa_push_challenges(status);
CREATE INDEX IF NOT EXISTS idx_push_challenges_expires_at ON mfa_push_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id);
CREATE INDEX IF NOT EXISTS idx_application_sso_settings_application_id ON application_sso_settings(application_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(category);
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events(outcome);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_type ON compliance_reports(type);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_status ON compliance_reports(status);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_at ON compliance_reports(generated_at);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework ON compliance_reports(framework);`

	indexesDown = `-- Rollback 009: Performance Indexes
DROP INDEX IF EXISTS idx_compliance_reports_framework;
DROP INDEX IF EXISTS idx_compliance_reports_generated_at;
DROP INDEX IF EXISTS idx_compliance_reports_status;
DROP INDEX IF EXISTS idx_compliance_reports_type;
DROP INDEX IF EXISTS idx_audit_events_outcome;
DROP INDEX IF EXISTS idx_audit_events_category;
DROP INDEX IF EXISTS idx_audit_events_type;
DROP INDEX IF EXISTS idx_audit_events_actor;
DROP INDEX IF EXISTS idx_audit_events_timestamp;
DROP INDEX IF EXISTS idx_application_sso_settings_application_id;
DROP INDEX IF EXISTS idx_applications_client_id;
DROP INDEX IF EXISTS idx_user_sessions_token;
DROP INDEX IF EXISTS idx_user_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP INDEX IF EXISTS idx_push_challenges_expires_at;
DROP INDEX IF EXISTS idx_push_challenges_status;
DROP INDEX IF EXISTS idx_push_challenges_user_id;
DROP INDEX IF EXISTS idx_push_devices_token;
DROP INDEX IF EXISTS idx_push_devices_user_id;
DROP INDEX IF EXISTS idx_webauthn_credential_id;
DROP INDEX IF EXISTS idx_webauthn_user_id;
DROP INDEX IF EXISTS idx_policies_type;
DROP INDEX IF EXISTS idx_review_items_user_id;
DROP INDEX IF EXISTS idx_review_items_review_id;
DROP INDEX IF EXISTS idx_access_reviews_status;
DROP INDEX IF EXISTS idx_scim_groups_external_id;
DROP INDEX IF EXISTS idx_scim_users_external_id;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_oauth_clients_client_id;
DROP INDEX IF EXISTS idx_user_roles_role_id;
DROP INDEX IF EXISTS idx_user_roles_user_id;
DROP INDEX IF EXISTS idx_groups_name;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;`

	// Migration 010: Seed Data
	seedDataUp = `-- Migration 010: Initial Seed Data
INSERT INTO users (id, username, email, password_hash, first_name, last_name, enabled, email_verified)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@openidx.local', '$2b$12$oX..0F6dHbNip8vASE5VdOgXiBfyqRZ768PU5vArjeOMxG5MGEEdq', 'System', 'Admin', true, true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, name, description, is_composite) VALUES
('60000000-0000-0000-0000-000000000001', 'admin', 'System administrator with full access', false),
('60000000-0000-0000-0000-000000000002', 'user', 'Standard user role', false),
('60000000-0000-0000-0000-000000000003', 'manager', 'Manager role with additional permissions', false),
('60000000-0000-0000-0000-000000000004', 'auditor', 'Audit and compliance role', false),
('60000000-0000-0000-0000-000000000005', 'developer', 'Software developer role', false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified) VALUES
('00000000-0000-0000-0000-000000000002', 'jsmith', 'john.smith@example.com', 'John', 'Smith', true, true),
('00000000-0000-0000-0000-000000000003', 'jdoe', 'jane.doe@example.com', 'Jane', 'Doe', true, true),
('00000000-0000-0000-0000-000000000004', 'bwilson', 'bob.wilson@example.com', 'Bob', 'Wilson', true, false),
('00000000-0000-0000-0000-000000000005', 'amartin', 'alice.martin@example.com', 'Alice', 'Martin', false, true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO groups (id, name, description, parent_id) VALUES
('10000000-0000-0000-0000-000000000001', 'Administrators', 'System administrators with full access', NULL),
('10000000-0000-0000-0000-000000000002', 'Developers', 'Software development team', NULL),
('10000000-0000-0000-0000-000000000003', 'DevOps', 'DevOps engineering team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000004', 'QA Team', 'Quality assurance team', '10000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000005', 'Finance', 'Finance department', NULL),
('10000000-0000-0000-0000-000000000006', 'HR', 'Human resources department', NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO group_memberships (user_id, group_id) VALUES
('00000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000003'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000002'),
('00000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000004'),
('00000000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000005'),
('00000000-0000-0000-0000-000000000005', '10000000-0000-0000-0000-000000000006')
ON CONFLICT DO NOTHING;

INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled) VALUES
('40000000-0000-0000-0000-000000000001', 'admin-console', 'Admin Console', 'OpenIDX Administration Console', 'web', 'openid-connect', 'http://localhost:3000', ARRAY['http://localhost:3000/callback'], true),
('40000000-0000-0000-0000-000000000002', 'sample-spa', 'Sample SPA', 'Sample Single Page Application', 'spa', 'openid-connect', 'http://localhost:4000', ARRAY['http://localhost:4000/callback'], true),
('40000000-0000-0000-0000-000000000003', 'api-service', 'API Service', 'Backend API Service', 'service', 'openid-connect', NULL, NULL, true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000001', 'admin-console', NULL, 'Admin Console', 'OpenIDX Administration Console', 'public',
 '["http://localhost:3000/login", "http://localhost:3000/callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 86400),
('80000000-0000-0000-0000-000000000002', 'api-service', 'api-service-secret', 'API Service', 'Backend API Service', 'confidential',
 '[]'::jsonb,
 '["client_credentials"]'::jsonb,
 '[]'::jsonb,
 '["openid", "api"]'::jsonb,
 false, false, 3600, 0)
ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000003', 'test-client', 'test-secret', 'Test Client', 'Client for testing authentication flow', 'confidential',
 '[]'::jsonb,
 '["authorization_code", "refresh_token", "client_credentials"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email"]'::jsonb,
 false, true, 3600, 86400)
ON CONFLICT (id) DO NOTHING;

INSERT INTO application_sso_settings (id, application_id, enabled, use_refresh_tokens, access_token_lifetime, refresh_token_lifetime, require_consent) VALUES
('50000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000001', true, true, 3600, 86400, false),
('50000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000002', true, true, 1800, 43200, true),
('50000000-0000-0000-0000-000000000003', '40000000-0000-0000-0000-000000000003', true, false, 3600, 0, false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
('00000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date) VALUES
('70000000-0000-0000-0000-000000000001', 'Q1 2026 Access Review', 'Quarterly access review for all users', 'user-access', 'pending', '00000000-0000-0000-0000-000000000001', '2026-01-01', '2026-03-31')
ON CONFLICT (id) DO NOTHING;`

	seedDataDown = `-- Rollback 010: Initial Seed Data
DELETE FROM user_roles WHERE user_id = '00000000-0000-0000-0000-000000000001' AND role_id = '60000000-0000-0000-0000-000000000001';
DELETE FROM access_reviews WHERE id = '70000000-0000-0000-0000-000000000001';
DELETE FROM application_sso_settings WHERE id LIKE '50000000-0000-0000-0000-000000000%';
DELETE FROM oauth_clients WHERE id LIKE '80000000-0000-0000-0000-000000000%';
DELETE FROM applications WHERE id LIKE '40000000-0000-0000-0000-000000000%';
DELETE FROM group_memberships WHERE user_id LIKE '00000000-0000-0000-0000-000000000%';
DELETE FROM groups WHERE id LIKE '10000000-0000-0000-0000-000000000%';
DELETE FROM roles WHERE id LIKE '60000000-0000-0000-0000-000000000%';
DELETE FROM users WHERE id LIKE '00000000-0000-0000-0000-000000000%';`

	// Migration 011-029 would be similarly defined...
	// For brevity, I'm including a placeholder for the rest
	// In production, these would be auto-generated from the migration files

	identityProvidersUp = `-- Migration 011: External Identity Providers
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    issuer_url VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    scopes JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_identity_providers_name ON identity_providers(name);
CREATE INDEX IF NOT EXISTS idx_identity_providers_provider_type ON identity_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_identity_providers_issuer_url ON identity_providers(issuer_url);
ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_users_idp_id ON users(idp_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id_idp_id ON users(idp_id, external_user_id) WHERE idp_id IS NOT NULL;`

	identityProvidersDown = `DROP INDEX IF EXISTS idx_users_external_id_idp_id;
DROP INDEX IF EXISTS idx_users_idp_id;
ALTER TABLE users DROP COLUMN IF EXISTS external_user_id;
ALTER TABLE users DROP COLUMN IF EXISTS idp_id;
DROP INDEX IF EXISTS idx_identity_providers_issuer_url;
DROP INDEX IF EXISTS idx_identity_providers_provider_type;
DROP INDEX IF EXISTS idx_identity_providers_name;
DROP TABLE IF EXISTS identity_providers;`

	provisioningRulesUp = `-- Migration 012: Provisioning Rules
CREATE TABLE IF NOT EXISTS provisioning_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger VARCHAR(50) NOT NULL,
    conditions JSONB DEFAULT '[]',
    actions JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_trigger ON provisioning_rules(trigger);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);`

	provisioningRulesDown = `DROP INDEX IF EXISTS idx_password_reset_tokens_token;
DROP TABLE IF EXISTS password_reset_tokens;
DROP INDEX IF EXISTS idx_provisioning_rules_trigger;
DROP TABLE IF EXISTS provisioning_rules;`

	permissionsUp = `-- Migration 013: Permissions
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(resource, action)
);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
INSERT INTO permissions (id, name, description, resource, action) VALUES
('a0000000-0000-0000-0000-000000000001', 'Read Users', 'View user accounts', 'users', 'read'),
('a0000000-0000-0000-0000-000000000002', 'Write Users', 'Create and edit user accounts', 'users', 'write'),
('a0000000-0000-0000-0000-000000000003', 'Delete Users', 'Delete user accounts', 'users', 'delete'),
('a0000000-0000-0000-0000-000000000004', 'Read Roles', 'View roles', 'roles', 'read'),
('a0000000-0000-0000-0000-000000000005', 'Write Roles', 'Create and edit roles', 'roles', 'write'),
('a0000000-0000-0000-0000-000000000006', 'Read Applications', 'View applications', 'applications', 'read'),
('a0000000-0000-0000-0000-000000000007', 'Write Applications', 'Create and edit applications', 'applications', 'write'),
('a0000000-0000-0000-0000-000000000008', 'Read Audit', 'View audit logs', 'audit', 'read'),
('a0000000-0000-0000-0000-000000000009', 'Write Settings', 'Modify system settings', 'settings', 'write')
ON CONFLICT (resource, action) DO NOTHING;`

	permissionsDown = `DELETE FROM permissions WHERE id LIKE 'a0000000-0000-0000-0000-000000000%';
DROP INDEX IF EXISTS idx_role_permissions_role_id;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;`

	systemSettingsUp = `-- Migration 014: System Settings
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID
);
INSERT INTO system_settings (key, value) VALUES
('system', '{"general": {"organization_name": "OpenIDX", "support_email": "support@openidx.io", "default_language": "en", "default_timezone": "UTC"}, "security": {"password_policy": {"min_length": 12, "require_uppercase": true, "require_lowercase": true, "require_numbers": true, "require_special": true, "max_age": 90, "history": 5}, "session_timeout": 30, "max_failed_logins": 5, "lockout_duration": 15, "require_mfa": false, "blocked_countries": []}, "authentication": {"allow_registration": true, "require_email_verify": true, "mfa_methods": ["totp", "webauthn", "sms"]}, "branding": {"primary_color": "#2563eb", "secondary_color": "#1e40af", "login_page_title": "Welcome to OpenIDX"}}'::jsonb),
('mfa_methods', '["totp", "webauthn", "sms"]'::jsonb)
ON CONFLICT (key) DO NOTHING;`

	systemSettingsDown = `DELETE FROM system_settings WHERE key IN ('system', 'mfa_methods');
DROP TABLE IF EXISTS system_settings;`

	directoryIntegrationsUp = `-- Migration 015: Directory Integrations
CREATE TABLE IF NOT EXISTS directory_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(50) DEFAULT 'never',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_directory_integrations_type ON directory_integrations(type);`

	directoryIntegrationsDown = `DROP INDEX IF EXISTS idx_directory_integrations_type;
DROP TABLE IF EXISTS directory_integrations;`

	proxyRoutesUp = `-- Migration 016: Proxy Routes
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    from_url VARCHAR(500) NOT NULL,
    to_url VARCHAR(500) NOT NULL,
    preserve_host BOOLEAN DEFAULT false,
    require_auth BOOLEAN DEFAULT true,
    allowed_roles JSONB,
    allowed_groups JSONB,
    policy_ids JSONB,
    idle_timeout INTEGER DEFAULT 900,
    absolute_timeout INTEGER DEFAULT 43200,
    cors_allowed_origins JSONB,
    custom_headers JSONB,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS proxy_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    route_id UUID,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_from_url ON proxy_routes(from_url);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_enabled ON proxy_routes(enabled);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_user ON proxy_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_token ON proxy_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_expires ON proxy_sessions(expires_at);`

	proxyRoutesDown = `DROP INDEX IF EXISTS idx_proxy_sessions_expires;
DROP INDEX IF EXISTS idx_proxy_sessions_token;
DROP INDEX IF EXISTS idx_proxy_sessions_user;
DROP INDEX IF EXISTS idx_proxy_routes_enabled;
DROP INDEX IF EXISTS idx_proxy_routes_from_url;
DROP TABLE IF EXISTS proxy_sessions;
DROP TABLE IF EXISTS proxy_routes;`

	openzitiUp = `-- Migration 017: OpenZiti Integration
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_enabled BOOLEAN DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_service_name VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_ziti_enabled ON proxy_routes(ziti_enabled);
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    protocol VARCHAR(20) DEFAULT 'tcp',
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    route_id UUID,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    identity_type VARCHAR(50) DEFAULT 'Device',
    user_id UUID,
    enrollment_jwt TEXT,
    enrolled BOOLEAN DEFAULT false,
    attributes JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(10) NOT NULL,
    service_roles JSONB DEFAULT '[]',
    identity_roles JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ziti_services_name ON ziti_services(name);
CREATE INDEX IF NOT EXISTS idx_ziti_identities_user_id ON ziti_identities(user_id);
INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required)
VALUES ('access-proxy', '', 'Zero Trust Access Proxy', 'public', '["http://localhost:8007/access/.auth/callback", "http://localhost:8088/access/.auth/callback", "http://demo.localtest.me:8088/access/.auth/callback"]'::jsonb, '["authorization_code", "refresh_token"]'::jsonb, '["code"]'::jsonb, '["openid", "profile", "email"]'::jsonb, true)
ON CONFLICT (client_id) DO NOTHING;`

	openzitiDown = `DELETE FROM oauth_clients WHERE client_id = 'access-proxy';
DROP INDEX IF EXISTS idx_ziti_identities_user_id;
DROP INDEX IF EXISTS idx_ziti_services_name;
DROP TABLE IF EXISTS ziti_service_policies;
DROP TABLE IF EXISTS ziti_identities;
DROP TABLE IF EXISTS ziti_services;
DROP INDEX IF EXISTS idx_proxy_routes_ziti_enabled;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS ziti_service_name;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS ziti_enabled;`

	directorySyncUp = `-- Migration 018: Directory Sync
ALTER TABLE users ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);
CREATE INDEX IF NOT EXISTS idx_users_directory_id ON users(directory_id);
CREATE INDEX IF NOT EXISTS idx_users_source ON users(source);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'local';
ALTER TABLE groups ADD COLUMN IF NOT EXISTS directory_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(1024);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_groups_directory_id ON groups(directory_id);
CREATE TABLE IF NOT EXISTS directory_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_usn_changed BIGINT,
    last_modify_timestamp VARCHAR(255),
    users_synced INTEGER DEFAULT 0,
    groups_synced INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    sync_duration_ms INTEGER,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(directory_id)
);
CREATE TABLE IF NOT EXISTS directory_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL,
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    users_added INTEGER DEFAULT 0,
    users_updated INTEGER DEFAULT 0,
    users_disabled INTEGER DEFAULT 0,
    groups_added INTEGER DEFAULT 0,
    groups_updated INTEGER DEFAULT 0,
    groups_deleted INTEGER DEFAULT 0,
    error_message TEXT,
    details JSONB
);
CREATE INDEX IF NOT EXISTS idx_sync_logs_directory ON directory_sync_logs(directory_id);
CREATE INDEX IF NOT EXISTS idx_sync_logs_started ON directory_sync_logs(started_at DESC);`

	directorySyncDown = `DROP INDEX IF EXISTS idx_sync_logs_started;
DROP INDEX IF EXISTS idx_sync_logs_directory;
DROP TABLE IF EXISTS directory_sync_logs;
DROP TABLE IF EXISTS directory_sync_state;
DROP INDEX IF EXISTS idx_groups_directory_id;
ALTER TABLE groups DROP COLUMN IF EXISTS external_id;
ALTER TABLE groups DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE groups DROP COLUMN IF EXISTS directory_id;
ALTER TABLE groups DROP COLUMN IF EXISTS source;
DROP INDEX IF EXISTS idx_users_source;
DROP INDEX IF EXISTS idx_users_directory_id;
ALTER TABLE users DROP COLUMN IF EXISTS ldap_dn;
ALTER TABLE users DROP COLUMN IF EXISTS directory_id;
ALTER TABLE users DROP COLUMN IF EXISTS source;`

	conditionalAccessUp = `-- Migration 019: Conditional Access
CREATE TABLE IF NOT EXISTS known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    fingerprint VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    trusted BOOLEAN DEFAULT false,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_known_devices_user ON known_devices(user_id);
CREATE TABLE IF NOT EXISTS login_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    location VARCHAR(255),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    device_fingerprint VARCHAR(128),
    risk_score INTEGER DEFAULT 0,
    success BOOLEAN NOT NULL,
    auth_methods TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS stepup_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    reason VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stepup_user ON stepup_challenges(user_id, status);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(128);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS auth_methods TEXT[];
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);`

	conditionalAccessDown = `ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS location;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS auth_methods;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS risk_score;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS device_fingerprint;
DROP INDEX IF EXISTS idx_stepup_user;
DROP TABLE IF EXISTS stepup_challenges;
DROP INDEX IF EXISTS idx_login_history_user;
DROP TABLE IF EXISTS login_history;
DROP INDEX IF EXISTS idx_known_devices_user;
DROP TABLE IF EXISTS known_devices;`

	apiKeysWebhooksUp = `-- Migration 020: API Keys, Webhooks, Email Verification, Invitations
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    owner_id UUID,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID,
    service_account_id UUID,
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CHECK (user_id IS NOT NULL OR service_account_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_sa ON api_keys(service_account_id);
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    attempt INTEGER DEFAULT 1,
    status VARCHAR(50) DEFAULT 'pending',
    next_retry_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    delivered_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_sub ON webhook_deliveries(subscription_id);
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS user_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL,
    roles TEXT[],
    groups TEXT[],
    token VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invitations_token ON user_invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON user_invitations(email);
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT false;`

	apiKeysWebhooksDown = `ALTER TABLE users DROP COLUMN IF EXISTS onboarding_completed;
DROP INDEX IF EXISTS idx_invitations_email;
DROP INDEX IF EXISTS idx_invitations_token;
DROP TABLE IF EXISTS user_invitations;
DROP TABLE IF EXISTS email_verification_tokens;
DROP INDEX IF EXISTS idx_webhook_deliveries_sub;
DROP INDEX IF EXISTS idx_webhook_deliveries_status;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_subscriptions;
DROP INDEX IF EXISTS idx_api_keys_sa;
DROP INDEX IF EXISTS idx_api_keys_user;
DROP INDEX IF EXISTS idx_api_keys_hash;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS service_accounts;`

	accessRequestsUp = `-- Migration 021: Access Requests
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID NOT NULL,
    resource_name VARCHAR(255),
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'normal',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS access_request_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    approver_id UUID NOT NULL,
    step_order INTEGER DEFAULT 1,
    decision VARCHAR(50) DEFAULT 'pending',
    comments TEXT,
    decided_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS approval_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    approval_steps JSONB NOT NULL DEFAULT '[]',
    auto_approve_conditions JSONB,
    max_wait_hours INTEGER DEFAULT 72,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_request_approvals_request ON access_request_approvals(request_id);
CREATE INDEX IF NOT EXISTS idx_request_approvals_approver ON access_request_approvals(approver_id, decision);
CREATE INDEX IF NOT EXISTS idx_approval_policies_resource ON approval_policies(resource_type, resource_id);`

	accessRequestsDown = `DROP INDEX IF EXISTS idx_approval_policies_resource;
DROP INDEX IF EXISTS idx_request_approvals_approver;
DROP INDEX IF EXISTS idx_request_approvals_request;
DROP INDEX IF EXISTS idx_access_requests_status;
DROP INDEX IF EXISTS idx_access_requests_requester;
DROP TABLE IF EXISTS approval_policies;
DROP TABLE IF EXISTS access_request_approvals;
DROP TABLE IF EXISTS access_requests;`

	securityAlertsUp = `-- Migration 022: Security Alerts
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    details JSONB,
    source_ip VARCHAR(45),
    remediation_actions JSONB DEFAULT '[]',
    resolved_by UUID,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS ip_threat_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    threat_type VARCHAR(50) NOT NULL,
    reason TEXT,
    blocked_until TIMESTAMP WITH TIME ZONE,
    permanent BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_threat_list_ip ON ip_threat_list(ip_address);
INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, actor_id, actor_type, actor_ip, target_id, target_type, resource_id, details)
VALUES
  (gen_random_uuid(), NOW() - INTERVAL '6 days 14 hours', 'system', 'operational', 'system_startup', 'success', 'system', 'system', '127.0.0.1', '', 'system', '', '{"message": "OpenIDX platform initialized"}'),
  (gen_random_uuid(), NOW() - INTERVAL '5 days 10 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '3 days 12 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '1 day 15 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.10', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}'),
  (gen_random_uuid(), NOW() - INTERVAL '6 hours', 'authentication', 'security', 'login', 'success', '00000000-0000-0000-0000-000000000001', 'user', '192.168.1.20', '00000000-0000-0000-0000-000000000001', 'user', '00000000-0000-0000-0000-000000000001', '{"username": "admin", "email": "admin@openidx.local"}');`

	securityAlertsDown = `DELETE FROM audit_events WHERE details->>'username' = 'admin';
DROP INDEX IF EXISTS idx_ip_threat_list_ip;
DROP INDEX IF EXISTS idx_security_alerts_created;
DROP INDEX IF EXISTS idx_security_alerts_severity;
DROP INDEX IF EXISTS idx_security_alerts_status;
DROP INDEX IF EXISTS idx_security_alerts_user;
DROP TABLE IF EXISTS ip_threat_list;
DROP TABLE IF EXISTS security_alerts;`

	passwordManagementUp = `-- Migration 023: Password Management
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS credential_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL,
    old_key_id UUID,
    new_key_id UUID,
    rotation_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'completed',
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_by UUID
);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_rotations_sa ON credential_rotations(service_account_id);`

	passwordManagementDown = `DROP INDEX IF EXISTS idx_credential_rotations_sa;
DROP TABLE IF EXISTS credential_rotations;
DROP INDEX IF NOT EXISTS idx_password_history_user;
DROP TABLE IF NOT EXISTS password_history;`

	sessionEnhancementsUp = `-- Migration 024: Session Enhancements
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_name VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS location VARCHAR(255);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked BOOLEAN DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_by UUID;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoke_reason VARCHAR(255);`

	sessionEnhancementsDown = `ALTER TABLE sessions DROP COLUMN IF EXISTS revoke_reason;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_by;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_type;
ALTER TABLE sessions DROP COLUMN IF EXISTS location;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_name;`

	multitenancyUp = `-- Migration 025: Multi-Tenancy
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    domain VARCHAR(255) UNIQUE,
    plan VARCHAR(50) DEFAULT 'free',
    status VARCHAR(50) DEFAULT 'active',
    settings JSONB DEFAULT '{}',
    max_users INTEGER DEFAULT 10,
    max_applications INTEGER DEFAULT 5,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    invited_by UUID,
    UNIQUE(organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain);
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE access_reviews ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS org_id UUID;
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_groups_org_id ON groups(org_id);
CREATE INDEX IF NOT EXISTS idx_roles_org_id ON roles(org_id);
CREATE INDEX IF NOT EXISTS idx_applications_org_id ON applications(org_id);
INSERT INTO organizations (id, name, slug, domain, plan, status, max_users, max_applications)
VALUES ('00000000-0000-0000-0000-000000000010', 'Default Organization', 'default', NULL, 'enterprise', 'active', 999999, 999999)
ON CONFLICT (id) DO NOTHING;
UPDATE users SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE groups SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE roles SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE applications SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'owner')
ON CONFLICT DO NOTHING;`

	multitenancyDown = `DELETE FROM organization_members WHERE organization_id = '00000000-0000-0000-0000-000000000010';
UPDATE users SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE groups SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE roles SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE applications SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
DELETE FROM organizations WHERE id = '00000000-0000-0000-0000-000000000010';
DROP INDEX IF EXISTS idx_applications_org_id;
DROP INDEX IF EXISTS idx_roles_org_id;
DROP INDEX IF EXISTS idx_groups_org_id;
DROP INDEX IF EXISTS idx_users_org_id;
ALTER TABLE security_alerts DROP COLUMN IF EXISTS org_id;
ALTER TABLE access_requests DROP COLUMN IF EXISTS org_id;
ALTER TABLE webhook_subscriptions DROP COLUMN IF EXISTS org_id;
ALTER TABLE service_accounts DROP COLUMN IF EXISTS org_id;
ALTER TABLE access_reviews DROP COLUMN IF EXISTS org_id;
ALTER TABLE policies DROP COLUMN IF EXISTS org_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS org_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS org_id;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS org_id;
ALTER TABLE applications DROP COLUMN IF EXISTS org_id;
ALTER TABLE roles DROP COLUMN IF EXISTS org_id;
ALTER TABLE groups DROP COLUMN IF EXISTS org_id;
ALTER TABLE users DROP COLUMN IF EXISTS org_id;
DROP INDEX IF EXISTS idx_org_members_user;
DROP INDEX IF EXISTS idx_org_members_org;
DROP INDEX IF EXISTS idx_organizations_domain;
DROP INDEX IF EXISTS idx_organizations_slug;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;`

	reportingUp = `-- Migration 026: Advanced Reporting
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    parameters JSONB DEFAULT '{}',
    schedule VARCHAR(100) NOT NULL,
    format VARCHAR(10) DEFAULT 'csv',
    enabled BOOLEAN DEFAULT true,
    recipients TEXT[],
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS report_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    scheduled_report_id UUID,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    format VARCHAR(10) NOT NULL,
    status VARCHAR(50) DEFAULT 'generating',
    file_path VARCHAR(500),
    file_size BIGINT,
    row_count INTEGER,
    error_message TEXT,
    generated_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_report_exports_org ON report_exports(org_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_org ON scheduled_reports(org_id);`

	reportingDown = `DROP INDEX IF EXISTS idx_scheduled_reports_org;
DROP INDEX IF EXISTS idx_report_exports_org;
DROP TABLE IF EXISTS report_exports;
DROP TABLE IF EXISTS scheduled_reports;`

	selfServiceUp = `-- Migration 027: Self-Service Portal
CREATE TABLE IF NOT EXISTS group_join_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, group_id)
);
CREATE TABLE IF NOT EXISTS user_application_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    application_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, application_id)
);
CREATE INDEX IF NOT EXISTS idx_group_requests_user ON group_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_group_requests_status ON group_join_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_app_assignments_user ON user_application_assignments(user_id);`

	selfServiceDown = `DROP INDEX IF EXISTS idx_user_app_assignments_user;
DROP TABLE IF EXISTS user_application_assignments;
DROP INDEX IF EXISTS idx_group_requests_status;
DROP INDEX IF EXISTS idx_group_requests_user;
DROP TABLE IF EXISTS group_join_requests;`

	notificationsUp = `-- Migration 028: Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    org_id UUID,
    channel VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    link VARCHAR(500),
    read BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    channel VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, channel, event_type)
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_prefs_user ON notification_preferences(user_id);`

	notificationsDown = `DROP INDEX IF EXISTS idx_notification_prefs_user;
DROP INDEX IF EXISTS idx_notifications_user;
DROP TABLE IF NOT EXISTS notification_preferences;
DROP TABLE IF NOT EXISTS notifications;`

	zitiEnhancedUp = `-- Migration 029: OpenZiti Enhanced
CREATE TABLE IF NOT EXISTS posture_check_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS posture_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    check_type VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(50) DEFAULT 'medium',
    remediation_hint TEXT,
    platforms JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS device_posture_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID,
    check_id UUID,
    passed BOOLEAN NOT NULL,
    details JSONB DEFAULT '{}',
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_posture_results_identity ON device_posture_results(identity_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_results_check ON device_posture_results(check_id);
CREATE TABLE IF NOT EXISTS policy_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    governance_policy_id UUID NOT NULL,
    ziti_policy_id VARCHAR(255),
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    last_synced_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policy_sync_governance ON policy_sync_state(governance_policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_sync_status ON policy_sync_state(status);
CREATE TABLE IF NOT EXISTS ziti_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    cert_data TEXT NOT NULL,
    private_key_encrypted TEXT,
    ca_chain TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    identity_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ziti_certificates_identity ON ziti_certificates(identity_id);
CREATE INDEX IF NOT EXISTS idx_ziti_certificates_expires ON ziti_certificates(expires_at);`

	zitiEnhancedDown = `DROP INDEX IF EXISTS idx_ziti_certificates_expires;
DROP INDEX IF EXISTS idx_ziti_certificates_identity;
DROP TABLE IF EXISTS ziti_certificates;
DROP INDEX IF EXISTS idx_policy_sync_status;
DROP INDEX IF EXISTS idx_policy_sync_governance;
DROP TABLE IF EXISTS policy_sync_state;
DROP INDEX IF EXISTS idx_posture_results_check;
DROP INDEX IF EXISTS idx_posture_results_identity;
DROP TABLE IF EXISTS device_posture_results;
DROP TABLE IF EXISTS posture_checks;
DROP TABLE IF NOT EXISTS posture_check_types;`

	// Migration 030: time-bound role assignments
	//
	// internal/oauth/service.go:686 (GenerateJWT) filters user_roles with
	// `AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`, and
	// internal/identity/role_expiry.go:35 DELETEs expired assignments using
	// the same column — but the user_roles table created in migration v1
	// never had `expires_at`. The role query therefore errored on every
	// invocation, the user.Roles slice came back empty, the OAuth token
	// carried no `roles` claim, and the post-#79 admin-API authz gate
	// returned 403 ("admin role required") even for the seeded admin user.
	// Adding the column closes the loop: existing rows get NULL (no expiry,
	// the desired default for the seeded admin) and time-bound assignments
	// can be issued by setting a future timestamp.
	userRolesExpiresAtUp = `-- Migration 030: add expires_at to user_roles
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at) WHERE expires_at IS NOT NULL;`

	userRolesExpiresAtDown = `DROP INDEX IF EXISTS idx_user_roles_expires_at;
ALTER TABLE user_roles DROP COLUMN IF EXISTS expires_at;`

	// Migration 031: the v1 oauth_refresh_tokens schema never had a
	// session_id column, but CreateRefreshToken's INSERT and GetRefreshToken's
	// SELECT both reference one (introduced when session-bound refresh
	// rotation landed). Postgres rejected the INSERT, the error was
	// swallowed in handleAuthorizationCodeGrant (`s.CreateRefreshToken(...)`
	// with the return ignored), and the client got a refresh_token that was
	// never persisted. The next /oauth/token grant_type=refresh_token then
	// 400'd with invalid_grant because the row didn't exist. Adding the
	// column closes the gap — existing rows (none for fresh installs, since
	// no refresh token ever made it through) get NULL, and freshly-issued
	// tokens carry the linked session for the revoke-by-session path.
	oauthRefreshSessionIDUp = `-- Migration 031: add session_id to oauth_refresh_tokens
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS session_id UUID;
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_session_id ON oauth_refresh_tokens(session_id) WHERE session_id IS NOT NULL;`

	oauthRefreshSessionIDDown = `DROP INDEX IF EXISTS idx_oauth_refresh_tokens_session_id;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS session_id;`

	// Migration 032: privacy / GDPR tables (user_consents, data_subject_requests,
	// privacy_retention_policies, privacy_assessments). These had been living only
	// in deployments/docker/init-db.sql — so any install that came up via
	// `cmd/migrate up` (Helm / Terraform / Kubernetes) was missing them, and
	// every call into internal/identity/handlers_privacy.go or
	// internal/admin/privacy.go 500'd at the first SELECT. Bringing them under
	// the migration runner is the prerequisite for the DSAR processor work.
	privacyTablesUp = `-- Migration 032: privacy / GDPR tables
CREATE TABLE IF NOT EXISTS user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_type VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL DEFAULT '1.0',
    granted BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB DEFAULT '{}',
    granted_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_consents_user ON user_consents(user_id, consent_type);
CREATE INDEX IF NOT EXISTS idx_user_consents_type ON user_consents(consent_type, granted);

CREATE TABLE IF NOT EXISTS data_subject_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    request_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    reason TEXT,
    requested_data_categories JSONB DEFAULT '[]',
    result_file_path VARCHAR(500),
    result_file_size BIGINT,
    processed_by UUID REFERENCES users(id),
    notes TEXT,
    due_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_dsar_user ON data_subject_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_dsar_status ON data_subject_requests(status);

CREATE TABLE IF NOT EXISTS privacy_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    data_category VARCHAR(100) NOT NULL,
    retention_days INTEGER NOT NULL,
    action VARCHAR(50) NOT NULL DEFAULT 'delete',
    anonymize_fields JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT false,
    last_executed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_privacy_retention_category ON privacy_retention_policies(data_category);

CREATE TABLE IF NOT EXISTS privacy_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    data_categories JSONB DEFAULT '[]',
    processing_purposes JSONB DEFAULT '[]',
    risk_level VARCHAR(50) DEFAULT 'low',
    status VARCHAR(50) DEFAULT 'draft',
    findings JSONB DEFAULT '[]',
    mitigations JSONB DEFAULT '[]',
    assessor_id UUID REFERENCES users(id),
    reviewer_id UUID REFERENCES users(id),
    review_notes TEXT,
    approved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_privacy_assessments_status ON privacy_assessments(status);
CREATE INDEX IF NOT EXISTS idx_privacy_assessments_risk ON privacy_assessments(risk_level);`

	privacyTablesDown = `DROP INDEX IF EXISTS idx_privacy_assessments_risk;
DROP INDEX IF EXISTS idx_privacy_assessments_status;
DROP TABLE IF EXISTS privacy_assessments;
DROP INDEX IF EXISTS idx_privacy_retention_category;
DROP TABLE IF EXISTS privacy_retention_policies;
DROP INDEX IF EXISTS idx_dsar_status;
DROP INDEX IF EXISTS idx_dsar_user;
DROP TABLE IF EXISTS data_subject_requests;
DROP INDEX IF EXISTS idx_user_consents_type;
DROP INDEX IF EXISTS idx_user_consents_user;
DROP TABLE IF EXISTS user_consents;`

	// Migration 033: qr_login_sessions — the passwordless QR-login table that
	// internal/identity/passwordless.go has been INSERTing into since the
	// feature shipped, but which no migration ever created. Every call into
	// /oauth/qr-login/create therefore 500'd at the first INSERT, and the
	// browser-side polling endpoint had nothing to poll. Surfaced by the
	// integration tests added in PR #126.
	//
	// Schema mirrors the columns the package reads/writes (see
	// CreateQRLoginSession / GetQRLoginSession): an id, a unique
	// session_token (the lookup key), opaque QR payload, status enum,
	// nullable user_id set when the mobile app scans, JSONB device blobs,
	// IP, and the four lifecycle timestamps.
	qrLoginSessionsUp = `-- Migration 033: qr_login_sessions
CREATE TABLE IF NOT EXISTS qr_login_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    qr_code_data TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    browser_info JSONB DEFAULT '{}',
    mobile_info JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    scanned_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE
);
-- session_token is the lookup key on every read; UNIQUE already creates an
-- index but we add the daily-approved-count predicate the passwordless
-- settings page hits.
CREATE INDEX IF NOT EXISTS idx_qr_login_status_created
    ON qr_login_sessions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_qr_login_user
    ON qr_login_sessions(user_id) WHERE user_id IS NOT NULL;`

	qrLoginSessionsDown = `DROP INDEX IF EXISTS idx_qr_login_user;
DROP INDEX IF EXISTS idx_qr_login_status_created;
DROP TABLE IF EXISTS qr_login_sessions;`

	// Migration 034 — adds the NULL-able org_id UUID column to every
	// table that the v2.0 multi-tenancy design says must be org-scoped
	// but that doesn't have the column yet (migration v025 covered the
	// initial wave: users, groups, roles, applications, oauth_clients,
	// audit_events, sessions, policies, access_reviews,
	// service_accounts, webhook_subscriptions, access_requests,
	// security_alerts; notifications got it inline in v028).
	//
	// This migration ONLY adds columns and indexes. It does NOT:
	//   - backfill values (that's v035)
	//   - set NOT NULL (that's v036)
	//   - add the foreign key constraint (that's v036)
	//   - activate RLS policies (that's v036, deferred via PERMISSIVE
	//     USING(true) until v1.8.0 turns them on)
	//
	// Idempotent via IF NOT EXISTS so re-running it (or running it on
	// an install where a future migration already added a particular
	// column) is safe.
	//
	// Tables deliberately NOT scoped here, because they are
	// install-wide rather than tenant-scoped:
	//   - organizations           (the tenant table itself)
	//   - permissions             (global permission-string catalog)
	//   - system_settings         (install-wide config: SMTP, etc.)
	//   - ip_threat_list          (shared threat-intel feed)
	//   - posture_check_types     (global enum of posture check kinds)
	//   - policy_sync_state       (global ziti sync watermark)
	//
	// If a future PR scopes one of these (e.g., per-tenant SMTP), it
	// owns that column add in its own migration.
	orgIDColumnsUp = `-- Migration 034: per-table org_id columns for v2.0 multi-tenancy

-- Identity / user-data tables (child of users)
ALTER TABLE api_keys                    ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE email_verification_tokens   ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE known_devices               ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE login_history               ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE notification_preferences    ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE password_history            ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE password_reset_tokens       ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE qr_login_sessions           ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE stepup_challenges           ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE user_consents               ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE user_invitations            ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE user_sessions               ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE group_memberships           ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE user_application_assignments ADD COLUMN IF NOT EXISTS org_id UUID;

-- MFA tables (per-user MFA enrollment)
ALTER TABLE mfa_backup_codes            ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE mfa_policies                ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE mfa_push_challenges         ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE mfa_push_devices            ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE mfa_totp                    ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE mfa_webauthn                ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE user_mfa_policies           ADD COLUMN IF NOT EXISTS org_id UUID;

-- OAuth tables (token / authorization-code lifetimes)
ALTER TABLE oauth_access_tokens         ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE oauth_authorization_codes   ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE oauth_refresh_tokens        ADD COLUMN IF NOT EXISTS org_id UUID;

-- Role / permission joins
ALTER TABLE composite_roles             ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE role_permissions            ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE user_roles                  ADD COLUMN IF NOT EXISTS org_id UUID;

-- Application / SSO config
ALTER TABLE application_sso_settings    ADD COLUMN IF NOT EXISTS org_id UUID;

-- Group tables
ALTER TABLE group_join_requests         ADD COLUMN IF NOT EXISTS org_id UUID;

-- Governance / access review / approval
ALTER TABLE access_request_approvals    ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE approval_policies           ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE compliance_reports          ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE review_items                ADD COLUMN IF NOT EXISTS org_id UUID;

-- Directory integrations / sync
ALTER TABLE directory_integrations      ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE directory_sync_logs         ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE directory_sync_state        ADD COLUMN IF NOT EXISTS org_id UUID;

-- Identity providers (per-org SAML/OIDC IdP)
ALTER TABLE identity_providers          ADD COLUMN IF NOT EXISTS org_id UUID;

-- Privacy / GDPR
ALTER TABLE data_subject_requests       ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE privacy_assessments         ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE privacy_retention_policies  ADD COLUMN IF NOT EXISTS org_id UUID;

-- Provisioning / SCIM
ALTER TABLE provisioning_rules          ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE scim_groups                 ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE scim_users                  ADD COLUMN IF NOT EXISTS org_id UUID;

-- Security / risk
ALTER TABLE credential_rotations        ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE device_posture_results      ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE posture_checks              ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE policy_rules                ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE webhook_deliveries          ADD COLUMN IF NOT EXISTS org_id UUID;

-- Proxy (ZTA)
ALTER TABLE proxy_routes                ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE proxy_sessions              ADD COLUMN IF NOT EXISTS org_id UUID;

-- OpenZiti
ALTER TABLE ziti_certificates           ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE ziti_identities             ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE ziti_service_policies       ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE ziti_services               ADD COLUMN IF NOT EXISTS org_id UUID;

-- Indexes on every column we just added. idx_<table>_org_id is the
-- convention v025 established and the v1.7.0 query-rewrite work will
-- rely on (RLS in v1.8.0 too).
CREATE INDEX IF NOT EXISTS idx_api_keys_org_id                    ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_org_id   ON email_verification_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_known_devices_org_id               ON known_devices(org_id);
CREATE INDEX IF NOT EXISTS idx_login_history_org_id               ON login_history(org_id);
CREATE INDEX IF NOT EXISTS idx_notification_preferences_org_id    ON notification_preferences(org_id);
CREATE INDEX IF NOT EXISTS idx_password_history_org_id            ON password_history(org_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_org_id       ON password_reset_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_qr_login_sessions_org_id           ON qr_login_sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_stepup_challenges_org_id           ON stepup_challenges(org_id);
CREATE INDEX IF NOT EXISTS idx_user_consents_org_id               ON user_consents(org_id);
CREATE INDEX IF NOT EXISTS idx_user_invitations_org_id            ON user_invitations(org_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_org_id               ON user_sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_group_memberships_org_id           ON group_memberships(org_id);
CREATE INDEX IF NOT EXISTS idx_user_application_assignments_org_id ON user_application_assignments(org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_org_id            ON mfa_backup_codes(org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_policies_org_id                ON mfa_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_push_challenges_org_id         ON mfa_push_challenges(org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_push_devices_org_id            ON mfa_push_devices(org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_totp_org_id                    ON mfa_totp(org_id);
CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_org_id                ON mfa_webauthn(org_id);
CREATE INDEX IF NOT EXISTS idx_user_mfa_policies_org_id           ON user_mfa_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_org_id         ON oauth_access_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_org_id   ON oauth_authorization_codes(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_org_id        ON oauth_refresh_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_composite_roles_org_id             ON composite_roles(org_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_org_id            ON role_permissions(org_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_org_id                  ON user_roles(org_id);
CREATE INDEX IF NOT EXISTS idx_application_sso_settings_org_id    ON application_sso_settings(org_id);
CREATE INDEX IF NOT EXISTS idx_group_join_requests_org_id         ON group_join_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_access_request_approvals_org_id    ON access_request_approvals(org_id);
CREATE INDEX IF NOT EXISTS idx_approval_policies_org_id           ON approval_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_org_id          ON compliance_reports(org_id);
CREATE INDEX IF NOT EXISTS idx_review_items_org_id                ON review_items(org_id);
CREATE INDEX IF NOT EXISTS idx_directory_integrations_org_id      ON directory_integrations(org_id);
CREATE INDEX IF NOT EXISTS idx_directory_sync_logs_org_id         ON directory_sync_logs(org_id);
CREATE INDEX IF NOT EXISTS idx_directory_sync_state_org_id        ON directory_sync_state(org_id);
CREATE INDEX IF NOT EXISTS idx_identity_providers_org_id          ON identity_providers(org_id);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_org_id       ON data_subject_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_privacy_assessments_org_id         ON privacy_assessments(org_id);
CREATE INDEX IF NOT EXISTS idx_privacy_retention_policies_org_id  ON privacy_retention_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_provisioning_rules_org_id          ON provisioning_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_org_id                 ON scim_groups(org_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_org_id                  ON scim_users(org_id);
CREATE INDEX IF NOT EXISTS idx_credential_rotations_org_id        ON credential_rotations(org_id);
CREATE INDEX IF NOT EXISTS idx_device_posture_results_org_id      ON device_posture_results(org_id);
CREATE INDEX IF NOT EXISTS idx_posture_checks_org_id              ON posture_checks(org_id);
CREATE INDEX IF NOT EXISTS idx_policy_rules_org_id                ON policy_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_id          ON webhook_deliveries(org_id);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_org_id                ON proxy_routes(org_id);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_org_id              ON proxy_sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_ziti_certificates_org_id           ON ziti_certificates(org_id);
CREATE INDEX IF NOT EXISTS idx_ziti_identities_org_id             ON ziti_identities(org_id);
CREATE INDEX IF NOT EXISTS idx_ziti_service_policies_org_id       ON ziti_service_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_ziti_services_org_id               ON ziti_services(org_id);`

	orgIDColumnsDown = `-- Migration 034 down: drop the indexes first, then the columns.
-- Idempotent. If a v035 backfill ran before this Down, the column
-- will still drop cleanly (values go with it).
DROP INDEX IF EXISTS idx_ziti_services_org_id;
DROP INDEX IF EXISTS idx_ziti_service_policies_org_id;
DROP INDEX IF EXISTS idx_ziti_identities_org_id;
DROP INDEX IF EXISTS idx_ziti_certificates_org_id;
DROP INDEX IF EXISTS idx_proxy_sessions_org_id;
DROP INDEX IF EXISTS idx_proxy_routes_org_id;
DROP INDEX IF EXISTS idx_webhook_deliveries_org_id;
DROP INDEX IF EXISTS idx_policy_rules_org_id;
DROP INDEX IF EXISTS idx_posture_checks_org_id;
DROP INDEX IF EXISTS idx_device_posture_results_org_id;
DROP INDEX IF EXISTS idx_credential_rotations_org_id;
DROP INDEX IF EXISTS idx_scim_users_org_id;
DROP INDEX IF EXISTS idx_scim_groups_org_id;
DROP INDEX IF EXISTS idx_provisioning_rules_org_id;
DROP INDEX IF EXISTS idx_privacy_retention_policies_org_id;
DROP INDEX IF EXISTS idx_privacy_assessments_org_id;
DROP INDEX IF EXISTS idx_data_subject_requests_org_id;
DROP INDEX IF EXISTS idx_identity_providers_org_id;
DROP INDEX IF EXISTS idx_directory_sync_state_org_id;
DROP INDEX IF EXISTS idx_directory_sync_logs_org_id;
DROP INDEX IF EXISTS idx_directory_integrations_org_id;
DROP INDEX IF EXISTS idx_review_items_org_id;
DROP INDEX IF EXISTS idx_compliance_reports_org_id;
DROP INDEX IF EXISTS idx_approval_policies_org_id;
DROP INDEX IF EXISTS idx_access_request_approvals_org_id;
DROP INDEX IF EXISTS idx_group_join_requests_org_id;
DROP INDEX IF EXISTS idx_application_sso_settings_org_id;
DROP INDEX IF EXISTS idx_user_roles_org_id;
DROP INDEX IF EXISTS idx_role_permissions_org_id;
DROP INDEX IF EXISTS idx_composite_roles_org_id;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_org_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_org_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_org_id;
DROP INDEX IF EXISTS idx_user_mfa_policies_org_id;
DROP INDEX IF EXISTS idx_mfa_webauthn_org_id;
DROP INDEX IF EXISTS idx_mfa_totp_org_id;
DROP INDEX IF EXISTS idx_mfa_push_devices_org_id;
DROP INDEX IF EXISTS idx_mfa_push_challenges_org_id;
DROP INDEX IF EXISTS idx_mfa_policies_org_id;
DROP INDEX IF EXISTS idx_mfa_backup_codes_org_id;
DROP INDEX IF EXISTS idx_user_application_assignments_org_id;
DROP INDEX IF EXISTS idx_group_memberships_org_id;
DROP INDEX IF EXISTS idx_user_sessions_org_id;
DROP INDEX IF EXISTS idx_user_invitations_org_id;
DROP INDEX IF EXISTS idx_user_consents_org_id;
DROP INDEX IF EXISTS idx_stepup_challenges_org_id;
DROP INDEX IF EXISTS idx_qr_login_sessions_org_id;
DROP INDEX IF EXISTS idx_password_reset_tokens_org_id;
DROP INDEX IF EXISTS idx_password_history_org_id;
DROP INDEX IF EXISTS idx_notification_preferences_org_id;
DROP INDEX IF EXISTS idx_login_history_org_id;
DROP INDEX IF EXISTS idx_known_devices_org_id;
DROP INDEX IF EXISTS idx_email_verification_tokens_org_id;
DROP INDEX IF EXISTS idx_api_keys_org_id;

ALTER TABLE ziti_services               DROP COLUMN IF EXISTS org_id;
ALTER TABLE ziti_service_policies       DROP COLUMN IF EXISTS org_id;
ALTER TABLE ziti_identities             DROP COLUMN IF EXISTS org_id;
ALTER TABLE ziti_certificates           DROP COLUMN IF EXISTS org_id;
ALTER TABLE proxy_sessions              DROP COLUMN IF EXISTS org_id;
ALTER TABLE proxy_routes                DROP COLUMN IF EXISTS org_id;
ALTER TABLE webhook_deliveries          DROP COLUMN IF EXISTS org_id;
ALTER TABLE policy_rules                DROP COLUMN IF EXISTS org_id;
ALTER TABLE posture_checks              DROP COLUMN IF EXISTS org_id;
ALTER TABLE device_posture_results      DROP COLUMN IF EXISTS org_id;
ALTER TABLE credential_rotations        DROP COLUMN IF EXISTS org_id;
ALTER TABLE scim_users                  DROP COLUMN IF EXISTS org_id;
ALTER TABLE scim_groups                 DROP COLUMN IF EXISTS org_id;
ALTER TABLE provisioning_rules          DROP COLUMN IF EXISTS org_id;
ALTER TABLE privacy_retention_policies  DROP COLUMN IF EXISTS org_id;
ALTER TABLE privacy_assessments         DROP COLUMN IF EXISTS org_id;
ALTER TABLE data_subject_requests       DROP COLUMN IF EXISTS org_id;
ALTER TABLE identity_providers          DROP COLUMN IF EXISTS org_id;
ALTER TABLE directory_sync_state        DROP COLUMN IF EXISTS org_id;
ALTER TABLE directory_sync_logs         DROP COLUMN IF EXISTS org_id;
ALTER TABLE directory_integrations      DROP COLUMN IF EXISTS org_id;
ALTER TABLE review_items                DROP COLUMN IF EXISTS org_id;
ALTER TABLE compliance_reports          DROP COLUMN IF EXISTS org_id;
ALTER TABLE approval_policies           DROP COLUMN IF EXISTS org_id;
ALTER TABLE access_request_approvals    DROP COLUMN IF EXISTS org_id;
ALTER TABLE group_join_requests         DROP COLUMN IF EXISTS org_id;
ALTER TABLE application_sso_settings    DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_roles                  DROP COLUMN IF EXISTS org_id;
ALTER TABLE role_permissions            DROP COLUMN IF EXISTS org_id;
ALTER TABLE composite_roles             DROP COLUMN IF EXISTS org_id;
ALTER TABLE oauth_refresh_tokens        DROP COLUMN IF EXISTS org_id;
ALTER TABLE oauth_authorization_codes   DROP COLUMN IF EXISTS org_id;
ALTER TABLE oauth_access_tokens         DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_mfa_policies           DROP COLUMN IF EXISTS org_id;
ALTER TABLE mfa_webauthn                DROP COLUMN IF EXISTS org_id;
ALTER TABLE mfa_totp                    DROP COLUMN IF EXISTS org_id;
ALTER TABLE mfa_push_devices            DROP COLUMN IF EXISTS org_id;
ALTER TABLE mfa_push_challenges         DROP COLUMN IF EXISTS org_id;
ALTER TABLE mfa_policies                DROP COLUMN IF EXISTS org_id;
ALTER TABLE mfa_backup_codes            DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_application_assignments DROP COLUMN IF EXISTS org_id;
ALTER TABLE group_memberships           DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_sessions               DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_invitations            DROP COLUMN IF EXISTS org_id;
ALTER TABLE user_consents               DROP COLUMN IF EXISTS org_id;
ALTER TABLE stepup_challenges           DROP COLUMN IF EXISTS org_id;
ALTER TABLE qr_login_sessions           DROP COLUMN IF EXISTS org_id;
ALTER TABLE password_reset_tokens       DROP COLUMN IF EXISTS org_id;
ALTER TABLE password_history            DROP COLUMN IF EXISTS org_id;
ALTER TABLE notification_preferences    DROP COLUMN IF EXISTS org_id;
ALTER TABLE login_history               DROP COLUMN IF EXISTS org_id;
ALTER TABLE known_devices               DROP COLUMN IF EXISTS org_id;
ALTER TABLE email_verification_tokens   DROP COLUMN IF EXISTS org_id;
ALTER TABLE api_keys                    DROP COLUMN IF EXISTS org_id;`

	// Migration 035 — backfills the default organization UUID into
	// every NULL org_id row across the tables v34 just scoped.
	//
	// The default organization itself was created by v25
	// (id = 00000000-0000-0000-0000-000000000010, slug = 'default').
	// v25 also backfilled four core tables (users, groups, roles,
	// applications); v35 fills in the remaining ~50.
	//
	// Strategy: a single UPDATE per table guarded by
	// WHERE org_id IS NULL. This is idempotent — re-running v35 is a
	// no-op because the second run finds no NULLs. It also does not
	// clobber any rows an install may have set to a non-default
	// org_id manually (e.g., via a custom seed script).
	//
	// Single-tenant installs that previously had no
	// 'default' org row will have one created by the safety INSERT
	// at the top of this migration: v25 already creates it
	// unconditionally on every install, so the INSERT below is
	// purely defensive against installs that may have somehow
	// reached v34 without v25 — that can't happen with the standard
	// runner, but the cost of an extra ON CONFLICT INSERT is zero.
	//
	// What this migration DOES NOT do:
	//   - It does not set org_id NOT NULL (v036 does that)
	//   - It does not add a FK to organizations(id) (v036 does that)
	//   - It does not change behavior of any service code
	//   - It does not activate RLS (v036 creates PERMISSIVE policies)
	//
	// Inheritance vs. blanket default: an earlier draft inherited
	// org_id from the parent row (e.g., mfa_totp.org_id from
	// users.org_id via JOIN). For single-tenant installs the result
	// is identical because every parent row already points at the
	// default org. For installs that have multiple organizations
	// today, this migration alone cannot reconstruct the intent;
	// those installs already have org_id populated where it matters
	// (the org service writes it on create), and any NULL leftovers
	// are unowned rows that the default org takes ownership of —
	// the operator can re-assign via the admin API after upgrade.
	orgIDBackfillUp = `-- Migration 035: backfill default org_id for v2.0 multi-tenancy

-- Defensive: ensure the default org row exists even if an install
-- somehow reaches v35 without v25 having run successfully. v25's
-- canonical row uses this exact id.
INSERT INTO organizations (id, name, slug, domain, plan, status, max_users, max_applications)
VALUES ('00000000-0000-0000-0000-000000000010', 'Default Organization', 'default', NULL, 'enterprise', 'active', 999999, 999999)
ON CONFLICT (id) DO NOTHING;

-- Identity / user-data tables
UPDATE api_keys                    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE email_verification_tokens   SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE known_devices               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE login_history               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE notification_preferences    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE password_history            SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE password_reset_tokens       SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE qr_login_sessions           SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE stepup_challenges           SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE user_consents               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE user_invitations            SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE user_sessions               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE group_memberships           SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE user_application_assignments SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- MFA tables
UPDATE mfa_backup_codes            SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE mfa_policies                SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE mfa_push_challenges         SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE mfa_push_devices            SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE mfa_totp                    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE mfa_webauthn                SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE user_mfa_policies           SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- OAuth tables
UPDATE oauth_access_tokens         SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE oauth_authorization_codes   SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE oauth_refresh_tokens        SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Tables v25 already added org_id to but may have unbackfilled rows
-- (defensive; v25 already does these so this is a no-op in normal
-- installs, but cheap to assert).
UPDATE oauth_clients               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE audit_events                SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE sessions                    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE policies                    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE access_reviews              SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE service_accounts            SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE webhook_subscriptions       SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE access_requests             SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE security_alerts             SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE notifications               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Role / permission joins
UPDATE composite_roles             SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE role_permissions            SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE user_roles                  SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Application / SSO config
UPDATE application_sso_settings    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Group tables
UPDATE group_join_requests         SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Governance / access review / approval
UPDATE access_request_approvals    SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE approval_policies           SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE compliance_reports          SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE review_items                SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Directory integrations / sync
UPDATE directory_integrations      SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE directory_sync_logs         SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE directory_sync_state        SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Identity providers
UPDATE identity_providers          SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Privacy / GDPR
UPDATE data_subject_requests       SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE privacy_assessments         SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE privacy_retention_policies  SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Provisioning / SCIM
UPDATE provisioning_rules          SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE scim_groups                 SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE scim_users                  SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Security / risk
UPDATE credential_rotations        SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE device_posture_results      SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE posture_checks              SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE policy_rules                SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE webhook_deliveries          SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- Proxy (ZTA)
UPDATE proxy_routes                SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE proxy_sessions              SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;

-- OpenZiti
UPDATE ziti_certificates           SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE ziti_identities             SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE ziti_service_policies       SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;
UPDATE ziti_services               SET org_id = '00000000-0000-0000-0000-000000000010' WHERE org_id IS NULL;`

	orgIDBackfillDown = `-- Migration 035 down: reverse the backfill by setting org_id back
-- to NULL for rows that currently hold the default UUID. This is
-- intentionally narrower than the Up's WHERE — it does not touch
-- rows that hold a non-default org_id, so a multi-org install
-- stays intact.
UPDATE ziti_services               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE ziti_service_policies       SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE ziti_identities             SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE ziti_certificates           SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE proxy_sessions              SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE proxy_routes                SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE webhook_deliveries          SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE policy_rules                SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE posture_checks              SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE device_posture_results      SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE credential_rotations        SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE scim_users                  SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE scim_groups                 SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE provisioning_rules          SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE privacy_retention_policies  SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE privacy_assessments         SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE data_subject_requests       SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE identity_providers          SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE directory_sync_state        SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE directory_sync_logs         SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE directory_integrations      SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE review_items                SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE compliance_reports          SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE approval_policies           SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE access_request_approvals    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE group_join_requests         SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE application_sso_settings    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE user_roles                  SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE role_permissions            SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE composite_roles             SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE notifications               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE security_alerts             SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE access_requests             SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE webhook_subscriptions       SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE service_accounts            SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE access_reviews              SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE policies                    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE sessions                    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE audit_events                SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE oauth_clients               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE oauth_refresh_tokens        SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE oauth_authorization_codes   SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE oauth_access_tokens         SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE user_mfa_policies           SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE mfa_webauthn                SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE mfa_totp                    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE mfa_push_devices            SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE mfa_push_challenges         SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE mfa_policies                SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE mfa_backup_codes            SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE user_application_assignments SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE group_memberships           SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE user_sessions               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE user_invitations            SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE user_consents               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE stepup_challenges           SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE qr_login_sessions           SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE password_reset_tokens       SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE password_history            SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE notification_preferences    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE login_history               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE known_devices               SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE email_verification_tokens   SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';
UPDATE api_keys                    SET org_id = NULL WHERE org_id = '00000000-0000-0000-0000-000000000010';`

	// Migration 036 — schema-level constraints and permissive RLS
	// policies. Final foundation-layer migration. After v36, every
	// scoped table has:
	//   - org_id NOT NULL with DEFAULT to the default org UUID
	//     (DEFAULT preserves the v1.6.0 ship gate: existing INSERTs
	//     that omit org_id silently land in the default org;
	//     v1.7.0 final PR drops DEFAULT once service layer is wired)
	//   - FK to organizations(id) ON DELETE RESTRICT (an admin
	//     cannot accidentally orphan a tenants data)
	//   - A permissive RLS policy (USING (true), no behavior change)
	//     that v1.8.0 ALTER POLICY to a real org_id filter
	//
	// RLS itself is NOT enabled on the tables — v1.8.0 owns
	// activation by ALTER TABLE ... ENABLE ROW LEVEL SECURITY.
	//
	// Transactionality: the migrator wraps each migration in a Tx,
	// so partial failure rolls back.
	//
	// Large-install caveat: SET NOT NULL on a table with millions
	// of rows triggers a validation scan. v35 backfilled every row
	// so SET NOT NULL will not reject any existing data; for very
	// large audit/login tables, run during maintenance window.
	orgIDConstraintsUp = `-- Migration 036: schema-level constraints + permissive RLS policies
-- Sets DEFAULT (back-compat), SET NOT NULL (schema correctness),
-- ADD FK to organizations (referential integrity, ON DELETE RESTRICT),
-- CREATE permissive RLS policy (placeholder — v1.8.0 tightens to a
-- real org filter and ALTER TABLE … ENABLE ROW LEVEL SECURITY).

-- Part 1 — DEFAULT preserves v1.6.0 ship gate: existing INSERTs
-- that omit org_id silently land in the default org. v1.7.0 service
-- work will set org_id explicitly; v1.7.0's final PR drops DEFAULT.
ALTER TABLE users                            ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE groups                           ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE roles                            ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE applications                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE oauth_clients                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE audit_events                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE sessions                         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE policies                         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE access_reviews                   ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE service_accounts                 ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE webhook_subscriptions            ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE access_requests                  ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE security_alerts                  ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE notifications                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE api_keys                         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE email_verification_tokens        ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE known_devices                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE login_history                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE notification_preferences         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE password_history                 ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE password_reset_tokens            ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE qr_login_sessions                ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE stepup_challenges                ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE user_consents                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE user_invitations                 ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE user_sessions                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE group_memberships                ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE user_application_assignments     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE mfa_backup_codes                 ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE mfa_policies                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE mfa_push_challenges              ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE mfa_push_devices                 ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE mfa_totp                         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE mfa_webauthn                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE user_mfa_policies                ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE oauth_access_tokens              ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE oauth_authorization_codes        ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE oauth_refresh_tokens             ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE composite_roles                  ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE role_permissions                 ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE user_roles                       ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE application_sso_settings         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE group_join_requests              ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE access_request_approvals         ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE approval_policies                ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE compliance_reports               ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE review_items                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE directory_integrations           ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE directory_sync_logs              ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE directory_sync_state             ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE identity_providers               ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE data_subject_requests            ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE privacy_assessments              ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE privacy_retention_policies       ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE provisioning_rules               ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE scim_groups                      ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE scim_users                       ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE credential_rotations             ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE device_posture_results           ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE posture_checks                   ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE policy_rules                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE webhook_deliveries               ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE proxy_routes                     ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE proxy_sessions                   ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE ziti_certificates                ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE ziti_identities                  ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE ziti_service_policies            ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';
ALTER TABLE ziti_services                    ALTER COLUMN org_id SET DEFAULT '00000000-0000-0000-0000-000000000010';

-- Part 2 — NOT NULL: v35 backfilled every existing row, so this
-- never rewrites data, just metadata. Forces new INSERTs to carry
-- an org_id (or fall back to the DEFAULT above).
ALTER TABLE users                            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE groups                           ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE roles                            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE applications                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE oauth_clients                    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE audit_events                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE sessions                         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE policies                         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE access_reviews                   ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE service_accounts                 ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE webhook_subscriptions            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE access_requests                  ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE security_alerts                  ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE notifications                    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE api_keys                         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE email_verification_tokens        ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE known_devices                    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE login_history                    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE notification_preferences         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE password_history                 ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE password_reset_tokens            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE qr_login_sessions                ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE stepup_challenges                ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE user_consents                    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE user_invitations                 ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE user_sessions                    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE group_memberships                ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE user_application_assignments     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mfa_backup_codes                 ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mfa_policies                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mfa_push_challenges              ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mfa_push_devices                 ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mfa_totp                         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE mfa_webauthn                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE user_mfa_policies                ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE oauth_access_tokens              ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE oauth_authorization_codes        ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE oauth_refresh_tokens             ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE composite_roles                  ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE role_permissions                 ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE user_roles                       ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE application_sso_settings         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE group_join_requests              ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE access_request_approvals         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE approval_policies                ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE compliance_reports               ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE review_items                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE directory_integrations           ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE directory_sync_logs              ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE directory_sync_state             ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE identity_providers               ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE data_subject_requests            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE privacy_assessments              ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE privacy_retention_policies       ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE provisioning_rules               ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE scim_groups                      ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE scim_users                       ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE credential_rotations             ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE device_posture_results           ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE posture_checks                   ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE policy_rules                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE webhook_deliveries               ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE proxy_routes                     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE proxy_sessions                   ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE ziti_certificates                ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE ziti_identities                  ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE ziti_service_policies            ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE ziti_services                    ALTER COLUMN org_id SET NOT NULL;

-- Part 3 — Referential integrity: every org_id row must point at a
-- live organization. ON DELETE RESTRICT prevents accidental tenant
-- deletion from orphaning user/role/audit data.
ALTER TABLE users                            ADD CONSTRAINT fk_users_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE groups                           ADD CONSTRAINT fk_groups_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE roles                            ADD CONSTRAINT fk_roles_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE applications                     ADD CONSTRAINT fk_applications_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE oauth_clients                    ADD CONSTRAINT fk_oauth_clients_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE audit_events                     ADD CONSTRAINT fk_audit_events_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE sessions                         ADD CONSTRAINT fk_sessions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE policies                         ADD CONSTRAINT fk_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE access_reviews                   ADD CONSTRAINT fk_access_reviews_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE service_accounts                 ADD CONSTRAINT fk_service_accounts_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE webhook_subscriptions            ADD CONSTRAINT fk_webhook_subscriptions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE access_requests                  ADD CONSTRAINT fk_access_requests_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE security_alerts                  ADD CONSTRAINT fk_security_alerts_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE notifications                    ADD CONSTRAINT fk_notifications_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE api_keys                         ADD CONSTRAINT fk_api_keys_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE email_verification_tokens        ADD CONSTRAINT fk_email_verification_tokens_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE known_devices                    ADD CONSTRAINT fk_known_devices_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE login_history                    ADD CONSTRAINT fk_login_history_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE notification_preferences         ADD CONSTRAINT fk_notification_preferences_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE password_history                 ADD CONSTRAINT fk_password_history_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE password_reset_tokens            ADD CONSTRAINT fk_password_reset_tokens_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE qr_login_sessions                ADD CONSTRAINT fk_qr_login_sessions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE stepup_challenges                ADD CONSTRAINT fk_stepup_challenges_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE user_consents                    ADD CONSTRAINT fk_user_consents_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE user_invitations                 ADD CONSTRAINT fk_user_invitations_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE user_sessions                    ADD CONSTRAINT fk_user_sessions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE group_memberships                ADD CONSTRAINT fk_group_memberships_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE user_application_assignments     ADD CONSTRAINT fk_user_application_assignments_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE mfa_backup_codes                 ADD CONSTRAINT fk_mfa_backup_codes_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE mfa_policies                     ADD CONSTRAINT fk_mfa_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE mfa_push_challenges              ADD CONSTRAINT fk_mfa_push_challenges_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE mfa_push_devices                 ADD CONSTRAINT fk_mfa_push_devices_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE mfa_totp                         ADD CONSTRAINT fk_mfa_totp_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE mfa_webauthn                     ADD CONSTRAINT fk_mfa_webauthn_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE user_mfa_policies                ADD CONSTRAINT fk_user_mfa_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE oauth_access_tokens              ADD CONSTRAINT fk_oauth_access_tokens_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE oauth_authorization_codes        ADD CONSTRAINT fk_oauth_authorization_codes_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE oauth_refresh_tokens             ADD CONSTRAINT fk_oauth_refresh_tokens_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE composite_roles                  ADD CONSTRAINT fk_composite_roles_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE role_permissions                 ADD CONSTRAINT fk_role_permissions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE user_roles                       ADD CONSTRAINT fk_user_roles_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE application_sso_settings         ADD CONSTRAINT fk_application_sso_settings_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE group_join_requests              ADD CONSTRAINT fk_group_join_requests_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE access_request_approvals         ADD CONSTRAINT fk_access_request_approvals_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE approval_policies                ADD CONSTRAINT fk_approval_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE compliance_reports               ADD CONSTRAINT fk_compliance_reports_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE review_items                     ADD CONSTRAINT fk_review_items_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE directory_integrations           ADD CONSTRAINT fk_directory_integrations_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE directory_sync_logs              ADD CONSTRAINT fk_directory_sync_logs_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE directory_sync_state             ADD CONSTRAINT fk_directory_sync_state_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE identity_providers               ADD CONSTRAINT fk_identity_providers_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE data_subject_requests            ADD CONSTRAINT fk_data_subject_requests_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE privacy_assessments              ADD CONSTRAINT fk_privacy_assessments_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE privacy_retention_policies       ADD CONSTRAINT fk_privacy_retention_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE provisioning_rules               ADD CONSTRAINT fk_provisioning_rules_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE scim_groups                      ADD CONSTRAINT fk_scim_groups_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE scim_users                       ADD CONSTRAINT fk_scim_users_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE credential_rotations             ADD CONSTRAINT fk_credential_rotations_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE device_posture_results           ADD CONSTRAINT fk_device_posture_results_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE posture_checks                   ADD CONSTRAINT fk_posture_checks_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE policy_rules                     ADD CONSTRAINT fk_policy_rules_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE webhook_deliveries               ADD CONSTRAINT fk_webhook_deliveries_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE proxy_routes                     ADD CONSTRAINT fk_proxy_routes_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE proxy_sessions                   ADD CONSTRAINT fk_proxy_sessions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE ziti_certificates                ADD CONSTRAINT fk_ziti_certificates_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE ziti_identities                  ADD CONSTRAINT fk_ziti_identities_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE ziti_service_policies            ADD CONSTRAINT fk_ziti_service_policies_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE ziti_services                    ADD CONSTRAINT fk_ziti_services_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE RESTRICT;

-- Part 4 — Permissive RLS policies. The table still has RLS OFF
-- (no ALTER TABLE … ENABLE ROW LEVEL SECURITY here) so the policy
-- is dormant. v1.8.0 ALTER POLICY to replace USING(true) with the
-- real org_id filter, then ALTER TABLE … ENABLE ROW LEVEL SECURITY
-- to make it the belt over the v1.7.0 app-layer suspenders.
CREATE POLICY pol_users_org_scope ON users AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_groups_org_scope ON groups AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_roles_org_scope ON roles AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_applications_org_scope ON applications AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_oauth_clients_org_scope ON oauth_clients AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_audit_events_org_scope ON audit_events AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_sessions_org_scope ON sessions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_policies_org_scope ON policies AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_access_reviews_org_scope ON access_reviews AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_service_accounts_org_scope ON service_accounts AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_webhook_subscriptions_org_scope ON webhook_subscriptions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_access_requests_org_scope ON access_requests AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_security_alerts_org_scope ON security_alerts AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_notifications_org_scope ON notifications AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_api_keys_org_scope ON api_keys AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_email_verification_tokens_org_scope ON email_verification_tokens AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_known_devices_org_scope ON known_devices AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_login_history_org_scope ON login_history AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_notification_preferences_org_scope ON notification_preferences AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_password_history_org_scope ON password_history AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_password_reset_tokens_org_scope ON password_reset_tokens AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_qr_login_sessions_org_scope ON qr_login_sessions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_stepup_challenges_org_scope ON stepup_challenges AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_user_consents_org_scope ON user_consents AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_user_invitations_org_scope ON user_invitations AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_user_sessions_org_scope ON user_sessions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_group_memberships_org_scope ON group_memberships AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_user_application_assignments_org_scope ON user_application_assignments AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_mfa_backup_codes_org_scope ON mfa_backup_codes AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_mfa_policies_org_scope ON mfa_policies AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_mfa_push_challenges_org_scope ON mfa_push_challenges AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_mfa_push_devices_org_scope ON mfa_push_devices AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_mfa_totp_org_scope ON mfa_totp AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_mfa_webauthn_org_scope ON mfa_webauthn AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_user_mfa_policies_org_scope ON user_mfa_policies AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_oauth_access_tokens_org_scope ON oauth_access_tokens AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_oauth_authorization_codes_org_scope ON oauth_authorization_codes AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_oauth_refresh_tokens_org_scope ON oauth_refresh_tokens AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_composite_roles_org_scope ON composite_roles AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_role_permissions_org_scope ON role_permissions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_user_roles_org_scope ON user_roles AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_application_sso_settings_org_scope ON application_sso_settings AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_group_join_requests_org_scope ON group_join_requests AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_access_request_approvals_org_scope ON access_request_approvals AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_approval_policies_org_scope ON approval_policies AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_compliance_reports_org_scope ON compliance_reports AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_review_items_org_scope ON review_items AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_directory_integrations_org_scope ON directory_integrations AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_directory_sync_logs_org_scope ON directory_sync_logs AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_directory_sync_state_org_scope ON directory_sync_state AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_identity_providers_org_scope ON identity_providers AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_data_subject_requests_org_scope ON data_subject_requests AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_privacy_assessments_org_scope ON privacy_assessments AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_privacy_retention_policies_org_scope ON privacy_retention_policies AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_provisioning_rules_org_scope ON provisioning_rules AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_scim_groups_org_scope ON scim_groups AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_scim_users_org_scope ON scim_users AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_credential_rotations_org_scope ON credential_rotations AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_device_posture_results_org_scope ON device_posture_results AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_posture_checks_org_scope ON posture_checks AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_policy_rules_org_scope ON policy_rules AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_webhook_deliveries_org_scope ON webhook_deliveries AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_proxy_routes_org_scope ON proxy_routes AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_proxy_sessions_org_scope ON proxy_sessions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_ziti_certificates_org_scope ON ziti_certificates AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_ziti_identities_org_scope ON ziti_identities AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_ziti_service_policies_org_scope ON ziti_service_policies AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY pol_ziti_services_org_scope ON ziti_services AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
`

	orgIDConstraintsDown = `-- Migration 036 down: reverse in the opposite order — drop policies
-- first (they reference the table), then drop FK constraints, then
-- drop NOT NULL, then drop DEFAULT. Idempotent via IF EXISTS.

DROP POLICY IF EXISTS pol_users_org_scope ON users;
DROP POLICY IF EXISTS pol_groups_org_scope ON groups;
DROP POLICY IF EXISTS pol_roles_org_scope ON roles;
DROP POLICY IF EXISTS pol_applications_org_scope ON applications;
DROP POLICY IF EXISTS pol_oauth_clients_org_scope ON oauth_clients;
DROP POLICY IF EXISTS pol_audit_events_org_scope ON audit_events;
DROP POLICY IF EXISTS pol_sessions_org_scope ON sessions;
DROP POLICY IF EXISTS pol_policies_org_scope ON policies;
DROP POLICY IF EXISTS pol_access_reviews_org_scope ON access_reviews;
DROP POLICY IF EXISTS pol_service_accounts_org_scope ON service_accounts;
DROP POLICY IF EXISTS pol_webhook_subscriptions_org_scope ON webhook_subscriptions;
DROP POLICY IF EXISTS pol_access_requests_org_scope ON access_requests;
DROP POLICY IF EXISTS pol_security_alerts_org_scope ON security_alerts;
DROP POLICY IF EXISTS pol_notifications_org_scope ON notifications;
DROP POLICY IF EXISTS pol_api_keys_org_scope ON api_keys;
DROP POLICY IF EXISTS pol_email_verification_tokens_org_scope ON email_verification_tokens;
DROP POLICY IF EXISTS pol_known_devices_org_scope ON known_devices;
DROP POLICY IF EXISTS pol_login_history_org_scope ON login_history;
DROP POLICY IF EXISTS pol_notification_preferences_org_scope ON notification_preferences;
DROP POLICY IF EXISTS pol_password_history_org_scope ON password_history;
DROP POLICY IF EXISTS pol_password_reset_tokens_org_scope ON password_reset_tokens;
DROP POLICY IF EXISTS pol_qr_login_sessions_org_scope ON qr_login_sessions;
DROP POLICY IF EXISTS pol_stepup_challenges_org_scope ON stepup_challenges;
DROP POLICY IF EXISTS pol_user_consents_org_scope ON user_consents;
DROP POLICY IF EXISTS pol_user_invitations_org_scope ON user_invitations;
DROP POLICY IF EXISTS pol_user_sessions_org_scope ON user_sessions;
DROP POLICY IF EXISTS pol_group_memberships_org_scope ON group_memberships;
DROP POLICY IF EXISTS pol_user_application_assignments_org_scope ON user_application_assignments;
DROP POLICY IF EXISTS pol_mfa_backup_codes_org_scope ON mfa_backup_codes;
DROP POLICY IF EXISTS pol_mfa_policies_org_scope ON mfa_policies;
DROP POLICY IF EXISTS pol_mfa_push_challenges_org_scope ON mfa_push_challenges;
DROP POLICY IF EXISTS pol_mfa_push_devices_org_scope ON mfa_push_devices;
DROP POLICY IF EXISTS pol_mfa_totp_org_scope ON mfa_totp;
DROP POLICY IF EXISTS pol_mfa_webauthn_org_scope ON mfa_webauthn;
DROP POLICY IF EXISTS pol_user_mfa_policies_org_scope ON user_mfa_policies;
DROP POLICY IF EXISTS pol_oauth_access_tokens_org_scope ON oauth_access_tokens;
DROP POLICY IF EXISTS pol_oauth_authorization_codes_org_scope ON oauth_authorization_codes;
DROP POLICY IF EXISTS pol_oauth_refresh_tokens_org_scope ON oauth_refresh_tokens;
DROP POLICY IF EXISTS pol_composite_roles_org_scope ON composite_roles;
DROP POLICY IF EXISTS pol_role_permissions_org_scope ON role_permissions;
DROP POLICY IF EXISTS pol_user_roles_org_scope ON user_roles;
DROP POLICY IF EXISTS pol_application_sso_settings_org_scope ON application_sso_settings;
DROP POLICY IF EXISTS pol_group_join_requests_org_scope ON group_join_requests;
DROP POLICY IF EXISTS pol_access_request_approvals_org_scope ON access_request_approvals;
DROP POLICY IF EXISTS pol_approval_policies_org_scope ON approval_policies;
DROP POLICY IF EXISTS pol_compliance_reports_org_scope ON compliance_reports;
DROP POLICY IF EXISTS pol_review_items_org_scope ON review_items;
DROP POLICY IF EXISTS pol_directory_integrations_org_scope ON directory_integrations;
DROP POLICY IF EXISTS pol_directory_sync_logs_org_scope ON directory_sync_logs;
DROP POLICY IF EXISTS pol_directory_sync_state_org_scope ON directory_sync_state;
DROP POLICY IF EXISTS pol_identity_providers_org_scope ON identity_providers;
DROP POLICY IF EXISTS pol_data_subject_requests_org_scope ON data_subject_requests;
DROP POLICY IF EXISTS pol_privacy_assessments_org_scope ON privacy_assessments;
DROP POLICY IF EXISTS pol_privacy_retention_policies_org_scope ON privacy_retention_policies;
DROP POLICY IF EXISTS pol_provisioning_rules_org_scope ON provisioning_rules;
DROP POLICY IF EXISTS pol_scim_groups_org_scope ON scim_groups;
DROP POLICY IF EXISTS pol_scim_users_org_scope ON scim_users;
DROP POLICY IF EXISTS pol_credential_rotations_org_scope ON credential_rotations;
DROP POLICY IF EXISTS pol_device_posture_results_org_scope ON device_posture_results;
DROP POLICY IF EXISTS pol_posture_checks_org_scope ON posture_checks;
DROP POLICY IF EXISTS pol_policy_rules_org_scope ON policy_rules;
DROP POLICY IF EXISTS pol_webhook_deliveries_org_scope ON webhook_deliveries;
DROP POLICY IF EXISTS pol_proxy_routes_org_scope ON proxy_routes;
DROP POLICY IF EXISTS pol_proxy_sessions_org_scope ON proxy_sessions;
DROP POLICY IF EXISTS pol_ziti_certificates_org_scope ON ziti_certificates;
DROP POLICY IF EXISTS pol_ziti_identities_org_scope ON ziti_identities;
DROP POLICY IF EXISTS pol_ziti_service_policies_org_scope ON ziti_service_policies;
DROP POLICY IF EXISTS pol_ziti_services_org_scope ON ziti_services;

ALTER TABLE users                            DROP CONSTRAINT IF EXISTS fk_users_org;
ALTER TABLE groups                           DROP CONSTRAINT IF EXISTS fk_groups_org;
ALTER TABLE roles                            DROP CONSTRAINT IF EXISTS fk_roles_org;
ALTER TABLE applications                     DROP CONSTRAINT IF EXISTS fk_applications_org;
ALTER TABLE oauth_clients                    DROP CONSTRAINT IF EXISTS fk_oauth_clients_org;
ALTER TABLE audit_events                     DROP CONSTRAINT IF EXISTS fk_audit_events_org;
ALTER TABLE sessions                         DROP CONSTRAINT IF EXISTS fk_sessions_org;
ALTER TABLE policies                         DROP CONSTRAINT IF EXISTS fk_policies_org;
ALTER TABLE access_reviews                   DROP CONSTRAINT IF EXISTS fk_access_reviews_org;
ALTER TABLE service_accounts                 DROP CONSTRAINT IF EXISTS fk_service_accounts_org;
ALTER TABLE webhook_subscriptions            DROP CONSTRAINT IF EXISTS fk_webhook_subscriptions_org;
ALTER TABLE access_requests                  DROP CONSTRAINT IF EXISTS fk_access_requests_org;
ALTER TABLE security_alerts                  DROP CONSTRAINT IF EXISTS fk_security_alerts_org;
ALTER TABLE notifications                    DROP CONSTRAINT IF EXISTS fk_notifications_org;
ALTER TABLE api_keys                         DROP CONSTRAINT IF EXISTS fk_api_keys_org;
ALTER TABLE email_verification_tokens        DROP CONSTRAINT IF EXISTS fk_email_verification_tokens_org;
ALTER TABLE known_devices                    DROP CONSTRAINT IF EXISTS fk_known_devices_org;
ALTER TABLE login_history                    DROP CONSTRAINT IF EXISTS fk_login_history_org;
ALTER TABLE notification_preferences         DROP CONSTRAINT IF EXISTS fk_notification_preferences_org;
ALTER TABLE password_history                 DROP CONSTRAINT IF EXISTS fk_password_history_org;
ALTER TABLE password_reset_tokens            DROP CONSTRAINT IF EXISTS fk_password_reset_tokens_org;
ALTER TABLE qr_login_sessions                DROP CONSTRAINT IF EXISTS fk_qr_login_sessions_org;
ALTER TABLE stepup_challenges                DROP CONSTRAINT IF EXISTS fk_stepup_challenges_org;
ALTER TABLE user_consents                    DROP CONSTRAINT IF EXISTS fk_user_consents_org;
ALTER TABLE user_invitations                 DROP CONSTRAINT IF EXISTS fk_user_invitations_org;
ALTER TABLE user_sessions                    DROP CONSTRAINT IF EXISTS fk_user_sessions_org;
ALTER TABLE group_memberships                DROP CONSTRAINT IF EXISTS fk_group_memberships_org;
ALTER TABLE user_application_assignments     DROP CONSTRAINT IF EXISTS fk_user_application_assignments_org;
ALTER TABLE mfa_backup_codes                 DROP CONSTRAINT IF EXISTS fk_mfa_backup_codes_org;
ALTER TABLE mfa_policies                     DROP CONSTRAINT IF EXISTS fk_mfa_policies_org;
ALTER TABLE mfa_push_challenges              DROP CONSTRAINT IF EXISTS fk_mfa_push_challenges_org;
ALTER TABLE mfa_push_devices                 DROP CONSTRAINT IF EXISTS fk_mfa_push_devices_org;
ALTER TABLE mfa_totp                         DROP CONSTRAINT IF EXISTS fk_mfa_totp_org;
ALTER TABLE mfa_webauthn                     DROP CONSTRAINT IF EXISTS fk_mfa_webauthn_org;
ALTER TABLE user_mfa_policies                DROP CONSTRAINT IF EXISTS fk_user_mfa_policies_org;
ALTER TABLE oauth_access_tokens              DROP CONSTRAINT IF EXISTS fk_oauth_access_tokens_org;
ALTER TABLE oauth_authorization_codes        DROP CONSTRAINT IF EXISTS fk_oauth_authorization_codes_org;
ALTER TABLE oauth_refresh_tokens             DROP CONSTRAINT IF EXISTS fk_oauth_refresh_tokens_org;
ALTER TABLE composite_roles                  DROP CONSTRAINT IF EXISTS fk_composite_roles_org;
ALTER TABLE role_permissions                 DROP CONSTRAINT IF EXISTS fk_role_permissions_org;
ALTER TABLE user_roles                       DROP CONSTRAINT IF EXISTS fk_user_roles_org;
ALTER TABLE application_sso_settings         DROP CONSTRAINT IF EXISTS fk_application_sso_settings_org;
ALTER TABLE group_join_requests              DROP CONSTRAINT IF EXISTS fk_group_join_requests_org;
ALTER TABLE access_request_approvals         DROP CONSTRAINT IF EXISTS fk_access_request_approvals_org;
ALTER TABLE approval_policies                DROP CONSTRAINT IF EXISTS fk_approval_policies_org;
ALTER TABLE compliance_reports               DROP CONSTRAINT IF EXISTS fk_compliance_reports_org;
ALTER TABLE review_items                     DROP CONSTRAINT IF EXISTS fk_review_items_org;
ALTER TABLE directory_integrations           DROP CONSTRAINT IF EXISTS fk_directory_integrations_org;
ALTER TABLE directory_sync_logs              DROP CONSTRAINT IF EXISTS fk_directory_sync_logs_org;
ALTER TABLE directory_sync_state             DROP CONSTRAINT IF EXISTS fk_directory_sync_state_org;
ALTER TABLE identity_providers               DROP CONSTRAINT IF EXISTS fk_identity_providers_org;
ALTER TABLE data_subject_requests            DROP CONSTRAINT IF EXISTS fk_data_subject_requests_org;
ALTER TABLE privacy_assessments              DROP CONSTRAINT IF EXISTS fk_privacy_assessments_org;
ALTER TABLE privacy_retention_policies       DROP CONSTRAINT IF EXISTS fk_privacy_retention_policies_org;
ALTER TABLE provisioning_rules               DROP CONSTRAINT IF EXISTS fk_provisioning_rules_org;
ALTER TABLE scim_groups                      DROP CONSTRAINT IF EXISTS fk_scim_groups_org;
ALTER TABLE scim_users                       DROP CONSTRAINT IF EXISTS fk_scim_users_org;
ALTER TABLE credential_rotations             DROP CONSTRAINT IF EXISTS fk_credential_rotations_org;
ALTER TABLE device_posture_results           DROP CONSTRAINT IF EXISTS fk_device_posture_results_org;
ALTER TABLE posture_checks                   DROP CONSTRAINT IF EXISTS fk_posture_checks_org;
ALTER TABLE policy_rules                     DROP CONSTRAINT IF EXISTS fk_policy_rules_org;
ALTER TABLE webhook_deliveries               DROP CONSTRAINT IF EXISTS fk_webhook_deliveries_org;
ALTER TABLE proxy_routes                     DROP CONSTRAINT IF EXISTS fk_proxy_routes_org;
ALTER TABLE proxy_sessions                   DROP CONSTRAINT IF EXISTS fk_proxy_sessions_org;
ALTER TABLE ziti_certificates                DROP CONSTRAINT IF EXISTS fk_ziti_certificates_org;
ALTER TABLE ziti_identities                  DROP CONSTRAINT IF EXISTS fk_ziti_identities_org;
ALTER TABLE ziti_service_policies            DROP CONSTRAINT IF EXISTS fk_ziti_service_policies_org;
ALTER TABLE ziti_services                    DROP CONSTRAINT IF EXISTS fk_ziti_services_org;

ALTER TABLE users                            ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE groups                           ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE roles                            ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE applications                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE oauth_clients                    ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE audit_events                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE sessions                         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE policies                         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE access_reviews                   ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE service_accounts                 ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE webhook_subscriptions            ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE access_requests                  ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE security_alerts                  ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE notifications                    ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE api_keys                         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE email_verification_tokens        ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE known_devices                    ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE login_history                    ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE notification_preferences         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE password_history                 ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE password_reset_tokens            ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE qr_login_sessions                ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE stepup_challenges                ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE user_consents                    ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE user_invitations                 ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE user_sessions                    ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE group_memberships                ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE user_application_assignments     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mfa_backup_codes                 ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mfa_policies                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mfa_push_challenges              ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mfa_push_devices                 ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mfa_totp                         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE mfa_webauthn                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE user_mfa_policies                ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE oauth_access_tokens              ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE oauth_authorization_codes        ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE oauth_refresh_tokens             ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE composite_roles                  ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE role_permissions                 ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE user_roles                       ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE application_sso_settings         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE group_join_requests              ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE access_request_approvals         ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE approval_policies                ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE compliance_reports               ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE review_items                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE directory_integrations           ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE directory_sync_logs              ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE directory_sync_state             ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE identity_providers               ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE data_subject_requests            ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE privacy_assessments              ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE privacy_retention_policies       ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE provisioning_rules               ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE scim_groups                      ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE scim_users                       ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE credential_rotations             ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE device_posture_results           ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE posture_checks                   ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE policy_rules                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE webhook_deliveries               ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE proxy_routes                     ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE proxy_sessions                   ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE ziti_certificates                ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE ziti_identities                  ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE ziti_service_policies            ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE ziti_services                    ALTER COLUMN org_id DROP NOT NULL;

ALTER TABLE users                            ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE groups                           ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE roles                            ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE applications                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE oauth_clients                    ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE audit_events                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE sessions                         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE policies                         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE access_reviews                   ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE service_accounts                 ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE webhook_subscriptions            ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE access_requests                  ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE security_alerts                  ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE notifications                    ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE api_keys                         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE email_verification_tokens        ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE known_devices                    ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE login_history                    ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE notification_preferences         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE password_history                 ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE password_reset_tokens            ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE qr_login_sessions                ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE stepup_challenges                ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE user_consents                    ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE user_invitations                 ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE user_sessions                    ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE group_memberships                ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE user_application_assignments     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE mfa_backup_codes                 ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE mfa_policies                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE mfa_push_challenges              ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE mfa_push_devices                 ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE mfa_totp                         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE mfa_webauthn                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE user_mfa_policies                ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE oauth_access_tokens              ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE oauth_authorization_codes        ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE oauth_refresh_tokens             ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE composite_roles                  ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE role_permissions                 ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE user_roles                       ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE application_sso_settings         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE group_join_requests              ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE access_request_approvals         ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE approval_policies                ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE compliance_reports               ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE review_items                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE directory_integrations           ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE directory_sync_logs              ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE directory_sync_state             ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE identity_providers               ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE data_subject_requests            ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE privacy_assessments              ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE privacy_retention_policies       ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE provisioning_rules               ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE scim_groups                      ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE scim_users                       ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE credential_rotations             ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE device_posture_results           ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE posture_checks                   ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE policy_rules                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE webhook_deliveries               ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE proxy_routes                     ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE proxy_sessions                   ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE ziti_certificates                ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE ziti_identities                  ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE ziti_service_policies            ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE ziti_services                    ALTER COLUMN org_id DROP DEFAULT;
`
)
