package migrations

// Migration v129 — seed the standard transactional email templates.
//
// The Email Templates admin page (GET/PUT /api/v1/email-templates) can only
// list and edit templates; there is no create endpoint and no migration ever
// seeded the email_templates table, so the page was permanently empty and the
// edit workflow was untestable (QA 10.4). This seeds the canonical set of
// transactional templates the platform sends (magic link, invitation, password
// reset, email verification, MFA enrollment, welcome) so admins have real rows
// to view and customize.
//
// Idempotent: keyed on the UNIQUE slug with ON CONFLICT DO NOTHING, so it never
// clobbers an admin's edits and is safe to re-run.
var seedEmailTemplatesUp = `-- Migration 129: seed standard email templates.
INSERT INTO email_templates (name, slug, subject, html_body, text_body, category, variables, enabled)
VALUES
  (
    'Magic Link Sign-In',
    'magic-link',
    'Your OpenIDX sign-in link',
    '<p>Hello {{.Name}},</p><p>Click the button below to sign in to OpenIDX. This link expires in {{.ExpiryMinutes}} minutes.</p><p><a href="{{.MagicLink}}">Sign in to OpenIDX</a></p><p>If you did not request this, you can safely ignore this email.</p>',
    'Hello {{.Name}},

Use this link to sign in to OpenIDX (expires in {{.ExpiryMinutes}} minutes):
{{.MagicLink}}

If you did not request this, you can safely ignore this email.',
    'authentication',
    '["Name","MagicLink","ExpiryMinutes"]'::jsonb,
    true
  ),
  (
    'User Invitation',
    'user-invite',
    'You have been invited to {{.OrganizationName}} on OpenIDX',
    '<p>Hello,</p><p>{{.InviterName}} has invited you to join <strong>{{.OrganizationName}}</strong> on OpenIDX.</p><p><a href="{{.InviteLink}}">Accept your invitation</a></p><p>This invitation expires on {{.ExpiryDate}}.</p>',
    'Hello,

{{.InviterName}} has invited you to join {{.OrganizationName}} on OpenIDX.

Accept your invitation: {{.InviteLink}}

This invitation expires on {{.ExpiryDate}}.',
    'onboarding',
    '["InviterName","OrganizationName","InviteLink","ExpiryDate"]'::jsonb,
    true
  ),
  (
    'Password Reset',
    'password-reset',
    'Reset your OpenIDX password',
    '<p>Hello {{.Name}},</p><p>We received a request to reset your OpenIDX password. Click below to choose a new one. This link expires in {{.ExpiryMinutes}} minutes.</p><p><a href="{{.ResetLink}}">Reset password</a></p><p>If you did not request this, no action is needed and your password will remain unchanged.</p>',
    'Hello {{.Name}},

We received a request to reset your OpenIDX password (link expires in {{.ExpiryMinutes}} minutes):
{{.ResetLink}}

If you did not request this, no action is needed.',
    'authentication',
    '["Name","ResetLink","ExpiryMinutes"]'::jsonb,
    true
  ),
  (
    'Email Verification',
    'email-verification',
    'Verify your OpenIDX email address',
    '<p>Hello {{.Name}},</p><p>Please confirm your email address to finish setting up your OpenIDX account.</p><p><a href="{{.VerifyLink}}">Verify email address</a></p><p>This link expires in {{.ExpiryHours}} hours.</p>',
    'Hello {{.Name}},

Please confirm your email address to finish setting up your OpenIDX account:
{{.VerifyLink}}

This link expires in {{.ExpiryHours}} hours.',
    'onboarding',
    '["Name","VerifyLink","ExpiryHours"]'::jsonb,
    true
  ),
  (
    'MFA Enrollment Reminder',
    'mfa-enrollment',
    'Secure your OpenIDX account with multi-factor authentication',
    '<p>Hello {{.Name}},</p><p>Your organization requires multi-factor authentication. Enroll a second factor to keep access to your account.</p><p><a href="{{.EnrollLink}}">Set up MFA</a></p>',
    'Hello {{.Name}},

Your organization requires multi-factor authentication. Set up a second factor here:
{{.EnrollLink}}',
    'security',
    '["Name","EnrollLink"]'::jsonb,
    true
  ),
  (
    'Welcome',
    'welcome',
    'Welcome to {{.OrganizationName}} on OpenIDX',
    '<p>Hello {{.Name}},</p><p>Welcome to <strong>{{.OrganizationName}}</strong>! Your OpenIDX account is ready.</p><p><a href="{{.LoginLink}}">Go to your dashboard</a></p>',
    'Hello {{.Name}},

Welcome to {{.OrganizationName}}! Your OpenIDX account is ready.
Go to your dashboard: {{.LoginLink}}',
    'onboarding',
    '["Name","OrganizationName","LoginLink"]'::jsonb,
    true
  )
ON CONFLICT (slug) DO NOTHING;
`

// Down removes only the seeded templates (by slug), leaving any admin-created
// rows intact.
var seedEmailTemplatesDown = `-- Rollback 129: remove seeded email templates.
DELETE FROM email_templates WHERE slug IN (
  'magic-link','user-invite','password-reset','email-verification','mfa-enrollment','welcome'
);
`
