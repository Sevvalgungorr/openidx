package migrations

// Migration v131 — seed the OAuth Playground client.
//
// The OAuth Playground (/oauth-playground) defaults to client_id
// "playground-client" (internal/admin/developer.go), but that client was never
// registered in oauth_clients. So Step 2 "Authorize" always failed with
// {"error":"invalid_client"} and Steps 3-4 were untestable (QA 11.2).
//
// This seeds a public PKCE client for the playground. It is a public client
// (no secret, PKCE required) — the playground runs in the browser and never
// holds a secret. redirect_uris cover the origins the console's baseURL
// resolves to: the SPA dev origin (:3000), the admin-api dev origin (:8005),
// and the production site. The playground reconstructs redirect_uri from that
// same baseURL, so one of these must match exactly for /oauth/authorize to
// accept it. Idempotent via ON CONFLICT (id) DO NOTHING.
var seedPlaygroundClientUp = `-- Migration 131: seed the OAuth Playground public client.
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type,
	redirect_uris, grant_types, response_types, scopes, pkce_required,
	allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000006', 'playground-client', NULL,
 'OAuth Playground', 'Interactive OAuth 2.0 + PKCE playground client', 'public',
 '["http://localhost:3000/oauth/callback", "http://localhost:8005/oauth/callback", "https://openidx.tdv.org/oauth/callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 86400)
ON CONFLICT (id) DO NOTHING;
`

var seedPlaygroundClientDown = `-- Rollback migration 131.
DELETE FROM oauth_clients WHERE id = '80000000-0000-0000-0000-000000000006';
`
