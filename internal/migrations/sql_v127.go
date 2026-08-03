package migrations

// Migration v127 — allow social_providers.provider_id to be NULL.
//
// social_providers is the display/config table for the social-login buttons on
// the sign-in page. Its provider_id was defined NOT NULL with a foreign key to
// identity_providers(id): the intent was that every social button links to a
// fully-configured OIDC identity provider (where client_id/secret live).
//
// But the admin console's "create social provider" flow only collects a
// provider_key ("google", "github", ...) plus display fields; it does not (yet)
// require picking or creating an identity_providers row. So the INSERT sent an
// empty/absent provider_id into a NOT NULL uuid column and every create failed
// with 500 "invalid input syntax for type uuid" (SQLSTATE 22P02).
//
// Making provider_id nullable lets an admin register a social-login button
// immediately and link it to a configured identity provider later. The FK (ON
// DELETE CASCADE) and the list LEFT JOIN already tolerate NULL.
var socialProvidersNullableProviderIDUp = `-- Migration 127: social_providers.provider_id nullable.
ALTER TABLE social_providers ALTER COLUMN provider_id DROP NOT NULL;
`

var socialProvidersNullableProviderIDDown = `-- Rollback 127.
-- Only re-add NOT NULL if no NULLs exist, so rollback cannot fail on real data.
UPDATE social_providers SET provider_id = provider_id WHERE false;
ALTER TABLE social_providers ALTER COLUMN provider_id SET NOT NULL;
`
