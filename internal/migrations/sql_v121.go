package migrations

// Migration v121 — extend the FORCE-RLS belt to six tables that missed it.
//
// The v37 belt (extended by v81/v94) puts every org-scoped table behind a
// Postgres row-level-security policy keyed on the `app.org_id` GUC that
// internal/common/database/rls.go sets at pool checkout. Six org-scoped tables
// were added afterwards without the belt:
//
//   - ssf_streams (v99) — the v99 migration's own comment calls it
//     "org-scoped for RLS", but no policy was ever created. Combined with an
//     OR-escape in the app-layer predicates this allowed cross-tenant reads
//     and writes of SSF/CAEP stream config; the route and query fixes ship
//     alongside this migration, and the belt is the DB-level backstop that
//     makes a future regression impossible.
//   - session_risks, risk_factors (v77), recording_retention_policies (v78) —
//     app code scopes these correctly today (they are already in
//     tools/orgscope's table list), but without an RLS policy a single missing
//     `AND org_id = $N` in a future change would leak silently.
//
// Its two sibling tables are deliberately EXCLUDED, because they are not
// tenant-partitioned in practice and forcing RLS would break the feature:
//   - ssf_stream_delivery — the outbox, drained by a background worker that
//     runs cross-org under bypass_rls and addresses rows by primary key.
//   - ssf_received_events — an install-wide replay-dedup log of INBOUND SETs,
//     written by the public receiver endpoint (SETs are authenticated by
//     signature, not by a session), which has no tenant context and stores no
//     org_id at all; a policy would reject every insert.
//
// ssf_streams allows a NULL org_id from before this change; those rows become
// invisible under the policy, which is the correct fail-closed direction (they
// could only have been created through the vulnerability being fixed).
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
// Idempotent: DROP POLICY IF EXISTS + CREATE POLICY, and ALTER … ENABLE/FORCE
// is a no-op when already set.
var rlsBeltGapUp = `-- Migration 121: close the FORCE-RLS belt gaps (SSF + risk + retention).

DROP POLICY IF EXISTS pol_ssf_streams_org_scope ON ssf_streams;
CREATE POLICY pol_ssf_streams_org_scope ON ssf_streams
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ssf_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_streams FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_session_risks_org_scope ON session_risks;
CREATE POLICY pol_session_risks_org_scope ON session_risks
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE session_risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_risks FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_risk_factors_org_scope ON risk_factors;
CREATE POLICY pol_risk_factors_org_scope ON risk_factors
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE risk_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_factors FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_recording_retention_policies_org_scope ON recording_retention_policies;
CREATE POLICY pol_recording_retention_policies_org_scope ON recording_retention_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE recording_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE recording_retention_policies FORCE  ROW LEVEL SECURITY;
`

var rlsBeltGapDown = `-- Rollback 121.
ALTER TABLE ssf_streams NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ssf_streams DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_ssf_streams_org_scope ON ssf_streams;

ALTER TABLE session_risks NO FORCE ROW LEVEL SECURITY;
ALTER TABLE session_risks DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_session_risks_org_scope ON session_risks;

ALTER TABLE risk_factors NO FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_factors DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_risk_factors_org_scope ON risk_factors;

ALTER TABLE recording_retention_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE recording_retention_policies DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_recording_retention_policies_org_scope ON recording_retention_policies;
`
