# dbproxy — PostgreSQL wire-protocol session broker (PAM B1)

Lets an operator use their **native `psql`** (or any Postgres driver) against a
protected database **without ever holding the real database credentials** and
without the database being directly reachable.

## Flow

```
psql "host=oidx-dbproxy port=6432 user=<ignored> dbname=<ignored>"  password=<OpenIDX broker token>
        │
        ▼
   ┌───────────┐  1. startup + AuthenticationCleartextPassword
   │  dbproxy  │  2. validate broker token → resolve upstream + vault credential
   │  (this    │  3. dial upstream, auth with the REAL credential (server-side only)
   │  package) │  4. relay; decode Query/Parse → AuditSink
   └───────────┘
        │
        ▼
   real PostgreSQL (never exposed to the client)
```

The operator authenticates with a **short-lived OpenIDX broker token** supplied
as the Postgres password. The real database username/password come from the
vault and are injected server-side; they never reach the client. Every
statement is decoded and emitted to the audit sink.

## What this cut includes

- Full frontend handshake (startup, SSL/GSS negotiation denied → cleartext
  retry, cleartext-password auth).
- Pluggable `TokenAuthenticator` (validates the broker token → `UpstreamTarget`
  with the vault-injected credential) and `AuditSink` (per-statement audit).
- Upstream startup + auth for **trust / cleartext / md5 / SCRAM-SHA-256**
  (the default for modern PostgreSQL), so the proxy authenticates to real
  managed databases.
- Bidirectional relay with client→server `Query`/`Parse` decoding for audit.
- Integration test: a fake upstream Postgres + the proxy + a real `pgproto3`
  client proving native-protocol auth, relay, query audit, and bad-token
  rejection — plus SCRAM client-flow unit tests. **Live-proven** against real
  PostgreSQL: a native `pgx` client connected through the proxy with only a
  broker token, the proxy authenticated upstream via SCRAM-SHA-256 with the
  injected credential, ran real queries, and every statement was audited.

## Follow-ups (tracked separately)

- **Live wiring in access-service:** a `TokenAuthenticator` backed by
  `brokered_sessions` + the vault (issue a `db`-type broker token via
  `/pam/connect/db`, resolve it here), and a listener started from
  `cmd/access-service` on a configurable port (feature-flagged, default off).
- **TLS termination** at the proxy (client side) and upstream TLS +
  SCRAM-SHA-256-PLUS channel binding.
- **Policy enforcement / masking:** the same decode point that audits `Query`
  can reject or rewrite statements against OPA policy.

## Why a wire proxy (not a query API)

Native tooling "just works" — `psql`, ORMs, migration tools, BI clients — with
zero credential distribution and full central audit. This is the differentiator
StrongDM / Teleport DB access sell; OpenIDX brings it into the unified platform.
