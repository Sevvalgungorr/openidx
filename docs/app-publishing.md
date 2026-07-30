# App Publishing

App Publishing lets administrators register internal web applications, auto-discover their paths and endpoints, classify each path by security level, and publish them as proxy routes with per-path authorization policies.

## Overview

Publishing an internal app through OpenIDX follows five progressive security levels:

| Level | Approach | What It Provides |
|-------|----------|-----------------|
| 1 | **Reverse Proxy + Forward Auth** | Basic proxy with per-route authentication checks |
| 2 | **APISIX Route-Level Policies** | Gateway-enforced auth, rate limiting, IP restrictions |
| 3 | **OPA Policy Engine** | Fine-grained ABAC/RBAC policies per path |
| 4 | **Proxy Routes + Auto-Discovery** | Automatic endpoint scanning with classification-based policies |
| 5 | **OpenZiti Zero-Trust** | Full zero-trust overlay network, no exposed ports |

The App Publish feature implements **Level 4** and optionally enables **Level 5** (Ziti/BrowZer) during publishing.

## How It Works

### 1. Register an Application

Provide the app name, internal target URL, and optionally an OpenAPI spec URL.

```
POST /api/v1/access/apps
{
  "name": "HR Portal",
  "target_url": "http://hr-app:8080",
  "spec_url": "http://hr-app:8080/openapi.json",
  "description": "Employee management system"
}
```

### 2. Run Discovery

Discovery scans the target application using four strategies (in order):

1. **OpenAPI/Swagger** - Parses `spec_url` or probes well-known spec paths (`/openapi.json`, `/swagger.json`, `/api-docs`, etc.)
2. **Common Path Probing** - Sends HEAD requests to ~20 well-known paths (`/admin`, `/api`, `/health`, `/login`, `/settings`, `/dashboard`, `/docs`, `/metrics`, `/graphql`, etc.)
3. **Sitemap/robots.txt** - Parses `/sitemap.xml` and `/robots.txt` for additional paths
4. **HTML Link Crawl** - Extracts same-host `<a href>` links from the root page (max depth 1)

```
POST /api/v1/access/apps/{id}/discover
```

Discovery runs asynchronously. Poll the app or paths endpoint to track progress.

### 3. Review Classifications

Each discovered path is auto-classified into one of four security levels:

| Classification | Path Patterns | Default Policy |
|---------------|--------------|----------------|
| **Critical** | `/admin*`, `/settings*`, `/system*`, any `DELETE` | Auth required, admin role, device trust |
| **Sensitive** | `/api/*/users`, `/api/*/keys`, `/api/*/tokens`, `/api/*/secrets` | Auth required, admin role |
| **Protected** | Everything else (default) | Auth required, any authenticated user |
| **Public** | `/`, `/health*`, `/login`, `/docs*`, `/static*`, `/assets*`, `/favicon.ico`, `/robots.txt` | No auth required |

Classifications can be overridden manually. Manual overrides are preserved when re-running discovery.

### 4. Publish as Proxy Routes

Select paths and publish them. Each path becomes a proxy route with authorization policies based on its classification:

```
POST /api/v1/access/apps/{id}/publish
{
  "path_ids": ["uuid1", "uuid2"],
  "enable_ziti": false,
  "enable_browzer": false
}
```

Options:
- **enable_ziti** - Create OpenZiti service for zero-trust network overlay
- **enable_browzer** - Enable BrowZer for clientless browser access

## Admin Console Guide

### Navigating to App Publish

1. Log in as an admin
2. In the sidebar, under **Network & Access**, click **App Publish**

### Registering an App

1. Click **Register App**
2. Fill in the form:
   - **Name** - Display name for the application
   - **Target URL** - Internal URL where the app is running (e.g., `http://internal-app:8080`)
   - **OpenAPI Spec URL** (optional) - URL to an OpenAPI/Swagger spec for better discovery
   - **Description** (optional) - What the app does
3. Click **Register**

### Running Discovery

1. On the **Apps** tab, find your app card
2. Click **Discover** to start scanning
3. The card shows a spinning indicator while discovery runs
4. Once complete, the card shows how many paths were found and which strategies succeeded

### Reviewing and Editing Classifications

1. Click **Paths** on an app card (or switch to the **Discovered Paths** tab)
2. The summary cards show counts per classification: Critical, Sensitive, Protected, Public
3. Use the search box to filter by path name
4. Use the classification dropdown to filter by security level
5. **To change a classification**: Use the inline dropdown in the Classification column
   - Select a different level (Critical, Sensitive, Protected, Public)
   - The change is saved immediately and marked as a manual override
   - Manual overrides are preserved when re-running discovery

### Publishing Paths

1. On the Discovered Paths tab, select paths using the checkboxes
2. Click **Publish Selected (N)**
3. In the confirmation dialog:
   - Optionally enable **OpenZiti** for zero-trust overlay networking
   - Optionally enable **BrowZer** for clientless browser access
4. Click **Publish**
5. Published paths appear on the **Published** tab with links to their proxy routes

### Viewing Published Routes

1. Switch to the **Published** tab
2. Each row shows the path, methods, classification, auth policy, and a link to the proxy route
3. Click **View Route** to navigate to the Proxy Routes page for further configuration

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/access/apps` | List registered apps |
| `POST` | `/api/v1/access/apps` | Register a new app |
| `GET` | `/api/v1/access/apps/:id` | Get app details |
| `DELETE` | `/api/v1/access/apps/:id` | Delete an app and its paths |
| `POST` | `/api/v1/access/apps/:id/discover` | Start async discovery |
| `GET` | `/api/v1/access/apps/:id/paths` | List discovered paths |
| `PUT` | `/api/v1/access/apps/:id/paths/:pathId` | Update path classification |
| `POST` | `/api/v1/access/apps/:id/publish` | Publish selected paths as routes |

## Policy Examples

### Critical Path (admin + device trust)
```json
{
  "require_auth": true,
  "allowed_roles": ["admin"],
  "require_device_trust": true
}
```

### Sensitive Path (admin only)
```json
{
  "require_auth": true,
  "allowed_roles": ["admin"]
}
```

### Protected Path (any authenticated user)
```json
{
  "require_auth": true,
  "allowed_roles": []
}
```

### Public Path (no auth)
```json
{
  "require_auth": false,
  "allowed_roles": []
}
```

## Custom-Domain TLS Edge (reverse-proxy deployment)

When you front a published app with its own hostname and a real certificate
(e.g. `netgraph.tdv.org` → an internal app on `:8088`), put a TLS-terminating
reverse proxy in front of the access service. The access service
(`handleProxy`) matches the route by `Host`, enforces the auth gate, then
proxies to the internal target. The edge only terminates TLS and forwards.

The following nginx config is the reference for that deployment. The OpenIDX
admin console + APIs and the published app are served from the same nginx, each
on its own `server` block / cert.

```nginx
# --- Published internal app on its own hostname + real cert ---
# TLS-terminate here; forward everything to the access service, which gates
# auth (redirect to the OpenIDX login) and proxies to the internal target.
server {
  listen 443 ssl;
  server_name netgraph.tdv.org;

  ssl_certificate     /etc/nginx/tdv-fullchain.pem;
  ssl_certificate_key /etc/nginx/tdv-key.pem;

  # If the app serves its UI under a sub-path (e.g. /ui/), redirect the bare
  # root so visitors hitting the plain hostname land on the app instead of the
  # upstream's own 404. The target is still behind the auth gate.
  location = / { return 302 /ui/; }

  location / {
    proxy_pass http://127.0.0.1:8007;   # access service
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;   # REQUIRED — see gotchas
    proxy_set_header X-Forwarded-Host  $host;
    proxy_http_version 1.1;
    proxy_read_timeout 60s;
  }
}

# Upgrade plain HTTP to HTTPS for the published host.
server {
  listen 80;
  server_name netgraph.tdv.org;
  return 301 https://$host$request_uri;
}
```

### Gotchas (each of these was a real bug)

1. **`X-Forwarded-Proto https` is mandatory.** The access service builds its
   OAuth callback (`/access/.auth/callback`) from this header — it falls back to
   the request scheme only when the header is absent. Omit it behind TLS
   termination and the emitted `redirect_uri` is `http://`, which won't match
   the registered/public HTTPS URL and the browser callback lands on a non-TLS
   port. (Code: `callbackScheme()` in `internal/access/service.go`.)

2. **Set `preserve_host = true` on the proxy route** when the upstream emits
   absolute redirects (trailing-slash normalization, login bounces, etc.).
   With `preserve_host = false` the access service sends the *upstream's* own
   host, so the app echoes its internal address (e.g.
   `http://10.0.0.5:8088/ui/`) in `Location` and the user leaks off the public
   hostname. Toggle it on the Proxy Routes page or
   `UPDATE proxy_routes SET preserve_host = true WHERE from_url LIKE '%<host>%'`.

3. **Redirect the bare root** (`location = / { return 302 /ui/; }`) when the app
   serves its UI under a sub-path — the upstream root often 404s. The redirect
   target stays behind the auth gate, so nothing is exposed unauthenticated.

### Registering the public callback / redirect URI

The published host must be allowed as an OAuth redirect target. Add
`https://<host>/access/.auth/callback` (and `https://<host>/login` if the SPA
login is used) to the redirect URIs of the `access-proxy` and `admin-console`
OAuth clients, or the gate's `/oauth/authorize` will 400.

## One-Click Publishing (launcher tiles + wildcard subdomains)

For a "click a tile, the app opens" experience, an app can be published as a
**one-click app**: it gets its own subdomain under a shared wildcard domain, a
single wildcard TLS cert covers every app, and a launcher tile is auto-created
so it shows up in **My Apps** for end users — no per-app proxy config.

### How it works

`POST /api/v1/access/apps/:id/publish-app` (the **Publish App** button on the
App Publish page) does four things in one step:

1. Creates a single **host-level proxy route** (`from_url = https://<host>`,
   `to_url = <target_url>`, `require_auth=true`, `preserve_host=true`).
2. Upserts a row in `applications` (the launcher reads it) with
   `base_url = https://<host><landing_path>`, so the app appears as a tile in
   **My Apps** and opens in a new tab on click.
3. Appends `https://<host>/access/.auth/callback` to the `access-proxy` OAuth
   client's redirect URIs — so SSO round-trips without a manual OAuth edit.
4. Records `public_host` + `landing_path` on `published_apps`.

Request body (all optional):

```json
{
  "public_host": "netgraph",          // bare label → <label>.<ACCESS_APPS_DOMAIN>; or a full host
  "landing_path": "/ui/",             // where the tile opens (default "/")
  "preserve_host": true               // default true
}
```

If `public_host` is a bare label, the server appends `ACCESS_APPS_DOMAIN`
(e.g. `apps.tdv.org` → `netgraph.apps.tdv.org`). Re-publishing the same app is
idempotent (route keyed by `from_url`, tile keyed by `client_id=proxy-app-<id>`).

### Wildcard edge (one cert for every app)

Point the wildcard domain at the gateway and terminate TLS with a **single
wildcard cert** that forwards everything to the access service. With a real
wildcard cert for your apex (e.g. a GlobalSign `*.tdv.org`), apps live directly
at `<slug>.tdv.org` with no browser warning and no per-app cert:

```nginx
server {
  listen 443 ssl;
  server_name *.tdv.org;                       # one block covers every published app
  ssl_certificate     /etc/nginx/tdv-fullchain.pem;   # real *.tdv.org wildcard
  ssl_certificate_key /etc/nginx/tdv-key.pem;
  location / {
    proxy_pass http://127.0.0.1:8007;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto https;   # REQUIRED (callback scheme)
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_http_version 1.1;
  }
}
server { listen 80; server_name *.tdv.org; return 301 https://$host$request_uri; }
```

Exact-match server blocks (e.g. `openidx.tdv.org` for the admin console) win
over this wildcard, so the console and any host with its own block are
unaffected. Set `ACCESS_APPS_DOMAIN=tdv.org` on the access service so a bare
label resolves to `<slug>.tdv.org`.

No real wildcard cert? Generate a self-signed one for a dedicated apps subdomain
and trust it once on each client:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout key.pem -out cert.pem \
  -subj "/CN=apps.example.com" -addext "subjectAltName=DNS:*.apps.example.com"
```

### Notes

- **DNS/hosts is still per-app.** `/etc/hosts` has no wildcard — add a line per
  app (`<SERVER_IP> netgraph.apps.tdv.org`) or run a wildcard DNS / dnsmasq.
  The wildcard *cert* removes per-app trust friction, not per-app name
  resolution.
- **`landing_path`** handles apps whose UI isn't at `/` (e.g. netgraph at
  `/ui/`) without a per-app nginx redirect — the tile just opens the right path.
- Adding a new app needs **no nginx change** — the `*.apps.tdv.org` block and
  the access service's DB-driven host matching cover it.

## Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Admin Console │────>│  Access Service  │────>│  Target App      │
│ (app-publish) │     │  /api/v1/access  │     │  (internal)      │
└──────────────┘     │  /apps/*         │     └──────────────────┘
                     │                  │              │
                     │  Discovery Engine│<─────────────┘
                     │  - OpenAPI parse │     HTTP probes
                     │  - Path probing  │
                     │  - Sitemap parse │
                     │  - HTML crawl    │
                     │                  │
                     │  Classification  │
                     │  Engine          │
                     │                  │
                     │  Publish Handler │──────> proxy_routes table
                     │  (creates routes)│──────> Ziti/BrowZer (optional)
                     └─────────────────┘
```
