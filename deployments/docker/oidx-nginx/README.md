# `oidx-nginx` front-door configuration

`nginx.conf` here is the front-door config for the box that terminates TLS for
`openidx.tdv.org`. The running container bind-mounts it from
`/home/cmit/oidx-runtime/oidx-tls/nginx.conf`.

## Why this directory exists

It did not exist until 2026-08-14, and that was the real defect behind a field
report. The console showed raw AngularJS markup

    {{'APP.NAME' | TRANSLATE}}   {{'LOGIN.ACTION_LOGIN' | translate}}

because the site-wide `script-src 'self'` refused Angular's expression
compiler. The header came from this file. Nobody could find that by reading
the repository, because the file was not in it: it was hand-edited on the box,
with no history, no review, and no way to tell the deployed bytes from the
intended ones.

A config that decides security headers for every response is production code.
Keeping it outside version control means:

- a header regression leaves no trace of who changed it or why;
- the CI gate that checks our policies cannot see the file that actually
  serves them;
- rebuilding the box means reconstructing it from a running container.

## Keeping the copies honest

    scripts/check-nginx-drift.sh

compares this file with the deployed one and fails on drift. It runs in CI,
where the live file is absent, so it skips with a clear message rather than
pretending to have checked. Run it locally on the box after any edit.

## Editing

1. Edit **this** file.
2. `cp deployments/docker/oidx-nginx/nginx.conf /home/cmit/oidx-runtime/oidx-tls/nginx.conf`
3. `podman exec oidx-nginx nginx -t` (syntax) then `podman restart oidx-nginx`.

`restart`, not `reload`: the config is a bind-mounted file, and editors that
replace the inode leave the container holding the old one.

Measured on 2026-08-14: a restart costs roughly 30s of 502s, and `podman
restart` left the container in `Exited (0)` once, needing an explicit
`podman start`. Watch it come back before walking away.

## The add_header trap

nginx does **not** merge `add_header`: a directive in a `location` replaces the
entire inherited set. Verified with a probe container -- a child location with
one `add_header` dropped the parent's other headers completely.

That is why both `/guacamole/` blocks repeat HSTS, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy and Permissions-Policy verbatim.
Deleting one of those lines does not fall back to the server-level value; it
silently ships the response without that header.
