#!/usr/bin/env bash
# install-logrotate.sh — install log rotation for the OpenIDX services.
#
# Why this is needed: the services write straight to files under
# /tmp/oidx-logs and nothing truncates them. Measured on a running install
# before this existed: 270 MB across seven logs, the largest 65 MB, none
# rotated since the services first started.
#
# The size was the smaller problem. The real cost was that a log spanning
# months reads as if it were current — a burst of errors that stopped a week
# earlier still sits at the end of the file and looks like a live incident.
#
# Idempotent: safe to run repeatedly. Verifies rather than assumes.
set -uo pipefail

CONF_DIR="${CONF_DIR:-$HOME/.config/oidx}"
UNIT_DIR="${UNIT_DIR:-$HOME/.config/systemd/user}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../systemd" && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/oidx-logs}"

fail() { printf '  ❌ %s\n' "$1"; exit 1; }
ok()   { printf '  ✅ %s\n' "$1"; }
warn() { printf '  ⚠️  %s\n' "$1"; }

command -v logrotate >/dev/null 2>&1 || fail "logrotate is not installed"

mkdir -p "$CONF_DIR" "$UNIT_DIR"
install -m 0644 "$SRC/oidx-logrotate.conf"    "$CONF_DIR/logrotate.conf"
install -m 0644 "$SRC/oidx-logrotate.service" "$UNIT_DIR/oidx-logrotate.service"
install -m 0644 "$SRC/oidx-logrotate.timer"   "$UNIT_DIR/oidx-logrotate.timer"
ok "config and units installed"

# Validate before enabling: a broken config that only fails at 03:00 is the
# kind of problem nobody notices until the disk is full.
if ! logrotate --debug --state "$CONF_DIR/logrotate.state" "$CONF_DIR/logrotate.conf" >/dev/null 2>&1; then
	fail "logrotate rejected the config — not enabling the timer"
fi
ok "config parses"

# copytruncate is not a style choice here. Every service holds its log file
# open for the life of the process (systemd StandardOutput=append:, and the
# access-service wrapper). Rename-and-create rotation would leave them writing
# into the unlinked inode: the new file stays empty and logging dies silently
# while everything still looks healthy.
grep -q '^\s*copytruncate' "$CONF_DIR/logrotate.conf" \
	|| fail "config must use copytruncate; the services hold their logs open"
ok "copytruncate present (required: services hold their logs open)"

systemctl --user daemon-reload
systemctl --user enable --now oidx-logrotate.timer >/dev/null 2>&1 \
	|| fail "could not enable oidx-logrotate.timer"
ok "timer enabled"

# A user timer stops with the session unless lingering is on. Without it,
# rotation silently stops the next time the user logs out.
if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
	warn "lingering is off: user timers stop at logout (enable with: loginctl enable-linger $USER)"
else
	ok "lingering on (timer survives logout)"
fi

# Any service that opens its log with '>' rather than '>>' keeps its own write
# offset. After copytruncate the next write lands at the old offset and the gap
# fills with NUL bytes — a sparse "6 MB" log whose first 6 MB are zeros. Costs
# little disk but makes size meaningless and grep slow.
# Only the scripts actually in use matter; timestamped .bak copies left behind
# by past deploys would otherwise produce a permanent false warning.
truncating="$(grep -lE '[^>]>[[:space:]]*'"$LOG_DIR"'/[a-z-]+\.log' "$HOME"/oidx-runtime/*.sh 2>/dev/null | head -3)"
if [ -n "$truncating" ]; then
	warn "these scripts redirect with '>' instead of '>>'; after rotation their logs fill with NUL padding:"
	printf '       %s\n' $truncating
fi

printf '\n  next run: %s\n' "$(systemctl --user list-timers oidx-logrotate --no-legend 2>/dev/null | awk '{print $1, $2, $3}')"
