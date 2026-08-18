#!/bin/sh
# Register the openidx:// URL scheme so a scanned QR / clicked deep-link opens
# the agent. Best-effort — never fail the package install over this.
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
	update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
	xdg-mime default openidx.desktop x-scheme-handler/openidx 2>/dev/null || true
fi
exit 0
