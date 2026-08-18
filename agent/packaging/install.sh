#!/bin/sh
# OpenIDX agent one-line installer for macOS / Linux.
#
#   curl -fsSL https://<server>/downloads/install.sh | sh -s -- \
#       --server https://<server> --code <enrollment-code>
#
# Downloads the right binary for this OS/arch from the server's /downloads,
# installs it to /usr/local/bin, and enrolls with the code from the
# "Add a device" wizard. POSIX sh; no bashisms.
set -eu

SERVER=""
CODE=""
DEST="${OPENIDX_DEST:-/usr/local/bin/openidx-agent}"

while [ $# -gt 0 ]; do
	case "$1" in
	--server) SERVER="$2"; shift 2 ;;
	--code) CODE="$2"; shift 2 ;;
	--dest) DEST="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

[ -n "$SERVER" ] || { echo "error: --server is required" >&2; exit 2; }
[ -n "$CODE" ] || { echo "error: --code is required" >&2; exit 2; }

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
linux) os=linux ;;
darwin) os=darwin ;;
*) echo "error: unsupported OS '$os'" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "error: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

bin="openidx-agent-${os}-${arch}"
url="${SERVER%/}/downloads/${bin}"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

echo "Downloading $url ..."
curl -fsSL "$url" -o "$tmp"
chmod +x "$tmp"

echo "Installing to $DEST ..."
if mv "$tmp" "$DEST" 2>/dev/null; then
	:
else
	sudo mv "$tmp" "$DEST"
fi
trap - EXIT

echo "Enrolling ..."
"$DEST" enroll --server "$SERVER" --code "$CODE"
echo "Done. The OpenIDX agent is installed and enrolled."
