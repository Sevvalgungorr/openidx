//go:build !windows

package control

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// socketPath returns the control socket path: $XDG_RUNTIME_DIR/openidx-agent.sock
// when set, else /tmp/openidx-agent.sock.
func socketPath() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "openidx-agent.sock")
}

// newListener creates a 0600 Unix domain socket, removing any stale socket
// first. The empty token signals to the server that no bearer is required —
// filesystem permissions (owner-only) are the access control on UDS.
func newListener() (ln net.Listener, addr, token string, err error) {
	path := socketPath()
	// Remove a stale socket left by a crashed prior run.
	if fi, statErr := os.Stat(path); statErr == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, "", "", fmt.Errorf("control path %s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}

	ln, err = net.Listen("unix", path)
	if err != nil {
		return nil, "", "", fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, "", "", fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, path, "", nil
}

// cleanupListener removes the UDS file after shutdown.
func cleanupListener(addr string) {
	if addr != "" {
		_ = os.Remove(addr)
	}
}
