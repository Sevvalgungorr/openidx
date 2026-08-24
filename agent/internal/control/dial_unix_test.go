//go:build !windows

package control

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// dialControl returns an http base URL + client that reaches the server's UDS.
// It waits until the socket accepts a connection.
func dialControl(t *testing.T, srv *Server) (string, *http.Client) {
	t.Helper()
	sockPath := srv.Addr()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control socket %s never became reachable: %v", sockPath, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}
	// The Host in the URL is ignored (custom DialContext), but must be valid.
	return "http://unix", client
}
