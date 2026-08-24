//go:build windows

package control

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// dialControl returns an http base URL + client that reaches the server's
// loopback TCP listener.
func dialControl(t *testing.T, srv *Server) (string, *http.Client) {
	t.Helper()
	addr := srv.Addr()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control addr %s never became reachable: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return "http://" + addr, &http.Client{}
}
