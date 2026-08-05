package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func TestExtractSubprotocolToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"access_token_abc.def.ghi", "abc.def.ghi"},
		{" access_token_xyz ", "xyz"},
		{"json, access_token_tok123", "tok123"},
		{"some-other-proto", ""},
		{"access_token_", ""},
	}
	for _, c := range cases {
		if got := extractSubprotocolToken(c.header); got != c.want {
			t.Errorf("extractSubprotocolToken(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

// TestWebSocketStreamRejectsUnauthenticated proves the security fix: with a JWKS
// URL configured, a WebSocket upgrade with no access_token_ subprotocol is
// rejected with 401 (the audit trail must not stream unauthenticated). Without a
// JWKS URL (dev), it does not gate on auth.
func TestWebSocketStreamRejectsUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	es := &EventStreamer{
		logger:  zap.NewNop(),
		jwksURL: "https://issuer.example/.well-known/jwks.json",
	}

	r := gin.New()
	r.GET("/stream", es.handleWebSocketStream)

	// No subprotocol token, no WebSocket upgrade headers → must be 401 (auth is
	// checked before the upgrade attempt).
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream connect: status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access token") {
		t.Fatalf("expected an access-token error, got %s", w.Body.String())
	}
}

func TestSelectedSubprotocol(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"access_token_abc.def.ghi", "access_token_abc.def.ghi"},
		{" access_token_xyz ", "access_token_xyz"},
		{"json, access_token_tok123", "access_token_tok123"},
		{"some-other-proto", ""},
	}
	for _, c := range cases {
		if got := selectedSubprotocol(c.header); got != c.want {
			t.Errorf("selectedSubprotocol(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

// TestWebSocketStreamEchoesSubprotocol is the regression test for the browser
// "Connecting…"/1006 bug: the browser WebSocket API fails the handshake unless
// the server's 101 response echoes back a Sec-WebSocket-Protocol matching one
// the client offered. Non-browser clients accept the upgrade regardless, which
// masked the bug. Here we drive a real gorilla/websocket dial (which DOES
// enforce the echo) and assert the negotiated subprotocol is returned.
func TestWebSocketStreamEchoesSubprotocol(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// No jwksURL → auth gate is skipped (dev mode), isolating the handshake.
	es := NewEventStreamerWithConfig(zap.NewNop(), nil, DefaultStreamConfig())

	r := gin.New()
	r.GET("/api/v1/audit/stream", es.handleWebSocketStream)

	srv := httptest.NewServer(r)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/audit/stream"
	dialer := websocket.Dialer{Subprotocols: []string{"access_token_test.jwt.token"}}

	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if got := conn.Subprotocol(); got != "access_token_test.jwt.token" {
		t.Fatalf("negotiated subprotocol = %q, want the offered access_token_ value (browser requires this echo)", got)
	}
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != "access_token_test.jwt.token" {
		t.Fatalf("101 response Sec-WebSocket-Protocol = %q, want echoed value", got)
	}
}
