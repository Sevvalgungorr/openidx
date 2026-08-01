package dbproxy

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"go.uber.org/zap"
)

// connectClient performs the client side of the broker handshake (startup →
// cleartext broker token → AuthenticationOk + ReadyForQuery) and returns the
// ready-to-use connection.
func connectClient(t *testing.T, addr, token string) (net.Conn, *pgproto3.Frontend) {
	t.Helper()
	cconn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fe := pgproto3.NewFrontend(cconn, cconn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "ignored", "database": "ignored"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if m, err := fe.Receive(); err != nil {
		t.Fatalf("receive auth request: %v", err)
	} else if _, ok := m.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("expected cleartext password request, got %T", m)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: token})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive post-auth: %v", err)
		}
		if _, ok := m.(*pgproto3.ReadyForQuery); ok {
			return cconn, fe
		}
	}
}

// TestProxyEnforcesPolicy drives a read-only + deny-list session end to end:
// reads pass through, writes are rejected with a policy ErrorResponse without
// ever reaching the upstream, and the connection stays usable afterwards.
func TestProxyEnforcesPolicy(t *testing.T) {
	up := newFakeUpstream(t)
	defer up.close()
	host, portStr, _ := net.SplitHostPort(up.addr())
	port, _ := strconv.Atoi(portStr)

	target := &UpstreamTarget{
		SessionID: "sess-pol", OrgID: "org-1", UserID: "user-1",
		Host: host, Port: port, Database: "app", Username: "dbuser", Password: "dbpass",
		Policy: &StatementPolicy{ReadOnly: true, Deny: []string{"DROP"}},
	}

	var (
		mu     sync.Mutex
		events []AuditEvent
	)
	sink := AuditSinkFunc(func(ev AuditEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	proxy := New(&staticAuth{token: "tok", target: target}, sink, zap.NewNop())
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	go proxy.Serve(context.Background(), pln)

	cconn, fe := connectClient(t, pln.Addr().String(), "tok")
	defer cconn.Close()

	// runQuery sends one simple query and collects the response kinds up to
	// ReadyForQuery.
	runQuery := func(sql string) (sawComplete bool, errResp *pgproto3.ErrorResponse) {
		fe.Send(&pgproto3.Query{String: sql})
		if err := fe.Flush(); err != nil {
			t.Fatal(err)
		}
		for {
			cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
			m, err := fe.Receive()
			if err != nil {
				t.Fatalf("receive response to %q: %v", sql, err)
			}
			switch r := m.(type) {
			case *pgproto3.CommandComplete:
				sawComplete = true
			case *pgproto3.ErrorResponse:
				// Receive reuses the message; copy what we assert on.
				errResp = &pgproto3.ErrorResponse{Severity: r.Severity, Code: r.Code, Message: r.Message}
			case *pgproto3.ReadyForQuery:
				return sawComplete, errResp
			}
		}
	}

	// 1. A read passes through.
	if ok, errResp := runQuery("SELECT 1"); !ok || errResp != nil {
		t.Fatalf("SELECT should pass (complete=%v err=%+v)", ok, errResp)
	}
	// 2. A write is rejected with the policy error, upstream never sees it.
	if ok, errResp := runQuery("INSERT INTO t VALUES (1)"); ok || errResp == nil {
		t.Fatalf("INSERT should be blocked (complete=%v err=%+v)", ok, errResp)
	} else if errResp.Code != "42501" {
		t.Errorf("expected SQLSTATE 42501, got %q (%s)", errResp.Code, errResp.Message)
	}
	// 3. A denied class is rejected too.
	if ok, errResp := runQuery("DROP TABLE t"); ok || errResp == nil {
		t.Fatal("DROP should be blocked by the deny list")
	}
	// 4. The connection is still healthy for reads.
	if ok, _ := runQuery("SELECT 2"); !ok {
		t.Fatal("connection should remain usable after a rejection")
	}

	if q := up.seenQueries(); len(q) != 2 || q[0] != "SELECT 1" || q[1] != "SELECT 2" {
		t.Fatalf("upstream saw %v, want only the two SELECTs", q)
	}

	mu.Lock()
	defer mu.Unlock()
	blocked := 0
	for _, ev := range events {
		if ev.Kind == "blocked" {
			blocked++
		}
	}
	if blocked != 2 {
		t.Errorf("expected 2 blocked audit events, got %d (%+v)", blocked, events)
	}
}

// TestProxyEnforcesPolicyExtendedProtocol rejects a write sent via the
// extended protocol (Parse) and answers ReadyForQuery on the client's Sync —
// nothing is forwarded upstream.
func TestProxyEnforcesPolicyExtendedProtocol(t *testing.T) {
	up := newFakeUpstream(t)
	defer up.close()
	host, portStr, _ := net.SplitHostPort(up.addr())
	port, _ := strconv.Atoi(portStr)

	target := &UpstreamTarget{
		SessionID: "sess-ext", OrgID: "org-1", UserID: "user-1",
		Host: host, Port: port, Database: "app", Username: "dbuser", Password: "dbpass",
		Policy: &StatementPolicy{ReadOnly: true},
	}
	proxy := New(&staticAuth{token: "tok", target: target}, nil, zap.NewNop())
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	go proxy.Serve(context.Background(), pln)

	cconn, fe := connectClient(t, pln.Addr().String(), "tok")
	defer cconn.Close()

	// Parse (blocked) → Bind → Execute → Sync, pipelined like a driver would.
	fe.Send(&pgproto3.Parse{Name: "s1", Query: "DELETE FROM t"})
	fe.Send(&pgproto3.Bind{PreparedStatement: "s1"})
	fe.Send(&pgproto3.Execute{})
	fe.Send(&pgproto3.Sync{})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	sawErr, sawRFQ := false, false
	for !sawRFQ {
		cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive extended-protocol response: %v", err)
		}
		switch r := m.(type) {
		case *pgproto3.ErrorResponse:
			sawErr = true
			if r.Code != "42501" {
				t.Errorf("expected SQLSTATE 42501, got %q", r.Code)
			}
		case *pgproto3.ReadyForQuery:
			sawRFQ = true
		}
	}
	if !sawErr {
		t.Fatal("expected a policy ErrorResponse for the blocked Parse")
	}
	if q := up.seenQueries(); len(q) != 0 {
		t.Fatalf("upstream should have seen nothing, saw %v", q)
	}
}
