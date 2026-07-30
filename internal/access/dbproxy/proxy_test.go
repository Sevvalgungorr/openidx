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

// staticAuth is a test TokenAuthenticator that accepts one token and points at
// a fixed upstream.
type staticAuth struct {
	token  string
	target *UpstreamTarget
}

func (s *staticAuth) Authenticate(ctx context.Context, token string, startup map[string]string) (*UpstreamTarget, error) {
	if token != s.token {
		return nil, context.Canceled // any error rejects
	}
	return s.target, nil
}

// fakeUpstream is a minimal Postgres server: it accepts a startup, replies
// AuthenticationOk + ReadyForQuery, then for each Query replies CommandComplete
// + ReadyForQuery. It records the queries it saw.
type fakeUpstream struct {
	ln      net.Listener
	mu      sync.Mutex
	queries []string
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{ln: ln}
	go f.serve()
	return f
}

func (f *fakeUpstream) addr() string { return f.ln.Addr().String() }
func (f *fakeUpstream) close()       { f.ln.Close() }

func (f *fakeUpstream) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeUpstream) handle(conn net.Conn) {
	defer conn.Close()
	be := pgproto3.NewBackend(conn, conn)
	// startup
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.StartupMessage); ok {
			break
		}
		// deny SSL
		conn.Write([]byte{'N'})
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.queries = append(f.queries, m.String)
			f.mu.Unlock()
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			_ = be.Flush()
		case *pgproto3.Terminate:
			return
		}
	}
}

func (f *fakeUpstream) seenQueries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.queries))
	copy(out, f.queries)
	return out
}

// TestProxyEndToEnd runs the proxy in front of a fake upstream and drives it
// with a real pgproto3 Frontend acting as psql: startup → cleartext password
// (broker token) → AuthenticationOk → Query → the audit sink and the upstream
// both observe the statement.
func TestProxyEndToEnd(t *testing.T) {
	up := newFakeUpstream(t)
	defer up.close()

	host, portStr, _ := net.SplitHostPort(up.addr())
	port, _ := strconv.Atoi(portStr)

	target := &UpstreamTarget{
		SessionID: "sess-1", OrgID: "org-1", UserID: "user-1",
		Host: host, Port: port, Database: "app", Username: "dbuser", Password: "dbpass",
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

	proxy := New(&staticAuth{token: "broker-token-xyz", target: target}, sink, zap.NewNop())
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	go proxy.Serve(context.Background(), pln)

	// Client (psql-equivalent) via pgproto3 Frontend.
	cconn, err := net.Dial("tcp", pln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cconn.Close()
	fe := pgproto3.NewFrontend(cconn, cconn)

	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "ignored", "database": "ignored"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	// Expect AuthenticationCleartextPassword.
	deadline := time.Now().Add(3 * time.Second)
	cconn.SetReadDeadline(deadline)
	m, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive auth request: %v", err)
	}
	if _, ok := m.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("expected cleartext password request, got %T", m)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: "broker-token-xyz"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	// Expect AuthenticationOk then ReadyForQuery.
	sawAuthOk, sawRFQ := false, false
	for !sawRFQ {
		cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive post-auth: %v", err)
		}
		switch m.(type) {
		case *pgproto3.AuthenticationOk:
			sawAuthOk = true
		case *pgproto3.ReadyForQuery:
			sawRFQ = true
		}
	}
	if !sawAuthOk {
		t.Fatal("did not receive AuthenticationOk")
	}

	// Send a query and read to CommandComplete.
	const sql = "SELECT current_user"
	fe.Send(&pgproto3.Query{String: sql})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	sawComplete := false
	for !sawComplete {
		cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive query response: %v", err)
		}
		if _, ok := m.(*pgproto3.CommandComplete); ok {
			sawComplete = true
		}
	}

	// Upstream saw the query.
	q := up.seenQueries()
	if len(q) != 1 || q[0] != sql {
		t.Fatalf("upstream queries = %v, want [%q]", q, sql)
	}

	// Audit sink saw connect + the query.
	mu.Lock()
	defer mu.Unlock()
	var gotQuery, gotConnect bool
	for _, ev := range events {
		if ev.Kind == "query" && ev.Statement == sql && ev.SessionID == "sess-1" {
			gotQuery = true
		}
		if ev.Kind == "connect" {
			gotConnect = true
		}
	}
	if !gotConnect {
		t.Error("audit sink missing connect event")
	}
	if !gotQuery {
		t.Errorf("audit sink missing query event; got %+v", events)
	}
}

// TestProxyRejectsBadToken asserts a wrong broker token fails auth cleanly.
func TestProxyRejectsBadToken(t *testing.T) {
	target := &UpstreamTarget{Host: "127.0.0.1", Port: 1, Database: "x", Username: "u", Password: "p"}
	proxy := New(&staticAuth{token: "good", target: target}, nil, zap.NewNop())
	pln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pln.Close()
	go proxy.Serve(context.Background(), pln)

	cconn, err := net.Dial("tcp", pln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cconn.Close()
	fe := pgproto3.NewFrontend(cconn, cconn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "x"}})
	_ = fe.Flush()
	cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := fe.Receive(); err != nil {
		t.Fatalf("auth request: %v", err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: "wrong"})
	_ = fe.Flush()
	// Expect an ErrorResponse.
	cconn.SetReadDeadline(time.Now().Add(3 * time.Second))
	m, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive after bad password: %v", err)
	}
	if _, ok := m.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse for bad token, got %T", m)
	}
}
