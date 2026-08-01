// Package dbproxy is OpenIDX's PostgreSQL wire-protocol session broker (PAM B1).
//
// It lets an operator use their native `psql` / any Postgres driver against a
// protected database WITHOUT ever holding the database's real credentials and
// without the database being directly reachable. The operator points psql at
// the proxy and authenticates with a SHORT-LIVED OpenIDX broker token (supplied
// as the Postgres password); the proxy:
//
//  1. speaks the Postgres startup handshake to the client and asks for a
//     cleartext password (the OpenIDX broker token);
//  2. validates the token via the injected TokenAuthenticator, which yields the
//     target upstream + the vault-injected REAL database credential
//     (server-side only — it never reaches the client);
//  3. dials the upstream Postgres, performs the startup + auth handshake there
//     with the real credential (delegated to pgconn so SCRAM/MD5/TLS are
//     handled correctly, including SCRAM-SHA-256), then hands the client an AuthenticationOk;
//  4. relays messages both ways. On the client→server direction it decodes
//     Query / Parse messages and emits them to the AuditSink, so every
//     statement run through the broker is centrally recorded.
//
// This is the P0 "native psql just works, zero standing credentials, full
// query audit" cut, plus statement policy enforcement (StatementPolicy:
// read-only sessions and per-class deny lists, rejected at the same decode
// point before reaching the upstream). Column-level masking is a follow-up.
package dbproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"go.uber.org/zap"
)

// UpstreamTarget describes where and how to reach the real database, resolved
// from a validated broker token. The credential fields are server-side secrets
// and are never sent to the client.
type UpstreamTarget struct {
	SessionID string // OpenIDX brokered_sessions id (for audit correlation)
	OrgID     string
	UserID    string
	Host      string
	Port      int
	Database  string
	Username  string // real DB user (from vault)
	Password  string // real DB password (from vault)
	// Policy, when non-nil, is enforced on every Query/Parse before it is
	// forwarded upstream (see StatementPolicy). Nil = audit-only.
	Policy *StatementPolicy
}

// TokenAuthenticator validates the broker token the client presented as its
// Postgres password and returns the upstream target to connect to. Implemented
// by the access service (vault + brokered_sessions lookups). Returning an error
// fails the client auth with a clean Postgres error.
type TokenAuthenticator interface {
	Authenticate(ctx context.Context, token string, startup map[string]string) (*UpstreamTarget, error)
}

// AuditEvent is one statement (or lifecycle event) observed on a proxied
// session. Direction is always client→server for queries.
type AuditEvent struct {
	SessionID string
	OrgID     string
	UserID    string
	Kind      string // "query" | "parse" | "blocked" | "connect" | "disconnect"
	Statement string // the SQL text (query/parse); empty for lifecycle events
	At        time.Time
}

// AuditSink receives audit events. Implementations must be non-blocking or
// cheap; the proxy calls this on the hot path of the relay loop.
type AuditSink interface {
	Record(ev AuditEvent)
}

// AuditSinkFunc adapts a function to AuditSink.
type AuditSinkFunc func(AuditEvent)

func (f AuditSinkFunc) Record(ev AuditEvent) { f(ev) }

// Proxy is the DB session broker. Construct with New and call Serve.
type Proxy struct {
	auth    TokenAuthenticator
	audit   AuditSink
	logger  *zap.Logger
	dialer  net.Dialer
	timeout time.Duration
}

// New builds a Proxy. audit may be nil (auditing disabled).
func New(auth TokenAuthenticator, audit AuditSink, logger *zap.Logger) *Proxy {
	if logger == nil {
		logger = zap.NewNop()
	}
	if audit == nil {
		audit = AuditSinkFunc(func(AuditEvent) {})
	}
	return &Proxy{
		auth:    auth,
		audit:   audit,
		logger:  logger.With(zap.String("component", "dbproxy")),
		timeout: 10 * time.Second,
	}
}

// Serve accepts connections on ln until the listener is closed. Each connection
// is handled in its own goroutine.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go p.handle(ctx, conn)
	}
}

// handle drives one client connection end to end.
func (p *Proxy) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	be := pgproto3.NewBackend(client, client)

	startup, err := p.readStartup(be, client)
	if err != nil {
		p.logger.Warn("startup failed", zap.Error(err))
		p.sendFatal(be, "08P01", "invalid startup")
		return
	}

	// Ask the client for a cleartext password (the OpenIDX broker token).
	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := be.Flush(); err != nil {
		return
	}
	msg, err := be.Receive()
	if err != nil {
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		p.sendFatal(be, "28000", "expected password")
		return
	}

	target, err := p.auth.Authenticate(ctx, pw.Password, startup)
	if err != nil {
		p.logger.Warn("token auth rejected", zap.Error(err))
		p.sendFatal(be, "28P01", "OpenIDX broker authentication failed")
		return
	}

	// Dial + authenticate upstream with the real credential.
	upstream, startupMsgs, err := p.dialUpstream(ctx, target, startup)
	if err != nil {
		p.logger.Warn("upstream connect failed",
			zap.String("host", target.Host), zap.Error(err))
		p.sendFatal(be, "08006", "upstream database unavailable")
		return
	}
	defer upstream.Close()

	// Tell the client it's authenticated, replay the upstream's startup
	// parameters + key data (native drivers require these), then signal ready.
	be.Send(&pgproto3.AuthenticationOk{})
	for _, m := range startupMsgs {
		be.Send(m)
	}
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}

	p.audit.Record(AuditEvent{
		SessionID: target.SessionID, OrgID: target.OrgID, UserID: target.UserID,
		Kind: "connect", At: time.Now(),
	})
	defer p.audit.Record(AuditEvent{
		SessionID: target.SessionID, OrgID: target.OrgID, UserID: target.UserID,
		Kind: "disconnect", At: time.Now(),
	})

	p.relay(be, client, upstream, target)
}

// readStartup consumes SSLRequest/GSSENCRequest negotiation (denying encryption
// in this cut) and returns the StartupMessage parameters.
func (p *Proxy) readStartup(be *pgproto3.Backend, client net.Conn) (map[string]string, error) {
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m.Parameters, nil
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			// Deny encryption negotiation ('N'); the client retries in cleartext.
			// (TLS termination at the proxy is a follow-up.)
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected startup message %T", msg)
		}
	}
}

// sendFatal sends an ErrorResponse then returns; best-effort.
func (p *Proxy) sendFatal(be *pgproto3.Backend, code, msg string) {
	be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = be.Flush()
}

// relay pipes messages between client and upstream. The client→server
// direction is decoded (via the client Backend) so Query/Parse statements can
// be audited and policy-checked, then forwarded to the upstream (via an
// upstream Frontend). The server→client direction is a straight byte copy
// when no policy is set; with a policy it is decoded too, so policy
// rejections can be interleaved into the client stream on message boundaries
// (a raw copy could split an upstream message around our ErrorResponse).
func (p *Proxy) relay(be *pgproto3.Backend, client net.Conn, upstream net.Conn, target *UpstreamTarget) {
	var wg sync.WaitGroup
	wg.Add(2)

	pol := target.Policy

	// clientMu serializes writes to the client between the server→client
	// pump and policy rejections written from the client→server side. Only
	// needed (and only used) on the policied path.
	var clientMu sync.Mutex
	// txStatus mirrors the last ReadyForQuery status seen from the upstream,
	// so rejections report the connection's real transaction state.
	txStatus := byte('I')

	// server → client
	go func() {
		defer wg.Done()
		if pol == nil {
			_, _ = io.Copy(client, upstream)
			_ = client.Close()
			return
		}
		fe := pgproto3.NewFrontend(upstream, upstream)
		for {
			msg, err := fe.Receive()
			if err != nil {
				_ = client.Close()
				return
			}
			clientMu.Lock()
			if r, ok := msg.(*pgproto3.ReadyForQuery); ok {
				txStatus = r.TxStatus
			}
			be.Send(msg)
			err = be.Flush()
			clientMu.Unlock()
			if err != nil {
				_ = client.Close()
				return
			}
		}
	}()

	// reject writes a policy ErrorResponse to the client without forwarding
	// anything upstream. followWithReady is set for simple-protocol Query
	// rejections (the server would normally answer with ReadyForQuery);
	// extended-protocol Parse rejections send it later, on Sync.
	reject := func(stmt string, perr error, followWithReady bool) {
		p.audit.Record(AuditEvent{
			SessionID: target.SessionID, OrgID: target.OrgID, UserID: target.UserID,
			Kind: "blocked", Statement: stmt, At: time.Now(),
		})
		clientMu.Lock()
		defer clientMu.Unlock()
		be.Send(&pgproto3.ErrorResponse{
			Severity: "ERROR", Code: "42501", // insufficient_privilege
			Message: "OpenIDX session policy: " + perr.Error(),
		})
		if followWithReady {
			be.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
		}
		_ = be.Flush()
	}

	// client → server (decode + audit + policy, then forward)
	go func() {
		defer wg.Done()
		up := pgproto3.NewFrontend(upstream, upstream)
		// After a rejected Parse, swallow the rest of the extended-protocol
		// pipeline (Bind/Describe/Execute) until the client's Sync, then
		// answer ReadyForQuery ourselves — nothing was sent upstream.
		discardUntilSync := false
		for {
			msg, err := be.Receive()
			if err != nil {
				_ = upstream.Close()
				return
			}
			if discardUntilSync {
				if _, ok := msg.(*pgproto3.Sync); ok {
					discardUntilSync = false
					clientMu.Lock()
					be.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
					_ = be.Flush()
					clientMu.Unlock()
				}
				continue
			}
			switch m := msg.(type) {
			case *pgproto3.Query:
				p.audit.Record(AuditEvent{
					SessionID: target.SessionID, OrgID: target.OrgID, UserID: target.UserID,
					Kind: "query", Statement: m.String, At: time.Now(),
				})
				if err := pol.Check(m.String); err != nil {
					reject(m.String, err, true)
					continue
				}
			case *pgproto3.Parse:
				p.audit.Record(AuditEvent{
					SessionID: target.SessionID, OrgID: target.OrgID, UserID: target.UserID,
					Kind: "parse", Statement: m.Query, At: time.Now(),
				})
				if err := pol.Check(m.Query); err != nil {
					reject(m.Query, err, false)
					discardUntilSync = true
					continue
				}
			}
			// Forward the decoded frontend message to the upstream unchanged.
			up.Send(msg)
			if err := up.Flush(); err != nil {
				_ = upstream.Close()
				return
			}
		}
	}()

	wg.Wait()
}
