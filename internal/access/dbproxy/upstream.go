package dbproxy

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5/pgproto3"
)

// dialUpstream connects to the real database and completes the startup + auth
// handshake using the vault-injected credential. It consumes the upstream's
// post-auth startup messages (ParameterStatus, BackendKeyData) through the
// first ReadyForQuery and returns them so the proxy can replay them to the
// client — native drivers (pgx, libpq) require ParameterStatus/BackendKeyData
// to finish their own startup. The returned conn is positioned for raw relay.
//
// Supported upstream auth methods in this cut: trust (AuthenticationOk),
// cleartext password, and MD5. SCRAM upstreams are rejected with a clear error
// (follow-up: delegate the upstream leg to pgconn).
func (p *Proxy) dialUpstream(ctx context.Context, t *UpstreamTarget, clientStartup map[string]string) (net.Conn, []pgproto3.BackendMessage, error) {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	dialCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	conn, err := p.dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream: %w", err)
	}

	fe := pgproto3.NewFrontend(conn, conn)

	// Preserve the client's requested parameters where sensible, but force the
	// authenticated user + database from the broker target.
	params := map[string]string{
		"user":     t.Username,
		"database": t.Database,
	}
	if app, ok := clientStartup["application_name"]; ok {
		params["application_name"] = app
	}
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: params})
	if err := fe.Flush(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send upstream startup: %w", err)
	}

	// Collect ParameterStatus + BackendKeyData to replay to the client.
	var startupMsgs []pgproto3.BackendMessage
	for {
		msg, err := fe.Receive()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("upstream auth receive: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			// auth accepted; keep reading until ReadyForQuery
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: t.Password})
			if err := fe.Flush(); err != nil {
				conn.Close()
				return nil, nil, err
			}
		case *pgproto3.AuthenticationMD5Password:
			fe.Send(&pgproto3.PasswordMessage{Password: md5Auth(t.Username, t.Password, m.Salt)})
			if err := fe.Flush(); err != nil {
				conn.Close()
				return nil, nil, err
			}
		case *pgproto3.AuthenticationSASL:
			if err := p.scramAuthUpstream(fe, m.AuthMechanisms, t.Password); err != nil {
				conn.Close()
				return nil, nil, err
			}
		case *pgproto3.AuthenticationGSS:
			conn.Close()
			return nil, nil, fmt.Errorf("upstream requires GSS auth, not supported")
		case *pgproto3.ErrorResponse:
			conn.Close()
			return nil, nil, fmt.Errorf("upstream auth error: %s (%s)", m.Message, m.Code)
		case *pgproto3.ParameterStatus:
			// Copy — the decoded message is reused by the frontend next Receive.
			startupMsgs = append(startupMsgs, &pgproto3.ParameterStatus{Name: m.Name, Value: m.Value})
		case *pgproto3.BackendKeyData:
			startupMsgs = append(startupMsgs, &pgproto3.BackendKeyData{ProcessID: m.ProcessID, SecretKey: m.SecretKey})
		case *pgproto3.ReadyForQuery:
			return conn, startupMsgs, nil // authenticated + idle; ready to relay
		default:
			// Ignore anything else until ReadyForQuery.
		}
	}
}

// md5Auth computes the Postgres md5 password response:
// "md5" + md5( md5(password + username) + salt ).
func md5Auth(user, password string, salt [4]byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt[:]...))
	return "md5" + hex.EncodeToString(outer[:])
}

// scramAuthUpstream performs the SCRAM-SHA-256 client exchange with the upstream
// after an AuthenticationSASL message, driving SASLInitialResponse →
// AuthenticationSASLContinue → SASLResponse → AuthenticationSASLFinal, and
// verifying the server signature. On success it returns nil with the frontend
// positioned to receive AuthenticationOk next.
func (p *Proxy) scramAuthUpstream(fe *pgproto3.Frontend, mechs []string, password string) error {
	supported := false
	for _, m := range mechs {
		if m == "SCRAM-SHA-256" {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("upstream SASL mechanisms %v do not include SCRAM-SHA-256", mechs)
	}

	sc, clientFirst, err := newScramClient(password)
	if err != nil {
		return err
	}
	fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte(clientFirst)})
	if err := fe.Flush(); err != nil {
		return err
	}

	// server-first
	msg, err := fe.Receive()
	if err != nil {
		return fmt.Errorf("scram: receive server-first: %w", err)
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			return fmt.Errorf("scram: server error: %s (%s)", er.Message, er.Code)
		}
		return fmt.Errorf("scram: expected SASLContinue, got %T", msg)
	}
	clientFinal, err := sc.step(string(cont.Data))
	if err != nil {
		return err
	}
	fe.Send(&pgproto3.SASLResponse{Data: []byte(clientFinal)})
	if err := fe.Flush(); err != nil {
		return err
	}

	// server-final
	msg, err = fe.Receive()
	if err != nil {
		return fmt.Errorf("scram: receive server-final: %w", err)
	}
	fin, ok := msg.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			return fmt.Errorf("scram: server error: %s (%s)", er.Message, er.Code)
		}
		return fmt.Errorf("scram: expected SASLFinal, got %T", msg)
	}
	if err := sc.verify(string(fin.Data)); err != nil {
		return err
	}
	return nil
}
