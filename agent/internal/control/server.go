package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Server is the local control-plane HTTP/JSON transport over an *Engine. A
// desktop GUI talks to it over a Unix domain socket (non-Windows) or a
// loopback TCP port guarded by a bearer token (Windows). It is a thin adapter:
// every route delegates to a facade method and relays its JSON string / error.
type Server struct {
	engine *Engine
	logger *zap.Logger

	ln    net.Listener
	addr  string // socket path (UDS) or host:port (Windows)
	token string // required bearer on Windows loopback; empty for UDS
	http  *http.Server
}

// NewServer builds a control server bound to a platform-appropriate listener
// (UDS on non-Windows, loopback+token on Windows). Call Serve to run it.
func NewServer(engine *Engine, logger *zap.Logger) (*Server, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	ln, addr, token, err := newListener()
	if err != nil {
		return nil, err
	}
	s := &Server{
		engine: engine,
		logger: logger,
		ln:     ln,
		addr:   addr,
		token:  token,
	}
	s.http = &http.Server{
		Handler:           s.authWrap(s.routes()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// Addr reports the socket path (UDS) or host:port (Windows loopback) clients
// connect to.
func (s *Server) Addr() string { return s.addr }

// Token reports the bearer token required on the loopback transport (Windows);
// empty on UDS (which is guarded by 0600 filesystem permissions instead).
func (s *Server) Token() string { return s.token }

// Serve runs the control server until ctx is cancelled, then shuts down
// gracefully and releases the listener.
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		err := s.http.Serve(s.ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	s.logger.Info("control server listening", zap.String("addr", s.addr))

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutCtx)
		s.engine.closeAll()
		cleanupListener(s.addr)
		return nil
	case err := <-errCh:
		s.engine.closeAll()
		cleanupListener(s.addr)
		return err
	}
}

// authWrap enforces the bearer token when one is configured (Windows loopback).
func (s *Server) authWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			if r.Header.Get("Authorization") != "Bearer "+s.token {
				writeErr(w, http.StatusUnauthorized, "invalid control token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("POST /enroll", s.handleEnroll)
	mux.HandleFunc("GET /posture", s.handlePosture)
	mux.HandleFunc("GET /pam/entries", s.handlePamList)
	mux.HandleFunc("POST /pam/connect", s.handlePamConnect)
	mux.HandleFunc("POST /pam/request", s.handlePamRequest)
	mux.HandleFunc("POST /ziti/dial", s.handleZitiDial)
	mux.HandleFunc("POST /ziti/close", s.handleZitiClose)
	return mux
}

// ---- handlers ----------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.engine.Status()
	writeEngineJSON(w, out, err)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	out, err := s.engine.Login()
	writeEngineJSON(w, out, err)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.Logout(); err != nil {
		writeEngineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Code == "" {
		writeErr(w, http.StatusBadRequest, "code is required")
		return
	}
	out, err := s.engine.Enroll(body.Code)
	writeEngineJSON(w, out, err)
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	out, err := s.engine.Posture()
	writeEngineJSON(w, out, err)
}

func (s *Server) handlePamList(w http.ResponseWriter, r *http.Request) {
	out, err := s.engine.PamList()
	writeEngineJSON(w, out, err)
}

func (s *Server) handlePamConnect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		EntryID string `json:"entry_id"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.EntryID == "" {
		writeErr(w, http.StatusBadRequest, "entry_id is required")
		return
	}
	url, err := s.engine.PamConnect(body.EntryID)
	if err != nil {
		writeEngineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"connect_url": url})
}

func (s *Server) handlePamRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		EntryID string `json:"entry_id"`
		Reason  string `json:"reason"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.EntryID == "" {
		writeErr(w, http.StatusBadRequest, "entry_id is required")
		return
	}
	if err := s.engine.PamRequest(body.EntryID, body.Reason); err != nil {
		writeEngineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleZitiDial(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Service == "" {
		writeErr(w, http.StatusBadRequest, "service is required")
		return
	}
	addr, err := s.engine.ZitiDial(body.Service)
	if err != nil {
		writeEngineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"local_addr": addr})
}

func (s *Server) handleZitiClose(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Service == "" {
		writeErr(w, http.StatusBadRequest, "service is required")
		return
	}
	if err := s.engine.ZitiClose(body.Service); err != nil {
		writeEngineErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- transport helpers -------------------------------------------------

// decodeBody strictly decodes a JSON request body; on malformed JSON it writes
// a 400 and returns false. An empty body decodes to the zero value (per-field
// validation happens in the handler).
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// writeEngineJSON relays a facade method's (jsonString, error) result: the
// engine already produced a JSON document, so it is written verbatim.
func writeEngineJSON(w http.ResponseWriter, jsonStr string, err error) {
	if err != nil {
		writeEngineErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jsonStr))
}

// writeEngineErr maps a facade error to an HTTP status: not-authenticated →
// 401, everything else → 500.
func writeEngineErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, errNotAuthenticated) {
		status = http.StatusUnauthorized
	}
	writeErr(w, status, err.Error())
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
