// Package access — Phase 4 remote-support session management and WebRTC
// signaling broker. The broker is intentionally in-memory and per-process:
// session state survives in Postgres, but the live signaling channel is
// best-effort. A reconnect on either side re-creates the broker entry by
// re-reading the row.
//
// Wire flow:
//
//  1. Admin POSTs /api/v1/access/remote-support/sessions {agent_id, mode}
//     → row inserted with status='pending', returns session_id.
//  2. /agent/config for that agent_id now embeds a remote_support block
//     pointing at the agent-side WS path (signed with the agent's auth
//     token so only the targeted device can join).
//  3. Agent connects to WS /agent/remote-support/sessions/:id.
//  4. Admin connects to WS /api/v1/access/remote-support/sessions/:id/ws.
//  5. Broker relays SDP offer / answer / ICE candidates. status flips to
//     'active' when both sides are connected.
//  6. Either side POSTs .../end OR closes its WS → status='ended'.
//
// Audit events ride the agent handler's logger so all device lifecycle
// activity sits in one unified_audit_events stream.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// RemoteSupportHandler owns the broker (peer registry + signaling fan-out)
// and the admin HTTP surface. Construct one per access-service instance.
type RemoteSupportHandler struct {
	logger               *zap.Logger
	db                   *database.PostgresDB
	auditAgent           *AgentAPIHandler
	turn                 *TurnMinter
	recordingStore       recordingStore
	defaultRetentionDays int
	// guacRecordingsRoot is the configured GuacamoleRecordingPath (directory).
	// The Guac retention sweeper uses it to guard against accidentally deleting
	// the entire recordings root when recording_path is missing or equals the root.
	guacRecordingsRoot string
	// guacRecordingRing, when non-nil and enabled, seals (encrypts at rest)
	// guacd's plaintext on-disk session recordings through the shared
	// AES-256-GCM keyring after the session ends and its transcript is
	// generated. See sealGuacRecordings + guac_recording_sealer.go.
	guacRecordingRing *recordingKeyring
	// guacamoleClient is used by the session-end detection sweep to query
	// live active sessions from the Guacamole REST API. Optional — when nil
	// the sweep is skipped (fail-safe: we never mark sessions ended if we
	// cannot see the live set).
	guacamoleClient *GuacamoleClient
	upgrader        websocket.Upgrader

	mu       sync.Mutex
	sessions map[string]*signalingSession
}

// NewRemoteSupportHandler constructs the handler. auditAgent is optional;
// when present, every lifecycle transition lands in unified_audit_events.
func NewRemoteSupportHandler(logger *zap.Logger, db *database.PostgresDB, auditAgent *AgentAPIHandler) *RemoteSupportHandler {
	return &RemoteSupportHandler{
		logger:     logger,
		db:         db,
		auditAgent: auditAgent,
		sessions:   make(map[string]*signalingSession),
		upgrader: websocket.Upgrader{
			ReadBufferSize:   2048,
			WriteBufferSize:  2048,
			HandshakeTimeout: 10 * time.Second,
			// Origin verification is enforced by APISIX upstream; broker
			// itself accepts any origin so localhost dev (admin console
			// proxied through APISIX) works without per-host config.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// SetTurnMinter installs the per-session TURN credential minter. Optional —
// when unset, HandleStartSession falls back to admin-supplied ice_servers
// (or empty if neither is configured).
func (h *RemoteSupportHandler) SetTurnMinter(m *TurnMinter) {
	h.turn = m
}

// SetDefaultRetentionDays installs the bottom-of-chain default that
// applies when neither a session override nor a per-org policy exists.
// Zero means "use the hard fallback (90)".
func (h *RemoteSupportHandler) SetDefaultRetentionDays(days int) {
	h.defaultRetentionDays = days
}

// SetGuacRecordingsRoot stores the configured Guacamole recording directory
// root so the Guac retention sweeper can validate paths before calling
// os.RemoveAll, preventing accidental deletion of the entire recordings root.
func (h *RemoteSupportHandler) SetGuacRecordingsRoot(root string) {
	h.guacRecordingsRoot = root
}

// SetGuacRecordingRing wires the encryption keyring used to seal guacd's
// on-disk recordings at rest (PAM A1). Optional — when nil or disabled, guac
// recordings are left plaintext on disk (back-compat) and the sealer sweep is
// inert. The same keyring/ framing as the WebRTC recording store is reused so
// rotation and playback are consistent across both recording backends.
func (h *RemoteSupportHandler) SetGuacRecordingRing(ring *recordingKeyring) {
	h.guacRecordingRing = ring
}

// SetGuacamoleClient wires the Guacamole REST client used by the
// session-end detection sweep. Without this, detectEndedGuacSessions is a
// no-op (fail-safe: sessions are never marked ended when the live set is
// unavailable).
func (h *RemoteSupportHandler) SetGuacamoleClient(gc *GuacamoleClient) {
	h.guacamoleClient = gc
}

// signalingSession is the live broker record for a session that has at
// least one peer connected. mu protects the conn pointers; everything else
// is immutable for the session's lifetime.
type signalingSession struct {
	sessionID string

	mu        sync.Mutex
	adminConn *brokerConn
	agentConn *brokerConn

	// agentReplay buffers the agent's SDP offer + ICE candidates so an admin
	// viewer that connects a moment after the device can still receive the
	// offer and negotiate. Only the agent side is buffered (see recordReplay):
	// the admin's answer is bound to a specific offer's ICE ufrag and must never
	// be replayed to a reconnected device. Reset on every fresh agent bind.
	agentReplay [][]byte
}

// brokerConn wraps a websocket.Conn with a single writer goroutine fed by a
// bounded channel. This decouples the two peers' read loops: a slow reader (e.g.
// the admin browser under load) no longer blocks the sender's read loop via a
// shared mutex during WriteMessage. Under backpressure, VP8 video frames (binary)
// are DROPPED rather than blocking — the renderer just requests a keyframe and
// catches up — while text (signaling/control) is always delivered. This is what
// killed relay stability: holding sess.mu across a blocking WriteMessage coupled
// both legs, so any write stall cascaded into a device-side abnormal close (1006).
type brokerConn struct {
	ws     *websocket.Conn
	send   chan wsMessage
	closed chan struct{}
	once   sync.Once
}

type wsMessage struct {
	mt   int
	data []byte
}

// brokerSendQueue is the per-connection outbound buffer. Sized to absorb a short
// stall without unbounded memory; overflow drops the oldest video frame.
const brokerSendQueue = 64

func newBrokerConn(ws *websocket.Conn) *brokerConn {
	c := &brokerConn{
		ws:     ws,
		send:   make(chan wsMessage, brokerSendQueue),
		closed: make(chan struct{}),
	}
	go c.writeLoop()
	return c
}

func (c *brokerConn) writeLoop() {
	for {
		select {
		case <-c.closed:
			return
		case msg := <-c.send:
			// A generous per-write deadline: a write that can't complete in this
			// window means the peer is genuinely gone, not merely slow.
			_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.ws.WriteMessage(msg.mt, msg.data); err != nil {
				c.Close()
				return
			}
		}
	}
}

// enqueue queues a message for delivery. Text messages block briefly (signaling
// must not be lost); binary video frames are dropped if the queue is full so a
// slow admin never stalls the device's read loop. Returns false if the conn is
// closed.
func (c *brokerConn) enqueue(mt int, data []byte) bool {
	// Copy: the caller's buffer (gorilla read buffer) is reused on the next read.
	buf := make([]byte, len(data))
	copy(buf, data)
	if mt == websocket.BinaryMessage {
		select {
		case c.send <- wsMessage{mt, buf}:
			return true
		case <-c.closed:
			return false
		default:
			// Queue full: drop this video frame. The decoder recovers on the next
			// keyframe (viewer requests one on decode error).
			return true
		}
	}
	// Text / control: deliver reliably, but bound the wait so a dead peer can't
	// wedge the sender forever.
	select {
	case c.send <- wsMessage{mt, buf}:
		return true
	case <-c.closed:
		return false
	case <-time.After(5 * time.Second):
		c.Close()
		return false
	}
}

func (c *brokerConn) writeControl(messageType int, deadline time.Time) error {
	return c.ws.WriteControl(messageType, nil, deadline)
}

func (c *brokerConn) Close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.ws.Close()
	})
}

// maxReplayMessages caps the per-peer signaling replay buffer. SDP + a modest
// number of ICE candidates fit comfortably; the cap prevents unbounded growth
// on a chatty or stuck peer.
const maxReplayMessages = 64

// defaultSTUNServers returns the ICE server list handed to both peers when no
// admin override or minted TURN credential is present. Public STUN lets each
// peer discover its server-reflexive (public) address so WebRTC can establish
// a direct path across typical NAT. Overridable per-session via the start
// request's ice_servers, or globally by wiring a TURN minter.
func defaultSTUNServers() json.RawMessage {
	return json.RawMessage(`[{"urls":["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302"]}]`)
}

// RegisterRemoteSupportAdminRoutes mounts the admin (and admin-WS) surface.
// MUST go behind middleware.Auth.
func (h *RemoteSupportHandler) RegisterRemoteSupportAdminRoutes(r *gin.RouterGroup) {
	r.GET("/remote-support/sessions", h.HandleListSessions)
	r.POST("/remote-support/sessions", h.HandleStartSession)
	r.GET("/remote-support/sessions/:id", h.HandleGetSession)
	r.POST("/remote-support/sessions/:id/end", h.HandleEndSession)
	// Admin-side WebSocket — the browser viewer connects here.
	r.GET("/remote-support/sessions/:id/ws", h.HandleAdminWS)
	// Recording upload pipeline (Phase 4 follow-up).
	r.POST("/remote-support/sessions/:id/recording/chunk", h.HandleUploadRecordingChunk)
	r.POST("/remote-support/sessions/:id/recording/finalize", h.HandleFinalizeRecording)
	r.GET("/remote-support/sessions/:id/recording", h.HandleDownloadRecording)
	// Per-tenant retention policy.
	h.RegisterRetentionAdminRoutes(r)
	// Legal hold workflow (exempts a session's recording from sweep).
	h.RegisterLegalHoldAdminRoutes(r)
}

// RegisterRemoteSupportPublicRoutes mounts the agent-facing WebSocket. It
// authenticates via X-Agent-ID + X-Auth-Token headers (same pattern as
// /agent/report) since agents don't have a tenant JWT.
func (h *RemoteSupportHandler) RegisterRemoteSupportPublicRoutes(r *gin.RouterGroup) {
	r.GET("/agent/remote-support/sessions/:id/ws", h.HandleAgentWS)
	// Device consent (attended support): the agent Allows/Denies before the
	// admin can view/control. Agent-authenticated (X-Agent-ID + X-Auth-Token).
	r.POST("/agent/remote-support/sessions/:id/consent", h.HandleAgentConsent)
}

// startSessionRequest is the body accepted by HandleStartSession.
type startSessionRequest struct {
	AgentID    string          `json:"agent_id" binding:"required"`
	Mode       string          `json:"mode"`        // "view" | "interactive" (default)
	ICEServers json.RawMessage `json:"ice_servers"` // optional override
	Notes      string          `json:"notes"`
	Record     bool            `json:"record"` // opt-in MediaRecorder capture
	// Transport selects the media path: "webrtc" (default, P2P) or "relay"
	// (VP8 frames streamed through the broker — full-Ziti, no STUN). Empty uses
	// the server default (REMOTE_SUPPORT_TRANSPORT).
	Transport string `json:"transport"`
	// ConsentRequired: when true, the person at the device must Allow the
	// session (attended support) before the admin can view/control. Servers /
	// unattended targets leave this false (today's behavior).
	ConsentRequired bool `json:"consent_required"`
	// RecordingRetentionDays: per-session retention override. nil means
	// "use the per-org policy or default". 0 means "infinite". Positive
	// values cap the recording lifetime to that many days.
	RecordingRetentionDays *int `json:"recording_retention_days,omitempty"`
}

// remoteSessionRow is what we return to admins (list + get + start).
type remoteSessionRow struct {
	ID                   string          `json:"id"`
	AgentID              string          `json:"agent_id"`
	AdminUserID          string          `json:"admin_user_id,omitempty"`
	Status               string          `json:"status"`
	Mode                 string          `json:"mode"`
	Transport            string          `json:"transport"`
	ICEServers           json.RawMessage `json:"ice_servers"`
	EndReason            string          `json:"end_reason,omitempty"`
	RecordingURL         string          `json:"recording_url,omitempty"`
	RecordingEnabled     bool            `json:"recording_enabled"`
	RecordingSizeBytes   int64           `json:"recording_size_bytes,omitempty"`
	RecordingChunkCount  int             `json:"recording_chunk_count,omitempty"`
	RecordingFinalizedAt *time.Time      `json:"recording_finalized_at,omitempty"`
	StartedAt            time.Time       `json:"started_at"`
	AcceptedAt           *time.Time      `json:"accepted_at,omitempty"`
	EndedAt              *time.Time      `json:"ended_at,omitempty"`
	Notes                string          `json:"notes,omitempty"`
	LastActivityAt       time.Time       `json:"last_activity_at"`
	// IsOnLegalHold derives from a LEFT JOIN against recording_legal_holds
	// — true when at least one row exists with released_at IS NULL for
	// this session. The admin UI uses this to render a lock icon next to
	// the recording link.
	IsOnLegalHold bool `json:"is_on_legal_hold"`
}

// HandleStartSession creates a new session targeting an enrolled agent.
func (h *RemoteSupportHandler) HandleStartSession(c *gin.Context) {
	var req startSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "interactive"
	}
	if mode != "interactive" && mode != "view" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'interactive' or 'view'"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// Resolve the media transport: explicit request wins, else the server
	// default (REMOTE_SUPPORT_TRANSPORT), else 'webrtc'.
	transport := strings.ToLower(strings.TrimSpace(req.Transport))
	if transport == "" {
		transport = defaultRemoteSupportTransport()
	}
	if transport != "webrtc" && transport != "relay" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "transport must be 'webrtc' or 'relay'"})
		return
	}

	// Reject if the agent has another active session already (broker would
	// happily run two, but the UX of two admins sharing a screen is bad).
	var blockingID string
	_ = h.db.Pool.QueryRow(c.Request.Context(), `
        SELECT id FROM remote_support_sessions
         WHERE agent_id = $1 AND status IN ('pending','active')
         LIMIT 1
    `, req.AgentID).Scan(&blockingID)
	if blockingID != "" {
		c.JSON(http.StatusConflict, gin.H{
			"error":      "agent already has an active session",
			"session_id": blockingID,
		})
		return
	}

	adminID := getUserID(c)
	id := uuid.New().String()

	// Resolve ice_servers in priority order:
	//   1. Admin-supplied (verbatim, back-compat).
	//   2. Minted per-session TURN credentials when the minter is wired.
	//   3. Default public STUN servers so peers can gather server-reflexive
	//      candidates and connect across NAT. (Host candidates alone only work
	//      when both peers share a subnet with no NAT/firewall in between; STUN
	//      is cheap and makes the common case — LAN + remote — just work. A
	//      TURN relay, wired via SetTurnMinter, is still needed for symmetric
	//      NAT, but STUN covers the vast majority.)
	ice := req.ICEServers
	mintedTurn := false
	if len(ice) == 0 {
		if h.turn != nil {
			minted, mintErr := h.turn.MintAsRawJSON(id)
			if mintErr != nil {
				h.logger.Warn("HandleStartSession: TURN mint failed; continuing without",
					zap.String("session_id", id), zap.Error(mintErr))
			} else {
				ice = minted
				mintedTurn = true
			}
		}
		if len(ice) == 0 {
			ice = defaultSTUNServers()
		}
	}

	recordingEnabled := req.Record && h.recordingStore != nil
	orgID := getOrgID(c)
	var retentionArg interface{}
	if req.RecordingRetentionDays != nil {
		retentionArg = *req.RecordingRetentionDays
	}
	var orgArg interface{}
	if orgID != "" {
		orgArg = orgID
	}
	// Supersede any prior in-flight session for this agent. Starting a new session
	// while an old one is still pending/active left two live sessions: the config
	// picks the newest, but the device's peer for the OLD one lingered in the
	// broker, delaying the switch and making the new session appear "stuck". Mark
	// older ones ended so there is exactly one live session per agent, and evict
	// their broker peers so the device cleanly re-binds to the new session.
	rows, err := h.db.Pool.Query(c.Request.Context(), `
        UPDATE remote_support_sessions
           SET status = 'ended', ended_at = NOW(), end_reason = 'superseded'
         WHERE agent_id = $1 AND status IN ('pending','active')
        RETURNING id
    `, req.AgentID)
	if err != nil {
		h.logger.Warn("HandleStartSession: supersede prior sessions failed", zap.Error(err))
	} else {
		var oldIDs []string
		for rows.Next() {
			var oldID string
			if rows.Scan(&oldID) == nil {
				oldIDs = append(oldIDs, oldID)
			}
		}
		rows.Close()
		for _, oldID := range oldIDs {
			h.evictSession(oldID)
		}
	}
	_, err = h.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO remote_support_sessions
            (id, agent_id, admin_user_id, status, mode, ice_servers, notes,
             recording_enabled, org_id, recording_retention_days,
             consent_required, consent_status, transport)
        VALUES ($1, $2, NULLIF($3,'')::uuid, 'pending', $4, $5::jsonb, $6,
                $7, $8::uuid, $9, $10, $11, $12)
    `, id, req.AgentID, adminID, mode, string(ice), req.Notes,
		recordingEnabled, orgArg, retentionArg,
		req.ConsentRequired, consentStatusFor(req.ConsentRequired), transport)
	if err != nil {
		h.logger.Error("HandleStartSession: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start session"})
		return
	}

	auditDetail := "agent=" + req.AgentID + " admin=" + adminID
	if mintedTurn {
		auditDetail += " turn=minted"
	}
	if recordingEnabled {
		auditDetail += " recording=on"
	}
	h.audit(c.Request.Context(), "remote_support.session_started", id, "success", auditDetail)

	c.JSON(http.StatusCreated, gin.H{
		"id":                id,
		"status":            "pending",
		"agent_id":          req.AgentID,
		"mode":              mode,
		"admin_ws":          "/api/v1/access/remote-support/sessions/" + id + "/ws",
		"agent_ws":          "/api/v1/access/agent/remote-support/sessions/" + id + "/ws",
		"ice_servers":       ice,
		"recording_enabled": recordingEnabled,
		"transport":         transport,
		"consent_required":  req.ConsentRequired,
		"consent_status":    consentStatusFor(req.ConsentRequired),
	})
}

// defaultRemoteSupportTransport returns the media transport used when a
// start-session request doesn't specify one: "relay" when
// REMOTE_SUPPORT_TRANSPORT=relay, else "webrtc".
func defaultRemoteSupportTransport() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("REMOTE_SUPPORT_TRANSPORT")), "relay") {
		return "relay"
	}
	return "webrtc"
}

// consentStatusFor returns the initial consent_status for a session: 'pending'
// when the device must Allow first, otherwise 'granted' (unattended/server —
// no behavior change).
func consentStatusFor(required bool) string {
	if required {
		return "pending"
	}
	return "granted"
}

// consentDecisionRequest is the body of the agent accept/decline call.
type consentDecisionRequest struct {
	Decision string `json:"decision"` // "grant" | "deny"
}

// HandleAgentConsent is the DEVICE side of attended-support consent:
// POST /api/v1/access/agent/remote-support/sessions/:id/consent {decision}.
// The agent proves ownership with X-Agent-ID + X-Auth-Token (same as the agent
// WS). It flips consent_status to granted/denied; a denial also ends the
// session so the admin can never view/control without an explicit Allow.
func (h *RemoteSupportHandler) HandleAgentConsent(c *gin.Context) {
	id := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	agentID := c.GetHeader("X-Agent-ID")
	authToken := c.GetHeader("X-Auth-Token")
	if agentID != row.AgentID || authToken == "" || !h.verifyAgentAuth(c.Request.Context(), agentID, authToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent credentials invalid"})
		return
	}
	var req consentDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	var newStatus string
	switch req.Decision {
	case "grant":
		newStatus = "granted"
	case "deny":
		newStatus = "denied"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be 'grant' or 'deny'"})
		return
	}

	if newStatus == "denied" {
		// A denial ends the session immediately (fail-closed).
		_, _ = h.db.Pool.Exec(c.Request.Context(), `
            UPDATE remote_support_sessions
               SET consent_status='denied', consent_decided_at=NOW(),
                   status='ended', ended_at=NOW(), end_reason='consent denied by device'
             WHERE id=$1`, id)
		h.audit(c.Request.Context(), "remote_support.consent_denied", id, "success", "agent="+agentID)
		c.JSON(http.StatusOK, gin.H{"consent_status": "denied", "status": "ended"})
		return
	}

	_, _ = h.db.Pool.Exec(c.Request.Context(), `
        UPDATE remote_support_sessions
           SET consent_status='granted', consent_decided_at=NOW()
         WHERE id=$1`, id)
	h.audit(c.Request.Context(), "remote_support.consent_granted", id, "success", "agent="+agentID)
	c.JSON(http.StatusOK, gin.H{"consent_status": "granted"})
}

// HandleListSessions returns recent sessions, newest first.
func (h *RemoteSupportHandler) HandleListSessions(c *gin.Context) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []remoteSessionRow{})
		return
	}
	rows, err := h.db.Pool.Query(c.Request.Context(), `
        SELECT s.id, s.agent_id, COALESCE(s.admin_user_id::text,''), s.status, s.mode,
               COALESCE(s.transport,'webrtc'),
               s.ice_servers, COALESCE(s.end_reason,''), COALESCE(s.recording_url,''),
               s.recording_enabled, s.recording_size_bytes, s.recording_chunk_count,
               s.recording_finalized_at,
               s.started_at, s.accepted_at, s.ended_at, COALESCE(s.notes,''),
               s.last_activity_at,
               EXISTS (SELECT 1 FROM recording_legal_holds rlh
                        WHERE rlh.session_id = s.id AND rlh.released_at IS NULL)
          FROM remote_support_sessions s
         ORDER BY s.started_at DESC
         LIMIT 200
    `)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list"})
		return
	}
	defer rows.Close()
	out := []remoteSessionRow{}
	for rows.Next() {
		rec, scanErr := scanRemoteSessionRow(rows)
		if scanErr != nil {
			h.logger.Warn("HandleListSessions: scan", zap.Error(scanErr))
			continue
		}
		out = append(out, rec)
	}
	c.JSON(http.StatusOK, out)
}

// HandleGetSession returns one session.
func (h *RemoteSupportHandler) HandleGetSession(c *gin.Context) {
	id := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get session", err), h.logger)
		return
	}
	c.JSON(http.StatusOK, row)
}

// HandleEndSession admin-initiated session termination.
func (h *RemoteSupportHandler) HandleEndSession(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Reason == "" {
		body.Reason = "admin_ended"
	}
	if err := h.endSession(c.Request.Context(), id, body.Reason); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("end session", err), h.logger)
		return
	}
	h.audit(c.Request.Context(), "remote_support.session_ended", id, "success", body.Reason)
	c.JSON(http.StatusOK, gin.H{"status": "ended", "id": id})
}

// HandleAdminWS handles the admin (browser) side of signaling.
func (h *RemoteSupportHandler) HandleAdminWS(c *gin.Context) {
	id := c.Param("id")
	if _, err := h.fetchSession(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	// Echo the token subprotocol the browser offered. A browser WebSocket that
	// opens with a subprotocol (we send `bearer.<jwt>` because browsers can't
	// set an Authorization header on WS) REQUIRES the server to select one of
	// the offered subprotocols in the handshake response; otherwise the browser
	// rejects the upgrade and closes the socket immediately (observed as a
	// ~30ms admin WS that dropped before it could answer the device's offer).
	var respHeader http.Header
	if proto := c.GetHeader("Sec-WebSocket-Protocol"); proto != "" {
		// The client may offer a comma-separated list; select the first token.
		sub := strings.TrimSpace(strings.Split(proto, ",")[0])
		if sub != "" {
			respHeader = http.Header{"Sec-WebSocket-Protocol": []string{sub}}
		}
	}
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, respHeader)
	if err != nil {
		h.logger.Warn("HandleAdminWS: upgrade failed", zap.Error(err))
		return
	}
	// Consent handling: the DEVICE self-gates — its agent only starts the relay
	// peer (and thus only streams / applies input) AFTER it sends a consent grant.
	// So the admin can join the broker immediately and simply receives no frames
	// until the device consents; the viewer shows "connecting" until then. We do
	// NOT block here waiting for consent: an earlier version 403'd the handshake
	// (browser reconnect-stormed and gave up before the user clicked Allow), and a
	// blocking wait without a reader let APISIX drop the idle socket after a few
	// seconds. Joining the broker now, with runPeer actively reading, is stable
	// and starts streaming the instant the device grants.
	h.runPeer(c.Request.Context(), id, conn, peerAdmin)
}

// HandleAgentWS handles the agent (device) side of signaling. The agent
// proves it owns the targeted agent_id by supplying its auth-token in the
// X-Auth-Token header; we verify against enrolled_agents.auth_token_hash.
func (h *RemoteSupportHandler) HandleAgentWS(c *gin.Context) {
	id := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	agentID := c.GetHeader("X-Agent-ID")
	authToken := c.GetHeader("X-Auth-Token")
	if agentID != row.AgentID || authToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent credentials invalid"})
		return
	}
	if !h.verifyAgentAuth(c.Request.Context(), agentID, authToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "auth token mismatch"})
		return
	}
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Warn("HandleAgentWS: upgrade failed", zap.Error(err))
		return
	}
	h.runPeer(c.Request.Context(), id, conn, peerAgent)
}

// peerRole identifies which side of the broker a connection represents.
type peerRole int

const (
	peerAdmin peerRole = iota
	peerAgent
)

// runPeer registers the connection in the broker and pumps messages until
// the socket closes. Every received message is relayed verbatim to the
// other peer (if connected) and updates last_activity_at so the janitor
// can age out orphan sessions.
func (h *RemoteSupportHandler) runPeer(ctx context.Context, sessionID string, rawConn *websocket.Conn, role peerRole) {
	// Wrap the raw socket in a brokerConn: a dedicated writer goroutine + bounded
	// queue so this peer's WRITES never block the OTHER peer's read loop. Reads
	// still happen on the raw socket below.
	conn := newBrokerConn(rawConn)
	defer conn.Close()

	sess := h.bindPeer(sessionID, conn, role)
	defer h.unbindPeer(sess, role)

	// Read deadline + pong handler: the keepalive pings below must be answered
	// within the window or the peer is considered dead. This gives deterministic
	// dead-connection detection instead of relying on TCP timeouts.
	_ = rawConn.SetReadDeadline(time.Now().Add(70 * time.Second))
	rawConn.SetPongHandler(func(string) error {
		return rawConn.SetReadDeadline(time.Now().Add(70 * time.Second))
	})

	// Replay the other peer's buffered signaling to this (possibly late-joining)
	// connection so a viewer that connects after the device already sent its
	// OFFER + ICE still gets them and can negotiate. Best-effort via the queue.
	for _, msg := range sess.replayFor(role) {
		if !conn.enqueue(websocket.TextMessage, msg) {
			return
		}
	}

	// If both peers are now connected, flip status → active.
	if sess.hasBothPeers() {
		h.markActive(ctx, sessionID)
	}

	// Keepalive: proxies (APISIX) drop idle WebSockets after ~60s. Ping every 25s
	// via the writer goroutine's control path. Stops when the read loop returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if err := conn.writeControl(websocket.PingMessage, time.Now().Add(5*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	for {
		mt, data, err := rawConn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.TextMessage && mt != websocket.BinaryMessage {
			continue
		}
		h.touchSession(ctx, sessionID)
		// Buffer for replay to a peer that joins later, then relay to the peer
		// that's already connected (if any). Only TEXT signaling is buffered:
		// binary frames are relay-transport VP8 video, which must never be
		// replayed (a late viewer waits for a fresh keyframe) and would otherwise
		// balloon the replay buffer with stale frames at video frame rates.
		if mt == websocket.TextMessage {
			sess.recordReplay(role, data)
		}
		if target := sess.otherPeer(role); target != nil {
			// enqueue is non-blocking for video (drops under backpressure) so a
			// slow peer never stalls this read loop — the fix for the 1006 close
			// cascade that made relay unstable.
			target.enqueue(mt, data)
		}
	}
}

// bindPeer attaches conn to the session broker entry, creating it on first
// peer.
func (h *RemoteSupportHandler) bindPeer(sessionID string, conn *brokerConn, role peerRole) *signalingSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok {
		sess = &signalingSession{sessionID: sessionID}
		h.sessions[sessionID] = sess
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	switch role {
	case peerAdmin:
		// If a previous admin connection lingers, drop it.
		if sess.adminConn != nil {
			sess.adminConn.Close()
		}
		sess.adminConn = conn
	case peerAgent:
		if sess.agentConn != nil {
			sess.agentConn.Close()
		}
		sess.agentConn = conn
		// A fresh agent connection begins a NEW negotiation with a new ICE
		// ufrag. Drop the previous offer/ICE buffer so a late-joining admin is
		// never handed a stale offer from a prior agent incarnation (which would
		// carry an old ufrag and make ICE fail). The buffer refills from this
		// connection's fresh offer via recordReplay.
		sess.agentReplay = nil
	}
	return sess
}

// unbindPeer detaches the connection. When neither peer remains we drop the
// broker entry; the session row stays in Postgres until explicitly ended so
// reconnect-after-network-blip works.
func (h *RemoteSupportHandler) unbindPeer(sess *signalingSession, role peerRole) {
	sess.mu.Lock()
	switch role {
	case peerAdmin:
		sess.adminConn = nil
	case peerAgent:
		sess.agentConn = nil
	}
	empty := sess.adminConn == nil && sess.agentConn == nil
	sess.mu.Unlock()
	if !empty {
		return
	}
	h.mu.Lock()
	delete(h.sessions, sess.sessionID)
	h.mu.Unlock()
}

func (s *signalingSession) hasBothPeers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adminConn != nil && s.agentConn != nil
}

func (s *signalingSession) otherPeer(role peerRole) *brokerConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if role == peerAdmin {
		return s.agentConn
	}
	return s.adminConn
}

// recordReplay buffers the AGENT's signaling (its SDP offer + ICE candidates)
// so an admin viewer that connects slightly later still receives the offer and
// can negotiate. Only the agent side is buffered: the admin's answer/ICE are
// tied to a specific offer's ICE ufrag and must never be replayed to a
// reconnected agent (doing so causes stable->SetRemote(answer)->stable and
// dropped candidates). The agent buffer is reset on every fresh agent bind.
func (s *signalingSession) recordReplay(role peerRole, data []byte) {
	if role != peerAgent {
		return
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentReplay = append(s.agentReplay, buf)
	if len(s.agentReplay) > maxReplayMessages {
		s.agentReplay = s.agentReplay[len(s.agentReplay)-maxReplayMessages:]
	}
}

// replayFor returns a copy of the buffered agent offer/ICE for a joining admin
// so it can catch up on signaling the agent sent before the admin connected.
// Only the admin receives a replay; the agent never does (nothing is buffered
// for it), which keeps every agent (re)connection a clean, fresh negotiation.
func (s *signalingSession) replayFor(role peerRole) [][]byte {
	if role != peerAdmin {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.agentReplay
	out := make([][]byte, len(src))
	copy(out, src)
	return out
}

// markActive flips a pending session to active when both peers connect.
func (h *RemoteSupportHandler) markActive(ctx context.Context, sessionID string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	_, _ = h.db.Pool.Exec(ctx, `
        UPDATE remote_support_sessions
           SET status = 'active', accepted_at = COALESCE(accepted_at, NOW()),
               last_activity_at = NOW()
         WHERE id = $1 AND status = 'pending'
    `, sessionID)
	h.audit(ctx, "remote_support.session_active", sessionID, "success", "")
}

// touchSession bumps last_activity_at so a stalled session can be aged out.
func (h *RemoteSupportHandler) touchSession(ctx context.Context, sessionID string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	_, _ = h.db.Pool.Exec(ctx,
		`UPDATE remote_support_sessions SET last_activity_at = NOW() WHERE id = $1`,
		sessionID)
}

// endSession persists end state and tears down any live broker entry.
func (h *RemoteSupportHandler) endSession(ctx context.Context, sessionID, reason string) error {
	if h.db != nil && h.db.Pool != nil {
		_, err := h.db.Pool.Exec(ctx, `
            UPDATE remote_support_sessions
               SET status = 'ended', ended_at = COALESCE(ended_at, NOW()),
                   end_reason = COALESCE(NULLIF($2,''), end_reason),
                   last_activity_at = NOW()
             WHERE id = $1 AND status IN ('pending','active')
        `, sessionID, reason)
		if err != nil {
			return err
		}
	}
	// Drop any live broker entry so both peers receive a clean close.
	h.evictSession(sessionID)
	return nil
}

// evictSession drops a session's live broker entry (if any), closing both peer
// connections so they receive a clean close. Safe to call for a session with no
// live broker entry. Used both on explicit end and when a new session supersedes
// an older in-flight one for the same agent.
func (h *RemoteSupportHandler) evictSession(sessionID string) {
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	if ok {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
	if sess != nil {
		sess.mu.Lock()
		if sess.adminConn != nil {
			sess.adminConn.Close()
			sess.adminConn = nil
		}
		if sess.agentConn != nil {
			sess.agentConn.Close()
			sess.agentConn = nil
		}
		sess.mu.Unlock()
	}
}

// verifyAgentAuth checks the supplied auth token against the
// enrolled_agents.auth_token_hash for the given agent_id.
func (h *RemoteSupportHandler) verifyAgentAuth(ctx context.Context, agentID, token string) bool {
	if h.db == nil || h.db.Pool == nil {
		return token != "" // dev mode: any non-empty token
	}
	var stored string
	err := h.db.Pool.QueryRow(ctx,
		`SELECT auth_token_hash FROM enrolled_agents WHERE agent_id = $1`,
		agentID).Scan(&stored)
	if err != nil {
		return false
	}
	return sha256Hex(token) == stored
}

// activeSessionInfo carries the per-agent session pointer that
// findActiveSessionForAgent returns. Promoted to a struct because the
// recording flag is a fifth datum and the positional-return signature
// was already noisy.
type activeSessionInfo struct {
	SessionID       string
	Mode            string
	ICEServers      json.RawMessage
	Recording       bool
	ConsentRequired bool
	ConsentStatus   string
	Transport       string
}

// findActiveSessionForAgent — called from HandleConfig to embed an in-flight
// session in the agent's config response. Returns the session info when one
// is active or pending for this agent, or `ok=false` when the agent has
// no live session.
func findActiveSessionForAgent(ctx context.Context, db *database.PostgresDB, agentID string) (info activeSessionInfo, ok bool) {
	if db == nil || db.Pool == nil || agentID == "" {
		return activeSessionInfo{}, false
	}
	var iceBytes []byte
	err := db.Pool.QueryRow(ctx, `
        SELECT id, mode, ice_servers, recording_enabled, consent_required, consent_status,
               COALESCE(transport,'webrtc')
          FROM remote_support_sessions
         WHERE agent_id = $1 AND status IN ('pending','active')
         ORDER BY started_at DESC
         LIMIT 1
    `, agentID).Scan(&info.SessionID, &info.Mode, &iceBytes, &info.Recording, &info.ConsentRequired, &info.ConsentStatus, &info.Transport)
	if err != nil {
		return activeSessionInfo{}, false
	}
	info.ICEServers = json.RawMessage(iceBytes)
	return info, true
}

// fetchSession reads the full row by ID for admin handlers.
func (h *RemoteSupportHandler) fetchSession(ctx context.Context, id string) (remoteSessionRow, error) {
	if h.db == nil || h.db.Pool == nil {
		return remoteSessionRow{}, errors.New("database unavailable")
	}
	row := h.db.Pool.QueryRow(ctx, `
        SELECT s.id, s.agent_id, COALESCE(s.admin_user_id::text,''), s.status, s.mode,
               COALESCE(s.transport,'webrtc'),
               s.ice_servers, COALESCE(s.end_reason,''), COALESCE(s.recording_url,''),
               s.recording_enabled, s.recording_size_bytes, s.recording_chunk_count,
               s.recording_finalized_at,
               s.started_at, s.accepted_at, s.ended_at, COALESCE(s.notes,''),
               s.last_activity_at,
               EXISTS (SELECT 1 FROM recording_legal_holds rlh
                        WHERE rlh.session_id = s.id AND rlh.released_at IS NULL)
          FROM remote_support_sessions s
         WHERE s.id = $1
    `, id)
	return scanRemoteSessionRow(row)
}

func scanRemoteSessionRow(r rowScanner) (remoteSessionRow, error) {
	var rec remoteSessionRow
	var iceBytes []byte
	err := r.Scan(
		&rec.ID, &rec.AgentID, &rec.AdminUserID, &rec.Status, &rec.Mode,
		&rec.Transport,
		&iceBytes, &rec.EndReason, &rec.RecordingURL,
		&rec.RecordingEnabled, &rec.RecordingSizeBytes, &rec.RecordingChunkCount,
		&rec.RecordingFinalizedAt,
		&rec.StartedAt, &rec.AcceptedAt, &rec.EndedAt, &rec.Notes,
		&rec.LastActivityAt,
		&rec.IsOnLegalHold,
	)
	rec.ICEServers = json.RawMessage(iceBytes)
	return rec, err
}

func (h *RemoteSupportHandler) audit(ctx context.Context, action, sessionID, outcome, detail string) {
	if h.auditAgent != nil {
		h.auditAgent.logAuditEvent(action, sessionID, outcome, detail)
		h.auditAgent.logAuditEventToDB(ctx, action, sessionID, outcome, detail)
	}
}

// StartJanitor runs a background goroutine that ages out pending/active
// sessions with no signaling activity in `idleAfter`. Janitor restart is
// safe — it operates only on Postgres state, not broker memory.
func (h *RemoteSupportHandler) StartJanitor(ctx context.Context, idleAfter time.Duration, tick time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.expireOrphanSessions(ctx, idleAfter)
			}
		}
	}()
}

func (h *RemoteSupportHandler) expireOrphanSessions(ctx context.Context, idleAfter time.Duration) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	tag, err := h.db.Pool.Exec(ctx, `
        UPDATE remote_support_sessions
           SET status = 'expired', ended_at = NOW(),
               end_reason = COALESCE(end_reason, 'orphan_timeout')
         WHERE status IN ('pending','active')
           AND last_activity_at < NOW() - $1::interval
    `, idleAfter.String())
	if err != nil {
		h.logger.Warn("expireOrphanSessions: update failed", zap.Error(err))
		return
	}
	if tag.RowsAffected() > 0 {
		h.audit(ctx, "remote_support.session_expired", "(batch)", "enforced",
			"count="+strconv.FormatInt(tag.RowsAffected(), 10))
	}
}
