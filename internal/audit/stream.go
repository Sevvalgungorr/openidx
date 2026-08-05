// Package audit provides real-time event streaming via WebSocket and webhook delivery
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// extractSubprotocolToken pulls the JWT out of a Sec-WebSocket-Protocol header
// value that carries it as "access_token_<jwt>" (the browser can't set an
// Authorization header on a WebSocket). The header may list multiple
// comma-separated protocols; we take the first access_token_ one.
func extractSubprotocolToken(header string) string {
	for _, p := range strings.Split(header, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "access_token_") {
			return strings.TrimPrefix(p, "access_token_")
		}
	}
	return ""
}

// selectedSubprotocol returns the exact "access_token_<jwt>" protocol string the
// client offered in Sec-WebSocket-Protocol, or "" if none. The browser
// WebSocket API requires the server's 101 response to echo back a subprotocol
// matching one the client offered; if it does not, the browser fails the
// handshake and closes with 1006 (even though non-browser clients accept the
// upgrade). We therefore echo the offered protocol verbatim on Upgrade.
func selectedSubprotocol(header string) string {
	for _, p := range strings.Split(header, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "access_token_") {
			return p
		}
	}
	return ""
}

// EventStreamer manages real-time streaming of audit events
type EventStreamer struct {
	logger          *zap.Logger
	clients         map[string]*StreamClient
	clientsMutex    sync.RWMutex
	webhookQueue    chan *WebhookDelivery
	webhookConfig   *WebhookConfig
	service         *Service
	originValidator *OriginValidator
	upgrader        *websocket.Upgrader
	// jwksURL, when set, enables JWT authentication of stream connections. The
	// audit event stream is sensitive security data and must not be readable
	// unauthenticated. Set via SetJWKSURL from the service entrypoint.
	jwksURL string
}

// SetJWKSURL enables JWT auth on the audit stream (REST routes via middleware,
// WebSocket via the access_token_<jwt> subprotocol validated at upgrade).
func (es *EventStreamer) SetJWKSURL(url string) {
	es.jwksURL = url
}

// StreamClient represents a connected WebSocket client
type StreamClient struct {
	ID      string
	Conn    *websocket.Conn
	Send    chan *ServiceAuditEvent
	Filters *StreamFilters
	done    chan struct{}
}

// StreamFilters defines event filters for a stream client
type StreamFilters struct {
	EventTypes []EventType          `json:"event_types"`
	Categories []EventCategory      `json:"categories"`
	ActorID    string               `json:"actor_id,omitempty"`
	Outcome    *ServiceEventOutcome `json:"outcome,omitempty"`
}

// WebhookConfig holds webhook delivery configuration
type WebhookConfig struct {
	MaxRetries int           `json:"max_retries"`
	RetryDelay time.Duration `json:"retry_delay"`
	Timeout    time.Duration `json:"timeout"`
	QueueSize  int           `json:"queue_size"`
	Enabled    bool          `json:"enabled"`
}

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	Event      *ServiceAuditEvent `json:"event"`
	WebhookURL string             `json:"webhook_url"`
	RetryCount int                `json:"retry_count"`
	ID         string             `json:"id"`
}

// WebhookSubscription represents a registered webhook endpoint
type WebhookSubscription struct {
	ID           string         `json:"id"`
	URL          string         `json:"url"`
	Secret       string         `json:"secret,omitempty"`
	Enabled      bool           `json:"enabled"`
	Filters      *StreamFilters `json:"filters,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	LastDelivery time.Time      `json:"last_delivery,omitempty"`
	FailureCount int            `json:"failure_count"`
}

// NewEventStreamer creates a new event streamer with configurable origin validation
func NewEventStreamer(logger *zap.Logger, service *Service, allowedOrigins []string) *EventStreamer {
	webhookConfig := &WebhookConfig{
		MaxRetries: 5,
		RetryDelay: time.Second,
		Timeout:    30 * time.Second,
		QueueSize:  1000,
		Enabled:    true,
	}

	originValidator := NewOriginValidator(logger, allowedOrigins, true)

	// Create upgrader with origin validation
	upgrader := &websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		CheckOrigin:      originValidator.CheckOrigin,
		HandshakeTimeout: 10 * time.Second,
	}

	return &EventStreamer{
		logger:          logger,
		clients:         make(map[string]*StreamClient),
		webhookQueue:    make(chan *WebhookDelivery, webhookConfig.QueueSize),
		webhookConfig:   webhookConfig,
		service:         service,
		originValidator: originValidator,
		upgrader:        upgrader,
	}
}

// NewEventStreamerWithConfig creates a new event streamer with full stream config
func NewEventStreamerWithConfig(logger *zap.Logger, service *Service, streamConfig *StreamConfig) *EventStreamer {
	if streamConfig == nil {
		streamConfig = DefaultStreamConfig()
	}

	webhookConfig := &WebhookConfig{
		MaxRetries: 5,
		RetryDelay: time.Second,
		Timeout:    30 * time.Second,
		QueueSize:  1000,
		Enabled:    true,
	}

	originValidator := NewOriginValidator(logger, streamConfig.AllowedOrigins, streamConfig.EnableSecurityLogging)

	upgrader := &websocket.Upgrader{
		ReadBufferSize:   streamConfig.MaxMessageSize,
		WriteBufferSize:  streamConfig.MaxMessageSize,
		CheckOrigin:      originValidator.CheckOrigin,
		HandshakeTimeout: time.Duration(streamConfig.WriteTimeout) * time.Second,
	}

	return &EventStreamer{
		logger:          logger,
		clients:         make(map[string]*StreamClient),
		webhookQueue:    make(chan *WebhookDelivery, webhookConfig.QueueSize),
		webhookConfig:   webhookConfig,
		service:         service,
		originValidator: originValidator,
		upgrader:        upgrader,
	}
}

// RegisterRoutes registers streaming routes
func (es *EventStreamer) RegisterRoutes(r *gin.RouterGroup) {
	stream := r.Group("/stream")
	{
		// GET "" is the WebSocket upgrade: browsers can't set an Authorization
		// header on a WebSocket, so the token arrives as the access_token_<jwt>
		// subprotocol and is validated inside handleWebSocketStream.
		stream.GET("", es.handleWebSocketStream)
		// /subscribe and the webhook management routes are normal HTTP and take
		// the JWT auth middleware directly.
		if es.jwksURL != "" {
			stream.POST("/subscribe", middleware.Auth(es.jwksURL), es.handleSubscribe)
		} else {
			stream.POST("/subscribe", es.handleSubscribe)
		}
	}

	webhooks := r.Group("/webhooks")
	if es.jwksURL != "" {
		webhooks.Use(middleware.Auth(es.jwksURL))
	}
	{
		webhooks.POST("", es.handleRegisterWebhook)
		webhooks.GET("", es.handleListWebhooks)
		webhooks.DELETE("/:id", es.handleDeleteWebhook)
		webhooks.POST("/:id/test", es.handleTestWebhook)
	}

	// Start webhook delivery worker
	go es.webhookWorker()
}

// handleWebSocketStream upgrades HTTP to WebSocket and streams events
func (es *EventStreamer) handleWebSocketStream(c *gin.Context) {
	// Authenticate BEFORE upgrading. The browser can't set an Authorization
	// header on a WebSocket, so the frontend passes the token as the
	// "access_token_<jwt>" subprotocol (see web/admin-console lib/api.ts). Reject
	// unauthenticated connections — the audit stream is sensitive security data.
	if es.jwksURL != "" {
		tokenStr := extractSubprotocolToken(c.Request.Header.Get("Sec-WebSocket-Protocol"))
		if tokenStr == "" {
			c.JSON(401, gin.H{"error": "missing access token (pass as access_token_<jwt> subprotocol)"})
			return
		}
		if _, err := middleware.VerifyBearerToken(es.jwksURL, tokenStr); err != nil {
			es.logger.Warn("audit stream: rejected unauthenticated/invalid WebSocket token",
				zap.String("remote_addr", c.Request.RemoteAddr), zap.Error(err))
			c.JSON(401, gin.H{"error": "invalid access token"})
			return
		}
	}

	// Echo the client's offered "access_token_<jwt>" subprotocol back in the 101
	// response. Browsers require this: a WebSocket opened with a subprotocol
	// whose handshake response omits a matching Sec-WebSocket-Protocol header is
	// failed by the browser and closed with 1006. Non-browser clients (curl,
	// raw sockets) accept the upgrade regardless, which can mask the bug.
	var upgradeHeader http.Header
	if sp := selectedSubprotocol(c.Request.Header.Get("Sec-WebSocket-Protocol")); sp != "" {
		upgradeHeader = http.Header{"Sec-WebSocket-Protocol": []string{sp}}
	}

	conn, err := es.upgrader.Upgrade(c.Writer, c.Request, upgradeHeader)
	if err != nil {
		es.logger.Error("Failed to upgrade to WebSocket",
			zap.String("client_id", c.Query("client_id")),
			zap.String("remote_addr", c.Request.RemoteAddr),
			zap.Error(err))
		return
	}

	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = fmt.Sprintf("client_%d", time.Now().UnixNano())
	}

	// Parse filters from query params
	filters := &StreamFilters{}
	if eventTypes := c.Query("event_types"); eventTypes != "" {
		var types []EventType
		for _, t := range splitAndTrim(eventTypes, ",") {
			types = append(types, EventType(t))
		}
		filters.EventTypes = types
	}
	if categories := c.Query("categories"); categories != "" {
		var cats []EventCategory
		for _, c := range splitAndTrim(categories, ",") {
			cats = append(cats, EventCategory(c))
		}
		filters.Categories = cats
	}
	filters.ActorID = c.Query("actor_id")
	if outcome := c.Query("outcome"); outcome != "" {
		o := ServiceEventOutcome(outcome)
		filters.Outcome = &o
	}

	client := &StreamClient{
		ID:      clientID,
		Conn:    conn,
		Send:    make(chan *ServiceAuditEvent, 256),
		Filters: filters,
		done:    make(chan struct{}),
	}

	es.clientsMutex.Lock()
	es.clients[clientID] = client
	es.clientsMutex.Unlock()

	es.logger.Info("WebSocket client connected",
		zap.String("client_id", clientID),
		zap.String("remote_addr", c.Request.RemoteAddr))

	// Start reader and writer goroutines
	go client.readPump(es)
	go client.writePump(es)
}

// readPump reads messages from the WebSocket connection
func (sc *StreamClient) readPump(es *EventStreamer) {
	defer func() {
		sc.Conn.Close()
		close(sc.done)
		es.removeClient(sc.ID)
	}()

	sc.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	sc.Conn.SetPongHandler(func(string) error {
		sc.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := sc.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				es.logger.Error("WebSocket read error",
					zap.String("client_id", sc.ID),
					zap.Error(err))
			}
			break
		}
	}
}

// writePump writes events to the WebSocket connection
func (sc *StreamClient) writePump(es *EventStreamer) {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		sc.Conn.Close()
	}()

	for {
		select {
		case event, ok := <-sc.Send:
			sc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				sc.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if sc.matchesFilters(event) {
				data, err := json.Marshal(event)
				if err != nil {
					es.logger.Error("Failed to marshal event",
						zap.String("client_id", sc.ID),
						zap.Error(err))
					continue
				}

				if err := sc.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
					es.logger.Error("WebSocket write error",
						zap.String("client_id", sc.ID),
						zap.Error(err))
					return
				}
			}

		case <-ticker.C:
			sc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := sc.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-sc.done:
			return
		}
	}
}

// matchesFilters checks if an event matches the client's filters
func (sc *StreamClient) matchesFilters(event *ServiceAuditEvent) bool {
	if sc.Filters == nil {
		return true
	}

	// Filter by event type
	if len(sc.Filters.EventTypes) > 0 {
		found := false
		for _, et := range sc.Filters.EventTypes {
			if event.EventType == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by category
	if len(sc.Filters.Categories) > 0 {
		found := false
		for _, cat := range sc.Filters.Categories {
			if event.Category == cat {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by actor ID
	if sc.Filters.ActorID != "" && event.ActorID != sc.Filters.ActorID {
		return false
	}

	// Filter by outcome
	if sc.Filters.Outcome != nil && event.Outcome != *sc.Filters.Outcome {
		return false
	}

	return true
}

// Broadcast sends an event to all connected WebSocket clients
func (es *EventStreamer) Broadcast(event *ServiceAuditEvent) {
	es.clientsMutex.RLock()
	defer es.clientsMutex.RUnlock()

	for _, client := range es.clients {
		select {
		case client.Send <- event:
		default:
			es.logger.Warn("Client send buffer full, dropping event",
				zap.String("client_id", client.ID))
		}
	}
}

// removeClient removes a client from the clients map
func (es *EventStreamer) removeClient(clientID string) {
	es.clientsMutex.Lock()
	defer es.clientsMutex.Unlock()
	delete(es.clients, clientID)
	es.logger.Info("WebSocket client disconnected", zap.String("client_id", clientID))
}

// handleSubscribe handles a subscription request (alternative to WebSocket)
func (es *EventStreamer) handleSubscribe(c *gin.Context) {
	var req struct {
		ClientID string         `json:"client_id"`
		Filters  *StreamFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}

	c.JSON(200, gin.H{
		"message":   "Use WebSocket endpoint at /api/v1/audit/stream for real-time events",
		"client_id": req.ClientID,
		"ws_url":    fmt.Sprintf("/api/v1/audit/stream?client_id=%s", req.ClientID),
	})
}

// handleRegisterWebhook registers a new webhook subscription
func (es *EventStreamer) handleRegisterWebhook(c *gin.Context) {
	var req struct {
		URL     string         `json:"url" binding:"required"`
		Secret  string         `json:"secret"`
		Enabled bool           `json:"enabled"`
		Filters *StreamFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}

	subscription := &WebhookSubscription{
		ID:        generateUUID(),
		URL:       req.URL,
		Secret:    req.Secret,
		Enabled:   req.Enabled,
		Filters:   req.Filters,
		CreatedAt: time.Now().UTC(),
	}

	// Store subscription in database
	if es.service.db != nil && es.service.db.Pool != nil {
		ctx := c.Request.Context()
		org, err := orgctx.From(ctx)
		if err != nil {
			c.JSON(403, gin.H{"error": "organization context required"})
			return
		}
		_, err = es.service.db.Pool.Exec(ctx, `
			INSERT INTO audit_webhook_subscriptions (id, url, secret, enabled, filters, created_at, org_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, subscription.ID, subscription.URL, subscription.Secret, subscription.Enabled,
			subscription.Filters, subscription.CreatedAt, org.ID)

		if err != nil {
			es.logger.Error("Failed to store webhook subscription", zap.Error(err))
			c.JSON(500, gin.H{"error": "failed to register webhook"})
			return
		}
	}

	c.JSON(201, subscription)
}

// handleListWebhooks lists all webhook subscriptions
func (es *EventStreamer) handleListWebhooks(c *gin.Context) {
	if es.service.db == nil || es.service.db.Pool == nil {
		c.JSON(200, []*WebhookSubscription{})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(403, gin.H{"error": "organization context required"})
		return
	}
	rows, err := es.service.db.Pool.Query(ctx, `
		SELECT id, url, enabled, filters, created_at, last_delivery, failure_count
		FROM audit_webhook_subscriptions
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query webhooks"})
		return
	}
	defer rows.Close()

	var webhooks []*WebhookSubscription
	for rows.Next() {
		var wh WebhookSubscription
		var filtersJSON []byte
		var lastDelivery *time.Time
		err := rows.Scan(&wh.ID, &wh.URL, &wh.Enabled, &filtersJSON,
			&wh.CreatedAt, &lastDelivery, &wh.FailureCount)
		if err != nil {
			es.logger.Warn("Failed to scan webhook subscription row", zap.Error(err))
			continue
		}
		if lastDelivery != nil {
			wh.LastDelivery = *lastDelivery
		}
		if len(filtersJSON) > 0 {
			json.Unmarshal(filtersJSON, &wh.Filters)
		}
		webhooks = append(webhooks, &wh)
	}

	c.JSON(200, webhooks)
}

// handleDeleteWebhook deletes a webhook subscription
func (es *EventStreamer) handleDeleteWebhook(c *gin.Context) {
	if es.service.db == nil || es.service.db.Pool == nil {
		c.JSON(500, gin.H{"error": "database not available"})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(403, gin.H{"error": "organization context required"})
		return
	}

	_, err = es.service.db.Pool.Exec(ctx,
		"DELETE FROM audit_webhook_subscriptions WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to delete webhook"})
		return
	}

	c.JSON(204, nil)
}

// handleTestWebhook sends a test event to a webhook
func (es *EventStreamer) handleTestWebhook(c *gin.Context) {
	if es.service.db == nil || es.service.db.Pool == nil {
		c.JSON(500, gin.H{"error": "database not available"})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(403, gin.H{"error": "organization context required"})
		return
	}

	var url string
	err = es.service.db.Pool.QueryRow(ctx,
		"SELECT url FROM audit_webhook_subscriptions WHERE id = $1 AND org_id = $2", id, org.ID).Scan(&url)
	if err != nil {
		c.JSON(404, gin.H{"error": "webhook not found"})
		return
	}

	// Create test event
	testEvent := &ServiceAuditEvent{
		ID:        generateUUID(),
		Timestamp: time.Now().UTC(),
		EventType: EventTypeSystem,
		Category:  CategoryOperational,
		Action:    "webhook.test",
		Outcome:   ServiceOutcomeSuccess,
		Details: map[string]interface{}{
			"message": "Test webhook delivery",
			"test":    true,
		},
	}

	delivery := &WebhookDelivery{
		Event:      testEvent,
		WebhookURL: url,
		RetryCount: 0,
		ID:         generateUUID(),
	}

	// Send test delivery directly
	success := es.deliverWebhook(delivery)
	if success {
		c.JSON(200, gin.H{"status": "delivered", "event": testEvent})
	} else {
		c.JSON(500, gin.H{"status": "failed", "event": testEvent})
	}
}

// SendWebhook queues a webhook for delivery
func (es *EventStreamer) SendWebhook(event *ServiceAuditEvent, webhookURL string) {
	delivery := &WebhookDelivery{
		Event:      event,
		WebhookURL: webhookURL,
		RetryCount: 0,
		ID:         generateUUID(),
	}

	select {
	case es.webhookQueue <- delivery:
	default:
		es.logger.Warn("Webhook queue full, dropping delivery",
			zap.String("webhook_url", webhookURL),
			zap.String("event_id", event.ID))
	}
}

// webhookWorker processes webhook deliveries from the queue
func (es *EventStreamer) webhookWorker() {
	for delivery := range es.webhookQueue {
		if !es.webhookConfig.Enabled {
			continue
		}

		success := es.deliverWebhook(delivery)
		if !success && delivery.RetryCount < es.webhookConfig.MaxRetries {
			// Exponential backoff retry
			delay := es.webhookConfig.RetryDelay * time.Duration(1<<uint(delivery.RetryCount))
			time.Sleep(delay)
			delivery.RetryCount++
			es.webhookQueue <- delivery
		}
	}
}

// deliverWebhook delivers a single webhook with retry logic
func (es *EventStreamer) deliverWebhook(delivery *WebhookDelivery) bool {
	ctx, cancel := context.WithTimeout(context.Background(), es.webhookConfig.Timeout)
	defer cancel()

	data, err := json.Marshal(delivery.Event)
	if err != nil {
		es.logger.Error("Failed to marshal webhook payload",
			zap.String("delivery_id", delivery.ID),
			zap.Error(err))
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", delivery.WebhookURL, bytes.NewReader(data))
	if err != nil {
		es.logger.Error("Failed to create webhook request",
			zap.String("delivery_id", delivery.ID),
			zap.Error(err))
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenIDX-Audit-Streamer/1.0")
	req.Header.Set("X-OpenIDX-Delivery-ID", delivery.ID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		es.logger.Warn("Webhook delivery failed",
			zap.String("delivery_id", delivery.ID),
			zap.String("webhook_url", delivery.WebhookURL),
			zap.Int("retry_count", delivery.RetryCount),
			zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		es.logger.Debug("Webhook delivered successfully",
			zap.String("delivery_id", delivery.ID),
			zap.String("webhook_url", delivery.WebhookURL),
			zap.Int("status_code", resp.StatusCode))

		// Update last delivery time
		if es.service.db != nil && es.service.db.Pool != nil {
			updateCtx, cancel := context.WithTimeout(orgctx.WithBypassRLS(context.Background()), 5*time.Second)
			//orgscope:ignore background webhook-delivery bookkeeping; keyed by webhook url, no request context
			_, _ = es.service.db.Pool.Exec(updateCtx, `
				UPDATE audit_webhook_subscriptions
				SET last_delivery = NOW(), failure_count = 0
				WHERE url = $1
			`, delivery.WebhookURL)
			cancel()
		}

		return true
	}

	es.logger.Warn("Webhook returned non-success status",
		zap.String("delivery_id", delivery.ID),
		zap.String("webhook_url", delivery.WebhookURL),
		zap.Int("status_code", resp.StatusCode))

	// Increment failure count
	if es.service.db != nil && es.service.db.Pool != nil {
		updateCtx, cancel := context.WithTimeout(orgctx.WithBypassRLS(context.Background()), 5*time.Second)
		//orgscope:ignore background webhook-delivery bookkeeping; keyed by webhook url, no request context
		_, _ = es.service.db.Pool.Exec(updateCtx, `
			UPDATE audit_webhook_subscriptions
			SET failure_count = failure_count + 1
			WHERE url = $1
		`, delivery.WebhookURL)
		cancel()
	}

	return false
}

// GetConnectedClients returns the number of connected WebSocket clients
func (es *EventStreamer) GetConnectedClients() int {
	es.clientsMutex.RLock()
	defer es.clientsMutex.RUnlock()
	return len(es.clients)
}

// GetAllowedOrigins returns the current allowed origins for WebSocket connections
func (es *EventStreamer) GetAllowedOrigins() []string {
	return es.originValidator.GetAllowedOrigins()
}

// UpdateAllowedOrigins updates the allowed origins for WebSocket connections
func (es *EventStreamer) UpdateAllowedOrigins(origins []string) {
	es.originValidator.UpdateAllowedOrigins(origins)
	es.logger.Info("WebSocket allowed origins updated",
		zap.Int("origin_count", len(origins)),
		zap.Bool("wildcard_allowed", es.originValidator.IsWildcardAllowed()))
}

// GetOriginValidator returns the origin validator for external use
func (es *EventStreamer) GetOriginValidator() *OriginValidator {
	return es.originValidator
}

// splitAndTrim splits a string and trims whitespace from each part
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := make([]string, 0)
	for _, p := range splitString(s, sep) {
		if trimmed := trimString(p); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// Helper functions for string manipulation
func splitString(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	var result []string
	current := ""
	for _, c := range s {
		if string(c) == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
