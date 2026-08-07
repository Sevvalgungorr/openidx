// Package webhooks provides webhook subscription management and event delivery
package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// Webhook event type constants
const (
	EventUserCreated     = "user.created"
	EventUserUpdated     = "user.updated"
	EventUserDeleted     = "user.deleted"
	EventUserLocked      = "user.locked"
	EventLoginSuccess    = "login.success"
	EventLoginFailed     = "login.failed"
	EventLoginHighRisk   = "login.high_risk"
	EventGroupUpdated    = "group.updated"
	EventRoleUpdated     = "role.updated"
	EventPolicyViolated  = "policy.violated"
	EventReviewCompleted = "review.completed"
)

// Subscription represents a webhook subscription
type Subscription struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Secret    string    `json:"-"`
	Events    []string  `json:"events"`
	Status    string    `json:"status"`
	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Delivery represents a webhook delivery attempt
type Delivery struct {
	ID             string     `json:"id"`
	SubscriptionID string     `json:"subscription_id"`
	EventType      string     `json:"event_type"`
	Payload        string     `json:"payload"`
	ResponseStatus *int       `json:"response_status,omitempty"`
	ResponseBody   *string    `json:"response_body,omitempty"`
	Attempt        int        `json:"attempt"`
	Status         string     `json:"status"`
	NextRetryAt    *time.Time `json:"next_retry_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
}

// Service handles webhook operations
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	logger *zap.Logger
	client *resilience.ResilientHTTPClient
	// cipher encrypts the per-subscription HMAC signing secret at rest. Reads are
	// prefix-aware (legacy plaintext rows pass through) so rollout needs no flag day.
	cipher *secretcrypt.Cipher
}

// NewService creates a new webhook service. cipher encrypts subscription signing
// secrets at rest (built from ENCRYPTION_KEY by the caller).
func NewService(db *database.PostgresDB, redis *database.RedisClient, logger *zap.Logger, cipher *secretcrypt.Cipher) *Service {
	rawClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	cb := resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
		Name:         "webhook-delivery",
		Threshold:    10,
		ResetTimeout: 30 * time.Second,
		Logger:       logger.With(zap.String("component", "webhook-circuit-breaker")),
	})
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger,
		client: resilience.NewResilientHTTPClient(rawClient, cb),
		cipher: cipher,
	}
}

// CreateSubscription creates a new webhook subscription
func (s *Service) CreateSubscription(ctx context.Context, name, url, secret string, events []string, createdBy string) (*Subscription, error) {
	var createdByPtr *string
	if createdBy != "" {
		createdByPtr = &createdBy
	}

	sub := &Subscription{
		ID:        uuid.New().String(),
		Name:      name,
		URL:       url,
		Secret:    secret,
		Events:    events,
		Status:    "active",
		CreatedBy: createdByPtr,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Encrypt the signing secret at rest; the returned struct keeps the plaintext
	// (the caller supplied it and may echo it once on creation).
	encSecret, err := s.cipher.Encrypt(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt webhook secret: %w", err)
	}

	// Persist org_id explicitly from the request context. The column has a
	// hardcoded DEFAULT (the seeded default org) that only matches org 010; for
	// every other tenant that default violates the RLS WITH CHECK
	// (org_id must equal app.org_id), so the row would either be rejected or land
	// in the wrong org and never appear in the tenant's list. Sourcing org_id
	// from orgctx makes create/list consistent for all tenants.
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("webhook create requires organization context: %w", err)
	}

	query := `INSERT INTO webhook_subscriptions (id, org_id, name, url, secret, events, status, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6::TEXT[], $7, $8, $9, $10)`

	_, err = s.db.Pool.Exec(ctx, query,
		sub.ID, org.ID, sub.Name, sub.URL, encSecret, sub.Events,
		sub.Status, sub.CreatedBy, sub.CreatedAt, sub.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook subscription: %w", err)
	}

	s.logger.Info("webhook subscription created",
		zap.String("id", sub.ID),
		zap.String("name", sub.Name),
		zap.String("url", sub.URL),
		zap.Strings("events", sub.Events),
	)

	return sub, nil
}

// ListSubscriptions returns all active webhook subscriptions
func (s *Service) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	query := `SELECT id, name, url, secret, events, status, created_by, created_at, updated_at
		FROM webhook_subscriptions WHERE status = 'active' ORDER BY created_at DESC`

	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhook subscriptions: %w", err)
	}
	defer rows.Close()

	var subscriptions []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(
			&sub.ID, &sub.Name, &sub.URL, &sub.Secret, &sub.Events,
			&sub.Status, &sub.CreatedBy, &sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan webhook subscription: %w", err)
		}
		if sub.Secret, err = s.cipher.Decrypt(sub.Secret); err != nil {
			return nil, fmt.Errorf("failed to decrypt webhook secret: %w", err)
		}
		subscriptions = append(subscriptions, sub)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating webhook subscriptions: %w", err)
	}

	return subscriptions, nil
}

// GetSubscription returns a webhook subscription by ID
func (s *Service) GetSubscription(ctx context.Context, id string) (*Subscription, error) {
	query := `SELECT id, name, url, secret, events, status, created_by, created_at, updated_at
		FROM webhook_subscriptions WHERE id = $1`

	var sub Subscription
	err := s.db.Pool.QueryRow(ctx, query, id).Scan(
		&sub.ID, &sub.Name, &sub.URL, &sub.Secret, &sub.Events,
		&sub.Status, &sub.CreatedBy, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("webhook subscription not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get webhook subscription: %w", err)
	}

	if sub.Secret, err = s.cipher.Decrypt(sub.Secret); err != nil {
		return nil, fmt.Errorf("failed to decrypt webhook secret: %w", err)
	}

	return &sub, nil
}

// UpdateSubscription updates a webhook subscription
func (s *Service) UpdateSubscription(ctx context.Context, id, name, url string, events []string, status string) error {
	query := `UPDATE webhook_subscriptions SET name = $2, url = $3, events = $4::TEXT[], status = $5, updated_at = $6
		WHERE id = $1`

	result, err := s.db.Pool.Exec(ctx, query, id, name, url, events, status, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update webhook subscription: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("webhook subscription not found: %s", id)
	}

	s.logger.Info("webhook subscription updated",
		zap.String("id", id),
		zap.String("name", name),
		zap.String("status", status),
	)

	return nil
}

// DeleteSubscription deletes a webhook subscription
func (s *Service) DeleteSubscription(ctx context.Context, id string) error {
	query := `DELETE FROM webhook_subscriptions WHERE id = $1`

	result, err := s.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete webhook subscription: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("webhook subscription not found: %s", id)
	}

	s.logger.Info("webhook subscription deleted", zap.String("id", id))

	return nil
}

// Publish sends an event to all matching webhook subscriptions
func (s *Service) Publish(ctx context.Context, eventType string, payload interface{}) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	query := `SELECT id, url, secret FROM webhook_subscriptions
		WHERE status = 'active' AND $1 = ANY(events)`

	rows, err := s.db.Pool.Query(ctx, query, eventType)
	if err != nil {
		return fmt.Errorf("failed to query matching subscriptions: %w", err)
	}
	defer rows.Close()

	var deliveryIDs []string
	for rows.Next() {
		var subID, subURL, subSecret string
		if err := rows.Scan(&subID, &subURL, &subSecret); err != nil {
			return fmt.Errorf("failed to scan subscription: %w", err)
		}

		deliveryID := uuid.New().String()
		insertQuery := `INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`

		_, err := s.db.Pool.Exec(ctx, insertQuery,
			deliveryID, subID, eventType, string(payloadJSON), 0, "pending", time.Now().UTC(),
		)
		if err != nil {
			s.logger.Error("failed to create webhook delivery",
				zap.String("subscription_id", subID),
				zap.Error(err),
			)
			continue
		}

		deliveryIDs = append(deliveryIDs, deliveryID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating subscriptions: %w", err)
	}

	// Push delivery IDs to Redis for processing
	for _, id := range deliveryIDs {
		if err := s.redis.Client.LPush(ctx, "webhook:deliveries", id).Err(); err != nil {
			s.logger.Error("failed to push delivery to Redis",
				zap.String("delivery_id", id),
				zap.Error(err),
			)
		}
	}

	s.logger.Info("webhook event published",
		zap.String("event_type", eventType),
		zap.Int("delivery_count", len(deliveryIDs)),
	)

	return nil
}

// ProcessDeliveries continuously processes pending webhook deliveries from the Redis queue
func (s *Service) ProcessDeliveries(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping webhook delivery processor")
			return
		default:
		}

		result, err := s.redis.Client.BRPop(ctx, 5*time.Second, "webhook:deliveries").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Timeout is expected when no deliveries are pending
			continue
		}

		if len(result) < 2 {
			continue
		}

		deliveryID := result[1]
		if err := s.deliverWebhook(ctx, deliveryID); err != nil {
			s.logger.Error("failed to deliver webhook",
				zap.String("delivery_id", deliveryID),
				zap.Error(err),
			)
		}
	}
}

// deliverWebhook sends a single webhook delivery
func (s *Service) deliverWebhook(ctx context.Context, deliveryID string) error {
	query := `SELECT d.id, d.subscription_id, d.event_type, d.payload, d.attempt, d.status,
			sub.url, sub.secret
		FROM webhook_deliveries d
		JOIN webhook_subscriptions sub ON d.subscription_id = sub.id
		WHERE d.id = $1`

	var (
		id, subscriptionID, eventType, payload, status string
		attempt                                        int
		subURL, subSecret                              string
	)

	err := s.db.Pool.QueryRow(ctx, query, deliveryID).Scan(
		&id, &subscriptionID, &eventType, &payload, &attempt, &status,
		&subURL, &subSecret,
	)
	if err != nil {
		return fmt.Errorf("failed to query delivery: %w", err)
	}
	// Idempotency: a duplicate nudge (e.g. the DB backstop re-queuing a row that
	// was actually in-flight) must not re-send an already-completed delivery.
	if status == "delivered" {
		return nil
	}
	if subSecret, err = s.cipher.Decrypt(subSecret); err != nil {
		return fmt.Errorf("failed to decrypt webhook secret: %w", err)
	}

	// Build the HTTP request
	body := []byte(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, subURL, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := computeSignature(subSecret, body)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-ID", deliveryID)
	req.Header.Set("X-Webhook-Event", eventType)
	req.Header.Set("X-Webhook-Timestamp", timestamp)
	req.Header.Set("X-Webhook-Signature", signature)

	// Send the request
	resp, err := s.client.Do(req)
	if err != nil {
		s.scheduleRetry(ctx, deliveryID, attempt, nil, err.Error())
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	// Read and truncate response body (limit to 1MB to prevent memory exhaustion from malicious receivers)
	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	respBodyStr := string(respBodyBytes)
	if len(respBodyStr) > 1000 {
		respBodyStr = respBodyStr[:1000]
	}

	// Check response status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		updateQuery := `UPDATE webhook_deliveries
			SET status = 'delivered', response_status = $2, response_body = $3, delivered_at = $4, attempt = attempt + 1
			WHERE id = $1`
		now := time.Now().UTC()
		_, err := s.db.Pool.Exec(ctx, updateQuery, deliveryID, resp.StatusCode, respBodyStr, now)
		if err != nil {
			return fmt.Errorf("failed to update delivery status: %w", err)
		}

		s.logger.Info("webhook delivered successfully",
			zap.String("delivery_id", deliveryID),
			zap.Int("status_code", resp.StatusCode),
		)
	} else {
		s.scheduleRetry(ctx, deliveryID, attempt, &resp.StatusCode, respBodyStr)
	}

	return nil
}

// scheduleRetry schedules a retry for a failed webhook delivery
func (s *Service) scheduleRetry(ctx context.Context, deliveryID string, attempt int, responseStatus *int, responseBody string) {
	nextAttempt := attempt + 1

	if nextAttempt > 3 {
		// Mark as failed after max retries
		updateQuery := `UPDATE webhook_deliveries
			SET status = 'failed', response_status = $2, response_body = $3, attempt = $4
			WHERE id = $1`
		_, err := s.db.Pool.Exec(ctx, updateQuery, deliveryID, responseStatus, responseBody, nextAttempt)
		if err != nil {
			s.logger.Error("failed to mark delivery as failed",
				zap.String("delivery_id", deliveryID),
				zap.Error(err),
			)
		}
		s.logger.Warn("webhook delivery failed after max retries",
			zap.String("delivery_id", deliveryID),
			zap.Int("attempts", nextAttempt),
		)
		return
	}

	// Calculate next retry time based on attempt number
	var retryDelay time.Duration
	switch nextAttempt {
	case 1:
		retryDelay = 1 * time.Minute
	case 2:
		retryDelay = 5 * time.Minute
	case 3:
		retryDelay = 30 * time.Minute
	}

	nextRetryAt := time.Now().UTC().Add(retryDelay)

	updateQuery := `UPDATE webhook_deliveries
		SET status = 'pending', response_status = $2, response_body = $3, attempt = $4, next_retry_at = $5
		WHERE id = $1`

	_, err := s.db.Pool.Exec(ctx, updateQuery, deliveryID, responseStatus, responseBody, nextAttempt, nextRetryAt)
	if err != nil {
		s.logger.Error("failed to schedule webhook retry",
			zap.String("delivery_id", deliveryID),
			zap.Error(err),
		)
		return
	}

	// Push back to Redis for retry processing
	if err := s.redis.Client.LPush(ctx, "webhook:deliveries", deliveryID).Err(); err != nil {
		s.logger.Error("failed to push retry delivery to Redis",
			zap.String("delivery_id", deliveryID),
			zap.Error(err),
		)
	}

	s.logger.Info("webhook delivery retry scheduled",
		zap.String("delivery_id", deliveryID),
		zap.Int("attempt", nextAttempt),
		zap.Time("next_retry_at", nextRetryAt),
	)
}

// computeSignature computes an HMAC-SHA256 signature for the webhook payload
func computeSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// GetDeliveryHistory returns delivery history for a subscription
func (s *Service) GetDeliveryHistory(ctx context.Context, subscriptionID string, limit int) ([]Delivery, error) {
	query := `SELECT id, subscription_id, event_type, payload, response_status, response_body,
			attempt, status, next_retry_at, created_at, delivered_at
		FROM webhook_deliveries
		WHERE subscription_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := s.db.Pool.Query(ctx, query, subscriptionID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query delivery history: %w", err)
	}
	defer rows.Close()

	var deliveries []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(
			&d.ID, &d.SubscriptionID, &d.EventType, &d.Payload,
			&d.ResponseStatus, &d.ResponseBody, &d.Attempt, &d.Status,
			&d.NextRetryAt, &d.CreatedAt, &d.DeliveredAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating deliveries: %w", err)
	}

	return deliveries, nil
}

// RetryDelivery resets a delivery to pending and queues it for reprocessing
func (s *Service) RetryDelivery(ctx context.Context, deliveryID string) error {
	query := `UPDATE webhook_deliveries SET status = 'pending', next_retry_at = NULL WHERE id = $1`

	result, err := s.db.Pool.Exec(ctx, query, deliveryID)
	if err != nil {
		return fmt.Errorf("failed to reset delivery status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("webhook delivery not found: %s", deliveryID)
	}

	if err := s.redis.Client.LPush(ctx, "webhook:deliveries", deliveryID).Err(); err != nil {
		return fmt.Errorf("failed to push delivery to Redis: %w", err)
	}

	s.logger.Info("webhook delivery retry requested", zap.String("delivery_id", deliveryID))

	return nil
}

// ProcessRetries periodically checks for pending deliveries that are due for retry
func (s *Service) ProcessRetries(ctx context.Context) {
	// Leader-gated: the retry sweep re-enqueues due deliveries by scanning the
	// DB, so across replicas it must run once per interval cluster-wide to avoid
	// duplicate re-enqueues. (Delivery itself uses a BRPop queue and is already
	// safe for competing consumers.)
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "webhooks:retry", 30*time.Second, s.processRetryBatch)
	<-ctx.Done()
	s.logger.Info("stopping webhook retry processor")
}

// processRetryBatch finds and re-queues pending deliveries that are due for retry
// OR that are stranded: a fresh delivery whose Redis nudge was lost (Redis blip/
// restart) has status='pending' with next_retry_at=NULL and would otherwise never
// be delivered. Recover those too, after a 30s grace so we don't race the normal
// nudge path. This makes the DB the reliable backstop — at-least-once delivery.
func (s *Service) processRetryBatch(ctx context.Context) {
	query := `SELECT id FROM webhook_deliveries
		WHERE status = 'pending'
		  AND ( (next_retry_at IS NOT NULL AND next_retry_at <= NOW())
		     OR (next_retry_at IS NULL AND created_at < NOW() - INTERVAL '30 seconds') )`

	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		s.logger.Error("failed to query retryable deliveries", zap.Error(err))
		return
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var deliveryID string
		if err := rows.Scan(&deliveryID); err != nil {
			s.logger.Error("failed to scan delivery ID", zap.Error(err))
			continue
		}

		if err := s.redis.Client.LPush(ctx, "webhook:deliveries", deliveryID).Err(); err != nil {
			s.logger.Error("failed to push retry delivery to Redis",
				zap.String("delivery_id", deliveryID),
				zap.Error(err),
			)
			continue
		}
		count++
	}

	if count > 0 {
		s.logger.Info("queued webhook deliveries for retry", zap.Int("count", count))
	}
}

// PingSubscription sends a test ping to a webhook subscription
func (s *Service) PingSubscription(ctx context.Context, subscriptionID string) (*Delivery, error) {
	// Load the subscription to verify it exists and get URL/secret
	sub, err := s.GetSubscription(ctx, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to load subscription for ping: %w", err)
	}

	// Create the test ping payload
	pingPayload := map[string]interface{}{
		"event":     "ping",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	payloadJSON, err := json.Marshal(pingPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ping payload: %w", err)
	}

	// Create a delivery record for the ping
	deliveryID := uuid.New().String()
	now := time.Now().UTC()

	insertQuery := `INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.db.Pool.Exec(ctx, insertQuery,
		deliveryID, subscriptionID, "ping", string(payloadJSON), 0, "pending", now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ping delivery record: %w", err)
	}

	// Build and send the HTTP request directly (no retry scheduling for test pings)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, strings.NewReader(string(payloadJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create ping request: %w", err)
	}

	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := computeSignature(sub.Secret, payloadJSON)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-ID", deliveryID)
	req.Header.Set("X-Webhook-Event", "ping")
	req.Header.Set("X-Webhook-Timestamp", timestamp)
	req.Header.Set("X-Webhook-Signature", signature)

	delivery := &Delivery{
		ID:             deliveryID,
		SubscriptionID: subscriptionID,
		EventType:      "ping",
		Payload:        string(payloadJSON),
		Attempt:        1,
		CreatedAt:      now,
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Update delivery as failed
		updateQuery := `UPDATE webhook_deliveries SET status = 'failed', attempt = 1, response_body = $2 WHERE id = $1`
		errMsg := err.Error()
		s.db.Pool.Exec(ctx, updateQuery, deliveryID, errMsg)

		delivery.Status = "failed"
		delivery.ResponseBody = &errMsg

		s.logger.Warn("webhook ping failed",
			zap.String("subscription_id", subscriptionID),
			zap.Error(err),
		)
		return delivery, nil
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB to prevent memory exhaustion from malicious receivers)
	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	respBodyStr := string(respBodyBytes)
	if len(respBodyStr) > 1000 {
		respBodyStr = respBodyStr[:1000]
	}

	deliveredAt := time.Now().UTC()
	statusCode := resp.StatusCode
	delivery.ResponseStatus = &statusCode
	delivery.ResponseBody = &respBodyStr
	delivery.DeliveredAt = &deliveredAt
	delivery.Attempt = 1

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		delivery.Status = "delivered"
		updateQuery := `UPDATE webhook_deliveries SET status = 'delivered', response_status = $2, response_body = $3, delivered_at = $4, attempt = 1 WHERE id = $1`
		s.db.Pool.Exec(ctx, updateQuery, deliveryID, statusCode, respBodyStr, deliveredAt)
	} else {
		delivery.Status = "failed"
		updateQuery := `UPDATE webhook_deliveries SET status = 'failed', response_status = $2, response_body = $3, attempt = 1 WHERE id = $1`
		s.db.Pool.Exec(ctx, updateQuery, deliveryID, statusCode, respBodyStr)
	}

	s.logger.Info("webhook ping completed",
		zap.String("subscription_id", subscriptionID),
		zap.String("delivery_id", deliveryID),
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", delivery.Status),
	)

	return delivery, nil
}

// GetDeliveryStats returns delivery statistics for a subscription
func (s *Service) GetDeliveryStats(ctx context.Context, subscriptionID string) (map[string]interface{}, error) {
	// Verify the subscription exists
	_, err := s.GetSubscription(ctx, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to load subscription for stats: %w", err)
	}

	query := `SELECT
		COUNT(*) AS total_deliveries,
		COUNT(*) FILTER (WHERE status = 'delivered') AS successful,
		COUNT(*) FILTER (WHERE status = 'failed') AS failed,
		COALESCE(AVG(EXTRACT(EPOCH FROM (delivered_at - created_at)) * 1000) FILTER (WHERE delivered_at IS NOT NULL), 0) AS avg_response_time_ms,
		MAX(delivered_at) AS last_delivery_at
	FROM webhook_deliveries
	WHERE subscription_id = $1`

	var (
		totalDeliveries int64
		successful      int64
		failed          int64
		avgResponseTime float64
		lastDeliveryAt  *time.Time
	)

	err = s.db.Pool.QueryRow(ctx, query, subscriptionID).Scan(
		&totalDeliveries,
		&successful,
		&failed,
		&avgResponseTime,
		&lastDeliveryAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query delivery stats: %w", err)
	}

	stats := map[string]interface{}{
		"subscription_id":       subscriptionID,
		"total_deliveries":      totalDeliveries,
		"successful_deliveries": successful,
		"failed_deliveries":     failed,
		"avg_response_time_ms":  int64(avgResponseTime),
		"last_delivery_at":      lastDeliveryAt,
	}

	// Calculate success rate
	if totalDeliveries > 0 {
		stats["success_rate"] = float64(successful) / float64(totalDeliveries) * 100.0
	} else {
		stats["success_rate"] = float64(0)
	}

	s.logger.Debug("webhook delivery stats retrieved",
		zap.String("subscription_id", subscriptionID),
		zap.Int64("total", totalDeliveries),
		zap.Int64("successful", successful),
		zap.Int64("failed", failed),
	)

	return stats, nil
}
