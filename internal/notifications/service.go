package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// Notification represents a notification sent to a user.
type Notification struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	OrgID     string                 `json:"org_id"`
	Channel   string                 `json:"channel"`
	Type      string                 `json:"type"`
	Title     string                 `json:"title"`
	Body      string                 `json:"body"`
	Link      *string                `json:"link"`
	Read      bool                   `json:"read"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
}

// NotificationPreference represents a user's preference for a specific notification channel and event type.
type NotificationPreference struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Channel   string    `json:"channel"`
	EventType string    `json:"event_type"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Service provides notification operations.
type Service struct {
	db     *database.PostgresDB
	logger *zap.Logger
	// ntfy, when set via SetNtfy, delivers the "push" channel to a
	// self-hosted ntfy server. Nil = push channel disabled.
	ntfy *ntfySender
}

// NewService creates a new notification service.
func NewService(db *database.PostgresDB, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// CreateNotification inserts a notification if the user has not disabled it.
func (s *Service) CreateNotification(ctx context.Context, notif *Notification) error {
	if !s.isNotificationEnabled(ctx, notif.UserID, notif.Channel, notif.Type) {
		s.logger.Debug("notification disabled by user preference",
			zap.String("user_id", notif.UserID),
			zap.String("channel", notif.Channel),
			zap.String("type", notif.Type),
		)
		return nil
	}

	if notif.ID == "" {
		notif.ID = uuid.New().String()
	}
	if notif.CreatedAt.IsZero() {
		notif.CreatedAt = time.Now().UTC()
	}

	metadataBytes, err := json.Marshal(notif.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO notifications (id, user_id, org_id, channel, type, title, body, link, read, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err = s.db.Pool.Exec(ctx, query,
		notif.ID, notif.UserID, notif.OrgID, notif.Channel, notif.Type,
		notif.Title, notif.Body, notif.Link, notif.Read, metadataBytes, notif.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert notification: %w", err)
	}

	return nil
}

// CreateMultiChannelNotification creates a notification for the in_app channel.
func (s *Service) CreateMultiChannelNotification(ctx context.Context, userID, orgID, notifType, title, body, link string, metadata map[string]interface{}) error {
	var linkPtr *string
	if link != "" {
		linkPtr = &link
	}

	notif := &Notification{
		UserID:   userID,
		OrgID:    orgID,
		Channel:  "in_app",
		Type:     notifType,
		Title:    title,
		Body:     body,
		Link:     linkPtr,
		Read:     false,
		Metadata: metadata,
	}

	err := s.CreateNotification(ctx, notif)

	// Push (ntfy) rides alongside in_app: asynchronous and best-effort, so a
	// down push server never blocks or fails the notification write.
	if err == nil && s.ntfy != nil {
		go s.maybePush(userID, notifType, title, body, link)
	}

	return err
}

// isNotificationEnabled checks whether a user has enabled notifications for the given channel and event type.
// If no preference record exists, notifications are enabled by default.
func (s *Service) isNotificationEnabled(ctx context.Context, userID, channel, eventType string) bool {
	query := `SELECT enabled FROM notification_preferences WHERE user_id = $1 AND channel = $2 AND event_type = $3`

	var enabled bool
	err := s.db.Pool.QueryRow(ctx, query, userID, channel, eventType).Scan(&enabled)
	if err != nil {
		// No record found or query error: default to enabled.
		return true
	}
	return enabled
}

// GetUserNotifications returns a paginated list of notifications for a user, along with the total count.
func (s *Service) GetUserNotifications(ctx context.Context, userID, channel string, unreadOnly bool, limit, offset int) ([]Notification, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	baseWhere := "WHERE user_id = $1 AND org_id = $2"
	args := []interface{}{userID, org.ID}
	argIdx := 3

	if channel != "" {
		baseWhere += fmt.Sprintf(" AND channel = $%d", argIdx)
		args = append(args, channel)
		argIdx++
	}
	if unreadOnly {
		baseWhere += " AND read = false"
	}

	// Count query.
	// SECURITY: baseWhere is built from hardcoded string literals and parameterized query values only
	//orgscope:ignore org filter (org_id) is applied via the interpolated baseWhere, which the linter can't see
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM notifications %s", baseWhere)
	var total int
	if err := s.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count notifications: %w", err)
	}

	// Data query.
	dataQuery := fmt.Sprintf(
		"SELECT id, user_id, org_id, channel, type, title, body, link, read, metadata, created_at FROM notifications %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		baseWhere, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := s.db.Pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query notifications: %w", err)
	}
	defer rows.Close()

	var notifications []Notification
	for rows.Next() {
		var n Notification
		var metadataBytes []byte
		if err := rows.Scan(&n.ID, &n.UserID, &n.OrgID, &n.Channel, &n.Type, &n.Title, &n.Body, &n.Link, &n.Read, &metadataBytes, &n.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan notification: %w", err)
		}
		if metadataBytes != nil {
			if err := json.Unmarshal(metadataBytes, &n.Metadata); err != nil {
				s.logger.Warn("failed to unmarshal notification metadata", zap.Error(err))
			}
		}
		notifications = append(notifications, n)
	}

	return notifications, total, nil
}

// GetUnreadCount returns the number of unread in_app notifications for a user.
func (s *Service) GetUnreadCount(ctx context.Context, userID string) (int, error) {
	query := `SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read = false AND channel = 'in_app'`
	var count int
	if err := s.db.Pool.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count unread notifications: %w", err)
	}
	return count, nil
}

// MarkAsRead marks the specified notifications as read for a user.
func (s *Service) MarkAsRead(ctx context.Context, userID string, ids []string) error {
	query := `UPDATE notifications SET read = true WHERE user_id = $1 AND id = ANY($2)`
	_, err := s.db.Pool.Exec(ctx, query, userID, ids)
	if err != nil {
		return fmt.Errorf("failed to mark notifications as read: %w", err)
	}
	return nil
}

// MarkAllAsRead marks all unread notifications as read for a user.
func (s *Service) MarkAllAsRead(ctx context.Context, userID string) error {
	query := `UPDATE notifications SET read = true WHERE user_id = $1 AND read = false`
	_, err := s.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to mark all notifications as read: %w", err)
	}
	return nil
}

// GetPreferences returns all notification preferences for a user.
func (s *Service) GetPreferences(ctx context.Context, userID string) ([]NotificationPreference, error) {
	query := `SELECT id, user_id, channel, event_type, enabled, created_at, updated_at FROM notification_preferences WHERE user_id = $1`
	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query notification preferences: %w", err)
	}
	defer rows.Close()

	var prefs []NotificationPreference
	for rows.Next() {
		var p NotificationPreference
		if err := rows.Scan(&p.ID, &p.UserID, &p.Channel, &p.EventType, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan notification preference: %w", err)
		}
		prefs = append(prefs, p)
	}

	return prefs, nil
}

// UpdatePreferences upserts notification preferences for a user within a transaction.
func (s *Service) UpdatePreferences(ctx context.Context, userID string, prefs []NotificationPreference) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	query := `
		INSERT INTO notification_preferences (id, user_id, channel, event_type, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, channel, event_type)
		DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = EXCLUDED.updated_at`

	now := time.Now().UTC()
	for _, p := range prefs {
		id := p.ID
		if id == "" {
			id = uuid.New().String()
		}
		_, err := tx.Exec(ctx, query, id, userID, p.Channel, p.EventType, p.Enabled, now, now)
		if err != nil {
			return fmt.Errorf("failed to upsert notification preference: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

func getUserID(c *gin.Context) string {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	return userIDStr
}

func (s *Service) handleGetNotifications(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	channel := c.Query("channel")

	unreadOnly := c.Query("unread") == "true"

	limit := 20
	offset := 0
	if v := c.Query("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if v := c.Query("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	notifications, total, err := s.GetUserNotifications(c.Request.Context(), userID, channel, unreadOnly, limit, offset)
	if err != nil {
		s.logger.Error("failed to get notifications", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get notifications"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"notifications": notifications,
		"total":         total,
		"limit":         limit,
		"offset":        offset,
	})
}

func (s *Service) handleGetUnreadCount(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	count, err := s.GetUnreadCount(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get unread count", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get unread count"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"unread_count": count})
}

func (s *Service) handleMarkAsRead(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var req struct {
		NotificationIDs []string `json:"notification_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if len(req.NotificationIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "notification_ids is required"})
		return
	}

	if err := s.MarkAsRead(c.Request.Context(), userID, req.NotificationIDs); err != nil {
		s.logger.Error("failed to mark notifications as read", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mark notifications as read"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "notifications marked as read"})
}

func (s *Service) handleMarkAllAsRead(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	if err := s.MarkAllAsRead(c.Request.Context(), userID); err != nil {
		s.logger.Error("failed to mark all notifications as read", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mark all notifications as read"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all notifications marked as read"})
}

func (s *Service) handleGetPreferences(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	prefs, err := s.GetPreferences(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get notification preferences", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get notification preferences"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"preferences": prefs})
}

func (s *Service) handleUpdatePreferences(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var req struct {
		Preferences []NotificationPreference `json:"preferences"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := s.UpdatePreferences(c.Request.Context(), userID, req.Preferences); err != nil {
		s.logger.Error("failed to update notification preferences", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update notification preferences"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "preferences updated"})
}

// --- Phase 17D: Notification Center Handlers ---

func (s *Service) handleGetNotificationHistory(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	typeFilter := c.Query("type")
	query := `SELECT id, user_id, org_id, channel, type, title, body, link, read, metadata, created_at
		FROM notifications WHERE user_id = $1`
	args := []interface{}{userID}
	argIdx := 2

	if typeFilter != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, typeFilter)
		argIdx++
	}
	_ = argIdx
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := s.db.Pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("failed to get notification history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get history"})
		return
	}
	defer rows.Close()

	var notifications []Notification
	for rows.Next() {
		var n Notification
		var metadataBytes []byte
		if err := rows.Scan(&n.ID, &n.UserID, &n.OrgID, &n.Channel, &n.Type,
			&n.Title, &n.Body, &n.Link, &n.Read, &metadataBytes, &n.CreatedAt); err != nil {
			continue
		}
		if metadataBytes != nil {
			_ = json.Unmarshal(metadataBytes, &n.Metadata)
		}
		notifications = append(notifications, n)
	}
	if notifications == nil {
		notifications = []Notification{}
	}
	c.JSON(http.StatusOK, gin.H{"data": notifications})
}

func (s *Service) handleDeleteNotification(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	notifID := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete notification"})
		return
	}

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM notifications WHERE id = $1 AND user_id = $2 AND org_id = $3", notifID, userID, org.ID)
	if err != nil {
		s.logger.Error("failed to delete notification", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete notification"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "notification not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "notification deleted"})
}

func (s *Service) handleGetDigestSettings(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, digest_type, channel, last_sent_at, next_scheduled_at,
			notification_count, enabled, settings, created_at, updated_at
		 FROM notification_digests WHERE user_id = $1`, userID)
	if err != nil {
		s.logger.Error("failed to get digest settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get digest settings"})
		return
	}
	defer rows.Close()

	type digest struct {
		ID                string          `json:"id"`
		DigestType        string          `json:"digest_type"`
		Channel           string          `json:"channel"`
		LastSentAt        *time.Time      `json:"last_sent_at"`
		NextScheduledAt   *time.Time      `json:"next_scheduled_at"`
		NotificationCount int             `json:"notification_count"`
		Enabled           bool            `json:"enabled"`
		Settings          json.RawMessage `json:"settings"`
		CreatedAt         time.Time       `json:"created_at"`
		UpdatedAt         time.Time       `json:"updated_at"`
	}

	var digests []digest
	for rows.Next() {
		var d digest
		if err := rows.Scan(&d.ID, &d.DigestType, &d.Channel, &d.LastSentAt, &d.NextScheduledAt,
			&d.NotificationCount, &d.Enabled, &d.Settings, &d.CreatedAt, &d.UpdatedAt); err != nil {
			continue
		}
		digests = append(digests, d)
	}
	if digests == nil {
		digests = []digest{}
	}
	c.JSON(http.StatusOK, gin.H{"data": digests})
}

func (s *Service) handleUpdateDigestSettings(c *gin.Context) {
	userID := getUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var req struct {
		DigestType string          `json:"digest_type" binding:"required"`
		Channel    string          `json:"channel"`
		Enabled    bool            `json:"enabled"`
		Settings   json.RawMessage `json:"settings"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Channel == "" {
		req.Channel = "email"
	}

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO notification_digests (user_id, digest_type, channel, enabled, settings)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id, digest_type, channel)
		 DO UPDATE SET enabled = EXCLUDED.enabled, settings = EXCLUDED.settings, updated_at = NOW()`,
		userID, req.DigestType, req.Channel, req.Enabled, req.Settings)
	if err != nil {
		s.logger.Error("failed to update digest settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update digest settings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "digest settings updated"})
}

// RegisterRoutes registers the notification HTTP routes on the given router group.
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	router.GET("/notifications", svc.handleGetNotifications)
	router.GET("/notifications/unread-count", svc.handleGetUnreadCount)
	router.POST("/notifications/mark-read", svc.handleMarkAsRead)
	router.POST("/notifications/mark-all-read", svc.handleMarkAllAsRead)
	router.GET("/notifications/preferences", svc.handleGetPreferences)
	router.PUT("/notifications/preferences", svc.handleUpdatePreferences)
	// Push (ntfy) subscription details for the calling user.
	router.GET("/notifications/push-config", svc.handleGetPushConfig)

	// Phase 17D: Notification Center extensions
	router.GET("/notifications/history", svc.handleGetNotificationHistory)
	router.DELETE("/notifications/:id", svc.handleDeleteNotification)
	router.GET("/notifications/digest", svc.handleGetDigestSettings)
	router.PUT("/notifications/digest", svc.handleUpdateDigestSettings)
}
