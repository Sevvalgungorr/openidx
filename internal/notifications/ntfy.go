// ntfy push channel — self-hosted push notifications without FCM/APNs.
//
// The notification service has always modeled a "push" channel in
// notification_preferences, but nothing ever delivered it. This wires the
// channel to a self-hosted ntfy server (https://ntfy.sh, open source): each
// user gets a stable, unguessable topic derived as
// HMAC-SHA256(topic_secret, user_id), the service publishes to it, and any
// subscriber (the OpenIDX mobile app, the ntfy app, a browser tab) receives
// the push — no Google/Apple push infrastructure in the path, fully on-prem.
//
// Clients discover their topic via GET /notifications/push-config; the topic
// is a per-user capability, so it is only ever returned to its own user.
// Delivery is best-effort and asynchronous: a down ntfy server never blocks
// or fails the in-app notification write.
package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// NtfyConfig configures the push channel. Enabled only when both BaseURL and
// TopicSecret are set — the secret is what makes per-user topics unguessable,
// so there is deliberately no way to run without it.
type NtfyConfig struct {
	// BaseURL of the self-hosted ntfy server, e.g. https://ntfy.internal.
	BaseURL string
	// Token optionally authenticates publishes (ntfy access tokens); use it
	// when the server denies anonymous writes (recommended).
	Token string
	// TopicSecret is the HMAC key for deriving per-user topics. Rotating it
	// rotates every user's topic (subscribers re-fetch push-config).
	TopicSecret string
}

type ntfySender struct {
	base   string
	token  string
	secret []byte
	client *http.Client
}

// SetNtfy enables (or, with an incomplete config, leaves disabled) the push
// channel on the service.
func (s *Service) SetNtfy(cfg NtfyConfig) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		s.logger.Warn("ntfy: invalid base URL; push channel disabled")
		return
	}
	if strings.TrimSpace(cfg.TopicSecret) == "" {
		s.logger.Warn("ntfy: NTFY_BASE_URL set but NTFY_TOPIC_SECRET empty; push channel disabled " +
			"(the secret is what makes per-user topics unguessable)")
		return
	}
	s.ntfy = &ntfySender{
		base:   base,
		token:  cfg.Token,
		secret: []byte(cfg.TopicSecret),
		client: &http.Client{Timeout: 5 * time.Second},
	}
	s.logger.Info("ntfy push channel enabled", zap.String("server", base))
}

// topicFor derives the user's stable push topic: an HMAC keyed on the server
// secret, so knowing a user id (or another user's topic) reveals nothing.
func (n *ntfySender) topicFor(userID string) string {
	mac := hmac.New(sha256.New, n.secret)
	mac.Write([]byte(userID))
	return "oidx-" + hex.EncodeToString(mac.Sum(nil))[:32]
}

// publish sends one push message. Best-effort: errors are returned for the
// caller to log, never to fail the notification write.
func (n *ntfySender) publish(ctx context.Context, userID, title, body, link string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		n.base+"/"+n.topicFor(userID), strings.NewReader(body))
	if err != nil {
		return err
	}
	// ntfy reads message metadata from headers; strip CR/LF so a
	// notification title can never smuggle extra headers.
	req.Header.Set("Title", sanitizeNtfyHeader(title))
	req.Header.Set("X-Tags", "openidx")
	if link != "" {
		req.Header.Set("X-Click", sanitizeNtfyHeader(link))
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy publish: HTTP %d", resp.StatusCode)
	}
	return nil
}

func sanitizeNtfyHeader(v string) string {
	v = strings.ReplaceAll(v, "\r\n", " ")
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", " "), "\r", " ")
}

// maybePush delivers a notification over the push channel if it is enabled
// and the user has not disabled push for this event type. Runs synchronously
// with a short timeout inside a goroutine started by the caller.
func (s *Service) maybePush(userID, notifType, title, body, link string) {
	if s.ntfy == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !s.isNotificationEnabled(ctx, userID, "push", notifType) {
		return
	}
	if err := s.ntfy.publish(ctx, userID, title, body, link); err != nil {
		s.logger.Warn("ntfy push failed (best-effort)", zap.Error(err))
	}
}

// handleGetPushConfig returns the calling user's push subscription details:
// the ntfy server URL and their private topic. The topic is a capability —
// it is derived from the caller's own user id and never anyone else's.
func (s *Service) handleGetPushConfig(c *gin.Context) {
	if s.ntfy == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":  true,
		"base_url": s.ntfy.base,
		"topic":    s.ntfy.topicFor(userID),
	})
}
