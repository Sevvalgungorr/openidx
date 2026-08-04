// Package identity - self-hosted ntfy delivery for push-MFA challenges.
//
// The mobile app already subscribes to a per-user ntfy topic for general
// notifications (see internal/notifications/ntfy.go + mobile
// features/notifications/push.ts). Delivering the MFA approval prompt over the
// SAME topic means push approvals arrive in real time on the phone with zero
// Google/Apple push dependency — consistent with the platform's "no FCM/APNs in
// the path" design, and testable end to end today.
//
// This mirrors the notifications service's topic derivation exactly
// (oidx-<hmac-sha256(secret,userID)[:32]>) so identity and notifications publish
// to the same topic without sharing a struct. FCM/APNs remain the delivery path
// for devices that registered a real provider token; ntfy is the always-on
// fallback.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ntfyChallengeTopic derives the user's stable ntfy topic. Must match
// internal/notifications/ntfy.go topicFor.
func ntfyChallengeTopic(secret []byte, userID string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(userID))
	return "oidx-" + hex.EncodeToString(mac.Sum(nil))[:32]
}

// sanitizeNtfyHeader strips CR/LF so a value can't smuggle extra ntfy headers.
func sanitizeNtfyHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return strings.TrimSpace(v)
}

// publishChallengeToNtfy sends the approval prompt to the user's ntfy topic with
// a deep link the app opens straight into the approve screen. Best-effort: a
// failure is logged, never fatal to challenge creation (the in-app poll still
// works). Returns false when ntfy is not configured so the caller can log why.
func (s *Service) publishChallengeToNtfy(ctx context.Context, challenge *PushMFAChallenge) bool {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.NtfyBaseURL), "/")
	secret := strings.TrimSpace(s.cfg.NtfyTopicSecret)
	if base == "" || secret == "" {
		return false
	}

	topic := ntfyChallengeTopic([]byte(secret), challenge.UserID)
	appName := ""
	if challenge.SessionInfo != nil {
		if v, ok := challenge.SessionInfo["app_name"].(string); ok {
			appName = v
		}
	}
	body := "Approve or deny this sign-in"
	if appName != "" {
		body = "Approve or deny sign-in to " + appName
	}
	if challenge.Location != "" {
		body += " from " + challenge.Location
	}
	// Deep link straight into the approval screen.
	link := "openidx://approve/" + challenge.ID

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+topic, strings.NewReader(body))
	if err != nil {
		s.logger.Warn("ntfy challenge publish: build request failed", zap.Error(err))
		return false
	}
	req.Header.Set("Title", sanitizeNtfyHeader("Authentication request"))
	req.Header.Set("X-Tags", "warning,openidx")
	req.Header.Set("X-Priority", "high")
	req.Header.Set("X-Click", sanitizeNtfyHeader(link))
	if tok := strings.TrimSpace(s.cfg.NtfyToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Warn("ntfy challenge publish failed", zap.String("challenge_id", challenge.ID), zap.Error(err))
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Warn("ntfy challenge publish non-2xx",
			zap.String("challenge_id", challenge.ID), zap.Int("status", resp.StatusCode))
		return false
	}
	return true
}
