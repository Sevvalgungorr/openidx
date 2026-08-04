// Package identity - QR-based self-enrollment for the push authenticator.
//
// This is the "scan a QR and register this phone" flow, the way Microsoft /
// Google Authenticator bind a device. The signed-in user (admin console or the
// mobile app's account screen) asks the server for a short-lived enrollment
// ticket; the server returns a QR payload. The authenticator app scans it and
// posts its own push token back with the ticket, and the server binds that
// device to the user — no separate mobile login required, because possession of
// the freshly-minted, single-use, short-TTL ticket (shown only on the already-
// authenticated user's screen) is the proof.
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"

	"go.uber.org/zap"
)

// pushEnrollTTL is how long an enrollment ticket is valid. Short by design: the
// user scans it within a minute or two, and a stale ticket must not linger as a
// bindable credential.
const pushEnrollTTL = 5 * time.Minute

// pushEnrollKeyPrefix namespaces the Redis ticket keys.
const pushEnrollKeyPrefix = "push_enroll:"

// PushEnrollmentTicket is what StartPushEnrollment returns. QRPayload is the
// string the console renders as a QR code; the authenticator scans it, reads the
// enrollment_token, and calls CompletePushEnrollment.
type PushEnrollmentTicket struct {
	EnrollmentToken string `json:"enrollment_token"`
	ExpiresInSecond int    `json:"expires_in"`
	QRPayload       string `json:"qr_payload"`
}

// pushEnrollTicketData is the JSON stored in Redis against the ticket token.
type pushEnrollTicketData struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
}

// pushEnrollQRPayload is the JSON encoded into the QR the phone scans. The app
// recognizes type "openidx-push-enroll", connects to api_base, and completes
// enrollment with token. account is a human label for the confirmation screen.
type pushEnrollQRPayload struct {
	Type    string `json:"type"`
	APIBase string `json:"api_base"`
	Token   string `json:"token"`
	Account string `json:"account"`
	Issuer  string `json:"issuer"`
}

// StartPushEnrollment mints a single-use, short-lived enrollment ticket for the
// authenticated user and returns the QR payload the authenticator app scans.
func (s *Service) StartPushEnrollment(ctx context.Context, userID string) (*PushEnrollmentTicket, error) {
	if s.redis == nil {
		return nil, fmt.Errorf("enrollment temporarily unavailable")
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Resolve a friendly account label (email/username) for the QR/confirmation.
	var account string
	_ = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(NULLIF(email,''), username, $1) FROM users WHERE id = $1 AND org_id = $2`,
		userID, org.ID).Scan(&account)
	if account == "" {
		account = userID
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	data, err := json.Marshal(pushEnrollTicketData{UserID: userID, OrgID: org.ID})
	if err != nil {
		return nil, err
	}
	if err := s.redis.Client.Set(ctx, pushEnrollKeyPrefix+token, string(data), pushEnrollTTL).Err(); err != nil {
		return nil, fmt.Errorf("failed to store enrollment ticket: %w", err)
	}

	apiBase := s.cfg.OAuthIssuer
	if apiBase == "" {
		apiBase = "https://openidx.tdv.org"
	}
	payload, _ := json.Marshal(pushEnrollQRPayload{
		Type:    "openidx-push-enroll",
		APIBase: apiBase,
		Token:   token,
		Account: account,
		Issuer:  "OpenIDX",
	})

	return &PushEnrollmentTicket{
		EnrollmentToken: token,
		ExpiresInSecond: int(pushEnrollTTL.Seconds()),
		QRPayload:       string(payload),
	}, nil
}

// CompletePushEnrollment validates an enrollment ticket and binds the presented
// device to the ticket's user. The ticket is consumed (single-use). The caller
// need not be authenticated as the user — the ticket is the authorization — but
// the org context must match the ticket's org so a ticket minted for one tenant
// cannot register a device under another.
func (s *Service) CompletePushEnrollment(ctx context.Context, token string, enrollment *PushMFAEnrollment, ipAddress string) (*PushMFADevice, error) {
	if s.redis == nil {
		return nil, fmt.Errorf("enrollment temporarily unavailable")
	}
	if token == "" {
		return nil, fmt.Errorf("enrollment token is required")
	}

	key := pushEnrollKeyPrefix + token
	raw, err := s.redis.Client.Get(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("enrollment ticket is invalid or expired")
	}

	var ticket pushEnrollTicketData
	if err := json.Unmarshal([]byte(raw), &ticket); err != nil {
		return nil, fmt.Errorf("enrollment ticket is invalid or expired")
	}

	// The request context must be scoped to the same org the ticket was minted
	// for; otherwise the RLS-scoped device insert would land in the wrong tenant
	// (or be blocked). This keeps enrollment tenant-safe.
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	if ticket.OrgID != "" && ticket.OrgID != org.ID {
		return nil, fmt.Errorf("enrollment ticket does not match this organization")
	}

	// Consume the ticket first (single-use) so a replay can't double-register.
	if delErr := s.redis.Client.Del(ctx, key).Err(); delErr != nil {
		s.logger.Warn("failed to delete consumed push enrollment ticket", zap.Error(delErr))
	}

	device, err := s.RegisterPushMFADevice(ctx, ticket.UserID, enrollment, ipAddress)
	if err != nil {
		return nil, err
	}
	return device, nil
}
