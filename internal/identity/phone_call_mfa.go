// Package identity - Phone Call Verification MFA
package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// PhoneCallEnrollment represents a phone call MFA enrollment
type PhoneCallEnrollment struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	PhoneNumber   string     `json:"phone_number"`
	CountryCode   string     `json:"country_code"`
	Verified      bool       `json:"verified"`
	Enabled       bool       `json:"enabled"`
	VoiceLanguage string     `json:"voice_language"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

// PhoneCallChallenge represents an active phone call verification
type PhoneCallChallenge struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	PhoneNumber string     `json:"phone_number"`
	CallType    string     `json:"call_type"` // outbound, callback
	CallSID     string     `json:"call_sid,omitempty"`
	Status      string     `json:"status"` // pending, calling, answered, completed, failed
	Attempts    int        `json:"attempts"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
}

// PhoneCallProvider interface for voice call services
type PhoneCallProvider interface {
	InitiateCall(phoneNumber, code, language string) (callSID string, err error)
	GetCallStatus(callSID string) (status string, err error)
}

// EnrollPhoneCall starts phone call MFA enrollment
func (s *Service) EnrollPhoneCall(ctx context.Context, userID, phoneNumber, countryCode string) (*PhoneCallChallenge, error) {
	// Format phone number
	fullNumber := countryCode + phoneNumber

	// Check if already enrolled
	var existing string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT id FROM mfa_phone_call WHERE user_id = $1", userID,
	).Scan(&existing)
	if err == nil {
		// Update existing enrollment
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE mfa_phone_call
			SET phone_number = $1, country_code = $2, verified = false
			WHERE user_id = $3`,
			phoneNumber, countryCode, userID,
		)
		if err != nil {
			return nil, err
		}
	} else {
		// Create new enrollment
		_, err = s.db.Pool.Exec(ctx,
			`INSERT INTO mfa_phone_call (id, user_id, phone_number, country_code, verified, enabled, voice_language, created_at)
			VALUES ($1, $2, $3, $4, false, true, 'en-US', NOW())`,
			uuid.New().String(), userID, phoneNumber, countryCode,
		)
		if err != nil {
			return nil, err
		}
	}

	// Create verification challenge
	return s.CreatePhoneCallChallenge(ctx, userID, fullNumber, "outbound")
}

// CreatePhoneCallChallenge creates a phone call challenge and initiates the call
func (s *Service) CreatePhoneCallChallenge(ctx context.Context, userID, phoneNumber, callType string) (*PhoneCallChallenge, error) {
	// Generate 6-digit code
	code, err := generateSecureCode(6)
	if err != nil {
		return nil, err
	}

	// Hash the code
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcryptCost)
	if err != nil {
		return nil, err
	}

	challengeID := uuid.New().String()
	expiresAt := time.Now().Add(5 * time.Minute)

	// Store challenge
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO phone_call_challenges
		(id, user_id, phone_number, code_hash, call_type, status, attempts, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', 0, NOW(), $6)`,
		challengeID, userID, phoneNumber, string(codeHash), callType, expiresAt,
	)
	if err != nil {
		return nil, err
	}

	// Initiate the call (if provider is configured)
	var callSID string
	if s.phoneCallProvider != nil {
		callSID, err = s.phoneCallProvider.InitiateCall(phoneNumber, code, "en-US")
		if err != nil {
			// Update status to failed
			s.db.Pool.Exec(ctx,
				"UPDATE phone_call_challenges SET status = 'failed' WHERE id = $1",
				challengeID,
			)
			return nil, fmt.Errorf("failed to initiate call: %w", err)
		}

		// Update with call SID
		s.db.Pool.Exec(ctx,
			"UPDATE phone_call_challenges SET call_sid = $1, status = 'calling' WHERE id = $2",
			callSID, challengeID,
		)
	}

	return &PhoneCallChallenge{
		ID:          challengeID,
		UserID:      userID,
		PhoneNumber: maskPhoneNumber(phoneNumber),
		CallType:    callType,
		CallSID:     callSID,
		Status:      "calling",
		Attempts:    0,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}, nil
}

// VerifyPhoneCallChallenge verifies the code from a phone call
func (s *Service) VerifyPhoneCallChallenge(ctx context.Context, userID, code string) error {
	// Get active challenge
	var challengeID, codeHash string
	var attempts int
	var expiresAt time.Time

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, code_hash, attempts, expires_at FROM phone_call_challenges
		WHERE user_id = $1 AND status IN ('pending', 'calling', 'answered')
		ORDER BY created_at DESC LIMIT 1`,
		userID,
	).Scan(&challengeID, &codeHash, &attempts, &expiresAt)
	if err != nil {
		return errors.New("no active phone call challenge found")
	}

	// Check expiration
	if time.Now().After(expiresAt) {
		s.db.Pool.Exec(ctx, "UPDATE phone_call_challenges SET status = 'expired' WHERE id = $1", challengeID)
		return errors.New("challenge expired")
	}

	// Check max attempts
	if attempts >= 3 {
		s.db.Pool.Exec(ctx, "UPDATE phone_call_challenges SET status = 'failed' WHERE id = $1", challengeID)
		return errors.New("maximum attempts exceeded")
	}

	// Increment attempts
	s.db.Pool.Exec(ctx,
		"UPDATE phone_call_challenges SET attempts = attempts + 1 WHERE id = $1",
		challengeID,
	)

	// Verify code
	if err := bcrypt.CompareHashAndPassword([]byte(codeHash), []byte(code)); err != nil {
		return errors.New("invalid verification code")
	}

	// Mark challenge as completed
	s.db.Pool.Exec(ctx,
		"UPDATE phone_call_challenges SET status = 'completed', verified_at = NOW() WHERE id = $1",
		challengeID,
	)

	// Mark enrollment as verified
	s.db.Pool.Exec(ctx,
		"UPDATE mfa_phone_call SET verified = true, last_used_at = NOW() WHERE user_id = $1",
		userID,
	)

	return nil
}

// GetPhoneCallEnrollment returns the phone call enrollment for a user
func (s *Service) GetPhoneCallEnrollment(ctx context.Context, userID string) (*PhoneCallEnrollment, error) {
	query := `
		SELECT id, user_id, phone_number, country_code, verified, enabled, voice_language, created_at, last_used_at
		FROM mfa_phone_call
		WHERE user_id = $1
	`

	var e PhoneCallEnrollment
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&e.ID, &e.UserID, &e.PhoneNumber, &e.CountryCode, &e.Verified, &e.Enabled,
		&e.VoiceLanguage, &e.CreatedAt, &e.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}

	// Mask phone number
	e.PhoneNumber = maskPhoneNumber(e.CountryCode + e.PhoneNumber)

	return &e, nil
}

// DeletePhoneCallEnrollment removes phone call MFA
func (s *Service) DeletePhoneCallEnrollment(ctx context.Context, userID string) error {
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM mfa_phone_call WHERE user_id = $1", userID)
	return err
}

// RequestCallback initiates a callback verification (user calls system)
func (s *Service) RequestCallback(ctx context.Context, userID string) (*PhoneCallChallenge, error) {
	// Get user's enrolled phone
	var phoneNumber, countryCode string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT phone_number, country_code FROM mfa_phone_call WHERE user_id = $1 AND verified = true",
		userID,
	).Scan(&phoneNumber, &countryCode)
	if err != nil {
		return nil, errors.New("no verified phone number found")
	}

	return s.CreatePhoneCallChallenge(ctx, userID, countryCode+phoneNumber, "callback")
}

// generateSecureCode generates a cryptographically secure numeric code
func generateSecureCode(length int) (string, error) {
	const digits = "0123456789"
	code := make([]byte, length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[n.Int64()]
	}

	return string(code), nil
}

// maskPhoneNumber masks a phone number for display
func maskPhoneNumber(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	return phone[:len(phone)-4] + "****"
}

// TwilioPhoneCallProvider implements PhoneCallProvider for Twilio
type TwilioPhoneCallProvider struct {
	AccountSID string
	AuthToken  string
	FromNumber string
}

// InitiateCall makes a phone call via Twilio
func (t *TwilioPhoneCallProvider) InitiateCall(phoneNumber, code, language string) (string, error) {
	// In production, this would use Twilio's API to make a call
	// The TwiML would speak the verification code
	/*
		twiml := fmt.Sprintf(`
			<Response>
				<Say voice="alice" language="%s">
					Your verification code is: %s. I repeat: %s.
				</Say>
			</Response>
		`, language, formatCodeForSpeech(code), formatCodeForSpeech(code))
	*/

	// For now, return a mock call SID
	return "CALL_" + uuid.New().String()[:8], nil
}

// GetCallStatus gets the status of a Twilio call
func (t *TwilioPhoneCallProvider) GetCallStatus(callSID string) (string, error) {
	// In production, query Twilio API for call status
	return "completed", nil
}
