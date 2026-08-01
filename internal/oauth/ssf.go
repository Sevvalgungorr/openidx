package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Shared Signals Framework (SSF) + Continuous Access Evaluation Profile (CAEP).
//
// This file builds and signs Security Event Tokens (SETs, RFC 8417) carrying
// CAEP/RISC events, and manages the transmitter's stream store + outbox. The
// push worker and HTTP surface live in ssf_transmitter.go; the receiver in
// ssf_receiver.go.

// CAEP / RISC event type URIs (OpenID Shared Signals).
const (
	EventSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCredentialChange       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTokenClaimsChange      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	EventAccountDisabled        = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventAccountPurged          = "https://schemas.openid.net/secevent/risc/event-type/account-purged"

	// setContentType is the media type SETs are delivered as (RFC 8935).
	setContentType = "application/secevent+jwt"
)

// SSFStream is a configured transmitter push stream.
type SSFStream struct {
	ID               string    `json:"stream_id"`
	OrgID            string    `json:"-"`
	Description      string    `json:"description,omitempty"`
	Audience         string    `json:"aud"`
	DeliveryEndpoint string    `json:"-"`
	EventsRequested  []string  `json:"events_requested"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"-"`
	UpdatedAt        time.Time `json:"-"`
	// Delivery is the SSF delivery method descriptor returned in the config.
	Delivery map[string]interface{} `json:"delivery,omitempty"`
}

// SSFStreamInput is the create/update payload.
type SSFStreamInput struct {
	Description      string   `json:"description,omitempty"`
	Audience         string   `json:"aud"`
	DeliveryEndpoint string   `json:"delivery_endpoint"`
	DeliveryAuth     string   `json:"delivery_auth,omitempty"`
	EventsRequested  []string `json:"events_requested,omitempty"`
	Status           string   `json:"status,omitempty"`
}

// caepSubject is the SET subject identifier (subject_type=email/iss_sub/opaque).
func caepSubjectEmail(email string) map[string]interface{} {
	return map[string]interface{}{"format": "email", "email": email}
}

func caepSubjectOpaque(id string) map[string]interface{} {
	return map[string]interface{}{"format": "opaque", "id": id}
}

// BuildSET constructs and signs a SET (RFC 8417) for a single CAEP/RISC event.
// eventClaims is the event-type-specific payload (may be nil/empty). Returns the
// compact JWS and its jti.
func (s *Service) BuildSET(audience, eventType, subjectEmail, subjectID string, eventClaims map[string]interface{}) (setJWT, jti string, err error) {
	now := time.Now()
	jti = uuid.NewString()

	subject := caepSubjectOpaque(subjectID)
	if subjectEmail != "" {
		subject = caepSubjectEmail(subjectEmail)
	}

	event := map[string]interface{}{
		"subject":         subject,
		"event_timestamp": now.Unix(),
	}
	for k, v := range eventClaims {
		event[k] = v
	}

	claims := jwt.MapClaims{
		"iss": s.issuer,
		"jti": jti,
		"iat": now.Unix(),
		"aud": audience,
		"events": map[string]interface{}{
			eventType: event,
		},
	}

	kid, signKey := s.signingKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = "secevent+jwt"
	setJWT, err = tok.SignedString(signKey)
	if err != nil {
		return "", "", fmt.Errorf("sign SET: %w", err)
	}
	return setJWT, jti, nil
}

// --- Stream store ---

func (s *Service) ssfEncrypt(plaintext string) (string, error) {
	if plaintext == "" || s.idpCipher == nil {
		return plaintext, nil
	}
	return s.idpCipher.Encrypt(plaintext)
}

func (s *Service) ssfDecrypt(stored string) (string, error) {
	if stored == "" || s.idpCipher == nil {
		return stored, nil
	}
	return s.idpCipher.Decrypt(stored)
}

func validSSFStatus(st string) bool {
	return st == "enabled" || st == "paused" || st == "disabled"
}

// errSSFNoOrg is returned when a stream operation is attempted without a
// resolved tenant. SSF streams carry a delivery_endpoint that receives this
// tenant's security events, so an unscoped operation is never legitimate —
// these helpers fail closed rather than falling back to a global scope.
var errSSFNoOrg = fmt.Errorf("organization context required")

// CreateSSFStream persists a transmitter stream.
func (s *Service) CreateSSFStream(ctx context.Context, orgID string, in *SSFStreamInput) (*SSFStream, error) {
	if orgID == "" {
		return nil, errSSFNoOrg
	}
	if in.Audience == "" || in.DeliveryEndpoint == "" {
		return nil, fmt.Errorf("aud and delivery_endpoint are required")
	}
	if in.Status == "" {
		in.Status = "enabled"
	}
	if !validSSFStatus(in.Status) {
		return nil, fmt.Errorf("invalid status %q (want enabled|paused|disabled)", in.Status)
	}
	events := in.EventsRequested
	if events == nil {
		events = []string{}
	}
	eventsJSON, _ := json.Marshal(events)
	authEnc, err := s.ssfEncrypt(in.DeliveryAuth)
	if err != nil {
		return nil, fmt.Errorf("encrypt delivery auth: %w", err)
	}
	id := uuid.NewString()
	_, err = s.db.Pool.Exec(ctx, `
        INSERT INTO ssf_streams
            (id, org_id, description, audience, delivery_endpoint, delivery_auth_enc, events_requested, status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, orgID, ssfNullIfEmpty(in.Description), in.Audience,
		in.DeliveryEndpoint, authEnc, string(eventsJSON), in.Status)
	if err != nil {
		return nil, fmt.Errorf("insert ssf stream: %w", err)
	}
	return s.GetSSFStream(ctx, orgID, id)
}

// GetSSFStream loads a stream (delivery auth never returned).
func (s *Service) GetSSFStream(ctx context.Context, orgID, id string) (*SSFStream, error) {
	if orgID == "" {
		return nil, errSSFNoOrg
	}
	row := s.db.Pool.QueryRow(ctx, `
        SELECT id, COALESCE(org_id::text,''), COALESCE(description,''), audience,
               delivery_endpoint, COALESCE(events_requested,'[]'::jsonb), status,
               created_at, updated_at
          FROM ssf_streams WHERE id=$1 AND org_id::text=$2`, id, orgID)
	return scanSSFStream(row)
}

// ListSSFStreams lists streams for an org.
func (s *Service) ListSSFStreams(ctx context.Context, orgID string) ([]SSFStream, error) {
	if orgID == "" {
		return nil, errSSFNoOrg
	}
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id, COALESCE(org_id::text,''), COALESCE(description,''), audience,
               delivery_endpoint, COALESCE(events_requested,'[]'::jsonb), status,
               created_at, updated_at
          FROM ssf_streams WHERE org_id::text=$1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSFStream
	for rows.Next() {
		st, err := scanSSFStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

// DeleteSSFStream removes a stream (+ its outbox via CASCADE).
func (s *Service) DeleteSSFStream(ctx context.Context, orgID, id string) error {
	if orgID == "" {
		return errSSFNoOrg
	}
	ct, err := s.db.Pool.Exec(ctx,
		`DELETE FROM ssf_streams WHERE id=$1 AND org_id::text=$2`, id, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("stream not found")
	}
	return nil
}

// --- helpers ---

func ssfNullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

type ssfRowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSSFStream(row ssfRowScanner) (*SSFStream, error) {
	var st SSFStream
	var events []byte
	if err := row.Scan(&st.ID, &st.OrgID, &st.Description, &st.Audience,
		&st.DeliveryEndpoint, &events, &st.Status, &st.CreatedAt, &st.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(events, &st.EventsRequested)
	if st.EventsRequested == nil {
		st.EventsRequested = []string{}
	}
	st.Delivery = map[string]interface{}{
		"method":       "https://schemas.openid.net/secevent/risc/delivery-method/push",
		"endpoint_url": st.DeliveryEndpoint,
	}
	return &st, nil
}
