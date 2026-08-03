// Package identity - WebAuthn (FIDO2/Passkey) implementation
package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// WebAuthnCredential represents a registered WebAuthn credential
type WebAuthnCredential struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	CredentialID      string     `json:"credential_id"` // Base64URL encoded
	PublicKey         string     `json:"-"`             // COSE encoded public key (sensitive)
	SignCount         uint32     `json:"sign_count"`
	AAGUID            string     `json:"aaguid,omitempty"`
	Transports        []string   `json:"transports,omitempty"`
	Name              string     `json:"name"`
	BackupEligible    bool       `json:"backup_eligible"`
	BackupState       bool       `json:"backup_state"`
	AttestationFormat string     `json:"attestation_format,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
}

// WebAuthnUser implements the webauthn.User interface
type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user ID as bytes
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the username
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the display name
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon returns the user icon (deprecated in WebAuthn Level 2)
func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns the user's credentials
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// BeginWebAuthnRegistration initiates WebAuthn registration
func (s *Service) BeginWebAuthnRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error) {
	// Get user from database
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get existing credentials
	existingCreds, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing credentials: %w", err)
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credID, _ := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		pubKey := []byte(cred.PublicKey)

		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:              credID,
			PublicKey:       pubKey,
			AttestationType: cred.AttestationFormat,
			Transport:       convertTransports(cred.Transports),
			Flags: webauthn.CredentialFlags{
				BackupEligible: cred.BackupEligible,
				BackupState:    cred.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    []byte(cred.AAGUID),
				SignCount: cred.SignCount,
			},
		})
	}

	// Create WebAuthn user
	userIDBytes, _ := uuid.Parse(userID)
	webauthnUser := &WebAuthnUser{
		ID:          userIDBytes[:],
		Name:        user.UserName,
		DisplayName: fmt.Sprintf("%s %s", user.GetFirstName(), user.GetLastName()),
		Credentials: webauthnCreds,
	}

	// Initialize WebAuthn
	webAuthn, err := s.getWebAuthnInstance()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	// Begin registration
	options, sessionData, err := webAuthn.BeginRegistration(webauthnUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store session data temporarily (in production, use Redis)
	sessionJSON, _ := json.Marshal(sessionData)
	s.storeWebAuthnSession(ctx, userID, "registration", string(sessionJSON))

	s.logger.Info("WebAuthn registration initiated",
		zap.String("user_id", userID),
		zap.String("username", user.UserName))

	return options, nil
}

// FinishWebAuthnRegistration completes WebAuthn registration
func (s *Service) FinishWebAuthnRegistration(ctx context.Context, userID string, credentialName string, response *protocol.ParsedCredentialCreationData) (*WebAuthnCredential, error) {
	// Get user from database
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get stored session data
	sessionDataJSON, err := s.getWebAuthnSession(ctx, userID, "registration")
	if err != nil {
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionDataJSON), &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Get existing credentials
	existingCreds, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing credentials: %w", err)
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credID, _ := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		pubKey := []byte(cred.PublicKey)

		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
		})
	}

	// Create WebAuthn user
	userIDBytes, _ := uuid.Parse(userID)
	webauthnUser := &WebAuthnUser{
		ID:          userIDBytes[:],
		Name:        user.UserName,
		DisplayName: fmt.Sprintf("%s %s", user.GetFirstName(), user.GetLastName()),
		Credentials: webauthnCreds,
	}

	// Initialize WebAuthn
	webAuthn, err := s.getWebAuthnInstance()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	// Verify registration
	credential, err := webAuthn.CreateCredential(webauthnUser, sessionData, response)
	if err != nil {
		s.logger.Error("WebAuthn registration verification failed",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to verify registration: %w", err)
	}

	// Store credential in database
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	publicKey := string(credential.PublicKey)
	aaguidStr := base64.RawURLEncoding.EncodeToString(credential.Authenticator.AAGUID)

	// Set default name if not provided
	if credentialName == "" {
		credentialName = fmt.Sprintf("Passkey %d", len(existingCreds)+1)
	}

	newCred := &WebAuthnCredential{
		ID:                uuid.New().String(),
		UserID:            userID,
		CredentialID:      credentialID,
		PublicKey:         publicKey,
		SignCount:         credential.Authenticator.SignCount,
		AAGUID:            aaguidStr,
		Transports:        convertTransportsToStrings(credential.Transport),
		Name:              credentialName,
		BackupEligible:    credential.Flags.BackupEligible,
		BackupState:       credential.Flags.BackupState,
		AttestationFormat: credential.AttestationType,
		CreatedAt:         time.Now(),
	}

	if err := s.storeWebAuthnCredential(ctx, newCred); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	// Clean up session data
	s.deleteWebAuthnSession(ctx, userID, "registration")

	s.logger.Info("WebAuthn credential registered",
		zap.String("user_id", userID),
		zap.String("credential_id", credentialID),
		zap.String("name", credentialName))

	return newCred, nil
}

// BeginWebAuthnAuthentication initiates WebAuthn authentication
func (s *Service) BeginWebAuthnAuthentication(ctx context.Context, username string) (*protocol.CredentialAssertion, error) {
	// Scope by org: the login page is served on a tenant subdomain, so the
	// resolver has attached the org. Usernames are unique per org, so the org
	// filter is both the isolation boundary and (under RLS) the visibility key.
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	// Get user by username
	query := `SELECT id, username, email, first_name, last_name FROM users WHERE username = $1 AND org_id = $2 AND enabled = true`
	var userID, uname, email, firstName, lastName string
	err = s.db.Pool.QueryRow(ctx, query, username, org.ID).Scan(&userID, &uname, &email, &firstName, &lastName)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Get credentials
	credentials, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no WebAuthn credentials registered for user")
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, 0, len(credentials))
	for _, cred := range credentials {
		credID, _ := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		pubKey := []byte(cred.PublicKey)

		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: cred.SignCount,
			},
		})
	}

	// Create WebAuthn user
	userIDBytes, _ := uuid.Parse(userID)
	webauthnUser := &WebAuthnUser{
		ID:          userIDBytes[:],
		Name:        uname,
		DisplayName: fmt.Sprintf("%s %s", firstName, lastName),
		Credentials: webauthnCreds,
	}

	// Initialize WebAuthn
	webAuthn, err := s.getWebAuthnInstance()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	// Begin authentication
	options, sessionData, err := webAuthn.BeginLogin(webauthnUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin authentication: %w", err)
	}

	// Store session data
	sessionJSON, _ := json.Marshal(sessionData)
	s.storeWebAuthnSession(ctx, userID, "authentication", string(sessionJSON))

	s.logger.Info("WebAuthn authentication initiated",
		zap.String("user_id", userID),
		zap.String("username", username))

	return options, nil
}

// FinishWebAuthnAuthentication completes WebAuthn authentication
func (s *Service) FinishWebAuthnAuthentication(ctx context.Context, username string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	// Scope by org (see BeginWebAuthnAuthentication).
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	// Get user by username
	query := `SELECT id, username, email, first_name, last_name FROM users WHERE username = $1 AND org_id = $2 AND enabled = true`
	var userID, uname, email, firstName, lastName string
	err = s.db.Pool.QueryRow(ctx, query, username, org.ID).Scan(&userID, &uname, &email, &firstName, &lastName)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	// Get stored session data
	sessionDataJSON, err := s.getWebAuthnSession(ctx, userID, "authentication")
	if err != nil {
		return "", fmt.Errorf("failed to get session data: %w", err)
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionDataJSON), &sessionData); err != nil {
		return "", fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Get credentials
	credentials, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get credentials: %w", err)
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, 0, len(credentials))
	for _, cred := range credentials {
		credID, _ := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		pubKey := []byte(cred.PublicKey)

		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: cred.SignCount,
			},
		})
	}

	// Create WebAuthn user
	userIDBytes, _ := uuid.Parse(userID)
	webauthnUser := &WebAuthnUser{
		ID:          userIDBytes[:],
		Name:        uname,
		DisplayName: fmt.Sprintf("%s %s", firstName, lastName),
		Credentials: webauthnCreds,
	}

	// Initialize WebAuthn
	webAuthn, err := s.getWebAuthnInstance()
	if err != nil {
		return "", fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	// Verify authentication
	credential, err := webAuthn.ValidateLogin(webauthnUser, sessionData, response)
	if err != nil {
		s.logger.Error("WebAuthn authentication verification failed",
			zap.String("user_id", userID),
			zap.Error(err))
		return "", fmt.Errorf("failed to verify authentication: %w", err)
	}

	// Update sign count and last used time
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	if err := s.updateWebAuthnCredential(ctx, userID, credentialID, credential.Authenticator.SignCount); err != nil {
		s.logger.Warn("Failed to update credential sign count",
			zap.String("user_id", userID),
			zap.String("credential_id", credentialID),
			zap.Error(err))
	}

	// Clean up session data
	s.deleteWebAuthnSession(ctx, userID, "authentication")

	s.logger.Info("WebAuthn authentication successful",
		zap.String("user_id", userID),
		zap.String("username", username),
		zap.String("credential_id", credentialID))

	return userID, nil
}

// BeginWebAuthnDiscoverableAuthentication begins a discoverable credential (resident key) assertion.
// No username is required — the browser selects the credential via user interaction.
func (s *Service) BeginWebAuthnDiscoverableAuthentication(ctx context.Context) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	webAuthn, err := s.getWebAuthnInstance()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	options, sessionData, err := webAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin discoverable login: %w", err)
	}

	s.logger.Info("WebAuthn discoverable authentication initiated")
	return options, sessionData, nil
}

// FinishWebAuthnDiscoverableAuthentication completes a discoverable credential assertion.
// The userHandle from the assertion response is used to look up the user and their credentials.
func (s *Service) FinishWebAuthnDiscoverableAuthentication(ctx context.Context, sessionData *webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (string, error) {
	webAuthn, err := s.getWebAuthnInstance()
	if err != nil {
		return "", fmt.Errorf("failed to initialize WebAuthn: %w", err)
	}

	// The user handle from the assertion contains the user ID
	userHandle := response.Response.UserHandle
	if len(userHandle) == 0 {
		return "", fmt.Errorf("no user handle in assertion response")
	}

	// Parse user ID from the handle (UUID bytes)
	userUUID, err := uuid.FromBytes(userHandle)
	if err != nil {
		return "", fmt.Errorf("invalid user handle format: %w", err)
	}
	userID := userUUID.String()

	// Get user info
	query := `SELECT id, username, first_name, last_name FROM users WHERE id = $1 AND enabled = true`
	var uid, uname, firstName, lastName string
	if err := s.db.Pool.QueryRow(ctx, query, userID).Scan(&uid, &uname, &firstName, &lastName); err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	// Get credentials for the user
	credentials, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get credentials: %w", err)
	}

	webauthnCreds := make([]webauthn.Credential, 0, len(credentials))
	for _, cred := range credentials {
		credID, _ := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		pubKey := []byte(cred.PublicKey)
		webauthnCreds = append(webauthnCreds, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: cred.SignCount,
			},
		})
	}

	userIDBytes, _ := uuid.Parse(userID)
	webauthnUser := &WebAuthnUser{
		ID:          userIDBytes[:],
		Name:        uname,
		DisplayName: fmt.Sprintf("%s %s", firstName, lastName),
		Credentials: webauthnCreds,
	}

	// Handler for discoverable login: given a raw user handle, return the user
	discoverableUserHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		return webauthnUser, nil
	}

	credential, err := webAuthn.ValidateDiscoverableLogin(discoverableUserHandler, *sessionData, response)
	if err != nil {
		s.logger.Error("WebAuthn discoverable authentication failed", zap.String("user_id", userID), zap.Error(err))
		return "", fmt.Errorf("failed to verify authentication: %w", err)
	}

	// Update sign count
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	if err := s.updateWebAuthnCredential(ctx, userID, credentialID, credential.Authenticator.SignCount); err != nil {
		s.logger.Warn("Failed to update credential sign count", zap.String("user_id", userID), zap.Error(err))
	}

	s.logger.Info("WebAuthn discoverable authentication successful",
		zap.String("user_id", userID),
		zap.String("username", uname),
		zap.String("credential_id", credentialID))

	return userID, nil
}

// GetWebAuthnCredentials returns all WebAuthn credentials for a user
func (s *Service) GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	return s.getWebAuthnCredentials(ctx, userID)
}

// DeleteWebAuthnCredential removes a WebAuthn credential
func (s *Service) DeleteWebAuthnCredential(ctx context.Context, userID, credentialID string) error {
	query := `DELETE FROM mfa_webauthn WHERE user_id = $1 AND id = $2`
	result, err := s.db.Pool.Exec(ctx, query, userID, credentialID)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("credential not found")
	}

	s.logger.Info("WebAuthn credential deleted",
		zap.String("user_id", userID),
		zap.String("credential_id", credentialID))

	return nil
}

// Helper functions

func (s *Service) getWebAuthnInstance() (*webauthn.WebAuthn, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: "OpenIDX",
		RPID:          s.cfg.WebAuthn.RPID,
		RPOrigins:     s.cfg.WebAuthn.RPOrigins,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Duration(s.cfg.WebAuthn.Timeout) * time.Second,
				TimeoutUVD: time.Duration(s.cfg.WebAuthn.Timeout) * time.Second,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Duration(s.cfg.WebAuthn.Timeout) * time.Second,
				TimeoutUVD: time.Duration(s.cfg.WebAuthn.Timeout) * time.Second,
			},
		},
	}

	return webauthn.New(wconfig)
}

func (s *Service) getWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	query := `
		SELECT id, user_id, credential_id, public_key, sign_count, aaguid, transports,
		       name, backup_eligible, backup_state, attestation_format, created_at, last_used_at
		FROM mfa_webauthn
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var credentials []WebAuthnCredential
	for rows.Next() {
		var cred WebAuthnCredential
		var transports []string
		var lastUsedAt *time.Time

		err := rows.Scan(
			&cred.ID,
			&cred.UserID,
			&cred.CredentialID,
			&cred.PublicKey,
			&cred.SignCount,
			&cred.AAGUID,
			&transports,
			&cred.Name,
			&cred.BackupEligible,
			&cred.BackupState,
			&cred.AttestationFormat,
			&cred.CreatedAt,
			&lastUsedAt,
		)
		if err != nil {
			return nil, err
		}

		cred.Transports = transports
		cred.LastUsedAt = lastUsedAt
		credentials = append(credentials, cred)
	}

	return credentials, nil
}

func (s *Service) storeWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error {
	// mfa_webauthn.org_id is NOT NULL. Omitting it made every registration's
	// final INSERT fail, surfacing to the user as a 500 "finish web authn
	// registration" after the browser had already created the passkey.
	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required to store webauthn credential: %w", err)
	}

	query := `
		INSERT INTO mfa_webauthn
		(id, user_id, credential_id, public_key, sign_count, aaguid, transports,
		 name, backup_eligible, backup_state, attestation_format, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err = s.db.Pool.Exec(ctx, query,
		cred.ID,
		cred.UserID,
		cred.CredentialID,
		cred.PublicKey,
		cred.SignCount,
		cred.AAGUID,
		cred.Transports,
		cred.Name,
		cred.BackupEligible,
		cred.BackupState,
		cred.AttestationFormat,
		cred.CreatedAt,
		org.ID,
	)

	return err
}

func (s *Service) updateWebAuthnCredential(ctx context.Context, userID, credentialID string, signCount uint32) error {
	query := `
		UPDATE mfa_webauthn
		SET sign_count = $1, last_used_at = $2
		WHERE user_id = $3 AND credential_id = $4
	`

	_, err := s.db.Pool.Exec(ctx, query, signCount, time.Now(), userID, credentialID)
	return err
}

func (s *Service) storeWebAuthnSession(ctx context.Context, userID, sessionType, data string) {
	// In production, store in Redis with TTL
	// For now, store in memory (not production-ready)
	s.webauthnSessions.Store(userID+":"+sessionType, data)
}

func (s *Service) getWebAuthnSession(ctx context.Context, userID, sessionType string) (string, error) {
	// In production, get from Redis
	data, ok := s.webauthnSessions.Load(userID + ":" + sessionType)
	if !ok {
		return "", fmt.Errorf("session not found")
	}
	return data.(string), nil
}

func (s *Service) deleteWebAuthnSession(ctx context.Context, userID, sessionType string) {
	// In production, delete from Redis
	s.webauthnSessions.Delete(userID + ":" + sessionType)
}

func convertTransports(transports []string) []protocol.AuthenticatorTransport {
	result := make([]protocol.AuthenticatorTransport, 0, len(transports))
	for _, t := range transports {
		result = append(result, protocol.AuthenticatorTransport(t))
	}
	return result
}

func convertTransportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	result := make([]string, 0, len(transports))
	for _, t := range transports {
		result = append(result, string(t))
	}
	return result
}
