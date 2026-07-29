// Package oauth provides OAuth 2.0 and OpenID Connect provider functionality
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var (
	// ErrInvalidRequest is returned when the authorization request is malformed
	ErrInvalidRequest = errors.New("invalid_request")
	// ErrUnauthorizedClient is returned when the client is not authorized
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	// ErrAccessDenied is returned when access is denied
	ErrAccessDenied = errors.New("access_denied")
	// ErrUnsupportedResponseType is returned when response_type is not supported
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	// ErrInvalidScope is returned when scope is invalid
	ErrInvalidScope = errors.New("invalid_scope")
	// ErrServerError is returned for server errors
	ErrServerError = errors.New("server_error")
	// ErrInvalidPKCE is returned when PKCE validation fails
	ErrInvalidPKCE = errors.New("invalid_pkce")
)

// AuthorizeRequest represents an OAuth 2.0 authorization request with PKCE support
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizeHandler handles OAuth 2.0 authorization code flow with PKCE
type AuthorizeHandler struct {
	service *Service
	logger  *zap.Logger
}

// NewAuthorizeHandler creates a new authorization handler
func NewAuthorizeHandler(service *Service, logger *zap.Logger) *AuthorizeHandler {
	return &AuthorizeHandler{
		service: service,
		logger:  logger.With(zap.String("handler", "authorize")),
	}
}

// HandleAuthorizeRequest handles the OAuth 2.0 authorization endpoint
// Implements RFC 6749 (Authorization Code Flow) and RFC 7636 (PKCE)
func (h *AuthorizeHandler) HandleAuthorizeRequest(c *gin.Context) {
	ctx := c.Request.Context()

	// Parse authorization request
	req, err := h.parseAuthorizeRequest(c)
	if err != nil {
		h.handleError(c, req, ErrInvalidRequest, err.Error())
		return
	}

	// Validate the client and redirect URI
	client, err := h.service.GetClient(ctx, req.ClientID)
	if err != nil {
		h.logger.Warn("Failed to get client", zap.String("client_id", req.ClientID), zap.Error(err))
		h.handleError(c, req, ErrUnauthorizedClient, "Invalid client")
		return
	}

	// Validate redirect URI
	if !h.validateRedirectURI(client, req.RedirectURI) {
		h.logger.Warn("Invalid redirect URI",
			zap.String("client_id", req.ClientID),
			zap.String("redirect_uri", req.RedirectURI))
		h.handleError(c, req, ErrInvalidRequest, "Invalid redirect_uri")
		return
	}

	// Validate response type
	if !h.validateResponseType(client, req.ResponseType) {
		h.handleError(c, req, ErrUnsupportedResponseType, "response_type not supported")
		return
	}

	// Validate scope
	if !h.validateScope(client, req.Scope) {
		h.handleError(c, req, ErrInvalidScope, "Invalid scope")
		return
	}

	// Validate PKCE parameters
	if err := h.validatePKCEParameters(client, req); err != nil {
		h.logger.Warn("PKCE validation failed",
			zap.String("client_id", req.ClientID),
			zap.Error(err))
		h.handleError(c, req, ErrInvalidPKCE, err.Error())
		return
	}

	// Store authorization request for later use
	authSessionID := GenerateRandomToken(32)
	if err := h.storeAuthorizationRequest(ctx, authSessionID, req, client); err != nil {
		h.logger.Error("Failed to store authorization request", zap.Error(err))
		h.handleError(c, req, ErrServerError, "Failed to store request")
		return
	}

	// Check if user is authenticated (would be from session cookie)
	// For now, redirect to login
	h.redirectToLogin(c, req, authSessionID)
}

// parseAuthorizeRequest parses and validates the authorization request parameters
func (h *AuthorizeHandler) parseAuthorizeRequest(c *gin.Context) (*AuthorizeRequest, error) {
	req := &AuthorizeRequest{
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		ResponseType:        c.Query("response_type"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}

	// Validate required parameters
	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if req.RedirectURI == "" {
		return nil, fmt.Errorf("redirect_uri is required")
	}
	if req.ResponseType == "" {
		return nil, fmt.Errorf("response_type is required")
	}

	// Set default code challenge method to S256 if not specified
	if req.CodeChallenge != "" && req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = "plain"
	}

	return req, nil
}

// validateRedirectURI validates that the redirect URI is registered for the client
func (h *AuthorizeHandler) validateRedirectURI(client *OAuthClient, redirectURI string) bool {
	for _, registeredURI := range client.RedirectURIs {
		if registeredURI == redirectURI {
			return true
		}
	}
	return false
}

// validateResponseType validates that the response type is supported by the client
func (h *AuthorizeHandler) validateResponseType(client *OAuthClient, responseType string) bool {
	// Check if response type is supported by the client
	for _, rt := range client.ResponseTypes {
		if rt == responseType {
			return true
		}
	}
	return false
}

// validateScope validates that the requested scopes are allowed for the client
func (h *AuthorizeHandler) validateScope(client *OAuthClient, scope string) bool {
	if scope == "" {
		return true
	}

	requestedScopes := strings.Split(scope, " ")
	for _, requested := range requestedScopes {
		if requested == "" {
			continue
		}
		allowed := false
		for _, allowedScope := range client.Scopes {
			if allowedScope == requested {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

// validatePKCEParameters validates PKCE parameters per RFC 7636
func (h *AuthorizeHandler) validatePKCEParameters(client *OAuthClient, req *AuthorizeRequest) error {
	// Public clients MUST use PKCE
	if client.Type == "public" {
		if req.CodeChallenge == "" {
			return fmt.Errorf("code_challenge is required for public clients")
		}
	}

	// Validate code challenge method if provided
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" {
		if req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
			return fmt.Errorf("unsupported code_challenge_method: %s", req.CodeChallengeMethod)
		}
		// Reject "plain" in production: it offers no protection against code
		// interception and is not advertised in discovery. Fail fast at authorize
		// rather than only at the token endpoint. (The token endpoint keeps its
		// own guard for defense in depth.)
		if req.CodeChallengeMethod == "plain" && h.service.config != nil && h.service.config.IsProduction() {
			return fmt.Errorf("code_challenge_method 'plain' is not allowed; use S256")
		}
	}

	// Validate code challenge format
	if req.CodeChallenge != "" {
		// code_challenge must be base64url-encoded
		_, err := base64.RawURLEncoding.DecodeString(req.CodeChallenge)
		if err != nil {
			return fmt.Errorf("invalid code_challenge format: must be base64url-encoded")
		}

		// Check length constraints per RFC 7636
		// code_challenge length after decoding should be between 43 and 128 characters
		decodedLen := len(req.CodeChallenge)
		if decodedLen < 43 || decodedLen > 128 {
			return fmt.Errorf("code_challenge length must be between 43 and 128 characters")
		}
	}

	return nil
}

// storeAuthorizationRequest stores the authorization request in Redis for later use
func (h *AuthorizeHandler) storeAuthorizationRequest(ctx context.Context, sessionID string, req *AuthorizeRequest, client *OAuthClient) error {
	key := "auth_request:" + sessionID

	data := map[string]interface{}{
		"client_id":             req.ClientID,
		"redirect_uri":          req.RedirectURI,
		"response_type":         req.ResponseType,
		"scope":                 req.Scope,
		"state":                 req.State,
		"nonce":                 req.Nonce,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"client_type":           client.Type,
	}

	// Store for 10 minutes
	return h.service.redis.Client.HMSet(ctx, key, data).Err()
}

// redirectToLogin redirects the user to the login page
func (h *AuthorizeHandler) redirectToLogin(c *gin.Context, req *AuthorizeRequest, sessionID string) {
	loginURL, _ := url.Parse("/oauth/login")
	query := loginURL.Query()
	query.Set("login_session", sessionID)
	query.Set("redirect_uri", req.RedirectURI)
	loginURL.RawQuery = query.Encode()

	c.Redirect(302, loginURL.String())
}

// handleError handles authorization errors and redirects appropriately
func (h *AuthorizeHandler) handleError(c *gin.Context, req *AuthorizeRequest, errorCode error, description string) {
	if req == nil || req.RedirectURI == "" {
		// No redirect URI available, return error response
		c.JSON(400, gin.H{
			"error":             errorCode.Error(),
			"error_description": description,
		})
		return
	}

	// Build error redirect
	redirectURL, err := BuildRedirectURI(req.RedirectURI, "", req.State, errorCode.Error(), description)
	if err != nil {
		h.logger.Error("Failed to build error redirect", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	c.Redirect(302, redirectURL)
}

// GenerateAuthorizationCode generates a cryptographically secure authorization code
// Uses crypto/rand for secure random generation
func GenerateAuthorizationCode() (string, error) {
	// Generate 32 random bytes (256 bits)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Encode using base64url (URL-safe without padding)
	code := base64.RawURLEncoding.EncodeToString(b)

	// Additional validation to ensure minimum length
	if len(code) < 43 {
		return "", fmt.Errorf("generated code is too short")
	}

	return code, nil
}

// ValidatePKCE validates the PKCE code_verifier against the stored code_challenge
// Implements RFC 7636 validation
func ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	// If no PKCE was used (no challenge stored), skip validation
	if codeChallenge == "" && codeVerifier == "" && codeChallengeMethod == "" {
		return nil
	}

	if codeVerifier == "" {
		return fmt.Errorf("code_verifier is required")
	}

	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required")
	}

	// Validate code_verifier format per RFC 7636
	// Must be 43-128 characters from [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return fmt.Errorf("code_verifier length must be between 43 and 128 characters")
	}

	for _, c := range codeVerifier {
		if !isValidPKCEChar(c) {
			return fmt.Errorf("code_verifier contains invalid character: %c", c)
		}
	}

	// Validate based on challenge method
	var computedChallenge string
	switch codeChallengeMethod {
	case "S256":
		// SHA-256 hash per RFC 7636 §4.6
		hash := sha256.Sum256([]byte(codeVerifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
	case "plain":
		// Plain text method (not recommended, but required by RFC 7636)
		computedChallenge = codeVerifier
	default:
		return fmt.Errorf("unsupported code_challenge_method: %s", codeChallengeMethod)
	}

	// Constant-time comparison to prevent timing attacks
	if !constantTimeStringCompare(computedChallenge, codeChallenge) {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

// isValidPKCEChar checks if a character is valid in a code_verifier per RFC 7636
func isValidPKCEChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// constantTimeStringCompare performs constant-time string comparison to prevent timing attacks
func constantTimeStringCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// BuildRedirectURI builds a redirect URI with authorization code or error
// Implements RFC 6749 §4.1.2 for successful and error responses
func BuildRedirectURI(baseURI, code, state, errorCode, errorDescription string) (string, error) {
	redirectURL, err := url.Parse(baseURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect_uri: %w", err)
	}

	query := redirectURL.Query()

	// Add state parameter if present (required for security)
	if state != "" {
		query.Set("state", state)
	}

	// Add code or error
	if code != "" {
		query.Set("code", code)
	} else if errorCode != "" {
		query.Set("error", errorCode)
		if errorDescription != "" {
			query.Set("error_description", errorDescription)
		}
	}

	redirectURL.RawQuery = query.Encode()
	return redirectURL.String(), nil
}

// IssueAuthorizationCode creates and stores an authorization code after user consent
// This is called after user authentication and consent
func (h *AuthorizeHandler) IssueAuthorizationCode(ctx context.Context, sessionID, userID string, sessionIDExtra string) (string, error) {
	// Retrieve stored authorization request
	key := "auth_request:" + sessionID
	data, err := h.service.redis.Client.HMGet(ctx, key,
		"client_id", "redirect_uri", "scope", "state", "nonce",
		"code_challenge", "code_challenge_method").Result()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve authorization request: %w", err)
	}

	if data[0] == nil {
		return "", fmt.Errorf("authorization request not found or expired")
	}

	req := &AuthorizeRequest{
		ClientID:            data[0].(string),
		RedirectURI:         data[1].(string),
		Scope:               data[2].(string),
		State:               data[3].(string),
		Nonce:               data[4].(string),
		CodeChallenge:       data[5].(string),
		CodeChallengeMethod: data[6].(string),
	}

	// Generate secure authorization code
	code, err := GenerateAuthorizationCode()
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Create authorization code record
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
	}

	// Store in database
	if err := h.service.CreateAuthorizationCode(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	// Store session_id association for token linkage
	if sessionIDExtra != "" {
		h.service.redis.Client.Set(ctx, "authcode_session:"+code, sessionIDExtra, 5*time.Minute)
	}

	// Clean up the authorization request
	h.service.redis.Client.Del(ctx, key)

	return code, nil
}

// GetStoredAuthorizationRequest retrieves a stored authorization request
func (h *AuthorizeHandler) GetStoredAuthorizationRequest(ctx context.Context, sessionID string) (*AuthorizeRequest, error) {
	key := "auth_request:" + sessionID
	data, err := h.service.redis.Client.HMGet(ctx, key,
		"client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
		"code_challenge", "code_challenge_method").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve authorization request: %w", err)
	}

	if data[0] == nil {
		return nil, fmt.Errorf("authorization request not found or expired")
	}

	return &AuthorizeRequest{
		ClientID:            data[0].(string),
		RedirectURI:         data[1].(string),
		ResponseType:        data[2].(string),
		Scope:               data[3].(string),
		State:               data[4].(string),
		Nonce:               data[5].(string),
		CodeChallenge:       data[6].(string),
		CodeChallengeMethod: data[7].(string),
	}, nil
}
