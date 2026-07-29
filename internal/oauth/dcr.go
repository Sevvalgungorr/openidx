package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Dynamic Client Registration (RFC 7591) + management (RFC 7592).
//
// Lets a client register itself at runtime instead of an admin pre-provisioning
// it. This is the substrate for agent identity: an autonomous agent (or a CI
// job, or an MCP server) can register, obtain credentials, and then use the
// token endpoint (incl. token exchange) without a human in the loop.
//
// Registration can be gated by an initial access token (a bearer the operator
// distributes) so the endpoint is not open to the world; when no gate is
// configured it is open (dev/first-run), matching common OSS defaults.

// clientMetadata is the RFC 7591 client metadata request/response body. Only the
// fields OpenIDX supports are modeled; unknown request fields are ignored.
type clientMetadata struct {
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TOSUri                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
}

// clientRegistrationResponse is the RFC 7591 registration response. It echoes
// the accepted metadata plus the issued credentials and management fields.
type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TOSUri                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
}

// dcrError writes an RFC 7591 §3.2.2 registration error.
func dcrError(c *gin.Context, status int, code, desc string) {
	c.JSON(status, gin.H{"error": code, "error_description": desc})
}

// handleRegisterClient implements POST /oauth/register (RFC 7591).
func (s *Service) handleRegisterClient(c *gin.Context) {
	if !s.dcrAuthorized(c) {
		dcrError(c, http.StatusUnauthorized, "invalid_token", "registration requires a valid initial access token")
		return
	}

	var md clientMetadata
	if err := c.ShouldBindJSON(&md); err != nil {
		dcrError(c, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON body")
		return
	}

	client, err := s.buildClientFromMetadata(&md)
	if err != nil {
		dcrError(c, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	if err := s.CreateClient(c.Request.Context(), client); err != nil {
		s.logger.Error("DCR: failed to persist client", zap.Error(err))
		dcrError(c, http.StatusInternalServerError, "invalid_client_metadata", "could not store client")
		return
	}

	// Mint a registration access token (RFC 7592) bound to this client so the
	// registrant can manage it later. Stored hashed.
	regToken, regHash := newRegistrationToken()
	if err := s.storeRegistrationToken(c.Request.Context(), client.ClientID, regHash); err != nil {
		// Non-fatal: the client is registered; management just won't be available.
		s.logger.Warn("DCR: failed to store registration access token", zap.Error(err))
		regToken = ""
	}

	s.logger.Info("DCR: client registered",
		zap.String("client_id", client.ClientID), zap.String("name", client.Name),
		zap.Strings("grant_types", client.GrantTypes))

	resp := s.registrationResponse(c, client, regToken)
	c.JSON(http.StatusCreated, resp)
}

// handleGetRegisteredClient implements GET /oauth/register/:client_id (RFC 7592).
func (s *Service) handleGetRegisteredClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if !s.registrationTokenValid(c, clientID) {
		dcrError(c, http.StatusUnauthorized, "invalid_token", "invalid registration access token")
		return
	}
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil {
		dcrError(c, http.StatusNotFound, "invalid_client_id", "unknown client")
		return
	}
	// Never re-expose the secret on read (RFC 7592 §3).
	resp := s.registrationResponse(c, client, "")
	resp.ClientSecret = ""
	c.JSON(http.StatusOK, resp)
}

// handleUpdateRegisteredClient implements PUT /oauth/register/:client_id.
func (s *Service) handleUpdateRegisteredClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if !s.registrationTokenValid(c, clientID) {
		dcrError(c, http.StatusUnauthorized, "invalid_token", "invalid registration access token")
		return
	}
	existing, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil {
		dcrError(c, http.StatusNotFound, "invalid_client_id", "unknown client")
		return
	}
	var md clientMetadata
	if err := c.ShouldBindJSON(&md); err != nil {
		dcrError(c, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON body")
		return
	}
	updated, err := s.buildClientFromMetadata(&md)
	if err != nil {
		dcrError(c, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	// Preserve identity + secret; only metadata is mutable here.
	updated.ClientID = existing.ClientID
	updated.ClientSecret = existing.ClientSecret
	if err := s.UpdateClient(c.Request.Context(), clientID, updated); err != nil {
		dcrError(c, http.StatusInternalServerError, "invalid_client_metadata", "could not update client")
		return
	}
	resp := s.registrationResponse(c, updated, "")
	resp.ClientSecret = ""
	c.JSON(http.StatusOK, resp)
}

// handleDeleteRegisteredClient implements DELETE /oauth/register/:client_id.
func (s *Service) handleDeleteRegisteredClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if !s.registrationTokenValid(c, clientID) {
		dcrError(c, http.StatusUnauthorized, "invalid_token", "invalid registration access token")
		return
	}
	if _, err := s.GetClient(c.Request.Context(), clientID); err != nil {
		dcrError(c, http.StatusNotFound, "invalid_client_id", "unknown client")
		return
	}
	if err := s.DeleteClient(c.Request.Context(), clientID); err != nil {
		dcrError(c, http.StatusInternalServerError, "invalid_client_id", "could not delete client")
		return
	}
	_, _ = s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM oauth_registration_tokens WHERE client_id = $1`, clientID)
	c.Status(http.StatusNoContent)
}

// buildClientFromMetadata validates RFC 7591 metadata and produces an
// OAuthClient with freshly minted credentials.
func (s *Service) buildClientFromMetadata(md *clientMetadata) (*OAuthClient, error) {
	grantTypes := md.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	for _, gt := range grantTypes {
		if !isRegisterableGrant(gt) {
			return nil, &metadataError{"unsupported grant_type: " + gt}
		}
	}

	// redirect_uris are required for the authorization_code / implicit flows.
	needsRedirect := contains(grantTypes, "authorization_code") || contains(grantTypes, "implicit")
	if needsRedirect && len(md.RedirectURIs) == 0 {
		return nil, &metadataError{"redirect_uris is required for the requested grant_types"}
	}
	for _, u := range md.RedirectURIs {
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://localhost") &&
			!strings.HasPrefix(u, "http://127.0.0.1") && !isPrivateURIScheme(u) {
			return nil, &metadataError{"redirect_uri must be https or a loopback/native scheme: " + u}
		}
	}

	// public (no secret) when token_endpoint_auth_method=none, else confidential.
	clientType := "confidential"
	if md.TokenEndpointAuthMethod == "none" {
		clientType = "public"
	}

	responseTypes := md.ResponseTypes
	if len(responseTypes) == 0 && needsRedirect {
		responseTypes = []string{"code"}
	}

	scopes := splitScope(md.Scope)

	client := &OAuthClient{
		ID:                   uuid.NewString(),
		ClientID:             "oidc_" + randToken(16),
		Name:                 firstNonEmptyStr(md.ClientName, "Dynamically Registered Client"),
		Description:          "Registered via RFC 7591 Dynamic Client Registration",
		Type:                 clientType,
		RedirectURIs:         md.RedirectURIs,
		GrantTypes:           grantTypes,
		ResponseTypes:        responseTypes,
		Scopes:               scopes,
		LogoURI:              md.LogoURI,
		PolicyURI:            md.PolicyURI,
		TOSUri:               md.TOSUri,
		PKCERequired:         clientType == "public",
		AllowRefreshToken:    contains(grantTypes, "refresh_token"),
		AccessTokenLifetime:  3600,
		RefreshTokenLifetime: 86400,
	}
	if clientType == "confidential" {
		client.ClientSecret = randToken(32)
	}
	return client, nil
}

func (s *Service) registrationResponse(c *gin.Context, client *OAuthClient, regToken string) clientRegistrationResponse {
	authMethod := "client_secret_basic"
	if client.Type == "public" {
		authMethod = "none"
	}
	resp := clientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            client.ClientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0, // 0 = never expires (RFC 7591)
		RegistrationAccessToken: regToken,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.Name,
		LogoURI:                 client.LogoURI,
		Scope:                   strings.Join(client.Scopes, " "),
		TOSUri:                  client.TOSUri,
		PolicyURI:               client.PolicyURI,
	}
	scheme := "https"
	if c.Request.TLS == nil && strings.HasPrefix(c.Request.Host, "127.0.0.1") {
		scheme = "http"
	}
	resp.RegistrationClientURI = scheme + "://" + c.Request.Host + "/oauth/register/" + client.ClientID
	return resp
}

// dcrAuthorized checks the initial access token gate. Default-secure: when no
// initial access token is configured, registration is refused UNLESS the
// operator explicitly opts into open registration (dcrAllowOpenRegistration).
// This prevents an unconfigured deployment from exposing an anonymous OAuth
// client registration endpoint (a phishing/token-theft vector).
func (s *Service) dcrAuthorized(c *gin.Context) bool {
	gate := s.dcrInitialAccessToken
	if gate == "" {
		return s.dcrAllowOpenRegistration
	}
	got := bearerToken(c)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(gate)) == 1
}

// storeRegistrationToken persists the hash of a registration access token.
func (s *Service) storeRegistrationToken(ctx context.Context, clientID, hash string) error {
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_registration_tokens (client_id, token_hash, created_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (client_id) DO UPDATE SET token_hash = EXCLUDED.token_hash`,
		clientID, hash)
	return err
}

// registrationTokenValid checks the bearer registration access token for a
// management call against the stored hash.
func (s *Service) registrationTokenValid(c *gin.Context, clientID string) bool {
	tok := bearerToken(c)
	if tok == "" {
		return false
	}
	var stored string
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT token_hash FROM oauth_registration_tokens WHERE client_id = $1`, clientID).Scan(&stored); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashRegistrationToken(tok)), []byte(stored)) == 1
}

// --- helpers ---

type metadataError struct{ msg string }

func (e *metadataError) Error() string { return e.msg }

func isRegisterableGrant(gt string) bool {
	switch gt {
	case "authorization_code", "refresh_token", "client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange":
		return true
	}
	return false
}

func isPrivateURIScheme(u string) bool {
	// Native app custom scheme, e.g. com.example.app:/callback (RFC 8252).
	i := strings.Index(u, ":")
	return i > 0 && !strings.HasPrefix(u, "http")
}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func newRegistrationToken() (token, hash string) {
	token = "rat_" + randToken(32)
	return token, hashRegistrationToken(token)
}

func hashRegistrationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func splitScope(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
