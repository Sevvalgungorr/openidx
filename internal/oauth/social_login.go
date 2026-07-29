// Package oauth provides social login federation (Google, GitHub, Microsoft)
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// ErrSocialAccountConflict is returned when a social login matches an existing
// user by email but the social account has not been explicitly linked yet.
// Auto-linking is refused to prevent account takeover.
var ErrSocialAccountConflict = errors.New("an account with this email already exists; please log in and link your social account from your profile")

// SocialTokens represents tokens received from a social OAuth provider
type SocialTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// SocialUserInfo represents user information from a social provider
type SocialUserInfo struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Picture   string `json:"picture,omitempty"`
	Provider  string `json:"provider"`
}

// SocialProviderConfig holds the configuration for a social identity provider
type SocialProviderConfig struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ProviderType     string   `json:"provider_type"`
	IssuerURL        string   `json:"issuer_url"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret"`
	Scopes           []string `json:"scopes"`
	AuthorizationURL string   `json:"authorization_url"`
	TokenURL         string   `json:"token_url"`
	UserInfoURL      string   `json:"userinfo_url"`
	Enabled          bool     `json:"enabled"`
}

// RegisterSocialLoginRoutes registers social login endpoints
func (s *Service) RegisterSocialLoginRoutes(router *gin.Engine) {
	social := router.Group("/oauth/social")
	{
		social.GET("/:provider_id", s.handleSocialLoginInit)
		social.GET("/callback", s.handleSocialLoginCallback)
	}
}

// handleSocialLoginInit initiates the social login flow by redirecting to the provider
func (s *Service) handleSocialLoginInit(c *gin.Context) {
	providerID := c.Param("provider_id")
	loginSession := c.Query("login_session")

	// Load provider configuration from database
	provider, err := s.loadSocialProviderConfig(c.Request.Context(), providerID)
	if err != nil {
		s.logger.Error("Failed to load social provider config",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
		return
	}

	if !provider.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Identity provider is disabled"})
		return
	}

	// Generate state parameter and store in Redis
	state := GenerateRandomToken(32)
	stateData := map[string]string{
		"provider_id":   providerID,
		"login_session": loginSession,
	}
	stateJSON, _ := json.Marshal(stateData)
	s.redis.Client.Set(c.Request.Context(), "social_state:"+state, string(stateJSON), 10*time.Minute)

	// Build authorization URL
	authURL := provider.AuthorizationURL
	if authURL == "" {
		authURL = s.deriveAuthorizationURL(provider)
	}

	baseURL := s.getBaseURL(c)
	redirectURI := baseURL + "/oauth/social/callback"

	scopes := provider.Scopes
	if len(scopes) == 0 {
		scopes = s.defaultScopesForProvider(provider.ProviderType)
	}

	params := url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}

	fullURL := authURL + "?" + params.Encode()

	s.logger.Info("Initiating social login",
		zap.String("provider_id", providerID),
		zap.String("provider_type", provider.ProviderType),
	)

	c.Redirect(http.StatusFound, fullURL)
}

// handleSocialLoginCallback processes the callback from the social provider
func (s *Service) handleSocialLoginCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		errorDesc := c.Query("error_description")
		s.logger.Error("Social login error from provider",
			zap.String("error", errorParam),
			zap.String("description", errorDesc))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "social_login_failed",
			"error_description": errorDesc,
		})
		return
	}

	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code or state parameter"})
		return
	}

	// Look up state in Redis
	stateJSON, err := s.redis.Client.Get(c.Request.Context(), "social_state:"+state).Result()
	if err != nil {
		s.logger.Error("Invalid or expired social login state", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state"})
		return
	}

	// Delete state immediately to prevent replay
	s.redis.Client.Del(c.Request.Context(), "social_state:"+state)

	var stateData map[string]string
	if err := json.Unmarshal([]byte(stateJSON), &stateData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse state data"})
		return
	}

	providerID := stateData["provider_id"]
	loginSession := stateData["login_session"]

	// Load provider configuration
	provider, err := s.loadSocialProviderConfig(c.Request.Context(), providerID)
	if err != nil {
		s.logger.Error("Failed to load social provider config for callback",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Provider configuration not found"})
		return
	}

	baseURL := s.getBaseURL(c)
	redirectURI := baseURL + "/oauth/social/callback"

	// Exchange code for tokens
	tokens, err := s.exchangeCodeForTokens(c.Request.Context(), provider, code, redirectURI)
	if err != nil {
		s.logger.Error("Failed to exchange code for tokens",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange authorization code"})
		return
	}

	// Fetch user info from the social provider
	userInfo, err := s.fetchSocialUserInfo(c.Request.Context(), provider, tokens.AccessToken)
	if err != nil {
		s.logger.Error("Failed to fetch user info from social provider",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user info"})
		return
	}

	s.logger.Info("Social login: fetched user info",
		zap.String("provider", provider.ProviderType),
		zap.String("email", userInfo.Email),
		zap.String("name", userInfo.Name),
		zap.String("social_id", userInfo.ID),
	)

	// Link or create local user
	userID, err := s.linkOrCreateSocialUser(c.Request.Context(), providerID, userInfo)
	if err != nil {
		if errors.Is(err, ErrSocialAccountConflict) {
			s.logger.Warn("Social login conflict: email already in use",
				zap.String("provider_id", providerID),
				zap.String("email", userInfo.Email))
			c.JSON(http.StatusConflict, gin.H{
				"error":             "account_conflict",
				"error_description": err.Error(),
			})
			return
		}
		s.logger.Error("Failed to link/create user from social login",
			zap.String("provider_id", providerID),
			zap.String("email", userInfo.Email),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user account"})
		return
	}

	// Log audit event in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "social_login", "login", "success",
			userID, c.ClientIP(), providerID, "identity_provider",
			map[string]interface{}{
				"provider_type": provider.ProviderType,
				"social_id":     userInfo.ID,
				"email":         userInfo.Email,
			})
	}()

	// If we have a login_session, issue an auth code via the normal OAuth flow
	if loginSession != "" {
		paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "login_session:"+loginSession).Result()
		if err == nil {
			var oauthParams map[string]string
			if json.Unmarshal([]byte(paramsJSON), &oauthParams) == nil {
				// Create a session linked to this login
				clientIP := c.ClientIP()
				userAgent := c.GetHeader("User-Agent")
				session, sessionErr := s.identityService.CreateSession(c.Request.Context(), userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
				if sessionErr != nil {
					s.logger.Warn("Failed to create session during social login", zap.Error(sessionErr))
				}
				if session != nil {
					oauthParams["session_id"] = session.ID
				}

				s.redis.Client.Del(c.Request.Context(), "login_session:"+loginSession)
				s.issueAuthorizationCode(c, oauthParams, userID)
				return
			}
		}
	}

	// Fallback: generate tokens directly using the SAML token flow
	samlUser := &SAMLUser{
		ID:          userID,
		Email:       userInfo.Email,
		FirstName:   userInfo.FirstName,
		LastName:    userInfo.LastName,
		DisplayName: userInfo.Name,
	}

	tokenResponse, err := s.generateTokensForUser(c.Request.Context(), samlUser, "admin-console", []string{"openid", "profile", "email"})
	if err != nil {
		s.logger.Error("Failed to generate tokens for social user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// --- Helper functions ---

// loadSocialProviderConfig loads an identity provider config from the database
func (s *Service) loadSocialProviderConfig(ctx context.Context, providerID string) (*SocialProviderConfig, error) {
	var provider SocialProviderConfig
	var scopesJSON []byte

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled
		FROM identity_providers
		WHERE id = $1 AND org_id = $2
	`, providerID, org.ID).Scan(
		&provider.ID, &provider.Name, &provider.ProviderType,
		&provider.IssuerURL, &provider.ClientID, &provider.ClientSecret,
		&scopesJSON, &provider.Enabled)

	if err != nil {
		return nil, fmt.Errorf("identity provider not found: %w", err)
	}
	if provider.ClientSecret, err = s.idpCipher.Decrypt(provider.ClientSecret); err != nil {
		return nil, fmt.Errorf("decrypt IdP client_secret: %w", err)
	}

	if len(scopesJSON) > 0 {
		_ = json.Unmarshal(scopesJSON, &provider.Scopes)
	}

	// Derive well-known URLs based on provider type
	provider.AuthorizationURL = s.deriveAuthorizationURL(&provider)
	provider.TokenURL = s.deriveTokenURL(&provider)
	provider.UserInfoURL = s.deriveUserInfoURL(&provider)

	return &provider, nil
}

// exchangeCodeForTokens exchanges an authorization code for tokens at the provider's token endpoint
func (s *Service) exchangeCodeForTokens(ctx context.Context, provider *SocialProviderConfig, code, redirectURI string) (*SocialTokens, error) {
	tokenURL := provider.TokenURL
	if tokenURL == "" {
		tokenURL = s.deriveTokenURL(provider)
	}

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {provider.ClientID},
	}

	// GitHub accepts client_secret in the body; Google/Microsoft use Basic auth or body
	if provider.ClientSecret != "" {
		data.Set("client_secret", provider.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := s.outboundHTTPClient("social-"+provider.ProviderType+"-token", 30*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokens SocialTokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokens, nil
}

// fetchSocialUserInfo fetches user information from the provider's userinfo endpoint
func (s *Service) fetchSocialUserInfo(ctx context.Context, provider *SocialProviderConfig, accessToken string) (*SocialUserInfo, error) {
	userInfoURL := provider.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = s.deriveUserInfoURL(provider)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	// GitHub API requires a User-Agent header
	if provider.ProviderType == "github" {
		req.Header.Set("User-Agent", "OpenIDX")
	}

	client := s.outboundHTTPClient("social-"+provider.ProviderType+"-userinfo", 30*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse response based on provider type
	userInfo := &SocialUserInfo{
		Provider: provider.ProviderType,
	}

	switch provider.ProviderType {
	case "google":
		if err := s.parseGoogleUserInfo(body, userInfo); err != nil {
			return nil, err
		}
	case "github":
		if err := s.parseGitHubUserInfo(ctx, body, accessToken, userInfo); err != nil {
			return nil, err
		}
	case "microsoft":
		if err := s.parseMicrosoftUserInfo(body, userInfo); err != nil {
			return nil, err
		}
	default:
		// Generic OIDC-style userinfo parsing
		if err := s.parseGenericUserInfo(body, userInfo); err != nil {
			return nil, err
		}
	}

	return userInfo, nil
}

// parseGoogleUserInfo parses Google's userinfo response
func (s *Service) parseGoogleUserInfo(body []byte, info *SocialUserInfo) error {
	var data struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to parse Google userinfo: %w", err)
	}

	info.ID = data.Sub
	info.Email = data.Email
	info.Name = data.Name
	info.FirstName = data.GivenName
	info.LastName = data.FamilyName
	info.Picture = data.Picture
	return nil
}

// parseGitHubUserInfo parses GitHub's user API response
func (s *Service) parseGitHubUserInfo(ctx context.Context, body []byte, accessToken string, info *SocialUserInfo) error {
	var data struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to parse GitHub userinfo: %w", err)
	}

	info.ID = fmt.Sprintf("%d", data.ID)
	info.Name = data.Name
	info.Email = data.Email
	info.Picture = data.AvatarURL

	// GitHub may not return email in user endpoint if it's private.
	// Fetch from the emails endpoint instead.
	if info.Email == "" {
		email, err := s.fetchGitHubPrimaryEmail(ctx, accessToken)
		if err != nil {
			s.logger.Warn("Failed to fetch GitHub primary email", zap.Error(err))
		} else {
			info.Email = email
		}
	}

	// Split name into first/last
	if info.Name != "" {
		parts := strings.SplitN(info.Name, " ", 2)
		info.FirstName = parts[0]
		if len(parts) > 1 {
			info.LastName = parts[1]
		}
	} else {
		info.Name = data.Login
		info.FirstName = data.Login
	}

	return nil
}

// fetchGitHubPrimaryEmail fetches the user's primary email from GitHub's emails API
func (s *Service) fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OpenIDX")

	client := s.outboundHTTPClient("social-github-email", 15*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	// Return the primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	// Fallback to first verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

// parseMicrosoftUserInfo parses Microsoft Graph's /me response
func (s *Service) parseMicrosoftUserInfo(body []byte, info *SocialUserInfo) error {
	var data struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to parse Microsoft userinfo: %w", err)
	}

	info.ID = data.ID
	info.Name = data.DisplayName
	info.FirstName = data.GivenName
	info.LastName = data.Surname
	info.Email = data.Mail
	if info.Email == "" {
		info.Email = data.UserPrincipalName
	}

	return nil
}

// parseGenericUserInfo parses a generic OIDC-style userinfo response
func (s *Service) parseGenericUserInfo(body []byte, info *SocialUserInfo) error {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to parse userinfo: %w", err)
	}

	info.ID, _ = data["sub"].(string)
	if info.ID == "" {
		info.ID, _ = data["id"].(string)
	}
	info.Email, _ = data["email"].(string)
	info.Name, _ = data["name"].(string)
	info.FirstName, _ = data["given_name"].(string)
	info.LastName, _ = data["family_name"].(string)
	info.Picture, _ = data["picture"].(string)

	return nil
}

// linkOrCreateSocialUser links the social identity to an existing user or creates a new one
// Returns the local user ID
func (s *Service) linkOrCreateSocialUser(ctx context.Context, providerID string, userInfo *SocialUserInfo) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}

	// Check if this social account is already linked
	var existingUserID string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT user_id FROM social_account_links
		WHERE provider_id = $1 AND external_id = $2
	`, providerID, userInfo.ID).Scan(&existingUserID)

	if err == nil {
		// Already linked - update last login info and return
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE social_account_links SET last_login_at = NOW(),
				profile_data = jsonb_set(COALESCE(profile_data, '{}'::jsonb), '{display_name}', to_jsonb($3::text)),
				email = $4
			WHERE provider_id = $1 AND external_id = $2
		`, providerID, userInfo.ID, userInfo.Name, userInfo.Email)

		return existingUserID, nil
	}

	// Not linked yet - check if a user with this email exists
	if userInfo.Email != "" {
		var userID string
		err := s.db.Pool.QueryRow(ctx,
			"SELECT id FROM users WHERE email = $1 AND org_id = $2", userInfo.Email, org.ID).Scan(&userID)

		if err == nil {
			// User exists but has no linked social account for this provider.
			// Refuse to auto-link to prevent account takeover; the user must
			// authenticate normally and link the social account from their profile.
			s.logger.Warn("Social login blocked: email matches existing user without linked social account",
				zap.String("user_id", userID),
				zap.String("email", userInfo.Email),
				zap.String("provider", userInfo.Provider),
			)

			return "", ErrSocialAccountConflict
		}
	}

	// No existing user - JIT provision a new user
	userID := uuid.New().String()
	username := s.deriveSocialUsername(userInfo)

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified, external_user_id, org_id)
		VALUES ($1, $2, $3, $4, $5, true, true, $6, $7)
		ON CONFLICT (email) DO UPDATE SET
			first_name = COALESCE(EXCLUDED.first_name, users.first_name),
			last_name = COALESCE(EXCLUDED.last_name, users.last_name),
			updated_at = NOW()
		RETURNING id
	`, userID, username, userInfo.Email, userInfo.FirstName, userInfo.LastName, userInfo.ID, org.ID)

	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	// On conflict, the userID from RETURNING may differ from what we generated
	// Re-fetch to be safe
	_ = s.db.Pool.QueryRow(ctx,
		"SELECT id FROM users WHERE email = $1 AND org_id = $2", userInfo.Email, org.ID).Scan(&userID)

	// Create the social account link
	if linkErr := s.createSocialAccountLink(ctx, providerID, userID, userInfo); linkErr != nil {
		s.logger.Warn("Failed to create social account link after user creation", zap.Error(linkErr))
	}

	s.logger.Info("Created user from social login (JIT provisioning)",
		zap.String("user_id", userID),
		zap.String("email", userInfo.Email),
		zap.String("provider", userInfo.Provider),
	)

	return userID, nil
}

// createSocialAccountLink inserts a social account link record
func (s *Service) createSocialAccountLink(ctx context.Context, providerID, userID string, userInfo *SocialUserInfo) error {
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO social_account_links (id, provider_id, user_id, external_id, profile_data, email, last_login_at, linked_at)
		VALUES ($1, $2, $3, $4, jsonb_build_object('display_name', $5::text), $6, NOW(), NOW())
		ON CONFLICT (provider_id, external_id) DO UPDATE SET
			user_id = $3,
			profile_data = jsonb_set(COALESCE(social_account_links.profile_data, '{}'::jsonb), '{display_name}', to_jsonb($5::text)),
			email = $6, last_login_at = NOW()
	`, uuid.New().String(), providerID, userID, userInfo.ID, userInfo.Name, userInfo.Email)

	return err
}

// --- URL derivation helpers ---

// deriveAuthorizationURL returns the authorization URL for a provider
func (s *Service) deriveAuthorizationURL(provider *SocialProviderConfig) string {
	switch provider.ProviderType {
	case "google":
		return "https://accounts.google.com/o/oauth2/v2/auth"
	case "github":
		return "https://github.com/login/oauth/authorize"
	case "microsoft":
		return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	default:
		// OIDC discovery-style: issuer_url + /protocol/openid-connect/auth
		if provider.IssuerURL != "" {
			return strings.TrimRight(provider.IssuerURL, "/") + "/protocol/openid-connect/auth"
		}
		return ""
	}
}

// deriveTokenURL returns the token URL for a provider
func (s *Service) deriveTokenURL(provider *SocialProviderConfig) string {
	switch provider.ProviderType {
	case "google":
		return "https://oauth2.googleapis.com/token"
	case "github":
		return "https://github.com/login/oauth/access_token"
	case "microsoft":
		return "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	default:
		if provider.IssuerURL != "" {
			return strings.TrimRight(provider.IssuerURL, "/") + "/protocol/openid-connect/token"
		}
		return ""
	}
}

// deriveUserInfoURL returns the userinfo URL for a provider
func (s *Service) deriveUserInfoURL(provider *SocialProviderConfig) string {
	switch provider.ProviderType {
	case "google":
		return "https://www.googleapis.com/oauth2/v3/userinfo"
	case "github":
		return "https://api.github.com/user"
	case "microsoft":
		return "https://graph.microsoft.com/v1.0/me"
	default:
		if provider.IssuerURL != "" {
			return strings.TrimRight(provider.IssuerURL, "/") + "/protocol/openid-connect/userinfo"
		}
		return ""
	}
}

// defaultScopesForProvider returns default scopes for a provider type
func (s *Service) defaultScopesForProvider(providerType string) []string {
	switch providerType {
	case "google":
		return []string{"openid", "email", "profile"}
	case "github":
		return []string{"user:email", "read:user"}
	case "microsoft":
		return []string{"openid", "email", "profile", "User.Read"}
	default:
		return []string{"openid", "email", "profile"}
	}
}

// deriveSocialUsername generates a username from social user info
func (s *Service) deriveSocialUsername(userInfo *SocialUserInfo) string {
	if userInfo.Email != "" {
		parts := strings.Split(userInfo.Email, "@")
		return parts[0]
	}
	if userInfo.Name != "" {
		return strings.ReplaceAll(strings.ToLower(userInfo.Name), " ", ".")
	}
	return "social_" + userInfo.ID
}
