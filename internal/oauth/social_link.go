package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Social account linking ("link mode").
//
// Why this file exists: handleSocialLoginCallback deliberately refuses to sign
// a user in when the social account is unknown but its email already belongs to
// a local user (ErrSocialAccountConflict). That refusal is correct — auto-linking
// on a matching email address is a classic account-takeover vector, because
// anyone who can create an IdP account bearing a victim's email address would
// inherit the victim's local account.
//
// The refusal message tells the user to "log in and link your social account
// from your profile", but no endpoint existed to do that, so the user was left
// in a dead end: they could not sign in with the provider, and could not link
// either. This file supplies the missing half of that contract.
//
// The security property we preserve: a link is only ever created for the user
// proven by the *local* session (the Bearer token presented when starting the
// flow), and only after the caller demonstrates control of the external account
// by completing a real authorization round-trip with the provider. The email
// address returned by the provider is recorded, never trusted to select the
// local account.

// linkStateTTL bounds how long a pending link authorization may sit in Redis.
// It mirrors the login flow's state TTL.
const linkStateTTL = 10 * time.Minute

const linkStatePrefix = "social_link_state:"

// RegisterSocialLinkRoutes registers the self-service account-linking endpoints.
//
// The start endpoint is authenticated: the local identity being linked comes
// from the Bearer token, never from a request parameter. The callback is
// reached via a browser redirect from the provider and therefore cannot carry
// the Authorization header, so it authenticates on the one-time state value
// which was bound to the user id at start time.
func (s *Service) RegisterSocialLinkRoutes(router *gin.Engine) {
	link := router.Group("/oauth/social/link")
	{
		link.POST("/:provider_id/start", s.handleSocialLinkStart)
		link.GET("/callback", s.handleSocialLinkCallback)
	}
}

// bearerUserID resolves the authenticated local user from the Authorization
// header. Returns "" when the caller is unauthenticated or the token is not
// currently valid.
func (s *Service) bearerUserID(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	claims, err := s.parseVerifiedClaims(strings.TrimPrefix(authHeader, "Bearer "), false)
	if err != nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

// handleSocialLinkStart begins a link-mode authorization.
//
// POST /oauth/social/link/:provider_id/start
//
// Responds with the provider authorization URL rather than issuing a redirect,
// so a single-page app can open it deliberately (and so that a stray redirect
// can never be triggered by a cross-site GET).
func (s *Service) handleSocialLinkStart(c *gin.Context) {
	userID := s.bearerUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required to link an account"})
		return
	}

	providerID := c.Param("provider_id")
	provider, err := s.loadSocialProviderConfig(c.Request.Context(), providerID)
	if err != nil {
		s.logger.Error("Link start: provider not found",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
		return
	}
	if !provider.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Identity provider is disabled"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start account linking"})
		return
	}

	state := GenerateRandomToken(32)
	stateData := map[string]string{
		"provider_id": providerID,
		"user_id":     userID,
		"org_id":      org.ID,
	}
	stateJSON, _ := json.Marshal(stateData)
	if err := s.redis.Client.Set(c.Request.Context(),
		linkStatePrefix+state, string(stateJSON), linkStateTTL).Err(); err != nil {
		s.logger.Error("Link start: failed to store state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start account linking"})
		return
	}

	authURL := provider.AuthorizationURL
	if authURL == "" {
		authURL = s.deriveAuthorizationURL(provider)
	}
	if authURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Provider has no authorization endpoint"})
		return
	}

	scopes := provider.Scopes
	if len(scopes) == 0 {
		scopes = s.defaultScopesForProvider(provider.ProviderType)
	}

	params := url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {s.socialLinkRedirectURI(c)},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}

	s.logger.Info("Social account link started",
		zap.String("provider_id", providerID),
		zap.String("provider_type", provider.ProviderType),
		zap.String("user_id", userID))

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": authURL + "?" + params.Encode(),
		"expires_in":        int(linkStateTTL.Seconds()),
	})
}

// socialLinkRedirectURI is the callback the provider redirects back to. It must
// match byte-for-byte between the authorize and token requests.
func (s *Service) socialLinkRedirectURI(c *gin.Context) string {
	return s.getBaseURL(c) + "/oauth/social/link/callback"
}

// handleSocialLinkCallback completes a link-mode authorization.
//
// GET /oauth/social/link/callback?code=...&state=...
//
// The local user is taken from the state entry created at start time, so a
// caller cannot redirect the link onto somebody else's account.
func (s *Service) handleSocialLinkCallback(c *gin.Context) {
	if errParam := c.Query("error"); errParam != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "link_failed",
			"error_description": c.Query("error_description"),
		})
		return
	}

	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code or state parameter"})
		return
	}

	stateJSON, err := s.redis.Client.Get(c.Request.Context(), linkStatePrefix+state).Result()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state"})
		return
	}
	// Consume the state immediately: one authorization, one link.
	s.redis.Client.Del(c.Request.Context(), linkStatePrefix+state)

	var stateData map[string]string
	if err := json.Unmarshal([]byte(stateJSON), &stateData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse state data"})
		return
	}
	providerID := stateData["provider_id"]
	userID := stateData["user_id"]
	if providerID == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
		return
	}

	provider, err := s.loadSocialProviderConfig(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Provider configuration not found"})
		return
	}

	// Proof of control: the caller must be able to complete a real code
	// exchange and produce a userinfo response from the provider.
	tokens, err := s.exchangeCodeForTokens(c.Request.Context(), provider, code, s.socialLinkRedirectURI(c))
	if err != nil {
		s.logger.Error("Link callback: token exchange failed",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to exchange authorization code"})
		return
	}

	userInfo, err := s.fetchSocialUserInfo(c.Request.Context(), provider, tokens.AccessToken)
	if err != nil {
		s.logger.Error("Link callback: userinfo fetch failed",
			zap.String("provider_id", providerID), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to fetch user info"})
		return
	}
	if userInfo.ID == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Provider returned no account identifier"})
		return
	}

	// The administrator's domain restriction applies here too. Without this
	// check, linking would be a way around a restriction that the sign-in path
	// enforces, and the linked account could then be used to sign in.
	policy, err := s.loadSocialProviderPolicy(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link account"})
		return
	}
	if !policy.emailDomainAllowed(userInfo.Email) {
		s.logger.Warn("Link callback: email domain not allowed for this provider",
			zap.String("provider_id", providerID),
			zap.String("user_id", userID))
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "domain_not_allowed",
			"error_description": ErrSocialDomainNotAllowed.Error(),
		})
		return
	}

	linked, err := s.linkSocialAccountToUser(c.Request.Context(), providerID, userID, userInfo)
	if err != nil {
		if err == errLinkOwnedByAnotherUser {
			s.logger.Warn("Link callback: external account already linked elsewhere",
				zap.String("provider_id", providerID),
				zap.String("user_id", userID))
			c.JSON(http.StatusConflict, gin.H{
				"error":             "already_linked",
				"error_description": "this account is already linked to a different user",
			})
			return
		}
		s.logger.Error("Link callback: failed to persist link",
			zap.String("provider_id", providerID),
			zap.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link account"})
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "social_link", "link", "success",
			userID, c.ClientIP(), providerID, "identity_provider",
			map[string]interface{}{
				"provider_type": provider.ProviderType,
				"social_id":     userInfo.ID,
				"email":         userInfo.Email,
				"already":       !linked,
			})
	}()

	s.logger.Info("Social account linked",
		zap.String("provider_id", providerID),
		zap.String("user_id", userID),
		zap.String("provider_type", provider.ProviderType))

	c.JSON(http.StatusOK, gin.H{
		"status":         "linked",
		"provider_id":    providerID,
		"provider_name":  provider.Name,
		"external_email": userInfo.Email,
		"newly_linked":   linked,
	})
}

// errLinkOwnedByAnotherUser signals that the external account is already bound
// to a different local user. Silently re-pointing the link would let whoever
// controls the external account move it between local identities, so this is
// surfaced as a conflict instead.
var errLinkOwnedByAnotherUser = fmt.Errorf("external account already linked to another user")

// linkSocialAccountToUser records the verified external identity against the
// local user. It writes both link tables: social_account_links is what the
// login path consults, and user_identity_links is what the profile and admin
// screens read. Returns whether a new link was created.
func (s *Service) linkSocialAccountToUser(ctx context.Context, providerID, userID string, userInfo *SocialUserInfo) (bool, error) {
	var ownerID string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM social_account_links WHERE provider_id = $1 AND external_id = $2",
		providerID, userInfo.ID).Scan(&ownerID)
	switch {
	case err == nil && ownerID == userID:
		// Already linked to this same user: refresh and report no-op.
		if err := s.createSocialAccountLink(ctx, providerID, userID, userInfo); err != nil {
			return false, err
		}
		if err := s.upsertIdentityLink(ctx, providerID, userID, userInfo); err != nil {
			return false, err
		}
		return false, nil
	case err == nil:
		return false, errLinkOwnedByAnotherUser
	}

	// Not linked yet. The same guard applies to the identity-link table, which
	// carries its own (provider_id, external_id) uniqueness.
	err = s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM user_identity_links WHERE provider_id = $1 AND external_id = $2",
		providerID, userInfo.ID).Scan(&ownerID)
	if err == nil && ownerID != userID {
		return false, errLinkOwnedByAnotherUser
	}

	if err := s.createSocialAccountLink(ctx, providerID, userID, userInfo); err != nil {
		return false, err
	}
	if err := s.upsertIdentityLink(ctx, providerID, userID, userInfo); err != nil {
		return false, err
	}
	return true, nil
}

// upsertIdentityLink mirrors the link into user_identity_links, the table the
// "linked accounts" profile screen and the admin console read. Before this
// existed nothing ever inserted into it, so those screens were permanently
// empty even for users who had signed in through a provider.
func (s *Service) upsertIdentityLink(ctx context.Context, providerID, userID string, userInfo *SocialUserInfo) error {
	profile, err := json.Marshal(map[string]string{
		"display_name": userInfo.Name,
		"provider":     userInfo.Provider,
	})
	if err != nil {
		return err
	}

	var externalEmail, displayName *string
	if userInfo.Email != "" {
		e := userInfo.Email
		externalEmail = &e
	}
	if userInfo.Name != "" {
		n := userInfo.Name
		displayName = &n
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO user_identity_links
			(id, user_id, provider_id, external_id, external_email, external_username,
			 display_name, profile_data, is_primary, linked_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, NOW(), NOW())
		ON CONFLICT (provider_id, external_id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			external_email = EXCLUDED.external_email,
			external_username = EXCLUDED.external_username,
			display_name = EXCLUDED.display_name,
			profile_data = EXCLUDED.profile_data,
			last_used_at = NOW()
	`, uuid.New().String(), userID, providerID, userInfo.ID,
		externalEmail, externalEmail, displayName, profile)

	return err
}
