package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DeveloperSettings holds global developer-facing configuration
type DeveloperSettings struct {
	APIKeyMaxPerUser    int      `json:"api_key_max_per_user"`
	APIKeyDefaultExpiry string   `json:"api_key_default_expiry"`
	APIKeyAllowedScopes []string `json:"api_key_allowed_scopes"`
	WebhookIPAllowlist  []string `json:"webhook_ip_allowlist"`
	WebhookMaxRetries   int      `json:"webhook_max_retries"`
	CORSAllowedOrigins  []string `json:"cors_allowed_origins"`
	RateLimitDefault    int      `json:"rate_limit_default"`
	SandboxEnabled      bool     `json:"sandbox_enabled"`
}

// APIEndpointInfo describes a single API endpoint in the catalog
type APIEndpointInfo struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Service     string   `json:"service"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes,omitempty"`
	Category    string   `json:"category"`
}

// CodeSample holds a code example in a specific language
type CodeSample struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

// PlaygroundSession represents an OAuth playground session
type PlaygroundSession struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	CodeVerifier  string    `json:"code_verifier"`
	CodeChallenge string    `json:"code_challenge"`
	RedirectURI   string    `json:"redirect_uri"`
	ClientID      string    `json:"client_id"`
	Scopes        string    `json:"scopes"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// PlaygroundExecRequest is the body for executing an OAuth playground step
type PlaygroundExecRequest struct {
	SessionID string `json:"session_id"`
	Step      string `json:"step"` // authorize, token, userinfo
	// Optional fields for token step
	Code string `json:"code,omitempty"`
	// Optional fields for userinfo step
	AccessToken string `json:"access_token,omitempty"`
}

// PlaygroundExecResult holds the result of an OAuth playground step execution
type PlaygroundExecResult struct {
	Step       string      `json:"step"`
	Success    bool        `json:"success"`
	StatusCode int         `json:"status_code,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       interface{} `json:"body,omitempty"`
	Error      string      `json:"error,omitempty"`
	URL        string      `json:"url,omitempty"`
}

// defaultDeveloperSettings returns sensible defaults when no settings exist
func defaultDeveloperSettings() *DeveloperSettings {
	return &DeveloperSettings{
		APIKeyMaxPerUser:    5,
		APIKeyDefaultExpiry: "90d",
		APIKeyAllowedScopes: []string{
			"read:users", "write:users",
			"read:groups", "write:groups",
			"read:applications", "write:applications",
			"read:audit", "read:governance",
			"read:provisioning", "write:provisioning",
		},
		WebhookIPAllowlist: []string{},
		WebhookMaxRetries:  3,
		CORSAllowedOrigins: []string{"http://localhost:3000"},
		RateLimitDefault:   100,
		SandboxEnabled:     false,
	}
}

// handleGetDeveloperSettings returns global developer settings
func (s *Service) handleGetDeveloperSettings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	var valueBytes []byte
	err := s.db.Pool.QueryRow(ctx,
		"SELECT setting_value FROM developer_settings WHERE setting_key = 'global'").Scan(&valueBytes)

	if err != nil {
		// Return defaults when no row exists
		s.logger.Debug("No developer settings found, returning defaults", zap.Error(err))
		c.JSON(http.StatusOK, defaultDeveloperSettings())
		return
	}

	var settings DeveloperSettings
	if err := json.Unmarshal(valueBytes, &settings); err != nil {
		s.logger.Error("Failed to unmarshal developer settings", zap.Error(err))
		c.JSON(http.StatusOK, defaultDeveloperSettings())
		return
	}

	c.JSON(http.StatusOK, settings)
}

// handleUpdateDeveloperSettings upserts global developer settings
func (s *Service) handleUpdateDeveloperSettings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var settings DeveloperSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valueBytes, err := json.Marshal(&settings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal settings"})
		return
	}

	ctx := c.Request.Context()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO developer_settings (setting_key, setting_value, updated_at)
		VALUES ('global', $1, NOW())
		ON CONFLICT (setting_key) DO UPDATE SET setting_value = $1, updated_at = NOW()
	`, valueBytes)
	if err != nil {
		s.logger.Error("Failed to upsert developer settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save developer settings"})
		return
	}

	c.JSON(http.StatusOK, settings)
}

// handleListAPIEndpoints returns the full API endpoint catalog grouped by service
func (s *Service) handleListAPIEndpoints(c *gin.Context) {
	catalog := buildAPIEndpointCatalog()

	// Optionally filter by service
	serviceFilter := c.Query("service")
	categoryFilter := c.Query("category")

	if serviceFilter != "" || categoryFilter != "" {
		var filtered []APIEndpointInfo
		for _, ep := range catalog {
			if serviceFilter != "" && ep.Service != serviceFilter {
				continue
			}
			if categoryFilter != "" && ep.Category != categoryFilter {
				continue
			}
			filtered = append(filtered, ep)
		}
		catalog = filtered
	}

	// Group by service for response
	grouped := make(map[string][]APIEndpointInfo)
	for _, ep := range catalog {
		grouped[ep.Service] = append(grouped[ep.Service], ep)
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     len(catalog),
		"endpoints": grouped,
	})
}

// handleGetCodeSamples returns code samples for a given endpoint
func (s *Service) handleGetCodeSamples(c *gin.Context) {
	endpoint := c.Query("endpoint")
	method := strings.ToUpper(c.DefaultQuery("method", "GET"))

	if endpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "endpoint query parameter is required"})
		return
	}

	baseURL := "https://api.example.com"
	samples := generateCodeSamples(method, endpoint, baseURL)

	c.JSON(http.StatusOK, gin.H{
		"method":   method,
		"endpoint": endpoint,
		"samples":  samples,
	})
}

// handleCreatePlaygroundSession creates a new OAuth playground session with PKCE parameters
func (s *Service) handleCreatePlaygroundSession(c *gin.Context) {
	var req struct {
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
		Scopes      string `json:"scopes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ClientID == "" {
		req.ClientID = "playground-client"
	}
	if req.RedirectURI == "" {
		req.RedirectURI = "http://localhost:3000/developer/oauth/callback"
	}
	if req.Scopes == "" {
		req.Scopes = "openid profile email"
	}

	// Generate PKCE parameters
	state, err := generateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}

	codeVerifier, err := generateRandomString(64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate code verifier"})
		return
	}

	codeChallenge := generateCodeChallenge(codeVerifier)

	session := PlaygroundSession{
		ID:            uuid.New().String(),
		State:         state,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		RedirectURI:   req.RedirectURI,
		ClientID:      req.ClientID,
		Scopes:        req.Scopes,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(15 * time.Minute),
	}

	ctx := c.Request.Context()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_playground_sessions (id, state, code_verifier, code_challenge,
			redirect_uri, client_id, scopes, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, session.ID, session.State, session.CodeVerifier, session.CodeChallenge,
		session.RedirectURI, session.ClientID, session.Scopes, session.CreatedAt, session.ExpiresAt)

	if err != nil {
		s.logger.Error("Failed to create playground session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create playground session"})
		return
	}

	c.JSON(http.StatusCreated, session)
}

// handleExecutePlayground executes an OAuth playground step
func (s *Service) handleExecutePlayground(c *gin.Context) {
	var req PlaygroundExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}

	ctx := c.Request.Context()

	// Load session
	var session PlaygroundSession
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, state, code_verifier, code_challenge, redirect_uri, client_id, scopes, created_at, expires_at
		FROM oauth_playground_sessions
		WHERE id = $1
	`, req.SessionID).Scan(
		&session.ID, &session.State, &session.CodeVerifier, &session.CodeChallenge,
		&session.RedirectURI, &session.ClientID, &session.Scopes,
		&session.CreatedAt, &session.ExpiresAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "playground session not found"})
		return
	}

	if time.Now().After(session.ExpiresAt) {
		c.JSON(http.StatusGone, gin.H{"error": "playground session has expired"})
		return
	}

	var result PlaygroundExecResult
	result.Step = req.Step

	switch req.Step {
	case "authorize":
		result = s.executePlaygroundAuthorize(session)
	case "token":
		result = s.executePlaygroundToken(session, req.Code)
	case "userinfo":
		result = s.executePlaygroundUserinfo(req.AccessToken)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid step, must be: authorize, token, or userinfo"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// executePlaygroundAuthorize builds the authorization URL
func (s *Service) executePlaygroundAuthorize(session PlaygroundSession) PlaygroundExecResult {
	oauthBaseURL := "http://localhost:8006"
	if s.config != nil {
		if s.config.OAuthIssuer != "" {
			oauthBaseURL = s.config.OAuthIssuer
		}
	}

	authURL := fmt.Sprintf(
		"%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		oauthBaseURL,
		session.ClientID,
		session.RedirectURI,
		strings.ReplaceAll(session.Scopes, " ", "+"),
		session.State,
		session.CodeChallenge,
	)

	return PlaygroundExecResult{
		Step:    "authorize",
		Success: true,
		URL:     authURL,
		Body: gin.H{
			"authorization_url": authURL,
			"state":             session.State,
			"code_challenge":    session.CodeChallenge,
			"method":            "S256",
			"instructions":      "Open this URL in a browser to authenticate. After consent, you will be redirected with an authorization code.",
		},
	}
}

// executePlaygroundToken exchanges the authorization code for tokens
func (s *Service) executePlaygroundToken(session PlaygroundSession, code string) PlaygroundExecResult {
	if code == "" {
		return PlaygroundExecResult{
			Step:    "token",
			Success: false,
			Error:   "authorization code is required for the token step",
		}
	}

	oauthBaseURL := "http://localhost:8006"
	if s.config != nil {
		if s.config.OAuthIssuer != "" {
			oauthBaseURL = s.config.OAuthIssuer
		}
	}

	tokenURL := fmt.Sprintf("%s/oauth/token", oauthBaseURL)

	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {session.RedirectURI},
		"client_id":     {session.ClientID},
		"code_verifier": {session.CodeVerifier},
	}.Encode()

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		return PlaygroundExecResult{
			Step:    "token",
			Success: false,
			Error:   fmt.Sprintf("token request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	var tokenResp interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return PlaygroundExecResult{
			Step:       "token",
			Success:    false,
			StatusCode: resp.StatusCode,
			Error:      fmt.Sprintf("failed to parse token response: %v", err),
		}
	}

	return PlaygroundExecResult{
		Step:       "token",
		Success:    resp.StatusCode == http.StatusOK,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       tokenResp,
	}
}

// executePlaygroundUserinfo calls the userinfo endpoint with the access token
func (s *Service) executePlaygroundUserinfo(accessToken string) PlaygroundExecResult {
	if accessToken == "" {
		return PlaygroundExecResult{
			Step:    "userinfo",
			Success: false,
			Error:   "access_token is required for the userinfo step",
		}
	}

	oauthBaseURL := "http://localhost:8006"
	if s.config != nil {
		if s.config.OAuthIssuer != "" {
			oauthBaseURL = s.config.OAuthIssuer
		}
	}

	userinfoURL := fmt.Sprintf("%s/oauth/userinfo", oauthBaseURL)

	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return PlaygroundExecResult{
			Step:    "userinfo",
			Success: false,
			Error:   fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return PlaygroundExecResult{
			Step:    "userinfo",
			Success: false,
			Error:   fmt.Sprintf("userinfo request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	var userinfoResp interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userinfoResp); err != nil {
		return PlaygroundExecResult{
			Step:       "userinfo",
			Success:    false,
			StatusCode: resp.StatusCode,
			Error:      fmt.Sprintf("failed to parse userinfo response: %v", err),
		}
	}

	return PlaygroundExecResult{
		Step:       "userinfo",
		Success:    resp.StatusCode == http.StatusOK,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       userinfoResp,
	}
}

// generateRandomString produces a URL-safe random string of the given byte length
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge produces an S256 PKCE code challenge from a code verifier
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateCodeSamples returns code samples in curl, JavaScript, Go, and Python
func generateCodeSamples(method, endpoint, baseURL string) []CodeSample {
	fullURL := baseURL + endpoint

	curlSample := generateCurlSample(method, fullURL)
	jsSample := generateJSSample(method, fullURL)
	goSample := generateGoSample(method, fullURL)
	pythonSample := generatePythonSample(method, fullURL)

	return []CodeSample{
		{Language: "curl", Code: curlSample},
		{Language: "javascript", Code: jsSample},
		{Language: "go", Code: goSample},
		{Language: "python", Code: pythonSample},
	}
}

func generateCurlSample(method, url string) string {
	switch method {
	case "GET":
		return fmt.Sprintf(`curl -X GET '%s' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  -H 'Content-Type: application/json'`, url)
	case "POST":
		return fmt.Sprintf(`curl -X POST '%s' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "value"
  }'`, url)
	case "PUT":
		return fmt.Sprintf(`curl -X PUT '%s' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "value"
  }'`, url)
	case "DELETE":
		return fmt.Sprintf(`curl -X DELETE '%s' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'`, url)
	default:
		return fmt.Sprintf(`curl -X %s '%s' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'`, method, url)
	}
}

func generateJSSample(method, url string) string {
	if method == "GET" || method == "DELETE" {
		return fmt.Sprintf(`const response = await fetch('%s', {
  method: '%s',
  headers: {
    'Authorization': 'Bearer YOUR_ACCESS_TOKEN',
    'Content-Type': 'application/json',
  },
});

const data = await response.json();
console.log(data);`, url, method)
	}

	return fmt.Sprintf(`const response = await fetch('%s', {
  method: '%s',
  headers: {
    'Authorization': 'Bearer YOUR_ACCESS_TOKEN',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    key: 'value',
  }),
});

const data = await response.json();
console.log(data);`, url, method)
}

func generateGoSample(method, url string) string {
	if method == "GET" || method == "DELETE" {
		return fmt.Sprintf(`package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	req, err := http.NewRequest("%s", "%s", nil)
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authorization", "Bearer YOUR_ACCESS_TOKEN")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}`, method, url)
	}

	return fmt.Sprintf(`package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func main() {
	payload := map[string]interface{}{
		"key": "value",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("%s", "%s", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authorization", "Bearer YOUR_ACCESS_TOKEN")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println(string(respBody))
}`, method, url)
}

func generatePythonSample(method, url string) string {
	if method == "GET" || method == "DELETE" {
		return fmt.Sprintf(`import requests

headers = {
    'Authorization': 'Bearer YOUR_ACCESS_TOKEN',
    'Content-Type': 'application/json',
}

response = requests.%s('%s', headers=headers)
print(response.json())`, strings.ToLower(method), url)
	}

	return fmt.Sprintf(`import requests

headers = {
    'Authorization': 'Bearer YOUR_ACCESS_TOKEN',
    'Content-Type': 'application/json',
}

payload = {
    'key': 'value',
}

response = requests.%s('%s', headers=headers, json=payload)
print(response.json())`, strings.ToLower(method), url)
}

// buildAPIEndpointCatalog returns the full catalog of known API endpoints
func buildAPIEndpointCatalog() []APIEndpointInfo {
	return []APIEndpointInfo{
		// Identity Service
		{Method: "GET", Path: "/api/v1/identity/users", Service: "identity", Description: "List all users with pagination", Scopes: []string{"read:users"}, Category: "users"},
		{Method: "POST", Path: "/api/v1/identity/users", Service: "identity", Description: "Create a new user", Scopes: []string{"write:users"}, Category: "users"},
		{Method: "GET", Path: "/api/v1/identity/users/:id", Service: "identity", Description: "Get a user by ID", Scopes: []string{"read:users"}, Category: "users"},
		{Method: "PUT", Path: "/api/v1/identity/users/:id", Service: "identity", Description: "Update a user", Scopes: []string{"write:users"}, Category: "users"},
		{Method: "DELETE", Path: "/api/v1/identity/users/:id", Service: "identity", Description: "Delete a user", Scopes: []string{"write:users"}, Category: "users"},
		{Method: "GET", Path: "/api/v1/identity/users/:id/sessions", Service: "identity", Description: "List sessions for a user", Scopes: []string{"read:users"}, Category: "users"},
		{Method: "GET", Path: "/api/v1/identity/groups", Service: "identity", Description: "List all groups", Scopes: []string{"read:groups"}, Category: "groups"},
		{Method: "POST", Path: "/api/v1/identity/groups", Service: "identity", Description: "Create a new group", Scopes: []string{"write:groups"}, Category: "groups"},
		{Method: "GET", Path: "/api/v1/identity/groups/:id", Service: "identity", Description: "Get a group by ID", Scopes: []string{"read:groups"}, Category: "groups"},
		{Method: "PUT", Path: "/api/v1/identity/groups/:id", Service: "identity", Description: "Update a group", Scopes: []string{"write:groups"}, Category: "groups"},
		{Method: "DELETE", Path: "/api/v1/identity/groups/:id", Service: "identity", Description: "Delete a group", Scopes: []string{"write:groups"}, Category: "groups"},

		// Governance Service
		{Method: "GET", Path: "/api/v1/governance/reviews", Service: "governance", Description: "List access reviews", Scopes: []string{"read:governance"}, Category: "reviews"},
		{Method: "POST", Path: "/api/v1/governance/reviews", Service: "governance", Description: "Create an access review campaign", Scopes: []string{"write:governance"}, Category: "reviews"},
		{Method: "GET", Path: "/api/v1/governance/reviews/:id", Service: "governance", Description: "Get access review details", Scopes: []string{"read:governance"}, Category: "reviews"},
		{Method: "POST", Path: "/api/v1/governance/reviews/:id/items/:itemId/decision", Service: "governance", Description: "Submit a review decision", Scopes: []string{"write:governance"}, Category: "reviews"},
		{Method: "GET", Path: "/api/v1/governance/policies", Service: "governance", Description: "List governance policies", Scopes: []string{"read:governance"}, Category: "policies"},
		{Method: "POST", Path: "/api/v1/governance/policies", Service: "governance", Description: "Create a governance policy", Scopes: []string{"write:governance"}, Category: "policies"},

		// Provisioning Service (SCIM 2.0)
		{Method: "GET", Path: "/scim/v2/Users", Service: "provisioning", Description: "List users (SCIM)", Scopes: []string{"read:provisioning"}, Category: "scim"},
		{Method: "POST", Path: "/scim/v2/Users", Service: "provisioning", Description: "Create user (SCIM)", Scopes: []string{"write:provisioning"}, Category: "scim"},
		{Method: "GET", Path: "/scim/v2/Users/:id", Service: "provisioning", Description: "Get user (SCIM)", Scopes: []string{"read:provisioning"}, Category: "scim"},
		{Method: "PUT", Path: "/scim/v2/Users/:id", Service: "provisioning", Description: "Replace user (SCIM)", Scopes: []string{"write:provisioning"}, Category: "scim"},
		{Method: "PATCH", Path: "/scim/v2/Users/:id", Service: "provisioning", Description: "Patch user (SCIM)", Scopes: []string{"write:provisioning"}, Category: "scim"},
		{Method: "GET", Path: "/scim/v2/Groups", Service: "provisioning", Description: "List groups (SCIM)", Scopes: []string{"read:provisioning"}, Category: "scim"},
		{Method: "POST", Path: "/scim/v2/Groups", Service: "provisioning", Description: "Create group (SCIM)", Scopes: []string{"write:provisioning"}, Category: "scim"},
		{Method: "GET", Path: "/scim/v2/ServiceProviderConfig", Service: "provisioning", Description: "SCIM service provider configuration", Scopes: nil, Category: "scim"},

		// Audit Service
		{Method: "GET", Path: "/api/v1/audit/events", Service: "audit", Description: "Query audit events with filters", Scopes: []string{"read:audit"}, Category: "audit"},
		{Method: "POST", Path: "/api/v1/audit/reports", Service: "audit", Description: "Generate a compliance report", Scopes: []string{"read:audit"}, Category: "reports"},
		{Method: "GET", Path: "/api/v1/audit/statistics", Service: "audit", Description: "Get audit statistics", Scopes: []string{"read:audit"}, Category: "audit"},

		// Admin API
		{Method: "GET", Path: "/api/v1/dashboard", Service: "admin", Description: "Get dashboard statistics", Scopes: []string{"read:admin"}, Category: "dashboard"},
		{Method: "GET", Path: "/api/v1/settings", Service: "admin", Description: "Get system settings", Scopes: []string{"read:admin"}, Category: "settings"},
		{Method: "PUT", Path: "/api/v1/settings", Service: "admin", Description: "Update system settings", Scopes: []string{"write:admin"}, Category: "settings"},
		{Method: "GET", Path: "/api/v1/applications", Service: "admin", Description: "List registered applications", Scopes: []string{"read:applications"}, Category: "applications"},
		{Method: "POST", Path: "/api/v1/applications", Service: "admin", Description: "Register a new application", Scopes: []string{"write:applications"}, Category: "applications"},

		// OAuth Service
		{Method: "GET", Path: "/oauth/authorize", Service: "oauth", Description: "OAuth 2.0 authorization endpoint", Scopes: nil, Category: "oauth"},
		{Method: "POST", Path: "/oauth/token", Service: "oauth", Description: "OAuth 2.0 token endpoint", Scopes: nil, Category: "oauth"},
		{Method: "GET", Path: "/oauth/userinfo", Service: "oauth", Description: "OpenID Connect userinfo endpoint", Scopes: nil, Category: "oauth"},
		{Method: "GET", Path: "/.well-known/openid-configuration", Service: "oauth", Description: "OpenID Connect discovery document", Scopes: nil, Category: "oauth"},
		{Method: "GET", Path: "/.well-known/jwks.json", Service: "oauth", Description: "JSON Web Key Set endpoint", Scopes: nil, Category: "oauth"},
	}
}
