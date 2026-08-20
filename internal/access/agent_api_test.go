package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestAgentHandler returns an AgentAPIHandler suitable for unit tests.
func newTestAgentHandler() *AgentAPIHandler {
	logger := zap.NewNop()
	return NewAgentAPIHandler(logger, nil, nil, nil)
}

// TestAgentEnroll_ValidToken verifies that a POST to /agent/enroll with an
// Authorization header returns 200 and non-empty agent_id, device_id, auth_token.
func TestAgentEnroll_ValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	c.Request = req

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp enrollResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AgentID)
	assert.NotEmpty(t, resp.DeviceID)
	assert.NotEmpty(t, resp.AuthToken)
}

// TestAgentEnroll_MissingToken verifies that a request without Authorization
// returns 401.
func TestAgentEnroll_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestAgentReport_Accepted verifies that a POST to /agent/report with a JSON
// body is acknowledged with 202.
func TestAgentReport_Accepted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/report", handler.HandleReport)

	body, _ := json.Marshal(map[string]interface{}{
		"agent_id": "test-agent-id",
		"status":   "healthy",
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "test-agent-id")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
}

// TestAgentConfig_ReturnsDefaults verifies that a GET to /agent/config returns
// 200 with a checks array and report_interval field.
func TestAgentConfig_ReturnsDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/config", handler.HandleConfig)

	req := httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp agentConfigResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Checks)
	assert.Equal(t, 3, len(resp.Checks))
	assert.Equal(t, "30s", resp.ReportInterval) // baselinePollInterval
}

// TestAgentConfig_DefaultsWhenNoAgentID verifies that a GET to /agent/config
// without an X-Agent-ID header or agent_id query param returns the same
// default configuration as when the database is unavailable.
func TestAgentConfig_DefaultsWhenNoAgentID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	// Handler has no DB (nil), so fallback must apply regardless.
	handler := newTestAgentHandler()
	router.GET("/agent/config", handler.HandleConfig)

	// Request without X-Agent-ID header and without agent_id query param.
	req := httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp agentConfigResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Must return the three default checks.
	assert.Equal(t, 3, len(resp.Checks), "expected 3 default checks when no agent_id provided")
	assert.Equal(t, "30s", resp.ReportInterval) // baselinePollInterval
	assert.Equal(t, "monitor", resp.EnforcementPolicy)

	// Verify specific check names match the built-in defaults.
	names := make([]string, len(resp.Checks))
	for i, ch := range resp.Checks {
		names[i] = ch.Name
	}
	assert.Contains(t, names, "os_version")
	assert.Contains(t, names, "disk_encryption")
	assert.Contains(t, names, "process_running")
}

// TestAgentEnroll_ResponseFields verifies that a successful enroll response
// includes the status and enrolled_at fields in addition to the core identifiers.
func TestAgentEnroll_ResponseFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["agent_id"], "agent_id should be present")
	assert.NotEmpty(t, resp["device_id"], "device_id should be present")
	assert.NotEmpty(t, resp["auth_token"], "auth_token should be present")
	assert.NotEmpty(t, resp["status"], "status should be present")
	assert.NotEmpty(t, resp["enrolled_at"], "enrolled_at should be present")

	// In development mode (no real DB) status should be auto-approved to "active"
	assert.Equal(t, "active", resp["status"])
}

// TestAgentReport_ParsesResults verifies that a POST to /agent/report with a
// well-formed report body returns 202 with a compliance_score field.
func TestAgentReport_ParsesResults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/report", handler.HandleReport)

	report := map[string]interface{}{
		"agent_id":  "agent-abc123",
		"device_id": "device-def456",
		"results": []map[string]interface{}{
			{
				"check_type": "disk_encryption",
				"severity":   "critical",
				"ran_at":     "2026-03-29T00:00:00Z",
				"result": map[string]interface{}{
					"status":  "pass",
					"score":   1.0,
					"message": "FileVault enabled",
				},
			},
			{
				"check_type": "os_version",
				"severity":   "high",
				"ran_at":     "2026-03-29T00:00:00Z",
				"result": map[string]interface{}{
					"status":  "pass",
					"score":   0.9,
					"message": "OS up to date",
				},
			},
		},
	}

	body, err := json.Marshal(report)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "agent-abc123")

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusAccepted, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "accepted", resp["status"])
	score, ok := resp["compliance_score"].(float64)
	require.True(t, ok, "compliance_score should be a float64")
	// critical(weight=4)*1.0 + high(weight=3)*0.9 = 4.0+2.7=6.7 / 7 ≈ 0.957
	assert.InDelta(t, 6.7/7.0, score, 0.001)

	actions, ok := resp["enforcement_actions"].([]interface{})
	require.True(t, ok, "enforcement_actions should be an array")
	assert.Len(t, actions, 2)
}

// TestGracePeriodEnforcer_NoDBNoPanic verifies that enforceExpiredGracePeriods
// does not panic when the handler has no database connection.
func TestGracePeriodEnforcer_NoDBNoPanic(t *testing.T) {
	handler := newTestAgentHandler()
	// Should not panic with nil DB
	handler.enforceExpiredGracePeriods(context.Background())
}

// TestHandleListAgents_EmptyDB verifies that GET /agent/list returns 200 with an
// empty JSON array when no database is configured.
func TestHandleListAgents_EmptyDB(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/list", handler.HandleListAgents)

	req := httptest.NewRequest(http.MethodGet, "/agent/list", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp, "expected empty array when DB is nil")
}

// TestHandleRevokeAgent verifies that POST /agent/:agent_id/revoke returns 200
// on the nil-DB path.
func TestHandleRevokeAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/:agent_id/revoke", handler.HandleRevokeAgent)

	req := httptest.NewRequest(http.MethodPost, "/agent/agent-abc123/revoke", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "revoked", resp["status"])
	assert.Equal(t, "agent-abc123", resp["agent_id"])
}

// TestHandleApproveAgent verifies that POST /agent/:agent_id/approve returns 200
// on the nil-DB path.
func TestHandleApproveAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/:agent_id/approve", handler.HandleApproveAgent)

	req := httptest.NewRequest(http.MethodPost, "/agent/agent-abc123/approve", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "active", resp["status"])
	assert.Equal(t, "agent-abc123", resp["agent_id"])
}

// TestRegisterAgentRoutes verifies that all three routes are registered and
// respond to the correct HTTP methods.
func TestRegisterAgentRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := newTestAgentHandler()
	group := router.Group("/")
	handler.RegisterAgentRoutes(group)

	// /agent/enroll — requires Authorization header
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer tok")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// /agent/report
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/agent/report", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// /agent/config
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestHandleGenerateToken_NilDB verifies that HandleGenerateToken returns 200
// with a plaintext token, id, and expires_at even when no database is configured.
func TestHandleGenerateToken_NilDB(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/tokens", handler.HandleGenerateToken)

	body, _ := json.Marshal(map[string]string{
		"description": "test token",
		"created_by":  "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["token"], "plaintext token must be returned")
	assert.NotEmpty(t, resp["id"], "token id must be returned")
	assert.NotEmpty(t, resp["expires_at"], "expires_at must be returned")
}

// TestHandleGenerateToken_NoBody verifies that HandleGenerateToken works with an
// empty request body (all fields optional).
func TestHandleGenerateToken_NoBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/tokens", handler.HandleGenerateToken)

	req := httptest.NewRequest(http.MethodPost, "/agent/tokens", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["token"])
}

// TestHandleListTokens_NilDB verifies that GET /agent/tokens returns 200 with
// an empty array when no database is configured.
func TestHandleListTokens_NilDB(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/tokens", handler.HandleListTokens)

	req := httptest.NewRequest(http.MethodGet, "/agent/tokens", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp, "expected empty array when DB is nil")
}

// TestHandleRevokeToken_NilDB verifies that DELETE /agent/tokens/:token_id
// returns 200 on the nil-DB path.
func TestHandleRevokeToken_NilDB(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.DELETE("/agent/tokens/:token_id", handler.HandleRevokeToken)

	req := httptest.NewRequest(http.MethodDelete, "/agent/tokens/some-uuid", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "revoked", resp["status"])
	assert.Equal(t, "some-uuid", resp["id"])
}

// TestHandleRevokeToken_MissingID verifies that DELETE /agent/tokens/ without a
// token_id param returns 404 (route not matched).
func TestHandleRevokeToken_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.DELETE("/agent/tokens/:token_id", handler.HandleRevokeToken)

	// Request to a path that does not match the :token_id wildcard.
	req := httptest.NewRequest(http.MethodDelete, "/agent/tokens/", nil)
	router.ServeHTTP(w, req)

	// Gin returns 301 redirect or 404 when trailing slash does not match.
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusMovedPermanently,
		"expected 404 or 301, got %d", w.Code)
}

// TestAgentEnrollDevMode verifies that HandleEnroll succeeds with nil DB
// (dev/fallback mode) without token validation.
func TestAgentEnrollDevMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler() // nil DB
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer any-token-works-in-dev")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "active", resp["status"], "dev mode should auto-approve enrollment")
}
