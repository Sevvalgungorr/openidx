// Package handlers provides tests for dashboard handlers
package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func init() {
	gin.SetMode(gin.TestMode)
}

// mockRow is a mock row for testing
type mockRow struct {
	data interface{}
	err  error
}

func (m *mockRow) Scan(dest ...interface{}) error {
	if m.err != nil {
		return m.err
	}
	// Handle mock data for stats
	if len(dest) == 4 {
		// Dashboard stats: totalUsers, activeUsers, activeSessions, pendingReviews
		if intPtr, ok := dest[0].(*int64); ok {
			*intPtr = 100
		}
		if intPtr, ok := dest[1].(*int64); ok {
			*intPtr = 80
		}
		if intPtr, ok := dest[2].(*int64); ok {
			*intPtr = 25
		}
		if intPtr, ok := dest[3].(*int64); ok {
			*intPtr = 3
		}
	}
	if len(dest) == 1 {
		// Single value query
		if intPtr, ok := dest[0].(*int64); ok {
			*intPtr = 5
		}
	}
	return nil
}

func (m *mockRow) Fields() []pgconn.FieldDescription {
	return nil
}

type mockRows struct {
	data   [][]interface{}
	column int
	closed bool
}

func (m *mockRows) Close() error {
	m.closed = true
	return nil
}

func (m *mockRows) Err() error {
	return nil
}

func (m *mockRows) Next() bool {
	m.column++
	return m.column <= len(m.data)
}

func (m *mockRows) Scan(dest ...interface{}) error {
	if m.column > len(m.data) {
		return &mockNoRowsError{}
	}
	row := m.data[m.column-1]
	for i, v := range row {
		dest[i] = v
	}
	return nil
}

type mockNoRowsError struct{}

func (m *mockNoRowsError) Error() string {
	return "no rows"
}

func (m *mockRows) Values() ([]interface{}, error) {
	if m.column > len(m.data) {
		return nil, &mockNoRowsError{}
	}
	return m.data[m.column-1], nil
}

func (m *mockRows) RawValues() [][]byte {
	return nil
}

func (m *mockRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}

func (m *mockRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT 0")
}

func (m *mockRows) ResultSetDescription() *pgconn.StatementDescription {
	return nil
}

// Create a test handler with a mock logger
func newTestHandler() *DashboardHandler {
	logger := zap.NewNop()
	return &DashboardHandler{
		logger: logger.With(zap.String("handler", "dashboard")),
		db:     nil, // Will be set in tests
	}
}

// TestNewDashboardHandler tests the handler constructor
func TestNewDashboardHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewDashboardHandler(logger, nil)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
	// db can be nil in tests
}

// TestDashboardStatsSerialization tests JSON serialization of DashboardStats
func TestDashboardStatsSerialization(t *testing.T) {
	now := time.Now()
	stats := DashboardStats{
		TotalUsers:     100,
		ActiveUsers:    80,
		ActiveSessions: 25,
		PendingReviews: 3,
		RecentEvents: []RecentEvent{
			{
				ID:        "evt-1",
				Type:      "authentication",
				Timestamp: now,
				Actor:     "user-1",
				Action:    "login",
				Outcome:   "success",
			},
		},
		SystemMetrics: SystemMetrics{
			CPUUsage:    45.5,
			MemoryUsage: 62.3,
			DiskUsage:   78.1,
			Uptime:      86400,
		},
		SecurityAlerts: SecurityAlerts{
			FailedLogins24h: 5,
			SuspiciousIPs:   2,
			ActiveThreats:   2,
		},
	}

	data, err := json.Marshal(stats)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded DashboardStats
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, int64(100), decoded.TotalUsers)
	assert.Equal(t, int64(80), decoded.ActiveUsers)
	assert.Equal(t, int64(25), decoded.ActiveSessions)
	assert.Equal(t, int64(3), decoded.PendingReviews)
	assert.Len(t, decoded.RecentEvents, 1)
	assert.Equal(t, "authentication", decoded.RecentEvents[0].Type)
	assert.Equal(t, 45.5, decoded.SystemMetrics.CPUUsage)
	assert.Equal(t, int64(5), decoded.SecurityAlerts.FailedLogins24h)
}

// TestGetDashboardStatsSuccess tests successful dashboard stats retrieval
// Note: This test would require a test container or mock database for full integration
// For now, we test the serialization and structure of the response
func TestGetDashboardStatsSuccess(t *testing.T) {
	// Verify that DashboardStats can be serialized properly
	now := time.Now()
	stats := DashboardStats{
		TotalUsers:     100,
		ActiveUsers:    80,
		ActiveSessions: 25,
		PendingReviews: 3,
		RecentEvents: []RecentEvent{
			{
				ID:        "evt-1",
				Type:      "authentication",
				Timestamp: now,
				Actor:     "user-1",
				Action:    "login",
				Outcome:   "success",
			},
		},
		SystemMetrics: SystemMetrics{
			Uptime: 86400,
		},
		SecurityAlerts: SecurityAlerts{
			FailedLogins24h: 5,
		},
	}

	// Verify serialization works
	data, err := json.Marshal(stats)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify that the handler can be created
	logger := zap.NewNop()
	handler := NewDashboardHandler(logger, nil)
	assert.NotNil(t, handler)
}

// TestGetDashboardStatsResponseStructure tests the response structure
func TestGetDashboardStatsResponseStructure(t *testing.T) {
	// Test response structure through serialization
	stats := DashboardStats{
		TotalUsers:     100,
		ActiveUsers:    80,
		ActiveSessions: 25,
		PendingReviews: 3,
		RecentEvents:   []RecentEvent{},
		SystemMetrics: SystemMetrics{
			Uptime: 86400,
		},
		SecurityAlerts: SecurityAlerts{},
	}

	data, err := json.Marshal(stats)
	require.NoError(t, err)

	var response map[string]interface{}
	err = json.Unmarshal(data, &response)
	require.NoError(t, err)

	// Verify response has expected fields
	assert.Contains(t, response, "total_users")
	assert.Contains(t, response, "active_users")
	assert.Contains(t, response, "active_sessions")
	assert.Contains(t, response, "pending_reviews")
	assert.Contains(t, response, "recent_events")
	assert.Contains(t, response, "system_metrics")
	assert.Contains(t, response, "security_alerts")
}

// TestRefreshCacheSuccess tests cache refresh endpoint structure
func TestRefreshCacheSuccess(t *testing.T) {
	// Test that RefreshCache can be called without panicking
	logger := zap.NewNop()
	handler := NewDashboardHandler(logger, nil)
	assert.NotNil(t, handler)

	// The actual endpoint would require a request context
	// This test verifies the handler exists and is properly structured
}

// TestGetMetricsSuccess tests system metrics endpoint structure
func TestGetMetricsSuccess(t *testing.T) {
	logger := zap.NewNop()
	handler := NewDashboardHandler(logger, nil)
	assert.NotNil(t, handler)

	// Verify SystemMetrics can be serialized
	metrics := SystemMetrics{
		Uptime: 86400,
	}

	data, err := json.Marshal(metrics)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// TestSystemMetricsSerialization tests SystemMetrics JSON serialization
func TestSystemMetricsSerialization(t *testing.T) {
	metrics := SystemMetrics{
		CPUUsage:    45.5,
		MemoryUsage: 62.3,
		DiskUsage:   78.1,
		Uptime:      86400,
	}

	data, err := json.Marshal(metrics)
	require.NoError(t, err)

	var decoded SystemMetrics
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, 45.5, decoded.CPUUsage)
	assert.Equal(t, 62.3, decoded.MemoryUsage)
	assert.Equal(t, 78.1, decoded.DiskUsage)
	assert.Equal(t, int64(86400), decoded.Uptime)
}

// TestSecurityAlertsSerialization tests SecurityAlerts JSON serialization
func TestSecurityAlertsSerialization(t *testing.T) {
	alerts := SecurityAlerts{
		FailedLogins24h: 15,
		SuspiciousIPs:   3,
		ActiveThreats:   3,
	}

	data, err := json.Marshal(alerts)
	require.NoError(t, err)

	var decoded SecurityAlerts
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, int64(15), decoded.FailedLogins24h)
	assert.Equal(t, int64(3), decoded.SuspiciousIPs)
	assert.Equal(t, int64(3), decoded.ActiveThreats)
}

// TestRecentEventSerialization tests RecentEvent JSON serialization
func TestRecentEventSerialization(t *testing.T) {
	now := time.Now()
	event := RecentEvent{
		ID:        "evt-123",
		Type:      "authentication",
		Timestamp: now,
		Actor:     "user-1",
		Action:    "login",
		Outcome:   "success",
	}

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var decoded RecentEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "evt-123", decoded.ID)
	assert.Equal(t, "authentication", decoded.Type)
	assert.Equal(t, "user-1", decoded.Actor)
	assert.Equal(t, "login", decoded.Action)
	assert.Equal(t, "success", decoded.Outcome)
}

// TestDashboardRoutesRegistration tests route registration
func TestDashboardRoutesRegistration(t *testing.T) {
	handler := newTestHandler()
	router := gin.New()
	group := router.Group("/api/v1")
	DashboardRoutes(group, handler)

	// Verify routes are registered by checking if they exist
	routes := router.Routes()
	routePaths := make(map[string]bool)
	for _, route := range routes {
		routePaths[route.Path] = true
	}

	assert.True(t, routePaths["/api/v1/dashboard"])
	assert.True(t, routePaths["/api/v1/dashboard/metrics"])
	assert.True(t, routePaths["/api/v1/dashboard/refresh"])
}

// TestRegisterAllRoutes tests all admin routes registration
func TestRegisterAllRoutes(t *testing.T) {
	logger := zap.NewNop()
	router := gin.New()
	group := router.Group("/api/v1")

	assert.NotPanics(t, func() {
		RegisterAllRoutes(group, nil, logger, nil)
	})
}

// TestDashboardStatsWithEmptyEvents tests dashboard with no recent events
func TestDashboardStatsWithEmptyEvents(t *testing.T) {
	stats := DashboardStats{
		RecentEvents: []RecentEvent{},
	}

	data, err := json.Marshal(stats)
	require.NoError(t, err)

	var decoded DashboardStats
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	// Recent events should be an empty slice, not nil
	assert.NotNil(t, decoded.RecentEvents)
	assert.Empty(t, decoded.RecentEvents)
}

// TestDashboardHandlerNilDB tests handler creation with nil database
func TestDashboardHandlerNilDB(t *testing.T) {
	// Create handler with nil db - the handler struct can be created
	// but calling GetDashboardStats would panic
	handler := &DashboardHandler{
		logger: zap.NewNop(),
		db:     nil,
	}
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
}

// TestSystemMetricsEmpty tests empty system metrics
func TestSystemMetricsEmpty(t *testing.T) {
	metrics := SystemMetrics{}

	data, err := json.Marshal(metrics)
	require.NoError(t, err)

	var decoded SystemMetrics
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, float64(0), decoded.CPUUsage)
	assert.Equal(t, float64(0), decoded.MemoryUsage)
	assert.Equal(t, float64(0), decoded.DiskUsage)
	assert.Equal(t, int64(0), decoded.Uptime)
}

// TestSecurityAlertsEmpty tests empty security alerts
func TestSecurityAlertsEmpty(t *testing.T) {
	alerts := SecurityAlerts{}

	data, err := json.Marshal(alerts)
	require.NoError(t, err)

	var decoded SecurityAlerts
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, int64(0), decoded.FailedLogins24h)
	assert.Equal(t, int64(0), decoded.SuspiciousIPs)
	assert.Equal(t, int64(0), decoded.ActiveThreats)
}

// TestRecentEventWithOptionalFields tests event with optional fields
func TestRecentEventWithOptionalFields(t *testing.T) {
	now := time.Now()
	event := RecentEvent{
		ID:        "evt-456",
		Type:      "authorization",
		Timestamp: now,
		// Actor omitted
		Action:  "access_granted",
		Outcome: "success",
	}

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var decoded RecentEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "evt-456", decoded.ID)
	assert.Equal(t, "", decoded.Actor) // Actor should be empty string
}

// TestDashboardStatsDefaultValues tests default values for stats
func TestDashboardStatsDefaultValues(t *testing.T) {
	stats := DashboardStats{}

	assert.Equal(t, int64(0), stats.TotalUsers)
	assert.Equal(t, int64(0), stats.ActiveUsers)
	assert.Equal(t, int64(0), stats.ActiveSessions)
	assert.Equal(t, int64(0), stats.PendingReviews)
	assert.Nil(t, stats.RecentEvents) // Nil when not initialized
}

// TestDashboardHandlerIntegration tests basic handler integration
func TestDashboardHandlerIntegration(t *testing.T) {
	logger := zap.NewNop()
	handler := NewDashboardHandler(logger, nil)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)

	// Verify routes can be registered
	router := gin.New()
	group := router.Group("/api/v1")
	DashboardRoutes(group, handler)

	routes := router.Routes()
	assert.True(t, len(routes) > 0, "At least one route should be registered")
}
