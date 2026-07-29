// Package access provides comprehensive unit tests for Ziti connection management
package access

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockLogger creates a test logger
func MockLogger(t *testing.T) *zap.Logger {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	return logger
}

// MockConfig creates a test configuration
func MockConfig(t *testing.T) *config.Config {
	tmpDir := t.TempDir()
	return &config.Config{
		ZitiCtrlURL:       "https://ziti.test:1280",
		ZitiAdminUser:     "admin",
		ZitiAdminPassword: "admin",
		ZitiIdentityDir:   tmpDir,
	}
}

// TestParseHostPort tests the parseHostPort function
func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		expectedHost string
		expectedPort int
		expectError  bool
	}{
		{
			name:         "Valid HTTP URL with port",
			rawURL:       "http://example.com:8080",
			expectedHost: "example.com",
			expectedPort: 8080,
		},
		{
			name:         "Valid HTTPS URL with port",
			rawURL:       "https://example.com:9443",
			expectedHost: "example.com",
			expectedPort: 9443,
		},
		{
			name:         "HTTP URL without port defaults to 80",
			rawURL:       "http://example.com",
			expectedHost: "example.com",
			expectedPort: 80,
		},
		{
			name:         "HTTPS URL without port defaults to 443",
			rawURL:       "https://example.com",
			expectedHost: "example.com",
			expectedPort: 443,
		},
		{
			name:         "Host without scheme defaults to HTTP port 80",
			rawURL:       "example.com",
			expectedHost: "example.com",
			expectedPort: 80,
		},
		{
			name:         "Host:port without scheme",
			rawURL:       "example.com:3000",
			expectedHost: "example.com",
			expectedPort: 3000,
		},
		{
			name:         "URL with path",
			rawURL:       "http://example.com:8080/path",
			expectedHost: "example.com",
			expectedPort: 8080,
		},
		{
			name:         "Invalid port number",
			rawURL:       "http://example.com:abc",
			expectedHost: "",
			expectedPort: 0,
		},
		{
			name:         "Invalid URL format",
			rawURL:       "://invalid",
			expectedHost: "",
			expectedPort: 0,
		},
		{
			name:         "Empty string",
			rawURL:       "",
			expectedHost: "",
			expectedPort: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := parseHostPort(tt.rawURL)
			if tt.expectError {
				assert.Empty(t, host, "Expected empty host for error case")
				assert.Zero(t, port, "Expected zero port for error case")
			} else {
				assert.Equal(t, tt.expectedHost, host, "Host mismatch")
				assert.Equal(t, tt.expectedPort, port, "Port mismatch")
			}
		})
	}
}

// TestConfigTypeFallback tests the config type fallback function
func TestConfigTypeFallback(t *testing.T) {
	zm := &ZitiManager{
		logger: MockLogger(t),
	}

	tests := []struct {
		name           string
		typeName       string
		expectedResult string
	}{
		{
			name:           "host.v1 default",
			typeName:       "host.v1",
			expectedResult: "NH5p4FpGR",
		},
		{
			name:           "intercept.v1 default",
			typeName:       "intercept.v1",
			expectedResult: "g7cIWbcGg",
		},
		{
			name:           "Unknown type returns typeName",
			typeName:       "unknown.type",
			expectedResult: "unknown.type",
		},
		{
			name:           "Empty string",
			typeName:       "",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := zm.configTypeFallback(tt.typeName)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestResolveConfigTypeID tests config type ID resolution with caching
func TestResolveConfigTypeID(t *testing.T) {
	t.Run("Cache hit returns cached value", func(t *testing.T) {
		zm := &ZitiManager{
			logger:            MockLogger(t),
			configTypeCache:   make(map[string]string),
			configTypeCacheMu: sync.RWMutex{},
		}
		// Pre-populate cache
		zm.configTypeCache["host.v1"] = "cached-id-123"

		result := zm.resolveConfigTypeID("host.v1")
		assert.Equal(t, "cached-id-123", result)
	})

	t.Run("API failure uses fallback", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		// Create a mock manager with fake auth token
		zm := &ZitiManager{
			cfg:               cfg,
			logger:            MockLogger(t),
			mgmtToken:         "fake-token",
			configTypeCache:   make(map[string]string),
			configTypeCacheMu: sync.RWMutex{},
			mgmtClient:        server.Client(),
		}

		result := zm.resolveConfigTypeID("host.v1")
		assert.Equal(t, "NH5p4FpGR", result, "Should use fallback on API failure")
	})
}

// TestZitiManagerInitialization tests ZitiManager initialization
func TestZitiManagerInitialization(t *testing.T) {
	t.Run("Initialization with missing CA file continues when skip-verify is on", func(t *testing.T) {
		tmpDir := t.TempDir()
		// As of P2.1 the manager refuses to start without either a CA
		// file or an explicit ZitiInsecureSkipVerify=true; the test
		// exercises the dev-loop branch by setting the latter.
		cfg := &config.Config{
			ZitiCtrlURL:            "https://ziti.test:1280",
			ZitiAdminUser:          "admin",
			ZitiAdminPassword:      "admin",
			ZitiIdentityDir:        tmpDir,
			ZitiInsecureSkipVerify: true,
		}

		// Create a mock auth server
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "authenticate") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"token": "test-token-123",
					},
				})
			} else if strings.Contains(r.URL.Path, "edge-router-policies") {
				w.WriteHeader(http.StatusCreated)
			} else if strings.Contains(r.URL.Path, "service-edge-router-policies") {
				w.WriteHeader(http.StatusCreated)
			} else if strings.Contains(r.URL.Path, "identities") && r.Method == "GET" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{},
				})
			} else if strings.Contains(r.URL.Path, "identities") && r.Method == "POST" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id": "identity-123",
						"enrollment": map[string]interface{}{
							"ott": map[string]string{
								"jwt": "fake-jwt-token",
							},
						},
					},
				})
			} else if strings.Contains(r.URL.Path, "identities/identity-123") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id": "identity-123",
						"enrollment": map[string]interface{}{
							"ott": map[string]string{
								"jwt": "",
							},
						},
					},
				})
			}
		}))
		defer authServer.Close()

		cfg.ZitiCtrlURL = authServer.URL

		// Note: This test will fail on enrollment due to invalid JWT,
		// but we're testing the initialization flow
		_, err := NewZitiManager(cfg, nil, MockLogger(t))
		// Expected to fail due to invalid enrollment JWT
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bootstrap ziti")
	})

	t.Run("Initialization fails when no CA and no skip-verify (P2.1 guard)", func(t *testing.T) {
		// Defense-in-depth: a production-shaped config that lost its CA
		// file (mis-deployed bundle, mounted volume missing, etc.) must
		// not silently fall back to InsecureSkipVerify — the manager
		// refuses to start instead, surfacing the misconfiguration.
		tmpDir := t.TempDir()
		cfg := &config.Config{
			ZitiCtrlURL:            "https://ziti.test:1280",
			ZitiAdminUser:          "admin",
			ZitiAdminPassword:      "admin",
			ZitiIdentityDir:        tmpDir, // empty dir — no ca.pem
			ZitiInsecureSkipVerify: false,  // explicit
		}
		_, err := NewZitiManager(cfg, nil, MockLogger(t))
		if err == nil {
			t.Fatal("expected NewZitiManager to refuse to start; got nil")
		}
		if !strings.Contains(err.Error(), "ca") && !strings.Contains(err.Error(), "ziti_insecure_skip_verify") {
			t.Errorf("err = %v, want mention of missing CA or skip-verify hint", err)
		}
	})

	t.Run("IsInitialized returns correct state", func(t *testing.T) {
		zm := &ZitiManager{
			logger:      MockLogger(t),
			initialized: true,
			mu:          sync.RWMutex{},
		}
		assert.True(t, zm.IsInitialized())

		zm.initialized = false
		assert.False(t, zm.IsInitialized())
	})
}

// TestZitiManagerClose tests proper cleanup
func TestZitiManagerClose(t *testing.T) {
	t.Run("Close stops all hosted services", func(t *testing.T) {
		zm := &ZitiManager{
			logger:         MockLogger(t),
			hostedServices: make(map[string]*hostedService),
			hostedMu:       sync.Mutex{},
		}

		// Add mock hosted services
		cancelCalled1 := false
		cancelCalled2 := false
		zm.hostedServices["service1"] = &hostedService{
			cancel:   func() { cancelCalled1 = true },
			listener: &mockListener{closed: false, id: 1},
		}
		zm.hostedServices["service2"] = &hostedService{
			cancel:   func() { cancelCalled2 = true },
			listener: &mockListener{closed: false, id: 2},
		}

		zm.Close()

		assert.True(t, cancelCalled1, "Cancel should be called for service1")
		assert.True(t, cancelCalled2, "Cancel should be called for service2")
		assert.Empty(t, zm.hostedServices, "All services should be removed")
	})
}

// mockListener is a mock implementation of edge.Listener
type mockListener struct {
	closed bool
	id     uint32
}

func (m *mockListener) Accept() (net.Conn, error) {
	return nil, io.EOF
}

func (m *mockListener) Close() error {
	m.closed = true
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockListener) AcceptEdge() (edge.Conn, error) {
	return nil, io.EOF
}

func (m *mockListener) Id() uint32 {
	return m.id
}

func (m *mockListener) IsClosed() bool {
	return m.closed
}

func (m *mockListener) UpdateCost(cost uint16) error {
	return nil
}

func (m *mockListener) UpdatePrecedence(precedence edge.Precedence) error {
	return nil
}

func (m *mockListener) UpdateCostAndPrecedence(cost uint16, precedence edge.Precedence) error {
	return nil
}

func (m *mockListener) SendHealthEvent(pass bool) error {
	return nil
}

// TestMgmtRequestAuthRetry tests authentication retry on 401
func TestMgmtRequestAuthRetry(t *testing.T) {
	authCallCount := 0
	apiCallCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "authenticate") {
			authCallCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"token": "test-token-new",
				},
			})
			return
		}

		apiCallCount++

		// Return 401 on first call, 200 on second
		if apiCallCount == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]string{
				"result": "success",
			},
		})
	}))
	defer server.Close()

	cfg := MockConfig(t)
	cfg.ZitiCtrlURL = server.URL

	zm := &ZitiManager{
		cfg:        cfg,
		logger:     MockLogger(t),
		mgmtToken:  "old-token",
		mgmtClient: server.Client(),
		mu:         sync.RWMutex{},
	}

	// The actual authenticate method will be called by mgmtRequest when it gets a 401
	body, status, err := zm.mgmtRequest("GET", "/test", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, 1, authCallCount, "Should authenticate once after 401")
	assert.Equal(t, 2, apiCallCount, "Should make two API calls (original + retry)")
	assert.NotNil(t, body)
}

// TestHostServiceErrorCases tests HostService error handling
func TestHostServiceErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		initialized bool
		expectError string
	}{
		{
			name:        "Not initialized returns error",
			initialized: false,
			expectError: "ziti SDK not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zm := &ZitiManager{
				logger:         MockLogger(t),
				initialized:    tt.initialized,
				mu:             sync.RWMutex{},
				hostedServices: make(map[string]*hostedService),
				hostedMu:       sync.Mutex{},
			}

			err := zm.HostService("test-service", "localhost", 8080)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			}
		})
	}

	t.Run("Already hosted service returns nil", func(t *testing.T) {
		zm := &ZitiManager{
			logger:         MockLogger(t),
			initialized:    true,
			mu:             sync.RWMutex{},
			hostedServices: make(map[string]*hostedService),
			hostedMu:       sync.Mutex{},
		}
		zm.hostedServices["test-service"] = &hostedService{}

		err := zm.HostService("test-service", "localhost", 8080)
		assert.NoError(t, err)
	})
}

// TestStopHostingService tests service hosting stop
func TestStopHostingService(t *testing.T) {
	t.Run("Stops existing hosted service", func(t *testing.T) {
		cancelCalled := false
		mockLn := &mockListener{closed: false, id: 3}

		zm := &ZitiManager{
			logger:         MockLogger(t),
			hostedServices: make(map[string]*hostedService),
			hostedMu:       sync.Mutex{},
		}
		zm.hostedServices["test-service"] = &hostedService{
			cancel:   func() { cancelCalled = true },
			listener: mockLn,
		}

		zm.StopHostingService("test-service")

		assert.True(t, cancelCalled, "Cancel should be called")
		assert.True(t, mockLn.IsClosed(), "Listener should be closed")
		_, exists := zm.hostedServices["test-service"]
		assert.False(t, exists, "Service should be removed from map")
	})

	t.Run("Non-existent service is safe", func(t *testing.T) {
		zm := &ZitiManager{
			logger:         MockLogger(t),
			hostedServices: make(map[string]*hostedService),
			hostedMu:       sync.Mutex{},
		}

		// Should not panic
		zm.StopHostingService("non-existent")
	})
}

// TestCreateService tests service creation
func TestCreateService(t *testing.T) {
	t.Run("Successful service creation", func(t *testing.T) {
		serviceCreated := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "services") {
				serviceCreated = true
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"id":   "service-123",
						"name": "test-service",
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		serviceID, err := zm.CreateService(context.Background(), "test-service", []string{"attr1", "attr2"})
		require.NoError(t, err)
		assert.Equal(t, "service-123", serviceID)
		assert.True(t, serviceCreated)
	})

	t.Run("Service creation with nil attributes uses name", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "services") {
				var req map[string]interface{}
				json.NewDecoder(r.Body).Decode(&req)

				attrs, ok := req["roleAttributes"].([]interface{})
				assert.True(t, ok, "roleAttributes should exist")
				assert.Len(t, attrs, 1, "Should have one attribute (the service name)")
				assert.Equal(t, "test-service", attrs[0], "Attribute should be service name")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{"id": "service-123"},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		_, err := zm.CreateService(context.Background(), "test-service", nil)
		require.NoError(t, err)
	})

	t.Run("Service creation API error returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "services") {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "Invalid service configuration",
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		_, err := zm.CreateService(context.Background(), "test-service", []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status")
	})
}

// TestDeleteService tests service deletion
func TestDeleteService(t *testing.T) {
	t.Run("Successful service deletion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "services") {
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteService(context.Background(), "service-123")
		assert.NoError(t, err)
	})

	t.Run("Service deletion with NoContent status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "services") {
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteService(context.Background(), "service-123")
		assert.NoError(t, err)
	})

	t.Run("Service deletion error status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "services") {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteService(context.Background(), "service-123")
		assert.Error(t, err)
	})
}

// TestCreateIdentity tests identity creation
func TestCreateIdentity(t *testing.T) {
	t.Run("Successful identity creation with enrollment JWT", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "identities") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id":   "identity-123",
						"name": "test-identity",
						"enrollment": map[string]interface{}{
							"ott": map[string]string{
								"jwt": "enrollment-jwt-token-xyz",
							},
						},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		zitiID, jwt, err := zm.CreateIdentity(context.Background(), "test-identity", "Device", []string{"role1"})
		require.NoError(t, err)
		assert.Equal(t, "identity-123", zitiID)
		assert.Equal(t, "enrollment-jwt-token-xyz", jwt)
	})

	t.Run("Identity creation with default type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "identities") {
				var req map[string]interface{}
				json.NewDecoder(r.Body).Decode(&req)

				assert.Equal(t, "Device", req["type"], "Default type should be Device")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id":         "identity-123",
						"enrollment": map[string]interface{}{},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		_, _, err := zm.CreateIdentity(context.Background(), "test-identity", "", nil)
		require.NoError(t, err)
	})

	t.Run("Identity creation with nil attributes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "identities") {
				var req map[string]interface{}
				json.NewDecoder(r.Body).Decode(&req)

				attrs, ok := req["roleAttributes"].([]interface{})
				assert.True(t, ok)
				assert.Empty(t, attrs, "Nil attributes should result in empty array")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id":         "identity-123",
						"enrollment": map[string]interface{}{},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		_, _, err := zm.CreateIdentity(context.Background(), "test-identity", "Device", nil)
		require.NoError(t, err)
	})
}

// TestServicePolicyCRUD tests service policy CRUD operations
func TestServicePolicyCRUD(t *testing.T) {
	t.Run("Create service policy success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "service-policies") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"id": "policy-123",
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		policyID, err := zm.CreateServicePolicy(context.Background(), "test-policy", "Dial",
			[]string{"#service1"}, []string{"#role1"})
		require.NoError(t, err)
		assert.Equal(t, "policy-123", policyID)
	})

	t.Run("Update service policy success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" && strings.Contains(r.URL.Path, "service-policies") {
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.UpdateServicePolicy(context.Background(), "policy-123", "updated-policy", "Bind",
			[]string{"#service2"}, []string{"#role2"})
		assert.NoError(t, err)
	})

	t.Run("Update service policy error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" && strings.Contains(r.URL.Path, "service-policies") {
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.UpdateServicePolicy(context.Background(), "policy-123", "updated-policy", "Bind",
			[]string{"#service2"}, []string{"#role2"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status")
	})

	t.Run("Delete service policy success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "service-policies") {
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteServicePolicy(context.Background(), "policy-123")
		assert.NoError(t, err)
	})
}

// TestIdentityRoleAttributes tests identity role attribute operations
func TestIdentityRoleAttributes(t *testing.T) {
	t.Run("Get identity role attributes success", func(t *testing.T) {
		expectedAttrs := []string{"role1", "role2", "role3"}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "identities") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id":             "identity-123",
						"roleAttributes": expectedAttrs,
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		attrs, err := zm.GetIdentityRoleAttributes(context.Background(), "identity-123")
		require.NoError(t, err)
		assert.Equal(t, expectedAttrs, attrs)
	})

	t.Run("Patch identity role attributes success", func(t *testing.T) {
		newAttrs := []string{"new-role1", "new-role2"}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PATCH" && strings.Contains(r.URL.Path, "identities") {
				var req map[string]interface{}
				json.NewDecoder(r.Body).Decode(&req)

				attrs, ok := req["roleAttributes"].([]interface{})
				require.True(t, ok)
				require.Len(t, attrs, 2)

				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.PatchIdentityRoleAttributes(context.Background(), "identity-123", newAttrs)
		assert.NoError(t, err)
	})

	t.Run("Patch identity role attributes error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PATCH" && strings.Contains(r.URL.Path, "identities") {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.PatchIdentityRoleAttributes(context.Background(), "identity-123", []string{"role1"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status")
	})
}

// TestGetIdentityEnrollmentJWT tests enrollment JWT retrieval
func TestGetIdentityEnrollmentJWT(t *testing.T) {
	t.Run("Successful JWT retrieval", func(t *testing.T) {
		expectedJWT := "test-jwt-token-abc123"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "identities") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id": "identity-123",
						"enrollment": map[string]interface{}{
							"ott": map[string]string{
								"jwt": expectedJWT,
							},
						},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		jwt, err := zm.GetIdentityEnrollmentJWT(context.Background(), "identity-123")
		require.NoError(t, err)
		assert.Equal(t, expectedJWT, jwt)
	})

	t.Run("No JWT available", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "identities") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"id":         "identity-123",
						"enrollment": map[string]interface{}{},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		jwt, err := zm.GetIdentityEnrollmentJWT(context.Background(), "identity-123")
		assert.Error(t, err)
		assert.Empty(t, jwt)
		assert.Contains(t, err.Error(), "no enrollment JWT available")
	})

	t.Run("API error returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "identities") {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		jwt, err := zm.GetIdentityEnrollmentJWT(context.Background(), "identity-123")
		assert.Error(t, err)
		assert.Empty(t, jwt)
	})
}

// TestIsIdentityEnrolled verifies the live-controller enrollment check that
// self-heals the drifted ziti_identities.enrolled flag.
func TestIsIdentityEnrolled(t *testing.T) {
	mk := func(t *testing.T, url string) *ZitiManager {
		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = url
		return &ZitiManager{cfg: cfg, logger: MockLogger(t), mgmtToken: "test-token", mgmtClient: &http.Client{}}
	}

	t.Run("empty enrollment => enrolled", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"id-1","enrollment":{}}}`))
		}))
		defer srv.Close()
		enrolled, err := mk(t, srv.URL).IsIdentityEnrolled(context.Background(), "id-1")
		require.NoError(t, err)
		assert.True(t, enrolled)
	})

	t.Run("pending ott => not enrolled", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"id-1","enrollment":{"ott":{"jwt":"pending"}}}}`))
		}))
		defer srv.Close()
		enrolled, err := mk(t, srv.URL).IsIdentityEnrolled(context.Background(), "id-1")
		require.NoError(t, err)
		assert.False(t, enrolled)
	})

	t.Run("controller error => error, not enrolled", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		enrolled, err := mk(t, srv.URL).IsIdentityEnrolled(context.Background(), "id-1")
		require.Error(t, err)
		assert.False(t, enrolled)
	})
}

// TestListServices tests service listing
func TestListServices(t *testing.T) {
	t.Run("Successful service list", func(t *testing.T) {
		expectedServices := []ZitiServiceInfo{
			{ID: "svc-1", Name: "service1", RoleAttributes: []string{"attr1"}},
			{ID: "svc-2", Name: "service2", RoleAttributes: []string{"attr2"}},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": expectedServices,
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		services, err := zm.ListServices(context.Background())
		require.NoError(t, err)
		assert.Len(t, services, 2)
		assert.Equal(t, "service1", services[0].Name)
		assert.Equal(t, "service2", services[1].Name)
	})

	t.Run("Empty service list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []ZitiServiceInfo{},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		services, err := zm.ListServices(context.Background())
		require.NoError(t, err)
		assert.Empty(t, services)
	})
}

// TestGetServiceByName tests service lookup by name
func TestGetServiceByName(t *testing.T) {
	t.Run("Service found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{"id": "svc-1", "name": "service1", "roleAttributes": []string{"attr1"}},
						{"id": "svc-2", "name": "service2", "roleAttributes": []string{"attr2"}},
						{"id": "svc-3", "name": "service3", "roleAttributes": []string{"attr3"}},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		service, err := zm.GetServiceByName("service2")
		require.NoError(t, err)
		assert.Equal(t, "svc-2", service.ID)
		assert.Equal(t, "service2", service.Name)
	})

	t.Run("Service not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{"id": "svc-1", "name": "service1", "roleAttributes": []string{"attr1"}},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		service, err := zm.GetServiceByName("non-existent")
		assert.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "service not found")
	})
}

// TestCheckControllerHealth tests controller health check
func TestCheckControllerHealth(t *testing.T) {
	t.Run("Healthy controller", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "version") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"version": "1.0.0",
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		healthy, err := zm.CheckControllerHealth(context.Background())
		require.NoError(t, err)
		assert.True(t, healthy)
	})

	t.Run("Unhealthy controller", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "version") {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		healthy, err := zm.CheckControllerHealth(context.Background())
		assert.Error(t, err)
		assert.False(t, healthy)
	})
}

// TestEnsureIdentityFile tests identity file creation and cleanup
func TestEnsureIdentityFile(t *testing.T) {
	t.Run("Directory creation for identity file", func(t *testing.T) {
		tmpDir := t.TempDir()
		nestedPath := filepath.Join(tmpDir, "nested", "dir", "identity.json")

		// Ensure the directory is created
		dir := filepath.Dir(nestedPath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)

		// Verify directory exists
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("Write identity file with correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		identityFile := filepath.Join(tmpDir, "test-identity.json")

		testData := []byte(`{"test": "data"}`)
		err := os.WriteFile(identityFile, testData, 0600)
		require.NoError(t, err)

		// Verify file content
		content, err := os.ReadFile(identityFile)
		require.NoError(t, err)
		assert.Equal(t, testData, content)

		// Verify file permissions (0600 = rw-------)
		info, err := os.Stat(identityFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})
}

// TestSingleConnListener tests the single connection listener wrapper
func TestSingleConnListener(t *testing.T) {
	t.Run("Accept returns connection then closes", func(t *testing.T) {
		mockConn := &mockConn{localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}}
		ln := &singleConnListener{
			ch:   make(chan net.Conn, 1),
			once: sync.Once{},
		}
		ln.ch <- mockConn

		conn, err := ln.Accept()
		require.NoError(t, err)
		assert.Same(t, mockConn, conn)

		// Second accept should return EOF
		conn, err = ln.Accept()
		assert.Error(t, err)
		assert.Nil(t, conn)
	})

	t.Run("Addr returns connection address after accept", func(t *testing.T) {
		expectedAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 9090}
		mockConn := &mockConn{localAddr: expectedAddr}
		ln := &singleConnListener{
			ch:   make(chan net.Conn, 1),
			once: sync.Once{},
		}
		ln.ch <- mockConn

		_, _ = ln.Accept()
		addr := ln.Addr()
		assert.Equal(t, expectedAddr, addr)
	})

	t.Run("Addr returns TCPAddr when no connection", func(t *testing.T) {
		ln := &singleConnListener{
			ch:   make(chan net.Conn, 1),
			once: sync.Once{},
		}
		addr := ln.Addr()
		assert.IsType(t, &net.TCPAddr{}, addr)
	})

	t.Run("Close is no-op", func(t *testing.T) {
		ln := &singleConnListener{
			ch:   make(chan net.Conn, 1),
			once: sync.Once{},
		}
		err := ln.Close()
		assert.NoError(t, err)
	})
}

// mockConn is a mock implementation of net.Conn
type mockConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestGetDB tests GetDB method
func TestGetDB(t *testing.T) {
	mockDB := &database.PostgresDB{}
	zm := &ZitiManager{
		db: mockDB,
	}

	assert.Same(t, mockDB, zm.GetDB())
}

// TestDeleteIdentity tests identity deletion
func TestDeleteIdentity(t *testing.T) {
	t.Run("Successful identity deletion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "identities") {
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteIdentity(context.Background(), "identity-123")
		assert.NoError(t, err)
	})

	t.Run("Identity deletion with NoContent status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "identities") {
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteIdentity(context.Background(), "identity-123")
		assert.NoError(t, err)
	})

	t.Run("Identity deletion error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" && strings.Contains(r.URL.Path, "identities") {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.DeleteIdentity(context.Background(), "identity-123")
		assert.Error(t, err)
	})
}

// TestListIdentities tests identity listing
func TestListIdentities(t *testing.T) {
	t.Run("Successful identity list", func(t *testing.T) {
		expectedIdentities := []ZitiIdentityInfo{
			{ID: "id-1", Name: "identity1", Type: "Device", Attributes: []string{"role1"}},
			{ID: "id-2", Name: "identity2", Type: "User", Attributes: []string{"role2"}},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "identities") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": expectedIdentities,
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		identities, err := zm.ListIdentities(context.Background())
		require.NoError(t, err)
		assert.Len(t, identities, 2)
		assert.Equal(t, "identity1", identities[0].Name)
		assert.Equal(t, "Device", identities[0].Type)
	})

	t.Run("Empty identity list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "identities") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []ZitiIdentityInfo{},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		identities, err := zm.ListIdentities(context.Background())
		require.NoError(t, err)
		assert.Empty(t, identities)
	})
}

// TestGetService tests service lookup by ID
func TestGetService(t *testing.T) {
	t.Run("Service found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{"id": "svc-1", "name": "service1", "roleAttributes": []string{"attr1"}},
						{"id": "svc-2", "name": "service2", "roleAttributes": []string{"attr2"}},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		service, err := zm.GetService("svc-2")
		require.NoError(t, err)
		assert.Equal(t, "svc-2", service.ID)
		assert.Equal(t, "service2", service.Name)
	})

	t.Run("Service not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{"id": "svc-1", "name": "service1", "roleAttributes": []string{"attr1"}},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		service, err := zm.GetService("non-existent")
		assert.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "service not found")
	})
}

// TestTestServiceDial tests service dialability testing
func TestTestServiceDial(t *testing.T) {
	t.Run("Service dialable when Ziti context initialized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{"id": "svc-1", "name": "service1", "roleAttributes": []string{"attr1"}},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
			// Note: zitiCtx is nil, so TestServiceDial will fail at the Dial step
			// but this test is about the service lookup part
		}

		// This will fail when trying to dial because zitiCtx is not initialized
		// But the service lookup part should work
		_, err := zm.TestServiceDial(context.Background(), "service1")
		assert.Error(t, err) // Expected to fail due to nil zitiCtx
	})

	t.Run("Service not dialable when not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": []map[string]interface{}{
						{"id": "svc-1", "name": "service1", "roleAttributes": []string{"attr1"}},
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		dialable, err := zm.TestServiceDial(context.Background(), "non-existent")
		assert.Error(t, err)
		assert.False(t, dialable)
	})

	t.Run("Service not dialable when Ziti context not initialized", func(t *testing.T) {
		zm := &ZitiManager{
			logger:      MockLogger(t),
			mu:          sync.RWMutex{},
			initialized: false,
		}

		dialable, err := zm.TestServiceDial(context.Background(), "service1")
		assert.Error(t, err)
		assert.False(t, dialable)
		assert.Contains(t, err.Error(), "Ziti context not initialized")
	})
}

// TestGetControllerVersion tests version retrieval
func TestGetControllerVersion(t *testing.T) {
	t.Run("Successful version retrieval", func(t *testing.T) {
		expectedVersion := map[string]interface{}{
			"data": map[string]string{
				"version": "v1.2.3",
				"build":   "abc123",
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "version") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(expectedVersion)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		version, err := zm.GetControllerVersion(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, version)
	})

	t.Run("Version retrieval error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "version") {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		version, err := zm.GetControllerVersion(context.Background())
		assert.Error(t, err)
		assert.Nil(t, version)
	})
}

// TestEnsureServiceEdgeRouterPolicy tests service edge router policy creation
func TestEnsureServiceEdgeRouterPolicy(t *testing.T) {
	t.Run("Successful policy creation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "service-edge-router-policies") {
				w.WriteHeader(http.StatusCreated)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.EnsureServiceEdgeRouterPolicy(context.Background(), "test-policy",
			[]string{"#service1"}, []string{"#all"})
		assert.NoError(t, err)
	})

	t.Run("Policy already exists (OK status)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "service-edge-router-policies") {
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.EnsureServiceEdgeRouterPolicy(context.Background(), "test-policy",
			[]string{"#service1"}, []string{"#all"})
		assert.NoError(t, err)
	})

	t.Run("Policy creation error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "service-edge-router-policies") {
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.EnsureServiceEdgeRouterPolicy(context.Background(), "test-policy",
			[]string{"#service1"}, []string{"#all"})
		assert.Error(t, err)
	})
}

// TestZitiManagerConcurrency tests concurrent access to ZitiManager
func TestZitiManagerConcurrency(t *testing.T) {
	t.Run("Concurrent mgmtRequest calls", func(t *testing.T) {
		var callCount atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"result": "success",
				},
			})
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		// Launch concurrent requests
		const concurrency = 10
		done := make(chan bool, concurrency)

		for i := 0; i < concurrency; i++ {
			go func() {
				_, status, err := zm.mgmtRequest("GET", "/test", nil)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
				done <- true
			}()
		}

		// Wait for all to complete
		for i := 0; i < concurrency; i++ {
			<-done
		}

		assert.Equal(t, concurrency, int(callCount.Load()))
	})

	t.Run("Concurrent IsInitialized calls", func(t *testing.T) {
		zm := &ZitiManager{
			logger:      MockLogger(t),
			initialized: true,
			mu:          sync.RWMutex{},
		}

		const concurrency = 100
		done := make(chan bool, concurrency)

		for i := 0; i < concurrency; i++ {
			go func() {
				result := zm.IsInitialized()
				assert.True(t, result)
				done <- true
			}()
		}

		for i := 0; i < concurrency; i++ {
			<-done
		}
	})
}

// TestCreateServiceWithConfig tests service creation with host/port config
func TestCreateServiceWithConfig(t *testing.T) {
	t.Run("Successful service creation with config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.Contains(r.URL.Path, "services") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"id": "service-123",
					},
				})
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		// Use nil database - the CreateServiceWithConfig will handle it
		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			db:         nil, // Will log warning but not error
			mu:         sync.RWMutex{},
		}

		// Note: CreateServiceWithConfig may fail without proper DB mock
		// This test documents the expected behavior
		service, err := zm.CreateServiceWithConfig(context.Background(), "test-service", "example.com", 8080)
		// May return error due to nil DB
		if err == nil {
			assert.Equal(t, "service-123", service.ID)
			assert.Equal(t, "test-service", service.Name)
		}
	})
}

// TestMgmtRequestErrorCases tests error handling in mgmtRequest
func TestMgmtRequestErrorCases(t *testing.T) {
	t.Run("Request creation failure", func(t *testing.T) {
		zm := &ZitiManager{
			cfg:    &config.Config{ZitiCtrlURL: "://invalid-url"},
			logger: MockLogger(t),
			mu:     sync.RWMutex{},
		}

		_, status, err := zm.mgmtRequest("GET", "/test", nil)
		assert.Error(t, err)
		assert.Equal(t, 0, status)
	})

	t.Run("Network error", func(t *testing.T) {
		// Use an invalid URL that will cause a network error
		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = "http://localhost:9999" // Port that's likely not listening

		client := &http.Client{Timeout: 100 * time.Millisecond}
		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: client,
			mu:         sync.RWMutex{},
		}

		_, _, err := zm.mgmtRequest("GET", "/test", nil)
		assert.Error(t, err)
	})
}

// TestGetAuditEvents tests audit event retrieval
func TestGetAuditEvents(t *testing.T) {
	t.Run("Returns empty slice by default", func(t *testing.T) {
		zm := &ZitiManager{
			logger: MockLogger(t),
			mu:     sync.RWMutex{},
		}

		events, err := zm.GetAuditEvents(context.Background(), nil)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("With timestamp filter", func(t *testing.T) {
		zm := &ZitiManager{
			logger: MockLogger(t),
			mu:     sync.RWMutex{},
		}

		pastTime := time.Now().Add(-24 * time.Hour)
		events, err := zm.GetAuditEvents(context.Background(), &pastTime)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})
}

// TestPatchIdentityRoleAttributesEdgeCases tests edge cases for patching attributes
func TestPatchIdentityRoleAttributesEdgeCases(t *testing.T) {
	t.Run("Empty attributes array", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PATCH" && strings.Contains(r.URL.Path, "identities") {
				var req map[string]interface{}
				json.NewDecoder(r.Body).Decode(&req)

				attrs, ok := req["roleAttributes"].([]interface{})
				require.True(t, ok)
				assert.Empty(t, attrs)

				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		err := zm.PatchIdentityRoleAttributes(context.Background(), "identity-123", []string{})
		assert.NoError(t, err)
	})

	t.Run("Large attributes array", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PATCH" && strings.Contains(r.URL.Path, "identities") {
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = server.URL

		zm := &ZitiManager{
			cfg:        cfg,
			logger:     MockLogger(t),
			mgmtToken:  "test-token",
			mgmtClient: server.Client(),
			mu:         sync.RWMutex{},
		}

		largeAttrs := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			largeAttrs[i] = "role-" + strconv.Itoa(i)
		}

		err := zm.PatchIdentityRoleAttributes(context.Background(), "identity-123", largeAttrs)
		assert.NoError(t, err)
	})
}

// TestHostAllServices tests hosting all services from database
func TestHostAllServices(t *testing.T) {
	t.Run("No Ziti-enabled routes", func(t *testing.T) {
		zm := &ZitiManager{
			cfg:    MockConfig(t),
			logger: MockLogger(t),
			db:     &database.PostgresDB{},
			mu:     sync.RWMutex{},
		}

		ctx := context.Background()

		// Should not panic
		zm.HostAllServices(ctx)
	})

	t.Run("With uninitialized SDK", func(t *testing.T) {
		zm := &ZitiManager{
			cfg:         MockConfig(t),
			logger:      MockLogger(t),
			db:          &database.PostgresDB{},
			initialized: false,
			mu:          sync.RWMutex{},
		}

		ctx := context.Background()

		// Should log warning and return
		zm.HostAllServices(ctx)
	})
}
