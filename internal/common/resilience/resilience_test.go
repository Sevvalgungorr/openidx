// Package resilience provides tests for circuit breaker and resilience patterns
package resilience

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/openidx/openidx/internal/common/testsupport"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewCircuitBreaker(t *testing.T) {
	t.Run("Creates with default state closed", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test-cb",
			Threshold:    3,
			ResetTimeout: time.Second,
			Logger:       logger,
		})

		assert.Equal(t, "test-cb", cb.name)
		assert.Equal(t, 3, cb.threshold)
		assert.Equal(t, time.Second, cb.resetTimeout)
		assert.Equal(t, StateClosed, cb.State())
		assert.Equal(t, 0, cb.failures)
	})

	t.Run("Creates with valid config", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:             "api-cb",
			Threshold:        5,
			ResetTimeout:     30 * time.Second,
			HalfOpenAttempts: 3,
			Logger:           logger,
		})

		assert.Equal(t, "api-cb", cb.name)
		assert.Equal(t, StateClosed, cb.State())
		assert.Equal(t, 3, cb.halfOpenAttempts)
	})

	t.Run("New helper function", func(t *testing.T) {
		cb := New("test", 5, 10*time.Second)

		assert.Equal(t, "test", cb.name)
		assert.Equal(t, 5, cb.threshold)
		assert.Equal(t, 10*time.Second, cb.resetTimeout)
		assert.Equal(t, StateClosed, cb.State())
	})
}

func TestCircuitBreaker_Execute(t *testing.T) {
	t.Run("Success in closed state returns value", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		called := false
		result, err := cb.Execute(func() (interface{}, error) {
			called = true
			return "success", nil
		})

		assert.NoError(t, err)
		assert.True(t, called)
		assert.Equal(t, "success", result)
		assert.Equal(t, StateClosed, cb.State())
		assert.Equal(t, 0, cb.failures)

		// Check for success log
		found := false
		for _, log := range logs.All() {
			if log.Message == "Circuit breaker recovered, transitioning to closed" {
				found = true
				break
			}
		}
		// No transition since it was already closed
		assert.False(t, found)
	})

	t.Run("Failure in closed state increments counter", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		// Execute failing operation twice
		testErr := errors.New("test error")
		for i := 0; i < 2; i++ {
			_, err := cb.Execute(func() (interface{}, error) {
				return nil, testErr
			})
			assert.Error(t, err)
			assert.Equal(t, testErr, err)
		}

		assert.Equal(t, StateClosed, cb.State())
		assert.Equal(t, 2, cb.failures)
	})

	t.Run("Threshold exceeded opens circuit", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		testErr := errors.New("test error")

		// Execute failing operations
		for i := 0; i < 3; i++ {
			cb.Execute(func() (interface{}, error) {
				return nil, testErr
			})
		}

		assert.Equal(t, StateOpen, cb.State())
		assert.Equal(t, 2, cb.failures)

		// Check for open log
		found := false
		for _, log := range logs.All() {
			if log.Message == "Circuit breaker opened" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("Open circuit rejects requests", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    1,
			ResetTimeout: time.Second,
			Logger:       logger,
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})

		assert.Equal(t, StateOpen, cb.State())

		// Try to execute again - should be rejected
		called := false
		_, err := cb.Execute(func() (interface{}, error) {
			called = true
			return "success", nil
		})

		assert.Error(t, err)
		assert.False(t, called)
		assert.Contains(t, err.Error(), "circuit breaker")
		assert.Contains(t, err.Error(), "open")
	})

	t.Run("Half-open state after reset timeout", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    1,
			ResetTimeout: 50 * time.Millisecond,
			Logger:       logger,
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})
		assert.Equal(t, StateOpen, cb.State())

		// Wait for reset timeout
		time.Sleep(60 * time.Millisecond)

		// Next request should transition to half-open and execute
		called := false
		result, err := cb.Execute(func() (interface{}, error) {
			called = true
			return "recovered", nil
		})

		assert.NoError(t, err)
		assert.True(t, called)
		assert.Equal(t, "recovered", result)
		assert.Equal(t, StateClosed, cb.State()) // Success should close it
	})

	t.Run("Half-open failure reopens circuit", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    1,
			ResetTimeout: 50 * time.Millisecond,
			Logger:       logger,
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})
		assert.Equal(t, StateOpen, cb.State())

		// Wait for reset timeout
		time.Sleep(60 * time.Millisecond)

		// Execute with failure - should reopen
		_, err := cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail again")
		})

		assert.Error(t, err)
		assert.Equal(t, StateOpen, cb.State())
	})

	t.Run("Success resets failure count", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		// Two failures
		for i := 0; i < 2; i++ {
			cb.Execute(func() (interface{}, error) {
				return nil, errors.New("fail")
			})
		}
		assert.Equal(t, 2, cb.failures)

		// One success
		cb.Execute(func() (interface{}, error) {
			return nil, nil
		})

		assert.Equal(t, 0, cb.failures)
		assert.Equal(t, StateClosed, cb.State())
	})
}

func TestCircuitBreaker_HalfOpenRetryLimit(t *testing.T) {
	t.Run("Half-open retry limit enforced", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:             "test",
			Threshold:        1,
			ResetTimeout:     50 * time.Millisecond,
			HalfOpenAttempts: 2, // Allow 2 attempts in half-open
			Logger:           logger,
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})
		assert.Equal(t, StateOpen, cb.State())

		// Wait for reset timeout
		time.Sleep(60 * time.Millisecond)

		// First half-open attempt - fails but allowed
		_, err := cb.Execute(func() (interface{}, error) {
			return nil, errors.New("half-open fail 1")
		})
		assert.Error(t, err)
		assert.Equal(t, StateOpen, cb.State())

		// Wait again for reset timeout
		time.Sleep(60 * time.Millisecond)

		// Second half-open attempt - fails but allowed
		_, err = cb.Execute(func() (interface{}, error) {
			return nil, errors.New("half-open fail 2")
		})
		assert.Error(t, err)
		assert.Equal(t, StateOpen, cb.State())

		// Wait again for reset timeout
		time.Sleep(60 * time.Millisecond)

		// Third half-open attempt - should be rejected
		called := false
		_, err = cb.Execute(func() (interface{}, error) {
			called = true
			return nil, nil
		})
		assert.Error(t, err)
		assert.False(t, called)
		assert.Contains(t, err.Error(), "exceeded half-open retry limit")
	})

	t.Run("Half-open unlimited attempts when set to 0", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:             "test",
			Threshold:        1,
			ResetTimeout:     50 * time.Millisecond,
			HalfOpenAttempts: 0, // Unlimited
			Logger:           logger,
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})
		assert.Equal(t, StateOpen, cb.State())

		// Wait for reset timeout
		time.Sleep(60 * time.Millisecond)

		// Multiple half-open attempts should all be allowed
		for i := 0; i < 5; i++ {
			_, err := cb.Execute(func() (interface{}, error) {
				return nil, errors.New("fail")
			})
			assert.Error(t, err)
			assert.Equal(t, StateOpen, cb.State())

			// Wait for reset timeout between attempts
			time.Sleep(60 * time.Millisecond)
		}

		// Should still be in half-open mode (not permanently blocked)
		assert.Equal(t, StateOpen, cb.State())
	})
}

func TestCircuitBreaker_Fallback(t *testing.T) {
	t.Run("Fallback called when circuit is open", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    1,
			ResetTimeout: time.Second,
			Logger:       logger,
		})

		fallbackCalled := false
		cb.WithFallback(func(err error) (interface{}, error) {
			fallbackCalled = true
			return "fallback-value", nil
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})
		assert.Equal(t, StateOpen, cb.State())

		// Try to execute - should call fallback
		called := false
		result, err := cb.Execute(func() (interface{}, error) {
			called = true
			return "original", nil
		})

		assert.NoError(t, err)
		assert.False(t, called)
		assert.True(t, fallbackCalled)
		assert.Equal(t, "fallback-value", result)
	})

	t.Run("Fallback called on execution failure", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		fallbackCalled := false
		cb.WithFallback(func(err error) (interface{}, error) {
			fallbackCalled = true
			return "cached-value", nil
		})

		// Execute with failure
		result, err := cb.Execute(func() (interface{}, error) {
			return nil, errors.New("db error")
		})

		assert.NoError(t, err)
		assert.True(t, fallbackCalled)
		assert.Equal(t, "cached-value", result)
		assert.Equal(t, StateClosed, cb.State()) // Still closed, below threshold
	})

	t.Run("Fallback returns error", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    1,
			ResetTimeout: time.Second,
			Logger:       logger,
		})

		cb.WithFallback(func(err error) (interface{}, error) {
			return nil, fmt.Errorf("fallback failed: %w", err)
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})

		// Try to execute - fallback should return error
		_, err := cb.Execute(func() (interface{}, error) {
			return "original", nil
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fallback failed")
	})

	t.Run("Fallback with half-open retry limit", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:             "test",
			Threshold:        1,
			ResetTimeout:     50 * time.Millisecond,
			HalfOpenAttempts: 1,
			Logger:           logger,
		})

		fallbackCalled := false
		cb.WithFallback(func(err error) (interface{}, error) {
			fallbackCalled = true
			return "fallback", nil
		})

		// Open the circuit
		cb.Execute(func() (interface{}, error) {
			return nil, errors.New("fail")
		})

		// Wait for reset timeout
		time.Sleep(60 * time.Millisecond)

		// First half-open attempt - fails, but fallback returns no error
		fallbackCalled = false
		result, err := cb.Execute(func() (interface{}, error) {
			return nil, errors.New("half-open fail")
		})
		// Fallback swallows the error
		assert.NoError(t, err)
		assert.True(t, fallbackCalled)
		assert.Equal(t, "fallback", result)

		// Wait again
		time.Sleep(60 * time.Millisecond)

		// Second half-open attempt - should exceed limit and call fallback
		fallbackCalled = false
		result, err = cb.Execute(func() (interface{}, error) {
			return "should not execute", nil
		})

		assert.NoError(t, err)
		assert.True(t, fallbackCalled)
		assert.Equal(t, "fallback", result)
	})
}

func TestCircuitBreaker_ExecuteError(t *testing.T) {
	t.Run("ExecuteError for backward compatibility", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "test",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		called := false
		err := cb.ExecuteError(func() error {
			called = true
			return nil
		})

		assert.NoError(t, err)
		assert.True(t, called)
		assert.Equal(t, StateClosed, cb.State())
	})
}

func TestCircuitBreaker_State(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Name:         "test",
		Threshold:    2,
		ResetTimeout: 100 * time.Millisecond,
		Logger:       logger,
	})

	assert.Equal(t, StateClosed, cb.State())

	// Cause failures to open
	cb.ExecuteError(func() error { return errors.New("fail") })
	cb.ExecuteError(func() error { return errors.New("fail") })

	assert.Equal(t, StateOpen, cb.State())
}

func TestCircuitBreaker_Reset(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Name:         "test",
		Threshold:    2,
		ResetTimeout: 100 * time.Millisecond,
		Logger:       logger,
	})

	// Open the circuit
	cb.ExecuteError(func() error { return errors.New("fail") })
	cb.ExecuteError(func() error { return errors.New("fail") })

	assert.Equal(t, StateOpen, cb.State())
	assert.Greater(t, cb.failures, 0)

	// Reset
	cb.Reset()

	assert.Equal(t, StateClosed, cb.State())
	assert.Equal(t, 0, cb.failures)
	assert.True(t, cb.lastFailure.IsZero())
}

func TestCircuitBreaker_Stats(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Name:             "test-cb",
		Threshold:        3,
		ResetTimeout:     100 * time.Millisecond,
		HalfOpenAttempts: 2,
		Logger:           logger,
	})

	stats := cb.Stats()

	assert.Equal(t, "test-cb", stats.Name)
	assert.Equal(t, StateClosed, stats.State)
	assert.Equal(t, 0, stats.Failures)
	assert.Equal(t, 3, stats.Threshold)
	assert.Nil(t, stats.LastFailure)
	assert.Equal(t, 0, stats.HalfOpenAttempt)

	// Cause a failure
	cb.ExecuteError(func() error { return errors.New("fail") })

	stats = cb.Stats()
	assert.Equal(t, 1, stats.Failures)
	assert.NotNil(t, stats.LastFailure)
}

func TestCircuitBreaker_Concurrent(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Name:         "test",
		Threshold:    10,
		ResetTimeout: 100 * time.Millisecond,
		Logger:       logger,
	})

	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	failCount := atomic.Int32{}

	// Run 20 concurrent operations, half will fail
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := cb.Execute(func() (interface{}, error) {
				if idx%2 == 0 {
					return nil, nil
				}
				return nil, errors.New("fail")
			})
			if err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Should have some successes and some failures
	assert.Greater(t, successCount.Load(), int32(0))
	assert.Greater(t, failCount.Load(), int32(0))

	// State should be deterministically set
	state := cb.State()
	assert.True(t, state == StateClosed || state == StateOpen)
}

func TestCircuitState_String(t *testing.T) {
	assert.Equal(t, "closed", string(StateClosed))
	assert.Equal(t, "open", string(StateOpen))
	assert.Equal(t, "half-open", string(StateHalfOpen))
}

func TestResilientHTTPClient(t *testing.T) {
	t.Run("Creates client with circuit breaker", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "http-cb",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		client := &http.Client{Timeout: time.Second}
		resilientClient := NewResilientHTTPClient(client, cb)

		assert.NotNil(t, resilientClient)
		assert.NotNil(t, resilientClient.client)
		assert.NotNil(t, resilientClient.cb)
		assert.Equal(t, "http-cb", resilientClient.cb.name)
	})

	t.Run("Successful request through circuit breaker", func(t *testing.T) {
		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "http-cb",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		client := &http.Client{Timeout: time.Second}
		resilientClient := NewResilientHTTPClient(client, cb)

		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := resilientClient.Do(req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("5xx response treated as failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "http-cb",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		client := &http.Client{Timeout: time.Second}
		resilientClient := NewResilientHTTPClient(client, cb)

		// First failure - Do returns error for 5xx
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := resilientClient.Do(req)

		// ResilientHTTPClient returns error for 5xx responses
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "server error: HTTP 500")
		// Response is still returned even though there's an error
		if resp != nil {
			resp.Body.Close()
		}

		assert.Equal(t, 1, cb.failures)

		// Second failure should open circuit
		req2, _ := http.NewRequest("GET", server.URL, nil)
		resp2, err2 := resilientClient.Do(req2)

		assert.Error(t, err2)
		if resp2 != nil {
			resp2.Body.Close()
		}

		assert.Equal(t, StateOpen, cb.State())
	})

	t.Run("4xx response not treated as failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "http-cb",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		client := &http.Client{Timeout: time.Second}
		resilientClient := NewResilientHTTPClient(client, cb)

		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := resilientClient.Do(req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()

		// 4xx should not count as failure
		assert.Equal(t, 0, cb.failures)
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("Network errors treated as failures", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "http-cb",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		client := &http.Client{
			Timeout: 1 * time.Millisecond,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return nil, errors.New("connection refused")
				},
			},
		}
		resilientClient := NewResilientHTTPClient(client, cb)

		// Make request to invalid address
		req, _ := http.NewRequest("GET", "http://invalid.local:9999", nil)
		_, err := resilientClient.Do(req)

		assert.Error(t, err)
		assert.Equal(t, 1, cb.failures)
	})

	t.Run("Get helper method", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`OK`))
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "http-cb",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		client := &http.Client{Timeout: time.Second}
		resilientClient := NewResilientHTTPClient(client, cb)

		resp, err := resilientClient.Get(server.URL)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestRegistry(t *testing.T) {
	t.Run("Creates empty registry", func(t *testing.T) {
		registry := NewRegistry()
		assert.NotNil(t, registry)
		assert.True(t, registry.IsHealthy())
		assert.Empty(t, registry.AllStats())
	})

	t.Run("Register and get circuit breaker", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		registry := NewRegistry()

		cb1 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "cb1",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		cb2 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "cb2",
			Threshold:    5,
			ResetTimeout: 200 * time.Millisecond,
			Logger:       logger,
		})

		registry.Register(cb1)
		registry.Register(cb2)

		// Get by name
		retrieved := registry.Get("cb1")
		assert.NotNil(t, retrieved)
		assert.Equal(t, "cb1", retrieved.name)

		retrieved2 := registry.Get("cb2")
		assert.NotNil(t, retrieved2)
		assert.Equal(t, "cb2", retrieved2.name)

		// Unknown name returns nil
		unknown := registry.Get("unknown")
		assert.Nil(t, unknown)
	})

	t.Run("AllStats returns stats for all breakers", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		registry := NewRegistry()

		cb1 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "cb1",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		cb2 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "cb2",
			Threshold:    5,
			ResetTimeout: 200 * time.Millisecond,
			Logger:       logger,
		})

		registry.Register(cb1)
		registry.Register(cb2)

		stats := registry.AllStats()
		assert.Len(t, stats, 2)

		names := make(map[string]bool)
		for _, s := range stats {
			names[s.Name] = true
		}
		assert.True(t, names["cb1"])
		assert.True(t, names["cb2"])
	})

	t.Run("IsHealthy returns false when any breaker is open", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		registry := NewRegistry()

		cb1 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "cb1",
			Threshold:    1,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		cb2 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "cb2",
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})

		registry.Register(cb1)
		registry.Register(cb2)

		assert.True(t, registry.IsHealthy())

		// Open cb1
		cb1.ExecuteError(func() error {
			return errors.New("fail")
		})

		assert.False(t, registry.IsHealthy())
	})

	t.Run("Concurrent access to registry", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		registry := NewRegistry()

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				cb := NewCircuitBreaker(CircuitBreakerConfig{
					Name:         fmt.Sprintf("cb-%d", idx),
					Threshold:    3,
					ResetTimeout: 100 * time.Millisecond,
					Logger:       logger,
				})
				registry.Register(cb)
				registry.Get(fmt.Sprintf("cb-%d", idx))
				registry.AllStats()
				registry.IsHealthy()
			}(i)
		}

		wg.Wait()

		stats := registry.AllStats()
		assert.Len(t, stats, 10)
	})
}

func TestStateToFloat(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected float64
	}{
		{StateClosed, 0},
		{StateHalfOpen, 1},
		{StateOpen, 2},
		{"unknown", 0}, // Default case
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			result := stateToFloat(tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCircuitBreaker_DistributedState(t *testing.T) {
	// Skip if testcontainers is not available
	t.Run("Redis distributed state coordination", func(t *testing.T) {
		ctx := context.Background()

		redisContainer := testsupport.RunOrSkip(t, "redis:7-alpine",
			func() (*rediscontainer.RedisContainer, error) {
				return rediscontainer.Run(ctx, "redis:7-alpine")
			})
		defer testcontainers.TerminateContainer(redisContainer)

		redisHost, err := redisContainer.Host(ctx)
		require.NoError(t, err)
		redisPort, err := redisContainer.MappedPort(ctx, "6379")
		require.NoError(t, err)

		rdb := redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%s", redisHost, redisPort.Port()),
		})
		defer rdb.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		// Create first circuit breaker
		cb1 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "distributed-cb",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
			RedisClient:  rdb,
		})

		// Open the circuit
		cb1.ExecuteError(func() error { return errors.New("fail") })
		cb1.ExecuteError(func() error { return errors.New("fail") })

		assert.Equal(t, StateOpen, cb1.State())

		// Wait a bit for Redis sync
		time.Sleep(50 * time.Millisecond)

		// Create second circuit breaker with same name - should load state from Redis
		cb2 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "distributed-cb",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
			RedisClient:  rdb,
		})

		// Should have loaded the open state from Redis
		assert.Eventually(t, func() bool {
			return cb2.State() == StateOpen
		}, 200*time.Millisecond, 20*time.Millisecond)

		// Reset first breaker
		cb1.Reset()

		// Wait for sync
		time.Sleep(50 * time.Millisecond)

		// Recreate breaker - should get closed state
		cb3 := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         "distributed-cb",
			Threshold:    2,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
			RedisClient:  rdb,
		})

		assert.Eventually(t, func() bool {
			return cb3.State() == StateClosed
		}, 200*time.Millisecond, 20*time.Millisecond)
	})
}

// Benchmark tests
func BenchmarkCircuitBreaker_Execute_Success(b *testing.B) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Name:         "test",
		Threshold:    100,
		ResetTimeout: time.Second,
		Logger:       logger,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(func() (interface{}, error) {
			return nil, nil
		})
	}
}

func BenchmarkCircuitBreaker_Execute_Failure(b *testing.B) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		Name:         "test",
		Threshold:    100,
		ResetTimeout: time.Second,
		Logger:       logger,
	})

	testErr := errors.New("test error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(func() (interface{}, error) {
			return nil, testErr
		})
	}
}

func BenchmarkRegistry_AllStats(b *testing.B) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	registry := NewRegistry()

	// Register 100 circuit breakers
	for i := 0; i < 100; i++ {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:         fmt.Sprintf("cb-%d", i),
			Threshold:    3,
			ResetTimeout: 100 * time.Millisecond,
			Logger:       logger,
		})
		registry.Register(cb)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.AllStats()
	}
}
