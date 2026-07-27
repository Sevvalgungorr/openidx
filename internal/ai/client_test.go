package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func testClient(t *testing.T, baseURL string, enabled bool) *Client {
	t.Helper()
	return NewClient(&config.Config{
		AIEnabled:            enabled,
		AIBaseURL:            baseURL,
		AIModel:              "test-model",
		AIHTTPTimeoutSeconds: 5,
	}, zap.NewNop())
}

func TestClientDisabled(t *testing.T) {
	c := testClient(t, "http://localhost:1", false)
	if c.Enabled() {
		t.Fatal("disabled config must yield disabled client")
	}
	if _, err := c.Complete(context.Background(), "sys", "user"); err == nil {
		t.Fatal("Complete on disabled client must error")
	}
	status := c.Status(context.Background())
	if status.Enabled || status.Reachable {
		t.Errorf("disabled status should be enabled=false reachable=false, got %+v", status)
	}
}

func TestClientComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var req struct {
			Model    string    `json:"model"`
			Messages []Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "test-model" || len(req.Messages) != 2 {
			t.Errorf("unexpected request: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"  the answer  "}}]}`))
	}))
	defer server.Close()

	c := testClient(t, server.URL+"/v1", true)
	got, err := c.Complete(context.Background(), "sys", "question")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if got != "the answer" {
		t.Errorf("expected trimmed answer, got %q", got)
	}
}

func TestClientCompleteErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`model not loaded`))
	}))
	defer server.Close()

	c := testClient(t, server.URL, true)
	if _, err := c.Complete(context.Background(), "sys", "q"); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestClientCompleteNoChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer server.Close()

	c := testClient(t, server.URL, true)
	if _, err := c.Complete(context.Background(), "sys", "q"); err == nil {
		t.Fatal("expected error on empty choices")
	}
}

func TestClientStatusReachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	status := testClient(t, server.URL, true).Status(context.Background())
	if !status.Enabled || !status.Reachable {
		t.Errorf("expected enabled+reachable, got %+v", status)
	}
	if status.Model != "test-model" {
		t.Errorf("expected model in status, got %+v", status)
	}
}
