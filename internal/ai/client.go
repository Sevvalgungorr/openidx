// Package ai provides a client for a LOCALLY-HOSTED large language model via
// the OpenAI-compatible chat completions API — the de-facto standard served by
// Ollama (`http://host:11434/v1`), LM Studio, vLLM and llama.cpp server. No
// data leaves the deployment: the base URL is expected to point at
// on-premises infrastructure, and the client is used strictly as an
// enrichment layer (narratives, briefings, grounded Q&A) over deterministic
// scoring. Every caller must degrade gracefully when the client is disabled.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// Client talks to one OpenAI-compatible chat completions endpoint.
type Client struct {
	baseURL string
	model   string
	http    *http.Client
	logger  *zap.Logger
	enabled bool
}

// NewClient builds a client from config. A disabled config returns a non-nil
// client whose Enabled() is false — callers branch on that, never on nil.
func NewClient(cfg *config.Config, logger *zap.Logger) *Client {
	timeout := 60 * time.Second
	if cfg != nil && cfg.AIHTTPTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.AIHTTPTimeoutSeconds) * time.Second
	}
	c := &Client{
		http:   &http.Client{Timeout: timeout},
		logger: logger,
	}
	if cfg != nil {
		c.enabled = cfg.AIEnabled
		c.baseURL = strings.TrimRight(cfg.AIBaseURL, "/")
		c.model = cfg.AIModel
	}
	return c
}

// Enabled reports whether the local AI provider is configured and turned on.
func (c *Client) Enabled() bool {
	return c != nil && c.enabled && c.baseURL != "" && c.model != ""
}

// Model returns the configured model name (for status displays).
func (c *Client) Model() string {
	if c == nil {
		return ""
	}
	return c.model
}

// Message is one chat turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
	Stream      bool      `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends a system+user prompt pair and returns the model's reply.
// Returns an error when the client is disabled — callers should check
// Enabled() first and fall back to deterministic output.
func (c *Client) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if !c.Enabled() {
		return "", fmt.Errorf("local AI provider is not enabled")
	}

	body, err := json.Marshal(chatRequest{
		Model: c.model,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.2,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("local AI request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("local AI returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("parse local AI response: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("local AI error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("local AI returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

// Status probes the provider with a models list request and reports
// reachability. Cheap enough to call from a status endpoint.
type Status struct {
	Enabled   bool   `json:"enabled"`
	Reachable bool   `json:"reachable"`
	BaseURL   string `json:"base_url,omitempty"`
	Model     string `json:"model,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func (c *Client) Status(ctx context.Context) Status {
	s := Status{Enabled: c.Enabled()}
	if !s.Enabled {
		s.Detail = "local AI provider disabled (set AI_ENABLED=true with an on-prem OpenAI-compatible endpoint, e.g. Ollama)"
		return s
	}
	s.BaseURL = c.baseURL
	s.Model = c.model

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, c.baseURL+"/models", nil)
	if err != nil {
		s.Detail = err.Error()
		return s
	}
	resp, err := c.http.Do(req)
	if err != nil {
		s.Detail = "endpoint unreachable: " + err.Error()
		return s
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	s.Reachable = resp.StatusCode == http.StatusOK
	if !s.Reachable {
		s.Detail = fmt.Sprintf("endpoint returned status %d", resp.StatusCode)
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
