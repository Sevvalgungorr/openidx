package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"
)

func newTestNtfyService(t *testing.T) *Service {
	t.Helper()
	return &Service{logger: zaptest.NewLogger(t)}
}

func TestSetNtfyRequiresSecret(t *testing.T) {
	s := newTestNtfyService(t)
	s.SetNtfy(NtfyConfig{BaseURL: "https://ntfy.internal"})
	if s.ntfy != nil {
		t.Fatal("push channel must stay disabled without a topic secret")
	}
	s.SetNtfy(NtfyConfig{BaseURL: "https://ntfy.internal", TopicSecret: "s3cret"})
	if s.ntfy == nil {
		t.Fatal("push channel should enable with base URL + secret")
	}
	s2 := newTestNtfyService(t)
	s2.SetNtfy(NtfyConfig{BaseURL: "not a url", TopicSecret: "s3cret"})
	if s2.ntfy != nil {
		t.Fatal("invalid base URL must leave push disabled")
	}
}

func TestNtfyTopicDerivation(t *testing.T) {
	s := newTestNtfyService(t)
	s.SetNtfy(NtfyConfig{BaseURL: "https://ntfy.internal", TopicSecret: "s3cret"})

	a1 := s.ntfy.topicFor("user-a")
	a2 := s.ntfy.topicFor("user-a")
	b := s.ntfy.topicFor("user-b")
	if a1 != a2 {
		t.Fatal("topic must be stable for the same user")
	}
	if a1 == b {
		t.Fatal("different users must get different topics")
	}
	if !strings.HasPrefix(a1, "oidx-") || len(a1) != len("oidx-")+32 {
		t.Fatalf("unexpected topic shape: %q", a1)
	}

	// A different secret rotates every topic.
	s2 := newTestNtfyService(t)
	s2.SetNtfy(NtfyConfig{BaseURL: "https://ntfy.internal", TopicSecret: "other"})
	if s2.ntfy.topicFor("user-a") == a1 {
		t.Fatal("topic must depend on the secret")
	}
}

func TestNtfyPublish(t *testing.T) {
	var gotPath, gotTitle, gotAuth, gotClick, gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotTitle.Store(r.Header.Get("Title"))
		gotAuth.Store(r.Header.Get("Authorization"))
		gotClick.Store(r.Header.Get("X-Click"))
		b := make([]byte, 256)
		n, _ := r.Body.Read(b)
		gotBody.Store(string(b[:n]))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestNtfyService(t)
	s.SetNtfy(NtfyConfig{BaseURL: srv.URL, Token: "tok", TopicSecret: "s3cret"})

	// Title with CR/LF must be flattened, never smuggled into headers.
	err := s.ntfy.publish(context.Background(), "user-a",
		"Login\r\napproved", "Approve sign-in from 1.2.3.4", "https://console/x")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if gotPath.Load() != "/"+s.ntfy.topicFor("user-a") {
		t.Errorf("published to wrong topic: %v", gotPath.Load())
	}
	if gotTitle.Load() != "Login approved" {
		t.Errorf("title not sanitized: %q", gotTitle.Load())
	}
	if gotAuth.Load() != "Bearer tok" {
		t.Errorf("missing bearer auth: %q", gotAuth.Load())
	}
	if gotClick.Load() != "https://console/x" {
		t.Errorf("click link missing: %q", gotClick.Load())
	}
	if gotBody.Load() != "Approve sign-in from 1.2.3.4" {
		t.Errorf("body mismatch: %q", gotBody.Load())
	}
}

func TestNtfyPublishServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	s := newTestNtfyService(t)
	s.SetNtfy(NtfyConfig{BaseURL: srv.URL, TopicSecret: "s3cret"})
	if err := s.ntfy.publish(context.Background(), "u", "t", "b", ""); err == nil {
		t.Fatal("expected error on non-2xx")
	}
}

func TestHandleGetPushConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Disabled → enabled:false, no topic leak.
	s := newTestNtfyService(t)
	r := gin.New()
	r.GET("/push-config", s.handleGetPushConfig)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/push-config", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled config wrong: %d %s", w.Code, w.Body.String())
	}

	// Enabled + authenticated → own topic returned.
	s2 := newTestNtfyService(t)
	s2.SetNtfy(NtfyConfig{BaseURL: "https://ntfy.internal", TopicSecret: "s3cret"})
	r2 := gin.New()
	r2.GET("/push-config", func(c *gin.Context) { c.Set("user_id", "user-a") }, s2.handleGetPushConfig)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/push-config", nil))
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), s2.ntfy.topicFor("user-a")) {
		t.Fatalf("enabled config wrong: %d %s", w2.Code, w2.Body.String())
	}

	// Enabled but unauthenticated → 401, never a topic.
	r3 := gin.New()
	r3.GET("/push-config", s2.handleGetPushConfig)
	w3 := httptest.NewRecorder()
	r3.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/push-config", nil))
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without user, got %d", w3.Code)
	}
}
